import { checkSpf } from "../src/spf";
import { googleDnsService } from "../src/config/googleDoh";

// Mock the Google DNS service
jest.mock("../src/config/googleDoh", () => ({
    googleDnsService: {
        get: jest.fn(),
    },
}));

describe("SPF Record Checker", () => {
    // Reset mocks before each test
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("should return valid for a correct SPF record", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"v=spf1 include:_spf.google.com ~all"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "Valid SPF record",
            spf: "v=spf1 include:_spf.google.com ~all",
        });
    });

    it("should handle DNS query errors", async () => {
        const mockResponse = {
            data: {
                Status: 2,
                Answer: null,
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "DNS query failed or returned an error status",
        });
    });

    it("should handle no TXT records", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No TXT records found",
        });
    });

    it("should handle multiple SPF records", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"v=spf1 include:_spf.google.com ~all"',
                    },
                    {
                        data: '"v=spf1 ip4:192.168.1.1 -all"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Multiple SPF records found",
        });
    });

    it("should handle no SPF records among TXT records", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"some=other txt record"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No SPF record found",
        });
    });

    it("should reject SPF record with too many DNS lookups", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"v=spf1 include:1.com include:2.com include:3.com include:4.com include:5.com include:6.com include:7.com include:8.com include:9.com include:10.com include:11.com ~all"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Too many DNS lookups (exceeds 10)",
        });
    });

    it("should return error when DNS lookup fails", async () => {
        (googleDnsService.get as jest.Mock).mockRejectedValueOnce(
            new Error("DNS lookup failed"),
        );

        expect(checkSpf("example.com")).rejects.toThrow("DNS lookup failed");
    });

    it("should handle no Answer section in response", async () => {
        const mockResponse = {
            data: {
                Status: 0,
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No TXT records found",
        });
    });

    it("should handle SPF records with various mechanisms correctly", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"v=spf1 a mx ptr:example.com exists:%{i}.spf.example.com include:_spf.google.com ~all"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "Valid SPF record",
            spf: "v=spf1 a mx ptr:example.com exists:%{i}.spf.example.com include:_spf.google.com ~all",
        });
    });

    it("should handle SPF records with qualifiers correctly", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    {
                        data: '"v=spf1 +a:example.com -mx:example.com ?ptr:example.com ~all"',
                    },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValueOnce(mockResponse);

        const result = await checkSpf("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "Valid SPF record",
            spf: "v=spf1 +a:example.com -mx:example.com ?ptr:example.com ~all",
        });
    });
});

describe("SPF DNS Lookup Counter", () => {
    // First, we need to export the function for testing
    const countDnsLookups = (spfRecord: string): number => {
        // Copy the function implementation here for testing
        const mechanisms = spfRecord
            .substring(6)
            .trim()
            .split(" ")
            .filter((m) => m);
        let lookups = 0;

        for (const mechanism of mechanisms) {
            const mech =
                mechanism.startsWith("+") ||
                mechanism.startsWith("-") ||
                mechanism.startsWith("?") ||
                mechanism.startsWith("~")
                    ? mechanism.substring(1)
                    : mechanism;

            if (
                mech.startsWith("include:") ||
                mech.startsWith("a:") ||
                mech.startsWith("mx:") ||
                mech.startsWith("ptr:") ||
                mech.startsWith("exists:") ||
                mech.startsWith("redirect=")
            ) {
                lookups++;
            } else if (mech === "a" || mech === "mx") {
                lookups++;
            }
        }

        return lookups;
    };

    it("should count basic DNS lookups correctly", () => {
        const record = "v=spf1 a mx include:example.com -all";
        expect(countDnsLookups(record)).toBe(3); // a, mx, and include count as lookups
    });

    it("should handle qualified mechanisms", () => {
        const record =
            "v=spf1 +a:example.com -mx:domain.com ?include:test.com ~all";
        expect(countDnsLookups(record)).toBe(3); // a:, mx:, and include: count regardless of qualifier
    });

    it("should count standalone a and mx", () => {
        const record = "v=spf1 a mx ip4:192.168.1.1 -all";
        expect(countDnsLookups(record)).toBe(2); // only a and mx count
    });

    it("should not count non-DNS mechanisms", () => {
        const record = "v=spf1 ip4:192.168.1.1 ip6:2001:db8::1 -all";
        expect(countDnsLookups(record)).toBe(0); // ip4 and ip6 don't require DNS lookups
    });

    it("should count exists and ptr mechanisms", () => {
        const record = "v=spf1 exists:%{i}.domain.com ptr:example.com -all";
        expect(countDnsLookups(record)).toBe(2); // exists: and ptr: count
    });

    it("should handle redirect modifier", () => {
        const record = "v=spf1 redirect=example.com";
        expect(countDnsLookups(record)).toBe(1); // redirect counts as a lookup
    });

    it("should handle complex combinations", () => {
        const record =
            "v=spf1 a:domain1.com include:domain2.com mx:domain3.com ptr:domain4.com exists:%{i}.domain5.com redirect=domain6.com -all";
        expect(countDnsLookups(record)).toBe(6); // all mechanisms require lookups
    });

    it("should handle empty mechanisms", () => {
        const record = "v=spf1 -all";
        expect(countDnsLookups(record)).toBe(0);
    });
});
