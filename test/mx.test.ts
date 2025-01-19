import { checkMx } from "../src/mx";
import { googleDnsService } from "../src/config/googleDoh";

// Mock the Google DNS service
jest.mock("../src/config/googleDoh", () => ({
    googleDnsService: {
        get: jest.fn(),
    },
}));

describe("MX Record Validation", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("should return valid for correct MX records", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    { data: "10 mail.example.com." },
                    { data: "20 backup-mail.example.com." },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "All MX records are valid",
            mx: [
                { preference: 10, exchange: "mail.example.com" },
                { preference: 20, exchange: "backup-mail.example.com" },
            ],
        });
    });

    it("should fail when DNS query returns error status", async () => {
        const mockResponse = {
            data: {
                Status: 2,
                Answer: null,
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "DNS query failed or returned an error status",
        });
    });

    it("should fail when no MX records found", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: null,
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No MX records found for the domain",
        });
    });

    it("should fail when empty MX records array", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No valid MX records found",
        });
    });

    it("should fail when duplicate MX exchanges found", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [
                    { data: "10 mail.example.com." },
                    { data: "20 mail.example.com." },
                ],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Duplicate MX exchanges found",
        });
    });

    it("should fail when preference value is invalid", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [{ data: "70000 mail.example.com." }],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Invalid preference value: 70000. Must be between 0 and 65535",
        });
    });

    it("should fail when exchange is an IP address", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [{ data: "10 192.168.1.1" }],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "MX exchange cannot be an IP address: 192.168.1.1",
        });
    });

    it("should fail when hostname format is invalid", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [{ data: "10 invalid@hostname" }],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Invalid hostname format: invalid@hostname",
        });
    });

    it("should handle trailing dots in exchange names", async () => {
        const mockResponse = {
            data: {
                Status: 0,
                Answer: [{ data: "10 mail.example.com." }],
            },
        };
        (googleDnsService.get as jest.Mock).mockResolvedValue(mockResponse);

        const result = await checkMx("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "All MX records are valid",
            mx: [{ preference: 10, exchange: "mail.example.com" }],
        });
    });
});
