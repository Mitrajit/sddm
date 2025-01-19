import { checkDmarc } from "../src/dmarc";
import { googleDnsService } from "../src/config/googleDoh";

// Mock the googleDnsService
jest.mock("../src/config/googleDoh", () => ({
    googleDnsService: {
        get: jest.fn(),
    },
}));

describe("checkDmarc", () => {
    const mockGet = googleDnsService.get as jest.Mock;

    beforeEach(() => {
        // Clear mock before each test
        jest.clearAllMocks();
    });

    it("should return invalid when DNS query fails", async () => {
        mockGet.mockResolvedValueOnce({ data: { Status: 3 } });

        const result = await checkDmarc("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "DNS query failed or returned an error status",
        });
    });

    it("should return invalid when no DMARC record is found", async () => {
        mockGet.mockResolvedValueOnce({
            data: {
                Status: 0,
                Answer: [{ data: "v=spf1 include:_spf.example.com ~all" }],
            },
        });

        const result = await checkDmarc("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "No valid DMARC record found",
        });
    });

    it("should return invalid when multiple DMARC records are found", async () => {
        mockGet.mockResolvedValueOnce({
            data: {
                Status: 0,
                Answer: [
                    { data: "v=DMARC1; p=none; rua=mailto:dmarc@example.com" },
                    {
                        data: "v=DMARC1; p=reject; rua=mailto:dmarc2@example.com",
                    },
                ],
            },
        });

        const result = await checkDmarc("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Multiple DMARC records found",
        });
    });

    it("should return invalid when DMARC record is missing required tags", async () => {
        mockGet.mockResolvedValueOnce({
            data: {
                Status: 0,
                Answer: [
                    { data: "v=DMARC1; p=none;" }, // missing rua tag
                ],
            },
        });

        const result = await checkDmarc("example.com");
        expect(result).toEqual({
            isValid: false,
            reason: "Invalid DMARC record format - missing required tags (v=DMARC1, p=, rua=)",
        });
    });

    it("should return valid for a correct DMARC record", async () => {
        const validDmarcRecord =
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com";
        mockGet.mockResolvedValueOnce({
            data: {
                Status: 0,
                Answer: [{ data: validDmarcRecord }],
            },
        });

        const result = await checkDmarc("example.com");
        expect(result).toEqual({
            isValid: true,
            reason: "Valid DMARC record",
            dmarc: validDmarcRecord,
        });
    });
});
