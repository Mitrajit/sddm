import { checkDkim } from "../src/dkim";
import { googleDnsService } from "../src/config/googleDoh";

// Mock the Google DNS service
jest.mock("../src/config/googleDoh", () => ({
    googleDnsService: {
        get: jest.fn().mockImplementation(async () => ({
            data: {
                Status: 3,
                TC: false,
                RD: true,
                RA: true,
                AD: false,
                CD: false,
                Question: [
                    {
                        name: "example.com.",
                        type: 16,
                    },
                ],
            },
        })),
    },
}));

describe("DKIM Record Validation", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        // Reset mock implementation but keep the structure
        (googleDnsService.get as jest.Mock)
            .mockReset()
            .mockImplementation(async () => ({
                data: {
                    Status: 3,
                },
            }));
    });

    afterEach(() => {
        jest.resetAllMocks();
    });

    // Test valid DKIM records
    describe("Valid DKIM Records", () => {
        const validResponse = {
            data: {
                Answer: [
                    {
                        name: "selector1._domainkey.example.com.",
                        type: 5,
                        TTL: 300,
                        data: "selector1-example-com._domainkey.example.onmicrosoft.com.",
                    },
                    {
                        name: "selector1-example-com._domainkey.example.onmicrosoft.com.",
                        type: 16,
                        TTL: 3600,
                        data: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7EMhPpSveifM1Wzs8Dy5AFULhNPcDLS8iW2s8KNi23GnfxHjqn6+jTo6BBlOmUt0qIsVBlXH3/Ab+;",
                    },
                ],
            },
        };

        it("should validate Google DKIM", async () => {
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                validResponse,
            );
            const result = await checkDkim("example.com", "google");
            expect(result.isValid).toBe(true);
            expect(result.dkimSelectors).toContain("google");
        });

        it("should validate Microsoft DKIM", async () => {
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                validResponse,
            );
            const result = await checkDkim("example.com", "microsoft");
            expect(result.isValid).toBe(true);
            expect(result.dkimSelectors).toContain("selector1");
        });

        it("should validate common DKIM check", async () => {
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                validResponse,
            );
            const result = await checkDkim("example.com");
            expect(result.isValid).toBe(true);
            expect(result.dkimSelectors?.length).toBeGreaterThan(0);
        });
    });

    // Test invalid DKIM records
    describe("Invalid DKIM Records", () => {
        it("should fail for missing version", async () => {
            const mockResponse = {
                data: {
                    Answer: [
                        {
                            data: "v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Uu5",
                        },
                    ],
                },
            };
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                mockResponse,
            );
            const result = await checkDkim("example.com", "google");
            expect(result.isValid).toBe(false);
            expect(result.reason).toContain("Invalid DKIM record format");
        });

        it("should fail for multiple records", async () => {
            const mockResponse = {
                data: {
                    Answer: [
                        { data: "v=DKIM1; k=rsa; p=KEY1" },
                        { data: "v=DKIM1; k=rsa; p=KEY2" },
                    ],
                },
            };
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                mockResponse,
            );
            const result = await checkDkim("example.com", "google");
            expect(result.isValid).toBe(false);
            expect(result.reason).toContain("Multiple DKIM records found");
        });

        it("should fail for missing public key", async () => {
            const mockResponse = {
                data: {
                    Answer: [{ data: "v=DKIM1; k=rsa;" }],
                },
            };
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                mockResponse,
            );
            const result = await checkDkim("example.com", "google");
            expect(result.isValid).toBe(false);
            expect(result.reason).toContain("Invalid DKIM record format");
        });
    });

    // Test error handling
    describe("Error Handling", () => {
        it("should throw error when DNS query fails", async () => {
            const error = new Error("DNS query failed");
            jest.spyOn(googleDnsService, "get").mockRejectedValueOnce(error);

            await expect(checkDkim("example.com", "google")).rejects.toThrow(
                "DNS query failed",
            );
        });

        it("should handle no records found", async () => {
            const mockResponse = {
                data: {
                    Status: 3,
                    TC: false,
                    RD: true,
                    RA: true,
                    AD: false,
                    CD: false,
                    Question: [
                        {
                            name: "example.com.",
                            type: 16,
                        },
                    ],
                    Authority: [
                        {
                            name: "com.",
                            type: 6,
                            TTL: 900,
                            data: "a.gtld-servers.net. nstld.verisign-grs.com. 1737308098 1800 900 604800 900",
                        },
                    ],
                    Comment: "Response from 192.33.14.30.",
                },
            };
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                mockResponse,
            );

            const result = await checkDkim("example.com");
            expect(result.isValid).toBe(false);
            expect(result.reason).toContain("No valid DKIM records found");
        });

        it("should handle invalid provider", async () => {
            await expect(
                // @ts-expect-error - Testing invalid provider
                checkDkim("example.com", "invalid-provider"),
            ).rejects.toThrow();
        });
    });

    // Test provider-specific behavior
    describe("Provider-Specific Checks", () => {
        it("should validate Microsoft 365 selectors", async () => {
            const mockResponse = {
                data: {
                    Answer: [
                        {
                            data: "v=DKIM1; k=rsa; p=KEY1",
                        },
                    ],
                },
            };
            jest.spyOn(googleDnsService, "get").mockResolvedValueOnce(
                mockResponse,
            );

            const result = await checkDkim("example.com", "microsoft");
            expect(result.isValid).toBe(true);
            expect(result.dkimSelectors).toContain("selector1");
            expect(result.reason).toBe("DKIM records found");
        });
    });
});
