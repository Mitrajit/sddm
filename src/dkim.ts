// Give true false if DKIM record is found

import { googleDnsService } from "./config/googleDoh";

const commonDkimSelectors = [
    "google",
    "selector1", // Microsoft 365
    "selector2",
    "k1", // (Mailchimp, mandrill)
    "k2",
    "ctct1", // (constant contact)
    "ctct2",
    "sm", // (Blackbaud, eTapestry)
    "s1", // (Nationbuilder)
    "s2",
    "sig1", // (iCloud)
    "litesrv", // (mailerlite)
    "zendesk1", // (Zendesk)
    "zendesk2",
    "mail",
    "email",
    "dkim",
    "default",
];

const dkimSelectorsForProviders = {
    google: ["google"],
    microsoft: ["selector1", "selector2"],
};

// Rules
// 1. Same selector should only one DKIM records
// 2. Parse the DKIM record

interface DkimValidationResult {
    isValid: boolean | null;
    reason: string;
}

function truncateRecord(record: string, maxLength: number = 50): string {
    if (record.length <= maxLength) return record;
    return record.substring(0, maxLength) + "...";
}

function isValidDkimRecord(record: string): boolean {
    // Basic DKIM record validation
    // Should contain v=DKIM1, k=rsa, and p= (public key) at minimum
    const cleanRecord = record.replace(/['"]/g, ""); // Remove quotes
    const parts = cleanRecord.split(";").map((part) => part.trim());

    const hasVersion = parts.some((part) => part.startsWith("v=DKIM1"));
    const hasKey = parts.some((part) => part.startsWith("k="));
    const hasPublicKey = parts.some((part) => {
        const publicKeyMatch = part.match(/^p=/);
        if (!publicKeyMatch) return false;

        // Make sure the public key isn't empty
        const publicKey = part.substring(2).trim();
        return publicKey.length > 0;
    });

    return hasVersion && hasKey && hasPublicKey;
}

async function validateDkimForSelector(
    domain: string,
    selector: string,
): Promise<DkimValidationResult> {
    const response = await googleDnsService.get(
        `/resolve?name=${selector}._domainkey.${domain}&type=TXT`,
    );

    const dkimRecords = response.data.Answer;
    if (!dkimRecords || dkimRecords.length === 0) {
        return {
            isValid: null,
            reason: `No DKIM records found for selector ${selector}`,
        };
    }

    // Filter out non-DKIM records
    const validDkimRecords = dkimRecords.filter((record: any) =>
        record.data.toLowerCase().includes("v=dkim1"),
    );

    // Rule 1: Check for multiple DKIM records
    if (validDkimRecords.length > 1) {
        return {
            isValid: false,
            reason: `Multiple DKIM records found for selector ${selector}`,
        };
    }

    // Rule 2: Parse and validate DKIM record
    if (validDkimRecords.length === 0) {
        return {
            isValid: false,
            reason: `No valid DKIM records found for selector ${selector}`,
        };
    }

    const record = validDkimRecords[0].data;
    if (!isValidDkimRecord(record)) {
        return {
            isValid: false,
            reason: `Invalid DKIM record format for selector ${selector} - ${truncateRecord(record)}`,
        };
    }

    return {
        isValid: true,
        reason: "All checks passed",
    };
}

export async function checkDkim(
    domain: string,
    provider?: "google" | "microsoft",
): Promise<{ isValid: boolean; reason: string; dkimSelectors?: string[] }> {
    const foundValidSelectors = new Map<string, string>();
    const selectorsToCheck = provider
        ? dkimSelectorsForProviders[provider]
        : commonDkimSelectors;
    for (const selector of selectorsToCheck) {
        const result = await validateDkimForSelector(domain, selector);

        if (result.isValid === true) {
            foundValidSelectors.set(selector, result.reason);
        } else if (
            result.isValid === false &&
            !result.reason.includes("No DKIM records found") &&
            !result.reason.includes("No valid DKIM records found")
        ) {
            return {
                isValid: false,
                reason: result.reason,
            };
        }
    }

    if (foundValidSelectors.size > 0) {
        return {
            isValid: true,
            reason: "DKIM records found",
            dkimSelectors: Array.from(foundValidSelectors.keys()),
        };
    }
    return {
        isValid: false,
        reason: "No valid DKIM records found",
    };
}
