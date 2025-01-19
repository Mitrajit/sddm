// Give true false if spf record is found
import { googleDnsService } from "./config/googleDoh";

// SPF check rules
// https://www.rfc-editor.org/rfc/rfc7208#section-4.6.2
// 1. Only one SPF record
// 2. Parse the SPF record
// 3. 10 dns lookups only

function countDnsLookups(spfRecord: string): number {
    // Remove v=spf1 from the start
    const mechanisms = spfRecord
        .substring(6)
        .trim()
        .split(" ")
        .filter((m) => m);
    let lookups = 0;

    for (const mechanism of mechanisms) {
        // Skip qualifiers if present
        const mech =
            mechanism.startsWith("+") ||
            mechanism.startsWith("-") ||
            mechanism.startsWith("?") ||
            mechanism.startsWith("~")
                ? mechanism.substring(1)
                : mechanism;

        // Count mechanisms that require DNS lookups
        if (
            mech.startsWith("include:") ||
            mech.startsWith("a:") ||
            mech.startsWith("mx:") ||
            mech.startsWith("ptr:") ||
            mech.startsWith("exists:") ||
            mech.startsWith("redirect=")
        ) {
            lookups++;
        }
        // Special case for standalone "a" and "mx"
        else if (mech === "a" || mech === "mx") {
            lookups++;
        }
    }

    return lookups;
}

export async function checkSpf(
    domain: string,
): Promise<{ isValid: boolean; reason: string; spf?: string }> {
    const response = await googleDnsService.get(
        `/resolve?name=${domain}&type=TXT`,
    );

    // Check DNS response status
    if (response.data.Status !== 0) {
        return {
            isValid: false,
            reason: `DNS query failed or returned an error status`,
        };
    }

    if (!response.data.Answer || response.data.Answer.length === 0) {
        return {
            isValid: false,
            reason: "No TXT records found",
        };
    }

    // Check each TXT record for SPF
    const spfRecords = response.data.Answer.filter((record: any) => {
        // Clean up the record data (remove quotes if present)
        let txt = record.data.replace(/^"|"$/g, "");
        return txt.toLowerCase().startsWith("v=spf1");
    });

    // Rule #1: Multiple SPF records are not allowed
    if (spfRecords.length > 1) {
        return {
            isValid: false,
            reason: "Multiple SPF records found",
        };
    }

    // If we found exactly one valid SPF record
    if (spfRecords.length === 1) {
        const spfText = spfRecords[0].data.replace(/^"|"$/g, "");

        // Rule #4: Check DNS lookup limit
        if (countDnsLookups(spfText) > 10) {
            return {
                isValid: false,
                reason: "Too many DNS lookups (exceeds 10)",
            };
        }

        return {
            isValid: true,
            reason: "Valid SPF record",
            spf: spfText,
        };
    }

    return {
        isValid: false,
        reason: "No SPF record found",
    };
}
