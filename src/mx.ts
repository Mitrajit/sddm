import { googleDnsService } from "./config/googleDoh";

// Rules for MX Records:
// 1. At least 1 MX record but no duplicate exchanges
// 2. MX record should be a DNS name, not an IP address
// 3. Exchange must be a valid hostname (RFC 5321)
// 4. Preference value must be a valid integer (0-65535)
// 5. Exchange cannot be empty or end with a dot

interface MxCheckResult {
    isValid: boolean;
    reason: string;
    mx?: { preference: number; exchange: string }[];
}

export async function checkMx(domain: string): Promise<MxCheckResult> {
    const response = await googleDnsService.get(
        `/resolve?name=${domain}&type=MX`,
    );
    const { data } = response;

    if (data.Status !== 0) {
        return {
            isValid: false,
            reason: "DNS query failed or returned an error status",
        };
    }

    if (!data.Answer) {
        return {
            isValid: false,
            reason: "No MX records found for the domain",
        };
    }

    const mxRecords = data.Answer.map((answer: any) => {
        const [preference, exchange] = answer.data.split(" ");
        return {
            preference: parseInt(preference, 10),
            exchange: exchange.toLowerCase().replace(/\.$/, ""), // Remove trailing dot if present
        };
    });

    // Check if we have at least one record
    if (mxRecords.length === 0) {
        return {
            isValid: false,
            reason: "No valid MX records found",
        };
    }

    // Check for duplicate exchanges
    const exchanges = new Set(mxRecords.map((record: any) => record.exchange));
    if (exchanges.size !== mxRecords.length) {
        return {
            isValid: false,
            reason: "Duplicate MX exchanges found",
        };
    }

    // Validate each record
    for (const record of mxRecords) {
        // Check preference range (0-65535)
        if (
            isNaN(record.preference) ||
            record.preference < 0 ||
            record.preference > 65535
        ) {
            return {
                isValid: false,
                reason: `Invalid preference value: ${record.preference}. Must be between 0 and 65535`,
            };
        }

        // Check if exchange is not an IP address (simple check)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(record.exchange)) {
            return {
                isValid: false,
                reason: `MX exchange cannot be an IP address: ${record.exchange}`,
            };
        }

        // Check if exchange is a valid hostname
        const hostnameRegex =
            /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!hostnameRegex.test(record.exchange)) {
            return {
                isValid: false,
                reason: `Invalid hostname format: ${record.exchange}`,
            };
        }
    }

    // All validations passed
    return {
        isValid: true,
        reason: "All MX records are valid",
        mx: mxRecords,
    };
}

// checkMxDoh("theartofswag.com") // true
//     .then((res) => {
//         console.log(res, "theartofswag.com");
//     })
//     .catch((err) => {
//         console.log("theartofswag.com", err);
//     });

// checkMxDoh("echoboxed.com") // true
//     .then((res) => {
//         console.log(res, "echoboxed.com");
//     })
//     .catch((err) => {
//         console.log("echoboxed.com", err);
//     });

// checkMxDoh("reachinbox.ai") // true
//     .then((res) => {
//         console.log(res, "reachinbox.ai");
//     })
//     .catch((err) => {
//         console.log("reachinbox.ai", err);
//     });

// checkMxDoh("fsdfsdf.fodsfd")
//     .then((res) => {
//         console.log(res, "fsdfsdf.fodsfd");
//     })
//     .catch((err) => {
//         console.log("fsdfsdf.fodsfd", err);
//     });
