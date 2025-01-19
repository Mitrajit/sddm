// Give true false if Dmarc record is found

import { googleDnsService } from "./config/googleDoh";
// Rules
// 1. Only 1 DMARC records must be present
// 2. Dmarc parsable

export async function checkDmarc(domain: string) {
    const response = await googleDnsService.get(
        `/resolve?name=_dmarc.${domain}&type=TXT`,
    );

    // Check if we have any DMARC records
    if (response.data.Status !== 0) {
        return {
            isValid: false,
            reason: "DNS query failed or returned an error status",
        };
    }
    if (!response.data.Answer || response.data.Answer.length === 0) {
        return {
            isValid: false,
            reason: "No TXT records found",
        };
    }

    // Rule 1: Check if there's exactly one DMARC record
    const dmarcRecords = response.data.Answer.filter((record: any) =>
        record.data.toLowerCase().includes("v=dmarc1"),
    );

    if (dmarcRecords.length === 0) {
        return {
            isValid: false,
            reason: "No valid DMARC record found",
        };
    }

    if (dmarcRecords.length > 1) {
        return {
            isValid: false,
            reason: "Multiple DMARC records found",
        };
    }

    // Rule 2: Check if the DMARC record is parsable
    const dmarcRecord = dmarcRecords[0].data.replace(/['"]/g, "");

    try {
        // Basic DMARC record validation
        const isDmarcValid =
            dmarcRecord.toLowerCase().startsWith("v=dmarc1") &&
            dmarcRecord.toLowerCase().includes("p=") &&
            dmarcRecord.toLowerCase().includes("rua=");

        if (!isDmarcValid) {
            return {
                isValid: false,
                reason: "Invalid DMARC record format - missing required tags (v=DMARC1, p=, rua=)",
            };
        }

        return {
            isValid: true,
            reason: "Valid DMARC record",
            dmarc: dmarcRecord,
        };
    } catch {
        return {
            isValid: false,
            reason: "Error parsing DMARC record",
        };
    }
}

// checkDmarcDoh("reachplc.com")
//     .then((res) => {
//         console.log(res, "reachplc.com");
//     })
//     .catch((err) => {
//         console.log("reachplc.com", err);
//     });

// checkDmarcDoh("reachinbox.ai")
//     .then((res) => {
//         console.log(res, "reachinbox.ai");
//     })
//     .catch((err) => {
//         console.log("reachinbox.ai", err);
//     });

// checkDmarcDoh("fsdfsdf.fodsfd")
//     .then((res) => {
//         console.log(res, "fsdfsdf.fodsfd");
//     })
//     .catch((err) => {
//         console.log("fsdfsdf.fodsfd", err);
//     });
