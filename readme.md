# SDDM

This is a package to check the SPF, DKIM, DMARC and MX records by DNS Lookup.

# Usage

```bash
npm install sddm
```

```typescript
import { checkDkim, checkSpf, checkDmarc, checkMx } from "sddm";

async function main() {
    const dkim = await checkDkim("reachinbox.ai");
    const spf = await checkSpf("reachinbox.ai");
    const dmarc = await checkDmarc("reachinbox.ai");
    const mx = await checkMx("reachinbox.ai");

    console.log(dkim);
    /**
     * {
     * isValid: true,
     * reason: 'DKIM records found',
     * dkimSelectors: [ 'google' ]
     * }
     */
    console.log(spf);
    /**
     * {
     * isValid: true,
     * reason: 'Valid SPF record',
     * spf: 'v=spf1 include:_spf.google.com ~all'
     * }
     */
    console.log(dmarc);
    /**
     * {
     * isValid: false,
     * reason: 'Multiple DMARC records found'
     * }
     */
    console.log(mx);
    /**
     * {
     *  isValid: true,
     *  reason: 'All MX records are valid',
     *  mx: [
     *    { preference: 1, exchange: 'smtp.google.com' }
     *  ]
     * }
     */
}

main();
```
