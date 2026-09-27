# Next steps (v0.2 and beyond)

v0.1 is a first step: CISA CSAF + KEV only, reproducible from two git commits.

1. **NVD join** (CVE API 2.0): NVD CVSS and CPE next to the advisory's CVSS, and measure disagreement.
2. **EPSS join** (FIRST): exploitation probability for the 99% of ICS CVEs not in KEV.
3. **CVE Program records** (cvelistV5): CNA, publication date, CWE where the advisory has none.
4. **CVSS v4** parsing as CISA advisories adopt it.
5. **Vendor map review** by practitioners; add a `parent_company` column for lineage (Invensys → Schneider, OSIsoft → AVEVA) without overwriting `vendor`.
6. **Product-level table** from `product_tree`: product family and name per affected product ID.
7. **Scheduled refresh**: a monthly GitHub Action that re-runs the pipeline and tags a dated release, with a Zenodo version for each.
8. **CISA publication date** for republished advisories (from the cisa.gov page), so "published by CISA" and "dated by vendor" can both be counted.
