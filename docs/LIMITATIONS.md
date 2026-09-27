# Limitations

Read these before using or citing the dataset. They are numbered so the talk and any paper can point to them.

1. **Coverage is CISA's CSAF corpus, not every ICS vulnerability.** The dataset holds what CISA published as ICS/ICSMA advisories in its CSAF repository (3,937 files at commit `369141e87131c0e9eb5dfc405673ffe106a29a19`). Vulnerabilities disclosed only by vendors, CERT@VDE, JPCERT or other CERTs and never carried by CISA are absent. Siemens' share (26.5%) partly reflects Siemens ProductCERT's volume and CISA's republication of its advisories, not a finding that Siemens products are less secure.

2. **Dates for republished advisories are the vendor's dates.** CISA republishes vendor CSAFs "retaining the dates and revision history of the original." 1,112 advisories are republished or converted from a vendor format, and 71 carry an ID year that differs from their initial release date (for example, an ICSA-25 advisory dated 2011). Year counts use `initial_release`, so a year's bar is "advisories dated that year", not "advisories CISA published that year."

3. **Vendor normalization is conservative and manual.** 883 raw strings reduce to 848 names by suffix stripping plus a reviewed alias list (`VENDOR_ALIASES` in `code/02_build.py`). Corporate lineage is not merged (Invensys is not folded into Schneider Electric, OSIsoft not into AVEVA). 19 raw strings name several companies and are left unsplit.

4. **Sectors come from free text and are missing before 2017.** The "Critical infrastructure sectors" note is absent from 99.5% of pre-2017 advisories. Where present it is mapped to the 16 PPD-21 sectors by regular expression, typos included; "Multiple" is kept as a flag, not expanded.

5. **CVSS is mixed-version and vendor-supplied.** Scores are CVSS 3.1 (7,462 CVEs), 3.0 (3,966) and 2.0 (631); 287 CVEs carry no score. The newest version wins, then the highest base score. Scores come from the advisory, not NVD, and CVSS v4 is not parsed in v0.1.

6. **Remediation categories are what the CSAF says, not whether a fix shipped.** Older advisories converted to CSAF often list only generic "mitigation" entries. `fix_available_any` (56.1%) is a lower bound, and `no_fix_all` (6.2%) counts only CVEs explicitly marked `none_available` or `no_fix_planned`.

7. **KEV is a floor for exploitation, and the join is by CVE ID only.** KEV lists exploitation CISA has confirmed, which is a small, US-government-centred subset of real-world exploitation. Absence from KEV is not evidence of non-exploitation. KEV began on 2021-11-03, so "days to KEV" for older CVEs measures catalog creation as much as exploitation. Timing statistics are therefore reported for CVEs first advised after launch (76 CVEs).

8. **"Third-party component" is a heuristic.** A KEV-listed CVE is `third_party` when the KEV vendor shares no distinctive name token with the advisory's first-listed vendor. It classifies all 117 KEV CVEs, but component suppliers that are also OT vendors, or renamed companies, could be misclassified. All 117 are listed for review in `data/processed/cves.csv`.

9. **Counts are dominated by a few very large advisories.** One advisory (ICSA-23-348-10, Siemens SIMATIC S7-1500) lists 544 CVEs, all in the product's embedded GNU/Linux subsystem; the median advisory lists 1. CVE-level shares are therefore weighted toward component-heavy firmware.

10. **Not yet joined: NVD, EPSS, CVE Program records.** These were unreachable from the build environment and are planned for v0.2 (`docs/NEXT_STEPS.md`). The KEV finding rests on CISA data alone.
