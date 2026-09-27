# Build spec: Open ICS Vulnerability Dataset + BSides talk

```
PROJECT:        Open ICS Advisory Dataset (OICSAD) v0.1 — archetypes: (1) open dataset + (11) presentation package
QUESTION:       What do 16 years of CISA ICS advisories say about which OT vulnerabilities get disclosed,
                how severe they are, whether fixes exist, and how many are known to be exploited, and
                what does it take to turn the federal feeds into a clean, reusable table?
SOURCES:        1. CISA CSAF advisories, OT/white (ICSA + ICSMA), github.com/cisagov/CSAF, commit pinned in
                   PROVENANCE.txt; US-government work (17 U.S.C. 105), TLP:WHITE / CLEAR.
                2. CISA Known Exploited Vulnerabilities catalog, github.com/cisagov/kev-data (official CISA
                   mirror of cisa.gov/known-exploited-vulnerabilities-catalog), commit pinned; CC0-1.0.
                Not used in v0.1 (blocked from build environment; planned for v0.2): NVD API 2.0, FIRST EPSS,
                CVE Program cvelistV5.
UNIT:           advisory (advisories.csv); advisory x CVE (advisory_cves.csv); CVE (cves.csv)
MEASURES:       advisory counts by initial-release year; vendor (normalized); CISA sector (16 PPD-21 sectors,
                regex-mapped from free text); CVSS base score/severity/attack vector (highest version per
                record); CWE; remediation category (vendor_fix / mitigation / workaround / none_available /
                no_fix_planned); KEV listing, KEV date added, ransomware-use flag; days from first advisory to
                KEV addition; revision count; republication flag.
OUTPUTS:        data/processed/{advisories,advisory_cves,cves,vendor_map}.csv; qa_report.txt; paper/stats.json;
                talk/figures/*.png; talk/ABSTRACT.md (CFP kit), talk/SPEAKER_NOTES.md, Slides artifact;
                docs/{CODEBOOK,LIMITATIONS,VERIFY_CHECKLIST,NEXT_STEPS,PUBLISH_GUIDE}.md
VENUES:         GitHub + Zenodo DOI (dataset) -> BSides Austin (Dec 2026, CFP not yet posted) ->
                BSides San Antonio (June 2027, CFP not yet posted); talk slides deposited to Zenodo after delivery.
VERIFY POINTS:  vendor normalization map; sector regex mapping; CVSS-version precedence rule; treatment of
                republished vendor advisories (date = original vendor date); 15 spot-check records vs cisa.gov.
LICENSE:        code MIT; data CC BY 4.0 (sources: public domain / CC0)
ASSUMPTIONS:    speaker = Friday Ogochukwu Ikwuogu; standard co-authors on dataset credit; 25-minute talk slot
                (with 55-minute extension notes); snapshot date = source commit dates in PROVENANCE.txt.
```
