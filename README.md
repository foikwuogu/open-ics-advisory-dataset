# Open ICS Advisory Dataset (OICSAD)

**Status:** v0.1.0, released 2026-09-26 | **Maintainer:** Friday Ogochukwu Ikwuogu, ORCID [0009-0009-2222-1318](https://orcid.org/0009-0009-2222-1318) | **DOI:** [10.5281/zenodo.22985480](https://doi.org/10.5281/zenodo.22985480) | **License:** code MIT, data CC BY 4.0

Every industrial control system (ICS) and medical device advisory CISA has published in machine-readable CSAF form, 2010-02-27 to 2026-09-24, parsed into three clean tables and joined to CISA's Known Exploited Vulnerabilities (KEV) catalog. It exists so that OT defenders, researchers and students can ask questions of the federal ICS advisory record with one `pandas.read_csv` instead of scraping 3,000+ web pages, and so that every normalization choice is visible and reversible.

This repository also holds the materials for the BSides talk *"Building an open ICS vulnerability dataset from federal sources"* (`talk/`).

## What is here

```
code/01_fetch.py      git-fetch CISA CSAF (OT) + CISA KEV, pin commits, log provenance
code/02_build.py      parse, normalize vendors and sectors, join KEV, write tables
code/03_qa.py         hard checks, spot checks, paper/stats.json
code/04_figures.py    talk/paper figures   (--final removes the draft tags)
code/05_document.py   renders README, docs, abstract, notes from templates + stats.json
data/raw/             sources as fetched + PROVENANCE.txt   (not committed; re-fetch)
data/processed/       advisories.csv, advisory_cves.csv, cves.csv, vendor_map.csv, qa_report.txt
docs/                 CODEBOOK, LIMITATIONS, VERIFY_CHECKLIST, NEXT_STEPS, BUILD_SPEC, PUBLISH_GUIDE
talk/                 CFP abstract, speaker notes, figures
```

## Run it

```
pip install -r requirements.txt
python code/01_fetch.py --csaf-commit 369141e87131c0e9eb5dfc405673ffe106a29a19 --kev-commit 9dfdff658ee0fbbca1c648235a29a5402f6533ca
python code/02_build.py
python code/03_qa.py
python code/04_figures.py
python code/05_document.py
```

With the two pinned commits a stranger reproduces `data/processed/` exactly. Drop the flags (and add `--refresh`) to pull the current feeds.

## Sources

| Source | Snapshot | License | Accessed |
|---|---|---|---|
| CISA CSAF advisories, `csaf_files/OT/white` ([github.com/cisagov/CSAF](https://github.com/cisagov/CSAF)) | commit `369141e87131c0e9eb5dfc405673ffe106a29a19` (2026-09-24) | US government work, public domain (17 U.S.C. 105); TLP:CLEAR | 2026-09-26 |
| CISA Known Exploited Vulnerabilities catalog ([github.com/cisagov/kev-data](https://github.com/cisagov/kev-data), official mirror of cisa.gov/kev) | catalog 2026.09.25, commit `9dfdff658ee0fbbca1c648235a29a5402f6533ca` | CC0 1.0 | 2026-09-26 |

## Headline numbers (from `paper/stats.json`)

- 3,937 advisories (3,749 ICSA, 188 ICSMA medical), 14,487 advisory-CVE links, 12,346 unique CVEs, 848 vendors after normalizing 883 raw vendor strings.
- Volume grew from 137 advisories in 2015 to 489 in 2025 (3.6x). Siemens alone accounts for 26.5% of advisories.
- 60.8% of scored CVEs are High or Critical; 60% are network-exploitable and 32.7% local.
- 117 CVEs (0.9%) are in KEV. 100 of those 117 (85.5%) are third-party IT components (Cisco IOS, Windows, Chromium, Linux, PAN-OS, FortiOS) embedded in OT products, and for CVEs first advised after KEV launched, 51 of 76 were already known-exploited when the ICS advisory appeared.

## Limitations

Read `docs/LIMITATIONS.md` before using or citing anything here.

## Code

https://github.com/foikwuogu/open-ics-advisory-dataset

## Citation

See `CITATION.cff`. DOI for this version (v0.1.0): [10.5281/zenodo.22985480](https://doi.org/10.5281/zenodo.22985480). To cite all versions, use the concept DOI [10.5281/zenodo.22985479](https://doi.org/10.5281/zenodo.22985479), which always resolves to the latest release.

## AI assistance

Code, parsing and first drafts of documentation were produced with AI assistance (Claude). The author made the analytic decisions and verified the outputs against the sources listed in `docs/VERIFY_CHECKLIST.md`.
