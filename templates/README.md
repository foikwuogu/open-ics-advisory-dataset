# Open ICS Advisory Dataset (OICSAD)

**Status:** v0.1.0, released 2026-09-26 | **Maintainer:** {{author.name}}, ORCID [{{author.orcid}}](https://orcid.org/{{author.orcid}}) | **DOI:** [10.5281/zenodo.22985480](https://doi.org/10.5281/zenodo.22985480) | **License:** code MIT, data CC BY 4.0

Every industrial control system (ICS) and medical device advisory CISA has published in machine-readable CSAF form, {{snapshot.first_advisory_date}} to {{snapshot.last_advisory_date}}, parsed into three clean tables and joined to CISA's Known Exploited Vulnerabilities (KEV) catalog. It exists so that OT defenders, researchers and students can ask questions of the federal ICS advisory record with one `pandas.read_csv` instead of scraping 3,000+ web pages, and so that every normalization choice is visible and reversible.

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
python code/01_fetch.py --csaf-commit {{snapshot.csaf_commit}} --kev-commit {{snapshot.kev_commit}}
python code/02_build.py
python code/03_qa.py
python code/04_figures.py
python code/05_document.py
```

With the two pinned commits a stranger reproduces `data/processed/` exactly. Drop the flags (and add `--refresh`) to pull the current feeds.

## Sources

| Source | Snapshot | License | Accessed |
|---|---|---|---|
| CISA CSAF advisories, `csaf_files/OT/white` ([github.com/cisagov/CSAF](https://github.com/cisagov/CSAF)) | commit `{{snapshot.csaf_commit}}` ({{snapshot.csaf_commit_date}}) | US government work, public domain (17 U.S.C. 105); TLP:CLEAR | 2026-09-26 |
| CISA Known Exploited Vulnerabilities catalog ([github.com/cisagov/kev-data](https://github.com/cisagov/kev-data), official mirror of cisa.gov/kev) | catalog {{snapshot.kev_catalog_version}}, commit `{{snapshot.kev_commit}}` | CC0 1.0 | 2026-09-26 |

## Headline numbers (from `paper/stats.json`)

- {{counts.advisories}} advisories ({{counts.icsa}} ICSA, {{counts.icsma}} ICSMA medical), {{counts.links}} advisory-CVE links, {{counts.cves}} unique CVEs, {{counts.vendors_normalized}} vendors after normalizing {{counts.vendor_strings_raw}} raw vendor strings.
- Volume grew from {{growth.y2015}} advisories in 2015 to {{growth.y2025}} in 2025 ({{growth.ratio_2025_2015}}x). Siemens alone accounts for {{siemens_pct}}% of advisories.
- {{cvss.pct_high_or_critical}}% of scored CVEs are High or Critical; {{cvss.pct_network}}% are network-exploitable and {{cvss.pct_local}}% local.
- {{counts.kev_in_ics}} CVEs ({{kev.pct_of_ics_cves}}%) are in KEV. {{kev.third_party}} of those {{counts.kev_in_ics}} ({{kev.pct_third_party}}%) are third-party IT components (Cisco IOS, Windows, Chromium, Linux, PAN-OS, FortiOS) embedded in OT products, and for CVEs first advised after KEV launched, {{kev.post_launch_kev_before_advisory}} of {{kev.post_launch_n}} were already known-exploited when the ICS advisory appeared.

## Limitations

Read `docs/LIMITATIONS.md` before using or citing anything here.

## Code

https://github.com/foikwuogu/open-ics-advisory-dataset

## Citation

See `CITATION.cff`. DOI: [10.5281/zenodo.22985480](https://doi.org/10.5281/zenodo.22985480) (reserved on Zenodo; resolves once the record is published).

## AI assistance

Code, parsing and first drafts of documentation were produced with AI assistance (Claude). The author made the analytic decisions and verified the outputs against the sources listed in `docs/VERIFY_CHECKLIST.md`.
