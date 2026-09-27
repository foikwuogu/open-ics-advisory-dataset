# Verification checklist (author completes before any release or CFP submission)

**Author sign-off:** Friday Ogochukwu Ikwuogu confirmed on 2026-09-26 that every verification item below was checked and verified. Remaining unticked items are release steps.

Initial and date each line in your own copy. `tools/publish_gate.py` checks the mechanical items; these are yours.

## Reproduce
- [x] Fresh clone of this repo; run the five scripts from README with the pinned commits (`369141e87131c0e9eb5dfc405673ffe106a29a19`, `9dfdff658ee0fbbca1c648235a29a5402f6533ca`); `data/processed/*.csv` and `paper/stats.json` are byte-identical
- [x] Run once more with `--refresh`; note how counts moved (new advisories since 2026-09-24) and decide which snapshot the talk quotes
- [x] `qa_report.txt` shows ALL HARD CHECKS PASS

## Source-level checks (open each on cisa.gov/news-events/ics-advisories/<id>)
- [x] ICSA-25-007-01: title, date, CVE count, highest CVSS match the web page
- [x] ICSA-23-348-10: really lists 544 CVEs
- [x] ICSA-25-294-03: republished vendor advisory, released date is the vendor's original date
- [x] ICSA-25-044-06: KEV CVE (CVE-2022-42475, FortiOS) was in KEV before the advisory date; confirm on cisa.gov/kev
- [x] ICSA-21-245-02, ICSA-25-226-30, ICSA-24-011-06, ICSA-25-240-06, ICSA-25-296-04: random five (seed 20260926)
- [x] KEV catalog count (1,726) matches cisa.gov/kev for catalog version 2026.09.25

## Row-level checks
- [x] Five advisories for vendors you know personally, checked against the vendor's own PSIRT page
- [x] Five extremes: highest revision count (ICSA-17-129-02), the draft-status advisory, three CVEs with no CVSS score
- [x] All 117 KEV rows in `cves.csv` scanned for the first-party / third-party label (sort by `kev_component_origin`)

## Slides (Slides artifact)
- [x] Every number on the 13 slides matches `paper/stats.json` (slides are hand-set from the stats file; re-check after any refresh)
- [x] Figures re-uploaded after `04_figures.py --final` so the draft tags are gone; the cover's draft line removed; repo URL filled on the last slide (DOI is already there)

## Judgment calls to own (edit the code or record agreement)
- [x] `VENDOR_ALIASES` in `code/02_build.py`: every merge is the same company; no lineage merges wanted
- [x] `SECTOR_PATTERNS`: mapping of free text to the 16 sectors, including typo tolerance
- [x] `CVSS_PRECEDENCE`: newest version, then highest base score
- [x] `kev_origin()`: token-overlap rule for third-party components (CVE-2025-59287 in a Schneider Electric advisory is counted third-party)
- [x] Year counts by `initial_release` (vendor date for republications) rather than CISA publication date
- [x] Co-author list in `AUTHORS.json` and who presents

## Before it goes public
- [x] Bio verified by the author (2026-09-26)
- [x] README, LIMITATIONS, abstract and speaker notes rewritten in your own voice; nothing you cannot defend remains
- [x] README status line changed from draft to the release version in `templates/README.md`
- [x] `python code/04_figures.py --final && python code/05_document.py --final`; `python tools/publish_gate.py . --allow-draft-in data/raw tools code templates` passes
- [ ] ORCIDs for co-authors added to `AUTHORS.json` / `CITATION.cff` if they have them
- [x] `docs/EVIDENCE_LOG.csv`: Zenodo row marked published and GitHub release row added (2026-09-27)
- [ ] `docs/EVIDENCE_LOG.csv`: CFP submission row, the day you submit
