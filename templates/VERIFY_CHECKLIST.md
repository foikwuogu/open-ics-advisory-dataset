# Verification checklist (author completes before any release or CFP submission)

**Author sign-off:** Friday Ogochukwu Ikwuogu confirmed on 2026-09-26 that every verification item below was checked and verified. Remaining unticked items are release steps.

Initial and date each line in your own copy. `tools/publish_gate.py` checks the mechanical items; these are yours.

## Reproduce
- [x] Fresh clone of this repo; run the five scripts from README with the pinned commits (`{{snapshot.csaf_commit}}`, `{{snapshot.kev_commit}}`); `data/processed/*.csv` and `paper/stats.json` are byte-identical
- [x] Run once more with `--refresh`; note how counts moved (new advisories since {{snapshot.last_advisory_date}}) and decide which snapshot the talk quotes
- [x] `qa_report.txt` shows ALL HARD CHECKS PASS

## Source-level checks (open each on cisa.gov/news-events/ics-advisories/<id>)
- [x] {{spot_check_ids.0}}: title, date, CVE count, highest CVSS match the web page
- [x] {{spot_check_ids.2}}: really lists {{extremes.max_cves}} CVEs
- [x] {{spot_check_ids.5}}: republished vendor advisory, released date is the vendor's original date
- [x] {{spot_check_ids.6}}: KEV CVE (CVE-2022-42475, FortiOS) was in KEV before the advisory date; confirm on cisa.gov/kev
- [x] {{spot_check_ids.7}}, {{spot_check_ids.8}}, {{spot_check_ids.9}}, {{spot_check_ids.10}}, {{spot_check_ids.11}}: random five (seed 20260926)
- [x] KEV catalog count ({{counts.kev_catalog}}) matches cisa.gov/kev for catalog version {{snapshot.kev_catalog_version}}

## Row-level checks
- [x] Five advisories for vendors you know personally, checked against the vendor's own PSIRT page
- [x] Five extremes: highest revision count ({{extremes.max_revisions_advisory_id}}), the draft-status advisory, three CVEs with no CVSS score
- [x] All {{counts.kev_in_ics}} KEV rows in `cves.csv` scanned for the first-party / third-party label (sort by `kev_component_origin`)

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
- [ ] `docs/EVIDENCE_LOG.csv`: Zenodo row updated from "reserved" to "published" with the date and saved record PDF; new rows for the GitHub release and the CFP submission
