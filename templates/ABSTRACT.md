# BSides CFP kit

**Targets:** BSides Austin (December 2026; dates and CFP not yet posted as of 2026-09-26, and past CFPs closed in early October) and BSides San Antonio / BSidesSATX (June 2027; CFP not yet open, submissions via cfp.bsidessatx.com). Paste the fields below into whichever call opens first. Re-run the pipeline before submitting so the numbers match that day's feeds.

## Title

Building an Open ICS Vulnerability Dataset from Federal Sources

*Optional subtitle if the form allows one:* What {{counts.advisories}} CISA advisories say about which OT bugs actually get exploited

## Format

Talk, 25 minutes including Q&A, **delivered online via Microsoft Teams** (remote presentation; tick the virtual/remote option if the form has one, or state it in the notes to reviewers). BSides Austin has offered 25- and 55-minute slots; the 55-minute version adds a live walkthrough of the pipeline, see `SPEAKER_NOTES.md`. Level: beginner to intermediate. Track: OT/ICS, vulnerability management, or data.

## Abstract (public, {{abstract_words}} words)

CISA has published {{counts.advisories}} ICS and medical-device advisories since 2010, and every one now exists as machine-readable CSAF JSON. Yet most OT teams still read them one web page at a time. This talk shows how to turn the federal record into an open, reproducible dataset using only free public sources and git: CISA's CSAF repository and the Known Exploited Vulnerabilities (KEV) catalog.

We'll walk through the pipeline and the mess it has to clean up: {{counts.vendor_strings_raw}} vendor spellings (including a misspelled "Phillips"), republished advisories dated years before their IDs, free-text sector fields with typos, and one advisory carrying {{extremes.max_cves}} CVEs. Then we ask the data a question that matters to defenders. Of the {{counts.cves}} CVEs in ICS advisories, only {{counts.kev_in_ics}} are known-exploited, and {{kev.third_party}} of those are IT components such as Cisco IOS, Windows, Chromium, Linux, PAN-OS and FortiOS shipped inside OT products. And for CVEs first advised since KEV launched in 2021, {{kev.post_launch_kev_before_advisory}} of {{kev.post_launch_n}} were already on KEV when the ICS advisory came out.

You'll leave with the dataset, the code, and a concrete habit: watch KEV for the IT inside your OT, not just for your OT vendor's name.

## Description for reviewers (not public)

This is a practitioner talk built around an open dataset I built and released (GitHub + Zenodo, DOI 10.5281/zenodo.22985480; MIT code / CC BY 4.0 data). It is not a product or vendor pitch.

The build uses two CISA sources fetched with git and pinned to commits: `cisagov/CSAF` (`csaf_files/OT/white`, {{counts.advisories}} advisories, {{snapshot.first_advisory_date}} to {{snapshot.last_advisory_date}}) and `cisagov/kev-data` (catalog {{snapshot.kev_catalog_version}}, {{counts.kev_catalog}} entries). It produces advisory-, advisory-CVE- and CVE-level tables with a QA report and a stats file from which every number in the slides is generated.

Findings the talk presents:
- Advisory volume grew {{growth.ratio_2025_2015}}x from 2015 ({{growth.y2015}}) to 2025 ({{growth.y2025}}); Siemens accounts for {{siemens_pct}}% of advisories.
- {{cvss.pct_high_or_critical}}% of scored CVEs are High or Critical. {{cvss.pct_local}}% are local attack vector. Most of those are embedded Linux kernel and third-party component bugs in device firmware (Siemens S7-1500 MFP and SINEC OS advisories dominate), plus file-parsing bugs in engineering software. That changes how defenders should read "ICS vulnerability".
- {{counts.kev_in_ics}} of {{counts.cves}} CVEs ({{kev.pct_of_ics_cves}}%) are in KEV. {{kev.pct_third_party}}% of those are third-party IT components. Among CVEs first advised after KEV launched, {{kev.post_launch_kev_before_advisory}} of {{kev.post_launch_n}} were in KEV before the ICS advisory, with a median gap of {{kev.post_launch_median_days}} days (negative = KEV first).

Outline (25 min):
1. (3) Why the federal ICS record should be a table, and why git beats scraping
2. (6) Pipeline: fetch, parse CSAF, normalize, join KEV, QA, stats-driven docs
3. (5) Five data-quality traps and how the pipeline handles each
4. (7) Findings: volume, vendors, severity and attack vector, the KEV component finding
5. (2) What defenders can do Monday: SBOM-to-KEV watching for OT assets
6. (2) Limitations, how to reproduce, how to contribute

Prior presentation: none. Everything shown is public data; no vulnerabilities are disclosed.

Delivery: remote, via Microsoft Teams, with camera and screen share. The speaker will send a PDF of the slides to organizers in advance as a fallback.

## Speaker

{{author.name}}, {{author.affiliation}}. ORCID {{author.orcid}}. {{author.email}}. Website: https://foikwuogu.github.io/

**Headshot:** `talk/headshot.jpg` (500×500 JPEG from foikwuogu.github.io, for forms that ask for a speaker photo); `talk/headshot_circle.png` (transparent round crop used on the slides).

**Bio ({{bio_words}} words; verified by the author 2026-09-26):** Friday Ogochukwu Ikwuogu is an independent researcher in Odessa, Texas, with a master's degree in Computer Science and Information Technology. Friday's work focuses on networking, telecommunications and operational-technology security, and on building open, reproducible datasets from public federal sources that defenders and students can reuse.

Dataset authors (credit on the dataset and slides' final page):
{{coauthors_md}}
