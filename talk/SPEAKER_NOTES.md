> **DRAFT, unverified.** Generated from `paper/stats.json`; do not cite or submit until `docs/VERIFY_CHECKLIST.md` is complete.

# Speaker notes: Building an Open ICS Vulnerability Dataset from Federal Sources

25-minute run (about 22 minutes talking plus 3 of Q&A), delivered online via Microsoft Teams. Times are cumulative. The **55-min** notes say what to add for the long slot. Every number here comes from `paper/stats.json`; re-render before the event.

## Delivering on Teams

- **Before the day:** join the organizers' test call; confirm who controls the recording and whether chat questions will be relayed to you. Send them a PDF export of the deck (Share › Export) as a fallback.
- **Share the right thing:** share only the browser window with the deck in Present mode, not your whole screen, so notifications stay private. Keep these notes on a second screen or on paper; Teams viewers only see the shared window.
- **Camera:** on for slide 1 and for Q&A; off while screen-sharing if bandwidth is thin.
- **Pace for remote viewers:** say the slide number when you change slides ("slide 10, the KEV finding"). Pause two seconds after each chart, because remote video lags.
- **Q&A:** ask people to type questions in the Teams chat during the talk; read each question aloud before answering so it lands in the recording.
- **55-min live demo:** share the terminal window separately, font 20pt+; have a pre-recorded fallback in case the network drops.
- **Backup:** if Teams drops you, rejoin from your phone on audio and ask the host to screen-share the PDF.

---

### 1. Title (0:00)
Camera on. Name, affiliation, one line: "I turned 16 years of CISA ICS advisories into a table anyone can download, and the table told me something I didn't expect about exploitation."

### 2. The federal ICS record is pages, not data (0:45)
- CISA has published 3,937 ICS and medical advisories since 2010-02-27. Every one is also CSAF 2.0 JSON in a public GitHub repo.
- Most teams still consume them as web pages or email. You can't ask a web page "how many of these are known-exploited?"
- Goal: an open, reproducible table. Free sources only, no API keys, anyone can rerun it.

### 3. Two sources, both via git (2:30)
- `cisagov/CSAF`, OT/white folder: 3,937 advisories. Sparse checkout, a few seconds.
- `cisagov/kev-data`: the official KEV mirror, 1,726 entries at catalog 2026.09.25.
- Why git? You get a commit hash, which is a citation. Rerun with the hash and you get the same bytes.
- Honest note: NVD and EPSS are on the v0.2 list. The findings today rest on CISA data alone.

### 4. Pipeline (4:00)
fetch (provenance log) → parse CSAF → normalize vendors & sectors → join KEV by CVE → QA hard checks → `stats.json` → figures and docs rendered from stats.
- Three tables: 3,937 advisories, 14,487 advisory-CVE links, 12,346 CVEs.
- Rule: no number is typed into a slide. The slides and this abstract are generated from the stats file.
- **55-min:** live demo. Clone, run the five scripts, open `qa_report.txt`.

### 5. Growth (6:00), fig1
- 137 advisories in 2015, 489 in 2025: 3.6x. 2026 has 378 so far.
- Caveat to say out loud: year = the date on the advisory, and republished vendor advisories keep the vendor's date (slide 7).

### 6. Trap 1: who is the vendor? (7:30)
- 883 raw vendor strings → 848 after normalization. "GE" vs "General Electric (GE)", "Schneider Electric Software, LLC", "Johnson Controls Inc" vs "Inc.", and "Phillips" with two Ls on a Philips medical advisory.
- 19 strings name several companies at once. I left them unsplit and said so.
- Rule: merge spellings, never merge corporate history (Invensys stays Invensys).

### 7. Traps 2–5: dates, sectors, scores, one giant advisory (9:00)
- Dates: 71 advisories have an ID year that disagrees with their date. Example ICSA-25-294-03, released 2011 by date, ID from 2025. CISA republishes vendor CSAFs with the original dates.
- Sectors: free text, typos ("Critical Manuacturing"), and missing from 99.5% of pre-2017 advisories.
- CVSS: three versions mixed (3.1, 3.0, 2.0); 287 CVEs unscored. Rule: newest version, then highest score.
- ICSA-23-348-10 (Siemens SIMATIC S7-1500) lists 544 CVEs, all in an embedded GNU/Linux subsystem. The median advisory lists 1. Count CVEs and you are partly counting Linux.
- **55-min:** show the diff of the QA report before and after each fix.

### 8. Who shows up (11:00), fig2
- Siemens: 26.5% of all advisories. The top five vendors appear in 45.8%, and 601 vendors appear exactly once.
- Say it plainly: this measures disclosure volume and PSIRT maturity, not who is least secure.

### 9. What kind of bugs (12:30), fig5
- 60.8% High/Critical, median base 7.5.
- 60% network, 32.7% local. Most of the local share is embedded Linux and component bugs in firmware, plus file-parsing bugs in engineering tools.
- Top CWE: CWE-20 Improper Input Validation, then Out-of-bounds Write and Out-of-bounds Read.

### 10. The KEV finding (14:30), fig3
- Only 117 of 12,346 ICS-advisory CVEs are in KEV (0.9%).
- 100 of the 117 (85.5%) are third-party IT components: Cisco (15), Microsoft (13), Google (12), Linux (11), PAN-OS and FortiOS inside ruggedized appliances.
- Examples: Windows SMBv1 (EternalBlue) in a Philips medical advisory; FortiOS CVE-2022-42475 in a Siemens RUGGEDCOM APE1808 advisory.
- Known-exploited CVEs are Critical 39.8% of the time vs 13.9% for the rest, but 14 KEV CVEs score below 7.0. CVSS alone would have deprioritized them.

### 11. Timing (17:00), fig4
- KEV started Nov 2021, so look only at CVEs first advised after that: 76 CVEs.
- 51 of 76 were already in KEV when the ICS advisory published. Median: -28 days (negative = KEV first).
- Interpretation: for embedded IT, the OT advisory is a lagging signal. The exploitation signal was public first.

### 12. What to do Monday (19:00)
- Get an SBOM or component list for OT assets (appliances, HMIs, engineering workstations), even a spreadsheet.
- Watch KEV for those component vendors (Cisco, Microsoft, Linux, Fortinet, Palo Alto, Chromium), not only for your OT vendor's name.
- When KEV lists a component, ask your OT vendor about exposure before their advisory lands.
- Use the dataset: `cves.csv` filtered to `in_kev == 1` is a ready-made watch list.

### 13. Limits, reproduce, contribute (21:00)
- The big three: CISA coverage only; KEV is a floor; third-party is a heuristic. The full list is `docs/LIMITATIONS.md`.
- Repo and DOI on screen; MIT code, CC BY 4.0 data.
- v0.2 wants NVD/EPSS joins, vendor-map review from people who know the vendors, and CVSS v4.
- Credit co-authors. Camera back on for Q&A; read each chat question aloud.

### Likely questions
- *Why not NVD?* Coverage and rate limits; CISA's own scores are what the advisory tells operators. NVD is in v0.2 as a comparison.
- *Is Siemens worst?* No. It's the most transparent at volume, and CISA republishes its advisories.
- *Is KEV representative of OT exploitation?* No, it's a confirmed-exploitation floor. Absence isn't safety.
