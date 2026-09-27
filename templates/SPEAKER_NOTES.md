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
- CISA has published {{counts.advisories}} ICS and medical advisories since {{snapshot.first_advisory_date}}. Every one is also CSAF 2.0 JSON in a public GitHub repo.
- Most teams still consume them as web pages or email. You can't ask a web page "how many of these are known-exploited?"
- Goal: an open, reproducible table. Free sources only, no API keys, anyone can rerun it.

### 3. Two sources, both via git (2:30)
- `cisagov/CSAF`, OT/white folder: {{counts.advisories}} advisories. Sparse checkout, a few seconds.
- `cisagov/kev-data`: the official KEV mirror, {{counts.kev_catalog}} entries at catalog {{snapshot.kev_catalog_version}}.
- Why git? You get a commit hash, which is a citation. Rerun with the hash and you get the same bytes.
- Honest note: NVD and EPSS are on the v0.2 list. The findings today rest on CISA data alone.

### 4. Pipeline (4:00)
fetch (provenance log) → parse CSAF → normalize vendors & sectors → join KEV by CVE → QA hard checks → `stats.json` → figures and docs rendered from stats.
- Three tables: {{counts.advisories}} advisories, {{counts.links}} advisory-CVE links, {{counts.cves}} CVEs.
- Rule: no number is typed into a slide. The slides and this abstract are generated from the stats file.
- **55-min:** live demo. Clone, run the five scripts, open `qa_report.txt`.

### 5. Growth (6:00), fig1
- {{growth.y2015}} advisories in 2015, {{growth.y2025}} in 2025: {{growth.ratio_2025_2015}}x. 2026 has {{growth.y2026_to_date}} so far.
- Caveat to say out loud: year = the date on the advisory, and republished vendor advisories keep the vendor's date (slide 7).

### 6. Trap 1: who is the vendor? (7:30)
- {{counts.vendor_strings_raw}} raw vendor strings → {{counts.vendors_normalized}} after normalization. "GE" vs "General Electric (GE)", "Schneider Electric Software, LLC", "Johnson Controls Inc" vs "Inc.", and "Phillips" with two Ls on a Philips medical advisory.
- {{quality.multi_company_vendor_strings}} strings name several companies at once. I left them unsplit and said so.
- Rule: merge spellings, never merge corporate history (Invensys stays Invensys).

### 7. Traps 2–5: dates, sectors, scores, one giant advisory (9:00)
- Dates: {{quality.id_year_mismatch}} advisories have an ID year that disagrees with their date. Example {{spot_check_ids.5}}, released 2011 by date, ID from 2025. CISA republishes vendor CSAFs with the original dates.
- Sectors: free text, typos ("Critical Manuacturing"), and missing from {{quality.sector_note_missing_pre2017}}% of pre-2017 advisories.
- CVSS: three versions mixed (3.1, 3.0, 2.0); {{cvss.unscored_cves}} CVEs unscored. Rule: newest version, then highest score.
- {{extremes.max_cves_advisory_id}} ({{extremes.max_cves_advisory_title}}) lists {{extremes.max_cves}} CVEs, all in an embedded GNU/Linux subsystem. The median advisory lists {{extremes.median_cves_per_advisory}}. Count CVEs and you are partly counting Linux.
- **55-min:** show the diff of the QA report before and after each fix.

### 8. Who shows up (11:00), fig2
- Siemens: {{siemens_pct}}% of all advisories. The top five vendors appear in {{top5_vendor_pct}}%, and {{vendors_single_advisory}} vendors appear exactly once.
- Say it plainly: this measures disclosure volume and PSIRT maturity, not who is least secure.

### 9. What kind of bugs (12:30), fig5
- {{cvss.pct_high_or_critical}}% High/Critical, median base {{cvss.median_base}}.
- {{cvss.pct_network}}% network, {{cvss.pct_local}}% local. Most of the local share is embedded Linux and component bugs in firmware, plus file-parsing bugs in engineering tools.
- Top CWE: {{cwe_top10.0.cwe}} {{cwe_top10.0.name}}, then {{cwe_top10.1.name}} and {{cwe_top10.2.name}}.

### 10. The KEV finding (14:30), fig3
- Only {{counts.kev_in_ics}} of {{counts.cves}} ICS-advisory CVEs are in KEV ({{kev.pct_of_ics_cves}}%).
- {{kev.third_party}} of the {{counts.kev_in_ics}} ({{kev.pct_third_party}}%) are third-party IT components: {{kev.component_vendors_top.0.vendor}} ({{kev.component_vendors_top.0.cves}}), {{kev.component_vendors_top.1.vendor}} ({{kev.component_vendors_top.1.cves}}), {{kev.component_vendors_top.2.vendor}} ({{kev.component_vendors_top.2.cves}}), {{kev.component_vendors_top.3.vendor}} ({{kev.component_vendors_top.3.cves}}), PAN-OS and FortiOS inside ruggedized appliances.
- Examples: Windows SMBv1 (EternalBlue) in a Philips medical advisory; FortiOS CVE-2022-42475 in a Siemens RUGGEDCOM APE1808 advisory.
- Known-exploited CVEs are Critical {{kev.pct_critical_among_kev}}% of the time vs {{kev.pct_critical_among_nonkev}}% for the rest, but {{kev.kev_below_high}} KEV CVEs score below 7.0. CVSS alone would have deprioritized them.

### 11. Timing (17:00), fig4
- KEV started Nov 2021, so look only at CVEs first advised after that: {{kev.post_launch_n}} CVEs.
- {{kev.post_launch_kev_before_advisory}} of {{kev.post_launch_n}} were already in KEV when the ICS advisory published. Median: {{kev.post_launch_median_days}} days (negative = KEV first).
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
