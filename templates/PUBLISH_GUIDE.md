# Publish guide: Open ICS Advisory Dataset v0.1.0 + BSides talk

Do these in order, in one sitting, **after** `docs/VERIFY_CHECKLIST.md` is complete. Nothing was pushed or submitted on your behalf.

## 0. Finalize (5 min)
1. Fill your GitHub repository URL into `CITATION.cff` (`repository-code`) and `zenodo.json` (`related_identifiers`), and the `date-released` field. The DOI goes into `CITATION.cff` after step 2.
2. Edit the status line in `templates/README.md` (draft → `v0.1.0, released <date>`).
3. `python code/04_figures.py --final && python code/05_document.py --final`
4. `python tools/publish_gate.py . --allow-draft-in data/raw tools code templates` must print a pass. Fix anything it lists.

## 1. GitHub (10 min; automatable)
1. Create a token at github.com → Settings → Developer settings → Fine-grained tokens, with repository create and contents read/write scopes. Keep it only in your shell: `export GITHUB_TOKEN=...`
2. `python tools/publish_github.py . --repo open-ics-advisory-dataset --description "Open, reproducible dataset of CISA ICS advisories joined to KEV" --release v0.1.0`
3. The processed CSVs total about 5 MB and are committed. `data/raw/` is git-ignored; users re-fetch it with pinned commits.
4. Revoke the token when done.

## 2. Zenodo (reserved DOI 10.5281/zenodo.22985480; you finish it in the web UI)
The DOI is already reserved on a Zenodo draft. **Do not run `tools/zenodo_deposit.py`**: it creates a new deposition and would mint a second, different DOI.
1. Build the archive: `zip -r release.zip README.md LICENSE CITATION.cff AUTHORS.json requirements.txt code templates tools data/processed data/raw/PROVENANCE.txt docs paper talk`
2. Open the draft on zenodo.org (Upload → your draft). Upload `release.zip`, removing any earlier file on the draft.
3. Check the metadata against `AUTHORS.json` and `zenodo.json`: title "Open ICS Advisory Dataset (OICSAD) v0.1.0"; creators in this order with exact spelling: Ikwuogu, Friday Ogochukwu (ORCID {{author.orcid}}); Orimogunje, Abidemi; Pinyi, Eria Othieno; Mike-Ewewie, David; resource type Dataset; license CC BY 4.0; version 0.1.0; related identifier = the GitHub URL (isSupplementedBy).
4. Publish. Confirm https://doi.org/10.5281/zenodo.22985480 resolves, then save a PDF of the record page.
5. Later versions: use "New version" on this record so the concept DOI stays stable.

## 3. BSides CFP (15 min; you submit)
1. Check each site for the open call, and confirm the event accepts remote (Teams) speakers, since both BSides events are normally in person: bsidesaustin.com/cfp (Austin, Dec 2026) and bsidessatx.com → Call for Presenters (San Antonio, June 2027; pretalx at cfp.bsidessatx.com).
2. Re-run the pipeline with `--refresh` the day you submit and re-render, so the abstract's numbers are current. Commit that snapshot.
3. Paste from `talk/ABSTRACT.md`: title, abstract (public), description/outline (reviewers), bio, 25-minute format. Check the form's word or character limits against the counts in the file.
4. Speaker: {{author.name}}, {{author.email}}. Add a co-speaker only if they will present. Upload `talk/headshot.jpg` where the form asks for a photo, and select the remote/virtual option (Microsoft Teams).
5. Link the GitHub repo and DOI in the notes-to-reviewers field.
6. Save the confirmation email/ID. Write the evidence-log row the same day.

## 4. Before the talk (Teams)
- Join the organizers' Teams test call; confirm recording, chat relay and who keeps time.
- Export the deck to PDF (Share › Export) and send it to the organizers as a fallback.

## 5. After the talk
- Upload the final slides PDF to Zenodo as a `presentation` record linked to the dataset DOI (`isSupplementTo`), and add the recording URL when BSides posts it.
- Log each item: date, artifact, venue, URL/DOI, status.

Evidence-log row format:
`date,artifact_or_event,type,venue_or_host,link_or_doi,status,prong_tags,metrics_snapshot,files_saved,notes`
