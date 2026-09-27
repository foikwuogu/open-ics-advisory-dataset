# Codebook

All tables are UTF-8 CSV in `data/processed/`. Empty cell = not present in the source. Source fields refer to CSAF 2.0 JSON paths in `cisagov/CSAF` and to fields of the KEV JSON.

## advisories.csv (one row per advisory)

| Column | Definition | Source / transformation |
|---|---|---|
| advisory_id | CISA advisory ID, e.g. ICSA-25-007-01 | `document.tracking.id`, upper-cased |
| advisory_type | ICSA (industrial) or ICSMA (medical) | prefix of advisory_id |
| title | Advisory title | `document.title`, whitespace collapsed |
| initial_release | First release date (YYYY-MM-DD) | `tracking.initial_release_date`; the vendor's date for republished CSAFs |
| current_release | Latest revision date | `tracking.current_release_date` |
| release_year | Year of initial_release | derived |
| id_year | Year encoded in the ID (ICSA-**25**-…) | derived |
| id_year_mismatch | 1 if id_year ≠ release_year | derived |
| revision_count | Entries in revision history | `len(tracking.revision_history)` |
| tracking_status | final / draft | `tracking.status` |
| publisher_category | coordinator / other | `document.publisher.category` |
| republished_or_converted | 1 if a note says republication/republished/"converted from" a vendor advisory | `document.notes[*].text` |
| vendor | Normalized vendor(s), "; "-separated, product-tree order | `product_tree.branches[category=vendor].name` → `normalize_vendor()` |
| vendor_raw | Vendor strings as published | same, unmodified |
| n_vendors | Count of normalized vendors | derived |
| sectors | PPD-21 sectors matched, "; "-separated | "Critical infrastructure sectors" note → `SECTOR_PATTERNS` |
| sector_multiple | 1 if the note says "Multiple" / "all sectors" | same note |
| sectors_raw | The sector note text | as published |
| countries_deployed_raw | "Countries/areas deployed" note | as published |
| hq_location_raw | "Company headquarters location" note | as published |
| n_cves | CVEs in the advisory | count of `vulnerabilities[*].cve` |
| max_cvss_base | Highest CVSS base score across its CVEs | from advisory_cves.cvss_base |
| any_critical | 1 if any CVE is Critical | derived |
| any_network_av | 1 if any CVE has network attack vector | derived |
| n_kev_cves | CVEs in the KEV catalog | join on CVE ID |
| any_no_fix | 1 if any CVE is marked none_available / no_fix_planned without a vendor_fix | derived |
| exploit_statement | no_known_public_exploits / public_exploits_reported / other / empty | "Exploitability" note, keyword rules |
| source_file | Path of the CSAF JSON under data/raw | derived |

## advisory_cves.csv (one row per advisory × CVE)

| Column | Definition | Source / transformation |
|---|---|---|
| advisory_id, cve | Keys | `vulnerabilities[*].cve` |
| advisory_initial_release | Date of the advisory | from advisories |
| cwe_id, cwe_name | Weakness | `vulnerabilities[*].cwe` |
| cvss_version | 3.1 / 3.0 / 2.0 | newest version present (`CVSS_PRECEDENCE`) |
| cvss_base | Base score | highest base score within that version |
| cvss_severity | NONE/LOW/MEDIUM/HIGH/CRITICAL | v3 `baseSeverity` (or computed from score); v2 NVD bands (LOW <4, MEDIUM <7, HIGH) |
| cvss_vector | Vector string | as published |
| attack_vector | NETWORK / ADJACENT_NETWORK / LOCAL / PHYSICAL | parsed from `AV:` in the vector string |
| n_products_known_affected | Product IDs in `product_status.known_affected` | count |
| remediation_categories | "; "-separated categories | `remediations[*].category` |
| fix_available | 1 if any remediation is vendor_fix | derived |
| no_fix | 1 if none_available or no_fix_planned and no vendor_fix | derived |
| in_kev | 1 if CVE is in KEV | KEV `cveID` |
| kev_date_added | KEV `dateAdded` | KEV |
| kev_known_ransomware | KEV `knownRansomwareCampaignUse` (Known / Unknown) | KEV |

## cves.csv (one row per CVE)

| Column | Definition | Source / transformation |
|---|---|---|
| cve, cve_year | CVE ID and its year | |
| first_advisory_id, first_advisory_date | Earliest advisory carrying the CVE | min over advisory_cves by date, then ID |
| n_advisories | Advisories carrying the CVE | count |
| vendor | Normalized vendor(s) of the first advisory | from advisories |
| cwe_id | Most common CWE across its advisories | mode |
| cvss_version, cvss_base, cvss_severity, attack_vector | Best score across advisories | same precedence rule |
| fix_available_any | 1 if any advisory lists a vendor_fix | derived |
| no_fix_all | 1 if every advisory marks it no-fix | derived |
| in_kev, kev_date_added, kev_known_ransomware | KEV fields | KEV |
| kev_vendor_project, kev_product | Vendor and product as KEV names them | KEV |
| kev_component_origin | first_party / third_party (KEV CVEs only) | `kev_origin()`: token overlap between KEV vendorProject and the first advisory's first-listed raw vendor |
| days_first_advisory_to_kev | kev_date_added − first_advisory_date, in days; negative = in KEV before the ICS advisory | derived |

## vendor_map.csv

| Column | Definition |
|---|---|
| vendor_raw | Vendor string as published |
| vendor | Normalized name used in the tables |
| rule | alias / alias(parenthetical) / suffix-stripped / unchanged |
| n_advisories | Advisories using this raw string |
