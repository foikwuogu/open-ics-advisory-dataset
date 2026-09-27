#!/usr/bin/env python3
"""03_qa.py: QA checks + the stats file every document reads from.

Writes:
  data/processed/qa_report.txt   row counts, match rates, sanity checks, named spot checks
  paper/stats.json               every number quoted in README, abstract, slides, notes
Exit code 1 if a hard check fails.
"""
import json
import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "data" / "processed"
KEV_JSON = ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"
PROV = ROOT / "data" / "raw" / "PROVENANCE.txt"
KEV_LAUNCH = "2021-11-03"   # BOD 22-01 established the KEV catalog
SEED = 20260926

a = pd.read_csv(P / "advisories.csv", dtype={"sectors": str})
a["vendor"] = a.vendor.fillna("")
l = pd.read_csv(P / "advisory_cves.csv")
c = pd.read_csv(P / "cves.csv")
vm = pd.read_csv(P / "vendor_map.csv")
kev = json.load(open(KEV_JSON))

out, fails = [], []


def say(s=""):
    out.append(s)


def check(cond, msg):
    say(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def pct(x, n):
    return round(100 * x / n, 1) if n else 0.0


# ------------------------------------------------------------------ provenance
prov = PROV.read_text().strip().splitlines()[-2:]
csaf_commit = re.search(r"commit (\w+) \(([^)]+)\)", prov[0])
kev_commit = re.search(r"commit (\w+) \(([^)]+)\)", prov[1])

# ------------------------------------------------------------------ hard checks
say("QA REPORT: Open ICS Advisory Dataset")
say("=" * 64)
say(f"CSAF commit {csaf_commit.group(1)} ({csaf_commit.group(2)})")
say(f"KEV  commit {kev_commit.group(1)} ({kev_commit.group(2)}), catalogVersion {kev['catalogVersion']}")
say()
say("[1] Row counts")
n_files = int(re.search(r"\((\d+) files\)", prov[0]).group(1))
say(f"  advisory JSON files fetched : {n_files}")
say(f"  advisories.csv              : {len(a)}")
say(f"  advisory_cves.csv           : {len(l)}")
say(f"  cves.csv                    : {len(c)}")
say(f"  vendor_map.csv (raw strings): {len(vm)}")
check(len(a) == n_files, "one advisory row per fetched file (no rows lost)")
check(a.advisory_id.is_unique, "advisory_id unique")
check(not l.duplicated(["advisory_id", "cve"]).any(), "no duplicate (advisory, CVE) pairs")
check(c.cve.is_unique, "cve unique in cves.csv")
check(l.cve.str.match(r"^CVE-\d{4}-\d{4,}$").all(), "every CVE id well-formed")
check(set(l.advisory_id) <= set(a.advisory_id), "every link points to an existing advisory")
check(a.n_cves.sum() == len(l), "sum of advisories.n_cves equals link rows")
check(c.n_advisories.sum() == len(l), "sum of cves.n_advisories equals link rows")
say()

say("[2] Ranges and sanity")
sc = l.cvss_base.dropna()
check(sc.between(0, 10).all(), f"CVSS base in [0,10] (min {sc.min()}, max {sc.max()})")
check(a.initial_release.between("2010-01-01", "2026-12-31").all(), "initial release dates within 2010-2026")
check((a.current_release >= a.initial_release).all(), "current_release >= initial_release")
check(a.revision_count.min() >= 1, "every advisory has >=1 revision")
kev_ids = {v["cveID"] for v in kev["vulnerabilities"]}
check(c[c.in_kev == 1].cve.isin(kev_ids).all() and not c[c.in_kev == 0].cve.isin(kev_ids).any(), "KEV flag agrees with catalog")
no_score = int(c.cvss_base.isna().sum())
say(f"  CVEs with no CVSS score in any advisory: {no_score} ({pct(no_score, len(c))}%)")
say(f"  advisories with id-year != release-year : {int(a.id_year_mismatch.sum())} (republished/converted: {int(a[a.id_year_mismatch==1].republished_or_converted.sum())})")
say(f"  advisories in tracking status 'draft'   : {int((a.tracking_status=='draft').sum())} -> {a[a.tracking_status=='draft'].advisory_id.tolist()}")
say()

say("[3] Normalization and match rates")
nv = a.vendor.str.split("; ").explode()
nv = nv[nv != ""]
say(f"  advisories with no vendor branch in product_tree: {int((a.vendor == '').sum())}")
say(f"  vendor strings raw -> normalized        : {len(vm)} -> {nv.nunique()}")
say(f"  rules applied: {vm.rule.value_counts().to_dict()}")
multi = vm[vm.vendor_raw.str.contains(r",.*\b(?:Inc|LLC|Ltd|GmbH|AG)\b.*,|, [A-Z][a-z]+ [A-Z]", regex=True)]
say(f"  raw vendor strings that look like several companies (left unsplit): {len(multi)}")
has_sector_note = a.sectors_raw.notna()
mapped = a.sectors.notna() | (a.sector_multiple == 1)
say(f"  advisories with a sector note           : {int(has_sector_note.sum())} ({pct(has_sector_note.sum(), len(a))}%)")
say(f"  ...of which mapped to >=1 PPD-21 sector or 'Multiple': {int((has_sector_note & mapped).sum())} ({pct((has_sector_note & mapped).sum(), has_sector_note.sum())}%)")
say(f"  unmapped sector texts: {a[has_sector_note & ~mapped].sectors_raw.tolist()}")
say(f"  KEV entries in catalog: {kev['count']}; KEV CVEs appearing in ICS advisories: {int(c.in_kev.sum())} ({pct(c.in_kev.sum(), kev['count'])}% of KEV)")
say()

# ------------------------------------------------------------------ spot checks
say("[4] Named spot checks (verify each against cisa.gov/news-events/ics-advisories/<id>)")
picks = []
picks.append(("known record", a[a.advisory_id == "ICSA-25-007-01"]))
picks.append(("earliest advisory", a.head(1)))
picks.append(("most CVEs in one advisory", a.sort_values("n_cves", ascending=False).head(1)))
picks.append(("most revisions", a.sort_values("revision_count", ascending=False).head(1)))
picks.append(("medical (ICSMA) latest", a[a.advisory_type == "ICSMA"].tail(1)))
picks.append(("republished vendor CSAF", a[(a.republished_or_converted == 1) & (a.id_year_mismatch == 1)].head(1)))
kev_first = c[c.in_kev == 1].sort_values("days_first_advisory_to_kev").head(1).first_advisory_id.tolist()
picks.append(("KEV added longest before advisory", a[a.advisory_id.isin(kev_first)]))
rand = a.sample(5, random_state=SEED)
for i, (_, r) in enumerate(rand.iterrows()):
    picks.append((f"random #{i+1} (seed {SEED})", rand.loc[[_]]))
spot_ids = []
for label, df in picks:
    for _, r in df.iterrows():
        spot_ids.append(r.advisory_id)
        cv = l[l.advisory_id == r.advisory_id]
        say(f"  - {label}: {r.advisory_id} | {r.title[:60]} | vendor={r.vendor} | released {r.initial_release} | "
            f"CVEs={r.n_cves} max CVSS={r.max_cvss_base} | KEV={r.n_kev_cves} | first CVE {cv.cve.iloc[0] if len(cv) else '-'}")
say()

# ------------------------------------------------------------------ stats
years = a.release_year.value_counts().sort_index()
full_years = years[years.index <= 2025]
vend = nv.value_counts()
sev = c.cvss_severity.value_counts()
scored = c.cvss_base.notna().sum()
av = c.attack_vector.value_counts()
cwe_names = l.dropna(subset=["cwe_id"]).groupby("cwe_id").cwe_name.agg(lambda s: s.mode().iloc[0])
cwe = c.cwe_id.value_counts()
k = c[c.in_kev == 1].copy()
post = k[k.first_advisory_date >= KEV_LAUNCH]
sect_since = a[a.release_year >= 2018]
sect = sect_since.sectors.dropna().str.split("; ").explode().value_counts()
kv = k.vendor.fillna("").str.split("; ").explode().value_counts()
k_sorted = k.sort_values("kev_date_added")

stats = {
    "snapshot": {
        "csaf_commit": csaf_commit.group(1), "csaf_commit_date": csaf_commit.group(2)[:10],
        "kev_commit": kev_commit.group(1), "kev_commit_date": kev_commit.group(2)[:10],
        "kev_catalog_version": kev["catalogVersion"],
        "first_advisory_date": a.initial_release.min(), "last_advisory_date": a.initial_release.max(),
    },
    "counts": {
        "advisories": len(a), "icsa": int((a.advisory_type == "ICSA").sum()), "icsma": int((a.advisory_type == "ICSMA").sum()),
        "links": len(l), "cves": len(c), "vendor_strings_raw": len(vm), "vendors_normalized": int(nv.nunique()),
        "kev_catalog": kev["count"], "kev_in_ics": int(c.in_kev.sum()),
        "cves_multi_advisory": int((c.n_advisories > 1).sum()),
    },
    "years": {int(y): int(n) for y, n in years.items()},
    "growth": {"y2015": int(years.get(2015, 0)), "y2025": int(years.get(2025, 0)),
               "ratio_2025_2015": round(years.get(2025, 0) / years.get(2015, 1), 1),
               "peak_year": int(full_years.idxmax()), "peak_count": int(full_years.max()),
               "y2026_to_date": int(years.get(2026, 0))},
    "vendors_top10": [{"vendor": v, "advisories": int(n), "pct": pct(n, len(a))} for v, n in vend.head(10).items()],
    "siemens_pct": pct(vend.get("Siemens", 0), len(a)),
    "top5_vendor_pct": pct(a.vendor.str.split("; ").apply(lambda vs: any(v in vend.head(5).index for v in vs)).sum(), len(a)),
    "vendors_single_advisory": int((vend == 1).sum()),
    "sectors_since_2018": {"advisories": len(sect_since), **{s: int(n) for s, n in sect.items()}},
    "cvss": {
        "scored_cves": int(scored), "unscored_cves": no_score,
        "critical": int(sev.get("CRITICAL", 0)), "high": int(sev.get("HIGH", 0)),
        "pct_critical": pct(sev.get("CRITICAL", 0), scored), "pct_high_or_critical": pct(sev.get("CRITICAL", 0) + sev.get("HIGH", 0), scored),
        "median_base": float(c.cvss_base.median()),
        "pct_network": pct(av.get("NETWORK", 0), scored), "pct_local": pct(av.get("LOCAL", 0), scored),
        "pct_adjacent": pct(av.get("ADJACENT_NETWORK", 0), scored), "pct_physical": pct(av.get("PHYSICAL", 0), scored),
        "version_mix": {"v" + str(k_).replace(".", ""): int(v) for k_, v in c.cvss_version.value_counts().items()},
    },
    "cwe_top10": [{"cwe": w, "name": cwe_names.get(w, ""), "cves": int(n), "pct": pct(n, c.cwe_id.notna().sum())} for w, n in cwe.head(10).items()],
    "cwe_missing": int(c.cwe_id.isna().sum()),
    "remediation": {
        "cves_fix_any": int(c.fix_available_any.sum()), "pct_fix_any": pct(c.fix_available_any.sum(), len(c)),
        "cves_no_fix": int(c.no_fix_all.sum()), "pct_no_fix": pct(c.no_fix_all.sum(), len(c)),
        "advisories_any_no_fix": int(a.any_no_fix.sum()),
    },
    "kev": {
        "pct_of_ics_cves": pct(len(k), len(c)), "pct_of_catalog": pct(len(k), kev["count"]),
        "ransomware_known": int((k.kev_known_ransomware == "Known").sum()),
        "median_days_advisory_to_kev_all": float(k.days_first_advisory_to_kev.median()),
        "kev_before_advisory": int((k.days_first_advisory_to_kev < 0).sum()),
        "post_launch_n": len(post),
        "post_launch_median_days": float(post.days_first_advisory_to_kev.median()) if len(post) else None,
        "post_launch_kev_before_advisory": int((post.days_first_advisory_to_kev < 0).sum()),
        "post_launch_within_30d": int(post.days_first_advisory_to_kev.between(0, 30).sum()),
        "pct_critical_among_kev": pct((k.cvss_severity == "CRITICAL").sum(), k.cvss_base.notna().sum()),
        "pct_critical_among_nonkev": pct((c[c.in_kev == 0].cvss_severity == "CRITICAL").sum(), c[c.in_kev == 0].cvss_base.notna().sum()),
        "kev_below_high": int((k.cvss_base < 7).sum()),
        "vendors_top": [{"vendor": v, "cves": int(n)} for v, n in kv.head(8).items()],
        "third_party": int((k.kev_component_origin == "third_party").sum()),
        "first_party": int((k.kev_component_origin == "first_party").sum()),
        "pct_third_party": pct((k.kev_component_origin == "third_party").sum(), len(k)),
        "post_launch_third_party": int((post.kev_component_origin == "third_party").sum()),
        "post_launch_kev_before_advisory_third_party": int(((post.days_first_advisory_to_kev < 0) & (post.kev_component_origin == "third_party")).sum()),
        "component_vendors_top": [{"vendor": v, "cves": int(n)} for v, n in k[k.kev_component_origin == "third_party"].kev_vendor_project.value_counts().head(8).items()],
        "latest": [{"cve": r.cve, "vendor": r.kev_vendor_project, "product": r.kev_product, "added": r.kev_date_added}
                   for r in k_sorted.tail(5).itertuples()],
    },
    "quality": {
        "id_year_mismatch": int(a.id_year_mismatch.sum()),
        "republished_or_converted": int(a.republished_or_converted.sum()),
        "pct_revised": pct((a.revision_count > 1).sum(), len(a)),
        "max_revisions": int(a.revision_count.max()),
        "sector_note_missing_pre2017": pct(a[a.release_year < 2017].sectors_raw.isna().sum(), (a.release_year < 2017).sum()),
        "sector_note_present": int(has_sector_note.sum()),
        "exploitability_note_present": int(a.exploit_statement.notna().sum()),
        "draft_status": int((a.tracking_status == "draft").sum()),
        "multi_company_vendor_strings": len(multi),
    },
    "extremes": {
        "max_cves_advisory_id": a.loc[a.n_cves.idxmax()].advisory_id, "max_cves_advisory_title": a.loc[a.n_cves.idxmax()].title,
        "max_cves": int(a.n_cves.max()), "median_cves_per_advisory": float(a.n_cves.median()),
        "max_revisions_advisory_id": a.loc[a.revision_count.idxmax()].advisory_id,
    },
    "spot_check_ids": spot_ids,
}

say("[5] Headline numbers (also in paper/stats.json)")
say(json.dumps({k_: stats[k_] for k_ in ("counts", "growth", "cvss", "remediation", "kev")}, indent=1))
say()
say(f"RESULT: {'ALL HARD CHECKS PASS' if not fails else str(len(fails)) + ' HARD CHECK(S) FAILED'}")

(ROOT / "paper").mkdir(exist_ok=True)
json.dump(stats, open(ROOT / "paper" / "stats.json", "w"), indent=1, default=str)
(P / "qa_report.txt").write_text("\n".join(out) + "\n")
print("\n".join(out))
sys.exit(1 if fails else 0)
