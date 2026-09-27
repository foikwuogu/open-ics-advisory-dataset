#!/usr/bin/env python3
"""02_build.py: parse CISA CSAF OT advisories, normalize, join KEV, write three tables.

Outputs (data/processed/):
  advisories.csv     one row per advisory
  advisory_cves.csv  one row per (advisory, CVE)
  cves.csv           one row per CVE (first appearance in the ICS advisory stream)
  vendor_map.csv     every raw vendor string -> normalized vendor, with the rule applied

Every judgment call is a named constant or function below so it can be reviewed:
  CVSS_PRECEDENCE, normalize_vendor(), VENDOR_ALIASES, SECTOR_PATTERNS, is_republished().
"""
import csv
import json
import re
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSAF_DIR = ROOT / "data" / "raw" / "csaf" / "csaf_files" / "OT" / "white"
KEV_JSON = ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"
OUT = ROOT / "data" / "processed"

# ---------------------------------------------------------------- judgment calls
# When a vulnerability carries several CVSS scores, use the newest CVSS version;
# within that version take the highest base score (worst-affected product).
CVSS_PRECEDENCE = {"3.1": 3, "3.0": 2, "2.0": 1}

CORP_SUFFIX = re.compile(
    r"\b(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|gmbh|ag|se|sa|s\.a|s\.p\.a|spa|"
    r"plc|bv|b\.v|nv|kg|co\. kg|oy|ab|as|srl|s\.r\.l|pty|kk|k\.k)\b\.?",
    re.I,
)
# Aliases applied to the cleaned key. Only merges of the *same* company under different
# spellings; corporate lineage (Invensys -> Schneider, OSIsoft -> AVEVA) is NOT merged.
VENDOR_ALIASES = {
    "ge": "General Electric",
    "general electric": "General Electric",
    "ge vernova": "GE Vernova",
    "schneider electric software": "Schneider Electric",
    "schneider electric": "Schneider Electric",
    "aveva software": "AVEVA",
    "aveva": "AVEVA",
    "johnson controls": "Johnson Controls",
    "mitsubishi electric": "Mitsubishi Electric",
    "becton dickinson and": "Becton Dickinson (BD)",
    "becton dickinson": "Becton Dickinson (BD)",
    "bd": "Becton Dickinson (BD)",
    "rockwell automation": "Rockwell Automation",
    "rockwell": "Rockwell Automation",
    "phoenix contact": "Phoenix Contact",
    "osisoft": "OSIsoft",
    "siemens": "Siemens",
    "hitachi energy": "Hitachi Energy",
    "delta electronics": "Delta Electronics",
    "honeywell international": "Honeywell",
    "honeywell": "Honeywell",
    "emerson": "Emerson",
    "yokogawa electric": "Yokogawa",
    "yokogawa": "Yokogawa",
    "omron": "Omron",
    "fuji electric": "Fuji Electric",
    "moxa": "Moxa",
    "advantech": "Advantech",
    "abb": "ABB",
    "philips": "Philips",
    "phillips": "Philips",   # source misspelling (ICSMA-18-058-02 and others)
    "koninklijke philips": "Philips",
    "3s-smart software solutions": "CODESYS (3S-Smart Software Solutions)",
    "codesys": "CODESYS (3S-Smart Software Solutions)",
    "wago": "WAGO",
    "eaton": "Eaton",
    "medtronic": "Medtronic",
    "baxter": "Baxter",
    "ptc": "PTC",
}

# The 16 US critical-infrastructure sectors (PPD-21 names as CISA uses them).
SECTOR_PATTERNS = [
    ("Chemical", r"\bchemical"),
    ("Commercial Facilities", r"commercial\s+facilit"),
    ("Communications", r"\bcommunications?\b"),
    ("Critical Manufacturing", r"manu?a?f?acturing|critical\s+manufactur"),  # tolerates source typos
    ("Dams", r"\bdams?\b"),
    ("Defense Industrial Base", r"defen[cs]e\s+industrial"),
    ("Emergency Services", r"emergency\s+services"),
    ("Energy", r"\benergy\b"),
    ("Financial Services", r"financial"),
    ("Food and Agriculture", r"\bfood\b|agricultur"),
    ("Government Services and Facilities", r"government"),
    ("Healthcare and Public Health", r"health"),
    ("Information Technology", r"information\s+technology"),
    ("Nuclear Reactors, Materials, and Waste", r"nuclear"),
    ("Transportation Systems", r"transportation"),
    ("Water and Wastewater Systems", r"water"),
]
MULTIPLE_PAT = re.compile(r"\bmultiple\b|\ball sectors\b", re.I)


GENERIC_TOKENS = {"electric", "electronics", "systems", "system", "technologies", "technology", "automation",
                  "software", "international", "group", "industries", "networks", "products", "multiple", "the", "and"}


def kev_origin(adv_vendor, kev_vendor):
    """first_party if the KEV vendorProject shares a distinctive name token with the advisory's first-listed vendor,
    else third_party (an IT component embedded in the OT product). Judgment call: review in VERIFY_CHECKLIST."""
    def toks(x):
        return {t for t in re.findall(r"[a-z0-9]+", (x or "").lower()) if len(t) >= 3 and t not in GENERIC_TOKENS}
    return "first_party" if toks(adv_vendor) & toks(kev_vendor) else "third_party"


def is_republished(doc):
    """CISA republication of a vendor CSAF (keeps vendor dates) or conversion of a vendor advisory."""
    for n in doc.get("notes", []):
        t = (n.get("text") or "").lower()
        if "republication" in t or "republished" in t or "converted from" in t:
            return True
    return False


# ---------------------------------------------------------------- helpers
def clean_vendor_key(raw):
    s = raw.replace("&", " and ")
    s = re.sub(r"\([^)]*\)", " ", s)          # drop parentheticals like "(GE)"
    s = s.replace(",", " ")
    for _ in range(3):
        s = CORP_SUFFIX.sub(" ", s)
    s = re.sub(r"[^\w\s\-]", " ", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def normalize_vendor(raw):
    raw = raw.strip()
    key = clean_vendor_key(raw)
    if key in VENDOR_ALIASES:
        return VENDOR_ALIASES[key], "alias"
    # also try the raw parenthetical abbreviation, e.g. "General Electric (GE)"
    m = re.search(r"\(([^)]+)\)", raw)
    if m and m.group(1).strip().lower() in VENDOR_ALIASES:
        return VENDOR_ALIASES[m.group(1).strip().lower()], "alias(parenthetical)"
    if key and key != raw.lower():
        # title-case only if the raw string was all caps/lower; otherwise keep raw casing minus suffix
        words = [w for w in re.split(r"\s+", re.sub(r"\([^)]*\)", " ", raw).replace(",", " ")) if w]
        words = [w for w in words if not CORP_SUFFIX.fullmatch(w.strip("."))]
        return " ".join(words).strip(" .,"), "suffix-stripped"
    return raw, "unchanged"


def note(doc, title):
    for n in doc.get("notes", []):
        if (n.get("title") or "").strip().lower() == title.lower():
            return re.sub(r"\s+", " ", n.get("text") or "").strip()
    return ""


def map_sectors(text):
    found = [sector for sector, pat in SECTOR_PATTERNS if re.search(pat, text, re.I)]
    return found, bool(MULTIPLE_PAT.search(text))


def v2_severity(score):
    return "LOW" if score < 4 else ("MEDIUM" if score < 7 else "HIGH")


AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


def v3_severity(score):
    if score == 0:
        return "NONE"
    return "LOW" if score < 4 else ("MEDIUM" if score < 7 else ("HIGH" if score < 9 else "CRITICAL"))


def best_score(vuln):
    best = None
    for s in vuln.get("scores", []):
        for key in ("cvss_v3", "cvss_v2"):
            c = s.get(key)
            if not c or c.get("baseScore") is None:
                continue
            ver = str(c.get("version"))
            rank = (CVSS_PRECEDENCE.get(ver, 0), float(c["baseScore"]))
            if best is None or rank > best[0]:
                # attack vector: from the vector string (the attackVector field is often absent)
                m = re.search(r"AV:([NALP])", c.get("vectorString", ""))
                av = AV_MAP.get(m.group(1), "") if m else c.get("attackVector", "")
                if key == "cvss_v3":
                    sev = c.get("baseSeverity", "") or v3_severity(float(c["baseScore"]))
                else:
                    sev = v2_severity(float(c["baseScore"]))
                best = (rank, ver, float(c["baseScore"]), sev.upper(), c.get("vectorString", ""), av.upper())
    if best is None:
        return {"cvss_version": "", "cvss_base": "", "cvss_severity": "", "cvss_vector": "", "attack_vector": ""}
    _, ver, score, sev, vec, av = best
    return {"cvss_version": ver, "cvss_base": score, "cvss_severity": sev, "cvss_vector": vec, "attack_vector": av}


def exploit_statement(text):
    t = text.lower()
    if not t:
        return ""
    if re.search(r"no known public exploits", t):
        return "no_known_public_exploits"
    if re.search(r"(public exploits? (are|is) (known|available)|exploits? that target|known to be exploited|has been exploited|actively exploited)", t):
        return "public_exploits_reported"
    return "other"


def d(s):
    return date.fromisoformat(s[:10]) if s else None


# ---------------------------------------------------------------- main
def main():
    OUT.mkdir(parents=True, exist_ok=True)
    kev = {v["cveID"]: v for v in json.load(open(KEV_JSON, encoding="utf-8"))["vulnerabilities"]}

    advisories, links = [], []
    vendor_raw_counts, vendor_map = Counter(), {}

    for f in sorted(CSAF_DIR.glob("20[0-9][0-9]/*.json")):
        j = json.load(open(f, encoding="utf-8"))
        doc, tr = j["document"], j["document"]["tracking"]
        aid = tr["id"].strip().upper()
        init, curr = tr.get("initial_release_date", ""), tr.get("current_release_date", "")
        m = re.match(r"ICS(M?)A-(\d\d)-", aid)
        id_year = 2000 + int(m.group(2)) if m else None

        raw_vendors = [b["name"].strip() for b in j.get("product_tree", {}).get("branches", []) if b.get("category") == "vendor"]
        norm_vendors = []
        for rv in raw_vendors:
            vendor_raw_counts[rv] += 1
            nv, rule = normalize_vendor(rv)
            vendor_map[rv] = (nv, rule)
            if nv not in norm_vendors:
                norm_vendors.append(nv)

        sectors_raw = note(doc, "Critical infrastructure sectors")
        sectors, multiple = map_sectors(sectors_raw)
        expl_raw = note(doc, "Exploitability")

        # product id -> product name (for affected counts)
        vulns = j.get("vulnerabilities", [])
        adv_cves = []
        for v in vulns:
            cve = (v.get("cve") or "").strip().upper()
            if not cve:
                continue
            sc = best_score(v)
            rem = sorted({r.get("category", "") for r in v.get("remediations", []) if r.get("category")})
            ps = v.get("product_status", {})
            k = kev.get(cve)
            kev_added = k["dateAdded"] if k else ""
            row = {
                "advisory_id": aid,
                "cve": cve,
                "advisory_initial_release": init[:10],
                "cwe_id": (v.get("cwe") or {}).get("id", ""),
                "cwe_name": (v.get("cwe") or {}).get("name", ""),
                **sc,
                "n_products_known_affected": len(ps.get("known_affected", [])),
                "remediation_categories": ";".join(rem),
                "fix_available": int("vendor_fix" in rem),
                "no_fix": int(("none_available" in rem or "no_fix_planned" in rem) and "vendor_fix" not in rem),
                "in_kev": int(bool(k)),
                "kev_date_added": kev_added,
                "kev_known_ransomware": (k or {}).get("knownRansomwareCampaignUse", ""),
            }
            adv_cves.append(row)
        links.extend(adv_cves)

        scores = [r["cvss_base"] for r in adv_cves if r["cvss_base"] != ""]
        advisories.append({
            "advisory_id": aid,
            "advisory_type": "ICSMA" if aid.startswith("ICSMA") else "ICSA",
            "title": re.sub(r"\s+", " ", doc.get("title", "")).strip(),
            "initial_release": init[:10],
            "current_release": curr[:10],
            "release_year": int(init[:4]) if init else "",
            "id_year": id_year or "",
            "id_year_mismatch": int(bool(id_year and init and id_year != int(init[:4]))),
            "revision_count": len(tr.get("revision_history", [])),
            "tracking_status": tr.get("status", ""),
            "publisher_category": doc.get("publisher", {}).get("category", ""),
            "republished_or_converted": int(is_republished(doc)),
            "vendor": "; ".join(norm_vendors),
            "vendor_raw": "; ".join(raw_vendors),
            "n_vendors": len(norm_vendors),
            "sectors": "; ".join(sectors),
            "sector_multiple": int(multiple),
            "sectors_raw": sectors_raw,
            "countries_deployed_raw": note(doc, "Countries/areas deployed"),
            "hq_location_raw": note(doc, "Company headquarters location"),
            "n_cves": len(adv_cves),
            "max_cvss_base": max(scores) if scores else "",
            "any_critical": int(any(r["cvss_severity"] == "CRITICAL" for r in adv_cves)),
            "any_network_av": int(any(r["attack_vector"] == "NETWORK" for r in adv_cves)),
            "n_kev_cves": sum(r["in_kev"] for r in adv_cves),
            "any_no_fix": int(any(r["no_fix"] for r in adv_cves)),
            "exploit_statement": exploit_statement(expl_raw),
            "source_file": f.relative_to(ROOT / "data" / "raw").as_posix(),
        })

    # --- CVE-level table: first appearance
    by_cve = defaultdict(list)
    for r in links:
        by_cve[r["cve"]].append(r)
    adv_idx = {a["advisory_id"]: a for a in advisories}
    cves = []
    for cve, rows in by_cve.items():
        rows = sorted(rows, key=lambda r: (r["advisory_initial_release"], r["advisory_id"]))
        first = rows[0]
        best = max(rows, key=lambda r: (CVSS_PRECEDENCE.get(str(r["cvss_version"]), 0), r["cvss_base"] if r["cvss_base"] != "" else -1))
        k = kev.get(cve)
        fa = d(first["advisory_initial_release"])
        ka = d(k["dateAdded"]) if k else None
        cwes = Counter(r["cwe_id"] for r in rows if r["cwe_id"])
        cves.append({
            "cve": cve,
            "cve_year": int(cve.split("-")[1]),
            "first_advisory_id": first["advisory_id"],
            "first_advisory_date": first["advisory_initial_release"],
            "n_advisories": len({r["advisory_id"] for r in rows}),
            "vendor": adv_idx[first["advisory_id"]]["vendor"],
            "cwe_id": cwes.most_common(1)[0][0] if cwes else "",
            "cvss_version": best["cvss_version"],
            "cvss_base": best["cvss_base"],
            "cvss_severity": best["cvss_severity"],
            "attack_vector": best["attack_vector"],
            "fix_available_any": int(any(r["fix_available"] for r in rows)),
            "no_fix_all": int(all(r["no_fix"] for r in rows)),
            "in_kev": int(bool(k)),
            "kev_date_added": k["dateAdded"] if k else "",
            "kev_vendor_project": (k or {}).get("vendorProject", ""),
            "kev_product": (k or {}).get("product", ""),
            "kev_known_ransomware": (k or {}).get("knownRansomwareCampaignUse", ""),
            "kev_component_origin": kev_origin(adv_idx[first["advisory_id"]]["vendor_raw"].split(";")[0], k["vendorProject"]) if k else "",
            "days_first_advisory_to_kev": (ka - fa).days if (ka and fa) else "",
        })
    cves.sort(key=lambda r: r["cve"])

    def write(name, rows):
        with open(OUT / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {name}: {len(rows)} rows")

    advisories.sort(key=lambda r: (r["initial_release"], r["advisory_id"]))
    links.sort(key=lambda r: (r["advisory_id"], r["cve"]))
    write("advisories.csv", advisories)
    write("advisory_cves.csv", links)
    write("cves.csv", cves)
    write("vendor_map.csv", [
        {"vendor_raw": rv, "vendor": vendor_map[rv][0], "rule": vendor_map[rv][1], "n_advisories": n}
        for rv, n in vendor_raw_counts.most_common()
    ])


if __name__ == "__main__":
    main()
