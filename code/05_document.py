#!/usr/bin/env python3
"""05_document.py: render every numbered document from templates/ + paper/stats.json.

Placeholders are {{dotted.path}} into stats.json (list items by index, e.g.
{{kev.component_vendors_top.0.vendor}}). Integers get thousands separators.
Authors come from AUTHORS.json via {{author.*}} and {{coauthors_md}}.
Without --final every rendered file starts with a DRAFT banner.

Usage: python code/05_document.py [--final]
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "templates"
TARGETS = {
    "README.md": ROOT / "README.md",
    "LIMITATIONS.md": ROOT / "docs" / "LIMITATIONS.md",
    "VERIFY_CHECKLIST.md": ROOT / "docs" / "VERIFY_CHECKLIST.md",
    "ABSTRACT.md": ROOT / "talk" / "ABSTRACT.md",
    "SPEAKER_NOTES.md": ROOT / "talk" / "SPEAKER_NOTES.md",
    "PUBLISH_GUIDE.md": ROOT / "docs" / "PUBLISH_GUIDE.md",
}

ap = argparse.ArgumentParser()
ap.add_argument("--final", action="store_true")
FINAL = ap.parse_args().final

stats = json.load(open(ROOT / "paper" / "stats.json"))
authors = json.load(open(ROOT / "AUTHORS.json"))["authors"]
stats["author"] = authors[0]
stats["coauthors_md"] = "\n".join(f"- {x['name']}, {x['affiliation']}, {x['email']}" for x in authors)


def lookup(path):
    cur = stats
    for part in path.split("."):
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    if isinstance(cur, bool):
        return str(cur)
    if isinstance(cur, int):
        return f"{cur:,}" if not (1900 <= cur <= 2100) else str(cur)
    if isinstance(cur, float):
        return f"{cur:g}"
    return str(cur)


BANNER = "> **DRAFT, unverified.** Generated from `paper/stats.json`; do not cite or submit until `docs/VERIFY_CHECKLIST.md` is complete.\n\n"
for name, dest in TARGETS.items():
    src = (T / name).read_text()
    missing = []

    def sub(m):
        try:
            return lookup(m.group(1))
        except (KeyError, IndexError, ValueError):
            if m.group(1) not in ("abstract_words", "bio_words"):
                missing.append(m.group(1))
            return m.group(0)

    out = re.sub(r"\{\{([\w.]+)\}\}", sub, src)
    # word counts for CFP limits, computed on the rendered text
    for key, pat in (("abstract_words", r"## Abstract[^\n]*\n(.*?)\n## "), ("bio_words", r"\*\*Bio[^\n]*?\*\*(.*?)\n\n")):
        m = re.search(pat, out, re.S)
        if m:
            body = re.sub(r"\[VERIFY[^\]]*\]", "", m.group(1))
            out = out.replace("{{%s}}" % key, str(len(body.split())))
    if missing:
        raise SystemExit(f"{name}: unresolved placeholders {missing}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(("" if FINAL else BANNER) + out)
    print("wrote", dest.relative_to(ROOT))
