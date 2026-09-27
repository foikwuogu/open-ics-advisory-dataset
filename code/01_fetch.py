#!/usr/bin/env python3
"""01_fetch.py: fetch the two federal sources with git and log provenance.

Sources
  1. CISA CSAF advisories (OT/white only): https://github.com/cisagov/CSAF
  2. CISA KEV catalog (official GitHub mirror): https://github.com/cisagov/kev-data

Both are fetched with git, because the GitHub repositories are CISA's own
distribution points and git pins an exact commit. To reproduce a specific
snapshot, pass --csaf-commit / --kev-commit with the hashes in
data/raw/PROVENANCE.txt.

Usage:  python code/01_fetch.py [--refresh] [--csaf-commit SHA] [--kev-commit SHA]
"""
import argparse
import datetime
import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROV = RAW / "PROVENANCE.txt"
CSAF_URL = "https://github.com/cisagov/CSAF"
KEV_URL = "https://github.com/cisagov/kev-data"


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def fetch_csaf(refresh, commit):
    dest = RAW / "csaf"
    if not dest.exists():
        git("clone", "-q", "--filter=blob:none", "--sparse", CSAF_URL, str(dest))
        git("sparse-checkout", "set", "csaf_files/OT", cwd=dest)
    elif refresh:
        git("pull", "-q", cwd=dest)
    if commit:
        git("fetch", "-q", "origin", commit, cwd=dest)
        git("checkout", "-q", commit, cwd=dest)
    return dest


def fetch_kev(refresh, commit):
    dest = RAW / "kev"
    if not dest.exists():
        git("clone", "-q", KEV_URL, str(dest))
    elif refresh:
        git("pull", "-q", cwd=dest)
    if commit:
        git("checkout", "-q", commit, cwd=dest)
    return dest


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(files):
    """SHA-256 over sorted 'relpath:sha256' lines, so the whole corpus has one fingerprint."""
    h = hashlib.sha256()
    total = 0
    for p in sorted(files):
        total += p.stat().st_size
        h.update(f"{p.as_posix()}:{sha256_file(p)}\n".encode())
    return h.hexdigest(), total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--csaf-commit")
    ap.add_argument("--kev-commit")
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)

    csaf = fetch_csaf(a.refresh, a.csaf_commit)
    kev = fetch_kev(a.refresh, a.kev_commit)
    today = datetime.date.today().isoformat()

    files = [p.relative_to(csaf) for p in (csaf / "csaf_files" / "OT" / "white").glob("20[0-9][0-9]/*.json")]
    os.chdir(csaf)
    digest, nbytes = tree_digest(files)
    os.chdir(ROOT)
    c_commit = git("rev-parse", "HEAD", cwd=csaf)
    c_date = git("log", "-1", "--format=%cI", cwd=csaf)
    kev_json = kev / "known_exploited_vulnerabilities.json"
    k_commit = git("rev-parse", "HEAD", cwd=kev)
    k_date = git("log", "-1", "--format=%cI", cwd=kev)

    lines = [
        f"{today} | csaf_files/OT/white/*.json ({len(files)} files) | {nbytes} bytes | "
        f"sha256-tree:{digest} | {CSAF_URL} | commit {c_commit} ({c_date}); fetched with git sparse checkout",
        f"{today} | known_exploited_vulnerabilities.json | {kev_json.stat().st_size} bytes | "
        f"sha256:{sha256_file(kev_json)} | {KEV_URL} | commit {k_commit} ({k_date}); official CISA mirror of cisa.gov/kev",
    ]
    with open(PROV, "a") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
