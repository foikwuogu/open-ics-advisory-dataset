#!/usr/bin/env python3
"""04_figures.py: talk/paper figures from the processed tables and stats.json.

Usage: python code/04_figures.py [--final]
Without --final every figure carries a DRAFT tag. Palette: validated reference
categorical slots 1-2 (blue #2a78d6, orange #eb6834), light surface.
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "data" / "processed"
FIG = ROOT / "talk" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

ap = argparse.ArgumentParser()
ap.add_argument("--final", action="store_true")
FINAL = ap.parse_args().final

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1"
BLUE, BLUE_LIGHT, ORANGE = "#2a78d6", "#86b6ef", "#eb6834"

S = json.load(open(ROOT / "paper" / "stats.json"))
a = pd.read_csv(P / "advisories.csv")
c = pd.read_csv(P / "cves.csv")
snap = f"CISA CSAF (OT) commit {S['snapshot']['csaf_commit'][:7]}, {S['snapshot']['csaf_commit_date']}; KEV {S['snapshot']['kev_catalog_version']}"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 13, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.facecolor": SURFACE, "figure.facecolor": SURFACE,
    "axes.spines.top": False, "axes.spines.right": False, "axes.titlesize": 17, "axes.titleweight": "bold",
    "axes.titlecolor": INK, "axes.titlelocation": "left",
})


def finish(fig, ax, name, source=snap):
    fig.text(0.01, 0.01, f"Source: {source}", fontsize=9, color=MUTED, ha="left", va="bottom")
    if not FINAL:
        fig.text(0.99, 0.985, "DRAFT - unverified", fontsize=11, color=ORANGE, ha="right", va="top", weight="bold")
    fig.savefig(FIG / name, dpi=200)
    plt.close(fig)
    print("wrote", name)


def rounded_barh(ax, y, w, color, h=0.62):
    return ax.barh(y, w, height=h, color=color, edgecolor=SURFACE, linewidth=2)


# 1 ---------------------------------------------------------------- advisories per year
yrs = pd.Series({int(k): v for k, v in S["years"].items()}).sort_index()
fig, ax = plt.subplots(figsize=(12, 6.2))
cols = [BLUE_LIGHT if y == 2026 else BLUE for y in yrs.index]
ax.bar(yrs.index, yrs.values, color=cols, width=0.72, edgecolor=SURFACE, linewidth=2)
ax.set_title(f"CISA ICS advisories per year, 2010-2026 (n = {S['counts']['advisories']:,})", pad=30)
ax.yaxis.grid(True, color=GRID, linewidth=0.8); ax.set_axisbelow(True)
ax.set_xticks(yrs.index); ax.tick_params(axis="x", labelsize=10.5)
g = S["growth"]
ax.annotate(f"{g['y2025']} in 2025\n{g['ratio_2025_2015']}x 2015", (2025, g["y2025"]), xytext=(2021.2, g["y2025"] + 20),
            color=INK, fontsize=12, arrowprops=dict(arrowstyle="-", color=INK2, lw=1))
ax.text(0, 1.01, f"2026 (lighter bar) is partial: {g['y2026_to_date']} advisories through {S['snapshot']['last_advisory_date']}",
        transform=ax.transAxes, color=INK2, fontsize=11.5)
ax.set_ylim(0, max(yrs) * 1.25); ax.set_ylabel("Advisories (by initial release date)")
fig.subplots_adjust(left=0.08, right=0.98, top=0.85, bottom=0.12)
finish(fig, ax, "fig1_advisories_per_year.png")

# 2 ---------------------------------------------------------------- top vendors
tv = pd.DataFrame(S["vendors_top10"]).iloc[::-1]
fig, ax = plt.subplots(figsize=(12, 6.2))
rounded_barh(ax, tv.vendor, tv.advisories, [ORANGE if v == "Siemens" else BLUE for v in tv.vendor])
for yv, (n, p) in enumerate(zip(tv.advisories, tv.pct)):
    ax.text(n + 12, yv, f"{n:,}  ({p}%)", va="center", color=INK, fontsize=11.5)
ax.set_title(f"Ten vendors by advisory count ({S['counts']['vendors_normalized']} vendors after normalization)", pad=14)
ax.set_xlim(0, tv.advisories.max() * 1.22); ax.xaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.set_xlabel("Advisories naming the vendor")
fig.subplots_adjust(left=0.22, right=0.97, top=0.88, bottom=0.14)
finish(fig, ax, "fig2_top_vendors.png")

# 3 ---------------------------------------------------------------- KEV component vendors
k = S["kev"]
cv = pd.DataFrame(k["component_vendors_top"]).iloc[::-1]
fig, ax = plt.subplots(figsize=(12, 6.2))
rounded_barh(ax, cv.vendor, cv.cves, ORANGE)
for yv, n in enumerate(cv.cves):
    ax.text(n + 0.25, yv, str(n), va="center", color=INK, fontsize=12)
ax.set_title(f"{k['third_party']} of {S['counts']['kev_in_ics']} known-exploited ICS CVEs are third-party IT components", pad=34)
ax.text(0, 1.02, "Component vendor named in CISA KEV, top 8 (the advisory itself names the OT vendor)", transform=ax.transAxes,
        color=INK2, fontsize=11.5)
ax.set_xlim(0, cv.cves.max() * 1.18); ax.xaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.set_xlabel("KEV-listed CVEs in ICS advisories")
fig.subplots_adjust(left=0.2, right=0.97, top=0.83, bottom=0.14)
finish(fig, ax, "fig3_kev_component_vendors.png")

# 4 ---------------------------------------------------------------- KEV timing (post-launch)
post = c[(c.in_kev == 1) & (c.first_advisory_date >= "2021-11-03")].copy()
bins = list(range(-800, 1001, 50))
fig, ax = plt.subplots(figsize=(12, 6.2))
neg = post[post.days_first_advisory_to_kev < 0].days_first_advisory_to_kev
pos = post[post.days_first_advisory_to_kev >= 0].days_first_advisory_to_kev
ax.hist(neg, bins=bins, color=ORANGE, edgecolor=SURFACE, linewidth=2, label=f"In KEV before the ICS advisory ({len(neg)})")
ax.hist(pos, bins=bins, color=BLUE, edgecolor=SURFACE, linewidth=2, label=f"ICS advisory first ({len(pos)})")
ax.axvline(0, color=INK2, lw=1)
ax.text(-20, ax.get_ylim()[1] * 0.93, "KEV first", ha="right", color=INK, fontsize=12)
ax.text(20, ax.get_ylim()[1] * 0.93, "advisory first", ha="left", color=INK, fontsize=12)
ax.set_title(f"Days from first ICS advisory to KEV listing ({k['post_launch_n']} CVEs, advised after Nov 2021)", pad=14)
ax.set_xlabel("Days (negative = already known-exploited when the ICS advisory published)")
ax.set_ylabel("CVEs"); ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.legend(frameon=False, loc="upper right", bbox_to_anchor=(1, 0.86), labelcolor=INK)
fig.subplots_adjust(left=0.08, right=0.98, top=0.88, bottom=0.14)
finish(fig, ax, "fig4_kev_timing.png")

# 5 ---------------------------------------------------------------- attack vector
cv5 = S["cvss"]
av = pd.DataFrame({"av": ["Network", "Local", "Adjacent network", "Physical"],
                   "pct": [cv5["pct_network"], cv5["pct_local"], cv5["pct_adjacent"], cv5["pct_physical"]]}).iloc[::-1]
fig, ax = plt.subplots(figsize=(12, 5.2))
rounded_barh(ax, av.av, av.pct, BLUE)
for yv, p in enumerate(av.pct):
    ax.text(p + 0.8, yv, f"{p}%", va="center", color=INK, fontsize=12)
ax.set_title(f"CVSS attack vector, {cv5['scored_cves']:,} scored ICS CVEs", pad=14)
ax.set_xlim(0, 75); ax.xaxis.grid(True, color=GRID); ax.set_axisbelow(True); ax.set_xlabel("% of scored CVEs")
fig.subplots_adjust(left=0.2, right=0.97, top=0.86, bottom=0.17)
finish(fig, ax, "fig5_attack_vector.png")
