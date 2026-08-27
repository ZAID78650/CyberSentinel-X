"""Render UNSW-NB15 dataset visuals for the SIH document.

Reads the bundled training set (backend/data/samples/unsw_sample.csv) and paints
spreadsheet-style screenshots plus a class-distribution chart:

  1. docs/screenshots/06-unsw-dataset.png        — 8-row slice, 16 columns
  2. docs/screenshots/07-unsw-full-header.png    — full 45-column header + 2 rows
  3. docs/screenshots/08-unsw-class-distribution.png — attack-category bar chart

Run:  cd backend && .venv/bin/python ../scripts/generate_unsw_screenshot.py
"""

import csv
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "backend" / "data" / "samples" / "unsw_sample.csv"
SHOTS = ROOT / "docs" / "screenshots"

MONO = "/System/Library/Fonts/Menlo.ttc"
SANS = "/System/Library/Fonts/Helvetica.ttc"

NAVY = (11, 61, 145)
DARK = (31, 56, 100)
GRID = (201, 210, 224)
ALT = (243, 246, 251)
TEXT = (30, 41, 59)
WHITE = (255, 255, 255)
GREEN = (22, 101, 52)
RED = (185, 28, 28)

DECIMALS = {"dur": 4, "rate": 2, "tcprtt": 2, "smean": 0}

# Representative columns across the feature groups + ground-truth labels
PREVIEW_COLUMNS = [
    "id", "dur", "proto", "service", "state", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "sttl", "tcprtt", "smean",
    "ct_state_ttl", "attack_cat", "label",
]

ATTACK_COLORS = [
    (185, 28, 28), (220, 38, 38), (234, 88, 12), (217, 119, 6),
    (202, 138, 4), (163, 63, 30), (190, 18, 60), (159, 18, 57),
    (136, 19, 55),
]


def fmt_value(col: str, raw: str) -> str:
    if col == "attack_cat":
        return raw
    if col in DECIMALS:
        try:
            return f"{float(raw):.{DECIMALS[col]}f}"
        except ValueError:
            return raw
    return raw


def read_rows(n: int) -> list[dict]:
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
        return [r for _, r in zip(range(n), csv.DictReader(fh))]


def total_rows() -> int:
    return sum(1 for _ in open(CSV_PATH, encoding="utf-8-sig")) - 1


def draw_chrome(d: ImageDraw, W: int, title: str, sub: str, right: str, bar_h: int = 64) -> None:
    d.rectangle([0, 0, W, bar_h], fill=NAVY)
    ft, fs = ImageFont.truetype(SANS, 24), ImageFont.truetype(SANS, 15)
    d.text((18, 10), title, font=ft, fill=WHITE)
    d.text((18, 38), sub, font=fs, fill=(203, 213, 225))
    d.text((W - 18 - fs.getlength(right), 22), right, font=fs, fill=(203, 213, 225))


# ---------------------------------------------------------------------------
# 1) 8-row preview slice (16 columns)
# ---------------------------------------------------------------------------

def render_preview() -> None:
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        picked: list[dict] = []
        families_seen: set[str] = set()
        for r in reader:
            fam = r["attack_cat"]
            if fam == "Normal":
                if sum(1 for p in picked if p["attack_cat"] == "Normal") < 4:
                    picked.append(r)
            else:
                if fam not in families_seen and len(families_seen) < 4:
                    families_seen.add(fam)
                    picked.append(r)
            if len(picked) >= 8:
                break
        rows = sorted(picked, key=lambda r: int(r["id"]))[:8]

    font_hdr = ImageFont.truetype(MONO, 18)
    font_cell = ImageFont.truetype(MONO, 18)
    pad = 18
    col_w = []
    for col in PREVIEW_COLUMNS:
        w = font_hdr.getlength(col)
        for r in rows:
            w = max(w, font_cell.getlength(fmt_value(col, r[col])))
        col_w.append(int(w) + pad)
    row_h, hdr_h, bar_h = 34, 40, 64
    W = sum(col_w) + 2
    H = bar_h + hdr_h + row_h * len(rows) + 2

    img = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(img)
    draw_chrome(d, W, "UNSW-NB15  ·  training set", "unsw_sample.csv",
                f"{total_rows():,} rows  ×  45 columns", bar_h)

    x = 1
    d.rectangle([0, bar_h, W, bar_h + hdr_h], fill=DARK)
    for i, col in enumerate(PREVIEW_COLUMNS):
        d.text((x + 8, bar_h + 10), col, font=font_hdr, fill=WHITE)
        x += col_w[i]

    y = bar_h + hdr_h
    for ri, r in enumerate(rows):
        if ri % 2 == 1:
            d.rectangle([0, y, W, y + row_h], fill=ALT)
        x = 1
        for i, col in enumerate(PREVIEW_COLUMNS):
            val = fmt_value(col, r[col])
            color = TEXT
            if col == "attack_cat":
                color = GREEN if val == "Normal" else RED
            elif col == "label":
                color = GREEN if val == "0" else RED
            d.text((x + 8, y + 7), val, font=font_cell, fill=color)
            x += col_w[i]
        y += row_h

    x = 1
    for w in col_w:
        x += w
        d.line([x, bar_h, x, y], fill=GRID, width=1)
    for yy in range(bar_h + hdr_h, y + 1, row_h):
        d.line([0, yy, W, yy], fill=GRID, width=1)
    d.rectangle([0, bar_h, W, y], outline=GRID)

    img.save(SHOTS / "06-unsw-dataset.png")
    print("Saved: 06-unsw-dataset.png", img.size)


# ---------------------------------------------------------------------------
# 2) Full 45-column header + two rows
# ---------------------------------------------------------------------------

def render_full_header() -> None:
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames
        rows = [next(reader)]  # first row (Normal)
        families = set()
        for r in reader:
            if r["attack_cat"] != "Normal" and r["attack_cat"] not in families:
                families.add(r["attack_cat"])
                rows.append(r)
            if len(rows) >= 4:
                break

    font_hdr = ImageFont.truetype(MONO, 16)
    font_cell = ImageFont.truetype(MONO, 16)
    pad = 12
    col_w = []
    for col in cols:
        w = font_hdr.getlength(col)
        for r in rows:
            w = max(w, font_cell.getlength(fmt_value(col, r[col])))
        col_w.append(int(w) + pad)
    row_h, hdr_h, bar_h = 30, 34, 64
    W = sum(col_w) + 2
    H = bar_h + hdr_h + row_h * len(rows) + 2

    img = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(img)
    draw_chrome(d, W, "UNSW-NB15  ·  training set", "unsw_sample.csv — full schema (45 columns)",
                f"{total_rows():,} rows  ×  {len(cols)} columns", bar_h)

    x = 1
    d.rectangle([0, bar_h, W, bar_h + hdr_h], fill=DARK)
    for i, col in enumerate(cols):
        d.text((x + 5, bar_h + 8), col, font=font_hdr, fill=WHITE)
        x += col_w[i]

    y = bar_h + hdr_h
    for ri, r in enumerate(rows):
        if ri % 2 == 1:
            d.rectangle([0, y, W, y + row_h], fill=ALT)
        x = 1
        for i, col in enumerate(cols):
            val = fmt_value(col, r[col])
            color = TEXT
            if col == "attack_cat":
                color = GREEN if val == "Normal" else RED
            elif col == "label":
                color = GREEN if val == "0" else RED
            d.text((x + 5, y + 6), val, font=font_cell, fill=color)
            x += col_w[i]
        y += row_h

    x = 1
    for w in col_w:
        x += w
        d.line([x, bar_h, x, y], fill=GRID, width=1)
    for yy in range(bar_h + hdr_h, y + 1, row_h):
        d.line([0, yy, W, yy], fill=GRID, width=1)
    d.rectangle([0, bar_h, W, y], outline=GRID)

    img.save(SHOTS / "07-unsw-full-header.png")
    print("Saved: 07-unsw-full-header.png", img.size)


# ---------------------------------------------------------------------------
# 3) Attack-category distribution (horizontal bar chart)
# ---------------------------------------------------------------------------

def render_distribution() -> None:
    counts = Counter()
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            counts[r["attack_cat"]] += 1
    total = sum(counts.values())
    items = counts.most_common()  # Normal first (largest)

    W, M_L, M_R, bar_h, gap = 1500, 300, 300, 30, 14
    label_font = ImageFont.truetype(SANS, 22)
    val_font = ImageFont.truetype(MONO, 21)
    title_font = ImageFont.truetype(SANS, 26)
    sub_font = ImageFont.truetype(SANS, 15)
    bar_h_ok = bar_h + gap
    H = 64 + 30 + len(items) * bar_h_ok + 40

    img = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(img)
    draw_chrome(d, W, "UNSW-NB15  ·  training set", "unsw_sample.csv — class distribution",
                f"{total:,} rows  ×  45 columns")

    y = 64 + 30
    x0, x1 = M_L, W - M_R
    max_v = items[0][1]

    d.text((M_L, y - 26), "attack_cat (ground truth)", font=title_font, fill=TEXT)

    for i, (fam, v) in enumerate(items):
        bar_w = int((v / max_v) * (x1 - x0))
        color = GREEN if fam == "Normal" else ATTACK_COLORS[i - 1 if fam != "Normal" else 0]
        d.text((x0 - 14, y + 3), fam, font=label_font, fill=TEXT, anchor="rm")
        d.rectangle([x0, y, x0 + bar_w, y + bar_h], fill=color)
        pct = v / total * 100
        d.text((x0 + bar_w + 12, y + 3), f"{v:,}   ({pct:.2f}%)", font=val_font, fill=TEXT)
        y += bar_h_ok

    d.text((M_L, y + 6), "Computed from the official training set — 175,341 rows",
           font=sub_font, fill=(100, 116, 139))

    img.save(SHOTS / "08-unsw-class-distribution.png")
    print("Saved: 08-unsw-class-distribution.png", img.size)


if __name__ == "__main__":
    SHOTS.mkdir(parents=True, exist_ok=True)
    render_preview()
    render_full_header()
    render_distribution()
