"""Writes the Hydra Engine logo (light and dark): HYDRA as a block-letter terminal banner.

    python make_logo.py <CascadiaMono.ttf> <out dir>

Solid blocks for the letters, box-drawing characters for their shadow, set in Cascadia Mono
(https://github.com/microsoft/cascadia-code, SIL OFL 1.1) and converted to outlines, so the SVGs
need no font and render the same everywhere. Blocks and box-drawing characters fill the whole
cell, so rows sit at the font's full line height and join without gaps. Writes logo-dark.svg and
logo-light.svg. Needs fonttools.
"""

import pathlib
import sys

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

ASC, DESC, ADV = 1900, 480, 1200
LINE = ASC + DESC

BANNER = [
    "██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ",
    "██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗",
    "███████║ ╚████╔╝ ██║  ██║██████╔╝███████║",
    "██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║",
    "██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║",
    "╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
]

# Blocks are the letters; everything else is their shadow.
PALETTES = {
    "dark": {"block": "#4ade80", "shadow": "#1d6b3e"},
    "light": {"block": "#15803d", "shadow": "#86c59d"},
}


def outline(font, art):
    """Path data for the blocks and for the shadows, in font units."""
    gs = font.getGlyphSet()
    cmap = font.getBestCmap()
    parts = {"block": [], "shadow": []}
    bounds = BoundsPen(gs)
    for r, row in enumerate(art):
        for c, ch in enumerate(row):
            if ch == " ":
                continue
            pen = SVGPathPen(gs)
            # Font y goes up, SVG y down: flip, baseline at ASC within each row.
            place = (1, 0, 0, -1, c * ADV, r * LINE + ASC)
            gs[cmap[ord(ch)]].draw(TransformPen(pen, place))
            gs[cmap[ord(ch)]].draw(TransformPen(bounds, place))
            parts["block" if ch == "█" else "shadow"].append(pen.getCommands())
    # The drawing's real extent: block glyphs reach past the font's ascent and descent.
    return {k: " ".join(v) for k, v in parts.items()}, bounds.bounds


def svg(parts, box, colors, pad=400):
    x0, y0, x1, y1 = box
    view = f"{x0 - pad:.0f} {y0 - pad:.0f} {x1 - x0 + 2 * pad:.0f} {y1 - y0 + 2 * pad:.0f}"
    paths = "".join(f'<path fill="{colors[k]}" d="{parts[k]}"/>' for k in ("shadow", "block"))
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}"><title>Hydra Engine</title>{paths}</svg>\n'


def main(font_path, out_dir):
    font = TTFont(font_path)
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    parts, box = outline(font, BANNER)
    for name, colors in PALETTES.items():
        (out / f"logo-{name}.svg").write_text(svg(parts, box, colors), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
