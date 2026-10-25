"""Writes the Hydra Engine logo (light and dark) as small hand-tuned SVGs.

One body (a coiled tail), five necks, five heads. The middle head's face is a terminal prompt.
The right-hand neck is cut short and a new head (dashed) is arriving: a client died, its locks
were freed, the body carries on and another client connects.
"""
import math, pathlib, sys

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

PALETTES = {
    "light": dict(body="#14532d", neck="#15803d", head="#166534", face="#ecfdf5", tongue="#dc2626",
                  ghost="#16a34a", belly="#22c55e"),
    "dark": dict(body="#4ade80", neck="#4ade80", head="#86efac", face="#052e16", tongue="#f87171",
                 ghost="#86efac", belly="#14532d"),
}

ROOT = (128, 176)
# (head x, head y, control-point sway): S-shaped necks
NECKS = [(44, 92, -1), (82, 50, 1), (128, 30, -1), (174, 50, -1)]
CUT = (200, 118)
NEW = (220, 82)
W = 12


def s_curve(x0, y0, x1, y1, sway):
    # cubic with the two control points pushed to opposite sides: an S
    dx, dy = x1 - x0, y1 - y0
    L = math.hypot(dx, dy)
    nx, ny = -dy / L, dx / L
    a = 16 * sway
    c1 = (x0 + dx * 0.35 + nx * a, y0 + dy * 0.35 + ny * a)
    c2 = (x0 + dx * 0.70 - nx * a, y0 + dy * 0.70 - ny * a)
    return f"M{x0} {y0} C{c1[0]:.1f} {c1[1]:.1f} {c2[0]:.1f} {c2[1]:.1f} {x1:.1f} {y1:.1f}"


def head(x, y, angle, p, prompt=False):
    s = 1.18 if prompt else 1.0
    g = [f'<g transform="translate({x} {y}) rotate({angle:.1f}) scale({s})">',
         # a wedge-shaped snake head, snout up
         f'<path d="M-16 12 C-19 -4 -11 -19 0 -21 C11 -19 19 -4 16 12 C9 17 -9 17 -16 12 Z" fill="{p["head"]}"/>']
    if prompt:
        g.append(f'<path d="M-10 -9 L-3 -3 L-10 3" fill="none" stroke="{p["face"]}" stroke-width="3.6" '
                 f'stroke-linecap="round" stroke-linejoin="round"/>')
        g.append(f'<rect x="1" y="1" width="10" height="3.6" rx="1.8" fill="{p["face"]}"/>')
        g.append(f'<path d="M0 -21 L0 -29 M0 -29 L-4 -34 M0 -29 L4 -34" fill="none" stroke="{p["tongue"]}" '
                 f'stroke-width="2.4" stroke-linecap="round"/>')
    else:
        g.append(f'<circle cx="-6" cy="-5" r="2.8" fill="{p["face"]}"/>')
        g.append(f'<circle cx="6" cy="-5" r="2.8" fill="{p["face"]}"/>')
    g.append("</g>")
    return "".join(g)


def svg(p):
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">',
             '<title>Hydra Engine</title>', '<g transform="translate(14 22) scale(0.9)">']
    # the body: a thick coiled tail under the necks
    parts.append(f'<path d="M128 170 C128 222 196 226 200 200 C204 178 170 174 162 192 C157 204 170 212 178 206" '
                 f'fill="none" stroke="{p["body"]}" stroke-width="22" stroke-linecap="round"/>')
    parts.append(f'<ellipse cx="128" cy="160" rx="30" ry="24" fill="{p["body"]}"/>')
    for (x, y, sw) in NECKS:
        parts.append(f'<path d="{s_curve(ROOT[0], ROOT[1] - 20, x, y + 10, sw)}" fill="none" '
                     f'stroke="{p["neck"]}" stroke-width="{W}" stroke-linecap="round"/>')
    parts.append(f'<path d="{s_curve(ROOT[0], ROOT[1] - 20, CUT[0], CUT[1], 1)}" fill="none" '
                 f'stroke="{p["neck"]}" stroke-width="{W}" stroke-linecap="butt"/>')
    # the arriving head
    parts.append(f'<g transform="translate({NEW[0]} {NEW[1]}) rotate(40)"><path d="M-13 10 C-15 -3 -9 -15 0 -17 '
                 f'C9 -15 15 -3 13 10 C7 14 -7 14 -13 10 Z" fill="none" stroke="{p["ghost"]}" '
                 f'stroke-width="3" stroke-dasharray="5 4"/></g>')
    for i, (x, y, sw) in enumerate(NECKS):
        ang = math.degrees(math.atan2(x - ROOT[0], -(y - ROOT[1]))) * 0.8
        parts.append(head(x, y, ang, p, prompt=(i == 2)))
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"


for name, p in PALETTES.items():
    (out / f"logo-{name}.svg").write_text(svg(p), encoding="utf-8", newline="\n")
