"""Writes the Hydra Engine architecture diagram (light and dark SVG).

Left: the heads (clients). Middle: the body (one daemon JVM). Right: projects opened in place.
"""
import pathlib, sys

out = pathlib.Path(sys.argv[1])

PAL = {
    "light": dict(bg="#ffffff", fg="#1f2328", mute="#59636e", line="#d1d9e0", card="#f6f8fa",
                  acc="#15803d", accbg="#dcfce7", warn="#b91c1c", body="#14532d", bodyfg="#ecfdf5",
                  lane="#166534", lane2="#1e3a8a", lanefg="#ffffff"),
    "dark": dict(bg="#0d1117", fg="#e6edf3", mute="#9198a1", line="#3d444d", card="#151b23",
                 acc="#4ade80", accbg="#0f2a1a", warn="#f87171", body="#14532d", bodyfg="#ecfdf5",
                 lane="#22c55e", lane2="#60a5fa", lanefg="#0d1117"),
}

CLIENTS = [
    ("Claude Code", "harness", False),
    ("Codex", "harness", False),
    ("OpenCode", "harness", False),
    ("QoderCLI", "harness", False),
    ("RusticRE", "MCP server", False),
    ("your script", "connect()", False),
    ("killed client", "", True),          # the cut head
]
PROJECTS = [
    ("game.gpr", "read-only view, no lock", ["game.exe", "engine.dll"]),
    ("tools.gpr", "writable, one owner", ["patcher.exe"]),
    ("work.gpr", "imports, dedup by SHA-256", ["new.bin"]),
]

FONT = "font-family=\"ui-sans-serif,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif\""
MONO = "font-family=\"ui-monospace,SFMono-Regular,'Cascadia Code',Consolas,monospace\""


def svg(p):
    W, H = 920, 430
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
         '<title>Many clients, one daemon, many projects</title>',
         f'<rect width="{W}" height="{H}" rx="14" fill="{p["bg"]}"/>']
    # column titles
    for x, t in ((110, "HEADS: clients"), (460, "BODY: one daemon per user"), (790, "PROJECTS: opened in place")):
        s.append(f'<text x="{x}" y="34" text-anchor="middle" {FONT} font-size="13" font-weight="700" '
                 f'letter-spacing="1.2" fill="{p["mute"]}">{t}</text>')
    # daemon body
    bx, by, bw, bh = 330, 56, 260, 344
    s.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="18" fill="{p["body"]}"/>')
    s.append(f'<text x="{bx + bw / 2}" y="{by + 34}" text-anchor="middle" {FONT} font-size="18" font-weight="700" '
             f'fill="{p["bodyfg"]}">Hydra Engine daemon</text>')
    s.append(f'<text x="{bx + bw / 2}" y="{by + 56}" text-anchor="middle" {MONO} font-size="12" '
             f'fill="{p["bodyfg"]}" opacity=".85">one JVM · loopback + token</text>')
    rows = [("quick lane", "decompile · functions · list", p["lane"]),
            ("long lane", "analyze · import · script", p["lane2"])]
    for i, (a, b, c) in enumerate(rows):
        y = by + 80 + i * 62
        s.append(f'<rect x="{bx + 18}" y="{y}" width="{bw - 36}" height="50" rx="10" fill="{c}"/>')
        s.append(f'<text x="{bx + 34}" y="{y + 21}" {FONT} font-size="13" font-weight="700" fill="{p["lanefg"]}">{a}</text>')
        s.append(f'<text x="{bx + 34}" y="{y + 39}" {MONO} font-size="11.5" fill="{p["lanefg"]}">{b}</text>')
    facts = ["round-robin by client", "1 writer, many readers / program", "per-client cancel",
             "warm decompilers, shared", "dead client: locks freed"]
    for i, f in enumerate(facts):
        s.append(f'<text x="{bx + 26}" y="{by + 234 + i * 21}" {FONT} font-size="13" fill="{p["bodyfg"]}">'
                 f'<tspan fill="{p["acc"] if p is PAL["dark"] else "#86efac"}">●</tspan> {f}</text>')
    # clients
    cy0, step = 60, 49
    for i, (name, kind, cut) in enumerate(CLIENTS):
        y = cy0 + i * step
        stroke = p["warn"] if cut else p["line"]
        dash = ' stroke-dasharray="5 4"' if cut else ""
        s.append(f'<rect x="20" y="{y}" width="180" height="40" rx="10" fill="{p["card"]}" stroke="{stroke}"{dash}/>')
        s.append(f'<text x="36" y="{y + 26}" {MONO} font-size="13" fill="{p["acc"]}">&gt;_</text>')
        s.append(f'<text x="62" y="{y + 19}" {FONT} font-size="14" font-weight="600" fill="{p["fg"]}">{name}</text>')
        s.append(f'<text x="62" y="{y + 34}" {FONT} font-size="11.5" fill="{p["mute"]}">'
                 f'{"locks freed, edits dropped" if cut else kind}</text>')
        x1, y1 = 200, y + 21
        x2, y2 = bx, by + 110 + (i - 3) * 20
        if cut:
            mx = (x1 + x2) / 2 - 20
            s.append(f'<path d="M{x1} {y1} C{x1 + 40} {y1} {mx - 30} {y2} {mx} {(y1 + y2) / 2 + 6}" fill="none" '
                     f'stroke="{p["warn"]}" stroke-width="2.5" stroke-dasharray="5 4"/>')
            s.append(f'<text x="{mx + 4}" y="{(y1 + y2) / 2 + 12}" {FONT} font-size="16" fill="{p["warn"]}">✂</text>')
        else:
            s.append(f'<path d="M{x1} {y1} C{x1 + 70} {y1} {x2 - 70} {y2} {x2} {y2}" fill="none" '
                     f'stroke="{p["acc"]}" stroke-width="2.5"/>')
    # projects
    py0 = 66
    for i, (name, mode, progs) in enumerate(PROJECTS):
        y = py0 + i * 112
        h = 96
        s.append(f'<rect x="680" y="{y}" width="220" height="{h}" rx="12" fill="{p["card"]}" stroke="{p["line"]}"/>')
        s.append(f'<text x="696" y="{y + 24}" {MONO} font-size="14" font-weight="700" fill="{p["fg"]}">{name}</text>')
        s.append(f'<text x="696" y="{y + 42}" {FONT} font-size="11.5" fill="{p["mute"]}">{mode}</text>')
        for j, prog in enumerate(progs):
            s.append(f'<rect x="{696 + j * 100}" y="{y + 54}" width="92" height="28" rx="7" fill="{p["accbg"]}"/>')
            s.append(f'<text x="{742 + j * 100}" y="{y + 72}" text-anchor="middle" {MONO} font-size="11.5" '
                     f'fill="{p["fg"]}">{prog}</text>')
        x1, y1 = bx + bw, by + 120 + (i - 1) * 60
        s.append(f'<path d="M{x1} {y1} C{x1 + 50} {y1} {680 - 50} {y + h / 2} 680 {y + h / 2}" fill="none" '
                 f'stroke="{p["acc"]}" stroke-width="2.5"/>')
    s.append("</svg>")
    return "\n".join(s) + "\n"


for k, p in PAL.items():
    (out / f"architecture-{k}.svg").write_text(svg(p), encoding="utf-8", newline="\n")
