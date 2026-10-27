"""Writes the Hydra Engine architecture diagram (light and dark SVG).

    python make_diagram.py <out dir>

The same picture as the website's "How it works": on the left the heads (agent harnesses, MCP
servers, scripts), each busy at the same moment; in the middle the engine, one daemon whose
quick lane answers in milliseconds while its long lane runs imports and analyses; on the right
programs in several projects, each opened in place. Wires take the colour of the lane their
request runs in: green for quick, blue for long. The numbers are measured ones (module README,
"Performance").
"""
import pathlib
import sys

W, H = 960, 400
SANS = "font-family=\"ui-sans-serif,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif\""
MONO = "font-family=\"ui-monospace,SFMono-Regular,'Cascadia Code',Consolas,monospace\""

PAL = {
    "dark": dict(bg="#000000", fg="#eef2f5", soft="#c3ccd5", mute="#7f8c9b", faint="#4a5866", row="#0b0d0d",
                 rowline="#1d2522", quick="#4ade80", quickbg="#041913", quickline="#1f9a4c", slotoff_q="#14321f",
                 long="#60a5fa", longbg="#04142a", longline="#2f6fe0", slotoff_l="#132744", card="#030806", cardline="#4ade80"),
    "light": dict(bg="#ffffff", fg="#1f2328", soft="#3d444d", mute="#59636e", faint="#8c959f", row="#f6f8fa",
                  rowline="#d1d9e0", quick="#15803d", quickbg="#ecfdf3", quickline="#16a34a", slotoff_q="#cfe9d8",
                  long="#1d4ed8", longbg="#eff4ff", longline="#3b82f6", slotoff_l="#cdd9f5", card="#fbfdfb", cardline="#16a34a"),
}

# (name, what it is doing now, lane)
HEADS = [
    ("Claude Code", "decompile · 7 ms", "quick"),
    ("Codex", "import driver.sys", "long"),
    ("OpenCode", "overlay · 116 ms", "quick"),
    ("QoderCLI", "decompile · 6.7 ms", "quick"),
    ("RusticRE  MCP", "join · 0.9 ms", "quick"),
    ("your script", "analyze libnet.so", "long"),
]
# (program, project, what runs on it, lane or None)
PROGRAMS = [
    ("arena.exe", "p1 /re/arena", "decompile", "quick"),
    ("racer.exe", "p2 /re/racer", "overlay", "quick"),
    ("boot.bin", "p3 /re/firmware", "decompile", "quick"),
    ("libnet.so", "p4 /re/server", "analyze", "long"),
    ("driver.sys", "p5 /re/drivers", "import", "long"),
]
# head index -> program index
WIRES = {0: 0, 1: 4, 2: 1, 3: 2, 4: 0, 5: 3}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def svg(p):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
         "<title>Many heads at work at once, one engine, many projects</title>",
         f'<rect width="{W}" height="{H}" rx="12" fill="{p["bg"]}"/>']

    def text(x, y, t, size=12, fill=p["fg"], font=SANS, weight=400, anchor="start", ls=0):
        s.append(f'<text x="{x}" y="{y}" {font} font-size="{size}" font-weight="{weight}" fill="{fill}" '
                 f'text-anchor="{anchor}" letter-spacing="{ls}">{esc(t)}</text>')

    # Column headings.
    text(28, 40, "HEADS", 11, p["mute"], MONO, 600, ls=2)
    text(84, 40, "/ any harness, at once", 11, p["faint"], MONO)
    text(668, 40, "PROJECTS", 11, p["mute"], MONO, 600, ls=2)
    text(746, 40, "/ any number, at once", 11, p["faint"], MONO)

    # Engine card.
    cx, cy, cw, ch = 360, 62, 248, 300
    s.append(f'<rect x="{cx}" y="{cy}" width="{cw}" height="{ch}" rx="8" fill="{p["card"]}" stroke="{p["cardline"]}" stroke-width="1.6"/>')
    s.append(f'<rect x="{cx + 6}" y="{cy + 6}" width="{cw - 12}" height="{ch - 12}" rx="5" fill="none" stroke="{p["cardline"]}" stroke-opacity="0.4" stroke-dasharray="4 3"/>')
    s.append(f'<rect x="{cx + cw / 2 - 62}" y="{cy - 9}" width="124" height="18" fill="{p["bg"]}"/>')
    text(cx + cw / 2, cy + 4, "HYDRA ENGINE", 11, p["quick"], MONO, 700, "middle", 3)
    text(cx + cw / 2, cy + 46, "one daemon · one warm Ghidra", 12, p["soft"], SANS, 400, "middle")
    text(cx + cw / 2, cy + 64, "projects, programs and decompilers stay open", 10.5, p["mute"], SANS, 400, "middle")

    lanes = [("quick", "QUICK LANE", 24, 4, "decompile · functions · rename", "answers in milliseconds"),
             ("long", "LONG LANE", 6, 2, "import · analyze · script · save", "runs alongside, never blocks")]
    for i, (k, name, slots, used, runs, note) in enumerate(lanes):
        lx, ly, lw, lh = cx + 18, cy + 92 + i * 102, cw - 36, 88
        s.append(f'<rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="6" fill="{p[k + "bg"]}" stroke="{p[k + "line"]}" stroke-width="1.4"/>')
        text(lx + 12, ly + 20, name, 11, p[k], MONO, 700, ls=1.5)
        text(lx + lw - 12, ly + 20, f"{used}/{slots} slots", 10, p["mute"], MONO, 400, "end")
        gap, sw = 2, (lw - 24 - (slots - 1) * 2) / slots
        for j in range(slots):
            fill = p[k] if j < used else p["slotoff_q" if k == "quick" else "slotoff_l"]
            s.append(f'<rect x="{lx + 12 + j * (sw + gap):.1f}" y="{ly + 30}" width="{sw:.1f}" height="5" rx="1" fill="{fill}"/>')
        text(lx + 12, ly + 54, note, 11, p["soft"], SANS)
        text(lx + 12, ly + 74, runs, 10, p["mute"], MONO)

    # Heads.
    hx, hw, hh = 28, 250, 34
    head_y = [62 + i * 50 for i in range(len(HEADS))]
    for (name, doing, lane), y in zip(HEADS, head_y):
        mcp = "MCP" in name
        s.append(f'<rect x="{hx}" y="{y}" width="{hw}" height="{hh}" rx="6" fill="{p["row"]}" stroke="{p[lane] if mcp else p["rowline"]}" stroke-opacity="{0.8 if mcp else 1}"/>')
        text(hx + 12, y + 22, name.replace("  MCP", ""), 13, p["fg"], SANS, 600 if mcp else 400)
        if mcp:
            s.append(f'<rect x="{hx + 84}" y="{y + 10}" width="32" height="15" rx="7.5" fill="{p["quick"]}"/>')
            text(hx + 100, y + 21, "MCP", 9, p["bg"], MONO, 700, "middle")
        text(hx + hw - 12, y + 22, ("› " if lane == "long" else "✓ ") + doing, 11, p[lane], MONO, 400, "end")
        s.append(f'<circle cx="{hx + hw}" cy="{y + hh / 2}" r="4" fill="{p["bg"]}" stroke="{p[lane]}" stroke-width="1.5"/>')

    # Programs.
    px, pw = 668, 264
    prog_y = [70 + i * 58 for i in range(len(PROGRAMS))]
    for (prog, proj, op, lane), y in zip(PROGRAMS, prog_y):
        s.append(f'<rect x="{px}" y="{y}" width="{pw}" height="38" rx="6" fill="{p["row"]}" stroke="{p[lane] if lane else p["rowline"]}" stroke-opacity="0.75"/>')
        text(px + 12, y + 17, prog, 12.5, p["fg"], MONO, 600)
        text(px + 12, y + 31, proj, 10, p["faint"], MONO)
        text(px + pw - 12, y + 24, op, 10.5, p[lane], MONO, 400, "end")

    # Wires: head -> engine (spread down its left edge) -> program (spread down its right edge).
    def curve(x1, y1, x2, y2):
        d = (x2 - x1) * 0.5
        return f"M{x1:.1f},{y1:.1f} C{x1 + d:.1f},{y1:.1f} {x2 - d:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"

    for i, y in enumerate(head_y):
        lane = HEADS[i][2]
        ey = cy + 40 + i * (ch - 80) / (len(HEADS) - 1)
        s.append(f'<path d="{curve(hx + hw + 4, y + hh / 2, cx, ey)}" fill="none" stroke="{p[lane]}" stroke-opacity="0.75" stroke-width="1.5"/>')
    for i, y in enumerate(prog_y):
        lane = PROGRAMS[i][3]
        ey = cy + 40 + i * (ch - 80) / (len(PROGRAMS) - 1)
        s.append(f'<path d="{curve(cx + cw, ey, px, y + 19)}" fill="none" stroke="{p[lane]}" stroke-opacity="0.75" stroke-width="1.5" stroke-dasharray="4 3"/>')

    # Legend.
    text(28, H - 18, "● quick lane: decompile, list, rename, open", 11, p["quick"], MONO)
    text(352, H - 18, "● long lane: import, analyze, script, save", 11, p["long"], MONO)
    text(W - 28, H - 18, "measured: warm decompile 6.7–7.1 ms", 11, p["mute"], MONO, 400, "end")

    s.append("</svg>")
    return "\n".join(s) + "\n"


if __name__ == "__main__":
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for name, pal in PAL.items():
        (out / f"architecture-{name}.svg").write_text(svg(pal), encoding="utf-8", newline="\n")
