"""Writes the Hydra Engine architecture diagram (light and dark SVG), animated.

    python make_diagram.py <out dir>

The website's "How it works", as an SVG that animates on its own in a README (SMIL, no script):
four agent harnesses (Claude Code, Codex, OpenCode, QoderCLI) reach the engine through the
RusticRE MCP server; the engine's quick lane answers in milliseconds while its long lane runs an
import and an analysis; programs in five projects show who is working on them. Every animation
shares one loop, so pulses, statuses, slots and progress bars stay in step. Answers carry measured
numbers (module README, "Performance").
"""
import pathlib
import sys

W, H = 960, 400
T = 11.0  # the loop, seconds
STEP = 0.05
SANS = "font-family=\"ui-sans-serif,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif\""
MONO = "font-family=\"ui-monospace,SFMono-Regular,'Cascadia Code',Consolas,monospace\""

PAL = {
    "dark": dict(bg="#000000", fg="#eef2f5", soft="#c3ccd5", mute="#7f8c9b", faint="#4a5866", row="#0b0d0d",
                 rowline="#1d2522", quick="#4ade80", quickbg="#041913", quickline="#1f9a4c", slotoff_q="#14321f",
                 long="#60a5fa", longbg="#04142a", longline="#2f6fe0", slotoff_l="#132744", card="#030806",
                 cardline="#4ade80", wire="#2b5a3f", back="#d4ff5a"),
    "light": dict(bg="#ffffff", fg="#1f2328", soft="#3d444d", mute="#59636e", faint="#8c959f", row="#f6f8fa",
                  rowline="#d1d9e0", quick="#15803d", quickbg="#ecfdf3", quickline="#16a34a", slotoff_q="#cfe9d8",
                  long="#1d4ed8", longbg="#eff4ff", longline="#3b82f6", slotoff_l="#cdd9f5", card="#fbfdfb",
                  cardline="#16a34a", wire="#a7d9b8", back="#4d7c0f"),
}

HEADS = ["Claude Code", "Codex", "OpenCode", "QoderCLI"]
PROGRAMS = [("arena.exe", "p1 /re/arena"), ("racer.exe", "p2 /re/racer"), ("boot.bin", "p3 /re/firmware"),
            ("libnet.so", "p4 /re/server"), ("driver.sys", "p5 /re/drivers")]

# head, program, lane, ask, op, answer, start, work (s)
REQS = [
    (0, 0, "quick", "› decompile Tick", "decompile", "✓ C · 7 ms", 0.3, 0.3),
    (1, 4, "long", "› import driver.sys", "import", "✓ imported · 8 s", 0.8, 4.0),
    (2, 1, "quick", "› overlay hyp-1", "overlay", "✓ overlay · 116 ms", 2.2, 0.35),
    (3, 2, "quick", "› decompile reset", "decompile", "✓ C · 6.7 ms", 2.35, 0.3),
    (0, 3, "long", "› analyze libnet.so", "analyze", "✓ analysed · 314 s", 4.4, 2.6),
    (2, 0, "quick", "› rename Tick", "rename", "✓ journal · 1.9 ms", 5.1, 0.3),
    (3, 1, "quick", "› join racer.exe", "join", "✓ joined · 0.9 ms", 5.25, 0.25),
    (1, 2, "quick", "› functions recv", "functions", "✓ 12 found · 3 ms", 7.4, 0.3),
]
OUT, CORE_Q, CORE_L, TO, BACK, HOLD = 0.7, 0.15, 0.4, 0.6, 0.9, 1.3


def phases(r):
    head, prog, lane, ask, op, ans, t0, work = r
    core = CORE_Q if lane == "quick" else CORE_L
    a = t0 + OUT
    b = a + core
    c = b + TO
    d = c + work
    e = d + BACK
    return dict(out=(t0, a), core=(a, b), to=(b, c), work=(c, d), back=(d, e), hold=(e, min(T, e + HOLD)))


def series(fn):
    """Samples fn(t) over the loop and returns (values, keyTimes) for a discrete animation."""
    vals, keys, last = [], [], object()
    n = int(T / STEP)
    for i in range(n):
        t = i * STEP
        v = fn(t)
        if v != last:
            vals.append(str(v))
            keys.append(f"{t / T:.4f}")
            last = v
    keys[0] = "0"
    return ";".join(vals), ";".join(keys)


def discrete(attr, fn):
    v, k = series(fn)
    if ";" not in v:
        # Constant over the loop: still set it, or the element keeps its unanimated default.
        return f'<set attributeName="{attr}" to="{v}"/>'
    return f'<animate attributeName="{attr}" values="{v}" keyTimes="{k}" calcMode="discrete" dur="{T}s" repeatCount="indefinite"/>'


def within(t, w):
    return w[0] <= t < w[1]


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def svg(p):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
         "<title>Four agent harnesses, through the RusticRE MCP server, at work in one Hydra Engine at once</title>",
         f'<rect width="{W}" height="{H}" rx="12" fill="{p["bg"]}"/>']

    def text(x, y, t, size=12, fill=p["fg"], font=SANS, weight=400, anchor="start", ls=0, extra=""):
        s.append(f'<text x="{x}" y="{y}" {font} font-size="{size}" font-weight="{weight}" fill="{fill}" '
                 f'text-anchor="{anchor}" letter-spacing="{ls}">{esc(t)}{extra}</text>')

    text(28, 40, "HEADS", 11, p["mute"], MONO, 600, ls=2)
    text(84, 40, "/ agent harnesses, at once", 11, p["faint"], MONO)
    text(668, 40, "PROJECTS", 11, p["mute"], MONO, 600, ls=2)
    text(746, 40, "/ any number, at once", 11, p["faint"], MONO)

    # Geometry.
    hx, hw, hh = 28, 232, 36
    head_y = [70 + i * 62 for i in range(len(HEADS))]
    mx, my, mw, mh = 286, 150, 54, 78  # the RusticRE MCP junction
    cx, cy, cw, ch = 372, 62, 240, 296
    px, pw = 668, 264
    prog_y = [70 + i * 58 for i in range(len(PROGRAMS))]

    def curve(x1, y1, x2, y2):
        d = (x2 - x1) * 0.5
        return f"M{x1:.1f},{y1:.1f} C{x1 + d:.1f},{y1:.1f} {x2 - d:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"

    # Wire paths: head -> junction -> engine; engine -> program.
    head_paths = []
    for i, y in enumerate(head_y):
        ey = cy + 60 + i * 52
        d = curve(hx + hw + 4, y + hh / 2, mx, my + mh / 2) + " " + curve(mx + mw, my + mh / 2, cx, ey)[0:].replace("M", "L", 1)
        head_paths.append(d)
    prog_paths = []
    for i, y in enumerate(prog_y):
        ey = cy + 46 + i * (ch - 92) / (len(PROGRAMS) - 1)
        prog_paths.append(curve(cx + cw, ey, px, y + 19))

    s.append("<defs>")
    for i, d in enumerate(head_paths):
        s.append(f'<path id="h{i}" d="{d}"/>')
    for i, d in enumerate(prog_paths):
        s.append(f'<path id="p{i}" d="{d}"/>')
    s.append("</defs>")
    for i in range(len(head_paths)):
        s.append(f'<use href="#h{i}" fill="none" stroke="{p["wire"]}" stroke-width="1.4"/>')
    for i in range(len(prog_paths)):
        s.append(f'<use href="#p{i}" fill="none" stroke="{p["wire"]}" stroke-width="1.4" stroke-dasharray="4 3"/>')

    # Pulses: out along head -> engine, then engine -> program; the answer runs back.
    for r in REQS:
        head, prog, lane = r[0], r[1], r[2]
        ph = phases(r)
        color = p[lane]
        for path, (t0, t1), rev, col, rad in (
            (f"h{head}", ph["out"], False, color, 3.6),
            (f"p{prog}", ph["to"], False, color, 3.6),
            (f"p{prog}", (ph["back"][0], ph["back"][0] + BACK / 2), True, p["back"], 2.8),
            (f"h{head}", (ph["back"][0] + BACK / 2, ph["back"][1]), True, p["back"], 2.8),
        ):
            a, b = t0 / T, t1 / T
            kp = "1;1;0;0" if rev else "0;0;1;1"
            s.append(f'<circle r="{rad}" fill="{col}" opacity="0">'
                     f'<animateMotion dur="{T}s" repeatCount="indefinite" keyPoints="{kp}" keyTimes="0;{a:.4f};{b:.4f};1" calcMode="linear"><mpath href="#{path}"/></animateMotion>'
                     + discrete("opacity", lambda t, w=(t0, t1): 1 if within(t, w) else 0)
                     + "</circle>")

    # The RusticRE MCP junction.
    s.append(f'<rect x="{mx}" y="{my}" width="{mw}" height="{mh}" rx="7" fill="{p["quickbg"]}" stroke="{p["quick"]}" stroke-width="1.4"/>')
    text(mx + mw / 2, my + 30, "Rustic", 11, p["fg"], SANS, 700, "middle")
    text(mx + mw / 2, my + 44, "RE", 11, p["fg"], SANS, 700, "middle")
    s.append(f'<rect x="{mx + 10}" y="{my + 52}" width="{mw - 20}" height="15" rx="7.5" fill="{p["quick"]}"/>')
    text(mx + mw / 2, my + 63, "MCP", 9, p["bg"], MONO, 700, "middle")

    # Heads, with a status that follows their requests.
    for i, y in enumerate(head_y):
        mine = [r for r in REQS if r[0] == i]
        busy = lambda t, mine=mine: next((r for r in mine if phases(r)["out"][0] <= t < phases(r)["back"][1]), None)
        done = lambda t, mine=mine: next((r for r in mine if within(t, phases(r)["hold"])), None)
        border = lambda t: (p[busy(t)[2]] if busy(t) else p["rowline"])
        s.append(f'<rect x="{hx}" y="{y}" width="{hw}" height="{hh}" rx="6" fill="{p["row"]}" stroke="{p["rowline"]}">'
                 + discrete("stroke", border) + "</rect>")
        text(hx + 12, y + 23, HEADS[i], 13, p["fg"], SANS)
        states = {"idle": lambda t: busy(t) is None and done(t) is None}
        for r in mine:
            states[r[3]] = (lambda t, r=r: busy(t) is r)
            states[r[5]] = (lambda t, r=r: busy(t) is None and done(t) is r)
        for label, on in states.items():
            lane = next((r[2] for r in mine if label in (r[3], r[5])), None)
            fill = p[lane] if lane else p["faint"]
            text(hx + hw - 14, y + 23, label, 11, fill, MONO, 600 if label.startswith("✓") else 400, "end",
                 extra=discrete("opacity", lambda t, on=on: 1 if on(t) else 0))
        port = lambda t: (p[busy(t)[2]] if busy(t) else p["wire"])
        s.append(f'<circle cx="{hx + hw}" cy="{y + hh / 2}" r="4" fill="{p["bg"]}" stroke="{p["wire"]}" stroke-width="1.5">'
                 + discrete("stroke", port) + "</circle>")

    # Engine card.
    s.append(f'<rect x="{cx}" y="{cy}" width="{cw}" height="{ch}" rx="8" fill="{p["card"]}" stroke="{p["cardline"]}" stroke-width="1.6"/>')
    s.append(f'<rect x="{cx + 6}" y="{cy + 6}" width="{cw - 12}" height="{ch - 12}" rx="5" fill="none" stroke="{p["cardline"]}" stroke-opacity="0.4" stroke-dasharray="4 3"/>')
    s.append(f'<rect x="{cx + cw / 2 - 62}" y="{cy - 9}" width="124" height="18" fill="{p["bg"]}"/>')
    text(cx + cw / 2, cy + 4, "HYDRA ENGINE", 11, p["quick"], MONO, 700, "middle", 3)
    text(cx + cw / 2, cy + 44, "one daemon · one warm Ghidra", 12, p["soft"], SANS, 400, "middle")
    text(cx + cw / 2, cy + 62, "projects, programs and decompilers stay open", 10.5, p["mute"], SANS, 400, "middle")

    def in_lane(lane, t):
        return sum(1 for r in REQS if r[2] == lane and phases(r)["core"][0] <= t < phases(r)["work"][1])

    for i, (k, name, slots, runs, note) in enumerate([
        ("quick", "QUICK LANE", 24, "decompile · functions · rename", "answers in milliseconds"),
        ("long", "LONG LANE", 6, "import · analyze · script · save", "runs alongside, never blocks"),
    ]):
        lx, ly, lw, lh = cx + 16, cy + 88 + i * 102, cw - 32, 88
        glow = lambda t, k=k: 1 if in_lane(k, t) else 0.55
        s.append(f'<rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="6" fill="{p[k + "bg"]}" stroke="{p[k + "line"]}" stroke-width="1.4">'
                 + discrete("stroke-opacity", glow) + "</rect>")
        text(lx + 12, ly + 20, name, 11, p[k], MONO, 700, ls=1.5)
        for n in range(0, 5):
            text(lx + lw - 12, ly + 20, f"{n}/{slots} slots", 10, p["mute"], MONO, 400, "end",
                 extra=discrete("opacity", lambda t, n=n, k=k: 1 if in_lane(k, t) == n else 0))
        gap, sw = 2, (lw - 24 - (slots - 1) * 2) / slots
        off = p["slotoff_q" if k == "quick" else "slotoff_l"]
        for j in range(slots):
            s.append(f'<rect x="{lx + 12 + j * (sw + gap):.1f}" y="{ly + 30}" width="{sw:.1f}" height="5" rx="1" fill="{off}">'
                     + discrete("fill", lambda t, j=j, k=k: p[k] if in_lane(k, t) > j else off) + "</rect>")
        text(lx + 12, ly + 54, note, 11, p["soft"], SANS)
        text(lx + 12, ly + 74, runs, 10, p["mute"], MONO)

    # Programs: who works on each, and a progress bar for long work.
    for i, ((prog, proj), y) in enumerate(zip(PROGRAMS, prog_y)):
        mine = [r for r in REQS if r[1] == i]
        working = lambda t, mine=mine: next((r for r in mine if within(t, phases(r)["work"])), None)
        s.append(f'<rect x="{px}" y="{y}" width="{pw}" height="38" rx="6" fill="{p["row"]}" stroke="{p["rowline"]}">'
                 + discrete("stroke", lambda t, w=working: p[w(t)[2]] if w(t) else p["rowline"]) + "</rect>")
        text(px + 12, y + 17, prog, 12.5, p["fg"], MONO, 600)
        text(px + 12, y + 31, proj, 10, p["faint"], MONO)
        for r in mine:
            text(px + pw - 12, y + 24, f"{r[4]} · {HEADS[r[0]].split()[0]}", 10.5, p[r[2]], MONO, 400, "end",
                 extra=discrete("opacity", lambda t, r=r: 1 if within(t, phases(r)["work"]) else 0))
            if r[2] == "long":
                w0, w1 = phases(r)["work"]
                s.append(f'<rect x="{px + 1}" y="{y + 35}" width="0" height="2.5" rx="1" fill="{p["long"]}">'
                         f'<animate attributeName="width" values="0;0;{pw - 2};0;0" keyTimes="0;{w0 / T:.4f};{w1 / T:.4f};{min(0.9999, w1 / T + 0.0005):.4f};1" dur="{T}s" repeatCount="indefinite"/></rect>')

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
