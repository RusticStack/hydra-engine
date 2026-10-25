"""Renders a transcript from record_session.py as an animated terminal SVG (lines appear in
order, then the loop restarts). Light and dark variants.

usage: render_terminal.py <transcript.json> <out dir>
"""
import html, json, pathlib, sys

tr = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
out = pathlib.Path(sys.argv[2])

PAL = {
    "light": dict(bg="#f6f8fa", bar="#e7ebef", fg="#1f2328", prompt="#15803d", dim="#6e7781",
                  border="#d1d9e0", dots=("#ff5f57", "#febc2e", "#28c840")),
    "dark": dict(bg="#0d1117", bar="#161b22", fg="#e6edf3", prompt="#4ade80", dim="#8b949e",
                 border="#30363d", dots=("#ff5f57", "#febc2e", "#28c840")),
}
LH, FS, PADX, TOP = 18, 13, 18, 44
CW = 7.85  # approximate monospace advance at 13px

rows = []  # (kind, text, ms)
for e in tr:
    ms = e["ms"]
    note = f"# {ms:,.0f} ms" if ms >= 10 else f"# {ms:.1f} ms"
    rows.append(("in", e["in"], note))
    for ln in e["out"].splitlines():
        rows.append(("out", ln.replace("\t", "    "), None))
rows.append(("in", "", None))

W = 860
H = TOP + LH * len(rows) + 16
step = 1.0      # seconds between statements
outgap = 0.08   # seconds between output lines
t, times = 0.4, []
for kind, _, _ in rows:
    if kind == "in":
        t += step
    else:
        t += outgap
    times.append(t)
total = times[-1] + 6.0


def svg(p):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'role="img" aria-label="A real Python session against the Hydra Engine daemon">',
         '<style>',
         f'text{{font-family:ui-monospace,SFMono-Regular,"Cascadia Code",Consolas,monospace;font-size:{FS}px;'
         f'white-space:pre}}',
         '.l{opacity:0;animation-duration:%.2fs;animation-iteration-count:infinite;animation-timing-function:step-end}' % total,
         '@media (prefers-reduced-motion:reduce){.l{animation:none;opacity:1}}']
    for i, tt in enumerate(times):
        a = 100 * tt / total
        s.append(f'@keyframes k{i}{{0%{{opacity:0}}{a:.2f}%{{opacity:1}}98%{{opacity:1}}100%{{opacity:0}}}}'
                 f'.l{i}{{animation-name:k{i}}}')
    s.append('</style>')
    s.append(f'<rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="10" fill="{p["bg"]}" stroke="{p["border"]}"/>')
    s.append(f'<path d="M.5 30 V10.5 a10 10 0 0 1 10 -10 H{W - 10.5} a10 10 0 0 1 10 10 V30 Z" fill="{p["bar"]}"/>')
    for j, c in enumerate(p["dots"]):
        s.append(f'<circle cx="{20 + j * 18}" cy="15.5" r="5.5" fill="{c}"/>')
    s.append(f'<text x="{W / 2}" y="20" text-anchor="middle" fill="{p["dim"]}">python  ·  Hydra Engine daemon</text>')
    for i, (kind, text, note) in enumerate(rows):
        y = TOP + LH * i + 10
        cls = f'l l{i}'
        if kind == "in":
            parts = [f'<tspan fill="{p["prompt"]}">&gt;&gt;&gt; </tspan>', f'<tspan fill="{p["fg"]}">{html.escape(text)}</tspan>']
            s.append(f'<text class="{cls}" x="{PADX}" y="{y}">{"".join(parts)}</text>')
            if note:
                s.append(f'<text class="{cls}" x="{W - PADX}" y="{y}" text-anchor="end" fill="{p["dim"]}">{note}</text>')
        else:
            s.append(f'<text class="{cls}" x="{PADX}" y="{y}" fill="{p["fg"]}">{html.escape(text)}</text>')
    s.append('</svg>')
    return "\n".join(s) + "\n"


for k, p in PAL.items():
    f = out / f"session-{k}.svg"
    f.write_text(svg(p), encoding="utf-8", newline="\n")
    print(f, f.stat().st_size)
