---
name: Bug report
about: Something in Hydra Engine does not work as documented
title: ''
labels: bug
assignees: ''

---

**What happened**
What you did, what you expected, and what happened instead.

**How to reproduce**
The smallest sequence that shows it. For the session daemon, the requests are the best
reproduction: `python ghidra_session.py call <cmd> key=value ...`, or the JSON lines you sent.

**Output**
The error response (`code`, `message`, `details`), and the relevant part of the daemon log
(`<state>/<instance>.log`; `ghidra_session.py config` prints where the state dir is).
Remove tokens, paths and program names you do not want public.

**Environment**
- Hydra Engine commit or build:
- Install: headless (`buildHeadless`) or full (`buildGhidra`):
- OS:
- JDK (`java -version`):
- Python (`python --version`):
- Client or harness (for example an MCP server, an agent harness, a script):

**Does it happen with upstream Ghidra too?**
If the problem is in Ghidra itself (it also happens with `analyzeHeadless` or a Ghidra build
from upstream), say so: it may belong upstream.

Security problems: do not open an issue. Report them privately, see `.github/SECURITY.md`.
