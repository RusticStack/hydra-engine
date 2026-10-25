**What this changes and why**


**How it was tested**
- [ ] `gradle buildHeadless` builds
- [ ] `session_smoke.py` passes
- [ ] `daemon_tests.py` passes
- [ ] other (say what):

Name the OS and JDK, and paste the summary lines of the test runs. Numbers in the README come
from measurements: if this changes one, say how it was measured.

**Checklist**
- [ ] One change per commit, each commit message says what and why.
- [ ] No upstream Ghidra file changed, or the reason is stated here (each one costs a conflict on
      every upstream sync; see CONTRIBUTING.md).
- [ ] Protocol changes are documented in the module README, and `PROTOCOL` is bumped if a client
      would break.
- [ ] Docs updated (README, module README, CHANGELOG.md).
