# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Resource-constrained trace runs (spec 14.13 acceptance): the engine must queue, refuse or report a partial result,
never silently produce different evidence.

    python -I trace_constrained.py --engine <install> --work <empty dir> --out result.json [--java <jdk>]

Two scenarios against a real daemon, both recorded with the engine's own words:

  disk     the daemon is started with `diskReserve` far above the free space of the trace volume. A new session is refused
           (`busy`, `details.reason` capacity, `resource` disk, with `have`/`need`/`retryAfterMs`), an append to an existing
           session is refused the same way, no file is left behind by the refusal, and every read is still served.
  budget   a session is opened with `max_events` = 2,000 and a live capture appends 10,000 events in batches of 200. The
           accounting must close: accepted + dropped_budget + rejected = submitted for every batch; the first batch that
           crosses the budget says so (`dropped_budget` > 0); `trace_info` reports `stopped` and a `budget` gap; a
           `core.capture.gap` event is queryable; later appends are refused and counted, not lost silently; the
           check over the stopped session is never `pass`; paging the session returns exactly the accepted events.

Exit status 0 only when every assertion held; the JSON holds the figures either way.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from pathlib import Path

JAVA = "C:/dev-overflow/jdk/jdk-25.0.5+8"


def ev(i, source="cap"):
    return {"kind": "core.resource.open" if i % 2 == 0 else "core.state.write", "source_id": source, "source_seq": i,
            "producer_gen": 1, "clock_domain": "mono", "t_mono_ns": 1000 + i * 1000, "confidence": "exact",
            "process_id": 7, "thread_id": 1 + i % 4,
            "payload": {"type": "file", "key": "res/%d" % (i % 31)} if i % 2 == 0 else
            {"object": i % 16, "key": "hp", "new": i % 100}}


def load_gs(install, java):
    os.environ["GHIDRA_SESSION_JAVA_HOME"] = java
    sys.path.insert(0, str(Path(install) / "Ghidra/Features/HeadlessSession/support"))
    import ghidra_session as gs  # noqa: E402
    return gs


def refusal(fn, *a, **k):
    """The error details of a refused call, or None when it was served."""
    try:
        fn(*a, **k)
    except Exception as ex:   # noqa: BLE001 - the refusal is the result
        d = getattr(ex, "details", None) or {}
        return {"code": getattr(ex, "code", type(ex).__name__), "message": str(ex)[:300], **d}
    return None


def scenario_disk(gs, engine, work):
    out = {"assertions": {}}
    ok = tight = None
    w = t = None
    try:
        # a session written on a daemon with room, then read and appended to through the tight one: same store root
        root_state = str(work / "shared-state")
        ok = gs.Daemon(engine, root_state, "constrained-ok")
        tight = gs.Daemon(engine, root_state, "constrained-tight", engine={"diskReserve": "900000000"})
        w = ok.connect("writer", "constrained")
        o = w.trace_open("held", create=True)
        cap = o["lease"]["cap"]
        w.trace_append("held", cap, [ev(0)])
        t = tight.connect("tight", "constrained")
        traces = Path(root_state) / "traces"
        before = sorted(p.name for p in traces.iterdir()) if traces.is_dir() else []
        r1 = refusal(t.trace_open, "refused-new", create=True)
        r2 = None
        got = t.trace_open("held", mode="write", cap=cap)      # reclaiming a lease writes nothing
        r2 = refusal(t.trace_append, "held", cap, [ev(1)])
        after = sorted(p.name for p in traces.iterdir()) if traces.is_dir() else []
        q = t.trace_query("held")
        lst = t.trace_list()
        out.update(new_session_refusal=r1, append_refusal=r2, files_before=before, files_after=after,
                   read_up_to=q.get("up_to"), listed=lst.get("count"), lease_after_reclaim=got.get("lease", {}).get("state"))
        a = out["assertions"]
        a["new session refused with busy/capacity on disk"] = bool(r1) and r1.get("resource") == "disk" and r1.get("code") == "busy"
        a["the refusal says have, need and when to retry"] = bool(r1) and r1.get("need", 0) > r1.get("have", 1) and r1.get("retryAfterMs", 0) > 0
        a["a refused session leaves no file behind"] = before == after
        a["an append to an existing session is refused the same way"] = bool(r2) and r2.get("resource") == "disk"
        a["reads are still served and show only the committed event"] = q.get("up_to") == 1 and (lst.get("count") or 0) >= 1
    finally:
        for s in (w, t):
            with contextlib.suppress(Exception):
                if s:
                    s.close()
        for d in (ok, tight):
            with contextlib.suppress(Exception):
                if d:
                    d.stop(force=True, timeout=60)
    return out


def scenario_budget(gs, engine, work):
    out = {"assertions": {}, "batches": []}
    d = gs.Daemon(engine, str(work / "budget-state"), "constrained-budget")
    s = None
    budget, total, batch = 2000, 10000, 200
    try:
        s = d.connect("cap", "constrained")
        st = s.call("status")
        out["daemon"] = {k: st.get(k) for k in ("limits", "scheduler", "launch", "memory", "hydraVersion", "java", "platform",
                                                 "install", "paths")}
        o = s.trace_open("capped", create=True, max_events=budget)
        cap = o["lease"]["cap"]
        accepted = dropped = rejected = 0
        first_drop_batch = None
        for first in range(0, total, batch):
            r = s.trace_append("capped", cap, [ev(i) for i in range(first, first + batch)])
            rej = len(r.get("rejected") or [])
            accepted += r["accepted"]
            dropped += r["dropped_budget"]
            rejected += rej
            if r["accepted"] + r["dropped_budget"] + rej != batch:
                out["assertions"]["every batch is accounted for"] = False
            if r["dropped_budget"] and first_drop_batch is None:
                first_drop_batch = first // batch
        info = s.trace_info("capped")
        gaps = s.trace_query("capped", kinds=["core.capture.gap"], limit=10)
        check = s.trace_check("capped", [{"type": "forbidden", "kind": "core.error", "name": "no-errors"}], persist=False)
        seen, after, pages = 0, 0, 0
        up_to = None
        while True:
            kw = {"limit": 1000, "after": after}
            if up_to is not None:
                kw["up_to"] = up_to
            p = s.trace_query("capped", **kw)
            up_to = p["up_to"]
            seen += len(p["rows"])
            pages += 1
            if p.get("next") is None:
                break
            after = p["next"]
        late = s.trace_append("capped", cap, [ev(total)])
        out.update(budget_events=budget, submitted=total, accepted=accepted, dropped_budget=dropped, rejected=rejected,
                   first_batch_with_drops=first_drop_batch, stopped=info.get("stopped"), budget_info=info.get("budget"),
                   gaps_in_info=info.get("gaps"), gap_events=len(gaps["rows"]), check_verdict=check["results"][0].get("verdict"),
                   events_in_session=info.get("events"), events_paged=seen, late_append=late)
        a = out["assertions"]
        a.setdefault("every batch is accounted for", True)
        a["accepted + dropped + rejected = submitted"] = accepted + dropped + rejected == total
        a["the budget was reached and the reply said so"] = dropped > 0 and first_drop_batch is not None
        a["trace_info reports the stop"] = bool(info.get("stopped"))
        a["a core.capture.gap event is queryable"] = len(gaps["rows"]) >= 1
        a["the check over a stopped capture is not pass"] = out["check_verdict"] != "pass"
        a["paging returns exactly the accepted events plus the stop marker"] = seen == info.get("events") and seen in (accepted, accepted + 1)
        a["a later append is refused and counted"] = late["accepted"] == 0 and late["dropped_budget"] == 1
        with contextlib.suppress(Exception):
            s.trace_close("capped", cap)
    finally:
        with contextlib.suppress(Exception):
            if s:
                s.close()
        with contextlib.suppress(Exception):
            d.stop(force=True, timeout=60)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--java", default=JAVA)
    a = ap.parse_args()
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    gs = load_gs(a.engine, a.java)
    res = {"engine": a.engine, "started": time.strftime("%Y%m%d-%H%M%S")}
    res["disk"] = scenario_disk(gs, a.engine, work)
    res["budget"] = scenario_budget(gs, a.engine, work)
    failed = [k for sc in ("disk", "budget") for k, v in res[sc]["assertions"].items() if not v]
    res["failed"] = failed
    Path(a.out).write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    for sc in ("disk", "budget"):
        for k, v in res[sc]["assertions"].items():
            print(("PASS " if v else "FAIL ") + sc + ": " + k)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
