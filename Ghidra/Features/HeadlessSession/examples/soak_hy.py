## ###
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
##
"""The Hydralysis side of the soak gate (PROTOCOL-3.md 9.17, the VF integration items), driven by ``soak_tests.py``.

Runs under the Python of a Hydralysis checkout (it imports ``hydralysis`` from ``spec["hy_src"]``) against the
candidate engine; every command takes one JSON spec file written by the supervisor and writes JSON results, never a
verdict: the judgement is in ``soak_tests.py`` (``judge_hy_*``), where the self-test plants violations into it.

    python soak_hy.py setup <spec>    # prepare the target, pick the subjects (functions no call reaches)
    python soak_hy.py agent <spec>    # one H-agent: queries, renames in its own view, publish, rebase, K15 probes
    python soak_hy.py k11p <spec>     # two sub-agents in one real stdio MCP server process (K11p)
    python soak_hy.py facts <spec>    # after the run: drain the publish queue, read every view and the head (K8, K16)
    python soak_hy.py stop <spec>     # stop the Hydralysis engine daemon

Each H-agent renames only its own subjects, functions that no CALL or JUMP reaches, so a publish never changes the
decompile of a function it did not touch (Hydralysis verifies a candidate by decompiling untouched functions; renaming
a called function changes its callers' text and is refused as ``candidate_failed``)."""
from __future__ import annotations

import contextlib
import json
import os
import pathlib
import random
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

import oracle  # noqa: E402

TARGET = "soak"
#: the outcomes of a decided changeset that keep its records (views.py ``_build``): a generation was built (applied,
#: rebased onto a newer head) or the head already held them (converged, skipped)
PUBLISH_DONE = ("applied", "rebased", "converged", "skipped")


def boot(spec: dict) -> dict:
    sys.path.insert(0, spec["hy_src"])
    os.environ["HYDRALYSIS_ROOT"] = spec["root"]
    os.environ["HYDRALYSIS_CONFIG"] = spec["config"]
    os.environ.pop("HYDRALYSIS_AGENT_ID", None)
    return json.loads(pathlib.Path(spec["config"]).read_text(encoding="utf-8"))


class HyError(Exception):
    def __init__(self, code, message, payload=None):
        super().__init__(message)
        self.code, self.message, self.payload = code, message, payload or {}


#: how often one edit is redone after a stale_view (master_generation_changed) before it counts as a failure
STALE_REDO_MAX = 3


def store_key_of(root, record_id) -> str | None:
    """The view key of the Hydralysis store that holds RECORD_ID: the stem of ``overlays/<key>.json`` (Hydralysis's
    own durable store, sealed). Not the working copy's folder name: after a rebase the copy lives in ``<key>r``
    (views._shadow), which has no store, and K8 then found ``overlays/<key>r.json`` unreadable (GATE11 run)."""
    if not record_id:
        return None
    for p in sorted((pathlib.Path(root) / "overlays").glob("*.json")):
        d, _ = oracle.read_sealed(p)
        if isinstance(d, dict) and any(isinstance(e, dict) and e.get("id") == record_id for e in d.get("edits") or ()):
            return p.stem
    return None


def rebase_options(err, revision) -> dict:
    """The rebase a stale_view refusal names in ``next`` (kind rebase, its expect_revision); when it names none, a
    rebase at the view's current revision (``revision()``)."""
    det = err.payload if isinstance(err.payload, dict) else {}
    opts = ((det.get("next") or {}).get("options") or {}) if isinstance(det.get("next"), dict) else {}
    if opts.get("kind") == "rebase" and isinstance(opts.get("expect_revision"), int):
        return {"kind": "rebase", "expect_revision": opts["expect_revision"]}
    return {"kind": "rebase", "expect_revision": revision()}


#: how long a publish that is in flight when the run stops is still awaited (the supervisor waits 240 s for the
#: H-agents): its changeset is decided by its leader; giving up at the stop reported publish_undecided for a
#: publish that Hydralysis then decided (GATE11 soak-pr2: both done/ records exist, written after the stop)
STOP_GRACE_S = 120.0


def await_decision(poll, republish, csid, deadline, stopped, grace_s=STOP_GRACE_S, clock=time.time, sleep=time.sleep,
                   leaderless_s=6.0) -> dict:
    """Polls a changeset until it is decided: ``{"outcome", "generation", "changeset", "restarts", "csid",
    "past_stop"}``; ``outcome`` None when it was not decided by DEADLINE (or GRACE_S after STOPPED() first held).
    A changeset that no job leads for LEADERLESS_S (its leader was killed) is published again (``republish(csid)``
    returns the csid, the same one when the records are reused: views.run_publish_job)."""
    restarts, no_leader_since, stop_at = 0, None, None
    cs = {}
    while True:
        now = clock()
        if stop_at is None and stopped():
            stop_at = now
            deadline = min(deadline, now + grace_s) if deadline > now else now + grace_s
        if now >= deadline:
            break
        q = poll(csid)
        cs = q.get("changeset") or {}
        if cs.get("state") == "done":
            return {"outcome": cs.get("outcome"), "generation": cs.get("generation"), "changeset": cs,
                    "restarts": restarts, "csid": csid, "past_stop": stop_at is not None}
        if cs.get("state") == "unknown":
            return {"outcome": "unknown", "generation": None, "changeset": cs, "restarts": restarts, "csid": csid,
                    "past_stop": stop_at is not None}
        leading = (q.get("queue") or {}).get("leader")
        if cs.get("state") == "publish_pending" and not leading:
            no_leader_since = no_leader_since or clock()
            if clock() - no_leader_since > leaderless_s:
                restarts += 1
                csid = republish(csid)
                no_leader_since = None
        else:
            no_leader_since = None
        sleep(0.5)
    return {"outcome": None, "generation": None, "changeset": cs, "restarts": restarts, "csid": csid,
            "past_stop": stop_at is not None}


def is_stale_master(err) -> bool:
    """The documented edit/publish race: ``stale_view`` with ``stale: master_generation_changed``."""
    det = err.payload if isinstance(err.payload, dict) else {}
    return err.code == "stale_view" and det.get("stale") == "master_generation_changed"


def make_ask(settings):
    from hydralysis import query
    runner = query.QueryRunner(settings)

    def ask(action, address="", limit=40, cursor="", **opts):
        try:
            return json.loads(runner.query(TARGET, action, address, limit=limit, cursor=cursor, timeout_s=120,
                                           options=opts or None))
        except RuntimeError as e:
            text = str(e)
            payload = None
            for cand in (text, text.split(": ", 1)[-1]):
                with contextlib.suppress(ValueError):
                    payload = json.loads(cand)
                    break
            if isinstance(payload, dict):
                raise HyError(payload.get("error") or payload.get("code") or "error", payload.get("message") or text[:300],
                              payload) from e
            raise HyError("error", text[:300]) from e
        except (ValueError, OSError, TimeoutError) as e:
            raise HyError(type(e).__name__, str(e)[:300]) from e
    return ask, runner


def names_of(ask, who) -> dict:
    """``{address: name}`` of every function as the view of ``who`` shows it."""
    out, cursor = {}, ""
    for _ in range(50):
        r = ask("functions", limit=200, cursor=cursor, **{"as": who})
        for f in r.get("functions", []):
            out[f["address"]] = f["name"]
        cursor = r.get("next_cursor") or ""
        if not r.get("truncated") or not cursor:
            break
    return out


def write_json(path, obj):
    p = pathlib.Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)


# ------------------------------------------------------------------------------ setup

def cmd_setup(spec: dict) -> int:
    settings = boot(spec)
    from hydralysis import preparation
    t0 = time.time()
    job = preparation.prepare(settings, spec["binary"], TARGET)
    while True:
        st = preparation.status(settings, job["job_id"])
        if st["state"] not in preparation.ACTIVE:
            break
        time.sleep(1)
    if st["state"] != "done":
        write_json(spec["out"], {"ok": False, "state": st["state"], "status": st})
        return 1
    ask, _ = make_ask(settings)
    names = names_of(ask, "soak-setup")
    free, called = [], []
    for addr in sorted(names):
        x = ask("xrefs", addr, limit=200, **{"as": "soak-setup"})
        refs = x.get("references") or []
        (called if any(r.get("type", "DATA") != "DATA" for r in refs) else free).append(addr)
    write_json(spec["out"], {"ok": True, "prepare_s": round(time.time() - t0, 1), "functions": names, "free": free,
                             "called": called})
    return 0


# ------------------------------------------------------------------------------ one H-agent

def cmd_agent(spec: dict) -> int:
    settings = boot(spec)
    ask, _ = make_ask(settings)
    idx, me = spec["index"], spec["as"]
    adir = pathlib.Path(spec["dir"])
    rng = random.Random(spec["seed"])
    led = oracle.Ledger(adir / "ledger.jsonl")
    res = open(adir / "results.jsonl", "a", encoding="utf-8", buffering=1)
    stop_file = pathlib.Path(spec["stop_file"])
    mine = spec["subjects"]
    others = spec["all_functions"]
    recs = oracle.Ledger.read(adir / "ledger.jsonl")
    n = max([r.get("n", 0) for r in recs if r.get("kind") == "hyedit"] or [0])
    npub = max([r.get("k", 0) for r in recs if r.get("kind") == "hypublish"] or [0])
    state = {"dirty": any(r.get("kind") == "hyedit" for r in recs), "view_key": None, "k15": 0}
    for r in recs:
        if r.get("view_key"):
            state["view_key"] = r["view_key"]

    def row(op, t0, ok, code=None, **extra):
        rec = {"t": round(time.time(), 3), "agent": me, "op": op, "ms": round((time.perf_counter() - t0) * 1000, 1), "ok": ok}
        if code:
            rec["code"] = code
        rec.update(extra)
        res.write(json.dumps(rec, default=str) + "\n")

    def call(op, action, address="", _extra=None, **kw):
        t0 = time.perf_counter()
        try:
            r = ask(action, address, **kw)
            row(op, t0, True, **(_extra or {}))
            return r
        except HyError as e:
            det = e.payload if isinstance(e.payload, dict) else {}
            row(op, t0, False, e.code, message=(e.message or "")[:300], **(_extra or {}),
                details={k: det.get(k) for k in ("reason", "resource", "retryable", "retry_after_ms", "csid", "stale")
                         if k in det} or None)
            raise

    def revision():
        return ask("status", **{"as": me}).get("view_revision", 0)

    def op_query():
        k = rng.random()
        if k < 0.45:
            call("hy_decompile", "decompile", rng.choice(others), **{"as": me})
        elif k < 0.75:
            call("hy_xrefs", "xrefs", rng.choice(others), limit=50, **{"as": me})
        else:
            call("hy_functions", "functions", limit=rng.choice((20, 100, 200)), **{"as": me})

    def op_edit():
        nonlocal n
        n += 1
        tag = f"hy{idx:02d}x{n}"
        addr = rng.choice(mine)
        opid = f"{me}:edit:{n}"
        led.sent(opid, kind="hyedit", n=n, tag=tag, addr=addr)
        expect = revision()
        for attempt in range(1, STALE_REDO_MAX + 2):
            try:
                e = call("hy_edit", "type_edit", addr, _extra={"n": n, "attempt": attempt}, kind="rename", name=tag,
                         source="soak", expect_revision=expect, **{"as": me})
                break
            except HyError as err:
                # the documented contract (Hydralysis README "An edit that races a publish is the client's to rebase"):
                # an edit refused stale_view (master_generation_changed) recorded nothing; the client rebases with the
                # call in the refusal's `next` and sends the edit again with the view_revision the rebase answers.
                # The hy_stale_redo row (written only after the rebase succeeded) explains the stale row (judge_hy_rows)
                if not (is_stale_master(err) and attempt <= STALE_REDO_MAX):
                    raise
                t0 = time.perf_counter()
                rb = call("hy_rebase", "type_edit", **{**rebase_options(err, revision), "as": me})
                expect = rb.get("view_revision", rb.get("revision")) if isinstance(rb, dict) else None
                if expect is None:
                    expect = revision()
                row("hy_stale_redo", t0, True, n=n, attempt=attempt, rebase_outcome=(rb or {}).get("outcome"))
        vk = store_key_of(spec["root"], e.get("overlay_id"))
        if vk is None:
            row("hy_view_key", time.perf_counter(), False, "record_not_in_any_store", record=e.get("overlay_id"),
                working_copy=e.get("working_copy"))
            vk = state["view_key"]
        state["view_key"] = vk
        led.ack(opid, kind="hyedit", n=n, tag=tag, addr=addr, view_key=vk, record=e.get("overlay_id"))
        state["dirty"] = True

    def op_publish():
        nonlocal npub
        if not state["dirty"]:
            return op_edit()
        npub += 1
        opid = f"{me}:pub:{npub}"
        led.sent(opid, kind="hypublish", k=npub)
        t0 = time.perf_counter()
        p = call("hy_publish_seal", "type_edit", kind="publish", expect_revision=revision(), confirm_one_way_upgrade=True,
                 **{"as": me})
        csid = p.get("csid")

        def republish(cur):
            again = call("hy_publish_restart", "type_edit", kind="publish", expect_revision=revision(),
                         confirm_one_way_upgrade=True, **{"as": me})
            row("hy_publish_restart_reused", t0, again.get("csid") == cur, None if again.get("csid") == cur
                else "new_csid", csid=cur, got=again.get("csid"), reused=again.get("reused"))
            return again.get("csid") or cur

        w = await_decision(lambda c: ask("status", show="queue", csid=c, **{"as": me}), republish, csid,
                           min(time.time() + spec.get("publish_wait_s", 300), spec["deadline"] + 60), stop_file.exists)
        outcome, gen, cs, restarts, csid = w["outcome"], w["generation"], w["changeset"], w["restarts"], w["csid"]
        if outcome in PUBLISH_DONE:
            # applied or rebased: a new generation holds the records; converged or skipped: the head already held them
            led.ack(opid, kind="hypublish", k=npub, csid=csid, generation=gen, outcome=outcome)
            row("hy_publish", t0, True, csid=csid, generation=gen, outcome=outcome, restarts=restarts,
                waited_past_stop=w["past_stop"])
            state["dirty"] = False
        else:
            row("hy_publish", t0, False, outcome or "publish_undecided", csid=csid, restarts=restarts, changeset=cs,
                waited_past_stop=w["past_stop"])

    def op_rebase():
        call("hy_rebase", "type_edit", kind="rebase", expect_revision=revision(), **{"as": me})

    def op_k15():
        """K15: a view rebuilt from base + store equals the live view (the working copy's state file is removed, which
        makes the next query rebuild the view)."""
        vk = state["view_key"]
        if state["k15"] >= spec.get("k15_max", 3):
            return op_query()   # each forced rebuild costs a working copy: a few per incarnation, and one per view at the end
        if not vk or not state["dirty"]:
            return op_edit()   # a view without pending records reads the head: nothing would be rebuilt
        state["k15"] += 1
        t0 = time.perf_counter()
        live = names_of(ask, me)
        sf = pathlib.Path(spec["root"]) / "working" / vk / "state.json"
        removed = False
        with contextlib.suppress(OSError):
            sf.unlink()
            removed = True
        rebuilt = names_of(ask, me)
        try:
            sync = (json.loads(sf.read_text(encoding="utf-8")).get("last_sync") or {})
        except (OSError, ValueError):
            sync = {}
        diff = [[a, live.get(a), rebuilt.get(a)] for a in sorted(set(live) | set(rebuilt)) if live.get(a) != rebuilt.get(a)]
        row("hy_k15", t0, True, removed=removed, rebuilt=bool(sync.get("rebuilt")), replayed=sync.get("applied_now"),
            diff=diff[:20], n=len(live))

    table = {"query": op_query, "edit": op_edit, "publish": op_publish, "rebase": op_rebase, "k15": op_k15}
    weights = {"query": 50, "edit": 20, "publish": 14, "rebase": 8, "k15": 5, **(spec.get("weights") or {})}
    names = [k for k in table if weights.get(k)]
    row("ready", time.perf_counter(), True)
    forced = [k for k in ("edit", "publish", "k15", "rebase") if weights.get(k)]
    try:
        while time.time() < spec["deadline"] and not stop_file.exists():
            name = forced.pop(0) if forced else rng.choices(names, [weights[k] for k in names])[0]
            with contextlib.suppress(HyError):
                table[name]()
            time.sleep(rng.uniform(0.05, 0.4))
        return 0
    finally:
        led.close()
        res.close()


# ------------------------------------------------------------------------------ K11p: one MCP server, two sub-agents

class Mcp:
    def __init__(self, spec, name):
        env = dict(os.environ, PYTHONPATH=spec["hy_src"])
        env.pop("HYDRALYSIS_AGENT_ID", None)
        self.p = subprocess.Popen([sys.executable, "-m", "hydralysis", "mcp"], env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=spec["root"])
        self.cond = threading.Condition()
        self.replies, self.next, self.err = {}, 1, []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=lambda: [self.err.append(x.decode("utf-8", "replace")) for x in self.p.stderr],
                         daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                    "clientInfo": {"name": name, "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self):
        for line in self.p.stdout:
            if line.strip():
                with contextlib.suppress(ValueError):
                    m = json.loads(line)
                    with self.cond:
                        self.replies[m.get("id")] = m
                        self.cond.notify_all()

    def _send(self, m):
        self.p.stdin.write(json.dumps(m).encode("utf-8") + b"\n")
        self.p.stdin.flush()

    def request(self, method, params, timeout=300):
        with self.cond:
            ident, self.next = self.next, self.next + 1
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        end = time.monotonic() + timeout
        with self.cond:
            while ident not in self.replies:
                left = end - time.monotonic()
                if left <= 0 or self.p.poll() is not None:
                    raise HyError("mcp_no_reply", f"{method}: exit {self.p.poll()}: {''.join(self.err)[-600:]}")
                self.cond.wait(min(left, 0.5))
            return self.replies.pop(ident)

    def query(self, agent, action, address="", **options):
        if agent:
            options["as"] = agent
        rep = self.request("tools/call", {"name": "ghidra_query", "arguments": {"target": TARGET, "action": action,
                                                                                "address": address, "options": options}})
        text = rep["result"]["content"][0]["text"]
        for cand in (text, text.split(": ", 1)[-1]):
            with contextlib.suppress(ValueError):
                return json.loads(cand), bool(rep["result"].get("isError"))
        return text, bool(rep["result"].get("isError"))

    def close(self):
        with contextlib.suppress(Exception):
            self.p.stdin.close()
            self.p.wait(timeout=60)
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait()


def cmd_k11p(spec: dict) -> int:
    """K11p (D59): two sub-agents of one MCP server process. Without ``as`` they share one view, so Q sees P's
    unpublished rename; with distinct ``options.as`` they do not, and each sees its own. Facts only; judged by
    ``soak_tests.judge_k11p``."""
    boot(spec)
    n = spec["round"]
    s1, s2 = spec["subjects"][:2]
    out = {"round": n, "subjects": [s1, s2], "errors": []}
    m = Mcp(spec, f"soak-k11p-{n}")
    try:
        st, bad = m.query(None, "status")
        out["default_agent"] = (st.get("session") or {}).get("agent") if isinstance(st, dict) else None
        tag_shared = f"k11s{n}"
        ed, bad = m.query(None, "type_edit", s1, kind="rename", name=tag_shared, source="soak",
                          expect_revision=(st or {}).get("view_revision", 0) if isinstance(st, dict) else 0)
        if bad:
            out["errors"].append(["shared_edit", ed])
        seen = {}

        def look(key, agent, addr):
            r, b = m.query(agent, "decompile", addr)
            seen[key] = (r.get("function") or {}).get("name") if isinstance(r, dict) and not b else ["error", r]

        t = threading.Thread(target=look, args=("Q_shared", None, s1))
        t.start()
        t.join(300)
        out["shared"] = {"tag": tag_shared, "q_saw": seen.get("Q_shared")}
        tag_p = f"k11P{n}"
        pa, qa = f"k11p-P{n}", f"k11p-Q{n}"
        stp, _ = m.query(pa, "status")
        ed, bad = m.query(pa, "type_edit", s2, kind="rename", name=tag_p, source="soak",
                          expect_revision=stp.get("view_revision", 0) if isinstance(stp, dict) else 0)
        if bad:
            out["errors"].append(["isolated_edit", ed])
        ts = [threading.Thread(target=look, args=("Q_isolated", qa, s2)), threading.Thread(target=look, args=("P_own", pa, s2))]
        for x in ts:
            x.start()
        for x in ts:
            x.join(300)
        out["isolated"] = {"tag": tag_p, "q_saw": seen.get("Q_isolated"), "p_saw": seen.get("P_own")}
    except HyError as e:
        out["errors"].append([e.code, e.message])
    finally:
        m.close()
        out["stderr_tail"] = "".join(m.err)[-800:]
    write_json(spec["out"], out)
    return 0


# ------------------------------------------------------------------------------ facts after the run

def cmd_facts(spec: dict) -> int:
    """Drains every lineage's publish queue (a leader killed with nothing after it leaves its changeset queued), then
    reads what K8, K12 and K16 judge: each H-agent view's store, base generation and names, and the head's names
    through a view that holds no edit."""
    settings = boot(spec)
    from hydralysis import views
    ask, _ = make_ask(settings)
    out = {"drain": [], "views": {}, "head": None, "errors": []}
    lroot = pathlib.Path(spec["root"]) / "lineages"
    for lin in sorted(p for p in lroot.glob("L-*") if p.is_dir()) if lroot.is_dir() else []:
        try:
            d = views.drain(settings, lin.name, timeout_s=600)
            out["drain"].append({"lineage": lin.name, **{k: d.get(k) for k in ("led", "built", "failure")}})
        except Exception as e:  # noqa: BLE001
            out["errors"].append(["drain", lin.name, f"{type(e).__name__}: {e}"])
    out["k15"] = {}
    for who, vk in spec["views"].items():
        try:
            st = ask("status", **{"as": who})
            ov = (st.get("overlays") or {})
            names = names_of(ask, who)
            out["views"][who] = {"view_key": vk, "base": st.get("base") or ov.get("base") or (st.get("view") or {}).get("base"),
                                 "status": {k: st.get(k) for k in ("view_revision", "base", "view", "target")},
                                 "names": names, "pending": ov.get("pending")}
            if vk:
                # K15 once more, on the final state: the working copy's state file is removed and the view rebuilt
                sf = pathlib.Path(spec["root"]) / "working" / vk / "state.json"
                with contextlib.suppress(OSError):
                    sf.unlink()
                rebuilt = names_of(ask, who)
                try:
                    sync = json.loads(sf.read_text(encoding="utf-8")).get("last_sync") or {}
                except (OSError, ValueError):
                    sync = {}
                out["k15"][who] = {"rebuilt": bool(sync.get("rebuilt")), "pending": ov.get("pending"),
                                   "diff": [[a, names.get(a), rebuilt.get(a)] for a in sorted(set(names) | set(rebuilt))
                                            if names.get(a) != rebuilt.get(a)][:20]}
        except HyError as e:
            out["errors"].append(["view", who, e.code, e.message])
    try:
        who = f"oracle-head-{int(time.time())}"
        out["head"] = {"as": who, "status": ask("status", **{"as": who}), "names": names_of(ask, who)}
    except HyError as e:
        out["errors"].append(["head", e.code, e.message])
    write_json(spec["out"], out)
    return 0


def cmd_stop(spec: dict) -> int:
    settings = boot(spec)
    from hydralysis import hydra
    try:
        hydra.Engine(settings).stop(force=True)
        print("stopped", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"stop: {type(e).__name__}: {e}", flush=True)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ("setup", "agent", "k11p", "facts", "stop"):
        print(__doc__)
        return 2
    spec = json.loads(pathlib.Path(argv[1]).read_text(encoding="utf-8"))
    return {"setup": cmd_setup, "agent": cmd_agent, "k11p": cmd_k11p, "facts": cmd_facts, "stop": cmd_stop}[argv[0]](spec)


if __name__ == "__main__":
    sys.exit(main())
