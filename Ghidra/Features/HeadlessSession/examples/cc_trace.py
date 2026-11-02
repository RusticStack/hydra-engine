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
"""The trace commands against the client contract (PROTOCOL-3.md "Trace commands", WS-C). Standard
library only; any OS. Loaded by ``client_compat_tests.py``, or alone:

    python cc_trace.py --ghidra <install> --work <empty dir>

Tests:

* ``trace_client_fields`` (offline): the 1.1.0 client's twelve ``trace_*`` methods send the command
  name and exactly the fields given, and return the engine's result unchanged.
* ``trace_stock_refused``: the stock 1.0.0 client (protocol 2) is told ``unknown_command`` for a
  ``trace_*`` request and keeps working, its hello is unchanged and has no ``trace`` capability;
  the 1.1.0 client on the same daemon sees capability ``trace`` and a working ``trace_list``.
"""
import client_compat_tests as cc
from client_compat_tests import check, expect_error


def t_trace_client_fields(c):
    fake = cc.FakeEngine(lambda req: {"protocol": 3, "minClient": "1.0.0", "hydraVersion": "x",
                                      "ghidraVersion": "12.3", "protocolMin": 2, "protocolMax": 3})
    with c.new.SocketSession(fake.endpoint, client="cc-trace", harness="tests") as s:
        calls = [
            ("trace_open", lambda: s.trace_open("s1", create=True), {"session": "s1", "create": True}),
            ("trace_append", lambda: s.trace_append("s1", "cap", [{"kind": "core.marker"}]),
             {"session": "s1", "cap": "cap", "events": [{"kind": "core.marker"}]}),
            ("trace_mark", lambda: s.trace_mark("s1", "cap", "lbl"),
             {"session": "s1", "cap": "cap", "label": "lbl"}),
            ("trace_query", lambda: s.trace_query("s1", limit=3), {"session": "s1", "limit": 3}),
            ("trace_explain", lambda: s.trace_explain("s1", "ev_1"), {"session": "s1", "event_id": "ev_1"}),
            ("trace_diff", lambda: s.trace_diff("s1", "s2"), {"a": "s1", "b": "s2"}),
            ("trace_check", lambda: s.trace_check("s1", [{"type": "forbidden"}]),
             {"session": "s1", "assertions": [{"type": "forbidden"}]}),
            ("trace_export", lambda: s.trace_export("s1"), {"session": "s1"}),
            ("trace_close", lambda: s.trace_close("s1", "cap"), {"session": "s1", "cap": "cap"}),
            ("trace_list", lambda: s.trace_list(), {}),
            ("trace_info", lambda: s.trace_info("s1"), {"session": "s1"}),
            ("trace_resymbolize", lambda: s.trace_resymbolize("s1", "cap", "p.exe"),
             {"session": "s1", "cap": "cap", "program": "p.exe"}),
        ]
        for cmd, run, want in calls:
            r = run()
            check(r == {"cmd": cmd}, f"{cmd}: result {r}")
            last = fake.requests[-1]
            sent = {k: v for k, v in last.items() if k not in ("id", "cmd", "token", "client", "harness")}
            check(last["cmd"] == cmd and sent == want, f"{cmd}: sent {last}")
    return f"{len(calls)} trace methods send their command and fields and return the result as it is"


def t_trace_stock_refused(c):
    c.need_engine()
    d = c.daemon("trace-stock")
    with d.connect("cc-trace", "tests") as s:
        check(s.hello["protocol"] == 2 and "capabilities" not in s.hello, "the stock client is not at protocol 2")
        expect_error("unknown_command", s.call, "trace_list")
        check(s.call("ping") == {"pong": True}, "the stock session stopped working after a refusal")
    n = c.new_daemon("trace-stock")
    with n.connect("cc-trace-new", "tests") as s3:
        check(s3.protocol == 3, f"1.1.0 at {s3.protocol}")
        caps = s3.hello["capabilities"]
        if "trace" not in caps:
            d.stop()
            return "skipped: this engine has no trace capability (hydra_native library missing or trace=false)"
        r = s3.trace_list()
        check("sessions" in r and "count" in r, f"trace_list: {r}")
    d.stop()
    return "protocol 2 gets unknown_command and keeps working; protocol 3 sees capability trace and trace_list"


TESTS = {"trace_client_fields": t_trace_client_fields, "trace_stock_refused": t_trace_stock_refused}
OFFLINE = {"trace_client_fields"}

if __name__ == "__main__":
    cc.run_file(__file__)
