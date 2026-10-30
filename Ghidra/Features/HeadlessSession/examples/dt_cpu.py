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
"""CPU detection and tuning profiles (Hydra Rust plan goal 4; ghidra.util.cpu.HydraCpu, docs/cpu-profiles.md).

    python daemon_tests.py --ghidra <install> --work <dir> --exe A.exe --dll B.dll --only cpu_selftest,cpu_profile_override,cpu_profile_identical

* ``cpu_selftest``: ``HydraCpu --selftest`` from the install's Utility.jar, with native access: profile
  selection on synthetic CPUs (Raptor Lake hybrid, P-cores only, AMD, a job CPU quota), budgets per core
  class, granted CPUs within 1..system and never above the JVM's count, and SetThreadSelectedCpuSets
  set + clear on this machine's granted CPU sets.
* ``cpu_profile_override``: ``HYDRA_CPU_PROFILE`` is respected (generic, a named profile, an unknown name
  -> generic, unset -> auto) and the system property ``hydra.cpu.profile`` wins over it; the daemon logs
  the profile it runs with, and sizes its gate from the granted CPUs.
* ``cpu_profile_identical``: the same fixture decompile (import + analysis of --exe, then up to 60
  functions) with the profile forced off (generic) and on (raptorlake-hybrid, and auto) gives identical C.
"""
import os
import pathlib
import subprocess
import sys

import daemon_tests as dt

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cpu_bench  # noqa: E402


def _java(c):
    install = c.gs.Install(c.a.ghidra)
    home, _ = c.gs.find_jdk(install, None, {})
    return str(c.gs._java_exe(pathlib.Path(home)))


def _probe(c, *args, env=None, props=(), native=True):
    jar = pathlib.Path(c.a.ghidra) / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    dt.check(jar.is_file(), f"no Utility.jar at {jar}")
    e = {k: v for k, v in os.environ.items() if k != "HYDRA_CPU_PROFILE"}
    e.update(env or {})
    argv = [_java(c), *(["--enable-native-access=ALL-UNNAMED"] if native else []), *props, "-cp", str(jar),
            "ghidra.util.cpu.HydraCpu", *args]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=e, stdin=subprocess.DEVNULL)
    kv = dict(ln.split("=", 1) for ln in p.stdout.splitlines() if "=" in ln)
    return p.returncode, p.stdout + p.stderr, kv


def t_cpu_selftest(c):
    rc, out, _ = _probe(c, "--selftest")
    dt.check(rc == 0 and "selftest: ok" in out, "HydraCpu --selftest failed:\n" + out[-2000:])
    rc2, out2, kv = _probe(c)
    dt.check(rc2 == 0, "probe failed:\n" + out2[-2000:])
    dt.check(int(kv["grantedCpus"]) >= 1 and int(kv["grantedCpus"]) <= int(kv["systemCpus"]), f"granted: {kv}")
    dt.check(int(kv["poolSize"]) == int(kv["grantedCpus"]) + 1, f"pool size is not granted + 1: {kv}")
    if os.name == "nt":
        dt.check(kv["source"] == "windows-cpusets" and kv["nativeAccess"] == "true",
                 f"native CPU sets not read on Windows: {kv}")
    rc3, out3, kv3 = _probe(c, native=False)
    dt.check(rc3 == 0 and kv3["source"] == "jvm" and "WARNING" not in out3,
             f"without native access the probe must fall back to the JVM silently: {out3[-800:]}")
    return (f"selftest ok; {kv['vendor']} family {kv['family']} model {kv['model']}, {kv['systemCpus']} logical, "
            f"{kv['grantedCpus']} granted, hybrid {kv['hybrid']}, auto -> {kv['profile']}")


def t_cpu_profile_override(c):
    got = {}
    for val, want in (("generic", "generic"), ("raptorlake-hybrid", "raptorlake-hybrid"),
                      ("nonesuch", "generic"), ("GENERIC", "generic")):
        rc, out, kv = _probe(c, env={"HYDRA_CPU_PROFILE": val})
        dt.check(rc == 0 and kv.get("profile") == want, f"HYDRA_CPU_PROFILE={val}: {kv or out[-800:]}")
        got[val] = kv["profile"]
    rc, out, kv = _probe(c)
    dt.check(kv.get("requested") == "auto" and kv["reason"].startswith("auto"), f"unset is not auto: {kv}")
    rc, out, kv = _probe(c, env={"HYDRA_CPU_PROFILE": "raptorlake-hybrid"}, props=["-Dhydra.cpu.profile=generic"])
    dt.check(kv.get("profile") == "generic", f"the system property does not win over the environment: {kv}")
    # the daemon runs with the override and logs it
    r = cpu_bench.run_once(c.gs, c.a.ghidra, pathlib.Path(c.a.exe), c.work / "cpu-override", "generic", "g", 3)
    cpu = r["cpu"]
    dt.check(cpu is not None, "the daemon log has no 'cpu: {...}' line")
    dt.check(cpu["profile"] == "generic" and cpu["requested"] == "generic", f"daemon profile: {cpu}")
    return f"env -> {got}; property wins; daemon: {cpu['profile']} ({cpu['reason']}), granted {cpu['grantedCpus']}"


def t_cpu_profile_identical(c):
    runs = {}
    for p in ("generic", "raptorlake-hybrid", "auto"):
        runs[p] = cpu_bench.run_once(c.gs, c.a.ghidra, pathlib.Path(c.a.exe), c.work / "cpu-identical", p, p, 60)
        dt.check(runs[p]["cpu"] is not None, f"{p}: no cpu line in the daemon log")
    dt.check(runs["raptorlake-hybrid"]["cpu"]["profile"] == "raptorlake-hybrid", "forced profile not active")
    dt.check(runs["generic"]["cpu"]["profile"] == "generic", "generic not active")
    n = runs["generic"]["functions"]
    dt.check(n > 0, "no functions decompiled")
    ds = {p: r["digest"] for p, r in runs.items()}
    dt.check(len(set(ds.values())) == 1, f"outputs differ between profiles: {ds}")
    return (f"{n} functions identical on generic/raptorlake-hybrid/auto({runs['auto']['cpu']['profile']}), "
            f"digest {ds['generic'][:12]}; placed L/B on forced: {runs['raptorlake-hybrid']['cpu']['latencyBudget']}"
            f"/{runs['raptorlake-hybrid']['cpu']['backgroundBudget']} budget")


TESTS = {
    "cpu_selftest": t_cpu_selftest,
    "cpu_profile_override": t_cpu_profile_override,
    "cpu_profile_identical": t_cpu_profile_identical,
}
