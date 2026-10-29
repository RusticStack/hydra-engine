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
"""Launcher, daemon manager and client for the Ghidra headless session.

Standard library only, Python 3.10+, any OS. No launch.bat, launch.sh or shell is involved: this
file finds a JDK, reads Ghidra's own ``support/launch.properties`` and module layout, and starts
the session JVM itself.

Shared daemon (the normal way to use it): one JVM per user that serves many projects and many
clients. The first caller starts it; everyone else finds it through a per-user endpoint file::

    import ghidra_session as gs
    with gs.connect(client="my-tool", harness="claude-code") as s:   # starts it if absent
        p = s.call("open_project", path=r"C:/re/Game")                # .gpr, its folder, a parent
        s.call("open_program", project=p["id"], path="game.exe")
        print(s.call("decompile", address="rva:0x1000")["c"])

Command line::

    python ghidra_session.py ensure            start the daemon if absent; print its endpoint
    python ghidra_session.py status            the running daemon: projects, programs, clients
    python ghidra_session.py health            does it answer, and how was it started
    python ghidra_session.py call CMD k=v...   one request through the daemon (JSON values ok)
    python ghidra_session.py stop [--force]    stop the daemon
    python ghidra_session.py serve             run the daemon in the foreground
    python ghidra_session.py stdio [ARGS...]   a private session on stdin/stdout (no daemon)
    python ghidra_session.py aot [--project P] build the JVM's AOT cache (faster cold start)
    python ghidra_session.py command           print the java command line it would run
    python ghidra_session.py config            print the effective configuration

Configuration, lowest to highest precedence: built-in defaults, ``<state dir>/config.json``,
environment (``GHIDRA_SESSION_*``), command-line options. The state dir is
``GHIDRA_SESSION_HOME`` or a per-user default (``%LOCALAPPDATA%\\GhidraSession`` on Windows,
``$XDG_STATE_HOME/ghidra-session`` or ``~/.local/state/ghidra-session`` elsewhere).

Starting and failing. ``Daemon.connect`` starts the daemon outside the caller's Windows Job Object
when the caller runs in one (breakaway, then WMI, then a one-shot scheduled task; PROTOCOL-3.md
D65), so that, when a route other than ``stayed`` works (``survival: "independent"``), the daemon
is not ended with the harness that started it. The session carries ``launch`` (how
it was started), ``started`` and ``warnings``; ``daemon_dies_with_harness`` means that every route
failed and the daemon ends with its harness. A start that fails raises ``LaunchError`` with a
``code`` (``LAUNCH_CODES``) and ``details``. ``Daemon.health()`` and ``Daemon.attach()`` are for the
doctor. ``singleton: "per-install"`` (config) refuses a second daemon of the same install under
another state dir with ``DuplicateDaemonError`` (best effort: the registry entry is written once the
daemon answers, so two launchers that start at the same moment can both pass); the default only
warns. ``GHIDRA_SESSION_SINGLETON`` overrides the policy; ``GHIDRA_SESSION_HEAP_CHECK=0`` (or
``heapCheck: false``) turns off the explicit-``maxHeap`` check, which compares ``-Xmx`` (a
reservation) with the free physical memory at that moment and can refuse a legitimate value on a
loaded machine. ``call(cmd, deadline=s)``
cancels a request that does not answer in time and raises ``SessionError("deadline_exceeded")``.

Compatibility: this file is a versioned client (``CLIENT_VERSION``) that speaks protocols
``PROTOCOL_MIN`` to ``PROTOCOL`` (2 to 3). Its ``hello`` asks for ``PROTOCOL``; the session answers
the protocol it will use on that connection (``session.protocol``, at least 2, at most the
engine's own maximum) and ``minClient``. ``connect`` raises ``IncompatibleError`` when the answer
lies outside that range, when the engine's advertised ``protocolMin``..``protocolMax`` does not
overlap it, or when ``CLIENT_VERSION`` is older than ``minClient`` (README, "Pinning and
upgrading"). Against a hydra.2 or hydra.3 engine, which knows only protocol 2, the connection is a
protocol 2 connection. The ``engine`` object of ``config.json`` is passed to the JVM as repeatable
``-set key=value`` flags (an engine that has no such flag, hydra.2 and hydra.3, refuses to start
with one: leave ``engine`` empty there).
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

#: The newest protocol this client speaks: the value its ``hello`` asks for.
PROTOCOL = 3
#: The oldest protocol this client still speaks (a hydra.2 or hydra.3 engine answers 2).
PROTOCOL_MIN = 2
#: This file's own version (major.minor.patch). The session refuses to be driven by a client older
#: than its ``minClient``; bump the major when the protocol changes incompatibly, the minor when
#: the client gains something, the patch for fixes. Shipped as hydra-client-<version>.zip.
CLIENT_VERSION = "1.1.0"
#: The Hydra Engine release this file was packaged with (hydra-client-<release>.zip stamps it);
#: ``dev`` when run from a source tree.
HYDRA_RELEASE = "dev"
MAIN_CLASS = "ghidra.app.util.headless.session.HeadlessSession"
FAST_MAIN_CLASS = "ghidra.app.util.headless.session.SessionMain"
DEFAULT_INSTANCE = "default"
ENDPOINT_WAIT_S = 180.0

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"


# ---- install --------------------------------------------------------------------------------

#: The ``code`` values of a ``LaunchError`` that says why a start failed (PROTOCOL-3.md, 3.8).
#: ``IncompatibleError`` keeps its own code, ``incompatible``.
LAUNCH_CODES = ("no_jdk", "jdk_too_old", "bad_install", "lock_held", "heap_too_large",
                "exited_early", "no_answer", "duplicate_daemon",
                "not_running")  # not_running: attach()/start=False and no daemon runs; a JVM that is
                # alive but does not answer (wedged, or not listening yet) is no_answer


class LaunchError(RuntimeError):
    """The session could not be started: no JDK, a bad install, a daemon that does not answer.

    ``str(e)`` is the message (unchanged by the structure). ``code`` is one of ``LAUNCH_CODES``
    (``None`` for an error that has no code yet) and ``details`` a dict with what a caller or the
    doctor needs: ``javaMin``, ``tried[]``, ``logTail``, ``holder``, ``suggest``, depending on the
    code."""

    def __init__(self, message, code=None, details=None):
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


class IncompatibleError(LaunchError):
    """The session speaks another protocol, or requires a newer client than this file."""

    def __init__(self, message, code="incompatible", details=None):
        super().__init__(message, code, details)


class DuplicateDaemonError(LaunchError):
    """``singleton: "per-install"`` and a live daemon of the same install runs under another state
    dir. ``holder`` is ``{pid, stateDir, instance, install, ...}``; ``ways_out`` the three ways
    out (also in ``details["suggest"]``)."""

    def __init__(self, message, holder, ways_out):
        super().__init__(message, "duplicate_daemon", {"holder": holder, "suggest": list(ways_out)})
        self.holder = holder
        self.ways_out = list(ways_out)


def parse_version(text) -> tuple[int, ...]:
    """``"1.2.3"`` as ``(1, 2, 3)``; anything else raises ``ValueError``."""
    parts = str(text).strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        raise ValueError(f"not a dotted version: {text!r}")
    return tuple(int(p) for p in parts)


def _is_protocol(v) -> bool:
    """True for a JSON integer (a bool, a string or a float is not a protocol number)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _span(lo, hi) -> str:
    return str(lo) if lo == hi else f"{lo}..{hi}"


def _client_range(protocol=None, protocol_min=None) -> tuple[int, int]:
    """The protocols this client accepts, as ``(lowest, highest)``, read from the module
    constants at call time. An explicit ``protocol`` without ``protocol_min`` is exactly that one
    protocol (what ``check_compatible`` meant before the range existed)."""
    hi = PROTOCOL if protocol is None else protocol
    if protocol_min is not None:
        lo = protocol_min
    else:
        lo = min(PROTOCOL_MIN, hi) if protocol is None else hi
    return lo, hi


def engine_protocols(info: dict) -> tuple[int, int] | None:
    """The protocols an engine says it serves, from a ``hello`` answer, a ``ready`` event or an
    endpoint file: ``protocolMin``..``protocolMax`` when it sends them, else the single
    ``protocol`` (a hydra.2 or hydra.3 engine). ``None`` when there is no usable integer."""
    p = info.get("protocol")
    lo, hi = info.get("protocolMin", p), info.get("protocolMax", p)
    if _is_protocol(lo) and _is_protocol(hi):
        return lo, hi
    return None


def check_compatible(info: dict, client_version: str = CLIENT_VERSION,
                     protocol: int | None = None, protocol_min: int | None = None) -> None:
    """Checks a ``hello`` answer (or the ``ready`` event) against this client; raises
    ``IncompatibleError`` with the versions on both sides when they do not fit. The answer's
    ``protocol`` must lie in ``PROTOCOL_MIN``..``PROTOCOL`` (``protocol`` alone, when given
    without ``protocol_min``, means exactly that protocol) and, when the engine advertises
    ``protocolMin`` and ``protocolMax``, that range must overlap the client's and contain the
    answer. A session that reports no ``minClient`` (a build before the contract) is accepted when
    the protocol fits."""
    theirs = info.get("protocol")
    lo, hi = _client_range(protocol, protocol_min)
    who = (f"Hydra Engine {info.get('hydraVersion') or '?'} (Ghidra "
           f"{info.get('ghidraVersion') or info.get('ghidra') or '?'})")
    mine = f"this client (ghidra_session.py {client_version}) speaks {_span(lo, hi)}"
    advertised = engine_protocols(info)
    said = f"protocol {theirs!r}" if not _is_protocol(theirs) else f"protocol {theirs}"
    if advertised and advertised != (theirs, theirs):
        said += f" (advertises {_span(*advertised)})"
    if not _is_protocol(theirs) or not lo <= theirs <= hi:
        raise IncompatibleError(
            f"{who} speaks {said}, {mine}: use the client of the same release as the engine")
    if advertised is None:
        raise IncompatibleError(f"{who} reports an unreadable protocolMin or protocolMax")
    if advertised[1] < lo or advertised[0] > hi or not advertised[0] <= theirs <= advertised[1]:
        raise IncompatibleError(
            f"{who} speaks {said} but its range does not fit, {mine}: use the client of the "
            f"same release as the engine")
    need = info.get("minClient")
    if need:
        try:
            too_old = parse_version(client_version) < parse_version(need)
        except ValueError as e:
            raise IncompatibleError(f"{who} reports an unreadable minClient: {e}") from e
        if too_old:
            raise IncompatibleError(
                f"{who} requires a client of at least {need}, this is ghidra_session.py "
                f"{client_version}: upgrade the client to the one released with the engine")


def _read_properties(path: Path) -> list[tuple[str, str]]:
    """Reads a Java-style ``key=value`` file, keeping repeated keys in order."""
    out = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out.append((k.strip(), v.strip()))
    return out


class Install:
    """A Ghidra installation (a release layout: ``<dir>/Ghidra/application.properties``)."""

    def __init__(self, path: str | os.PathLike):
        self.dir = Path(path).resolve()
        self.app_root = self.dir / "Ghidra"
        props_file = self.app_root / "application.properties"
        if not props_file.is_file():
            raise LaunchError(f"not a Ghidra installation (no Ghidra/application.properties): "
                              f"{self.dir}", "bad_install",
                              {"path": str(self.dir), "missing": "Ghidra/application.properties"})
        self.props = dict(_read_properties(props_file))
        self.version = self.props.get("application.version", "?")
        self.release = self.props.get("application.release.name", "")
        self.name = self.props.get("application.name", "Ghidra")
        self.java_min = int(self.props.get("application.java.min", "21") or 21)
        jmax = self.props.get("application.java.max", "")
        self.java_max = int(jmax) if jmax else None
        self.support = self.dir / "support"
        self.utility_jar = self.app_root / "Framework" / "Utility" / "lib" / "Utility.jar"
        if not self.utility_jar.is_file():
            raise LaunchError(f"{self.utility_jar} is missing: only built (release) installs "
                              "can be launched", "bad_install",
                              {"path": str(self.dir), "missing": str(self.utility_jar)})
        self.module_dir = self.app_root / "Features" / "HeadlessSession"
        if not (self.module_dir / "lib" / "HeadlessSession.jar").is_file():
            raise LaunchError(f"this install has no HeadlessSession module: {self.module_dir}",
                              "bad_install", {"path": str(self.dir),
                                              "missing": str(self.module_dir / "lib" / "HeadlessSession.jar")})

    @staticmethod
    def locate(explicit: str | None = None) -> "Install":
        """``explicit``, else the install this file belongs to, else ``GHIDRA_INSTALL_DIR`` (for a
        copy of this file kept outside an install)."""
        if explicit:
            return Install(explicit)
        here = Path(__file__).resolve()
        # <install>/Ghidra/Features/HeadlessSession/support/ghidra_session.py
        for parent in here.parents:
            if (parent / "Ghidra" / "application.properties").is_file():
                return Install(parent)
        if os.environ.get("GHIDRA_INSTALL_DIR"):
            return Install(os.environ["GHIDRA_INSTALL_DIR"])
        raise LaunchError("no Ghidra install: pass --ghidra <dir> or set GHIDRA_INSTALL_DIR",
                          "bad_install", {"suggest": "pass --ghidra <dir> or set GHIDRA_INSTALL_DIR"})

    # launch.properties: VMARGS, VMARGS_<OS>, ENVVARS, ENVVARS_<OS>, JAVA_HOME_OVERRIDE
    def launch_properties(self) -> dict:
        os_key = "WINDOWS" if IS_WINDOWS else "MACOS" if IS_MAC else "LINUX"
        res = {"vmargs": [], "envvars": {}, "java_home_override": ""}
        f = self.support / "launch.properties"
        if not f.is_file():
            return res
        for k, v in _read_properties(f):
            if k in ("VMARGS", f"VMARGS_{os_key}"):
                if v:
                    res["vmargs"].append(v)
            elif k in ("ENVVARS", f"ENVVARS_{os_key}"):
                if "=" in v:
                    ek, ev = v.split("=", 1)
                    res["envvars"][ek] = ev
            elif k == "JAVA_HOME_OVERRIDE":
                res["java_home_override"] = v
        return res

    def settings_dir(self, vmargs: list[str]) -> Path:
        """Ghidra's per-user settings dir (rules from launch.properties' comments)."""
        leaf = f"{self.name.lower().replace(' ', '')}_{self.version}_" \
               f"{self.release.replace(' ', '').upper()}"
        app = self.name.lower().replace(" ", "")
        for a in vmargs:
            if a.startswith("-Dapplication.settingsdir="):
                return Path(a.split("=", 1)[1]) / app / leaf
        if os.environ.get("XDG_CONFIG_HOME"):
            return Path(os.environ["XDG_CONFIG_HOME"]) / app / leaf
        if IS_WINDOWS:
            return Path(os.environ.get("APPDATA", Path.home())) / app / leaf
        if IS_MAC:
            return Path.home() / "Library" / app / leaf
        return Path.home() / ".config" / app / leaf

    # The release-mode classpath of GhidraLauncher.buildClasspath, rebuilt from the module layout:
    # patch dir, then every module's lib/ and libs/ jars, modules ordered by type then name,
    # external (extension) modules last, fat jars moved to the end, Utility left out (it is
    # passed first by the caller).
    _TYPE_PRIORITY = {"Framework": 0, "Configurations": 1, "Features": 2, "Debug": 3,
                      "Processors": 4, "GPL": 5, "Extensions": 6, "Test": 7}

    def modules(self, vmargs: list[str]) -> list[tuple[Path, bool]]:
        found: dict[str, tuple[Path, bool]] = {}

        def is_module(d: Path) -> bool:
            return (d / "Module.manifest").is_file()

        def walk(root: Path, depth: int):
            if not root.is_dir() or depth <= 0:
                return
            for sub in sorted(p for p in root.iterdir() if p.is_dir()):
                if sub.name == "build":
                    continue
                if is_module(sub):
                    found.setdefault(sub.name, (sub, False))
                else:
                    walk(sub, depth - 1)

        walk(self.dir / "GPL", 3)
        walk(self.app_root, 3)
        ext_dirs = [self.settings_dir(vmargs) / "Extensions", self.app_root / "Extensions"]
        for ext in ext_dirs:
            if not ext.is_dir():
                continue
            for sub in sorted(p for p in ext.iterdir() if p.is_dir()):
                if self.app_root in sub.parents:
                    continue  # already found inside the application root
                if (sub / "Module.manifest.uninstalled").exists() or not is_module(sub):
                    continue
                found.setdefault(sub.name, (sub, True))

        def key(item):
            name, (d, external) = item
            if external:
                return (1, 0, name)
            prio = self._TYPE_PRIORITY.get(d.parent.name, len(self._TYPE_PRIORITY))
            return (0, prio, name)

        return [v for _, v in sorted(found.items(), key=key)]

    def classpath(self, vmargs: list[str]) -> list[str]:
        cp: list[str] = []
        patch = self.app_root / "patch"
        if patch.is_dir():
            # GhidraLauncher lists the directory itself for loose class files. A stock install
            # has only a README there, and a JVM AOT cache refuses any non-empty directory on
            # the classpath, so the directory is listed only when it holds something loadable.
            loose = [p for p in patch.iterdir()
                     if p.suffix.lower() != ".jar" and not p.name.lower().startswith("readme")]
            if loose:
                cp.append(str(patch))
            cp.extend(str(j) for j in sorted(patch.glob("*.jar"), key=lambda p: p.name))
        fat: set[str] = set()
        utility_root = self.app_root / "Framework" / "Utility"
        for mdir, _ext in self.modules(vmargs):
            for line in (mdir / "Module.manifest").read_text(encoding="utf-8",
                                                             errors="replace").splitlines():
                if line.strip().startswith("FAT JAR:"):
                    fat.add(line.strip()[len("FAT JAR:"):].strip())
            if mdir.resolve() == utility_root.resolve():
                continue
            for lib in ("lib", "libs"):
                ld = mdir / lib
                if ld.is_dir():
                    cp.extend(str(j) for j in sorted(ld.glob("*.jar"), key=lambda p: p.name))
        normal = [p for p in cp if Path(p).name not in fat]
        return normal + [p for p in cp if Path(p).name in fat]


# ---- JDK ------------------------------------------------------------------------------------

def _java_exe(home: Path) -> Path:
    return home / "bin" / ("java.exe" if IS_WINDOWS else "java")


def _jdk_version(home: Path) -> tuple[int, str] | None:
    """(major, full) from the JDK's ``release`` file, without starting a JVM."""
    rel = home / "release"
    if not rel.is_file():
        return None
    for k, v in _read_properties(rel):
        if k == "JAVA_VERSION":
            full = v.strip('"')
            parts = full.split(".")
            major = int(parts[1]) if parts[0] == "1" else int(re.match(r"\d+", parts[0]).group())
            return major, full
    return None


def find_jdk(install: Install, explicit: str | None, launch_props: dict) -> tuple[Path, str]:
    """A JDK home that satisfies the install's Java range. Order: explicit (``--java``/config),
    ``GHIDRA_SESSION_JAVA_HOME``, launch.properties ``JAVA_HOME_OVERRIDE``, ``JAVA_HOME``, the
    JDK Ghidra's own launcher saved for this version, then ``java`` on PATH."""
    tried = []
    wrong_version = []  # real JDKs that the install's Java range excludes

    def candidates():
        yield "explicit", explicit
        yield "GHIDRA_SESSION_JAVA_HOME", os.environ.get("GHIDRA_SESSION_JAVA_HOME")
        yield "JAVA_HOME_OVERRIDE", launch_props.get("java_home_override")
        yield "JAVA_HOME", os.environ.get("JAVA_HOME")
        save = install.settings_dir(launch_props["vmargs"]) / "java_home.save"
        if save.is_file():
            yield "java_home.save", save.read_text(encoding="utf-8").strip()
        on_path = shutil.which("java")
        if on_path:
            yield "PATH", str(Path(on_path).resolve().parent.parent)

    for src, cand in candidates():
        if not cand:
            continue
        home = Path(cand)
        if home.is_file():  # a java executable was given
            home = home.resolve().parent.parent
        v = _jdk_version(home)
        if v is None or not _java_exe(home).is_file():
            tried.append(f"{src}={cand} (not a JDK)")
            continue
        major, full = v
        if major < install.java_min or (install.java_max and major > install.java_max):
            tried.append(f"{src}={cand} (Java {full}; Ghidra {install.version} needs "
                         f"{install.java_min}{'-' + str(install.java_max) if install.java_max else '+'})")
            wrong_version.append({"source": src, "home": str(home), "version": full})
            continue
        if not (home / "bin" / ("javac.exe" if IS_WINDOWS else "javac")).is_file():
            tried.append(f"{src}={cand} (a JRE; Ghidra needs a JDK)")
            continue
        return home, full
    details = {"javaMin": install.java_min, "javaMax": install.java_max, "tried": tried,
               "suggest": "set GHIDRA_SESSION_JAVA_HOME or pass --java"}
    if wrong_version:
        details["found"] = wrong_version
    raise LaunchError("no suitable JDK found; set GHIDRA_SESSION_JAVA_HOME or pass --java. Tried: "
                      + ("; ".join(tried) or "nothing (no JAVA_HOME, no java on PATH)"),
                      "jdk_too_old" if wrong_version else "no_jdk", details)


# ---- state dir and configuration ------------------------------------------------------------

def state_dir(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    if os.environ.get("GHIDRA_SESSION_HOME"):
        return Path(os.environ["GHIDRA_SESSION_HOME"]).resolve()
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "GhidraSession"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "GhidraSession"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "ghidra-session"


def ensure_state(st: Path) -> Path:
    """Creates the state dir; owner-only on POSIX (it holds the daemon's token). On Windows it
    inherits the per-user ACL of its parent (``%LOCALAPPDATA%`` by default)."""
    st.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        with contextlib.suppress(OSError):
            os.chmod(st, 0o700)
    return st


def physical_memory_bytes() -> int | None:
    try:
        if IS_WINDOWS:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]

            st = MEMORYSTATUSEX()
            st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullTotalPhys)
            return None
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError, AttributeError):
        return None


def available_memory_bytes() -> int | None:
    """Physical memory that is free right now (what a JVM could commit without paging), or None."""
    try:
        if IS_WINDOWS:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]

            st = MEMORYSTATUSEX()
            st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullAvailPhys)
            return None
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
    except (OSError, ValueError, AttributeError):
        return None


def heap_bytes(text) -> int | None:
    """``-Xmx`` text (``16g``, ``512m``, ``2048k``, a plain byte count) in bytes; None if unreadable."""
    t = str(text).strip().lower()
    units = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
    try:
        return int(t[:-1]) * units[t[-1]] if t and t[-1] in units else int(t)
    except ValueError:
        return None


def default_max_heap() -> str:
    """A quarter of physical memory, between 2 GiB and 32 GiB (compressed-oops limit)."""
    mem = physical_memory_bytes()
    if not mem:
        return "4g"
    gib = max(2, min(31, mem // (4 << 30)))
    return f"{gib}g"


DEFAULTS = {
    "java": None,            # JDK home (else discovered)
    "maxHeap": None,         # -Xmx; None: default_max_heap()
    "minHeap": "512m",       # -Xms
    "gc": "g1",              # g1 | zgc | parallel | default (the JDK's choice)
    "vmargs": [],            # extra JVM options, appended last
    "tmpdir": None,          # java.io.tmpdir: where Ghidra keeps unsaved database buffers
    "mode": "fast",          # fast (app class loader, AOT-capable) | standard (GhidraClassLoader)
    "aot": "auto",           # auto (use the cache when it exists) | off
    "classCache": True,      # reuse the class search result while the classpath is unchanged
    "idleTimeout": 0,        # seconds without clients before the daemon exits; 0: stay up
    "keepWarm": 3600,        # seconds an unused read-only program stays open; 0: close at once
    "maxQuick": 0,           # concurrent quick requests (decompile, ...); 0: CPU count
    "maxLong": 0,            # concurrent long requests (analyze, import, script); 0: max(8, CPUs)
                             # (E3a, D40; an engine before hydra.4 still uses CPUs/4, at least 2)
    "maxImports": 0,         # concurrent imports (each also takes a long slot); 0: CPU/4, 1..4
    "scriptPath": [],        # extra GhidraScript directories
    "log": None,             # daemon log; None: <state>/<instance>.log
    "upgradeCache": True,    # serve read-only opens of older-format programs from an upgraded copy
    "upgradeCacheDir": None,  # where those copies live; None: <state>/upgrade-cache
    "forkCopyLimitMb": 2048,  # fork_project mode auto: refuse a full (not cloned) copy over this
    "engine": {},            # engine settings: each key=value goes to the JVM as ``-set key=value``
    "singleton": "warn",     # warn | per-install: a live daemon of this install under another state
                             # dir is reported (warn) or refused (DuplicateDaemonError)
    "heapCheck": True,       # refuse an explicit maxHeap that is larger than the free physical memory
}

ENV_MAP = {
    "GHIDRA_SESSION_JAVA_HOME": ("java", str),
    "GHIDRA_SESSION_MAXMEM": ("maxHeap", str),
    "GHIDRA_SESSION_GC": ("gc", str),
    "GHIDRA_SESSION_TMPDIR": ("tmpdir", str),
    "GHIDRA_SESSION_MODE": ("mode", str),
    "GHIDRA_SESSION_AOT": ("aot", str),
    "GHIDRA_SESSION_IDLE_TIMEOUT": ("idleTimeout", int),
    "GHIDRA_SESSION_KEEP_WARM": ("keepWarm", int),
    "GHIDRA_SESSION_UPGRADE_CACHE": ("upgradeCache", lambda v: v.strip().lower() not in
                                     ("0", "false", "off", "no")),
    "GHIDRA_SESSION_UPGRADE_CACHE_DIR": ("upgradeCacheDir", str),
    "GHIDRA_SESSION_FORK_COPY_LIMIT_MB": ("forkCopyLimitMb", int),
    "GHIDRA_SESSION_SINGLETON": ("singleton", str),
    "GHIDRA_SESSION_HEAP_CHECK": ("heapCheck", lambda v: v.strip().lower() not in
                                  ("0", "false", "off", "no")),
}


_ENGINE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")


def engine_flags(engine: dict | None) -> list[str]:
    """The JVM arguments for an ``engine`` object: ``-set key=value`` once per entry, in the
    object's order. A value is a string, a number or a boolean (written ``true``/``false``, as
    the engine's ``Settings`` reads it); anything else, a key that is not an identifier, or a
    value with a control character raises ``LaunchError``, so nothing reaches the JVM that the
    engine would have to guess about."""
    if engine is None:
        return []
    if not isinstance(engine, dict):
        raise LaunchError(f"engine must be an object of key: value settings, not {engine!r}")
    out: list[str] = []
    for k, v in engine.items():
        if not isinstance(k, str) or not _ENGINE_KEY.fullmatch(k):
            raise LaunchError(f"engine: bad key {k!r} (letters, digits, . _ -, starting with a "
                              f"letter)")
        if isinstance(v, bool):
            text = "true" if v else "false"
        elif isinstance(v, int):
            text = str(v)
        elif isinstance(v, float) and v == v and v not in (float("inf"), float("-inf")):
            text = repr(v)
        elif isinstance(v, str) and not any(ord(c) < 32 or ord(c) == 127 for c in v):
            text = v
        else:
            raise LaunchError(f"engine.{k}: {v!r} is not a string, number or boolean")
        out += ["-set", f"{k}={text}"]
    return out


def load_config(state: Path, overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULTS)
    cfg["engine"] = {}
    f = state / "config.json"
    if f.is_file():
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except ValueError as e:
            raise LaunchError(f"{f}: {e}") from e
        unknown = set(data) - set(DEFAULTS)
        if unknown:
            raise LaunchError(f"{f}: unknown keys {sorted(unknown)}; known: {sorted(DEFAULTS)}")
        cfg.update(data)
        try:
            engine_flags(cfg["engine"])
        except LaunchError as e:
            raise LaunchError(f"{f}: {e}") from e
    for env, (key, typ) in ENV_MAP.items():
        if os.environ.get(env):
            cfg[key] = typ(os.environ[env])
    if os.environ.get("GHIDRA_SESSION_VMARGS"):
        cfg["vmargs"] = list(cfg["vmargs"]) + os.environ["GHIDRA_SESSION_VMARGS"].split()
    for k, v in (overrides or {}).items():
        if v is not None:
            if k == "engine":
                # settings merge key by key, the caller's winning, rather than replace the file's
                engine_flags(v)
                v = {**(cfg["engine"] or {}), **v}
            cfg[k] = v
    if cfg["mode"] not in ("fast", "standard"):
        raise LaunchError(f"mode must be fast or standard, not {cfg['mode']!r}")
    if cfg["gc"] not in ("g1", "zgc", "parallel", "default"):
        raise LaunchError(f"gc must be g1, zgc, parallel or default, not {cfg['gc']!r}")
    if cfg["singleton"] not in ("warn", "per-install"):
        raise LaunchError(f"singleton must be warn or per-install, not {cfg['singleton']!r}")
    return cfg


# ---- the JVM command ------------------------------------------------------------------------

class Launch:
    """Everything needed to start one session JVM."""

    def __init__(self, install: Install, cfg: dict, state: Path):
        self.install = install
        self.cfg = cfg
        self.state = state
        self.props = install.launch_properties()
        self.jdk, self.jdk_version = find_jdk(install, cfg.get("java"), self.props)
        self.java = _java_exe(self.jdk)
        self.env = dict(os.environ)
        for k, v in self.props["envvars"].items():
            self.env.setdefault(k, v)

    def gc_args(self) -> list[str]:
        gc = self.cfg["gc"]
        if gc == "g1":
            # Return unused heap to the OS while the daemon idles; dedup the many equal strings
            # of a large program's symbols.
            return ["-XX:+UseG1GC", "-XX:+UseStringDeduplication",
                    "-XX:G1PeriodicGCInterval=300000"]
        if gc == "zgc":
            return ["-XX:+UseZGC", "-XX:ZUncommitDelay=300"]
        if gc == "parallel":
            return ["-XX:+UseParallelGC"]
        return []

    def key(self, classpath: list[str]) -> str:
        """Identity of this JVM + classpath: names the AOT cache and the class search cache."""
        h = hashlib.sha256()
        h.update(f"{self.jdk}|{self.jdk_version}|{self.install.dir}|{self.install.version}"
                 .encode())
        for p in classpath:
            try:
                st = os.stat(p)
                h.update(f"|{p}|{st.st_size}|{st.st_mtime_ns}".encode())
            except OSError:
                h.update(f"|{p}|-".encode())
        return h.hexdigest()[:16]

    def heap(self) -> str:
        return self.cfg.get("maxHeap") or default_max_heap()

    def check_heap(self):
        """An explicit ``maxHeap`` above the physical memory that is free now is refused with
        ``heap_too_large`` (the JVM would start and then be paged to death or killed). The default
        heap (a quarter of the memory) is never checked, and ``heapCheck: false`` turns it off."""
        if not self.cfg.get("maxHeap") or not self.cfg.get("heapCheck", True):
            return
        want = heap_bytes(self.cfg["maxHeap"])
        free = available_memory_bytes()
        total = physical_memory_bytes()
        if want is not None and free is not None and want > free:
            raise LaunchError(
                f"maxHeap {self.cfg['maxHeap']} ({want >> 20} MiB) is more than the free physical "
                f"memory ({free >> 20} MiB of {(total or 0) >> 20} MiB); lower maxHeap, free memory, "
                f"or set heapCheck to false", "heap_too_large",
                {"maxHeap": self.cfg["maxHeap"], "heapBytes": want, "freeBytes": free,
                 "totalBytes": total,
                 "suggest": f"use maxHeap up to {max(1, free >> 30)}g, or set heapCheck false"})

    @staticmethod
    def grants_native_access(args: list[str]) -> bool:
        """True when ``args`` already carry ``--enable-native-access`` for unnamed code (any
        spelling: ``=ALL-UNNAMED``, a list containing it, or the two-token form)."""
        for i, a in enumerate(args):
            if a.startswith("--enable-native-access="):
                if "ALL-UNNAMED" in a.split("=", 1)[1].split(","):
                    return True
            elif a == "--enable-native-access" and i + 1 < len(args):
                if "ALL-UNNAMED" in args[i + 1].split(","):
                    return True
        return False

    def aot_flavor(self, base_vm: list[str]) -> str:
        """The JVM options an AOT cache must have been recorded with: the JVM refuses a cache made
        with another garbage collector, object header layout or compressed-pointer mode, and then
        silently runs without it. So each set of options gets its own cache file."""
        heap = self.heap().lower()
        units = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
        try:
            size = int(heap[:-1]) * units[heap[-1]] if heap[-1] in units else int(heap)
        except ValueError:
            size = 0
        shaping = re.compile(r"-XX:[+-]?(Use\w*GC|UseCompactObjectHeaders|UseCompressed\w+|"
                             r"ObjectAlignmentInBytes=\S+)$")
        opts = [a for a in [*base_vm, *self.gc_args(), *(self.cfg.get("vmargs") or [])]
                if shaping.match(a)] + [f"coops={size < 32 << 30}"]
        return hashlib.sha256("|".join(opts).encode()).hexdigest()[:8]

    def command(self, app_args: list[str], *, aot_output: Path | None = None,
                use_aot: bool = True) -> tuple[list[str], dict]:
        """(argv, info). Fast mode passes the classpath through an @argfile in the state dir."""
        mode = self.cfg["mode"]
        vm = list(self.props["vmargs"])
        info = {"mode": mode, "java": str(self.java), "jdk": self.jdk_version}
        if mode == "fast":
            # The default app class loader instead of GhidraClassLoader: everything is on -cp,
            # so the JVM's AOT/CDS cache can hold Ghidra's classes too. CDS is only off in
            # launch.properties because of the custom loader.
            vm = [a for a in vm if not a.startswith("-Djava.system.class.loader=")
                  and a != "-Xshare:off"]
            cp = [str(self.install.utility_jar)] + self.install.classpath(vm)
            key = self.key(cp)
            argdir = self.state / "launch"
            argdir.mkdir(parents=True, exist_ok=True)
            argfile = argdir / f"classpath-{key}.args"
            if not argfile.is_file():
                tmp = argfile.with_suffix(".tmp")
                # @argfile syntax: quote, and escape backslashes inside quotes
                quoted = os.pathsep.join(cp).replace("\\", "\\\\")
                tmp.write_text(f'-cp "{quoted}"\n', encoding="utf-8")
                os.replace(tmp, argfile)
            info["key"] = key
            info["classpathEntries"] = len(cp)
            head = [f"@{argfile}"]
            main = [FAST_MAIN_CLASS]
            info["aotKey"] = aot_key = f"{key}-{self.aot_flavor(vm)}"
            aot_file = self.state / "aot" / f"{aot_key}.aot"
            if aot_output is not None:
                vm.append(f"-XX:AOTCacheOutput={aot_output}")
                info["aot"] = "training"
            elif use_aot and self.cfg["aot"] == "auto" and aot_file.is_file():
                vm += [f"-XX:AOTCache={aot_file}", f"-Dghidra.session.aot={aot_file}"]
                info["aot"] = str(aot_file)
            else:
                info["aot"] = None
            if self.cfg.get("classCache", True):
                vm.append(f"-Dghidra.session.classCache={self.state / 'classcache' / key}.json")
        else:
            head = ["-cp", str(self.install.utility_jar)]
            main = ["ghidra.Ghidra", MAIN_CLASS]
            info["aot"] = None
        # D60: the daemon's own Job Object (E9) calls the FFM API, which needs this on the JVM
        # command line itself (not JAVA_TOOL_OPTIONS, which the WMI route would lose). Ghidra's
        # launch.properties may already carry it (for FlatLaf): then nothing is added.
        if not self.grants_native_access(vm + list(self.cfg.get("vmargs") or [])):
            vm.append("--enable-native-access=ALL-UNNAMED")
        heap = self.heap()
        vm += [f"-Xmx{heap}", f"-Xms{self.cfg.get('minHeap') or '512m'}"]
        vm += self.gc_args()
        # stdout is the protocol channel; the JVM's own log (an AOT cache that does not match,
        # GC warnings) goes to stdout unless told otherwise.
        vm += ["-Xlog:disable", "-Xlog:all=warning:stderr", "-Djava.awt.headless=true"]
        if self.cfg.get("tmpdir"):
            Path(self.cfg["tmpdir"]).mkdir(parents=True, exist_ok=True)
            vm.append(f"-Djava.io.tmpdir={self.cfg['tmpdir']}")
        vm += list(self.cfg.get("vmargs") or [])
        info["maxHeap"] = heap
        app_args = list(app_args)
        if self.cfg.get("upgradeCache", True):
            app_args += ["-upgradeCache",
                         str(self.cfg.get("upgradeCacheDir") or self.state / "upgrade-cache")]
        if self.cfg.get("forkCopyLimitMb") is not None:
            app_args += ["-forkCopyLimitMb", str(int(self.cfg["forkCopyLimitMb"]))]
        app_args += engine_flags(self.cfg.get("engine"))
        argv = [str(self.java), *vm, *head, *main, *app_args]
        return argv, info


# ---- file locks (also seen by the JVM's FileChannel locks) ----------------------------------

class FileLock:
    """An exclusive lock on one file, held while the object is open. On POSIX it is an fcntl
    record lock (the kind Java's FileChannel.lock takes); on Windows a LockFileEx range lock."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        self.held = False

    def try_acquire(self) -> bool:
        try:
            if IS_WINDOWS:
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.lockf(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)
            self.held = True
            return True
        except OSError:
            return False

    def acquire(self, timeout: float) -> bool:
        end = time.monotonic() + timeout
        while not self.try_acquire():
            if time.monotonic() > end:
                return False
            time.sleep(0.05)
        return True

    def release(self):
        if self.held:
            try:
                if IS_WINDOWS:
                    import msvcrt
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.lockf(self.fd, fcntl.LOCK_UN, 1, 0)
            except OSError:
                pass
            self.held = False

    def close(self):
        self.release()
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---- client ---------------------------------------------------------------------------------

class SessionError(Exception):
    """An ``ok:false`` answer. ``code`` is the protocol's error code (README, "Error codes")."""

    def __init__(self, code, message, details=None, trace=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.trace = trace


class _Base:
    """Request/response matching over a JSON-lines channel. Thread-safe: several threads may
    call at once; responses are routed to their waiter by id."""

    def __init__(self):
        self._id = 0
        self._lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._done = threading.Condition()
        self._pending = {}
        self._closed = False
        self.events = []
        self.on_event = None
        self.last_ms = 0
        self.last_response = None  # the last whole response (with stale/refreshed markers)
        self._raw = {}
        self._abandoned = set()  # ids whose answer nobody waits for any more (deadline expired)

    #: True when ``_recv(timeout)`` can give up after ``timeout`` seconds (a ``deadline``).
    supports_deadline = False

    def _send(self, line: str):
        raise NotImplementedError

    def _recv(self, timeout: float | None = None) -> str | None:
        """One line; ``""`` at the end of the stream; ``None`` when ``timeout`` passed first
        (only when ``supports_deadline``)."""
        raise NotImplementedError

    def call(self, cmd: str, deadline: float | None = None, **fields):
        """Sends one request and waits for its response. Raises SessionError on ok:false.

        ``deadline`` (seconds, client side only: it is not sent) limits the wait: when it passes
        the request is cancelled (``cancel target=<id>`` is sent), the late answer is dropped, and
        ``SessionError("deadline_exceeded")`` is raised. The connection stays usable. Needs a
        socket session (the pipe of a stdio session cannot be timed). This exists from library
        1.1.0; an engine install before hydra.4 ships 1.0.0, whose ``call`` waits without a limit.

        ``client=`` and ``harness=`` are labels of this one request: they replace the
        connection's name for it in ``busy``/``conflict`` holders, ``status``, the import queue
        and ``cancel`` scoping (README, "Who is asking"). For a caller that makes many requests
        use :meth:`labelled`."""
        self._check_deadline(deadline)
        return self.wait(self.send(cmd, **fields), deadline)

    def _check_deadline(self, deadline):
        if deadline is not None:
            if not self.supports_deadline:
                raise SessionError("unsupported", "a deadline needs a socket session")
            if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) \
                    or not deadline > 0:
                raise ValueError(f"deadline must be a positive number of seconds, not {deadline!r}")

    def call_raw(self, cmd: str, deadline: float | None = None, **fields) -> dict:
        """Like ``call``, but returns the whole response: ``result`` plus the markers next to it
        (``stale``: read-only views whose project changed on disk, send ``refresh``;
        ``refreshed``: projects another client refreshed since this one last heard)."""
        self._check_deadline(deadline)
        rid = self.send(cmd, **fields)
        with self._done:
            self._raw[rid] = None
        try:
            self.wait(rid, deadline)
            with self._done:
                return self._raw[rid]
        finally:
            with self._done:
                self._raw.pop(rid, None)

    def labelled(self, client: str | None = None, harness: str | None = None) -> "Labelled":
        """A view of this connection whose requests all carry the given labels, for one
        connection that serves several callers (an MCP server with several agents)::

            agent_a = s.labelled(client="agent-a", harness="claude-code")
            agent_a.call("decompile", address="0x1000")
            agent_a.cancel_all()          # only agent-a's requests
        """
        return Labelled(self, client, harness)

    def send(self, cmd: str, **fields) -> int:
        """Sends a request without waiting; returns its id (for ``cancel`` or a later wait)."""
        return self._send_request(cmd, fields)

    def _send_request(self, cmd: str, fields: dict, abandon: bool = False) -> int:
        with self._lock:
            self._id += 1
            rid = self._id
            if abandon:  # before the line leaves: its answer may be the next thing read
                with self._done:
                    self._abandoned.add(rid)
            self._send(json.dumps({"id": rid, "cmd": cmd, **fields}) + "\n")
        return rid

    def _expire(self, rid: int, deadline: float):
        """The deadline of ``rid`` passed: cancel it, drop its answer, raise."""
        with self._done:
            if rid in self._pending or self._closed:
                return  # answered (or ended) at the last moment: the wait loop takes it
            self._abandoned.add(rid)
        cancel_id = None
        try:
            # parallel: on a connection that runs its requests in order, a plain cancel would
            # queue behind the very request it is meant to end
            cancel_id = self._send_request("cancel", {"target": rid, "parallel": True},
                                           abandon=True)
        except (OSError, ValueError):
            pass  # the connection is gone: nothing to cancel
        raise SessionError("deadline_exceeded",
                           f"no answer to request {rid} within {deadline:g} s; cancel sent",
                           {"deadlineS": deadline, "target": rid, "cancelId": cancel_id})

    def wait(self, rid: int, deadline: float | None = None):
        self._check_deadline(deadline)
        end = None if deadline is None else time.monotonic() + deadline
        while True:
            with self._done:
                if rid in self._pending:
                    msg = self._pending.pop(rid)
                    break
                if self._closed:
                    raise SessionError("closed", "the session connection ended")
            if end is not None and time.monotonic() >= end:
                self._expire(rid, deadline)
                continue
            if self._read_lock.acquire(timeout=0.05):
                try:
                    with self._done:
                        if rid in self._pending:
                            continue
                    if end is None:
                        line = self._recv()
                    else:
                        # a slice, so that the deadline is looked at even when nothing arrives
                        line = self._recv(max(0.0, min(0.25, end - time.monotonic())))
                        if line is None:
                            continue
                    with self._done:
                        if not line:
                            self._closed = True
                        elif not line.lstrip().startswith("{"):
                            pass  # not protocol (a JVM message on stdout); ignore
                        else:
                            m = json.loads(line)
                            if "event" in m and "ok" not in m:
                                self.events.append(m)
                                if self.on_event:
                                    self.on_event(m)
                            elif m.get("id") in self._abandoned:
                                self._abandoned.discard(m.get("id"))  # a late answer: dropped
                            else:
                                self._pending[m.get("id")] = m
                        self._done.notify_all()
                finally:
                    self._read_lock.release()
            else:
                with self._done:
                    self._done.wait(0.05)
        self.last_ms = msg.get("ms", 0)
        self.last_response = msg
        with self._done:
            if rid in self._raw:
                self._raw[rid] = msg
        if not msg.get("ok"):
            e = msg.get("error", {})
            raise SessionError(e.get("code"), e.get("message"), e.get("details"), e.get("trace"))
        return msg["result"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Labelled:
    """One caller's view of a shared connection: every request it sends carries this view's
    ``client`` and ``harness`` labels (a label given to a single call wins). Requests are
    ``parallel`` by default, because a connection that carries several callers must not make
    them wait for each other; pass ``parallel=False`` to keep the connection's order."""

    def __init__(self, base: _Base, client: str | None = None, harness: str | None = None,
                 parallel: bool = True):
        self.base = base
        self.client = client
        self.harness = harness
        self.parallel = parallel

    def _fields(self, fields: dict) -> dict:
        out = dict(fields)
        if self.client is not None:
            out.setdefault("client", self.client)
        if self.harness is not None:
            out.setdefault("harness", self.harness)
        if self.parallel:
            out.setdefault("parallel", True)
        return out

    def call(self, cmd: str, deadline: float | None = None, **fields):
        return self.base.call(cmd, deadline, **self._fields(fields))

    def send(self, cmd: str, **fields) -> int:
        return self.base.send(cmd, **self._fields(fields))

    def wait(self, rid: int, deadline: float | None = None):
        return self.base.wait(rid, deadline)

    def cancel(self, target: int):
        """Cancels one of this view's requests by id."""
        return self.base.call("cancel", target=target, **self._fields({}))

    def cancel_all(self):
        """Cancels every request of this view's label and no other caller's."""
        return self.base.call("cancel", all=True, **self._fields({}))

    def __getattr__(self, name):
        return getattr(self.base, name)


HELLO_DEADLINE_S = 5.0


def _hello_left(end: float) -> float:
    """The deadline for one ``hello``: at most HELLO_DEADLINE_S, at least 0.5 s, and no more
    than what is left until the monotonic time ``end``. The 0.5 s floor is deliberate (a hello
    needs a moment even when the budget is spent), so a call that dials last can overrun its
    ``timeout`` by up to 0.5 s."""
    return max(0.5, min(HELLO_DEADLINE_S, end - time.monotonic()))


class SocketSession(_Base):
    """A client of a session that serves a loopback socket (the daemon)."""

    supports_deadline = True

    def __init__(self, endpoint: dict | str | os.PathLike, client: str = "", harness: str = "",
                 timeout: float | None = None, check: bool = True,
                 hello_deadline: float | None = None):
        super().__init__()
        #: How the daemon was started (``spawn_daemon``'s outcome: ``caller_in_job``, ``spawn``,
        #: ``survival``, ``warnings``), and whether this connect started it. Set by
        #: ``Daemon.connect``; ``None``/``False`` on a session made directly.
        self.launch = None
        self.started = False
        #: Structured warnings of the connect (``daemon_dies_with_harness``, ``duplicate_daemon``).
        self.warnings = []
        if not isinstance(endpoint, dict):
            endpoint = json.loads(Path(endpoint).read_text(encoding="utf-8"))
        self.endpoint = endpoint
        self.sock = socket.create_connection((endpoint["host"], endpoint["port"]),
                                             timeout=timeout)
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # The library owns its reader: lines are cut from a byte buffer here, and a wait can be
        # timed (select) without a timeout on the socket, which a concurrent send would share.
        self._buf = bytearray()
        #: The protocol this connection runs at: the ``protocol`` of the engine's ``hello``
        #: answer (2 against a hydra.2 or hydra.3 engine, up to ``PROTOCOL`` against a newer
        #: one). ``None`` until the answer is in, and when an unchecked answer carries none.
        self.protocol = None
        try:
            self.hello = self.call("hello", token=endpoint["token"], client=client,
                                   harness=harness, clientVersion=CLIENT_VERSION,
                                   protocol=PROTOCOL, deadline=hello_deadline)
            if check:
                check_compatible(self.hello)
            if _is_protocol(self.hello.get("protocol")):
                self.protocol = self.hello["protocol"]
        except BaseException:
            self.close()
            raise

    def _send(self, line):
        self.sock.sendall(line.encode("utf-8"))

    def _recv(self, timeout=None):
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            i = self._buf.find(b"\n")
            if i >= 0:
                line = bytes(self._buf[:i + 1])
                del self._buf[:i + 1]
                return line.decode("utf-8")
            if end is not None:
                left = end - time.monotonic()
                if left <= 0:
                    return None
                try:
                    if not select.select([self.sock], [], [], left)[0]:
                        return None
                except (OSError, ValueError):
                    return ""  # closed by another thread meanwhile: the stream ended
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                chunk = b""  # reset or closed: the stream ended
            if not chunk:
                rest = bytes(self._buf)
                self._buf.clear()
                return rest.decode("utf-8", "replace")  # the unterminated tail, then ""
            self._buf += chunk

    def close(self):
        # Shut the socket down first, so the session sees the disconnect (and releases what this
        # client held) at once, and a thread blocked in recv returns.
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def _first_event(stdout, stderr) -> dict:
    """The first protocol line. The JVM itself may print to stdout before the session claims it
    (for example ``-XX:StartFlightRecording`` announces the recording there): such lines are not
    JSON objects, so they are passed to stderr (when it is a file) and skipped."""
    while True:
        line = stdout.readline()
        if not line:
            return {"event": "fatal"}
        if line.lstrip().startswith("{"):
            return json.loads(line)
        if stderr not in (None, subprocess.DEVNULL):
            with contextlib.suppress(Exception):
                stderr.write(line.encode("utf-8", "replace"))
                stderr.flush()


class StdioSession(_Base):
    """A private session JVM driven over its stdin/stdout (no daemon, no socket)."""

    def __init__(self, *args: str, ghidra: str | None = None, state: str | None = None,
                 stderr_path: str | None = None, **cfg_overrides):
        super().__init__()
        st = state_dir(state)
        ensure_state(st)
        launch = Launch(Install.locate(ghidra), load_config(st, cfg_overrides), st)
        argv, self.launch_info = launch.command(list(args))
        self._stderr = open(stderr_path, "ab") if stderr_path else subprocess.DEVNULL
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self._stderr, env=launch.env, text=True,
                                     encoding="utf-8", bufsize=1)
        first = _first_event(self.proc.stdout, self._stderr)
        self.startup_wall = time.perf_counter() - t0
        if first.get("event") != "ready":
            err = first.get("error", {})
            raise SessionError(err.get("code", "fatal"), err.get("message", "did not start"))
        self.ready = first
        try:
            check_compatible(first)
        except IncompatibleError:
            self.close()
            raise
        #: A stdio session sends no ``hello``, so it runs at the protocol its ``ready`` event
        #: names: the lowest the engine serves (2 for every engine so far).
        self.protocol = first["protocol"]

    def _send(self, line):
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self, timeout=None):
        return self.proc.stdout.readline()

    def close(self):
        if self.proc.poll() is None:
            with contextlib.suppress(Exception):
                self.call("shutdown")
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._stderr is not subprocess.DEVNULL:
            self._stderr.close()


# ---- spawning the daemon outside the caller's job (D65) --------------------------------------

#: The routes after the plain spawn, in order, that may be tried when the caller is in a job:
#: ``breakaway`` (CREATE_BREAKAWAY_FROM_JOB), ``wmi`` (Win32_Process.Create, the WMI provider host
#: creates the process), ``task`` (a one-shot scheduled task of the current user). A test removes
#: routes here to prove that the job, not luck, decides (SP3); production leaves all three.
SPAWN_ROUTES = ("breakaway", "wmi", "task")

_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_CREATE_NO_WINDOW = 0x08000000
_JOB_KILL_ON_CLOSE = 0x2000


class SpawnError(Exception):
    """One spawn route failed (the reason is the message); the sequence goes on to the next."""


_K32 = None
_K32_LOCK = threading.RLock()  # the signatures are set on a shared DLL object: once, never raced
_PE32 = None


def _kernel32():
    """kernel32 with the signatures this file uses (Windows only), made once."""
    with _K32_LOCK:
        return _kernel32_locked()


def _kernel32_locked():
    global _K32
    if _K32 is None:
        import ctypes
        import ctypes.wintypes as wt
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.BOOL)]
        k.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                wt.DWORD, ctypes.c_void_p]
        k.OpenProcess.restype = ctypes.c_void_p
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        _K32 = k
    return _K32


def caller_job() -> dict:
    """D65 (1): the job THIS process is in. ``{"in_job", "kill_on_close", "limit_flags"}``;
    ``kill_on_close`` and ``limit_flags`` are None when not in a job or when the job cannot be
    queried. (``QueryInformationJobObject`` with a NULL handle reads the calling process's job.)"""
    if not IS_WINDOWS:
        return {"in_job": False, "kill_on_close": None, "limit_flags": None}
    import ctypes
    import ctypes.wintypes as wt
    k = _kernel32()
    b = wt.BOOL()
    if not k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(b)) or not b.value:
        return {"in_job": False, "kill_on_close": None, "limit_flags": None}
    buf = (ctypes.c_ubyte * 64)()  # JOBOBJECT_BASIC_LIMIT_INFORMATION
    if not k.QueryInformationJobObject(None, 2, buf, 64, None):
        return {"in_job": True, "kill_on_close": None, "limit_flags": None}
    flags = ctypes.c_uint32.from_buffer(buf, 16).value
    return {"in_job": True, "kill_on_close": bool(flags & _JOB_KILL_ON_CLOSE),
            "limit_flags": hex(flags)}


class _PidProc:
    """The part of ``subprocess.Popen`` that ``Daemon._wait_ready`` uses (``pid``, ``poll``,
    ``returncode``) for a process that this one did not create (WMI, scheduled task)."""

    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        import ctypes
        import ctypes.wintypes as wt
        k = _kernel32()
        h = k.OpenProcess(0x1000, False, self.pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            self.returncode = -1  # gone (or not ours to see)
            return self.returncode
        try:
            code = wt.DWORD()
            if k.GetExitCodeProcess(h, ctypes.byref(code)) and code.value != 259:  # STILL_ACTIVE
                self.returncode = code.value
        finally:
            k.CloseHandle(h)
        return self.returncode


def _toolhelp():
    """``(kernel32, PE32)`` with the Toolhelp signatures set once. The PE32 class is one object
    for the whole process: a class made per call gave each concurrent caller a distinct type, and
    the ``argtypes`` of the shared function objects then rejected the other callers' instances
    ("expected LP_PE32 instance instead of pointer to PE32")."""
    global _PE32
    import ctypes
    import ctypes.wintypes as wt
    with _K32_LOCK:
        k = _kernel32_locked()
        if _PE32 is None:
            class PE32(ctypes.Structure):
                _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                            ("th32ProcessID", wt.DWORD),
                            ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD),
                            ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                            ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
                            ("szExeFile", wt.WCHAR * 260)]

            k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
            k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [ctypes.c_void_p,
                                                                      ctypes.POINTER(PE32)]
            _PE32 = PE32
        return k, _PE32


def _children_of(pid: int) -> list[tuple[int, str]]:
    """``[(pid, image name)]`` of the direct children of ``pid`` (Toolhelp snapshot)."""
    import ctypes

    k, PE32 = _toolhelp()
    snap = k.CreateToolhelp32Snapshot(0x2, 0)
    out = []
    try:
        pe = PE32()
        pe.dwSize = ctypes.sizeof(pe)
        ok = k.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.th32ParentProcessID == pid:
                out.append((pe.th32ProcessID, pe.szExeFile))
            ok = k.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k.CloseHandle(snap)
    return out


class _WrappedProc(_PidProc):
    """The WMI route creates ``cmd.exe``, whose child is the JVM. ``Daemon._wait_ready`` compares
    the endpoint's pid with ``proc.pid``, so ``pid`` answers with the JVM's pid as soon as the
    wrapper has one, and ``poll()`` follows the wrapper (it lives as long as the JVM)."""

    def __init__(self, wrapper_pid):
        super().__init__(wrapper_pid)
        self.wrapper_pid = wrapper_pid
        self._jvm = None

    @property
    def pid(self):
        if self._jvm is None:
            for p, name in _children_of(self.wrapper_pid):
                if name.lower() == "java.exe":
                    self._jvm = p
        return self._jvm or self.wrapper_pid

    @pid.setter
    def pid(self, v):
        pass


_CMD_FORBIDDEN = re.compile(r'[%"\r\n\x00]')


def _cmd_quote(a: str) -> str:
    """Always-quoted argument, CreateProcess/MSVCRT rules (backslashes before the closing quote
    are doubled). Quoting every argument keeps the cmd.exe metacharacters & | < > ^ ( ) literal.
    ``%`` (cmd expands it even inside quotes) and ``"``, CR, LF are refused."""
    if _CMD_FORBIDDEN.search(a):
        raise SpawnError(f"argument not representable on a cmd.exe line: {a!r}")
    return '"' + re.sub(r"(\\+)$", r"\1\1", a) + '"'


def cmd_line(argv: list[str], set_env: dict | None, log_path) -> str:
    """``cmd.exe /d /v:off /s /c "set "K=V"&& "java" "arg" ... >> "log" 2>&1"``: for the routes
    that carry no environment and no handles (WMI, scheduled task) the whole configuration is on
    the command line. ``cmd.exe`` is the process such a route creates; java is its child."""
    sets = "".join(f'set {_cmd_quote(k + "=" + v)}&& ' for k, v in (set_env or {}).items())
    return (f'cmd.exe /d /v:off /s /c "{sets}{" ".join(_cmd_quote(a) for a in argv)} '
            f'>> {_cmd_quote(str(log_path))} 2>&1"')


def env_to_carry(launch_env: dict, props_envvars: dict | None) -> dict:
    """The variables worth putting on the command line of an environment-free route (measured:
    the WMI and task environment is the user's registry environment, none of the caller's):
    launch.properties ``ENVVARS`` and the JVM option variables (``JAVA_TOOL_OPTIONS``,
    ``JDK_JAVA_OPTIONS``, ``_JAVA_OPTIONS``). TEMP and TMP travel as ``-Djava.io.tmpdir``."""
    out = dict(props_envvars or {})
    for k in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        if launch_env.get(k):
            out[k] = launch_env[k]
    return out


# PowerShell under the machine's own execution policy (the cmdlets used here need no bypass).
_PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]


def _run_ps(script: str, env: dict, timeout: float, what: str):
    try:
        return subprocess.run(_PS + [script], env=env, capture_output=True, text=True,
                              timeout=timeout, creationflags=_CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SpawnError(f"{what}: {e}") from e


def _spawn_wmi(command_line: str, cwd: str, timeout: float = 30.0) -> _PidProc:
    """``Win32_Process.Create`` through ``Invoke-CimMethod``. The command line travels in an
    environment variable of the helper process only, never through the process it creates."""
    script = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
              "-Arguments @{CommandLine=$env:HYDRA_WMI_CMD; CurrentDirectory=$env:HYDRA_WMI_CWD}; "
              "[pscustomobject]@{pid=$r.ProcessId; rv=$r.ReturnValue} | ConvertTo-Json -Compress")
    r = _run_ps(script, dict(os.environ, HYDRA_WMI_CMD=command_line, HYDRA_WMI_CWD=cwd),
                timeout, "powershell")
    try:
        j = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise SpawnError(f"wmi: no result (rc {r.returncode}): "
                         f"{(r.stderr or r.stdout).strip()[:300]}")
    if j.get("rv") != 0 or not j.get("pid"):
        raise SpawnError(f"wmi: Win32_Process.Create ReturnValue {j.get('rv')}")
    return _PidProc(int(j["pid"]))


def _spawn_task(args_after_cmd: str, cwd: str, timeout: float = 60.0) -> str:
    """Registers a one-shot, no-trigger, per-user task (current user, interactive logon, limited,
    no time limit, runs on battery), starts it and returns its name. ``args_after_cmd`` is the
    part of the command line after ``cmd.exe``. ``_unregister_task`` removes it."""
    name = "HydraDaemon-" + uuid.uuid4().hex[:10]
    script = ("$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $env:HYDRA_TASK_ARGS "
              "-WorkingDirectory $env:HYDRA_TASK_CWD; "
              "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries "
              "-DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) "
              "-MultipleInstances Parallel; "
              "$p = New-ScheduledTaskPrincipal -UserId "
              "([Security.Principal.WindowsIdentity]::GetCurrent().Name) "
              "-LogonType Interactive -RunLevel Limited; "
              f"Register-ScheduledTask -TaskName '{name}' -Action $a -Settings $s -Principal $p "
              f"-Force | Out-Null; Start-ScheduledTask -TaskName '{name}'; 'ok'")
    r = _run_ps(script, dict(os.environ, HYDRA_TASK_ARGS=args_after_cmd, HYDRA_TASK_CWD=cwd),
                timeout, "task")
    if r.returncode != 0 or "ok" not in r.stdout:
        with contextlib.suppress(Exception):
            _unregister_task(name)
        raise SpawnError(f"task: rc {r.returncode}: {(r.stderr or r.stdout).strip()[:300]}")
    return name


def _unregister_task(name: str, stop: bool = False):
    """Removes the task entry. ``stop`` also ends what it started (the failure path only: it
    would end a healthy daemon too)."""
    script = ((f"Stop-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue; "
               if stop else "")
              + f"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false "
                "-ErrorAction SilentlyContinue")
    with contextlib.suppress(Exception):
        subprocess.run(_PS + [script], capture_output=True, text=True, timeout=60,
                       creationflags=_CREATE_NO_WINDOW)


def spawn_daemon(argv, env, log_path, cwd, *, argv_envfree=None, set_env=None, routes=None,
                 wait_endpoint=None, task_wait: float = 30.0):
    """D65 launch sequence. Returns ``(proc, outcome)``.

    ``argv``/``env``: the JVM command line and environment for the direct routes. ``argv_envfree``
    and ``set_env`` (``env_to_carry``): the same for the routes that carry no environment.
    ``wait_endpoint()`` returns the daemon's pid once its endpoint file shows up, else None (only
    the task route needs it: it has no process to hand back). ``routes`` defaults to
    ``SPAWN_ROUTES``.

    (2) not in a job: the detached spawn, ``spawn:"detached"``. (3) in a job: try
    ``CREATE_BREAKAWAY_FROM_JOB``, ``spawn:"breakaway"``. (4) breakaway denied (WinError 5): outside
    the job through WMI, ``spawn:"wmi"``; then a scheduled task, ``spawn:"task"``. (5) all failed:
    stay in the job, ``spawn:"stayed"``, ``survival:"bound_to_harness"`` and the warning
    ``daemon_dies_with_harness``. ``outcome`` also has ``caller_in_job``, ``caller_kill_on_close``,
    ``caller_limit_flags``, ``warnings[]`` and ``attempts[{route, ok, ms, error?}]``; a task route
    adds ``task_name`` and ``_unregister`` (a callable: call it once the daemon answered)."""
    routes = SPAWN_ROUTES if routes is None else routes
    cj = caller_job()
    out = {"caller_in_job": cj["in_job"], "caller_kill_on_close": cj["kill_on_close"],
           "caller_limit_flags": cj["limit_flags"], "spawn": None, "survival": None,
           "warnings": [], "attempts": []}
    log_path = Path(log_path)

    def direct(flags):
        # The parent's handle on the log is closed again before any other route runs: a log that
        # this process still holds open makes the redirect of the cmd.exe wrapper fail.
        with open(log_path, "ab") as lf:
            if not IS_WINDOWS:
                return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                                        env=env, close_fds=True, start_new_session=True)
            return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf, env=env,
                                    creationflags=flags, close_fds=True)

    def attempt(route, fn):
        t0 = time.perf_counter()
        try:
            res = fn()
        except (OSError, SpawnError) as e:
            out["attempts"].append({"route": route, "ok": False,
                                    "ms": round((time.perf_counter() - t0) * 1000),
                                    "error": f"{type(e).__name__}: {e}"})
            return None
        out["attempts"].append({"route": route, "ok": True,
                                "ms": round((time.perf_counter() - t0) * 1000)})
        return res

    base = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
    if not cj["in_job"]:
        p = attempt("detached", lambda: direct(base))
        if p:
            out.update(spawn="detached", survival="independent")
            return p, out
    else:
        if "breakaway" in routes:
            p = attempt("breakaway", lambda: direct(base | _CREATE_BREAKAWAY_FROM_JOB))
            if p:
                out.update(spawn="breakaway", survival="independent")
                return p, out
        free = argv_envfree or argv
        if "wmi" in routes:
            try:
                cl = cmd_line(free, set_env, log_path)
            except SpawnError as e:
                cl = None
                out["attempts"].append({"route": "wmi", "ok": False, "ms": 0, "error": str(e)})
            if cl:
                p = attempt("wmi", lambda: _spawn_wmi(cl, cwd))
                if p:
                    out.update(spawn="wmi", survival="independent")
                    return _WrappedProc(p.pid), out
        if "task" in routes:
            # No pid to give back and no error channel when the command cannot start: the route
            # counts only once the JVM's endpoint shows up within task_wait; else the task is
            # stopped and removed and the sequence goes on.
            tn = None
            try:
                cl = cmd_line(free, set_env, log_path)
                tn = attempt("task", lambda: _spawn_task(cl[len("cmd.exe "):], cwd))
            except SpawnError as e:
                out["attempts"].append({"route": "task", "ok": False, "ms": 0, "error": str(e)})
            if tn:
                jvm = None
                if wait_endpoint is not None:
                    end = time.monotonic() + task_wait
                    while jvm is None and time.monotonic() < end:
                        jvm = wait_endpoint()
                        if jvm is None:
                            time.sleep(0.1)
                    if jvm is None:
                        _unregister_task(tn, stop=True)
                        out["attempts"].append({"route": "task", "ok": False,
                                                "ms": round(task_wait * 1000),
                                                "error": f"no endpoint within {task_wait:.0f} s; "
                                                         "task stopped and removed"})
                        tn = None
                if tn:
                    out.update(spawn="task", survival="independent", task_name=tn)
                    out["_unregister"] = lambda tn=tn: _unregister_task(tn)
                    return (_PidProc(jvm) if jvm else None), out
    # (5) stay in the job (or: not in a job but the detached spawn failed)
    p = direct(base)
    out.update(spawn="stayed", survival="bound_to_harness")
    if cj["in_job"]:
        out["warnings"].append({
            "code": "daemon_dies_with_harness",
            "message": "the daemon runs in the job of the harness that started it (breakaway "
                       "denied, WMI and scheduled task unavailable) and ends with it"})
    return p, out


# ---- the registry of daemons (PROTOCOL-3.md, 3.8) ---------------------------------------------

def user_state_root() -> Path:
    """The launcher's default state root, independent of ``-stateDir`` (``GHIDRA_SESSION_HOME``
    relocates it): where the registry lives, so that daemons started with different roots see
    each other."""
    return state_dir(None)


def _norm(p) -> str:
    return os.path.normcase(str(p))


def registry_key(install, state, instance) -> str:
    return hashlib.sha256(f"{_norm(install)}|{_norm(state)}|{instance}".encode()).hexdigest()


def registry_write(install: "Install", state: Path, instance: str, pid,
                   version: str = "") -> Path | None:
    """Writes ``<userStateRoot>/registry/<sha256(install|stateDir|instance)>.json`` atomically.
    A registry that cannot be written never fails a launch (returns None)."""
    try:
        d = user_state_root() / "registry"
        d.mkdir(parents=True, exist_ok=True)
        f = d / f"{registry_key(install.dir, state, instance)}.json"
        for old in d.glob("*.json"):  # prune entries of daemons that are gone (lock free or missing)
            if old == f:
                continue
            try:
                e = json.loads(old.read_text(encoding="utf-8"))
                gone = not _lock_is_held(Path(e["stateDir"]) / f"{e['instance']}.lock")
            except (OSError, ValueError, KeyError, TypeError):
                gone = True
            if gone:
                with contextlib.suppress(OSError):
                    old.unlink()
        entry = {"pid": pid, "stateDir": str(state), "instance": instance,
                 "install": str(install.dir), "hydraVersion": version or install.version,
                 "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        tmp = f.with_name(f.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(entry, indent=1), encoding="utf-8")
        os.replace(tmp, f)
        return f
    except OSError:
        return None


def _lock_is_held(lock_file: Path) -> bool:
    if not lock_file.is_file():
        return False
    lk = FileLock(lock_file)
    try:
        if lk.try_acquire():
            return False
        return True
    finally:
        lk.close()


def registry_live() -> list[dict]:
    """The registry's live entries: those whose instance lock is held (``Daemon.jvm_alive``)."""
    out = []
    d = user_state_root() / "registry"
    try:
        files = sorted(d.glob("*.json"))
    except OSError:
        return out
    for f in files:
        try:
            e = json.loads(f.read_text(encoding="utf-8"))
            lock = Path(e["stateDir"]) / f"{e['instance']}.lock"
            if _lock_is_held(lock):
                out.append(e)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return out


def find_duplicate(install: "Install", state: Path, instance: str) -> dict | None:
    """A live daemon of the same install under another state dir, or None."""
    for e in registry_live():
        if _norm(e.get("install", "")) == _norm(install.dir) \
                and _norm(e.get("stateDir", "")) != _norm(state):
            return e
    return None


# ---- the shared daemon ----------------------------------------------------------------------

class Daemon:
    """The per-user daemon of one instance: ``<state>/<instance>.json`` (endpoint),
    ``<instance>.lock`` (held by the JVM for its whole life), ``<instance>.start.lock`` (held by
    whoever is starting it) and ``<instance>.log``."""

    def __init__(self, ghidra: str | None = None, state: str | None = None,
                 instance: str = DEFAULT_INSTANCE, **cfg_overrides):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", instance):
            raise LaunchError(f"bad instance name {instance!r}")
        self.ghidra = ghidra
        self.state = state_dir(state)
        self.instance = instance
        self.cfg_overrides = cfg_overrides
        self.endpoint_file = self.state / f"{instance}.json"
        self.lock_file = self.state / f"{instance}.lock"
        self.start_lock_file = self.state / f"{instance}.start.lock"
        self.launch_file = self.state / f"{instance}.launch.json"
        #: The outcome of the last ``_spawn`` of this object (``spawn_daemon``'s dict).
        self.last_launch = None
        self._log_offset = 0

    @property
    def log_file(self) -> Path:
        cfg = load_config(self.state, self.cfg_overrides)
        return Path(cfg["log"]) if cfg.get("log") else self.state / f"{self.instance}.log"

    def read_endpoint(self) -> dict | None:
        try:
            return json.loads(self.endpoint_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def jvm_alive(self) -> bool:
        """True while some JVM holds the instance lock."""
        if not self.lock_file.exists():
            return False
        lk = FileLock(self.lock_file)
        try:
            if lk.try_acquire():
                return False
            return True
        finally:
            lk.close()

    def _try_connect(self, client, harness, timeout=5.0, check=True,
                     hello_deadline=None) -> SocketSession | None:
        ep = self.read_endpoint()
        if not ep:
            return None
        # A killed JVM leaves its endpoint file behind. Do not dial it: on Windows a connect to
        # a closed loopback port is retried for about 2 s before it is refused.
        if not self.jvm_alive():
            return None
        try:
            return SocketSession(ep, client=client, harness=harness, timeout=timeout,
                                 check=check, hello_deadline=hello_deadline)
        except (OSError, SessionError, KeyError, ValueError):
            return None

    def _check_install(self, ep: dict, install: Install):
        if ep.get("install") and Path(ep["install"]).resolve() != install.dir:
            raise LaunchError(
                f"the {self.instance!r} daemon runs {ep['install']} (Ghidra {ep.get('ghidra')}), "
                f"not {install.dir}; stop it, or use another --instance")
        # Any overlap of this client's range with the daemon's counts: the connection then runs
        # at the highest protocol both speak (``hello`` negotiates it). An endpoint that sends
        # no protocolMin/protocolMax serves the single ``protocol`` it names.
        lo, hi = _client_range()
        served = engine_protocols(ep)
        if served is None or served[1] < lo or served[0] > hi:
            raise LaunchError(f"the {self.instance!r} daemon speaks protocol "
                              f"{_span(*served) if served else repr(ep.get('protocol'))}, this "
                              f"client (ghidra_session.py {CLIENT_VERSION}) speaks "
                              f"{_span(lo, hi)}; stop it first")

    def connect(self, client: str = "", harness: str = "", start: bool = True,
                timeout: float = ENDPOINT_WAIT_S) -> SocketSession:
        """Joins the running daemon, starting it first if there is none (and ``start``).

        The session carries ``launch`` (how that daemon was started, see ``spawn_daemon``),
        ``started`` (this call started it) and ``warnings`` (``daemon_dies_with_harness``: the
        daemon runs in the job of the harness that started it and ends with it;
        ``duplicate_daemon``: a live daemon of the same install runs under another state dir).

        ``timeout`` is a budget per phase, not for the whole call. The hello dials share one
        ``timeout`` (up to 0.5 s of overrun, the floor of the last hello deadline, see
        ``_hello_left``); the wait for the start lock takes up to ``timeout`` on its own, and
        the wait for a spawned daemon to answer takes up to ``timeout`` again. The worst case
        is therefore about 2 x ``timeout`` plus the spawn time. A daemon that is alive but
        does not answer ``hello`` ends as ``no_answer``, not as a hang."""
        install = Install.locate(self.ghidra)
        t_end = time.monotonic() + timeout
        # A daemon that is alive but wedged accepts the TCP connection and never answers hello:
        # every dial gets a deadline taken from the time that is left.
        s = self._try_connect(client, harness, hello_deadline=_hello_left(t_end))
        if s:
            self._check_install(s.endpoint, install)
            return self._annotate(s)
        if not start and self.jvm_alive():
            # a daemon runs but did not answer hello within the deadline: wedged, not absent
            ep = self.read_endpoint()
            raise LaunchError(f"the {self.instance!r} daemon is running but did not answer; "
                              f"see {self.log_file}", "no_answer",
                              {"timeoutS": timeout, "log": str(self.log_file),
                               "logTail": self._log_tail(0),
                               "holder": {"pid": ep.get("pid")} if ep else None,
                               "suggest": "the daemon may be wedged: health() tells "
                                          "whether it answers; stop(force) or kill() it"})
        if not start:
            raise LaunchError(f"no {self.instance!r} daemon is running (state {self.state})",
                              "not_running", {"stateDir": str(self.state),
                                              "instance": self.instance})
        ensure_state(self.state)
        with FileLock(self.start_lock_file) as lk:
            if not lk.acquire(timeout):
                raise LaunchError(f"another process held the start lock for the "
                                  f"{timeout:.0f} s this wait was allowed "
                                  f"({self.start_lock_file})", "lock_held",
                                  {"lock": str(self.start_lock_file), "waitedS": timeout,
                                   "holder": None,
                                   "suggest": "wait for the other launcher, or find the process "
                                              "that holds the lock"})
            s = self._try_connect(client, harness,  # someone else started it meanwhile
                                  hello_deadline=_hello_left(t_end))
            if s:
                self._check_install(s.endpoint, install)
                return self._annotate(s)
            if self.jvm_alive():
                # starting up, or wedged: wait for its endpoint
                s = self._wait_ready(None, client, harness, max(0.0, t_end - time.monotonic()), 0,  # since=0: logTail has the last lines
                                     asked=timeout)
                self._check_install(s.endpoint, install)
                return self._annotate(s)
            with contextlib.suppress(OSError):
                self.endpoint_file.unlink()  # stale: its JVM is gone
            warnings = self._singleton_check(install)
            proc = self._spawn(install)
            outcome = self.last_launch
            try:
                s = self._wait_ready(proc, client, harness, timeout, self._log_offset,
                                     asked=timeout)
            except BaseException:
                if outcome.get("task_name"):
                    _unregister_task(outcome["task_name"], stop=True)
                raise
            if outcome.get("task_name"):
                _unregister_task(outcome["task_name"])  # the daemon is up: the entry has done its job
            public = {k: v for k, v in outcome.items() if not k.startswith("_")}
            self._after_start(install, s, public)
            s.launch, s.started = public, True
            s.warnings = list(public.get("warnings") or []) + warnings
            return s

    def attach(self, client: str = "", harness: str = "") -> SocketSession:
        """Joins the running daemon and never starts one (``connect(start=False)``): for the
        doctor. Raises ``LaunchError`` with code ``not_running`` when there is no daemon, and
        ``no_answer`` when a JVM holds the instance lock but does not answer ``hello`` within the
        deadline (wedged, or still starting and not yet listening: the caller decides which)."""
        return self.connect(client, harness, start=False)

    def _singleton_check(self, install: Install) -> list[dict]:
        """Before spawning: a live daemon of the same install under another state dir. Policy
        ``warn`` (default) returns a structured warning; ``per-install`` raises
        ``DuplicateDaemonError``."""
        cfg = load_config(self.state, self.cfg_overrides)
        holder = find_duplicate(install, self.state, self.instance)
        if not holder:
            return []
        ways = [f"connect to it: ghidra_session.connect(state={holder['stateDir']!r}, "
                f"instance={holder['instance']!r})",
                f"stop it first: python ghidra_session.py --state {holder['stateDir']} "
                f"--instance {holder['instance']} stop",
                "allow a second daemon: leave singleton at \"warn\" (config.json "
                "\"singleton\" or GHIDRA_SESSION_SINGLETON)"]
        msg = (f"a daemon of this install already runs (pid {holder.get('pid')}, state "
               f"{holder['stateDir']}, instance {holder['instance']!r})")
        if cfg["singleton"] == "per-install":
            raise DuplicateDaemonError(msg + "; singleton is per-install", holder, ways)
        return [{"code": "duplicate_daemon", "message": msg, "holder": holder, "suggest": ways}]

    def _after_start(self, install: Install, s: SocketSession, public: dict):
        """The daemon answers: write the registry entry and the launch record."""
        pid = s.endpoint.get("pid")
        registry_write(install, self.state, self.instance, pid,
                       str(s.endpoint.get("hydraVersion") or s.endpoint.get("ghidra") or ""))
        try:
            tmp = self.launch_file.with_name(self.launch_file.name + f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"pid": pid, "launch": public}, indent=1), encoding="utf-8")
            os.replace(tmp, self.launch_file)
        except OSError:
            pass

    def _read_launch(self) -> dict | None:
        """The launch record of the daemon that is running now (None if it has none, e.g. it was
        started by an older launcher)."""
        try:
            rec = json.loads(self.launch_file.read_text(encoding="utf-8"))
            ep = self.read_endpoint()
            if ep and rec.get("pid") == ep.get("pid"):
                return rec.get("launch")
        except (OSError, ValueError, AttributeError):
            pass
        return None

    def _annotate(self, s: SocketSession) -> SocketSession:
        """A session that joined a running daemon: carry how that daemon was started."""
        launch = self._read_launch()
        if launch:
            s.launch = launch
            s.warnings = list(launch.get("warnings") or [])
        return s

    def health(self, client: str = "ghidra_session", harness: str = "cli",
               deadline: float = 10.0) -> dict:
        """What the launcher can say about this instance's daemon, without starting one::

            {"instance", "stateDir", "alive" (the instance lock is held), "pid", "answers",
             "source" ("health" | "ping" | None), "engine" (the engine's own health answer, when
             it has one), "launch" (how it was started), "warnings" [], "reason" (when it does
             not answer)}

        ``deadline`` limits each wait, so that a daemon that is alive but wedged (suspended)
        answers ``answers: false`` instead of hanging this call. An engine before hydra.4 has no
        ``health`` command: ``ping`` then proves that it answers."""
        ep = self.read_endpoint()
        out = {"instance": self.instance, "stateDir": str(self.state), "alive": self.jvm_alive(),
               "pid": ep.get("pid") if ep else None, "answers": False, "source": None,
               "launch": None, "warnings": []}
        launch = self._read_launch()
        if launch:
            out["launch"] = launch
            out["warnings"] = list(launch.get("warnings") or [])
        if not out["alive"]:
            out["reason"] = "no daemon holds the instance lock"
            return out
        s = self._try_connect(client, harness, check=False, hello_deadline=deadline)
        if s is None:
            out["reason"] = "the daemon did not answer hello within the deadline"
            return out
        with s:
            try:
                out["engine"] = s.call("health", deadline=deadline)
                out.update(answers=True, source="health")
            except SessionError as e:
                if e.code == "deadline_exceeded":
                    out["reason"] = f"no answer to health within {deadline:g} s"
                    return out
                try:
                    s.call("ping", deadline=deadline)
                    out.update(answers=True, source="ping")
                except SessionError as e2:
                    out["reason"] = str(e2)
        return out

    def _log_size(self) -> int:
        try:
            return self.log_file.stat().st_size
        except OSError:
            return 0

    def _log_tail(self, since: int = 0, lines: int = 40) -> list[str]:
        """The last ``lines`` lines the daemon log got since byte ``since`` (at most 64 KiB)."""
        try:
            with open(self.log_file, "rb") as f:
                size = f.seek(0, os.SEEK_END)
                start = max(since if since <= size else 0, size - (64 << 10))
                f.seek(start)
                text = f.read().decode("utf-8", "replace")
        except OSError:
            return []
        return text.splitlines()[-lines:]

    def _spawn(self, install: Install) -> subprocess.Popen:
        """Starts the JVM (D65: outside the caller's job when there is one) and returns its
        process object. How it was started is ``self.last_launch``."""
        cfg = load_config(self.state, self.cfg_overrides)
        launch = Launch(install, cfg, self.state)
        launch.check_heap()
        args = ["-daemon", "-stateDir", str(self.state), "-instance", self.instance,
                "-idleTimeout", str(cfg["idleTimeout"]), "-keepWarm", str(cfg["keepWarm"]),
                "-maxQuick", str(cfg["maxQuick"]), "-maxLong", str(cfg["maxLong"])]
        if cfg.get("maxImports"):
            args += ["-maxImports", str(cfg["maxImports"])]
        for d in cfg.get("scriptPath") or []:
            args += ["-scriptPath", d]
        argv, info = launch.command(args)
        log = self.log_file
        log.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            if log.exists() and log.stat().st_size > 32 << 20:
                os.replace(log, log.with_suffix(log.suffix + ".1"))
        self._log_offset = self._log_size()
        with open(log, "ab") as lf:
            lf.write(f"\n==== ghidra_session {time.strftime('%Y-%m-%d %H:%M:%S')} {info}\n"
                     .encode())
        # The routes that carry no environment (WMI, task) get the few variables Ghidra reads on
        # the command line, and the caller's temp dir as java.io.tmpdir.
        argv_free = list(argv)
        if not any(a.startswith("-Djava.io.tmpdir=") for a in argv_free):
            argv_free.insert(1, f"-Djava.io.tmpdir={tempfile.gettempdir()}")

        def endpoint_pid():
            ep = self.read_endpoint()
            return ep.get("pid") if ep else None

        proc, outcome = spawn_daemon(argv, launch.env, log, str(self.state),
                                     argv_envfree=argv_free,
                                     set_env=env_to_carry(launch.env, launch.props["envvars"]),
                                     wait_endpoint=endpoint_pid)
        self.last_launch = outcome
        return proc

    def _wait_ready(self, proc, client, harness, timeout, since: int = 0,
                    asked: float | None = None) -> SocketSession:
        """``timeout`` is the time this wait may take; ``asked`` is the ``timeout`` the caller
        passed, which the error reports (default: ``timeout``). It is not a budget for the whole
        ``connect`` call (see its docstring)."""
        asked = timeout if asked is None else asked
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if proc is not None and proc.poll() is not None:
                tail = self._log_tail(since)
                raise LaunchError(f"the daemon exited with code {proc.returncode} while starting; "
                                  f"see {self.log_file}", "exited_early",
                                  {"exitCode": proc.returncode, "log": str(self.log_file),
                                   "logTail": tail,
                                   "suggest": "read the log tail; a JVM option or a Java version "
                                              "the install does not accept ends here"})
            ep = self.read_endpoint()
            # the endpoint of the JVM we started (not a stale file a killed one left behind)
            if ep and (proc is None or ep.get("pid") == proc.pid):
                # a hello that times out is "not up yet": the loop goes on until the end
                s = self._try_connect(client, harness, hello_deadline=_hello_left(end))
                if s:
                    return s
            time.sleep(0.05)
        ep = self.read_endpoint()
        raise LaunchError(f"the daemon did not answer within {asked:.0f} s (the allowance of this wait); see "
                                  f"{self.log_file}",
                          "no_answer", {"timeoutS": asked, "log": str(self.log_file),
                                        "logTail": self._log_tail(since),
                                        "holder": {"pid": ep.get("pid")} if ep else None,
                                        "suggest": "the daemon may be wedged: health() tells "
                                                   "whether it answers; stop(force) or kill() it"})

    def status(self) -> dict | None:
        """The daemon's ``status``; ``None`` when there is no daemon or it does not answer
        ``hello`` within HELLO_DEADLINE_S. A daemon that answers ``hello`` and then not ``status``
        within the same deadline raises ``SessionError("deadline_exceeded")``."""
        s = self._try_connect("ghidra_session", "cli", check=False,  # also of an older release
                              hello_deadline=HELLO_DEADLINE_S)
        if not s:
            return None
        with s:
            return s.call("status", deadline=HELLO_DEADLINE_S)

    def stop(self, force: bool = False, timeout: float = 60.0) -> bool:
        """Asks the daemon to shut down; returns True when its JVM is gone. A daemon that does
        not answer ``hello`` within HELLO_DEADLINE_S is wedged: ``False`` is returned (kill() it,
        or resume it and stop(force=True)). A daemon that answers ``hello`` but not ``shutdown``
        within the same deadline is treated like a closed connection: the wait for the JVM to
        exit then runs for ``timeout`` and ends in ``LaunchError`` when it does not."""
        s = self._try_connect("ghidra_session", "cli", check=False,  # stop what we cannot drive
                              hello_deadline=HELLO_DEADLINE_S)
        if not s:
            return not self.jvm_alive()
        pid = s.endpoint.get("pid")
        try:
            with s:
                s.call("shutdown", force=force, deadline=HELLO_DEADLINE_S)
        except SessionError as e:
            if e.code not in ("closed", "deadline_exceeded"):
                raise
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not self.jvm_alive():
                return True
            time.sleep(0.1)
        raise LaunchError(f"daemon pid {pid} did not exit within {timeout:.0f} s")

    def kill(self) -> bool:
        """Kills the daemon's JVM without a shutdown (tests, wedged daemons)."""
        ep = self.read_endpoint()
        if not ep or not ep.get("pid"):
            return False
        _kill_pid(int(ep["pid"]))
        end = time.monotonic() + 30
        while time.monotonic() < end and self.jvm_alive():
            time.sleep(0.05)
        # The instance lock goes with the first handles the OS closes; the project locks may go
        # seconds later (closing a file with many dirty pages, on ReFS, waits for them). Wait for
        # the process itself, so that a daemon started next finds every lock released.
        _wait_pid_exit(int(ep["pid"]), max(1.0, end - time.monotonic()))
        return not self.jvm_alive()


def _wait_pid_exit(pid: int, timeout: float) -> bool:
    """Waits until the process is gone (True), or the timeout passes (False)."""
    if IS_WINDOWS:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not h:
            return True  # no such process any more
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(h, int(timeout * 1000)) == 0
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with contextlib.suppress(ChildProcessError, OSError):
            os.waitpid(pid, os.WNOHANG)  # reap it when this process started it
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        time.sleep(0.05)
    return False


def _kill_pid(pid: int):
    if IS_WINDOWS:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if h:
            ctypes.windll.kernel32.TerminateProcess(h, 1)
            ctypes.windll.kernel32.CloseHandle(h)
    else:
        import signal
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def connect(client: str = "", harness: str = "", ghidra: str | None = None,
            state: str | None = None, instance: str = DEFAULT_INSTANCE, start: bool = True,
            **cfg_overrides) -> SocketSession:
    """Joins the per-user daemon, starting it if it is not running. The returned session is
    thread-safe; close it (or use ``with``) to release what this client holds."""
    return Daemon(ghidra, state, instance, **cfg_overrides).connect(client, harness, start)


# ---- AOT cache ------------------------------------------------------------------------------

def build_aot(ghidra: str | None, state: str | None, project: str | None,
              program: str | None, log=print, **cfg_overrides) -> Path:
    """A training run: starts a private session with ``-XX:AOTCacheOutput``, exercises start-up,
    a project, a program and the decompiler, and exits, which writes the cache. Later fast-mode
    launches with the same JDK and classpath load it."""
    st = state_dir(state)
    ensure_state(st)
    cfg = load_config(st, dict(cfg_overrides, mode="fast"))
    launch = Launch(Install.locate(ghidra), cfg, st)
    argv, info = launch.command([], use_aot=False)
    key = info["aotKey"]
    out = st / "aot" / f"{key}.aot"
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".building")
    argv, info = launch.command([], aot_output=tmp)
    t0 = time.perf_counter()
    errlog = st / "aot" / f"{key}.log"
    with open(errlog, "wb") as ef:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=ef,
                                env=launch.env, text=True, encoding="utf-8", bufsize=1)

        class _P(_Base):
            def _send(self, line):
                proc.stdin.write(line)
                proc.stdin.flush()

            def _recv(self):
                return proc.stdout.readline()

            def close(self):
                pass

        first = _first_event(proc.stdout, ef)
        if first.get("event") != "ready":
            proc.kill()
            raise LaunchError(f"training session did not start; see {errlog}")
        s = _P()
        s.call("status")
        if project:
            s.call("open_project", path=project)
            progs = s.call("list", programsOnly=True, limit=50)["entries"]
            target = program or (progs[0]["path"] if progs else None)
            if target:
                s.call("open_program", path=target)
                fns = s.call("functions", limit=5)["functions"]
                for f in fns[:3]:
                    with contextlib.suppress(SessionError):
                        s.call("decompile", address=f["address"])
            s.call("close_project", discard=True)
        s.call("shutdown")
        # The JVM now forks the cache assembly, which writes to the same stdout: keep draining
        # it, or the assembly blocks on a full pipe.
        proc.communicate(timeout=1800)
    if not tmp.is_file():
        raise LaunchError(f"the JVM wrote no AOT cache (exit {proc.returncode}); see {errlog}")
    os.replace(tmp, out)
    log(f"AOT cache {out} ({out.stat().st_size >> 20} MiB) in {time.perf_counter() - t0:.1f} s")
    return out


# ---- command line ---------------------------------------------------------------------------

def _value(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ghidra_session", description=__doc__.split("\n\n")[0])
    ap.add_argument("--ghidra", help="Ghidra install dir (default: the one holding this file)")
    ap.add_argument("--state", help="state dir (default: GHIDRA_SESSION_HOME or per-user)")
    ap.add_argument("--instance", default=DEFAULT_INSTANCE, help="daemon instance name")
    ap.add_argument("--java", help="JDK home")
    ap.add_argument("--max-heap", dest="maxHeap", help="JVM -Xmx, e.g. 16g")
    ap.add_argument("--gc", choices=["g1", "zgc", "parallel", "default"])
    ap.add_argument("--mode", choices=["fast", "standard"])
    ap.add_argument("--tmpdir", help="java.io.tmpdir for Ghidra's database buffers")
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("ensure", help="start the daemon if absent; print its endpoint (no token)")
    sub.add_parser("status", help="print the running daemon's status")
    p = sub.add_parser("health", help="print what the launcher knows of the daemon (exit 1 if it "
                       "does not answer)")
    p.add_argument("--deadline", type=float, default=10.0, help="seconds to wait (default 10)")
    p = sub.add_parser("call", help="send one request, print the result as JSON")
    p.add_argument("cmd")
    p.add_argument("fields", nargs="*", help="key=value; values are JSON when they parse")
    p = sub.add_parser("stop", help="stop the daemon")
    p.add_argument("--force", action="store_true", help="even while other clients are connected")
    sub.add_parser("kill", help="kill the daemon's JVM without a shutdown")
    p = sub.add_parser("serve", help="run the daemon in the foreground")
    p.add_argument("--idle-timeout", type=int, dest="idleTimeout")
    p = sub.add_parser("stdio", help="run a private session on this process's stdin/stdout")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p = sub.add_parser("aot", help="build the AOT cache with a training run")
    p.add_argument("--project", help="a project to exercise (opened read-only)")
    p.add_argument("--program", help="the program in it to open (default: the first)")
    p = sub.add_parser("command", help="print the java command line")
    p.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("config", help="print the effective configuration")
    sub.add_parser("version", help="print this client's version and protocol")
    a = ap.parse_args(argv)
    over = {k: getattr(a, k, None) for k in ("java", "maxHeap", "gc", "mode", "tmpdir")}
    try:
        st = state_dir(a.state)
        if a.action == "version":
            print(json.dumps({"client": CLIENT_VERSION, "protocol": PROTOCOL,
                              "release": HYDRA_RELEASE}))
            return 0
        if a.action == "config":
            cfg = load_config(st, over)
            launch = Launch(Install.locate(a.ghidra), cfg, st)
            cfg["effectiveMaxHeap"] = cfg["maxHeap"] or default_max_heap()
            print(json.dumps({"state": str(st), "install": str(launch.install.dir),
                              "ghidra": launch.install.version, "jdk": str(launch.jdk),
                              "jdkVersion": launch.jdk_version, "config": cfg}, indent=1))
            return 0
        if a.action == "command":
            ensure_state(st)
            launch = Launch(Install.locate(a.ghidra), load_config(st, over), st)
            argv_, info = launch.command(a.args)
            print(subprocess.list2cmdline(argv_) if IS_WINDOWS else " ".join(argv_))
            print(json.dumps(info), file=sys.stderr)
            return 0
        if a.action == "stdio":
            ensure_state(st)
            launch = Launch(Install.locate(a.ghidra), load_config(st, over), st)
            argv_, _ = launch.command(a.args)
            return subprocess.call(argv_, env=launch.env)
        if a.action == "aot":
            build_aot(a.ghidra, a.state, a.project, a.program, **over)
            return 0
        if a.action == "serve":
            ensure_state(st)
            if getattr(a, "idleTimeout", None) is not None:
                over["idleTimeout"] = a.idleTimeout
            cfg = load_config(st, over)
            launch = Launch(Install.locate(a.ghidra), cfg, st)
            args = ["-daemon", "-stateDir", str(st), "-instance", a.instance, "-idleTimeout",
                    str(cfg["idleTimeout"]), "-keepWarm", str(cfg["keepWarm"]), "-maxQuick",
                    str(cfg["maxQuick"]), "-maxLong", str(cfg["maxLong"])]
            if cfg.get("maxImports"):
                args += ["-maxImports", str(cfg["maxImports"])]
            for d in cfg.get("scriptPath") or []:
                args += ["-scriptPath", d]
            argv_, _ = launch.command(args)
            return subprocess.call(argv_, env=launch.env, stdin=subprocess.DEVNULL)
        d = Daemon(a.ghidra, a.state, a.instance, **over)
        if a.action == "ensure":
            with d.connect("ghidra_session", "cli") as s:
                ep = {k: v for k, v in s.endpoint.items() if k != "token"}
                ep["endpointFile"] = str(d.endpoint_file)
                print(json.dumps(ep, indent=1))
            return 0
        if a.action == "status":
            stt = d.status()
            if stt is None:
                print(f"no {a.instance!r} daemon is running", file=sys.stderr)
                return 1
            print(json.dumps(stt, indent=1))
            return 0
        if a.action == "health":
            h = d.health(deadline=a.deadline)
            print(json.dumps(h, indent=1))
            return 0 if h["answers"] else 1
        if a.action == "stop":
            print("stopped" if d.stop(force=a.force) else "not running")
            return 0
        if a.action == "kill":
            print("killed" if d.kill() else "not running")
            return 0
        if a.action == "call":
            fields = {}
            for kv in a.fields:
                if "=" not in kv:
                    ap.error(f"field {kv!r} is not key=value")
                k, v = kv.split("=", 1)
                fields[k] = _value(v)
            with d.connect("ghidra_session", "cli") as s:
                print(json.dumps(s.call(a.cmd, **fields), indent=1))
            return 0
    except SessionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except IncompatibleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    except LaunchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
