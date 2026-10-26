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
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

PROTOCOL = 2
MAIN_CLASS = "ghidra.app.util.headless.session.HeadlessSession"
FAST_MAIN_CLASS = "ghidra.app.util.headless.session.SessionMain"
DEFAULT_INSTANCE = "default"
ENDPOINT_WAIT_S = 180.0

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"


# ---- install --------------------------------------------------------------------------------

class LaunchError(RuntimeError):
    """The session could not be started: no JDK, a bad install, a daemon that does not answer."""


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
                              f"{self.dir}")
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
                              "can be launched")
        self.module_dir = self.app_root / "Features" / "HeadlessSession"
        if not (self.module_dir / "lib" / "HeadlessSession.jar").is_file():
            raise LaunchError(f"this install has no HeadlessSession module: {self.module_dir}")

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
        raise LaunchError("no Ghidra install: pass --ghidra <dir> or set GHIDRA_INSTALL_DIR")

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
            continue
        if not (home / "bin" / ("javac.exe" if IS_WINDOWS else "javac")).is_file():
            tried.append(f"{src}={cand} (a JRE; Ghidra needs a JDK)")
            continue
        return home, full
    raise LaunchError("no suitable JDK found; set GHIDRA_SESSION_JAVA_HOME or pass --java. Tried: "
                      + ("; ".join(tried) or "nothing (no JAVA_HOME, no java on PATH)"))


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
    "maxLong": 0,            # concurrent long requests (analyze, import, script); 0: CPU/4
    "scriptPath": [],        # extra GhidraScript directories
    "log": None,             # daemon log; None: <state>/<instance>.log
    "upgradeCache": True,    # serve read-only opens of older-format programs from an upgraded copy
    "upgradeCacheDir": None,  # where those copies live; None: <state>/upgrade-cache
    "forkCopyLimitMb": 2048,  # fork_project mode auto: refuse a full (not cloned) copy over this
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
}


def load_config(state: Path, overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULTS)
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
    for env, (key, typ) in ENV_MAP.items():
        if os.environ.get(env):
            cfg[key] = typ(os.environ[env])
    if os.environ.get("GHIDRA_SESSION_VMARGS"):
        cfg["vmargs"] = list(cfg["vmargs"]) + os.environ["GHIDRA_SESSION_VMARGS"].split()
    for k, v in (overrides or {}).items():
        if v is not None:
            cfg[k] = v
    if cfg["mode"] not in ("fast", "standard"):
        raise LaunchError(f"mode must be fast or standard, not {cfg['mode']!r}")
    if cfg["gc"] not in ("g1", "zgc", "parallel", "default"):
        raise LaunchError(f"gc must be g1, zgc, parallel or default, not {cfg['gc']!r}")
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

    def _send(self, line: str):
        raise NotImplementedError

    def _recv(self) -> str:
        raise NotImplementedError

    def call(self, cmd: str, **fields):
        """Sends one request and waits for its response. Raises SessionError on ok:false."""
        return self.wait(self.send(cmd, **fields))

    def send(self, cmd: str, **fields) -> int:
        """Sends a request without waiting; returns its id (for ``cancel`` or a later wait)."""
        with self._lock:
            self._id += 1
            rid = self._id
            self._send(json.dumps({"id": rid, "cmd": cmd, **fields}) + "\n")
        return rid

    def wait(self, rid: int):
        while True:
            with self._done:
                if rid in self._pending:
                    msg = self._pending.pop(rid)
                    break
                if self._closed:
                    raise SessionError("closed", "the session connection ended")
            if self._read_lock.acquire(timeout=0.05):
                try:
                    with self._done:
                        if rid in self._pending:
                            continue
                    line = self._recv()
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
                            else:
                                self._pending[m.get("id")] = m
                        self._done.notify_all()
                finally:
                    self._read_lock.release()
            else:
                with self._done:
                    self._done.wait(0.05)
        self.last_ms = msg.get("ms", 0)
        if not msg.get("ok"):
            e = msg.get("error", {})
            raise SessionError(e.get("code"), e.get("message"), e.get("details"), e.get("trace"))
        return msg["result"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class SocketSession(_Base):
    """A client of a session that serves a loopback socket (the daemon)."""

    def __init__(self, endpoint: dict | str | os.PathLike, client: str = "", harness: str = "",
                 timeout: float | None = None):
        super().__init__()
        if not isinstance(endpoint, dict):
            endpoint = json.loads(Path(endpoint).read_text(encoding="utf-8"))
        self.endpoint = endpoint
        self.sock = socket.create_connection((endpoint["host"], endpoint["port"]),
                                             timeout=timeout)
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._r = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self._w = self.sock.makefile("w", encoding="utf-8", newline="\n")
        self.hello = self.call("hello", token=endpoint["token"], client=client, harness=harness)

    def _send(self, line):
        self._w.write(line)
        self._w.flush()

    def _recv(self):
        return self._r.readline()

    def close(self):
        # makefile() objects keep the socket open: close them, then shut the socket down, so the
        # session sees the disconnect (and releases what this client held) at once.
        for f in (self._w, self._r):
            with contextlib.suppress(OSError):
                f.close()
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

    def _send(self, line):
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self):
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

    def _try_connect(self, client, harness, timeout=5.0) -> SocketSession | None:
        ep = self.read_endpoint()
        if not ep:
            return None
        # A killed JVM leaves its endpoint file behind. Do not dial it: on Windows a connect to
        # a closed loopback port is retried for about 2 s before it is refused.
        if not self.jvm_alive():
            return None
        try:
            return SocketSession(ep, client=client, harness=harness, timeout=timeout)
        except (OSError, SessionError, KeyError, ValueError):
            return None

    def _check_install(self, ep: dict, install: Install):
        if ep.get("install") and Path(ep["install"]).resolve() != install.dir:
            raise LaunchError(
                f"the {self.instance!r} daemon runs {ep['install']} (Ghidra {ep.get('ghidra')}), "
                f"not {install.dir}; stop it, or use another --instance")
        if ep.get("protocol") != PROTOCOL:
            raise LaunchError(f"the {self.instance!r} daemon speaks protocol "
                              f"{ep.get('protocol')}, this client {PROTOCOL}; stop it first")

    def connect(self, client: str = "", harness: str = "", start: bool = True,
                timeout: float = ENDPOINT_WAIT_S) -> SocketSession:
        """Joins the running daemon, starting it first if there is none (and ``start``)."""
        install = Install.locate(self.ghidra)
        s = self._try_connect(client, harness)
        if s:
            self._check_install(s.endpoint, install)
            return s
        if not start:
            raise LaunchError(f"no {self.instance!r} daemon is running (state {self.state})")
        ensure_state(self.state)
        with FileLock(self.start_lock_file) as lk:
            if not lk.acquire(timeout):
                raise LaunchError(f"another process has been starting the daemon for "
                                  f"{timeout:.0f} s ({self.start_lock_file})")
            s = self._try_connect(client, harness)  # someone else started it meanwhile
            if s:
                self._check_install(s.endpoint, install)
                return s
            if self.jvm_alive():
                # starting up, or wedged: wait for its endpoint
                s = self._wait_ready(None, client, harness, timeout)
                self._check_install(s.endpoint, install)
                return s
            with contextlib.suppress(OSError):
                self.endpoint_file.unlink()  # stale: its JVM is gone
            proc = self._spawn(install)
            return self._wait_ready(proc, client, harness, timeout)

    def _spawn(self, install: Install) -> subprocess.Popen:
        cfg = load_config(self.state, self.cfg_overrides)
        launch = Launch(install, cfg, self.state)
        args = ["-daemon", "-stateDir", str(self.state), "-instance", self.instance,
                "-idleTimeout", str(cfg["idleTimeout"]), "-keepWarm", str(cfg["keepWarm"]),
                "-maxQuick", str(cfg["maxQuick"]), "-maxLong", str(cfg["maxLong"])]
        for d in cfg.get("scriptPath") or []:
            args += ["-scriptPath", d]
        argv, info = launch.command(args)
        log = self.log_file
        log.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            if log.exists() and log.stat().st_size > 32 << 20:
                os.replace(log, log.with_suffix(log.suffix + ".1"))
        lf = open(log, "ab")
        lf.write(f"\n==== ghidra_session {time.strftime('%Y-%m-%d %H:%M:%S')} {info}\n"
                 .encode())
        lf.flush()
        kw = {}
        if IS_WINDOWS:
            # Outlive the harness that started it: no console, its own process group, and out of
            # the caller's job object when the job allows it (agent harnesses often run inside
            # one that is killed with them).
            flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            try:
                return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                                        env=launch.env, creationflags=flags | 0x01000000,
                                        close_fds=True)  # | CREATE_BREAKAWAY_FROM_JOB
            except OSError:
                kw["creationflags"] = flags
        else:
            kw["start_new_session"] = True
        try:
            return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                                    env=launch.env, close_fds=True, **kw)
        finally:
            lf.close()

    def _wait_ready(self, proc, client, harness, timeout) -> SocketSession:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if proc is not None and proc.poll() is not None:
                raise LaunchError(f"the daemon exited with code {proc.returncode} while starting; "
                                  f"see {self.log_file}")
            ep = self.read_endpoint()
            # the endpoint of the JVM we started (not a stale file a killed one left behind)
            if ep and (proc is None or ep.get("pid") == proc.pid):
                s = self._try_connect(client, harness)
                if s:
                    return s
            time.sleep(0.05)
        raise LaunchError(f"the daemon did not answer within {timeout:.0f} s; see {self.log_file}")

    def status(self) -> dict | None:
        s = self._try_connect("ghidra_session", "cli")
        if not s:
            return None
        with s:
            return s.call("status")

    def stop(self, force: bool = False, timeout: float = 60.0) -> bool:
        """Asks the daemon to shut down; returns True when its JVM is gone."""
        s = self._try_connect("ghidra_session", "cli")
        if not s:
            return not self.jvm_alive()
        pid = s.endpoint.get("pid")
        try:
            with s:
                s.call("shutdown", force=force)
        except SessionError as e:
            if e.code != "closed":
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
        return not self.jvm_alive()


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
    a = ap.parse_args(argv)
    over = {k: getattr(a, k, None) for k in ("java", "maxHeap", "gc", "mode", "tmpdir")}
    try:
        st = state_dir(a.state)
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
    except LaunchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
