/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.headless.session;

import java.io.*;
import java.net.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLaunchable;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.Msg;

/**
 * A long-lived headless Ghidra process that works like the window does: open projects, list
 * them, open and switch programs, query, edit, analyse, run scripts, save, and stay up for the
 * next command. {@code analyzeHeadless} is one command about one program file; this is a session.
 * <p>
 * Callers speak JSON lines (one request object per line, one response per line) on stdio and/or
 * on an authenticated loopback socket. See {@code Ghidra/Features/HeadlessSession/README.md}.
 * <p>
 * With {@code -daemon} it is the shared per-user service: one JVM that serves any number of
 * projects and clients, found through {@code <stateDir>/<instance>.json} and kept unique by an
 * exclusive lock on {@code <stateDir>/<instance>.lock} for its whole life.
 * {@code support/ghidra_session.py} starts it when absent and connects to it otherwise.
 * <p>
 * stdout is the protocol channel of the stdio client: it is claimed before Ghidra starts and
 * everything else (Ghidra's log, scripts' {@code System.out}) is sent to stderr.
 */
public class HeadlessSession implements GhidraLaunchable {

	private static final String USAGE = """
		usage: HeadlessSession [-project <file.gpr | dir>] [-writable]
		                       [-listen [127.0.0.1:]<port>] [-endpoint <file>] [-noStdio]
		                       [-daemon -stateDir <dir> [-instance <name>]]
		                       [-idleTimeout <seconds>] [-keepWarm <seconds>]
		                       [-maxQuick <n>] [-maxLong <n>] [-maxImports <n>]
		                       [-scriptPath <dir>]... [-log <file>]
		                       [-upgradeCache <dir>] [-forkCopyLimitMb <n>]
		                       [-set <key>=<value>]... [-selfTest]
		  (normally started by Ghidra/Features/HeadlessSession/support/ghidra_session.py)
		  -project      open this project at start (a .gpr, its folder, or a parent with one)
		  -writable     open it writable (takes the project lock); default: read-only view
		  -listen       also serve clients on a loopback TCP port (0 picks one)
		  -endpoint     write {port, token, pid, ...} for socket clients to this file
		  -noStdio      do not serve stdin/stdout; requires -listen
		  -daemon       the shared per-user service: -listen 0 -noStdio, endpoint and instance
		                lock in -stateDir, named by -instance (default "default")
		  -idleTimeout  without stdio: exit after this many seconds without clients (0: never)
		  -keepWarm     keep an unused read-only program or project open this long (default 3600)
		  -maxQuick     concurrent quick requests (default: CPU count)
		  -maxLong      concurrent long requests: analyze, import, script, save (default: CPU/4)
		  -maxImports   concurrent imports, each also in a long slot (default: CPU/4, 1 to 4)
		  -scriptPath   an extra GhidraScript directory; repeat it, or give a list separated by
		                the platform's path separator
		  -log          Ghidra application log file
		  -upgradeCache serve read-only opens of programs in an older database format from an
		                upgraded copy of their project kept in this directory (default: none)
		  -forkCopyLimitMb  fork_project mode auto refuses a full (not block-cloned) copy larger
		                than this (default 2048)
		  -set          an engine setting (PROTOCOL-3.md 3.7); repeat it. The launcher passes every
		                entry of the "engine" object of config.json this way
		  -selfTest     check the engine's registries and seams, print one line each and exit
		                (0 when every check held); starts no session
		""";

	private final Object exitLock = new Object();
	private volatile Session session;
	private volatile Path endpointFile;
	private FileChannel instanceChannel;
	private FileLock instanceLock;

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		long t0 = System.nanoTime();
		Options o;
		boolean requireExpect = false;
		try {
			o = Options.parse(args);
			requireExpect = Settings.bool("requireExpect", false); // a bad value is a usage error
		}
		catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			System.err.print(USAGE);
			System.exit(2);
			return;
		}
		if (o.selfTest) {
			System.exit(SelfTest.run());
			return;
		}
		boolean requireExpectSetting = requireExpect;

		// Claim the protocol channel before anything else can print to stdout.
		OutputStream proto = new FileOutputStream(FileDescriptor.out);
		System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true,
			StandardCharsets.UTF_8));

		if (o.daemon && !lockInstance(o)) {
			System.exit(3);
			return;
		}

		HeadlessGhidraApplicationConfiguration config = new SessionApplicationConfiguration();
		if (o.log != null) {
			config.setApplicationLogFile(new File(o.log));
		}
		Application.initializeApplication(layout, config);
		// The OSGi framework that compiles scripts starts after the session is ready; the
		// commands that run scripts wait for it (DeferredInit.await).
		List<ResourceFile> scriptDirs =
			o.scriptDirs.stream().map(d -> new ResourceFile(new File(d))).toList();
		DeferredInit.add("script bundles",
			() -> GhidraScriptUtil.acquireBundleHostReference().add(scriptDirs, true, true));

		int cpus = Runtime.getRuntime().availableProcessors();
		int maxQuick = o.maxQuick > 0 ? o.maxQuick : cpus;
		int maxLong = o.maxLong > 0 ? o.maxLong : Math.max(2, cpus / 4);
		Scheduler scheduler = new Scheduler(maxQuick, maxLong);
		int maxImports = o.maxImports > 0 ? o.maxImports : ImportGate.defaultPermits(cpus);
		ImportGate.GLOBAL.setPermits(maxImports);
		// what hello reports to a protocol 3 client (3.2); the other packages set their own
		Advertised.limit("maxQuick", () -> maxQuick);
		Advertised.limit("maxLong", () -> maxLong);
		Advertised.limit("maxImports", () -> maxImports);
		Advertised.policy("requireExpect", () -> requireExpectSetting);
		Identity.setPaths(o.stateDir == null ? null : Path.of(o.stateDir).toAbsolutePath().toString(),
			o.daemon ? o.instance : null, o.endpoint, o.log, o.scriptDirs, o.upgradeCache);
		Identity.warm();
		session = new Session(scheduler, o.keepWarmSeconds,
			new UpgradeCache(o.upgradeCache == null ? null : new File(o.upgradeCache), scheduler));
		if (o.forkCopyLimitMb >= 0) {
			session.forkCopyLimitBytes = o.forkCopyLimitMb << 20;
		}
		Runtime.getRuntime().addShutdownHook(new Thread(this::removeEndpoint, "session-exit"));

		Connection stdio = null;
		if (o.stdio) {
			stdio = new Connection(session, new BufferedInputStream(System.in, 1 << 16), proto,
				"stdio", true, null, this::exit);
		}

		if (o.project != null) {
			JsonObject req = Json.of("path", o.project, "writable", o.writable);
			try {
				Connection boot = stdio;
				Client c = boot != null ? boot.client() : session.connect("startup", true, x -> {
				});
				session.execute(c, "open_project", req, new RequestMonitor(null, null));
				if (boot == null) {
					session.disconnect(c);
				}
			}
			catch (SessionException e) {
				fatal(proto, e, o.stdio);
				return;
			}
		}

		String token = null;
		if (o.listenPort >= 0) {
			byte[] raw = new byte[32];
			new SecureRandom().nextBytes(raw);
			token = HexFormat.of().formatHex(raw);
			ServerSocket server = new ServerSocket();
			server.bind(new InetSocketAddress(o.listenHost, o.listenPort), 50);
			session.listenInfo =
				Json.of("host", o.listenHost.getHostAddress(), "port", server.getLocalPort());
			startAcceptor(server, token);
		}

		long readyMs = (System.nanoTime() - t0) / 1_000_000;
		session.launchInfo = launchInfo(readyMs);
		if (o.endpoint != null) {
			writeEndpoint(Path.of(o.endpoint), session.listenInfo.get("port").getAsInt(), token,
				o);
		}

		JsonObject ready = session.info(null);
		ready.addProperty("event", "ready");
		ready.addProperty("startupMs", readyMs);
		ready.addProperty("protocolMin", HydraInfo.PROTOCOL_MIN); // V6: additive
		ready.addProperty("protocolMax", HydraInfo.PROTOCOL_MAX);
		if (token != null && o.stdio) {
			ready.addProperty("token", token); // the launcher's own pipe
		}
		Msg.info(this, "headless session ready: " + Json.GSON.toJson(session.launchInfo));

		startReaper();
		if (stdio != null) {
			stdio.send(ready);
			DeferredInit.start();
			stdio.run(); // returns at end of stdin: the launcher is gone
			exit();
			return;
		}
		DeferredInit.start();
		idleLoop(o.idleTimeoutSeconds);
	}

	/** How this JVM was started, as far as it can tell, and how long start-up took. */
	private static JsonObject launchInfo(long readyMs) {
		JsonObject o = Json.of("mode",
			ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader ? "standard" : "fast",
			"aot", System.getProperty("ghidra.session.aot"), "classCache",
			SessionApplicationConfiguration.classCacheState, "readyMs", readyMs);
		Optional<Instant> start = ProcessHandle.current().info().startInstant();
		start.ifPresent(s -> Json.put(o, "jvmToReadyMs",
			Duration.between(s, Instant.now()).toMillis()));
		return o;
	}

	/**
	 * Takes the daemon's instance lock, held for the life of the JVM. A second daemon of the same
	 * instance gives up here, before Ghidra starts, and exits with code 3.
	 */
	private boolean lockInstance(Options o) throws IOException {
		Path dir = Path.of(o.stateDir).toAbsolutePath();
		Files.createDirectories(dir);
		Path lock = dir.resolve(o.instance + ".lock");
		instanceChannel = FileChannel.open(lock, StandardOpenOption.CREATE,
			StandardOpenOption.WRITE, StandardOpenOption.READ);
		try {
			instanceLock = instanceChannel.tryLock();
		}
		catch (OverlappingFileLockException e) {
			instanceLock = null;
		}
		if (instanceLock == null) {
			System.err.println("another headless session daemon holds " + lock + "; exiting");
			instanceChannel.close();
			return false;
		}
		return true;
	}

	private void fatal(OutputStream proto, SessionException e, boolean stdio) {
		Msg.error(this, "headless session: " + e.getMessage());
		if (stdio) {
			JsonObject f = Json.of("event", "fatal", "error",
				Json.of("code", e.code(), "message", e.getMessage()));
			try {
				proto.write((Json.GSON.toJson(f) + "\n").getBytes(StandardCharsets.UTF_8));
				proto.flush();
			}
			catch (IOException ignored) {
				// nobody is listening
			}
		}
		removeEndpoint();
		System.exit(2);
	}

	private void startAcceptor(ServerSocket server, String token) {
		Thread t = new Thread(() -> {
			while (!session.isShuttingDown()) {
				Socket s;
				try {
					s = server.accept();
				}
				catch (IOException e) {
					if (!session.isShuttingDown()) {
						Msg.error(this, "accept failed", e);
					}
					return;
				}
				Thread ct = new Thread(() -> serveSocket(s, token), "session-socket");
				ct.setDaemon(true);
				ct.start();
			}
		}, "session-accept");
		t.setDaemon(true);
		t.start();
	}

	private void serveSocket(Socket s, String token) {
		try (s) {
			s.setTcpNoDelay(true);
			s.setKeepAlive(true); // a client that vanishes without a FIN is still released
			Connection c = new Connection(session,
				new BufferedInputStream(s.getInputStream(), 1 << 16),
				new BufferedOutputStream(s.getOutputStream(), 1 << 16), "socket", false, token,
				this::exit);
			Msg.info(this, c.client().label() + " connected from " + s.getRemoteSocketAddress());
			c.run();
		}
		catch (IOException e) {
			Msg.info(this, "socket client: " + e.getMessage());
		}
	}

	private void startReaper() {
		Thread t = new Thread(() -> {
			while (!session.isShuttingDown()) {
				try {
					Thread.sleep(Math.min(15_000, Math.max(1_000, session.keepWarmMs / 4)));
					session.reap();
				}
				catch (InterruptedException e) {
					return;
				}
				catch (RuntimeException e) {
					Msg.error(this, "reaper", e);
				}
			}
		}, "session-reaper");
		t.setDaemon(true);
		t.start();
	}

	private void idleLoop(long idleSeconds) throws InterruptedException {
		long idleSince = System.currentTimeMillis();
		while (!session.isShuttingDown()) {
			Thread.sleep(1000);
			if (session.clientCount() > 0) {
				idleSince = System.currentTimeMillis();
			}
			else if (idleSeconds > 0 &&
				System.currentTimeMillis() - idleSince > idleSeconds * 1000) {
				Msg.info(this, "no clients for " + idleSeconds + " s; stopping");
				exit();
			}
		}
		// Another thread is in exit(): closing projects, cancelling upgrade cache builds. It ends
		// the process with System.exit. Returning here would end the main thread, and with only
		// daemon threads left the JVM would exit in the middle of that clean-up.
		synchronized (exitLock) {
			while (true) {
				exitLock.wait();
			}
		}
	}

	private void exit() {
		synchronized (exitLock) {
			try {
				session.close();
			}
			catch (RuntimeException e) {
				Msg.error(this, "shutdown", e);
			}
			finally {
				GhidraScriptUtil.releaseBundleHostReference();
				removeEndpoint();
				System.exit(0);
			}
		}
	}

	private void writeEndpoint(Path file, int port, String token, Options o) throws IOException {
		JsonObject e = Json.of("protocol", HydraInfo.PROTOCOL, "protocolMin",
			HydraInfo.PROTOCOL_MIN, "protocolMax", HydraInfo.PROTOCOL_MAX, "minClient",
			HydraInfo.minClient(), "hydraVersion", HydraInfo.hydraVersion(), "ghidraVersion",
			Application.getApplicationVersion(), "installId", HydraInfo.installId(), "pid",
			ProcessHandle.current().pid(), "host", o.listenHost.getHostAddress(), "port", port,
			"token", token, "instance", o.daemon ? o.instance : null, "install",
			Application.getInstallationDirectory().getAbsolutePath(), "ghidra",
			Application.getApplicationVersion(), "java", System.getProperty("java.version"),
			"project", o.project, "writable", o.writable, "launch", session.launchInfo,
			"started", System.currentTimeMillis());
		Path dir = file.toAbsolutePath().getParent();
		Files.createDirectories(dir);
		Path tmp = Files.createTempFile(dir, ".endpoint", ".tmp");
		try {
			Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
		}
		catch (UnsupportedOperationException ex) {
			// Windows: the file inherits the (per-user) ACL of its folder
		}
		Files.writeString(tmp, Json.GSON.toJson(e) + "\n", StandardCharsets.UTF_8);
		Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
			StandardCopyOption.ATOMIC_MOVE);
		endpointFile = file;
	}

	/** Removes the endpoint file, unless another daemon has replaced it meanwhile. */
	private void removeEndpoint() {
		Path f = endpointFile;
		endpointFile = null;
		if (f == null) {
			return;
		}
		try {
			String text = Files.readString(f, StandardCharsets.UTF_8);
			if (text.contains("\"pid\":" + ProcessHandle.current().pid() + ",")) {
				Files.deleteIfExists(f);
			}
		}
		catch (IOException e) {
			// best effort
		}
	}

	private static final class Options {
		String project;
		boolean writable;
		boolean stdio = true;
		InetAddress listenHost;
		int listenPort = -1;
		String endpoint;
		boolean daemon;
		String stateDir;
		String instance = "default";
		long idleTimeoutSeconds;
		long keepWarmSeconds = 3600;
		int maxQuick;
		int maxLong;
		int maxImports;
		List<String> scriptDirs = new ArrayList<>();
		String log;
		String upgradeCache;
		long forkCopyLimitMb = -1;
		boolean selfTest;

		static Options parse(String[] args) {
			Options o = new Options();
			for (int i = 0; i < args.length; i++) {
				String a = args[i];
				switch (a) {
					case "-project" -> o.project = value(args, ++i, a);
					case "-writable" -> o.writable = true;
					case "-listen" -> o.listen(value(args, ++i, a));
					case "-endpoint" -> o.endpoint = value(args, ++i, a);
					case "-noStdio" -> o.stdio = false;
					case "-daemon" -> o.daemon = true;
					case "-stateDir" -> o.stateDir = value(args, ++i, a);
					case "-instance" -> o.instance = value(args, ++i, a);
					case "-idleTimeout" -> o.idleTimeoutSeconds = number(args, ++i, a);
					case "-keepWarm" -> o.keepWarmSeconds = number(args, ++i, a);
					case "-maxQuick" -> o.maxQuick = (int) number(args, ++i, a);
					case "-maxLong" -> o.maxLong = (int) number(args, ++i, a);
					case "-maxImports" -> o.maxImports = (int) number(args, ++i, a);
					case "-scriptPath" -> {
						for (String d : value(args, ++i, a).split(File.pathSeparator)) {
							if (!d.isBlank()) {
								o.scriptDirs.add(d.trim());
							}
						}
					}
					case "-log" -> o.log = value(args, ++i, a);
					case "-upgradeCache" -> o.upgradeCache = value(args, ++i, a);
					case "-forkCopyLimitMb" -> o.forkCopyLimitMb = number(args, ++i, a);
					case "-set" -> Settings.set(value(args, ++i, a));
					case "-selfTest" -> o.selfTest = true;
					default -> throw new IllegalArgumentException("unknown option: " + a);
				}
			}
			if (o.daemon) {
				if (o.stateDir == null) {
					throw new IllegalArgumentException("-daemon needs -stateDir");
				}
				if (!o.instance.matches("[A-Za-z0-9_.-]{1,64}")) {
					throw new IllegalArgumentException("bad -instance name: " + o.instance);
				}
				o.stdio = false;
				if (o.listenPort < 0) {
					o.listen("0");
				}
				o.endpoint = Path.of(o.stateDir, o.instance + ".json").toString();
			}
			if (!o.stdio && o.listenPort < 0) {
				throw new IllegalArgumentException("-noStdio needs -listen");
			}
			if (o.endpoint != null && o.listenPort < 0) {
				throw new IllegalArgumentException("-endpoint needs -listen");
			}
			return o;
		}

		private void listen(String spec) {
			String host = "127.0.0.1";
			String port = spec;
			int colon = spec.lastIndexOf(':');
			if (colon >= 0) {
				host = spec.substring(0, colon);
				port = spec.substring(colon + 1);
			}
			try {
				listenHost = InetAddress.getByName(host);
			}
			catch (UnknownHostException e) {
				throw new IllegalArgumentException("bad -listen host: " + host);
			}
			if (!listenHost.isLoopbackAddress()) {
				throw new IllegalArgumentException(
					"-listen accepts loopback addresses only, not " + host);
			}
			listenPort = Integer.parseInt(port);
			if (listenPort < 0 || listenPort > 65535) {
				throw new IllegalArgumentException("bad -listen port: " + port);
			}
		}

		private static String value(String[] args, int i, String opt) {
			if (i >= args.length) {
				throw new IllegalArgumentException(opt + " needs a value");
			}
			return args[i];
		}

		private static long number(String[] args, int i, String opt) {
			try {
				long v = Long.parseLong(value(args, i, opt));
				if (v < 0) {
					throw new NumberFormatException();
				}
				return v;
			}
			catch (NumberFormatException e) {
				throw new IllegalArgumentException(opt + " needs a number >= 0");
			}
		}
	}

	/**
	 * {@code -selfTest}: checks the registries and the seams of package E1 without starting a
	 * session (no Ghidra application, no project), so that a test can run it against any build:
	 * one line per check, {@code ok} or {@code FAIL}, then {@code SETTINGS <json>} with what
	 * {@code -set} stored, and the exit code is 0 only when every check held.
	 */
	static final class SelfTest {
		private static int bad;

		private SelfTest() {
		}

		private static void check(String what, boolean cond) {
			System.out.println((cond ? "ok   " : "FAIL ") + what);
			if (!cond) {
				bad++;
			}
		}

		private static boolean throwsIllegal(Runnable r) {
			try {
				r.run();
				return false;
			}
			catch (IllegalArgumentException e) {
				return true;
			}
		}

		private static JsonObject obj(String json) {
			return com.google.gson.JsonParser.parseString(json).getAsJsonObject();
		}

		static int run() {
			advertised();
			settings();
			lanes();
			negotiation();
			errors();
			preflight();
			dbVersions();
			System.out.println(
				bad == 0 ? "all self-test checks held" : bad + " self-test check(s) FAILED");
			return bad == 0 ? 0 : 1;
		}

		private static void advertised() {
			check("registering an unknown capability throws",
				throwsIllegal(() -> Advertised.capability("noSuchCapability", 1)));
			check("registering an unknown limit throws",
				throwsIllegal(() -> Advertised.limit("noSuchLimit", () -> 1)));
			check("registering an unknown policy throws",
				throwsIllegal(() -> Advertised.policy("noSuchPolicy", () -> true)));
			check("a capability version below 1 throws",
				throwsIllegal(() -> Advertised.capability("health", 0)));
			// registered out of order, rendered in declaration order
			Advertised.capability("identity", 1);
			Advertised.capability("expectAll", 2);
			Advertised.limit("maxLong", () -> 4);
			Advertised.limit("maxQuick", () -> 16);
			Advertised.policy("requireExpect", () -> false);
			check("capabilities render in declaration order, only those registered",
				Json.GSON.toJson(Advertised.capabilities()).equals("{\"expectAll\":2,\"identity\":1}"));
			check("limits render in declaration order",
				Json.GSON.toJson(Advertised.limits()).equals("{\"maxQuick\":16,\"maxLong\":4}"));
			check("policy renders what was set",
				Json.GSON.toJson(Advertised.policy()).equals("{\"requireExpect\":false}"));
		}

		private static void settings() {
			check("a setting without = throws", throwsIllegal(() -> Settings.set("novalue")));
			check("a setting with a bad key throws", throwsIllegal(() -> Settings.set("1x=2")));
			check("an integer that is not one throws", throwsIllegal(() -> {
				Settings.set("selfTestInt", "x");
				Settings.integer("selfTestInt", 0);
			}));
			check("a boolean that is not true or false throws", throwsIllegal(() -> {
				Settings.set("selfTestBool", "yes");
				Settings.bool("selfTestBool", false);
			}));
			Settings.set("selfTestInt", "7");
			Settings.set("selfTestBool", "true");
			check("a value reaches its typed reader", Settings.integer("selfTestInt", 0) == 7 &&
				Settings.bool("selfTestBool", false) && Settings.integer("selfTestUnset", 5) == 5);
			Settings.set("selfTestInt", "8");
			check("a repeated key keeps its last value", Settings.integer("selfTestInt", 0) == 8);
		}

		private static final List<String> LONG = List.of("analyze", "import", "script", "save",
			"fork_project", "refresh", "reopen", "promote_overlay");
		private static final List<String> QUICK = List.of("list", "functions", "decompile",
			"rename", "comment", "open_program", "switch", "open_project");
		private static final List<String> NONE = List.of("ping", "hello", "status", "cancel",
			"shutdown", "projects", "programs", "info", "close_project", "close_program", "edit",
			"journal", "discard_edits", "project", "overlays", "apply_overlay", "drop_overlay",
			"health", "nosuchcommand", "");

		private static void lanes() {
			boolean same = true;
			JsonObject quickHint = Json.of("lane", "quick", "timeout", 30);
			for (boolean v3 : new boolean[] { false, true }) {
				for (JsonObject req : new JsonObject[] { new JsonObject(), quickHint }) {
					for (String cmd : LONG) {
						same &= Scheduler.laneOf(cmd, req, v3) == Scheduler.Lane.LONG;
					}
					for (String cmd : QUICK) {
						same &= Scheduler.laneOf(cmd, req, v3) == Scheduler.Lane.QUICK;
					}
					for (String cmd : NONE) {
						same &= Scheduler.laneOf(cmd, req, v3) == null;
					}
				}
			}
			check("laneOf(cmd, req, v3) is today's lane for every command, v2 and v3, with and " +
				"without a lane hint", same);
			Scheduler s = new Scheduler(3, 2);
			String empty =
				"{\"quick\":{\"slots\":3,\"inUse\":0,\"queued\":0,\"running\":[],\"waiting\":[]," +
					"\"admitted\":0,\"everQueued\":0,\"backgroundQueued\":0},\"long\":{\"slots\":2," +
					"\"inUse\":0,\"queued\":0,\"running\":[],\"waiting\":[],\"admitted\":0," +
					"\"everQueued\":0,\"backgroundQueued\":0}}";
			check("describe(false) of an idle scheduler is today's object",
				Json.GSON.toJson(s.describe(false)).equals(empty));
			check("describe(true) is the same object until the v3 fields exist",
				Json.GSON.toJson(s.describe(true)).equals(empty));
			Client c = new Client(1, "selftest", false, null);
			try (Scheduler.Ticket t = s.admit(c, "save", new JsonObject(), null, 100)) {
				JsonObject d = s.describe(false);
				check("a save holds a long slot, as today",
					d.getAsJsonObject("long").get("inUse").getAsInt() == 1 &&
						d.getAsJsonObject("quick").get("inUse").getAsInt() == 0);
				JsonObject d3 = s.describe(true);
				check("describe(true) shows the same single running save, in the long lane",
					d3.getAsJsonObject("long").getAsJsonArray("running").size() == 1 &&
						!d3.has("maint"));
			}
		}

		private static void negotiation() {
			String[] asks = { "{}", "{\"protocol\":3}", "{\"protocol\":9}", "{\"protocol\":2}",
				"{\"protocol\":1}", "{\"protocol\":0}", "{\"protocol\":-5}", "{\"protocol\":\"3\"}",
				"{\"protocol\":3.0}", "{\"protocol\":true}", "{\"protocol\":null}",
				"{\"protocol\":[3]}", "{\"protocol\":99999999999999999999}",
				"{\"protocol\":-99999999999999999999}", "{\"protocol\":-4294967293}",
				"{\"protocol\":-4294967292}", "{\"protocol\":-9223372036854775805}" };
			int[] want = { 2, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2 };
			boolean all = true;
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < asks.length; i++) {
				int got = Client.requestedProtocol(obj(asks[i]));
				all &= got == want[i];
				sb.append(' ').append(asks[i]).append("->").append(got);
			}
			check("the protocol a hello asks for is answered as 3.1 says:" + sb, all);
			Client a = new Client(1, "selftest", false, null);
			check("a connection is protocol 2 before any hello", a.protocol() == 2 && !a.v3());
			a.negotiate(obj("{\"protocol\":3}"));
			a.negotiate(obj("{\"protocol\":2}"));
			check("the first hello fixes protocol 3; a later hello asking 2 changes nothing",
				a.protocol() == 3 && a.v3());
			Client b = new Client(2, "selftest", false, null);
			b.negotiate(obj("{}"));
			b.negotiate(obj("{\"protocol\":3}"));
			check("the first hello fixes protocol 2; a later hello asking 3 changes nothing",
				b.protocol() == 2 && !b.v3());
		}

		private static void errors() {
			JsonObject base = Json.of("lane", "long");
			check("busyDetails for v2 returns the details as they were",
				SessionException
						.busyDetails(false, base.deepCopy(), "slot_wait", Json.of("x", 1), true)
						.equals(base));
			check("busyDetails for v3 adds reason, queue and abandoned",
				Json.GSON.toJson(SessionException.busyDetails(true, base.deepCopy(), "slot_wait",
					Json.of("position", 1), false)).equals(
						"{\"lane\":\"long\",\"reason\":\"slot_wait\",\"queue\":{\"position\":1}," +
							"\"abandoned\":false}"));
			check("badRequest for v2 has no details",
				SessionException.badRequest(false, "m", "lane", List.of("quick")).details() == null);
			check("badRequest for v3 has field and allowed",
				Json.GSON.toJson(SessionException.badRequest(true, "m", "lane",
					List.of("quick", "long")).details()).equals(
						"{\"field\":\"lane\",\"allowed\":[\"quick\",\"long\"]}"));
			check("retryAfterMs is clamped to 250..10000",
				new SessionException("busy", "m").withRetryAfterMs(1).retryAfterMs() == 250 &&
					new SessionException("busy", "m").withRetryAfterMs(1000).retryAfterMs() == 1000 &&
					new SessionException("busy", "m").withRetryAfterMs(99999).retryAfterMs() == 10000);
			SessionException e = new SessionException("conflict", "m").withNext(Json.of("cmd", "x"))
					.withRetryAfterMs(500).rewrap("m2", null);
			check("rewrap keeps next and retryAfterMs", e.next() != null && e.retryAfterMs() == 500 &&
				e.getMessage().equals("m2") && e.code().equals("conflict"));
		}

		private static void preflight() {
			List<String> order = new ArrayList<>();
			Preflight.register(Preflight.ALL, (cmd, req) -> order.add("*" + cmd));
			Preflight.register("selftest", (cmd, req) -> order.add("own"));
			Preflight.run("selftest", new JsonObject());
			Preflight.run("other", new JsonObject());
			check("Preflight runs the * checks, then the command's, in order; a command without " +
				"its own runs only the *", order.equals(List.of("*selftest", "own", "*other")) &&
					Preflight.count("selftest") == 2 && Preflight.count("other") == 1);
			Preflight.register("selftestRefuse", (cmd, req) -> {
				throw new SessionException(SessionException.BAD_REQUEST, "refused");
			});
			boolean refused = false;
			try {
				Preflight.run("selftestRefuse", new JsonObject());
			}
			catch (SessionException ex) {
				refused = ex.code().equals(SessionException.BAD_REQUEST);
			}
			check("a refusal propagates", refused);
		}

		private static void dbVersions() {
			check("DbVersions.program() reads ProgramDB.DB_VERSION (positive)",
				DbVersions.program() > 0);
			check("DbVersions.dataTypes() reads DataTypeManagerDB.DB_VERSION (positive; E2 tested " +
				"it against the 12.1.4 fixture)", DbVersions.dataTypes() != null &&
					DbVersions.dataTypes() > 0);
			JsonObject all = new JsonObject();
			Settings.all().forEach((k, v) -> {
				if (!k.startsWith("selfTest")) {
					all.addProperty(k, v);
				}
			});
			// the line a test reads: what -set stored (the self-test's own keys left out), and how
			// the two typed readers see the keys the engine itself defines
			System.out.println("SETTINGS " + Json.GSON.toJson(Json.of("set", all, "requireExpect",
				Settings.bool("requireExpect", false), "maintSlots", Settings.integer("maintSlots", -1))));
		}
	}
}
