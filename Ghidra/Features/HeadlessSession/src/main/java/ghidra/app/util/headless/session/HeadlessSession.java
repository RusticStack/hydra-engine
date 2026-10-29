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
		  -maxLong      concurrent long requests: analyze, import, script (and save, fork_project,
		                refresh, reopen, promote_overlay on a protocol 2 connection)
		                (default: max(8, CPUs); -set maxLong=<n> does the same)
		  -maxImports   concurrent imports, each also in a long slot (default: CPU/4, 1 to 4)
		  -scriptPath   an extra GhidraScript directory; repeat it, or give a list separated by
		                the platform's path separator
		  -log          Ghidra application log file
		  -upgradeCache serve read-only opens of programs in an older database format from an
		                upgraded copy of their project kept in this directory (default: none)
		  -forkCopyLimitMb  fork_project mode auto refuses a full (not block-cloned) copy larger
		                than this (default 2048)
		  -set          an engine setting (PROTOCOL-3.md 3.7); repeat it. The launcher passes every
		                entry of the "engine" object of config.json this way. Lane settings:
		                maintSlots (default 4: the slots of the maint lane, protocol 3),
		                maxRunningPerKey[.quick|.long|.maint] (the per-key running cap),
		                quickScriptMaxS (default 60, at most 120)
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
		// E9, D60: the daemon makes its own kill-on-close Job Object before anything else, so
		// every process it starts afterwards (native decompilers, script workers) dies with it.
		// It never throws; health.processJob reports what happened.
		ProcessJob.start(layout.getApplicationInstallationDir().getFile(false).toPath());
		long t0 = System.nanoTime();
		Options o;
		boolean requireExpect = false;
		try {
			o = Options.parse(args);
			requireExpect = Settings.bool("requireExpect", false); // a bad value is a usage error
			Scheduler.validateSettings(); // so is a bad lane setting
			Health.validateSettings(); // and testHooks as a setting: it is a launch property only
			Budgets.validate(); // E9: the budgets, and -Xmx against minXmxMb
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
		// the long default is max(8, CPUs) (D40; it was a quarter of the CPUs, at least 2, and a
		// 7th client's tiny script, save and fork waited 10 s behind six long ones)
		int maxLong = o.maxLong > 0 ? o.maxLong
				: Settings.integer("maxLong", Scheduler.defaultLongSlots(cpus));
		int maintSlots = Math.max(1, Settings.integer("maintSlots", Scheduler.DEFAULT_MAINT_SLOTS));
		Scheduler scheduler = new Scheduler(maxQuick, maxLong, maintSlots);
		int maxImports = o.maxImports > 0 ? o.maxImports : ImportGate.defaultPermits(cpus);
		ImportGate.GLOBAL.setPermits(maxImports);
		// what hello reports to a protocol 3 client (3.2); the other packages set their own
		Advertised.limit("maxQuick", () -> maxQuick);
		Advertised.limit("maxLong", () -> maxLong);
		Advertised.limit("maxMaint", () -> maintSlots);
		Advertised.limit("quickScriptMaxS", Scheduler::quickScriptMaxS);
		Advertised.limit("maxRunningPerKey", scheduler::caps);
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
		// E5: the watchdog before anything can block (a project opened at start-up, a client);
		// testHooks is read from the JVM property only.
		Health.announce();
		session.startWatchdog();
		// E9: the governor after the watchdog (admission, the decompiler gate, the guarded sampler)
		Health.contribute("processJob", ProcessJob::describe); // after E3c's waits (the order is pinned)
		Governor.start(session);
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
		Guarded.start("session-accept", () -> {
			while (!session.isShuttingDown()) {
				Guarded.beat(0); // blocks in accept by design: liveness only
				Socket s;
				try {
					s = server.accept();
				}
				catch (IOException e) {
					if (session.isShuttingDown() || server.isClosed()) {
						return;
					}
					// the accept thread is restarted (3.11): Guarded runs this body again
					throw e;
				}
				try {
					Guarded.beat(0); // where a planted test fault lands
				}
				catch (Throwable t) {
					try {
						s.close();
					}
					catch (IOException ignored) {
						// the connection is dropped either way
					}
					throw t;
				}
				Thread ct = new Thread(() -> serveSocket(s, token), "session-socket");
				ct.setDaemon(true);
				ct.start();
			}
		});
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

	/**
	 * The reaper runs under {@link Guarded} (E9, D46): measurement A saw it die of an
	 * {@code OutOfMemoryError} at {@code -Xmx256m} while the daemon went on without it. A
	 * {@code Throwable} in a lap is logged and counted ({@code health.governor.threads}) and the
	 * next lap runs after a backoff.
	 */
	private void startReaper() {
		Guarded.start("session-reaper", () -> {
			while (!session.isShuttingDown()) {
				long lapMs = Math.min(15_000, Math.max(1_000, session.keepWarmMs / 4));
				Guarded.beat(lapMs); // proof of life in health.governor.threadState
				Thread.sleep(lapMs);
				session.reap();
			}
		});
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
			cancelHooks();
			waiterCaps();
			closeVsViewChange();
			dbVersions();
			health();
			governor();
			System.out.println(
				bad == 0 ? "all self-test checks held" : bad + " self-test check(s) FAILED");
			return bad == 0 ? 0 : 1;
		}

		/** E5: the state rules of 3.4, the contributor list, and testHooks as a setting. */
		private static void health() {
			check("health.state: a fresh tick, a free lock and nothing wrong is ok",
				Health.state(400, 15_000, true, 0, 0, true, false).equals("ok"));
			check("health.state: an old tick, a held scheduler lock or a deadlock is suspect",
				Health.state(15_001, 15_000, true, 0, 0, true, false).equals("suspect") &&
					Health.state(0, 15_000, false, 0, 0, true, false).equals("suspect") &&
					Health.state(0, 15_000, true, 2, 0, true, false).equals("suspect"));
			check("health.state: an abandoned holder, an unreadable db version or the hook is " +
				"degraded",
				Health.state(0, 15_000, true, 0, 1, true, false).equals("degraded") &&
					Health.state(0, 15_000, true, 0, 0, false, false).equals("degraded") &&
					Health.state(0, 15_000, true, 0, 0, true, true).equals("degraded"));
			check("health.state: suspect wins over degraded",
				Health.state(0, 15_000, false, 0, 1, false, true).equals("suspect"));
			check("a contributor may not use a core key of the reply or an empty name",
				throwsIllegal(() -> Health.contribute("state", () -> null)) &&
					throwsIllegal(() -> Health.contribute("", () -> null)));
			Health.contribute("selfTestFigure", () -> new com.google.gson.JsonPrimitive(7));
			Health.contribute("selfTestBroken", () -> {
				throw new IllegalStateException("boom");
			});
			Health.contribute("selfTestNothing", () -> null);
			Health.clearSnapshot();
			JsonObject h = Health.reply(System.currentTimeMillis() - 5, null);
			check("a contributor's figure is in the reply, a failing one is an error entry, a " +
				"null one is left out",
				h.get("selfTestFigure").getAsInt() == 7 &&
					h.getAsJsonObject("selfTestBroken").get("error").getAsString()
							.contains("boom") &&
					!h.has("selfTestNothing"));
			check("health keeps its core keys first, in the order of 3.4",
				h.keySet().stream().limit(11).toList().equals(List.of("state", "pid", "uptimeMs",
					"protocol", "tick", "schedulerLockOk", "lanes", "deadlocked", "abandoned",
					"memory", "testHooks")));
			check("health with no snapshot yet reports tick 0 and does not claim a held lock",
				h.getAsJsonObject("tick").get("n").getAsInt() == 0 &&
					h.get("schedulerLockOk").getAsBoolean());
			Settings.set("testHooks", "true");
			check("testHooks as an engine setting is a usage error (it is a launch property)",
				throwsIllegal(Health::validateSettings));
			Settings.clear();
			Settings.set("watchdogStallMs", "soon");
			check("a watchdogStallMs that is not an integer is a usage error",
				throwsIllegal(Health::validateSettings));
			Settings.clear();
			check("the test hooks are off in this JVM (no launch property)", !Health.testHooks());
		}

		/** E9: the budgets, the gate's fairness, the guarded thread and the sweep's path rule. */
		private static void governor() {
			Settings.clear();
			check("viewDiskBudget and diskReserve take sizes; a plain number is megabytes",
				sizeOf("20GB") == (20L << 30) && sizeOf("512MB") == (512L << 20) &&
					sizeOf("7") == (7L << 20) && sizeOf("100 KB") == (100L << 10));
			check("a size that is not one is a usage error naming the key",
				throwsIllegal(() -> {
					Settings.set("viewDiskBudget", "lots");
					Budgets.size("viewDiskBudget", 0);
				}));
			Settings.clear();
			check("the defaults of 3.11 validate on this heap (minXmxMb forced to 0)", ok(() -> {
				Settings.set("minXmxMb", "0");
				Budgets.validate();
			}));
			Settings.clear();
			Settings.set("minXmxMb", "1000000");
			check("a heap below minXmxMb is refused at start-up", throwsIllegal(Budgets::validate));
			Settings.clear();
			Settings.set("heapSoftPct", "90");
			Settings.set("heapHardPct", "80");
			check("a soft watermark above the hard one is a usage error",
				throwsIllegal(Budgets::validate));
			Settings.clear();
			Settings.set("maxViews", "0");
			check("maxViews below 1 is a usage error", throwsIllegal(Budgets::validate));
			Settings.clear();
			check("estHeap starts at max(8 MB, 6% of the database) and is replaced by a measurement",
				Budgets.estHeap("k1", 1L << 20) == (8L << 20) &&
					Budgets.estHeap("k1", 1000L << 20) == (60L << 20));
			Budgets.learn("k1", 5L << 20);
			check("a learned estimate replaces the default", Budgets.estHeap("k1", 1L << 30) == (5L << 20));
			Budgets.clearLearned();
			check("the gate has min(CPUs, nativeBudget / 200 MB) permits, at least one",
				Budgets.gatePermits() >= 1 &&
					Budgets.gatePermits() <= Runtime.getRuntime().availableProcessors());
			gateFairness();
			guardedRestarts();
			reservations();
			Governor.capacity("views", 1, 1, "x", 1);
			SessionException busy = Governor.capacity("heap", 9, 5, "no room", 99_999);
			check("a capacity refusal is busy with reason, resource, have, need and a clamped retry",
				busy.code().equals("busy") &&
					busy.details().get("reason").getAsString().equals("capacity") &&
					busy.details().get("resource").getAsString().equals("heap") &&
					busy.details().get("have").getAsLong() == 9 &&
					busy.details().get("need").getAsLong() == 5 &&
					busy.retryAfterMs() == SessionException.RETRY_MAX_MS);
			java.nio.file.Path fake = java.nio.file.Path.of(System.getProperty("java.io.tmpdir"),
				"hydra-selftest-no-install");
			JsonObject sw = ProcessJob.sweep(fake, false);
			check("the orphan sweep of an install with no decompiler finds none (path match)",
				sw.get("checked").getAsInt() == 0 && sw.getAsJsonArray("orphans").size() == 0);
			check("the process job is off unless the test hooks and the property are both on",
				!ProcessJob.disabledForTest());
		}

		private static long sizeOf(String v) {
			Settings.set("selfTestSize", v);
			return Budgets.size("selfTestSize", -1);
		}

		private static boolean ok(Runnable r) {
			try {
				r.run();
				return true;
			}
			catch (RuntimeException e) {
				System.out.println("     " + e.getMessage());
				return false;
			}
		}

		/** One permit held by X; X queues three waiters and Y one; the freed permit goes to Y first. */
		private static void gateFairness() {
			DecompilerGate g = new DecompilerGate(1);
			Object x = "X";
			Object y = "Y";
			DecompilerGate.Permit first = g.acquire(x, null, 5000);
			java.util.List<String> order = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
			java.util.List<Thread> ts = new java.util.ArrayList<>();
			java.util.concurrent.atomic.AtomicInteger queued = new java.util.concurrent.atomic.AtomicInteger();
			for (Object who : new Object[] { x, x, x, y }) {
				Thread t = new Thread(() -> {
					queued.incrementAndGet();
					DecompilerGate.Permit p = g.acquire(who, null, 10_000);
					order.add(who.toString());
					try {
						Thread.sleep(20);
					}
					catch (InterruptedException e) {
						// ends
					}
					p.release();
				});
				ts.add(t);
				t.start();
				try {
					while (g.waitingClients().size() < (who == y ? 2 : 1) ||
						queued.get() < ts.size()) {
						Thread.sleep(5);
					}
					Thread.sleep(30);
				}
				catch (InterruptedException e) {
					return;
				}
			}
			first.release();
			for (Thread t : ts) {
				try {
					t.join(10_000);
				}
				catch (InterruptedException e) {
					return;
				}
			}
			check("the gate serves clients in turn: Y before the second X, not X X X Y (got " + order + ")",
				order.equals(java.util.List.of("Y", "X", "X", "X")));
			DecompilerGate g2 = new DecompilerGate(1);
			DecompilerGate.Permit held = g2.acquire(x, null, 1000);
			boolean refused = false;
			long t0 = System.nanoTime();
			try {
				g2.acquire(y, null, 300);
			}
			catch (SessionException e) {
				refused = e.code().equals("busy") &&
					e.details().get("resource").getAsString().equals("native");
			}
			held.release();
			check("a wait for a permit that never comes ends in busy capacity native",
				refused && (System.nanoTime() - t0) / 1_000_000L < 3000);
			check("a released permit can be taken again, and release twice counts once",
				ok(() -> {
					DecompilerGate.Permit p = g2.acquire(x, null, 500);
					p.release();
					p.release();
					DecompilerGate.Permit q = g2.acquire(x, null, 500);
					q.release();
				}));
		}

		/**
		 * Requests that arrive together cannot all pass one count: 64 threads reserve at the same
		 * moment (a barrier) against a view limit, a per-client limit and a heap limit, and exactly
		 * the room there is is granted. The check and the reservation are one step (3.11).
		 */
		private static void reservations() {
			int n = 64;
			Settings.clear();
			Settings.set("maxViews", "4");
			Settings.set("maxViewsPerClient", "1000");
			Governor g = Governor.forTest(() -> 0);
			Client[] cs = new Client[n];
			for (int i = 0; i < n; i++) {
				cs[i] = new Client(i, "socket", false, e -> { });
			}
			int[] got = raceReserve(g, cs, 1);
			check("64 concurrent reservations against maxViews 4 grant exactly 4 (granted " + got[0] +
				", reserved " + g.reservedViewsNow() + ")", got[0] == 4 && g.reservedViewsNow() == 4);
			for (int i = 0; i < n; i++) {
				if (got[1 + i] == 1) {
					g.unreserve(cs[i], true, 1);
				}
			}
			check("the reservations are given back", g.reservedViewsNow() == 0);
			got = raceReserve(g, cs, 1);
			check("and the room is granted again, exactly 4 (granted " + got[0] + ")", got[0] == 4);
			for (int i = 0; i < n; i++) {
				if (got[1 + i] == 1) {
					g.unreserve(cs[i], true, 1);
				}
			}
			// one client, maxViewsPerClient 2, 64 requests at once
			Settings.set("maxViews", "1000");
			Settings.set("maxViewsPerClient", "2");
			Client one = cs[0];
			Client[] same = new Client[n];
			java.util.Arrays.fill(same, one);
			got = raceReserve(g, same, 1);
			check("64 concurrent requests of one client against maxViewsPerClient 2 grant exactly 2 " +
				"(granted " + got[0] + ")", got[0] == 2);
			for (int i = 0; i < n; i++) {
				if (got[1 + i] == 1) {
					g.unreserve(one, true, 1);
				}
			}
			// the heap: room for 5.5 estimates, so at most 5 are granted whoever asks
			Settings.set("maxViewsPerClient", "1000");
			long limit = Budgets.maxHeapBytes() / 100 * Budgets.heapSoftPct();
			long room = limit - g.heapAfterGc();
			if (room > (64L << 20)) {
				long est = (long) (room / (Budgets.EST_FACTOR * 5.5));
				got = raceReserve(g, cs, est);
				check("64 concurrent reservations against room for 5.5 estimates of heap grant at " +
					"most 5 (granted " + got[0] + ")", got[0] >= 1 && got[0] <= 6);
			}
			Settings.clear();
		}

		/** Every thread reserves one view at once; {@code [granted, per-thread 1/0...]}. */
		private static int[] raceReserve(Governor g, Client[] cs, long est) {
			int n = cs.length;
			int[] out = new int[1 + n];
			java.util.concurrent.CyclicBarrier bar = new java.util.concurrent.CyclicBarrier(n);
			Thread[] ts = new Thread[n];
			for (int i = 0; i < n; i++) {
				int k = i;
				ts[i] = new Thread(() -> {
					try {
						bar.await();
						if (g.tryReserveView(cs[k], false, est, "k" + k, new boolean[1]) == null) {
							out[1 + k] = 1;
						}
					}
					catch (Exception e) {
						out[1 + k] = -1;
					}
				});
				ts[i].start();
			}
			for (Thread t : ts) {
				try {
					t.join(30_000);
				}
				catch (InterruptedException e) {
					return out;
				}
			}
			for (int i = 0; i < n; i++) {
				out[0] += out[1 + i] == 1 ? 1 : 0;
			}
			return out;
		}

		/** A body that throws an Error is run again; the count is kept; the reserve is released. */
		private static void guardedRestarts() {
			Guarded.clear();
			int[] n = { 0 };
			Thread t = new Thread(() -> Guarded.loop("selfTestThread", () -> {
				if (++n[0] < 3) {
					throw new OutOfMemoryError("planted");
				}
			}));
			t.start();
			try {
				t.join(15_000);
			}
			catch (InterruptedException e) {
				return;
			}
			check("a guarded body that threw an OutOfMemoryError twice ran a third time and ended " +
				"(restarts " + Guarded.restartsOf("selfTestThread") + ", runs " + n[0] + ")",
				n[0] == 3 && Guarded.restartsOf("selfTestThread") == 2 && !t.isAlive());
			JsonObject st = Guarded.states().getAsJsonObject("selfTestThread");
			check("the liveness figure of a guarded thread: not alive, ended, 2 restarts, not stale",
				st != null && !st.get("alive").getAsBoolean() && st.get("ended").getAsBoolean() &&
					st.get("restarts").getAsInt() == 2 && !st.get("stale").getAsBoolean());
			Guarded.beat(1); // not on a guarded thread: a no-op
			check("a fault can only be planted on a guarded thread that exists",
				!Guarded.inject("noSuchThread", "runtime"));
			Guarded.clear();
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

		/** Commands that are long on every protocol. */
		private static final List<String> LONG = List.of("analyze", "import", "script");
		/** Commands that are long on protocol 2 and maint on protocol 3 (D16, gate 2). */
		private static final List<String> MAINT = List.of("save", "fork_project", "refresh",
			"reopen", "promote_overlay");
		private static final List<String> QUICK = List.of("list", "functions", "decompile",
			"rename", "comment", "open_program", "switch", "open_project");
		private static final List<String> NONE = List.of("ping", "hello", "status", "cancel",
			"shutdown", "projects", "programs", "info", "close_project", "close_program", "edit",
			"journal", "discard_edits", "project", "overlays", "apply_overlay", "drop_overlay",
			"health", "nosuchcommand", "");

		private static Scheduler.Lane laneOf(String cmd, JsonObject req, boolean v3) {
			return Scheduler.laneOf(cmd, req, v3);
		}

		private static Client v3Client(int id) {
			Client x = new Client(id, "selftest", false, null);
			x.negotiate(obj("{\"protocol\":3}"));
			return x;
		}

		private static void lanes() {
			boolean v2same = true;
			boolean v3same = true;
			JsonObject quickHint = Json.of("lane", "quick", "timeout", 30);
			for (boolean v3 : new boolean[] { false, true }) {
				for (JsonObject req : new JsonObject[] { new JsonObject(), quickHint }) {
					boolean ok = true;
					for (String cmd : LONG) {
						// a script with lane:"quick" is quick on protocol 3 only
						boolean hint = cmd.equals("script") && req == quickHint && v3;
						ok &= laneOf(cmd, req, v3) ==
							(hint ? Scheduler.Lane.QUICK : Scheduler.Lane.LONG);
					}
					for (String cmd : MAINT) {
						ok &= laneOf(cmd, req, v3) ==
							(v3 ? Scheduler.Lane.MAINT : Scheduler.Lane.LONG);
					}
					for (String cmd : QUICK) {
						ok &= laneOf(cmd, req, v3) == Scheduler.Lane.QUICK;
					}
					for (String cmd : NONE) {
						ok &= laneOf(cmd, req, v3) == null;
					}
					if (v3) {
						v3same &= ok;
					}
					else {
						v2same &= ok;
					}
				}
			}
			check("laneOf(cmd, req, v3) on protocol 2 is hydra.3's lane for every command, with " +
				"and without a lane hint", v2same);
			check("laneOf on protocol 3: save, fork_project, refresh, reopen and promote_overlay " +
				"are maint; a script is quick only with lane:\"quick\"", v3same);
			String[] refused = { "{\"lane\":\"quick\"}", "{\"lane\":\"quick\",\"timeout\":0}",
				"{\"lane\":\"quick\",\"timeout\":121}", "{\"lane\":\"quick\",\"timeout\":\"9\"}",
				"{\"lane\":\"fast\",\"timeout\":9}", "{\"lane\":5,\"timeout\":9}" };
			boolean notes = true;
			for (String r : refused) {
				Scheduler.Decision d = Scheduler.decide("script", obj(r), true);
				notes &= d.lane() == Scheduler.Lane.LONG && d.note() != null;
			}
			Scheduler.Decision longHint =
				Scheduler.decide("script", Json.of("lane", "long", "timeout", 9), true);
			Scheduler.Decision absent = Scheduler.decide("script", new JsonObject(), true);
			Scheduler.Decision v2hint = Scheduler.decide("script", quickHint, false);
			check("a refused lane hint stays long and says why; long and absent say nothing; " +
				"protocol 2 never sees a note", notes && longHint.note() == null &&
					absent.note() == null && v2hint.note() == null &&
					v2hint.lane() == Scheduler.Lane.LONG);
			check("the long default is max(8, CPUs) and the caps are quick max(1, n/2), long " +
				"max(1, n-1), maint 1",
				Scheduler.defaultLongSlots(2) == 8 && Scheduler.defaultLongSlots(24) == 24 &&
					Scheduler.defaultCap(Scheduler.Lane.QUICK, 24) == 12 &&
					Scheduler.defaultCap(Scheduler.Lane.LONG, 8) == 7 &&
					Scheduler.defaultCap(Scheduler.Lane.LONG, 1) == 1 &&
					Scheduler.defaultCap(Scheduler.Lane.MAINT, 4) == 1);
			Scheduler s = new Scheduler(3, 2, 4);
			String empty =
				"{\"quick\":{\"slots\":3,\"inUse\":0,\"queued\":0,\"running\":[],\"waiting\":[]," +
					"\"admitted\":0,\"everQueued\":0,\"backgroundQueued\":0},\"long\":{\"slots\":2," +
					"\"inUse\":0,\"queued\":0,\"running\":[],\"waiting\":[],\"admitted\":0," +
					"\"everQueued\":0,\"backgroundQueued\":0}}";
			check("describe(false) of an idle scheduler is hydra.3's object (no maint lane)",
				Json.GSON.toJson(s.describe(false)).equals(empty));
			JsonObject idle3 = s.describe(true);
			check("describe(true) adds the maint lane and the v3 figures",
				List.of("quick", "long", "maint").equals(new ArrayList<>(idle3.keySet())) &&
					idle3.getAsJsonObject("maint").get("slots").getAsInt() == 4 &&
					idle3.getAsJsonObject("long").has("perKeyCap") &&
					!idle3.getAsJsonObject("long").get("starving").getAsBoolean());
			Client c = new Client(1, "selftest", false, null);
			try (Scheduler.Ticket t = s.admit(c, "save", new JsonObject(), null, 100)) {
				JsonObject d = s.describe(false);
				check("a protocol 2 save holds a long slot, as on hydra.3",
					d.getAsJsonObject("long").get("inUse").getAsInt() == 1 &&
						d.getAsJsonObject("quick").get("inUse").getAsInt() == 0 && !d.has("maint"));
			}
			try (Scheduler.Ticket t = s.admit(v3Client(2), "save", new JsonObject(), null, 100)) {
				JsonObject d3 = s.describe(true);
				check("a protocol 3 save holds a maint slot and no long slot",
					d3.getAsJsonObject("maint").getAsJsonArray("running").size() == 1 &&
						d3.getAsJsonObject("long").get("inUse").getAsInt() == 0);
			}
			capsAndQueue();
			yieldAndReacquire();
		}

		private static void sleepMs(long ms) {
			try {
				Thread.sleep(ms);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}

		/** Waits (at most 5 s) until a lane shows at least {@code n} queued requests. */
		private static void waitQueued(Scheduler s, String lane, int n) {
			long end = System.nanoTime() + 5_000_000_000L;
			while (System.nanoTime() < end &&
				s.describe(true).getAsJsonObject(lane).get("queued").getAsInt() < n) {
				sleepMs(5);
			}
		}

		private static void asyncAdmit(Scheduler s, Client c, String cmd, JsonObject req,
				List<Scheduler.Ticket> got, List<String> errors) {
			Thread th = new Thread(() -> {
				try {
					Scheduler.Ticket t = s.admit(c, cmd, req, null, 10_000);
					synchronized (got) {
						got.add(t);
					}
				}
				catch (SessionException e) {
					synchronized (errors) {
						errors.add(e.code() + ":" + e.getMessage());
					}
				}
			}, "selftest-admit");
			th.setDaemon(true);
			th.start();
		}

		private static void waitGot(List<Scheduler.Ticket> got, int n) {
			long end = System.nanoTime() + 5_000_000_000L;
			while (System.nanoTime() < end) {
				synchronized (got) {
					if (got.size() >= n) {
						return;
					}
				}
				sleepMs(5);
			}
		}

		/**
		 * The work-conserving per-key cap (3.5): maint with 4 slots and cap 1, two keys that each
		 * run one request and queue another, while two other keys fill the rest: when the others
		 * finish both queued requests run and no slot idles. A key at its cap waits while another
		 * key under its cap waits.
		 */
		private static void capsAndQueue() {
			Scheduler s = new Scheduler(8, 8, 4);
			JsonObject none = new JsonObject();
			List<Scheduler.Ticket> held = new ArrayList<>();
			for (int i = 0; i < 4; i++) {
				held.add(s.admit(v3Client(10 + i), "save", none, null, 1000));
			}
			List<Scheduler.Ticket> got = new ArrayList<>();
			List<String> errors = new ArrayList<>();
			asyncAdmit(s, held.get(0).client, "save", none, got, errors);
			waitQueued(s, "maint", 1);
			asyncAdmit(s, held.get(1).client, "save", none, got, errors);
			waitQueued(s, "maint", 2);
			held.get(2).close();
			held.get(3).close();
			waitGot(got, 2);
			JsonObject m = s.describe(true).getAsJsonObject("maint");
			check("per_key_cap_conserving: 4 maint slots, cap 1, two keys that each run one and " +
				"queue another: when the others finish both queued requests run, no slot idles",
				m.get("inUse").getAsInt() == 4 && m.get("queued").getAsInt() == 0 &&
					m.get("perKeyCap").getAsInt() == 1 && errors.isEmpty());
			held.get(0).close();
			held.get(1).close();
			synchronized (got) {
				got.forEach(Scheduler.Ticket::close);
			}

			// the cap holds while another key under its cap waits
			Scheduler q = new Scheduler(2, 2, 2);
			Client a = v3Client(20);
			Client b = v3Client(21);
			Scheduler.Ticket a1 = q.admit(a, "save", none, null, 1000);
			Scheduler.Ticket a2 = q.admit(a, "save", none, null, 1000);
			List<Scheduler.Ticket> gotQ = new ArrayList<>();
			List<String> errQ = new ArrayList<>();
			asyncAdmit(q, a, "save", none, gotQ, errQ);
			waitQueued(q, "maint", 1);
			asyncAdmit(q, b, "save", none, gotQ, errQ);
			waitQueued(q, "maint", 2);
			a1.close();
			waitGot(gotQ, 1);
			String who;
			synchronized (gotQ) {
				who = gotQ.isEmpty() ? "nobody" : Integer.toString(gotQ.get(0).client.id);
			}
			check("a key at its cap waits while another key under its cap waits: the freed " +
				"slot goes to the other key", who.equals("21"));
			a2.close();
			waitGot(gotQ, 2);
			synchronized (gotQ) {
				gotQ.forEach(Scheduler.Ticket::close);
			}

			// the fair key: a label makes a protocol 3 request its own key; protocol 2 keeps the id
			Scheduler k = new Scheduler(4, 4, 4);
			Client p3 = v3Client(30);
			Client p2 = new Client(31, "selftest", false, null);
			Scheduler.Ticket plain = k.admit(p3, "save", none, null, 1000);
			Caller.enter(p3, new Caller.Identity("agent-a", "h", true));
			Scheduler.Ticket labelled = k.admit(p3, "save", none, null, 1000);
			Caller.leave();
			Caller.enter(p2, new Caller.Identity("agent-a", "h", true));
			Scheduler.Ticket v2labelled = k.admit(p2, "decompile", none, null, 1000);
			Caller.leave();
			check("the fair key of a protocol 3 request is the connection plus its label (an " +
				"unlabelled request shares the connection's); a protocol 2 request keeps the " +
				"connection id even when it is labelled",
				plain.key.equals("30") && labelled.key.equals("30/agent-a\0h") &&
					v2labelled.key.equals("31"));
			plain.close();
			labelled.close();
			v2labelled.close();
		}

		private static void yieldAndReacquire() {
			Scheduler s = new Scheduler(1, 1, 1);
			Client c = new Client(40, "selftest", false, null);
			Client other = new Client(41, "selftest", false, null);
			Scheduler.Ticket t = s.admit(c, "decompile", new JsonObject(), null, 100);
			int[] before = s.recorded(Scheduler.Lane.QUICK);
			t.yieldSlot();
			int[] yielded = s.recorded(Scheduler.Lane.QUICK);
			Scheduler.Ticket o = s.admit(other, "decompile", new JsonObject(), null, 100);
			boolean busy = false;
			try {
				t.reacquire(null, 50);
			}
			catch (SessionException e) {
				busy = e.code().equals(SessionException.BUSY);
			}
			o.close();
			t.reacquire(null, 1000);
			boolean held = s.describe(false).getAsJsonObject("quick").get("inUse").getAsInt() == 1;
			t.close();
			int[] closed = s.recorded(Scheduler.Lane.QUICK);
			check("yieldSlot gives the slot to another key, reacquire waits for one again " +
				"(busy while it is taken) and close releases it once",
				busy && held &&
					s.describe(false).getAsJsonObject("quick").get("inUse").getAsInt() == 0);
			// E3c (the E3a review nit): a yield is not a completion and records no hold time; only the
			// end of the request does (the other key's close above is the one completion before it)
			check("yieldSlot records neither a hold time nor a completion; the final close records one",
				yielded[0] == before[0] && yielded[1] == before[1] && closed[0] == yielded[0] + 2 &&
					closed[1] == yielded[1] + 2);
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
			// the generic checks of Requests.registerPreflight (the Scheduler registers them once)
			int generic = Preflight.count("selftestNoChecks");
			check("the scheduler registered the generic checks under *", generic >= 1);
			Preflight.register(Preflight.ALL, (cmd, req) -> order.add("*" + cmd));
			Preflight.register("selftest", (cmd, req) -> order.add("own"));
			Preflight.run("selftest", new JsonObject());
			Preflight.run("other", new JsonObject());
			check("Preflight runs the * checks, then the command's, in order; a command without " +
				"its own runs only the *", order.equals(List.of("*selftest", "own", "*other")) &&
					Preflight.count("selftest") == generic + 2 && Preflight.count("other") == generic + 1);
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

		private static void cancelHooks() {
			RequestMonitor m = new RequestMonitor(null, null);
			int[] ran = new int[2];
			m.addCancelHook(() -> ran[0]++);
			m.addCancelHook(() -> {
				throw new IllegalStateException("a hook that throws must not stop the others");
			});
			m.addCancelHook(() -> ran[1]++);
			check("a cancel hook has not run before the cancel", ran[0] == 0 && ran[1] == 0);
			m.cancel();
			m.cancel();
			m.addCancelHook(() -> ran[0] += 10);
			check("every cancel hook runs once on cancel, a throwing one does not stop the " +
				"others, and a hook added after the cancel runs at once",
				ran[0] == 11 && ran[1] == 1 && m.isCancelled());
			// two threads cancelling together (the timeout timer and a client's cancel) and a hook
			// added while the cancel runs: every hook runs exactly once
			int rounds = 300;
			java.util.concurrent.atomic.AtomicInteger twice = new java.util.concurrent.atomic.AtomicInteger();
			for (int i = 0; i < rounds; i++) {
				RequestMonitor r = new RequestMonitor(null, null);
				java.util.concurrent.atomic.AtomicInteger n = new java.util.concurrent.atomic.AtomicInteger();
				java.util.concurrent.atomic.AtomicInteger late = new java.util.concurrent.atomic.AtomicInteger();
				for (int k = 0; k < 4; k++) {
					r.addCancelHook(n::incrementAndGet);
				}
				java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
				Thread[] ts = new Thread[3];
				for (int k = 0; k < ts.length; k++) {
					final boolean adder = k == 2;
					ts[k] = new Thread(() -> {
						try {
							go.await();
						}
						catch (InterruptedException e) {
							return;
						}
						if (adder) {
							r.addCancelHook(late::incrementAndGet);
						}
						else {
							r.cancel();
						}
					});
					ts[k].start();
				}
				go.countDown();
				for (Thread t : ts) {
					try {
						t.join();
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}
				if (n.get() != 4 || late.get() != 1) {
					twice.incrementAndGet();
				}
			}
			check("under concurrent cancels and a hook added meanwhile, every hook ran exactly " +
				"once (" + rounds + " rounds)", twice.get() == 0);
		}

		/**
		 * The waiter cap (D39) on the plain locks of a project (slot transition, structure change):
		 * with the lock held, a protocol 3 caller beyond {@code max(2, slots / 4)} waiters is
		 * answered QUEUE_FULL at once, the waiters keep their place and get the lock, a protocol 2
		 * caller is never capped, and the counter returns to 0.
		 */
		private static void waiterCaps() {
			java.util.concurrent.locks.ReentrantLock lock = new java.util.concurrent.locks.ReentrantLock();
			java.util.concurrent.atomic.AtomicInteger waiters = new java.util.concurrent.atomic.AtomicInteger();
			Client v3 = new Client(60, "selftest", false, null);
			v3.negotiate(obj("{\"protocol\":3}"));
			Client v2 = new Client(61, "selftest", false, null);
			java.util.concurrent.CountDownLatch held = new java.util.concurrent.CountDownLatch(1);
			java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
			Thread holder = new Thread(() -> {
				lock.lock();
				held.countDown();
				try {
					release.await();
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				finally {
					lock.unlock();
				}
			});
			holder.start();
			Waits.Outcome[] got = new Waits.Outcome[2];
			Thread[] ws = new Thread[2];
			try {
				held.await();
				for (int i = 0; i < ws.length; i++) {
					final int k = i;
					ws[i] = new Thread(() -> {
						Caller.enter(v3, new Caller.Identity("w" + k, "h", true),
							new RequestMonitor(null, null));
						try {
							got[k] = Waits.lock(lock, 20000, waiters);
							if (got[k] == Waits.Outcome.GOT) {
								lock.unlock();
							}
						}
						finally {
							Caller.leave();
						}
					});
					ws[i].start();
				}
				long end = System.currentTimeMillis() + 10000;
				while (lock.getQueueLength() < 2 && System.currentTimeMillis() < end) {
					sleepMs(10);
				}
				check("two protocol 3 requests queue for a held lock (the cap is 2)",
					lock.getQueueLength() == 2 && waiters.get() == 2);
				Caller.enter(v3, new Caller.Identity("w2", "h", true), new RequestMonitor(null, null));
				long t0 = System.nanoTime();
				Waits.Outcome third;
				try {
					third = Waits.lock(lock, 20000, waiters);
				}
				finally {
					Caller.leave();
				}
				long ms = (System.nanoTime() - t0) / 1_000_000L;
				check("the third protocol 3 waiter is answered QUEUE_FULL at once (" + ms + " ms) " +
					"and is not left counted", third == Waits.Outcome.QUEUE_FULL && ms < 1000 &&
						waiters.get() == 2 && lock.getQueueLength() == 2);
				Caller.enter(v2, new Caller.Identity("w3", "h", true), new RequestMonitor(null, null));
				Waits.Outcome old;
				try {
					old = Waits.lock(lock, 150, waiters);
				}
				finally {
					Caller.leave();
				}
				check("a protocol 2 waiter is never capped: it waits its time and times out",
					old == Waits.Outcome.TIMED_OUT);
				release.countDown();
				for (Thread t : ws) {
					t.join(20000);
				}
				holder.join(20000);
				check("the two waiters that queued get the lock when it is released, and the " +
					"counter returns to 0", got[0] == Waits.Outcome.GOT && got[1] == Waits.Outcome.GOT &&
						waiters.get() == 0 && !lock.isLocked());
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				check("the waiter cap check was interrupted", false);
			}
			finally {
				release.countDown();
			}
		}

		/**
		 * The close of an idle project and a view change of it (a {@code refresh}, the reopening of a
		 * read-only view as writable) exclude each other (E3c). A thread plays the view change the way
		 * {@code ProjectCommands.makeWritable} and {@code refresh} run it: it holds the project's
		 * {@code structure} lock, checks {@code closed}, and then (held by a latch, the slow
		 * {@code SessionProject.open}) would install its new view. Meanwhile the reap's
		 * {@code closeIdle} runs. Before the fix the close ran in that window and the new view was
		 * installed on a closed project: nothing ever closed it and the daemon kept the project's OS
		 * lock.
		 */
		private static void closeVsViewChange() {
			ProjectRegistry reg = new ProjectRegistry();
			ProjectRegistry.Slot sl = reg.slot("selftest:close-vs-view-change");
			ProjectEntry p = new ProjectEntry("p1", null, sl.canonical, null, 0);
			sl.entry = p;
			sl.state = ProjectRegistry.State.OPEN;
			java.util.concurrent.CountDownLatch checked = new java.util.concurrent.CountDownLatch(1);
			java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
			java.util.concurrent.atomic.AtomicBoolean onClosed =
				new java.util.concurrent.atomic.AtomicBoolean();
			java.util.concurrent.atomic.AtomicInteger closes =
				new java.util.concurrent.atomic.AtomicInteger();
			java.util.function.Consumer<ProjectEntry> closer = x -> {
				closes.incrementAndGet();
				x.closed = true;
			};
			Thread change = new Thread(() -> {
				p.structure.lock();
				try {
					if (p.closed) {
						return;
					}
					checked.countDown();
					go.await(10, java.util.concurrent.TimeUnit.SECONDS);
					onClosed.set(p.closed); // the repoint would install its view now
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				finally {
					p.structure.unlock();
				}
			});
			change.start();
			try {
				boolean ready = checked.await(10, java.util.concurrent.TimeUnit.SECONDS);
				boolean during = reg.closeIdle(p, closer);
				go.countDown();
				change.join(10000);
				p.structure.lock();
				boolean ownThread;
				try {
					ownThread = reg.closeIdle(p, closer); // a view change of this very thread
				}
				finally {
					p.structure.unlock();
				}
				boolean after = reg.closeIdle(p, closer);
				check("a close of an idle project does not run while a view change of it (refresh, " +
					"writable reopen) holds its structure lock, and runs once after it",
					ready && !during && !onClosed.get() && !ownThread && after && closes.get() == 1 &&
						reg.current(sl.canonical) == null);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				check("the close versus view change check was interrupted", false);
			}
			finally {
				go.countDown();
			}
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
