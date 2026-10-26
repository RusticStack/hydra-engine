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
		                       [-maxQuick <n>] [-maxLong <n>] [-scriptPath <dir>]... [-log <file>]
		                       [-upgradeCache <dir>] [-forkCopyLimitMb <n>]
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
		  -scriptPath   an extra GhidraScript directory; repeat it, or give a list separated by
		                the platform's path separator
		  -log          Ghidra application log file
		  -upgradeCache serve read-only opens of programs in an older database format from an
		                upgraded copy of their project kept in this directory (default: none)
		  -forkCopyLimitMb  fork_project mode auto refuses a full (not block-cloned) copy larger
		                than this (default 2048)
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
		try {
			o = Options.parse(args);
		}
		catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			System.err.print(USAGE);
			System.exit(2);
			return;
		}

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
		Scheduler scheduler = new Scheduler(o.maxQuick > 0 ? o.maxQuick : cpus,
			o.maxLong > 0 ? o.maxLong : Math.max(2, cpus / 4));
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

		JsonObject ready = session.info();
		ready.addProperty("event", "ready");
		ready.addProperty("startupMs", readyMs);
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
		JsonObject e = Json.of("protocol", Session.PROTOCOL_VERSION, "minClient",
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
		List<String> scriptDirs = new ArrayList<>();
		String log;
		String upgradeCache;
		long forkCopyLimitMb = -1;

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
}
