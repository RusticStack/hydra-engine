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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;

import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.Msg;

/**
 * A long-lived headless Ghidra process that works like the window does: open a project, list
 * it, open and switch programs, query, edit, analyse, run scripts, save, and stay up for the next
 * command. {@code analyzeHeadless} is one command about one program file; this is a session.
 * <p>
 * Callers speak JSON lines (one request object per line, one response per line) on stdio and/or
 * on an authenticated loopback socket. See {@code Ghidra/Features/HeadlessSession/README.md}.
 * <p>
 * stdout is the protocol channel of the stdio client: it is claimed before Ghidra starts and
 * everything else (Ghidra's log, scripts' {@code System.out}) is sent to stderr.
 */
public class HeadlessSession implements GhidraLaunchable {

	private static final String USAGE = """
		usage: headlessSession [-project <file.gpr | dir>] [-writable]
		                       [-listen [127.0.0.1:]<port>] [-endpoint <file>] [-noStdio]
		                       [-idleTimeout <seconds>] [-scriptPath <dir>]...
		                       [-log <file>]
		  -project      open this project at start (a .gpr, its folder, or a parent with one)
		  -writable     open it writable (takes the project lock); default: read-only view
		  -listen       also serve clients on a loopback TCP port (0 picks one)
		  -endpoint     write {port, token, pid, ...} for socket clients to this file
		  -noStdio      do not serve stdin/stdout (daemon); requires -listen
		  -idleTimeout  with -noStdio: exit after this many seconds without clients
		  -scriptPath   an extra GhidraScript directory; repeat it, or quote a ';' list
		  -log          Ghidra application log file
		""";

	private final Object exitLock = new Object();
	private volatile Session session;
	private volatile Path endpointFile;

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

		HeadlessGhidraApplicationConfiguration config =
			new HeadlessGhidraApplicationConfiguration();
		if (o.log != null) {
			config.setApplicationLogFile(new File(o.log));
		}
		Application.initializeApplication(layout, config);
		GhidraScriptUtil.acquireBundleHostReference()
				.add(o.scriptDirs.stream().map(d -> new ResourceFile(new File(d))).toList(), true,
					true);

		session = new Session();
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
			if (o.endpoint != null) {
				writeEndpoint(Path.of(o.endpoint), server.getLocalPort(), token, o);
			}
			startAcceptor(server, token);
		}

		JsonObject ready = session.info();
		ready.addProperty("event", "ready");
		ready.addProperty("startupMs", (System.nanoTime() - t0) / 1_000_000);
		if (token != null && o.stdio) {
			ready.addProperty("token", token); // the launcher's own pipe
		}
		Msg.info(this, "headless session ready: " + Json.GSON.toJson(session.info()));

		if (stdio != null) {
			stdio.send(ready);
			stdio.run(); // returns at end of stdin: the launcher is gone
			exit();
			return;
		}
		idleLoop(o.idleTimeoutSeconds);
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
		JsonObject e = Json.of("protocol", Session.PROTOCOL_VERSION, "pid",
			ProcessHandle.current().pid(), "host", o.listenHost.getHostAddress(), "port", port,
			"token", token, "project", o.project, "writable", o.writable, "ghidra",
			Application.getApplicationVersion(), "started", System.currentTimeMillis());
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

	private void removeEndpoint() {
		Path f = endpointFile;
		endpointFile = null;
		if (f != null) {
			try {
				Files.deleteIfExists(f);
			}
			catch (IOException e) {
				// best effort
			}
		}
	}

	private static final class Options {
		String project;
		boolean writable;
		boolean stdio = true;
		InetAddress listenHost;
		int listenPort = -1;
		String endpoint;
		long idleTimeoutSeconds;
		List<String> scriptDirs = new ArrayList<>();
		String log;

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
					case "-idleTimeout" -> o.idleTimeoutSeconds =
						Long.parseLong(value(args, ++i, a));
					case "-scriptPath" -> {
						for (String d : value(args, ++i, a).split(";")) {
							if (!d.isBlank()) {
								o.scriptDirs.add(d.trim());
							}
						}
					}
					case "-log" -> o.log = value(args, ++i, a);
					default -> throw new IllegalArgumentException("unknown option: " + a);
				}
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
	}
}
