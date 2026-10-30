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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

import com.google.gson.*;

import ghidra.util.Msg;
import ghidra.util.cpu.HydraCpu;

/**
 * One client's JSON-lines channel (stdio or a loopback socket).
 * <p>
 * The reader thread parses each line. {@code ping}, {@code status} and {@code cancel} are
 * answered at once on that thread. Every other request runs on this connection's ordered lane,
 * so one client's requests run in the order sent while other clients run in parallel; a request
 * with {@code "parallel":true} runs at once on its own thread instead (for clients that
 * multiplex several callers over one connection). Every request is registered as soon as it is
 * read, so {@code cancel} reaches it while it still waits its turn. Responses carry the request's
 * {@code id}; {@code progress} events carry it too.
 * <p>
 * With the setting {@code orderPerScope} (default off, PROTOCOL-3.md 8.18) a protocol 3 connection
 * keeps one ordered lane per caller scope instead of one for the whole connection: the requests of
 * one {@code client}/{@code harness} label still run in the order sent, while the requests of
 * other labels run beside them. Unlabelled requests keep the connection's own lane.
 */
final class Connection {

	static final int MAX_LINE_BYTES = 64 * 1024 * 1024;

	private final Session session;
	private final InputStream in;
	private final OutputStream out;
	private final String token; // null: no authentication needed (stdio)
	private final Client client;
	private final ExecutorService worker;
	private final ThreadPoolExecutor parallel;
	static final int MAX_PARALLEL = 32;
	private volatile boolean open = true;
	private final Runnable onShutdown;
	/** The bounded outbound queue and its writer thread (BP23, 3.10). */
	private final Outbound outbound;
	/** Set when this connection's request is the {@code shutdown} that ends the process. */
	private volatile boolean exiting;
	/** What a protocol 3 connection dispatches in parallel unless the request says {@code ordered} (BP15). */
	private static final java.util.Set<String> READ_CLASS = java.util.Set.of("info", "functions",
		"decompile", "list", "project", "projects", "programs", "journal", "overlays");
	/**
	 * The ordered lanes of the labelled scopes (setting {@code orderPerScope}): the requests of a
	 * scope that wait for the one drainer of that scope. A scope has an entry while its drainer runs.
	 */
	private final Map<String, ArrayDeque<Runnable>> scoped = new HashMap<>();
	/** Set when the release of 3.5 reaches {@code shutdownNow}: the scoped lanes stop too. */
	private volatile boolean abandoned;

	Connection(Session session, InputStream in, OutputStream out, String transport,
			boolean launcher, String token, Runnable onShutdown) {
		this.session = session;
		this.in = in;
		this.out = out;
		this.token = token;
		this.onShutdown = onShutdown;
		this.client = session.connect(transport, launcher, this::send);
		this.client.authenticated = token == null;
		// The ordered lane: at most one thread, FIFO, so one client's requests still run in the
		// order sent. Its thread ends after laneIdleMs without work (it used to live as long as
		// the connection), so an idle client holds no lane thread (Goal 2, async I/O).
		ThreadPoolExecutor lane = new ThreadPoolExecutor(1, 1, laneIdleMs(), TimeUnit.MILLISECONDS,
			new LinkedBlockingQueue<>(), r -> {
				// request handling is latency-critical: on a hybrid CPU the profile may prefer P-cores
				Thread t = new Thread(HydraCpu.placed(HydraCpu.Role.LATENCY, r),
					"session-" + client.label().replace(' ', '-'));
				t.setDaemon(true);
				return t;
			});
		lane.allowCoreThreadTimeOut(true);
		this.worker = lane;
		this.parallel = new ThreadPoolExecutor(0, MAX_PARALLEL, 30, TimeUnit.SECONDS,
			new SynchronousQueue<>(), r -> {
				Thread t = new Thread(HydraCpu.placed(HydraCpu.Role.LATENCY, r),
					"session-" + client.label().replace(' ', '-') + "-p");
				t.setDaemon(true);
				return t;
			});
		this.outbound = new Outbound(virtualIo() && "socket".equals(transport));
	}

	/**
	 * Whether a socket connection's reader and writer run on virtual threads ({@code -set
	 * connectionThreads=virtual}, the default; {@code platform} restores one platform thread
	 * each). They only wait on the socket and on monitors (which no longer pin a carrier since
	 * JDK 24, JEP 491), so an idle client costs no platform thread. Requests never run on them
	 * except the inline ones ({@code ping}, {@code status}, {@code cancel}, {@code health}) and
	 * the authenticating {@code hello}, as before. The release of a client that left (closing its
	 * programs and projects, Ghidra DB code) runs on a platform thread of its own, not on the
	 * virtual reader (see {@link #run()}).
	 */
	static boolean virtualIo() {
		String v = Settings.string("connectionThreads", "virtual").trim();
		return switch (v) {
			case "virtual" -> true;
			case "platform" -> false;
			default -> throw new IllegalArgumentException(
				"-set connectionThreads=" + v + ": not virtual or platform");
		};
	}

	/**
	 * Start-up validation of {@code connectionThreads} and {@code laneIdleMs}: a bad value is a
	 * usage error at launch, not a failure of every later socket connection.
	 *
	 * @throws IllegalArgumentException with a usage message
	 */
	static void validateSettings() {
		virtualIo();
		laneIdleMs();
	}

	/** How long an idle ordered lane keeps its thread ({@code -set laneIdleMs}, default 10 s). */
	static long laneIdleMs() {
		return Math.max(1, Settings.integer("laneIdleMs", 10_000));
	}

	/** A thread for a connection's socket I/O: virtual unless {@link #virtualIo()} says not. */
	static Thread ioThread(String name, Runnable body) {
		Thread t = virtualIo() ? Thread.ofVirtual().name(name).unstarted(body)
				: Thread.ofPlatform().name(name).daemon(true).unstarted(body);
		t.start();
		return t;
	}

	Client client() {
		return client;
	}

	/** Reads until end of input, then releases what the client held. */
	void run() {
		synchronized (readerGuard) {
			reader = Thread.currentThread();
		}
		try {
			byte[] line;
			while (open && (line = readLine()) != null) {
				handleLine(new String(line, StandardCharsets.UTF_8));
			}
		}
		catch (IOException e) {
			if (open) {
				Msg.info(this, client.label() + ": " + e.getMessage());
			}
		}
		finally {
			synchronized (readerGuard) {
				reader = null; // close() no longer interrupts this thread
				Thread.interrupted(); // an interrupt from close() only meant: stop reading
			}
			// The client is gone from the moment its input ended, as on the platform reader: a
			// shutdown sent right after this client closed must not count it as connected while
			// the release below is still being handed to its own thread.
			open = false;
			client.leaving = true;
			if (Thread.currentThread().isVirtual()) {
				// the release closes programs and projects (Ghidra DB, lock files) and waits up to
				// cleanupGraceS + abandonWaitS: it runs on a platform thread, so the virtual
				// reader only ever does socket I/O and many clients leaving at once do not hold
				// the carriers of the virtual scheduler
				Thread r = Thread.ofPlatform().name("session-" +
					client.label().replace(' ', '-') + "-release").daemon(true).start(this::release);
				boolean interrupted = false;
				while (true) {
					try {
						r.join();
						break;
					}
					catch (InterruptedException e) {
						interrupted = true;
					}
				}
				if (interrupted) {
					Thread.currentThread().interrupt();
				}
			}
			else {
				release();
			}
		}
	}

	/** Releases what the client held (3.5): cancel, bounded waits, disconnect, drain the writer. */
	private void release() {
		open = false;
		client.leaving = true;
		// cancel first: the worker must not finish a long request for a client that is gone;
		// a request parked in a lock wait is interrupted by its cancel (Waits, 3.5)
		client.running.values().forEach(RequestMonitor::cancel);
		worker.shutdown();
		parallel.shutdown();
		// bounded release (3.5): cancel, wait cleanupGraceS, shutdownNow (interrupts lock waits
		// and I/O, not busy loops), wait abandonWaitS, then disconnect regardless
		try {
			if (exiting) {
				// the process is going down on this connection's own thread (shutdown): that
				// thread must not be interrupted, it is the one closing the session. Only
				// the process-ending shutdown request gets here and its own thread then
				// ends the process, so the long bound is never reached in practice.
				awaitBoth(3_600_000L);
			}
			else if (!awaitBoth(Session.cleanupGraceMs())) {
				Msg.warn(this, client.label() + ": " + client.running.size() +
					" request(s) still run " + Session.cleanupGraceMs() / 1000 +
					" s after the connection closed; interrupting them");
				abandoned = true;
				worker.shutdownNow();
				parallel.shutdownNow();
				if (!awaitBoth(Session.abandonWaitMs())) {
					Msg.warn(this, client.label() + ": " + client.running.size() +
						" request(s) ignore cancel and interrupt; releasing the client anyway " +
						"(the program locks they hold are flagged abandoned)");
				}
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		session.disconnect(client);
		outbound.finish();
		if (HydraCpu.profile().placeThreads()) {
			// the placements so far (cumulative), for cpu_bench.py and dt_cpu.py
			Msg.info(this, "cpu: " + HydraCpu.report());
		}
	}

	private boolean awaitBoth(long ms) throws InterruptedException {
		long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms);
		boolean a = worker.awaitTermination(ms, TimeUnit.MILLISECONDS);
		long left = Math.max(0, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime()));
		boolean b = parallel.awaitTermination(left, TimeUnit.MILLISECONDS);
		return a && b;
	}

	private void handleLine(String text) {
		if (text.isBlank()) {
			return;
		}
		JsonObject req;
		try {
			JsonElement el = JsonParser.parseString(text);
			if (!el.isJsonObject()) {
				throw new JsonParseException("a request is a JSON object");
			}
			req = el.getAsJsonObject();
		}
		catch (JsonParseException e) {
			send(error(null, new SessionException(SessionException.BAD_REQUEST,
				"not a JSON object: " + e.getMessage()), 0));
			return;
		}
		JsonElement id = req.get("id");
		String cmd = req.has("cmd") && req.get("cmd").isJsonPrimitive()
				? req.get("cmd").getAsString()
				: "";
		if (!client.authenticated) {
			authenticate(req, id, cmd);
			return;
		}
		if (cmd.equals("hello")) {
			// The first hello fixes the protocol of the connection, here on the reader thread and
			// before the next line is read, so every later request and reply is gated against a
			// value that is already final. A later hello changes nothing (PROTOCOL-3.md 3.1).
			client.negotiate(req);
		}
		Caller.Identity who;
		try {
			who = Caller.of(client, req);
		}
		catch (SessionException e) {
			send(error(id, e, 0));
			return;
		}
		if (Session.isInline(cmd)) {
			RequestMonitor im = new RequestMonitor(id, this::send);
			im.describeAs(cmd, who);
			respond(req, id, cmd, im);
			return;
		}
		String key = id == null ? null : id.toString();
		RequestMonitor m = new RequestMonitor(id, this::send);
		m.describeAs(cmd, who);
		if (req.has("artifact") && req.get("artifact").isJsonPrimitive()) {
			m.artifact(req.get("artifact").getAsString());
		}
		if (key != null && client.running.putIfAbsent(key, m) != null) {
			send(error(id, new SessionException(SessionException.BAD_REQUEST,
				"request id " + key + " is still running; use a new id"), 0));
			return;
		}
		boolean par;
		boolean implicit = false; // a read-class command of a v3 connection (BP15)
		try {
			par = Json.bool(req, "parallel", false);
			if (!par && client.v3() && READ_CLASS.contains(cmd) &&
				!Json.bool(req, "ordered", false)) {
				par = true;
				implicit = true;
			}
		}
		catch (SessionException e) {
			if (key != null) {
				client.running.remove(key, m);
			}
			send(error(id, e, 0));
			return;
		}
		// a labelled request of a v3 connection gets its scope's own ordered lane (orderPerScope)
		String scope = !par && client.v3() && Settings.bool("orderPerScope", false)
				? who.scope()
				: null;
		try {
			if (scope != null) {
				executeScoped(scope, () -> respond(req, id, cmd, m));
			}
			else {
				(par ? parallel : worker).execute(() -> respond(req, id, cmd, m));
			}
		}
		catch (RejectedExecutionException e) {
			if (implicit && !parallel.isShutdown()) {
				// all MAX_PARALLEL threads are busy: an implicit request waits its turn instead
				try {
					worker.execute(() -> respond(req, id, cmd, m));
					return;
				}
				catch (RejectedExecutionException again) {
					// closing: answered below
				}
			}
			if (key != null) {
				client.running.remove(key, m);
			}
			send(error(id, par
					? new SessionException(SessionException.BUSY,
						"this client already runs " + MAX_PARALLEL + " parallel requests")
					: new SessionException(SessionException.CONFLICT, "connection closing"),
				0));
		}
	}

	/**
	 * Runs {@code r} after every earlier request of {@code scope} (setting {@code orderPerScope}).
	 * One drainer per scope takes the scope's requests in arrival order, on a thread of the
	 * parallel pool, or on the connection's own lane when all {@link #MAX_PARALLEL} are busy (the
	 * order of the scope is kept either way: the scope never has two drainers).
	 *
	 * @throws RejectedExecutionException when the connection is closing
	 */
	private void executeScoped(String scope, Runnable r) {
		synchronized (scoped) {
			ArrayDeque<Runnable> q = scoped.get(scope);
			if (q != null) {
				q.add(r); // the scope's drainer runs: it takes r in turn
				return;
			}
			q = new ArrayDeque<>();
			q.add(r);
			scoped.put(scope, q);
		}
		Runnable drain = () -> drainScope(scope);
		try {
			try {
				parallel.execute(drain);
			}
			catch (RejectedExecutionException e) {
				if (parallel.isShutdown()) {
					throw e;
				}
				worker.execute(drain);
			}
		}
		catch (RejectedExecutionException e) {
			synchronized (scoped) {
				scoped.remove(scope); // r is the only request of a scope that had no drainer
			}
			throw e;
		}
	}

	/**
	 * Runs the next request of a scope, then hands the scope's next turn back to the pools (the
	 * parallel pool first) instead of keeping this thread: a drainer that fell back to the
	 * connection's own lane gives it up after each request, so the connection's unlabelled ordered
	 * requests are not held behind a label that keeps sending. Only when both pools refuse (the
	 * connection is closing) does it drain the rest here. Stops after {@code shutdownNow}
	 * (abandoned), which drops the scope's queued requests the way it drops the pools' queues.
	 */
	private void drainScope(String scope) {
		while (true) {
			Runnable r;
			synchronized (scoped) {
				ArrayDeque<Runnable> q = scoped.get(scope);
				r = abandoned ? null : q.poll();
				if (r == null) {
					scoped.remove(scope);
					return;
				}
			}
			try {
				r.run();
			}
			catch (RuntimeException e) {
				// respond answers every failure itself; this keeps the scope's lane alive regardless
				Msg.error(this, client.label() + ": a request of a scoped lane failed", e);
			}
			synchronized (scoped) {
				if (abandoned || scoped.get(scope).isEmpty()) {
					scoped.remove(scope);
					return;
				}
			}
			Runnable next = () -> drainScope(scope);
			try {
				parallel.execute(next);
				return;
			}
			catch (RejectedExecutionException e) {
				try {
					worker.execute(next);
					return;
				}
				catch (RejectedExecutionException closing) {
					// both pools are shut down: drain the rest of the scope on this thread
				}
			}
		}
	}

	private void authenticate(JsonObject req, JsonElement id, String cmd) {
		String supplied = req.has("token") && req.get("token").isJsonPrimitive()
				? req.get("token").getAsString()
				: "";
		boolean ok = cmd.equals("hello") && MessageDigest.isEqual(
			supplied.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
		if (!ok) {
			send(error(id, new SessionException(SessionException.UNAUTHORIZED,
				"the first request must be {\"cmd\":\"hello\",\"token\":...} with the token " +
					"from the endpoint file"),
				0));
			outbound.drain(2000); // the refusal must reach the client before the socket closes
			close();
			return;
		}
		client.authenticated = true;
		client.negotiate(req); // the authenticating hello fixes the protocol, before it is answered
		RequestMonitor hm = new RequestMonitor(id, this::send);
		hm.describeAs(cmd, new Caller.Identity(client.name, client.harness, false));
		respond(req, id, cmd, hm);
	}

	private void respond(JsonObject req, JsonElement id, String cmd, RequestMonitor m) {
		String key = id == null ? null : id.toString();
		long t0 = System.nanoTime();
		JsonObject resp;
		boolean stop = false;
		try {
			if (m.isCancelled()) {
				throw new SessionException(SessionException.CANCELLED,
					"cancelled before it started");
			}
			Caller.enter(client, m.caller(), m);
			JsonElement result = session.execute(client, cmd, req, m);
			resp = new JsonObject();
			if (id != null) {
				resp.add("id", id);
			}
			resp.addProperty("ok", true);
			resp.add("result", result);
			if (client.v3()) {
				// a request that waited 250 ms or more says where and for how long (C9, D49)
				JsonObject waited = m.waited();
				if (waited != null) {
					JsonObject q = m.queueSeen();
					if (q != null) {
						resp.add("queue", q);
					}
					resp.add("waited", waited);
				}
			}
			resp.addProperty("ms", (System.nanoTime() - t0) / 1_000_000);
			stop = cmd.equals("shutdown");
			exiting = stop; // before the reply: the client may close as soon as it has read it
		}
		catch (SessionException e) {
			// a failure caused by a file another process holds is busy, never a client mistake
			// (GATE10, A63); every other answer is unchanged
			SessionException held = HeldFiles.translate(cmd, e);
			SessionException out = held != null ? held : e;
			resp = error(id, client.v3() ? withCancelDetails(out, cmd, m) : out, t0);
		}
		catch (Throwable t) {
			SessionException held = HeldFiles.translate(cmd, t);
			if (held != null) {
				Msg.warn(this, client.label() + " " + cmd + ": " + held.getMessage());
				resp = error(id, held, t0);
			}
			else {
				Msg.error(this, client.label() + " " + cmd + " failed", t);
				resp = error(id, new SessionException(SessionException.FAILED,
					t.getClass().getSimpleName() + ": " + t.getMessage(), null, t), t0);
			}
		}
		finally {
			Caller.leave();
			m.done();
			if (key != null) {
				client.running.remove(key, m);
			}
		}
		if (!Session.isInline(cmd)) {
			try {
				session.annotate(client, resp);
			}
			catch (RuntimeException e) {
				Msg.warn(this, client.label() + ": could not check revisions: " + e);
			}
			Caller.Identity ci = m.caller();
			Msg.info(this, (ci == null ? client.label() : client.label(ci.name(), ci.harness())) +
				" " + cmd + " " + resp.get("ms") + " ms " +
				(resp.get("ok").getAsBoolean() ? "ok"
						: resp.getAsJsonObject("error").get("code").getAsString()));
		}
		send(resp);
		if (stop) {
			outbound.drain(2000); // the reply to shutdown is written before the process exits
			onShutdown.run();
		}
	}

	/**
	 * The failure reply. A protocol 3 connection also gets {@code error.next} and
	 * {@code error.retryAfterMs} when the exception carries them (conditional C10); a protocol 2
	 * connection never does, so its replies are byte-identical to protocol 2's.
	 */
	private JsonObject error(JsonElement id, SessionException e, long t0) {
		JsonObject resp = new JsonObject();
		if (id != null) {
			resp.add("id", id);
		}
		resp.addProperty("ok", false);
		JsonObject err = Json.of("code", e.code(), "message", String.valueOf(e.getMessage()));
		if (e.details() != null) {
			err.add("details", e.details());
		}
		if (client.v3()) {
			if (e.next() != null) {
				err.add("next", e.next());
			}
			if (e.retryAfterMs() != null) {
				err.addProperty("retryAfterMs", e.retryAfterMs());
			}
		}
		if (e.getCause() != null && e.code().equals(SessionException.FAILED)) {
			StringWriter sw = new StringWriter();
			e.getCause().printStackTrace(new PrintWriter(sw));
			String[] lines = sw.toString().split("\\R");
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < Math.min(lines.length, 20); i++) {
				sb.append(lines[i]).append('\n');
			}
			err.addProperty("trace", sb.toString());
		}
		resp.add("error", err);
		resp.addProperty("ms", t0 == 0 ? 0 : (System.nanoTime() - t0) / 1_000_000);
		return resp;
	}

	/**
	 * The {@code cancelled} of a protocol 3 connection says where it ended the request
	 * ({@code phase}: {@code queued}, {@code lock_wait} or {@code running}) and, for the commands
	 * that can tell, whether the change reached the program ({@code applied}); conditional C11.
	 * Other commands carry no {@code applied}: absent, not guessed (3.3).
	 */
	private static SessionException withCancelDetails(SessionException e, String cmd,
			RequestMonitor m) {
		if (!SessionException.CANCELLED.equals(e.code())) {
			return e;
		}
		String phase = m.cancelPhase();
		if (phase == null) {
			phase = "running";
		}
		JsonObject d = e.details() == null ? new JsonObject() : e.details();
		if (!d.has("phase")) {
			Json.put(d, "phase", phase);
		}
		if (!d.has("applied")) {
			Boolean applied = null;
			switch (cmd) {
				case "rename", "comment", "edit", "apply_overlay", "save" -> applied = Boolean.FALSE;
				case "script" -> {
					if (!phase.equals("running")) {
						applied = Boolean.FALSE; // it never started
					}
					else if (d.has("mode") && d.get("mode").isJsonPrimitive() &&
						"owner".equals(d.get("mode").getAsString()) && d.has("changed")) {
						applied = d.get("changed").getAsBoolean();
					}
				}
				default -> {
					// absent, not guessed
				}
			}
			if (applied != null) {
				d.addProperty("applied", applied);
			}
		}
		return e.details() == d ? e : e.rewrap(e.getMessage(), d);
	}

	/** Set when a client stopped reading and was disconnected for it. */
	volatile boolean stalled;

	/** Queues a line for the writer thread: events may be dropped, a reply may not (BP23). */
	void send(JsonObject o) {
		byte[] bytes = encode(o);
		boolean reply = o.has("ok");
		if (!open && !reply) {
			return;
		}
		if (!reply) {
			outbound.offerEvent(bytes);
			return;
		}
		if (!outbound.offerReply(bytes)) {
			onStall();
		}
	}

	/**
	 * The line for {@code o}: Gson's JSON and a newline. A {@code result} that is already JSON
	 * bytes (the Rust read plane, {@link ReadPlane.RawJson}) is spliced in where Gson would have
	 * written it, so the line is byte for byte the one a tree result gives.
	 */
	static byte[] encode(JsonObject o) {
		if (o.get("result") instanceof ReadPlane.RawJson raw) {
			o.add("result", JsonNull.INSTANCE); // same key, same place in the object
			String s = Json.GSON.toJson(o);
			String head = "{" + (o.has("id") ? "\"id\":" + Json.GSON.toJson(o.get("id")) + "," : "") +
				"\"ok\":true,\"result\":";
			if (s.startsWith(head + "null")) {
				byte[] h = head.getBytes(StandardCharsets.UTF_8);
				byte[] t = (s.substring(head.length() + 4) + "\n").getBytes(StandardCharsets.UTF_8);
				byte[] out = new byte[h.length + raw.bytes.length + t.length];
				System.arraycopy(h, 0, out, 0, h.length);
				System.arraycopy(raw.bytes, 0, out, h.length, raw.bytes.length);
				System.arraycopy(t, 0, out, h.length + raw.bytes.length, t.length);
				return out;
			}
			o.add("result", raw.tree()); // an unexpected layout: the tree path
		}
		return (Json.GSON.toJson(o) + "\n").getBytes(StandardCharsets.UTF_8);
	}

	/** The client does not read: drop it (its requests are cancelled and its locks released). */
	private void onStall() {
		if (stalled) {
			return;
		}
		Msg.warn(this, client.label() + " does not read what is sent to it for more than " +
			outbound.stallMs + " ms; disconnecting it (writeStallMs)");
		stalled = true;
		open = false;
		close();
	}

	/** Looks every 500 ms for a socket write that has not finished within {@code writeStallMs}. */
	private static final java.util.concurrent.ScheduledExecutorService STALL_WATCH =
		Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "session-stall-watch");
			t.setDaemon(true);
			return t;
		});

	/**
	 * The outbound side of one connection: a bounded queue and the one thread that writes to the
	 * socket. A thread that holds a program lock and reports progress to a client that stopped
	 * reading would otherwise block in the socket write for as long as the client stays silent
	 * (BP23): events are dropped when the queue is over its bound, a reply waits up to
	 * {@code writeStallMs} for room and then the client is disconnected.
	 */
	private final class Outbound implements Runnable {
		private static final long EVENT_BYTES_MAX = 1L << 20;
		private static final int EVENT_COUNT_MAX = 2048;
		private static final long REPLY_BYTES_MAX = 64L << 20;
		/** A write unit of the writer: the stall clock restarts after each (the stream's buffer size). */
		private static final int WRITE_CHUNK = 1 << 16;

		final long stallMs = Math.max(250, Settings.integer("writeStallMs", 5000));
		private final java.util.ArrayDeque<byte[]> queue = new java.util.ArrayDeque<>();
		private long queued;
		private boolean stopping;
		/** {@code System.nanoTime()} when the current socket write began, 0 when none is running. */
		private volatile long writing;
		private final Thread thread;

		private final java.util.concurrent.ScheduledFuture<?> watch;

		Outbound(boolean virtual) {
			String name = "session-" + client.label().replace(' ', '-') + "-out";
			// a virtual writer parks in a socket write instead of holding a platform thread; the
			// stdio writer (a file write would hold the carrier anyway) stays a platform thread
			thread = virtual ? Thread.ofVirtual().name(name).unstarted(this)
					: Thread.ofPlatform().name(name).daemon(true).unstarted(this);
			thread.start();
			watch = STALL_WATCH.scheduleWithFixedDelay(() -> {
				if (writerStalled()) {
					onStall();
				}
			}, 500, 500, TimeUnit.MILLISECONDS);
		}

		synchronized void offerEvent(byte[] b) {
			if (stopping || queued > EVENT_BYTES_MAX || queue.size() >= EVENT_COUNT_MAX) {
				return; // dropped: progress is best effort
			}
			queue.add(b);
			queued += b.length;
			notifyAll();
		}

		/** @return false when the client does not read: the reply is not queued */
		synchronized boolean offerReply(byte[] b) {
			long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(stallMs);
			try {
				while (!stopping && !queue.isEmpty() && queued + b.length > REPLY_BYTES_MAX) {
					if (writerStalled() || System.nanoTime() - end >= 0) {
						return false;
					}
					wait(50);
				}
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			if (stopping) {
				return true; // the connection is over; nobody reads it
			}
			if (writerStalled()) {
				return false;
			}
			queue.add(b);
			queued += b.length;
			notifyAll();
			return true;
		}

		private boolean writerStalled() {
			long w = writing;
			return w != 0 && System.nanoTime() - w > TimeUnit.MILLISECONDS.toNanos(stallMs);
		}

		/** Waits until everything queued was written, at most {@code ms}. */
		synchronized void drain(long ms) {
			long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms);
			try {
				while (!queue.isEmpty() && System.nanoTime() - end < 0) {
					wait(20);
				}
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}

		/** Wakes a virtual writer parked in a socket write (the connection is closing). */
		void interruptIfVirtual() {
			if (thread.isVirtual()) {
				thread.interrupt();
			}
		}

		/** After the last reply: lets the writer drain (bounded), then stops it. */
		void finish() {
			watch.cancel(false);
			synchronized (this) {
				drain(stallMs);
				stopping = true;
				queue.clear();
				queued = 0;
				notifyAll();
			}
		}

		@Override
		public void run() {
			while (true) {
				byte[] b;
				synchronized (this) {
					while (queue.isEmpty()) {
						if (stopping) {
							return;
						}
						try {
							wait();
						}
						catch (InterruptedException e) {
							// close() interrupted this virtual writer: it ends for good, so nothing
							// queued later could be written. Stop taking replies and empty the queue,
							// or finish() would wait writeStallMs for a queue nobody drains.
							open = false;
							stopping = true;
							queue.clear();
							queued = 0;
							notifyAll();
							return;
						}
					}
					b = queue.peekFirst();
					writing = System.nanoTime();
				}
				boolean ok = true;
				try {
					// in chunks, each one moving the stall clock: writeStallMs is the time without
					// progress, not the time a large reply takes to a client that reads it slowly.
					// A virtual writer's socket is non-blocking underneath, so one big write waits
					// for the reader where a platform thread's blocking send handed the reply to
					// the kernel; a client that stops reading still stalls one chunk (as before)
					for (int off = 0; off < b.length; off += WRITE_CHUNK) {
						out.write(b, off, Math.min(WRITE_CHUNK, b.length - off));
						synchronized (this) {
							writing = System.nanoTime();
						}
					}
					out.flush();
				}
				catch (IOException e) {
					ok = false;
				}
				synchronized (this) {
					writing = 0;
					queue.pollFirst();
					queued -= b.length;
					if (!ok) {
						open = false;
						queue.clear();
						queued = 0;
					}
					notifyAll();
				}
			}
		}
	}

	void close() {
		open = false;
		try {
			in.close();
		}
		catch (IOException e) {
			// already closed
		}
		// A virtual reader or writer parked in a socket operation is woken by an interrupt at
		// once (the socket is closed under it); a platform one ignores it, as before. Without it
		// a closed connection could wait for the poller to notice before it is released.
		synchronized (readerGuard) {
			if (reader != null && reader.isVirtual()) {
				reader.interrupt();
			}
		}
		outbound.interruptIfVirtual();
	}

	private final Object readerGuard = new Object();
	/** The thread in {@link #run()}'s read loop, null once it left it. */
	private Thread reader;

	private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

	/** Reads one line (without its terminator), refusing lines over {@link #MAX_LINE_BYTES}. */
	private byte[] readLine() throws IOException {
		buf.reset();
		int b;
		while ((b = in.read()) != -1) {
			if (b == '\n') {
				return trimCr(buf.toByteArray());
			}
			if (buf.size() >= MAX_LINE_BYTES) {
				send(error(null, new SessionException(SessionException.BAD_REQUEST,
					"request line longer than " + MAX_LINE_BYTES + " bytes"), 0));
				throw new IOException("request line too long; connection closed");
			}
			buf.write(b);
		}
		return buf.size() > 0 ? trimCr(buf.toByteArray()) : null;
	}

	private static byte[] trimCr(byte[] b) {
		if (b.length > 0 && b[b.length - 1] == '\r') {
			byte[] t = new byte[b.length - 1];
			System.arraycopy(b, 0, t, 0, t.length);
			return t;
		}
		return b;
	}
}
