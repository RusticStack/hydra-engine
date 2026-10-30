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
import java.util.concurrent.*;

import com.google.gson.*;

import ghidra.util.Msg;

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

	Connection(Session session, InputStream in, OutputStream out, String transport,
			boolean launcher, String token, Runnable onShutdown) {
		this.session = session;
		this.in = in;
		this.out = out;
		this.token = token;
		this.onShutdown = onShutdown;
		this.client = session.connect(transport, launcher, this::send);
		this.client.authenticated = token == null;
		this.worker = Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, "session-" + client.label().replace(' ', '-'));
			t.setDaemon(true);
			return t;
		});
		this.parallel = new ThreadPoolExecutor(0, MAX_PARALLEL, 30, TimeUnit.SECONDS,
			new SynchronousQueue<>(), r -> {
				Thread t = new Thread(r, "session-" + client.label().replace(' ', '-') + "-p");
				t.setDaemon(true);
				return t;
			});
		this.outbound = new Outbound();
	}

	Client client() {
		return client;
	}

	/** Reads until end of input, then releases what the client held. */
	void run() {
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
		try {
			(par ? parallel : worker).execute(() -> respond(req, id, cmd, m));
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
		byte[] bytes = (Json.GSON.toJson(o) + "\n").getBytes(StandardCharsets.UTF_8);
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

		final long stallMs = Math.max(250, Settings.integer("writeStallMs", 5000));
		private final java.util.ArrayDeque<byte[]> queue = new java.util.ArrayDeque<>();
		private long queued;
		private boolean stopping;
		/** {@code System.nanoTime()} when the current socket write began, 0 when none is running. */
		private volatile long writing;
		private final Thread thread;

		private final java.util.concurrent.ScheduledFuture<?> watch;

		Outbound() {
			thread = new Thread(this, "session-" + client.label().replace(' ', '-') + "-out");
			thread.setDaemon(true);
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
							return;
						}
					}
					b = queue.peekFirst();
					writing = System.nanoTime();
				}
				boolean ok = true;
				try {
					out.write(b);
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
	}

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
