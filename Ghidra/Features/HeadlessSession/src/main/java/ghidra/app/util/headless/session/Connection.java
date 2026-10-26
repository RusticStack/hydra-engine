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
	private final Object writeLock = new Object();
	private volatile boolean open = true;
	private final Runnable onShutdown;

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
			// cancel first: the worker must not finish a long request for a client that is gone
			client.running.values().forEach(RequestMonitor::cancel);
			worker.shutdown();
			parallel.shutdown();
			try {
				worker.awaitTermination(1, TimeUnit.HOURS);
				parallel.awaitTermination(1, TimeUnit.HOURS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			session.disconnect(client);
		}
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
		if (Session.isInline(cmd)) {
			respond(req, id, cmd, new RequestMonitor(id, this::send));
			return;
		}
		String key = id == null ? null : id.toString();
		RequestMonitor m = new RequestMonitor(id, this::send);
		if (key != null && client.running.putIfAbsent(key, m) != null) {
			send(error(id, new SessionException(SessionException.BAD_REQUEST,
				"request id " + key + " is still running; use a new id"), 0));
			return;
		}
		boolean par;
		try {
			par = Json.bool(req, "parallel", false);
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
			close();
			return;
		}
		client.authenticated = true;
		respond(req, id, cmd, new RequestMonitor(id, this::send));
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
			JsonElement result = session.execute(client, cmd, req, m);
			resp = new JsonObject();
			if (id != null) {
				resp.add("id", id);
			}
			resp.addProperty("ok", true);
			resp.add("result", result);
			resp.addProperty("ms", (System.nanoTime() - t0) / 1_000_000);
			stop = cmd.equals("shutdown");
		}
		catch (SessionException e) {
			resp = error(id, e, t0);
		}
		catch (Throwable t) {
			Msg.error(this, client.label() + " " + cmd + " failed", t);
			resp = error(id, new SessionException(SessionException.FAILED,
				t.getClass().getSimpleName() + ": " + t.getMessage(), null, t), t0);
		}
		finally {
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
			Msg.info(this, client.label() + " " + cmd + " " + resp.get("ms") + " ms " +
				(resp.get("ok").getAsBoolean() ? "ok"
						: resp.getAsJsonObject("error").get("code").getAsString()));
		}
		send(resp);
		if (stop) {
			onShutdown.run();
		}
	}

	private static JsonObject error(JsonElement id, SessionException e, long t0) {
		JsonObject resp = new JsonObject();
		if (id != null) {
			resp.add("id", id);
		}
		resp.addProperty("ok", false);
		JsonObject err = Json.of("code", e.code(), "message", String.valueOf(e.getMessage()));
		if (e.details() != null) {
			err.add("details", e.details());
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

	void send(JsonObject o) {
		byte[] bytes = (Json.GSON.toJson(o) + "\n").getBytes(StandardCharsets.UTF_8);
		synchronized (writeLock) {
			if (!open && !o.has("ok")) {
				return;
			}
			try {
				out.write(bytes);
				out.flush();
			}
			catch (IOException e) {
				open = false;
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
