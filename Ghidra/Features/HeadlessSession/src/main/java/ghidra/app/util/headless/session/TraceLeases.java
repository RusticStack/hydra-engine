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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The writer lease of a trace session (TRACE-1 section 2): one owner capability per session.
 * <p>
 * A session has at most one <b>writer</b>. The first {@code trace_open} that creates it is
 * granted the lease and receives a <b>capability</b> ({@code cap}, 128 random bits; only its
 * SHA-256 is kept, in memory and in {@code lease.json} next to the session's files). A writing
 * command carries the capability and must come from the connection that holds the lease; any
 * other caller reads (queries, explain, diff, check, export, info) and is never refused for it.
 * <ul>
 * <li>The same connection opening again with its capability keeps the lease and the
 * generation.</li>
 * <li>A producer that reconnects opens with its capability: it gets the lease back from the old
 * connection, and the <b>producer generation</b> goes up by one. A stale writer (the old
 * connection, or an old capability) is refused from then on with {@code not_owner}.</li>
 * <li>When the holder's connection ends, the lease is <b>orphaned</b>: the capability holder
 * may reclaim it, and anyone may take it over with {@code takeover:true}, which makes the old
 * capability worthless and also bumps the generation. A live holder is never taken over.</li>
 * <li>After a daemon restart every lease is an orphan ({@code lease.json} survives; the
 * connection does not).</li>
 * </ul>
 * Nothing here waits on another request: the table is guarded by one short monitor, and no file
 * I/O other than the small {@code lease.json} happens under it.
 */
final class TraceLeases {

	private TraceLeases() {
		// static
	}

	/** One session's lease. Fields are guarded by the class monitor. */
	static final class Lease {
		final String session;
		Client owner;
		String ownerLabel;
		String capHash;
		int producerGen;
		long since;
		long orphanedAt;

		Lease(String session) {
			this.session = session;
		}
	}

	/**
	 * What an {@link #acquire} decided. {@code cap} is set only when a new capability was issued.
	 */
	record Grant(Lease lease, String cap, boolean reclaimed, boolean tookOver) {
	}

	private static final Map<String, Lease> LEASES = new ConcurrentHashMap<>();
	private static final SecureRandom RANDOM = new SecureRandom();

	static int count() {
		return LEASES.size();
	}

	static String newCap() {
		byte[] b = new byte[16];
		RANDOM.nextBytes(b);
		return "cap_" + HexFormat.of().formatHex(b);
	}

	static String sha(String s) {
		try {
			return HexFormat.of().formatHex(
				MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
		}
		catch (java.security.NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	private static boolean alive(Lease l) {
		Client o = l.owner;
		return o != null && !o.leaving;
	}

	private static Lease load(Path dir, String session) {
		Lease l = LEASES.get(session);
		if (l != null) {
			return l;
		}
		Path f = dir.resolve("lease.json");
		if (!Files.isRegularFile(f)) {
			return null;
		}
		try {
			JsonObject o = JsonParser.parseString(Files.readString(f)).getAsJsonObject();
			l = new Lease(session);
			l.capHash = o.get("capSha256").getAsString();
			l.producerGen = o.get("producerGen").getAsInt();
			l.orphanedAt = System.currentTimeMillis();
			LEASES.put(session, l);
			return l;
		}
		catch (IOException | RuntimeException e) {
			throw new SessionException(SessionException.FAILED,
				"the lease record of trace session " + session + " is unreadable: " + e,
				Json.of("reason", "lease_record"), e);
		}
	}

	private static void persist(Path dir, Lease l) {
		try {
			Files.createDirectories(dir);
			Path tmp = dir.resolve("lease.json.tmp");
			Files.writeString(tmp,
				Json.GSON.toJson(Json.of("capSha256", l.capHash, "producerGen", l.producerGen)));
			Files.move(tmp, dir.resolve("lease.json"), StandardCopyOption.REPLACE_EXISTING);
		}
		catch (IOException e) {
			throw new SessionException(SessionException.FAILED,
				"cannot record the lease of trace session " + l.session + ": " + e,
				Json.of("reason", "lease_record"), e);
		}
	}

	/**
	 * Opens {@code session} for writing as {@code c}. See the class comment for the cases.
	 *
	 * @throws SessionException {@code not_owner} when a live connection holds the lease and
	 *             {@code cap} is not its capability, or when the lease is an orphan and neither
	 *             the capability nor {@code takeover} was given
	 */
	static synchronized Grant acquire(Path dir, String session, Client c, String cap,
			boolean takeover) {
		Lease l = load(dir, session);
		if (l == null) {
			l = new Lease(session);
			String fresh = newCap();
			l.capHash = sha(fresh);
			l.producerGen = 1;
			l.owner = c;
			l.ownerLabel = c.label();
			l.since = System.currentTimeMillis();
			persist(dir, l);
			LEASES.put(session, l);
			return new Grant(l, fresh, false, false);
		}
		boolean capOk = cap != null && sha(cap).equals(l.capHash);
		if (l.owner == c && capOk) {
			return new Grant(l, null, false, false);
		}
		if (alive(l) && !capOk) {
			throw notOwner(l, "trace session " + session + " is written by " + l.ownerLabel +
				"; open it with mode \"read\" to read it, or wait for its writer to end", "read");
		}
		if (alive(l) || capOk) {
			// the producer reconnected (or the orphan's capability holder came back)
			l.owner = c;
			l.ownerLabel = c.label();
			l.producerGen++;
			l.since = System.currentTimeMillis();
			persist(dir, l);
			return new Grant(l, null, true, false);
		}
		if (!takeover) {
			throw notOwner(l, "the writer of trace session " + session +
				" is gone; present its capability to continue, or open with \"takeover\":true",
				"takeover");
		}
		String fresh = newCap();
		l.capHash = sha(fresh);
		l.owner = c;
		l.ownerLabel = c.label();
		l.producerGen++;
		l.since = System.currentTimeMillis();
		persist(dir, l);
		return new Grant(l, fresh, false, true);
	}

	/**
	 * Checks that {@code c} holds the lease of {@code session} with {@code cap}; returns the
	 * lease.
	 *
	 * @throws SessionException {@code not_owner}
	 */
	static synchronized Lease require(String session, Client c, String cap, String cmd) {
		Lease l = LEASES.get(session);
		if (l == null || l.owner == null) {
			throw notOwner(l, cmd + " needs the writer lease of trace session " + session +
				"; open it with trace_open (mode \"write\")", l == null ? "open" : "takeover");
		}
		if (l.owner != c || cap == null || !sha(cap).equals(l.capHash)) {
			throw notOwner(l, cmd + " needs the writer lease of trace session " + session +
				", held by " + l.ownerLabel + (cap == null ? " (no cap given)" : ""), "read");
		}
		return l;
	}

	/** The writer ends its writing: the lease is orphaned, the capability stays valid. */
	static synchronized void release(String session, Client c) {
		Lease l = LEASES.get(session);
		if (l != null && l.owner == c) {
			l.owner = null;
			l.orphanedAt = System.currentTimeMillis();
		}
	}

	/** Drops the lease of a session whose creation failed (and its record). */
	static synchronized void forget(String session) {
		LEASES.remove(session);
	}

	/** A connection ended: every lease it held is orphaned. */
	static synchronized void clientGone(Client c) {
		for (Lease l : LEASES.values()) {
			if (l.owner == c) {
				l.owner = null;
				l.orphanedAt = System.currentTimeMillis();
			}
		}
	}

	static synchronized int generation(String session) {
		Lease l = LEASES.get(session);
		return l == null ? 0 : l.producerGen;
	}

	/** The state of a lease for {@code trace_info} and {@code trace_list} (never the capability). */
	static synchronized JsonObject describe(String session, Path dir) {
		Lease l = LEASES.get(session);
		if (l == null) {
			try {
				l = load(dir, session);
			}
			catch (SessionException e) {
				return Json.of("state", "unknown");
			}
		}
		if (l == null) {
			return Json.of("state", "none");
		}
		return alive(l)
				? Json.of("state", "held", "holder", l.ownerLabel, "producerGen", l.producerGen,
					"sinceMs", System.currentTimeMillis() - l.since)
				: Json.of("state", "orphan", "producerGen", l.producerGen);
	}

	private static SessionException notOwner(Lease l, String message, String suggest) {
		JsonObject d = new JsonObject();
		Json.put(d, "session", l == null ? null : l.session);
		Json.put(d, "holder", l == null || l.owner == null ? null : l.ownerLabel);
		Json.put(d, "orphan", l != null && l.owner == null);
		Json.put(d, "producerGen", l == null ? 0 : l.producerGen);
		Json.put(d, "suggest", suggest);
		return new SessionException(SessionException.NOT_OWNER, message, d);
	}
}
