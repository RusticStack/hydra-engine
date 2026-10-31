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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

import com.google.gson.*;

import ghidra.util.exception.CancelledException;

/**
 * Backups (PROTOCOL-3.md 3.4, package E2): the manifest {@code backup.json} (one schema, two
 * writers: this engine and Hydralysis), its <b>canonical form</b>, the verification of a copy
 * against its source, and the engine's check of a backup offered to the upgrade gate.
 * <p>
 * <b>Canonical form</b> (what {@code selfSha256} and {@code filesetSha256} hash): UTF-8 without a
 * BOM; no whitespace outside strings; separators {@code ,} and {@code :}; object keys sorted by
 * code point; integers only (no floats, no exponents); strings escape exactly the quote, the
 * backslash and the control characters U+0000 to U+001F ({@code \b \t \n \f \r} where they exist,
 * else a backslash, the letter u and four lower-case hex digits) and nothing else: {@code < > & '}, U+007F and every non-ASCII
 * character, U+2028 and U+2029 included, are written literally. An unpaired surrogate is refused.
 * Python writes the same bytes with
 * {@code json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)}. Gson cannot
 * be configured to this form, hence this serializer.
 */
final class ProjectBackup {

	static final String KIND = "ghidra-session-backup";
	static final String FILE = "backup.json";
	static final int FORMAT = 1;
	/** The most mismatches a failed verify reports. */
	static final int MAX_MISMATCHES = 20;

	private ProjectBackup() {
	}

	// ---- the canonical serializer --------------------------------------------------------------

	/** The canonical text of {@code e}; throws {@link IllegalArgumentException} outside the form. */
	static String canonical(JsonElement e) {
		StringBuilder sb = new StringBuilder();
		write(sb, e);
		return sb.toString();
	}

	static byte[] canonicalBytes(JsonElement e) {
		return canonical(e).getBytes(StandardCharsets.UTF_8);
	}

	private static void write(StringBuilder sb, JsonElement e) {
		if (e == null || e.isJsonNull()) {
			sb.append("null");
		}
		else if (e.isJsonObject()) {
			List<String> keys = new ArrayList<>(e.getAsJsonObject().keySet());
			keys.sort(ProjectBackup::compareCodePoints);
			sb.append('{');
			boolean first = true;
			for (String k : keys) {
				if (!first) {
					sb.append(',');
				}
				first = false;
				string(sb, k);
				sb.append(':');
				write(sb, e.getAsJsonObject().get(k));
			}
			sb.append('}');
		}
		else if (e.isJsonArray()) {
			sb.append('[');
			boolean first = true;
			for (JsonElement x : e.getAsJsonArray()) {
				if (!first) {
					sb.append(',');
				}
				first = false;
				write(sb, x);
			}
			sb.append(']');
		}
		else {
			JsonPrimitive p = e.getAsJsonPrimitive();
			if (p.isBoolean()) {
				sb.append(p.getAsBoolean() ? "true" : "false");
			}
			else if (p.isNumber()) {
				String t = p.getAsString();
				if (!t.matches("-?(0|[1-9][0-9]*)")) {
					throw new IllegalArgumentException(
						"a manifest holds integers only, not '" + t + "'");
				}
				sb.append(t.equals("-0") ? "0" : t);
			}
			else {
				string(sb, p.getAsString());
			}
		}
	}

	private static int compareCodePoints(String a, String b) {
		int i = 0;
		int j = 0;
		while (i < a.length() && j < b.length()) {
			int ca = a.codePointAt(i);
			int cb = b.codePointAt(j);
			if (ca != cb) {
				return Integer.compare(ca, cb);
			}
			i += Character.charCount(ca);
			j += Character.charCount(cb);
		}
		return Integer.compare(a.length() - i, b.length() - j);
	}

	private static void string(StringBuilder sb, String s) {
		sb.append('"');
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			if (Character.isHighSurrogate(ch)) {
				if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
					throw new IllegalArgumentException(
						"an unpaired surrogate has no UTF-8 form and is refused in a manifest");
				}
				sb.append(ch).append(s.charAt(++i));
				continue;
			}
			if (Character.isLowSurrogate(ch)) {
				throw new IllegalArgumentException(
					"an unpaired surrogate has no UTF-8 form and is refused in a manifest");
			}
			switch (ch) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\b' -> sb.append("\\b");
				case '\t' -> sb.append("\\t");
				case '\n' -> sb.append("\\n");
				case '\f' -> sb.append("\\f");
				case '\r' -> sb.append("\\r");
				default -> {
					if (ch < 0x20) {
						sb.append(String.format("\\u%04x", (int) ch));
					}
					else {
						sb.append(ch);
					}
				}
			}
		}
		sb.append('"');
	}

	static MessageDigest sha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	static String sha256Hex(byte[] b) {
		return HexFormat.of().formatHex(sha256().digest(b));
	}

	/** The SHA-256 of a file, streamed; checks cancellation between blocks when {@code m} is set. */
	static String sha256Of(Path f, RequestMonitor m) throws IOException, CancelledException {
		MessageDigest md = sha256();
		byte[] buf = HASH_BUFFERS.poll();
		if (buf == null) {
			buf = new byte[1 << 20];
		}
		try (InputStream in = Files.newInputStream(f)) {
			int n;
			while ((n = in.read(buf)) > 0) {
				md.update(buf, 0, n);
				if (m != null) {
					m.checkCancelled();
				}
			}
		}
		finally {
			if (HASH_BUFFERS.size() < 4) {
				HASH_BUFFERS.offer(buf);
			}
		}
		return HexFormat.of().formatHex(md.digest());
	}

	/**
	 * Hydra: read buffers of {@link #sha256Of}, kept for the next hash. A fresh megabyte per file
	 * was 6 % of the daemon's allocation in the 16-agent benchmark (every fork hashes its copy).
	 */
	private static final java.util.concurrent.ConcurrentLinkedQueue<byte[]> HASH_BUFFERS =
		new java.util.concurrent.ConcurrentLinkedQueue<>();

	// ---- the manifest --------------------------------------------------------------------------

	/** One file of a backup: its path below the backup folder, size and SHA-256. */
	record FileEntry(String path, long size, String sha256) {
		JsonObject json() {
			return Json.of("path", path, "size", size, "sha256", sha256);
		}
	}

	/** The outcome of {@link #verifyCopy}. */
	record Verified(String level, List<FileEntry> files, List<JsonObject> mismatches) {
		boolean ok() {
			return mismatches.isEmpty();
		}
	}

	/** The {@code filesetSha256}: the SHA-256 of the canonical form of the {@code files} array. */
	static String filesetSha(List<FileEntry> files) {
		JsonArray a = new JsonArray();
		files.forEach(f -> a.add(f.json()));
		return sha256Hex(canonicalBytes(a));
	}

	/** Adds {@code selfSha256} (the hash of the canonical form without it) to {@code manifest}. */
	static void seal(JsonObject manifest) {
		manifest.remove("selfSha256");
		manifest.addProperty("selfSha256", sha256Hex(canonicalBytes(manifest)));
	}

	/** True when {@code selfSha256} is the hash of the manifest without it. */
	static boolean selfHashOk(JsonObject manifest) {
		if (!Json.has(manifest, "selfSha256")) {
			return false;
		}
		JsonObject copy = manifest.deepCopy();
		String claimed = copy.remove("selfSha256").getAsString();
		try {
			return claimed.equals(sha256Hex(canonicalBytes(copy)));
		}
		catch (IllegalArgumentException e) {
			return false;
		}
	}

	/** Writes {@code backup.json} in canonical form into {@code dir}; returns its SHA-256. */
	static String write(Path dir, JsonObject manifest) throws IOException {
		byte[] bytes = canonicalBytes(manifest);
		Path tmp = dir.resolve(FILE + ".tmp");
		Files.write(tmp, bytes);
		Files.move(tmp, dir.resolve(FILE), StandardCopyOption.REPLACE_EXISTING);
		return sha256Hex(bytes);
	}

	/**
	 * Marks the published manifest read-only (best effort: it is not touched again, 3.4). Done
	 * after the publish and never in the staging folder, where a read-only file would stop the
	 * folder from being deleted when the publish fails or the publisher is killed.
	 */
	static void freeze(Path manifest) {
		try {
			manifest.toFile().setReadOnly();
		}
		catch (RuntimeException e) {
			// not every file system has the attribute
		}
	}

	/**
	 * Compares the copy in {@code stagedDir} (laid out as the source, under the source's name)
	 * with the source project at the level asked: {@code none} (nothing compared), {@code size}
	 * (every file's size) or {@code hash} (the SHA-256 of every file of both sides, read after
	 * the copy). The returned files are named for the destination ({@code destName}) and carry the
	 * hash of the <i>copy</i> at every level, so the manifest can be re-hashed by a client later.
	 * Mismatches (at most {@link #MAX_MISMATCHES}) are listed as {@code {path, expected, actual}},
	 * the source's value first.
	 */
	static Verified verifyCopy(ProjectResolver.Resolved src, Path stagedDir, String destName,
			String level, RequestMonitor m) throws IOException, CancelledException {
		SortedMap<String, Path> from = UpgradeCache.sourceFiles(src.gpr().toPath(), src.name());
		SortedMap<String, Path> to = UpgradeCache.sourceFiles(
			stagedDir.resolve(src.name() + ".gpr"), src.name());
		List<FileEntry> files = new ArrayList<>();
		List<JsonObject> bad = new ArrayList<>();
		Set<String> keys = new TreeSet<>(from.keySet());
		keys.addAll(to.keySet());
		for (String k : keys) {
			m.checkCancelled();
			String out = rename(k, src.name(), destName);
			Path a = from.get(k);
			Path b = to.get(k);
			long sa = -1;
			long sb = -1;
			try {
				sa = a == null ? -1 : Files.size(a);
			}
			catch (NoSuchFileException e) {
				// removed from the source since we listed it
			}
			try {
				sb = b == null ? -1 : Files.size(b);
			}
			catch (NoSuchFileException e) {
				// the copy lost it
			}
			String hb = b == null || sb < 0 ? null : sha256Of(b, m);
			if (hb != null) {
				files.add(new FileEntry(out, sb, hb));
			}
			if (level.equals("none")) {
				continue;
			}
			if (sa != sb) {
				mismatch(bad, out, sa < 0 ? "missing" : "size " + sa,
					sb < 0 ? "missing" : "size " + sb);
				continue;
			}
			if (level.equals("hash") && sa >= 0) {
				String ha = sha256Of(a, m);
				if (!ha.equals(hb)) {
					mismatch(bad, out, ha, hb);
				}
			}
		}
		return new Verified(level, files, bad);
	}

	private static void mismatch(List<JsonObject> bad, String path, String expected,
			String actual) {
		if (bad.size() < MAX_MISMATCHES) {
			bad.add(Json.of("path", path, "expected", expected, "actual", actual));
		}
	}

	private static String rename(String rel, String from, String to) {
		if (from.equals(to)) {
			return rel;
		}
		if (rel.equals(from + ".gpr")) {
			return to + ".gpr";
		}
		if (rel.startsWith(from + ".rep/")) {
			return to + ".rep/" + rel.substring(from.length() + 5);
		}
		return rel;
	}

	// ---- the gate's check of a backup ----------------------------------------------------------

	/** The outcome of {@link #check}: {@code reason} is null when the backup is valid. */
	record Check(String reason, String detail, String id, JsonObject manifest) {
		boolean ok() {
			return reason == null;
		}
	}

	/**
	 * The engine's (cheap) check of a backup offered as {@code backup} to the upgrade gate (3.4):
	 * it parses; {@code format == 1}; {@code kind}; {@code verify.ok}; {@code selfSha256} matches
	 * the engine's recomputation; {@code source.revision} equals {@code projectRevision}; and every
	 * listed file exists below the manifest's folder with its recorded size. It does not re-hash
	 * the files (the client does that before relying on a backup; this is not a security
	 * boundary).
	 */
	static Check check(String backupJson, String projectRevision) {
		return check(backupJson, projectRevision == null ? List.of() : List.of(projectRevision));
	}

	/**
	 * {@link #check(String, String)} for a project that has two honest revisions: the one it was
	 * opened from and the one on disk now. Ghidra rewrites a project's index backups when it opens
	 * it writable (measurement C: a pristine writable open changed {@code ~index.bak}), so the
	 * revision of the files moves the moment the project is open, before any program is: a backup
	 * of the project as it was opened is the backup of what the upgrade will change.
	 */
	static Check check(String backupJson, Collection<String> projectRevisions) {
		Path f;
		try {
			f = Path.of(backupJson);
		}
		catch (InvalidPathException e) {
			return fail("unparseable", "not a path: " + backupJson);
		}
		if (!Files.isRegularFile(f)) {
			return fail("missing", f.toString());
		}
		JsonObject m;
		try {
			JsonElement e = JsonParser.parseString(Files.readString(f, StandardCharsets.UTF_8));
			if (!e.isJsonObject()) {
				return fail("unparseable", "not an object");
			}
			m = e.getAsJsonObject();
		}
		catch (IOException | JsonParseException e) {
			return fail("unparseable", String.valueOf(e.getMessage()));
		}
		try {
			if (!Json.has(m, "format") || m.get("format").getAsInt() != FORMAT) {
				return fail("format", "format must be 1");
			}
			if (!KIND.equals(Json.str(m, "kind", null))) {
				return fail("kind", "kind must be " + KIND);
			}
			JsonObject v = Json.obj(m, "verify");
			if (v == null || !Json.bool(v, "ok", false)) {
				return fail("unverified", "verify.ok is not true");
			}
			if (!selfHashOk(m)) {
				return fail("self_hash", "selfSha256 does not match the manifest");
			}
			JsonObject src = Json.obj(m, "source");
			String rev = src == null ? null : Json.str(src, "revision", null);
			if (rev == null || !projectRevisions.contains(rev)) {
				return fail("revision", "the backup was made at revision " + rev +
					", the project is at " + String.join(" / ", projectRevisions));
			}
			if (!m.has("files") || !m.get("files").isJsonArray()) {
				return fail("files", "files must be an array");
			}
			Path dir = f.toAbsolutePath().normalize().getParent();
			for (JsonElement x : m.getAsJsonArray("files")) {
				JsonObject fo = x.getAsJsonObject();
				String rel = Json.str(fo, "path");
				Path p = dir.resolve(rel).normalize();
				if (rel.startsWith("/") || rel.contains("\\") || !p.startsWith(dir)) {
					return fail("file_path", "unsafe path " + rel);
				}
				if (!Files.isRegularFile(p)) {
					return fail("file_missing", rel);
				}
				if (Files.size(p) != fo.get("size").getAsLong()) {
					return fail("file_size", rel);
				}
			}
			return new Check(null, null, Json.str(m, "id", null), m);
		}
		catch (IOException | RuntimeException e) {
			return fail("unparseable", e.getClass().getSimpleName() + ": " + e.getMessage());
		}
	}

	private static Check fail(String reason, String detail) {
		return new Check(reason, detail, null, null);
	}

	/** A backup id: {@code <UTC yyyymmddThhmmssZ>-<revision8>-<purpose>}. */
	static String newId(String revision, String purpose) {
		String ts = java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
				.withZone(java.time.ZoneOffset.UTC)
				.format(Instant.now());
		String rev8 = revision == null ? "00000000" : revision.substring(0, Math.min(8, revision.length()));
		return ts + "-" + rev8 + "-" + purpose.replaceAll("[^A-Za-z0-9._-]", "_");
	}

	// ---- the upgrade stamp -----------------------------------------------------------------------

	/** What a program opened writable with {@code upgrade:true} under a valid backup remembers. */
	record UpgradeStamp(String backupId, int storedVersion) {
		String comment() {
			return "Hydra " + HydraInfo.hydraVersion() + " upgrade from " + storedVersion +
				"; backup " + backupId;
		}
	}

	private static final Map<ProgramEntry, UpgradeStamp> STAMPS =
		Collections.synchronizedMap(new WeakHashMap<>());

	static void remember(ProgramEntry e, UpgradeStamp stamp) {
		STAMPS.put(e, stamp);
	}

	/** The stamp for the next save of {@code e} (taken once: the first save after the upgrade). */
	static UpgradeStamp take(ProgramEntry e) {
		return STAMPS.remove(e);
	}

	static void forget(ProgramEntry e) {
		STAMPS.remove(e);
	}
}
