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

import java.util.List;

import com.google.gson.JsonObject;

/**
 * A command failure with a stable, machine-readable {@link #code}. The protocol reports it as
 * {@code {"ok":false,"error":{"code":...,"message":...,"details":{...}}}}; for a protocol 3
 * connection the error may also carry {@code next} and {@code retryAfterMs} (PROTOCOL-3.md 3.3,
 * reply conditional C10).
 */
public class SessionException extends RuntimeException {

	/** The request was malformed: missing or wrong field, bad address. */
	public static final String BAD_REQUEST = "bad_request";
	/** The {@code cmd} is not a session command. */
	public static final String UNKNOWN_COMMAND = "unknown_command";
	/** The connection has not authenticated (socket transport only). */
	public static final String UNAUTHORIZED = "unauthorized";
	/** No project is open in this session. */
	public static final String NO_PROJECT = "no_project";
	/** No program is selected, or the named program is not open for this client. */
	public static final String NO_PROGRAM = "no_program";
	/** A project path, folder, program, function, script or file does not exist. */
	public static final String NOT_FOUND = "not_found";
	/** A write was asked for on something opened read-only (project or program). */
	public static final String READ_ONLY = "read_only";
	/** Another client owns the writable program. */
	public static final String NOT_OWNER = "not_owner";
	/** The lock needed was not obtained within the request's {@code wait}. Retry later. */
	public static final String BUSY = "busy";
	/** The request contradicts the session's state (e.g. switching a project others use). */
	public static final String CONFLICT = "conflict";
	/** Closing would discard unsaved changes; save first or pass {@code "discard":true}. */
	public static final String UNSAVED_CHANGES = "unsaved_changes";
	/** The request was cancelled by {@code cancel} or ran past its {@code timeout}. */
	public static final String CANCELLED = "cancelled";
	/** Ghidra reported an error; {@code message} carries its text. */
	public static final String FAILED = "failed";
	/**
	 * Protocol 3 only (a protocol 2 connection gets {@link #CONFLICT} with
	 * {@code details.reason:"backup_required"}): a one-way upgrade of a project that is not a
	 * disposable copy was asked for without a valid backup. Raised by package E2.
	 */
	public static final String BACKUP_REQUIRED = "backup_required";
	/** Protocol 3 only: a script's {@code scriptSha256} does not match the file. Raised by E4. */
	public static final String SCRIPT_CHANGED = "script_changed";

	/** {@code error.retryAfterMs} is clamped to this range (3.3). */
	static final long RETRY_MIN_MS = 250;
	static final long RETRY_MAX_MS = 10_000;

	private final String code;
	private final JsonObject details;
	private JsonObject next;
	private Long retryAfterMs;

	public SessionException(String code, String message) {
		this(code, message, null, null);
	}

	public SessionException(String code, String message, JsonObject details) {
		this(code, message, details, null);
	}

	public SessionException(String code, String message, JsonObject details, Throwable cause) {
		super(message, cause);
		this.code = code;
		this.details = details;
	}

	public String code() {
		return code;
	}

	public JsonObject details() {
		return details;
	}

	/**
	 * A ready request in the shape of the {@code suggestion} objects ({@code {"cmd":...}}), for the
	 * cases where the engine knows the move. Sent as {@code error.next} to a protocol 3 client
	 * only; {@code details.suggest} keeps its string vocabulary unchanged.
	 */
	public SessionException withNext(JsonObject nextRequest) {
		this.next = nextRequest;
		return this;
	}

	/**
	 * How long a client should wait before it retries, when waiting can help ({@code busy}),
	 * clamped to 250..10000 ms. Sent as {@code error.retryAfterMs} (a sibling of {@code details})
	 * to a protocol 3 client only.
	 */
	public SessionException withRetryAfterMs(long ms) {
		this.retryAfterMs = Math.max(RETRY_MIN_MS, Math.min(RETRY_MAX_MS, ms));
		return this;
	}

	public JsonObject next() {
		return next;
	}

	public Long retryAfterMs() {
		return retryAfterMs;
	}

	/**
	 * The same failure under another message and other details (a wrapper that adds the index of
	 * the failing operation, for one), keeping {@link #next} and {@link #retryAfterMs} and naming
	 * this exception as the cause.
	 */
	SessionException rewrap(String message, JsonObject newDetails) {
		SessionException e = new SessionException(code, message, newDetails, this);
		e.next = next;
		e.retryAfterMs = retryAfterMs;
		return e;
	}

	// ---- the two detail helpers of PROTOCOL-3.md 3.1 (conditionals C12 and C13) -------------

	/**
	 * The one place that decides whether a {@code busy} carries the protocol 3 keys (C12):
	 * {@code reason} ({@code slot_wait}, {@code lock_wait}, {@code lock_queue_full},
	 * {@code abandoned}), {@code queue} (the object of 3.4, may be null) and {@code abandoned}
	 * (may be null). A protocol 2 connection gets {@code base} exactly as it was. Every busy
	 * answer of the scheduler and of the project, program and overlay locks goes through it.
	 * {@code retryAfterMs} is not a details key (see {@link #withRetryAfterMs}).
	 */
	static JsonObject busyDetails(boolean v3, JsonObject base, String reason, JsonObject queue,
			Boolean abandoned) {
		if (!v3) {
			return base;
		}
		if (reason != null) {
			Json.put(base, "reason", reason);
		}
		if (queue != null) {
			Json.put(base, "queue", queue);
		}
		if (abandoned != null) {
			Json.put(base, "abandoned", abandoned);
		}
		return base;
	}

	/**
	 * The one place that builds a {@code bad_request} for a closed or named field (C13): a
	 * protocol 3 connection gets {@code details:{field, allowed[]}} ({@code allowed} may be null);
	 * a protocol 2 connection gets no details, as today.
	 */
	static SessionException badRequest(boolean v3, String message, String field,
			List<String> allowed) {
		if (!v3) {
			return new SessionException(BAD_REQUEST, message);
		}
		JsonObject d = Json.of("field", field);
		if (allowed != null) {
			Json.put(d, "allowed", allowed);
		}
		return new SessionException(BAD_REQUEST, message, d);
	}
}
