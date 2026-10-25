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

import com.google.gson.JsonObject;

/**
 * A command failure with a stable, machine-readable {@link #code}. The protocol reports it as
 * {@code {"ok":false,"error":{"code":...,"message":...,"details":{...}}}}.
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

	private final String code;
	private final JsonObject details;

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
}
