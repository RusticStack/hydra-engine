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

import com.google.gson.*;

/**
 * Reading a request's {@code wait}, the output cap and the cancelled error, the
 * same way for every command.
 */
final class Requests {

	private Requests() {
		// static helpers
	}

	static final long DEFAULT_WAIT_MS = 10_000;
	static final int DEFAULT_TEXT_CAP = 200_000;
	static final int MAX_TEXT_CAP = 16_000_000;

	/**
	 * How long a request may wait for a slot or a lock. {@code "wait": true} (on
	 * {@code open_program}: wait for the upgrade cache copy) or {@code false} keeps the default.
	 */
	static long waitMs(JsonObject req) {
		if (Json.has(req, "wait") && req.get("wait").isJsonPrimitive() &&
			req.getAsJsonPrimitive("wait").isBoolean()) {
			return DEFAULT_WAIT_MS;
		}
		return Json.num(req, "wait", DEFAULT_WAIT_MS, 0, 86_400_000L);
	}

	/**
	 * What a wait that has the whole budget of {@code wait} still has left: the milliseconds until
	 * {@code deadlineNanos} when the request set a numeric {@code wait} ({@code limited}), else
	 * {@link Scheduler#UNLIMITED_MS}. Both the scheduler slot and the project lock of an import
	 * take this instead of a fresh {@link #waitMs} (PROTOCOL-3.md 3.5, import wait fix, V2).
	 */
	static long remainingMs(boolean limited, long deadlineNanos) {
		if (!limited) {
			return Scheduler.UNLIMITED_MS;
		}
		return Math.max(0, (deadlineNanos - System.nanoTime()) / 1_000_000L);
	}

	private static boolean registered;

	/**
	 * Registers the generic checks of {@link Preflight} under {@link Preflight#ALL} (once), each
	 * a call of the helper the command itself uses, so that the preflight and the command cannot
	 * drift: {@code timeout} (script, analyze, import), the required {@code address} and
	 * {@code name} of {@code decompile}, {@code rename} and {@code comment}, and the type of
	 * {@code rk} and {@code expect}. The checks of one command's own fields ({@code lane},
	 * {@code isolation}, {@code purpose}, {@code verify}) are registered by the package that
	 * owns the command. They run for a protocol 3 request that would have to queue, before it
	 * queues.
	 */
	static synchronized void registerPreflight() {
		if (registered) {
			return;
		}
		registered = true;
		Preflight.register(Preflight.ALL, (cmd, req) -> {
			switch (cmd) {
				case "script", "analyze", "import" -> Json.num(req, "timeout", 0, 0, 7 * 86_400);
				case "decompile" -> Json.str(req, "address");
				case "rename" -> {
					Json.str(req, "address");
					Json.str(req, "name");
				}
				case "comment" -> Json.str(req, "address");
				default -> {
					// nothing generic to check
				}
			}
			if (cmd.equals("rename") || cmd.equals("comment")) {
				EditCommands.rkOf(req);
				if (req.has("expect") && !req.get("expect").isJsonNull() &&
					!req.get("expect").isJsonPrimitive()) {
					throw SessionException.badRequest(true,
						"expect must be a string, or null for \"none\"", "expect", null);
				}
			}
		});
	}

	static boolean waitsForCache(JsonObject req) {
		return Json.has(req, "wait") && req.get("wait").isJsonPrimitive() &&
			req.getAsJsonPrimitive("wait").isBoolean() && req.get("wait").getAsBoolean();
	}

	static SessionException cancelled(RequestMonitor m) {
		return new SessionException(SessionException.CANCELLED,
			m.timedOut() ? "timed out" : "cancelled");
	}
}
