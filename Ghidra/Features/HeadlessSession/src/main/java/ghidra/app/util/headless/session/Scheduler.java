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

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Admission control for the daemon's work, so that many clients share it fairly.
 * <p>
 * Requests are sorted into two lanes, each with a fixed number of slots:
 * <ul>
 * <li><b>quick</b> (decompile, functions, list, open, rename, ...): many slots, by default one
 * per CPU;</li>
 * <li><b>long</b> (analyze, import, script, save): few slots, by default a quarter of the
 * CPUs.</li>
 * </ul>
 * Long work can therefore never take the slots that quick queries need: one client's whole-program
 * export or analysis does not delay another client's 10 ms decompile. When a lane is full, waiting
 * requests are admitted <b>round-robin by client</b>, so a client that sends a hundred requests
 * cannot starve one that sends one. A request waits at most its {@code wait} and then fails with
 * {@code busy}, naming the lane and what holds it; a cancelled request leaves the queue at once.
 * <p>
 * Slots are taken before any project or program lock, and lock holders never wait for a slot, so
 * the two cannot deadlock.
 */
final class Scheduler {

	enum Lane {
		QUICK, LONG;

		String json() {
			return name().toLowerCase();
		}
	}

	/** The lane of a command, or null for commands that need no slot (bookkeeping). */
	static Lane laneOf(String cmd) {
		return switch (cmd) {
			case "analyze", "import", "script", "save" -> Lane.LONG;
			case "list", "functions", "decompile", "rename", "comment", "open_program", "switch",
					"open_project" ->
				Lane.QUICK;
			default -> null;
		};
	}

	private final ReentrantLock lock = new ReentrantLock();
	private final Condition changed = lock.newCondition();
	private final Map<Lane, State> lanes = new EnumMap<>(Lane.class);

	Scheduler(int quickSlots, int longSlots) {
		lanes.put(Lane.QUICK, new State(Math.max(1, quickSlots)));
		lanes.put(Lane.LONG, new State(Math.max(1, longSlots)));
	}

	private static final class State {
		final int slots;
		int inUse;
		/** Waiting tickets by client id; iteration order is the round-robin order. */
		final LinkedHashMap<Integer, ArrayDeque<Ticket>> queue = new LinkedHashMap<>();
		final Set<Ticket> running = new LinkedHashSet<>();
		long admitted;
		long queuedTotal;

		State(int slots) {
			this.slots = slots;
		}

		int queued() {
			int n = 0;
			for (ArrayDeque<Ticket> q : queue.values()) {
				n += q.size();
			}
			return n;
		}
	}

	/** One admitted request; closing it frees its slot. */
	final class Ticket implements AutoCloseable {
		final Lane lane;
		final Client client;
		final String cmd;
		final long queuedAt = System.currentTimeMillis();
		long startedAt;
		boolean granted;
		private boolean closed;

		Ticket(Lane lane, Client client, String cmd) {
			this.lane = lane;
			this.client = client;
			this.cmd = cmd;
		}

		@Override
		public void close() {
			release(this);
		}

		String describe() {
			return client.label() + " " + cmd;
		}
	}

	/**
	 * Waits for a slot in the command's lane. Returns null when the command needs none.
	 *
	 * @throws SessionException {@code busy} after {@code waitMs}, {@code cancelled} on cancel
	 */
	Ticket admit(Client c, String cmd, RequestMonitor m, long waitMs) {
		Lane lane = laneOf(cmd);
		if (lane == null) {
			return null;
		}
		lock.lock();
		try {
			State s = lanes.get(lane);
			Ticket t = new Ticket(lane, c, cmd);
			if (s.inUse < s.slots && s.queue.isEmpty()) {
				grant(s, t);
				return t;
			}
			s.queuedTotal++;
			s.queue.computeIfAbsent(c.id, k -> new ArrayDeque<>()).add(t);
			long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMs);
			while (!t.granted) {
				if (m != null && m.isCancelled()) {
					dequeue(s, t);
					throw new SessionException(SessionException.CANCELLED,
						"cancelled while queued for a " + lane.json() + " slot");
				}
				long left = deadline - System.nanoTime();
				if (left <= 0) {
					dequeue(s, t);
					JsonObject d = Json.of("lane", lane.json(), "slots", s.slots, "queued",
						s.queued(), "waitedMs", waitMs);
					List<String> holders = new ArrayList<>();
					s.running.forEach(r -> holders.add(r.describe()));
					Json.put(d, "running", holders);
					throw new SessionException(SessionException.BUSY,
						"all " + s.slots + " " + lane.json() + " slots are in use (" +
							String.join(", ", holders) + "); retry, or pass a longer \"wait\"",
						d);
				}
				try {
					changed.awaitNanos(Math.min(left, TimeUnit.MILLISECONDS.toNanos(100)));
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					dequeue(s, t);
					throw new SessionException(SessionException.CANCELLED, "interrupted");
				}
			}
			return t;
		}
		finally {
			lock.unlock();
		}
	}

	private void grant(State s, Ticket t) {
		t.granted = true;
		t.startedAt = System.currentTimeMillis();
		s.inUse++;
		s.admitted++;
		s.running.add(t);
	}

	private void dequeue(State s, Ticket t) {
		ArrayDeque<Ticket> q = s.queue.get(t.client.id);
		if (q != null) {
			q.remove(t);
			if (q.isEmpty()) {
				s.queue.remove(t.client.id);
			}
		}
	}

	private void release(Ticket t) {
		lock.lock();
		try {
			if (t.closed) {
				return;
			}
			t.closed = true;
			State s = lanes.get(t.lane);
			s.inUse--;
			s.running.remove(t);
			// Round-robin: take the first waiting client's oldest ticket, then move that client to
			// the back of the order.
			while (s.inUse < s.slots && !s.queue.isEmpty()) {
				Iterator<Map.Entry<Integer, ArrayDeque<Ticket>>> it = s.queue.entrySet().iterator();
				Map.Entry<Integer, ArrayDeque<Ticket>> head = it.next();
				it.remove();
				Ticket next = head.getValue().poll();
				if (!head.getValue().isEmpty()) {
					s.queue.put(head.getKey(), head.getValue());
				}
				if (next != null) {
					grant(s, next);
				}
			}
			changed.signalAll();
		}
		finally {
			lock.unlock();
		}
	}

	JsonObject describe() {
		lock.lock();
		try {
			JsonObject o = new JsonObject();
			long now = System.currentTimeMillis();
			for (Map.Entry<Lane, State> e : lanes.entrySet()) {
				State s = e.getValue();
				JsonArray running = new JsonArray();
				for (Ticket t : s.running) {
					running.add(Json.of("client", t.client.id, "cmd", t.cmd, "ms",
						now - t.startedAt));
				}
				o.add(e.getKey().json(),
					Json.of("slots", s.slots, "inUse", s.inUse, "queued", s.queued(), "running",
						running, "admitted", s.admitted, "everQueued", s.queuedTotal));
			}
			return o;
		}
		finally {
			lock.unlock();
		}
	}
}
