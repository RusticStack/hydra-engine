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
 * Admission control for the daemon's work, so that many clients share it fairly
 * (PROTOCOL-3.md 3.5, package E3a).
 * <p>
 * Requests are sorted into three lanes, each with a fixed number of slots:
 * <ul>
 * <li><b>quick</b> (decompile, functions, list, open, rename, ...; and, on a protocol 3
 * connection, a {@code script} that asks for {@code lane:"quick"} with a bounded
 * {@code timeout}): many slots, by default one per CPU;</li>
 * <li><b>long</b> (analyze, import, script; and, on a protocol 2 connection, save, fork_project,
 * refresh, reopen and promote_overlay): by default {@code max(8, CPUs)} slots;</li>
 * <li><b>maint</b> (protocol 3 only: save, fork_project, refresh, reopen, promote_overlay):
 * {@code maintSlots}, by default 4, so that a commit does not queue behind an analysis.</li>
 * </ul>
 * Long work can therefore never take the slots that quick queries need. When a lane is full,
 * waiting requests are admitted <b>round-robin by key</b>: the key is the connection for a
 * protocol 2 client and the connection plus the request's {@code client}/{@code harness} label
 * for a protocol 3 client, so a client that sends a hundred requests cannot starve one that
 * sends one. A <b>work-conserving per-key running cap</b> holds a key that already runs its cap
 * back, but only while another key that is under its own cap waits for the lane: a slot is never
 * left idle for the cap's sake. A request waits at most its {@code wait} and then fails with
 * {@code busy}, naming the lane and what holds it; a cancelled request leaves the queue at once.
 * <p>
 * Slots are taken before any project or program lock, and lock holders never wait for a slot, so
 * the two cannot deadlock.
 * <p>
 * The daemon's own background work (upgrade cache builds) takes long-lane slots at the lowest
 * priority: only while no client's request waits for one ({@link #admitBackground}).
 */
final class Scheduler {

	enum Lane {
		QUICK, LONG, MAINT;

		String json() {
			return name().toLowerCase();
		}
	}

	/** The lane a request goes to and, when a hint was not honoured, why. */
	record Decision(Lane lane, String note) {
	}

	/** The hard maximum of {@code quickScriptMaxS} (3.5). */
	static final int QUICK_SCRIPT_HARD_MAX_S = 120;
	static final int QUICK_SCRIPT_DEFAULT_S = 60;
	/** The lane's default {@code maintSlots} (D40; revision 5 had 2). */
	static final int DEFAULT_MAINT_SLOTS = 4;
	/** The lane's long-lane default is {@code max(8, CPUs)} (D40; revision 5 had CPUs / 4, at least 2). */
	static int defaultLongSlots(int cpus) {
		return Math.max(8, cpus);
	}

	/**
	 * Reads every lane setting once, so that a value that is not an integer is a usage error at
	 * start-up ({@link IllegalArgumentException} naming the key) and not a failure later.
	 */
	static void validateSettings() {
		for (String k : List.of("maintSlots", "maxLong", "quickScriptMaxS", "starveMs",
			"maxRunningPerKey", "maxRunningPerKey.quick", "maxRunningPerKey.long",
			"maxRunningPerKey.maint")) {
			Settings.integer(k, 0);
		}
	}

	/** The longest {@code timeout}, in seconds, a {@code lane:"quick"} script may ask for. */
	static int quickScriptMaxS() {
		int v = Settings.integer("quickScriptMaxS", QUICK_SCRIPT_DEFAULT_S);
		return Math.max(1, Math.min(QUICK_SCRIPT_HARD_MAX_S, v));
	}

	/**
	 * The lane decision of a command, or null for commands that need no slot (bookkeeping).
	 * {@code req} and {@code v3} are the seam of PROTOCOL-3.md D17 and behaviour gate 2: on a
	 * protocol 3 connection {@code save}, {@code fork_project}, {@code refresh}, {@code reopen}
	 * and {@code promote_overlay} go to {@code maint} and a {@code script} with
	 * {@code lane:"quick"} and {@code 0 < timeout <= quickScriptMaxS} goes to {@code quick};
	 * a protocol 2 connection keeps today's lanes and never sees a note.
	 */
	static Decision decide(String cmd, JsonObject req, boolean v3) {
		switch (cmd) {
			case "analyze", "import":
				return new Decision(Lane.LONG, null);
			case "script":
				return v3 ? scriptLane(req) : new Decision(Lane.LONG, null);
			case "save", "fork_project", "refresh", "reopen", "promote_overlay":
				return new Decision(v3 ? Lane.MAINT : Lane.LONG, null);
			case "list", "functions", "decompile", "rename", "comment", "open_program", "switch",
					"open_project":
				return new Decision(Lane.QUICK, null);
			default:
				return null;
		}
	}

	private static Decision scriptLane(JsonObject req) {
		com.google.gson.JsonElement hint = req == null ? null : req.get("lane");
		if (hint == null || hint.isJsonNull()) {
			return new Decision(Lane.LONG, null);
		}
		String h = hint.isJsonPrimitive() && hint.getAsJsonPrimitive().isString()
				? hint.getAsString()
				: null;
		if ("long".equals(h)) {
			return new Decision(Lane.LONG, null);
		}
		if (!"quick".equals(h)) {
			return new Decision(Lane.LONG,
				"lane must be \"quick\" or \"long\"; the script runs in the long lane");
		}
		int max = quickScriptMaxS();
		double timeout = 0;
		com.google.gson.JsonElement t = req.get("timeout");
		if (t != null && t.isJsonPrimitive() && t.getAsJsonPrimitive().isNumber()) {
			timeout = t.getAsDouble();
		}
		if (timeout <= 0) {
			return new Decision(Lane.LONG, "lane quick needs a timeout of 1 to " + max +
				" seconds; the script runs in the long lane");
		}
		if (timeout > max) {
			return new Decision(Lane.LONG, "lane quick needs a timeout of at most " + max +
				" seconds (quickScriptMaxS), not " + (long) timeout +
				"; the script runs in the long lane");
		}
		return new Decision(Lane.QUICK, null);
	}

	/** The lane of a command, or null for commands that need no slot. See {@link #decide}. */
	static Lane laneOf(String cmd, JsonObject req, boolean v3) {
		Decision d = decide(cmd, req, v3);
		return d == null ? null : d.lane();
	}

	/** The default per-key running cap of a lane with {@code slots} slots (3.5). */
	static int defaultCap(Lane lane, int slots) {
		return switch (lane) {
			case QUICK -> Math.max(1, slots / 2);
			case LONG -> Math.max(1, slots - 1);
			case MAINT -> 1;
		};
	}

	private static final int HISTORY = 20;
	private static final int ETA_MIN_COMPLETIONS = 5;
	private static final int ETA_DOMINATED_FACTOR = 5;

	private final ReentrantLock lock = new ReentrantLock();
	private final Map<Lane, State> lanes = new EnumMap<>(Lane.class);

	Scheduler(int quickSlots, int longSlots) {
		this(quickSlots, longSlots, Math.max(1, Settings.integer("maintSlots", DEFAULT_MAINT_SLOTS)));
	}

	Scheduler(int quickSlots, int longSlots, int maintSlots) {
		lanes.put(Lane.QUICK, new State(Lane.QUICK, Math.max(1, quickSlots), lock.newCondition()));
		lanes.put(Lane.LONG, new State(Lane.LONG, Math.max(1, longSlots), lock.newCondition()));
		lanes.put(Lane.MAINT, new State(Lane.MAINT, Math.max(1, maintSlots), lock.newCondition()));
		// what a protocol 3 hello reports (3.2); the other packages enable their own
		Advertised.capability("laneHint", 1);
		Advertised.capability("maintLane", 1);
		Advertised.capability("queueInfo", 1);
		Requests.registerPreflight();
	}

	/** The slots of a lane, for {@code hello.limits}. */
	int slots(Lane lane) {
		return lanes.get(lane).slots;
	}

	/** How often the waiters of {@code lane} were woken (the self-test of the per-lane wake-up). */
	long signals(Lane lane) {
		lock.lock();
		try {
			return lanes.get(lane).signals;
		}
		finally {
			lock.unlock();
		}
	}

	/** The per-key running caps, for {@code hello.limits.maxRunningPerKey}. */
	JsonObject caps() {
		JsonObject o = new JsonObject();
		for (Lane l : Lane.values()) {
			o.addProperty(l.json(), lanes.get(l).cap);
		}
		return o;
	}

	private static final class State {
		final Lane lane;
		final int slots;
		/** Most requests of one key that run at once while another key waits under its own cap. */
		final int cap;
		/**
		 * Signalled when this lane changes (a slot freed, a waiter left): only this lane's waiters
		 * wake, a release in one lane does not wake the waiters of the others (PROTOCOL-3.md 8.18).
		 */
		final Condition changed;
		/** How often this lane's waiters were signalled (the self-test of the per-lane wake-up). */
		long signals;
		int inUse;
		/** Waiting tickets by key; iteration order is the round-robin order. */
		final LinkedHashMap<String, ArrayDeque<Ticket>> queue = new LinkedHashMap<>();
		final Set<Ticket> running = new LinkedHashSet<>();
		/** How many tickets of each key hold a slot now. */
		final Map<String, Integer> runningByKey = new HashMap<>();
		/** Background tickets waiting, oldest first: admitted only when no client waits. */
		final ArrayDeque<Ticket> background = new ArrayDeque<>();
		/** The hold times (ms) of the last {@link Scheduler#HISTORY} finished tickets. */
		final ArrayDeque<Long> holds = new ArrayDeque<>();
		long admitted;
		long queuedTotal;
		long completions;

		State(Lane lane, int slots, Condition changed) {
			this.lane = lane;
			this.slots = slots;
			this.changed = changed;
			int c = defaultCap(lane, slots);
			c = Settings.integer("maxRunningPerKey", c);
			c = Settings.integer("maxRunningPerKey." + lane.json(), c);
			this.cap = Math.max(1, c);
		}

		int queued() {
			int n = 0;
			for (ArrayDeque<Ticket> q : queue.values()) {
				n += q.size();
			}
			return n;
		}

		int runningOf(String key) {
			return runningByKey.getOrDefault(key, 0);
		}
	}

	/** One admitted request; closing it frees its slot. */
	final class Ticket implements AutoCloseable {
		final Lane lane;
		final Client client;
		final String cmd;
		/** The fair key: the connection, plus the request's label for a protocol 3 connection. */
		final String key;
		/** Who asked, named the way the request names itself (its own labels, if any). */
		final String who;
		final long queuedAt = System.currentTimeMillis();
		long startedAt;
		boolean granted;
		private boolean closed;

		Ticket(Lane lane, Client client, String cmd, String key) {
			this.lane = lane;
			this.client = client;
			this.cmd = cmd;
			this.key = key;
			this.who = Caller.label(client);
		}

		@Override
		public void close() {
			release(this);
		}

		String describe() {
			return who + " " + cmd;
		}

		/**
		 * Gives the slot back while this request blocks on something else, so that another key
		 * can use it (PROTOCOL-3.md D39). Inert: nothing calls it until E3c wires it behind the
		 * setting {@code yieldSlots}. The ticket stays valid; {@link #reacquire} takes a slot
		 * again, and closing it afterwards (or without) is correct either way.
		 */
		void yieldSlot() {
			Scheduler.this.yieldTicket(this);
		}

		/**
		 * Waits for a slot again after {@link #yieldSlot}, at the front of its key's queue.
		 *
		 * @throws SessionException {@code busy} after {@code waitMs}, {@code cancelled} on cancel
		 */
		void reacquire(RequestMonitor m, long waitMs) {
			Scheduler.this.reacquire(this, m, waitMs);
		}
	}

	/** The ticket of the request this thread executes (set by {@link Session#execute}), or null. */
	private static final ThreadLocal<Ticket> BOUND = new ThreadLocal<>();

	/** Binds (or, with null, unbinds) the ticket of the request this thread executes. */
	static void bind(Ticket t) {
		if (t == null) {
			BOUND.remove();
		}
		else {
			BOUND.set(t);
		}
	}

	/** The ticket of the request this thread executes, or null. */
	static Ticket bound() {
		return BOUND.get();
	}

	/** The fair key of a request of {@code c}: its connection id, plus the label for protocol 3. */
	private static String keyOf(Client c) {
		if (!c.v3()) {
			return Integer.toString(c.id);
		}
		Caller.Identity id = Caller.current(c);
		String scope = id == null ? null : id.scope();
		return scope == null ? Integer.toString(c.id) : c.id + "/" + scope;
	}

	/** Longest a wait is allowed to be, in milliseconds: 30 days stands for "no limit". */
	static final long UNLIMITED_MS = 30L * 86_400_000L;

	private static long deadlineNanos(long waitMs) {
		return System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.min(waitMs, UNLIMITED_MS));
	}

	/**
	 * Waits for a slot in the command's lane. Returns null when the command needs none.
	 * {@code req} is the request that asked: it carries the lane hint (read here) and, for a
	 * protocol 3 client whose request would have to queue, the fields {@link Preflight} validates
	 * before the wait.
	 *
	 * @throws SessionException {@code busy} after {@code waitMs}, {@code cancelled} on cancel,
	 *             {@code bad_request} (protocol 3, queueing request) from the preflight
	 */
	Ticket admit(Client c, String cmd, JsonObject req, RequestMonitor m, long waitMs) {
		Decision decision = decide(cmd, req, c.v3());
		if (decision == null) {
			return null;
		}
		Lane lane = decision.lane();
		if (m != null) {
			m.lane(lane.json(), decision.note());
		}
		if (c.v3() && wouldQueue(lane)) {
			// validate before waiting: a bad request fails now, not after its wait (G4)
			Preflight.run(cmd, req);
		}
		lock.lock();
		try {
			State s = lanes.get(lane);
			Ticket t = new Ticket(lane, c, cmd, keyOf(c));
			if (s.inUse < s.slots && s.queue.isEmpty()) {
				grant(s, t);
				return t;
			}
			enqueue(s, t, false);
			awaitGrant(s, t, m, waitMs);
			return t;
		}
		finally {
			if (m != null) {
				m.waiting(null);
			}
			lock.unlock();
		}
	}

	private boolean wouldQueue(Lane lane) {
		lock.lock();
		try {
			State s = lanes.get(lane);
			return !(s.inUse < s.slots && s.queue.isEmpty());
		}
		finally {
			lock.unlock();
		}
	}

	/** Called with the lock held. */
	private void enqueue(State s, Ticket t, boolean front) {
		s.queuedTotal++;
		ArrayDeque<Ticket> q = s.queue.computeIfAbsent(t.key, k -> new ArrayDeque<>());
		if (front) {
			q.addFirst(t);
		}
		else {
			q.add(t);
		}
	}

	/** How often a v3 waiter recomputes its queue details (the pace of the progress event). */
	private static final long INFO_INTERVAL_NANOS = 1_000_000_000L;

	/**
	 * Called with the lock held: waits until {@code t} is granted. Throws {@code cancelled} or
	 * {@code busy} after taking {@code t} out of the queue.
	 */
	private void awaitGrant(State s, Ticket t, RequestMonitor m, long waitMs) {
		boolean v3 = t.client.v3();
		long deadline = deadlineNanos(waitMs);
		long t0 = System.nanoTime();
		String what = s.lane.json() + " slot";
		if (m != null && !v3) {
			m.waiting(what);
		}
		// the queue details (a copy of every queue, under the scheduler lock) are recomputed at the
		// pace of the progress event, not at every 100 ms wake-up: N waiters would otherwise copy
		// N queues N times a second
		long nextInfo = t0;
		try {
			while (!t.granted) {
				if (m != null && v3 && System.nanoTime() - nextInfo >= 0) {
					JsonObject q = queueInfo(s, t);
					String text = "waiting for a " + s.lane.json() + " slot (position " +
						q.get("position") + ", " + q.get("ahead") + " ahead" + etaText(q) + ")";
					// the progress event is written to the client's socket: never under the
					// scheduler lock, which every admission and release takes
					lock.unlock();
					try {
						m.waiting(what, q);
						m.queueSeen(q);
						m.setMessage(text);
					}
					finally {
						lock.lock();
					}
					nextInfo = System.nanoTime() + INFO_INTERVAL_NANOS;
					if (t.granted) {
						break;
					}
				}
				if (m != null && m.isCancelled()) {
					dequeue(s, t);
					throw new SessionException(SessionException.CANCELLED,
						"cancelled while queued for a " + s.lane.json() + " slot");
				}
				long left = deadline - System.nanoTime();
				if (left <= 0) {
					JsonObject queue = v3 ? queueInfo(s, t) : null;
					dequeue(s, t);
					JsonObject d = Json.of("lane", s.lane.json(), "slots", s.slots, "queued",
						s.queued(), "waitedMs", waitMs);
					List<String> holders = new ArrayList<>();
					s.running.forEach(r -> holders.add(r.describe()));
					Json.put(d, "running", holders);
					d = SessionException.busyDetails(v3, d, "slot_wait", queue, null);
					SessionException ex = new SessionException(SessionException.BUSY,
						"all " + s.slots + " " + s.lane.json() + " slots are in use (" +
							String.join(", ", holders) + "); retry, or pass a longer \"wait\"",
						d);
					if (v3) {
						ex.withRetryAfterMs(retryAfterMs(s));
					}
					throw ex;
				}
				try {
					s.changed.awaitNanos(Math.min(left, TimeUnit.MILLISECONDS.toNanos(100)));
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					dequeue(s, t);
					throw new SessionException(SessionException.CANCELLED, "interrupted");
				}
			}
		}
		finally {
			long waited = (System.nanoTime() - t0) / 1_000_000;
			if (m != null) {
				m.waited("slot", waited);
				if (v3) {
					m.waiting(null, null);
					m.clearMessage();
				}
			}
		}
	}

	private static String etaText(JsonObject q) {
		return q.has("estimatedWaitMs") && !q.get("estimatedWaitMs").isJsonNull()
				? ", about " + Math.max(1, q.get("estimatedWaitMs").getAsLong() / 1000) + " s"
				: "";
	}

	/**
	 * Waits, without a deadline, for a slot in the long lane for the daemon's own background work
	 * (building upgrade cache copies). It is admitted only while no client's request waits for
	 * that lane, so it never delays one: clients' requests are granted first, and the quick lane
	 * is never touched.
	 *
	 * @throws SessionException {@code cancelled} when {@code m} is cancelled while it waits
	 */
	Ticket admitBackground(Client c, String what, RequestMonitor m) {
		lock.lock();
		try {
			State s = lanes.get(Lane.LONG);
			Ticket t = new Ticket(Lane.LONG, c, what, "background");
			s.background.add(t);
			while (true) {
				if (s.inUse < s.slots && s.queue.isEmpty() && s.background.peek() == t) {
					s.background.poll();
					grant(s, t);
					return t;
				}
				if (m.isCancelled()) {
					s.background.remove(t);
					signal(s);
					throw new SessionException(SessionException.CANCELLED,
						"cancelled while queued for a background slot");
				}
				try {
					s.changed.awaitNanos(TimeUnit.MILLISECONDS.toNanos(100));
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					s.background.remove(t);
					throw new SessionException(SessionException.CANCELLED, "interrupted");
				}
			}
		}
		finally {
			lock.unlock();
		}
	}

	/** Called with the lock held: wakes the waiters of {@code s}'s lane, and only those. */
	private static void signal(State s) {
		s.signals++;
		s.changed.signalAll();
	}

	private void grant(State s, Ticket t) {
		t.granted = true;
		t.startedAt = System.currentTimeMillis();
		s.inUse++;
		s.admitted++;
		s.running.add(t);
		s.runningByKey.merge(t.key, 1, Integer::sum);
	}

	private void dequeue(State s, Ticket t) {
		ArrayDeque<Ticket> q = s.queue.get(t.key);
		if (q != null) {
			q.remove(t);
			if (q.isEmpty()) {
				s.queue.remove(t.key);
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
			if (!t.granted) {
				return; // yielded and never reacquired: it holds no slot
			}
			State s = lanes.get(t.lane);
			free(s, t, true);
			handOver(s);
			signal(s);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	* Called with the lock held: {@code t} stops holding its slot. {@code completed} is false for a
	* yield (PROTOCOL-3.md D39): the request is not finished, so neither its hold time nor a
	* completion is recorded (they feed the median behind the queue estimates); the final release
	* records the last stretch.
	*/
	private void free(State s, Ticket t, boolean completed) {
		t.granted = false;
		s.inUse--;
		s.running.remove(t);
		s.runningByKey.computeIfPresent(t.key, (k, n) -> n <= 1 ? null : n - 1);
		if (!completed) {
			return;
		}
		long held = Math.max(0, System.currentTimeMillis() - t.startedAt);
		s.holds.addLast(held);
		while (s.holds.size() > HISTORY) {
			s.holds.pollFirst();
		}
		s.completions++;
	}

	/**
	 * Called with the lock held: grants free slots to waiting tickets in round-robin order, taking
	 * the first key that is under its running cap and, only when every waiting key has reached
	 * its cap, the first key (a slot is never left idle for the cap's sake).
	 */
	private void handOver(State s) {
		while (s.inUse < s.slots && !s.queue.isEmpty()) {
			Map.Entry<String, ArrayDeque<Ticket>> pick = null;
			for (Map.Entry<String, ArrayDeque<Ticket>> e : s.queue.entrySet()) {
				if (s.runningOf(e.getKey()) < s.cap) {
					pick = e;
					break;
				}
			}
			if (pick == null) {
				pick = s.queue.entrySet().iterator().next();
			}
			String key = pick.getKey();
			ArrayDeque<Ticket> dq = pick.getValue();
			s.queue.remove(key);
			Ticket next = dq.poll();
			if (!dq.isEmpty()) {
				s.queue.put(key, dq); // to the back of the round
			}
			if (next != null) {
				grant(s, next);
			}
		}
	}

	private void yieldTicket(Ticket t) {
		lock.lock();
		try {
			if (t.closed || !t.granted) {
				return;
			}
			State s = lanes.get(t.lane);
			free(s, t, false); // a yield records no hold time and no completion (E3a review)
			handOver(s);
			signal(s);
		}
		finally {
			lock.unlock();
		}
	}

	private void reacquire(Ticket t, RequestMonitor m, long waitMs) {
		lock.lock();
		try {
			if (t.closed || t.granted) {
				return;
			}
			State s = lanes.get(t.lane);
			if (s.inUse < s.slots && s.queue.isEmpty()) {
				grant(s, t);
				return;
			}
			enqueue(s, t, true);
			awaitGrant(s, t, m, waitMs);
		}
		finally {
			lock.unlock();
		}
	}

	// ---- queue information ----------------------------------------------------------------

	/**
	 * Called with the lock held: the waiting tickets of a lane in the order they would be served
	 * (round-robin by key, the running caps left out: an estimate, never a promise).
	 */
	private static List<Ticket> serviceOrder(State s) {
		List<ArrayDeque<Ticket>> rounds = new ArrayList<>();
		for (ArrayDeque<Ticket> q : s.queue.values()) {
			rounds.add(new ArrayDeque<>(q));
		}
		List<Ticket> out = new ArrayList<>();
		while (!rounds.isEmpty()) {
			Iterator<ArrayDeque<Ticket>> it = rounds.iterator();
			List<ArrayDeque<Ticket>> next = new ArrayList<>();
			while (it.hasNext()) {
				ArrayDeque<Ticket> q = it.next();
				out.add(q.poll());
				if (!q.isEmpty()) {
					next.add(q);
				}
			}
			rounds = next;
		}
		return out;
	}

	private static long median(Collection<Long> values) {
		if (values.isEmpty()) {
			return 0;
		}
		long[] a = values.stream().mapToLong(Long::longValue).sorted().toArray();
		return a[a.length / 2];
	}

	/**
	 * Called with the lock held: the estimated wait in milliseconds for a ticket with {@code ahead}
	 * tickets in front, or null. Null until the lane has recorded {@value #ETA_MIN_COMPLETIONS}
	 * completions, and again when a running holder has run longer than five times the median (the
	 * lane is dominated by one long job and the median says nothing). Crude on purpose: the long
	 * lane mixes 100 ms scripts and hour-long analyses.
	 */
	private static Long etaMs(State s, int ahead) {
		if (s.completions < ETA_MIN_COMPLETIONS) {
			return null;
		}
		long med = median(s.holds);
		long now = System.currentTimeMillis();
		for (Ticket r : s.running) {
			if (now - r.startedAt > ETA_DOMINATED_FACTOR * med) {
				return null;
			}
		}
		long rounds = (ahead + 1 + s.slots - 1) / s.slots;
		return rounds * med;
	}

	/** Called with the lock held: the {@code queue} object of 3.4 for a waiting ticket. */
	private JsonObject queueInfo(State s, Ticket t) {
		int ahead = Math.max(0, serviceOrder(s).indexOf(t));
		return queueObject(s, ahead);
	}

	private static JsonObject queueObject(State s, int ahead) {
		JsonObject o = Json.of("lane", s.lane.json(), "position", ahead + 1, "ahead", ahead);
		Long eta = etaMs(s, ahead);
		o.add("estimatedWaitMs", eta == null ? com.google.gson.JsonNull.INSTANCE
				: new com.google.gson.JsonPrimitive(eta));
		o.addProperty("estimate", true);
		return o;
	}

	/**
	* How many requests of {@code lane} have completed and how many hold times it has recorded (the
	* two are equal): a yielded ticket adds neither (self-test and tests).
	*/
	int[] recorded(Lane lane) {
		lock.lock();
		try {
			State s = lanes.get(lane);
			return new int[] { (int) s.completions, s.holds.size() };
		}
		finally {
			lock.unlock();
		}
	}

	/** {@code error.retryAfterMs} of a slot-wait {@code busy}: the lane's median hold time. */
	private static long retryAfterMs(State s) {
		return s.holds.isEmpty() ? 1000 : median(s.holds);
	}

	// ---- status -----------------------------------------------------------------------------

	/**
	 * The {@code status.scheduler} object. A protocol 2 connection gets today's object (quick and
	 * long, the same keys, the same order) under the unconditional scheduler lock. A protocol 3
	 * connection (reply conditional C2) also gets the {@code maint} lane, per waiting request the
	 * {@code position} and {@code estimatedWaitMs}, per lane {@code oldestWaitMs},
	 * {@code longestRunningMs}, {@code starving}, {@code perKeyCap} and the per-key counts, and
	 * {@code {"unavailable":true,"waitedMs":250}} when the scheduler lock could not be taken in
	 * 250 ms (behaviour gate 5, so that {@code status} can still answer).
	 */
	JsonObject describe(boolean v3) {
		if (v3) {
			boolean got;
			try {
				got = lock.tryLock(250, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				got = false;
			}
			if (!got) {
				return Json.of("unavailable", true, "waitedMs", 250);
			}
		}
		else {
			lock.lock();
		}
		try {
			JsonObject o = new JsonObject();
			long now = System.currentTimeMillis();
			long starveMs = Settings.integer("starveMs", 30_000);
			for (Map.Entry<Lane, State> e : lanes.entrySet()) {
				if (e.getKey() == Lane.MAINT && !v3) {
					continue;
				}
				State s = e.getValue();
				JsonArray running = new JsonArray();
				long longest = 0;
				for (Ticket t : s.running) {
					running.add(Json.of("client", t.client.id, "who", t.who, "cmd", t.cmd, "ms",
						now - t.startedAt));
					longest = Math.max(longest, now - t.startedAt);
				}
				JsonArray waiting = new JsonArray();
				long oldest = 0;
				if (v3) {
					List<Ticket> order = serviceOrder(s);
					for (int i = 0; i < order.size(); i++) {
						Ticket t = order.get(i);
						JsonObject w = Json.of("client", t.client.id, "who", t.who, "cmd", t.cmd,
							"waitedMs", now - t.queuedAt);
						w.addProperty("position", i + 1);
						Long eta = etaMs(s, i);
						w.add("estimatedWaitMs", eta == null ? com.google.gson.JsonNull.INSTANCE
								: new com.google.gson.JsonPrimitive(eta));
						waiting.add(w);
						oldest = Math.max(oldest, now - t.queuedAt);
					}
				}
				else {
					for (ArrayDeque<Ticket> q : s.queue.values()) {
						for (Ticket t : q) {
							waiting.add(Json.of("client", t.client.id, "who", t.who, "cmd", t.cmd,
								"waitedMs", now - t.queuedAt));
						}
					}
				}
				JsonObject lane = Json.of("slots", s.slots, "inUse", s.inUse, "queued", s.queued(),
					"running", running, "waiting", waiting, "admitted", s.admitted, "everQueued",
					s.queuedTotal, "backgroundQueued", s.background.size());
				if (v3) {
					lane.addProperty("oldestWaitMs", oldest);
					lane.addProperty("longestRunningMs", longest);
					lane.addProperty("starving", s.queued() > 0 && oldest > starveMs);
					lane.addProperty("perKeyCap", s.cap);
					lane.add("perKey", perKey(s));
				}
				o.add(e.getKey().json(), lane);
			}
			return o;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * The lane figures of {@code health.lanes} (PROTOCOL-3.md 3.4): per lane {@code inUse},
	 * {@code queued}, {@code oldestWaitMs}, {@code longestRunningMs} and {@code starving}
	 * ({@code queued > 0} and the oldest wait above {@code starveMs}, default 30 s). Takes the
	 * scheduler lock with {@code tryLock(waitMs)} and returns null when it could not: the caller
	 * (the watchdog) then reports {@code schedulerLockOk:false} instead of waiting. Lane figures
	 * are informational, never a verdict on a long request.
	 */
	JsonObject healthLanes(long waitMs) {
		try {
			if (!lock.tryLock(waitMs, TimeUnit.MILLISECONDS)) {
				return null;
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return null;
		}
		try {
			long now = System.currentTimeMillis();
			long starveMs = Settings.integer("starveMs", 30_000);
			JsonObject o = new JsonObject();
			for (Map.Entry<Lane, State> e : lanes.entrySet()) {
				State s = e.getValue();
				long longest = 0;
				for (Ticket t : s.running) {
					longest = Math.max(longest, now - t.startedAt);
				}
				long oldest = 0;
				for (ArrayDeque<Ticket> q : s.queue.values()) {
					for (Ticket t : q) {
						oldest = Math.max(oldest, now - t.queuedAt);
					}
				}
				int queued = s.queued();
				o.add(e.getKey().json(), Json.of("inUse", s.inUse, "queued", queued,
					"oldestWaitMs", oldest, "longestRunningMs", longest, "starving",
					queued > 0 && oldest > starveMs));
			}
			return o;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * The test hook behind {@code debug_stall what:"scheduler"} (D22): a daemon thread takes the
	 * scheduler lock and holds it for {@code ms}, so that {@code health} reports
	 * {@code schedulerLockOk:false} and a protocol 2 {@code status} blocks while a protocol 3 one
	 * answers {@code unavailable}. Returns once the lock is held. Callable only with
	 * {@code -Dghidra.session.testHooks=true}.
	 */
	void stallForTest(long ms) {
		if (!Health.testHooks()) {
			throw new IllegalStateException("test hooks are off");
		}
		java.util.concurrent.CountDownLatch held = new java.util.concurrent.CountDownLatch(1);
		Thread t = new Thread(() -> {
			lock.lock();
			try {
				held.countDown();
				Thread.sleep(ms);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			finally {
				lock.unlock();
			}
		}, "session-debug-stall");
		t.setDaemon(true);
		t.start();
		try {
			held.await();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	/** Called with the lock held: how many requests of each key run and wait in a lane. */
	private static JsonArray perKey(State s) {
		Map<String, JsonObject> keys = new LinkedHashMap<>();
		for (Ticket t : s.running) {
			keys.computeIfAbsent(t.key, k -> keyEntry(t)).addProperty("running",
				keys.get(t.key).get("running").getAsInt() + 1);
		}
		for (ArrayDeque<Ticket> q : s.queue.values()) {
			for (Ticket t : q) {
				keys.computeIfAbsent(t.key, k -> keyEntry(t)).addProperty("queued",
					keys.get(t.key).get("queued").getAsInt() + 1);
			}
		}
		JsonArray a = new JsonArray();
		keys.values().forEach(a::add);
		return a;
	}

	private static JsonObject keyEntry(Ticket t) {
		return Json.of("client", t.client.id, "who", t.who, "running", 0, "queued", 0);
	}
}
