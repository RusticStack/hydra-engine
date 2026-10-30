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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * The decompile results of unchanged programs, shared by every connection (goal 4 of the Rust
 * plan, "caching results of sealed data").
 * <p>
 * A result is keyed by the identity of the program <b>object</b> (a shared program, an overlay
 * and a reopened program are different objects and never share an entry), its modification
 * number, the function's entry and the hash of the decompiler set-up
 * ({@link ProgramEntry#DECOMPILER_SETUP}). Every change of a Ghidra program goes through
 * {@code fireEvent}, which increments the modification number, so an entry of a changed program
 * is never served again; the older entries of a program are dropped when its first newer one is
 * stored. A result is stored only when the modification number is the same before and after the
 * decompile, and only a completed decompile is stored (a failure is answered fresh every time).
 * <p>
 * N callers asking for the same key at once trigger one decompile (single flight): the first is
 * the leader, the others wait for its outcome. A failure of the leader (a timeout, a crash, a
 * declined function) is handed to all of its waiters at once and not stored (the caller decides
 * whether a waiter answers the same or decompiles itself, in parallel with the others); only a
 * cancelled leader makes the next waiter lead. A waiter waits no longer than its own budget. The
 * memory is bounded by a size-based LRU of {@code decompileCache} bytes (default: 1/32 of the
 * heap, at most 256 MB; off when that is below 8 MB, or with {@code -set decompileCache=0}).
 */
final class DecompileCache {

	/** How a flight ended: a {@link Result} or a {@link Failure}. */
	sealed interface Outcome permits Result, Failure {
	}

	/**
	 * A decompile that ended without a result (a timeout, a crash, a function the decompiler
	 * declines): handed to the callers that joined that flight, never stored. {@code payload} is
	 * the caller's description of the failure, opaque here.
	 */
	record Failure(Object payload) implements Outcome {
	}

	/** {@link #compute} gave up waiting for another caller's decompile at its deadline. */
	static final Failure WAIT_EXPIRED =
		new Failure("the wait for another caller's decompile expired");

	/** What one decompile answered: the signature and the full C text. */
	record Result(String signature, String c) implements Outcome {
		long weight() {
			// two object headers, two strings (Latin-1 or UTF-16), the key and the map entry
			return 160 + 2L * (signature.length() + c.length());
		}
	}

	/** The cache key: program object, modification number, entry and decompiler set-up. */
	record Key(long program, long modification, int space, long offset, int setup) {
	}

	static final long FLOOR_BYTES = 8L << 20;
	static final long CEILING_BYTES = 256L << 20;

	private static volatile DecompileCache instance;

	/** The daemon's cache, made on first use from the settings (null when it is off). */
	static DecompileCache get() {
		DecompileCache c = instance;
		if (c == null) {
			synchronized (DecompileCache.class) {
				c = instance;
				if (c == null) {
					c = new DecompileCache(Budgets.decompileCacheBytes());
					instance = c;
					DecompileCache made = c;
					Health.contribute("decompileCache", made::describe);
				}
			}
		}
		return c.budget > 0 ? c : null;
	}

	/** The default budget for a heap of {@code heapBytes}: 1/32, at most 256 MB, 0 below 8 MB. */
	static long defaultBytes(long heapBytes) {
		long b = Math.min(CEILING_BYTES, heapBytes / 32);
		return b < FLOOR_BYTES ? 0 : b;
	}

	private final long budget;
	// guarded by this
	private final LinkedHashMap<Key, Result> lru = new LinkedHashMap<>(256, 0.75f, true);
	private long bytes;
	/**
	 * Per program token with entries in {@link #lru}: {newest modification number stored, number
	 * of entries}. A token leaves the map with its last entry, so the map is bounded by the LRU.
	 */
	private final Map<Long, long[]> programs = new HashMap<>();

	private final ConcurrentHashMap<Key, CompletableFuture<Outcome>> inflight =
		new ConcurrentHashMap<>();

	/** Program object to token; weak so the cache never keeps a closed program alive. */
	private final Map<Program, Long> tokens = new WeakHashMap<>();
	private final AtomicLong nextToken = new AtomicLong(1);

	private final AtomicLong hits = new AtomicLong();
	private final AtomicLong misses = new AtomicLong();
	private final AtomicLong joined = new AtomicLong();
	private final AtomicLong evicted = new AtomicLong();
	private final AtomicLong dropped = new AtomicLong();
	private final AtomicLong unstored = new AtomicLong();
	private final AtomicLong shared = new AtomicLong();
	private final AtomicLong expired = new AtomicLong();

	DecompileCache(long budget) {
		this.budget = budget;
	}

	long budget() {
		return budget;
	}

	/** The key of {@code f} in {@code p} as the program stands now. */
	Key key(Program p, Function f) {
		long t;
		synchronized (tokens) {
			t = tokens.computeIfAbsent(p, x -> nextToken.getAndIncrement());
		}
		Address a = f.getEntryPoint();
		return new Key(t, p.getModificationNumber(), a.getAddressSpace().getSpaceID(),
			a.getOffset(), ProgramEntry.DECOMPILER_SETUP);
	}

	/**
	 * The outcome of {@code k}: from the cache, from the flight of a concurrent leader, or from
	 * {@code work} run by this caller as the leader.
	 * <p>
	 * {@code work} returns a {@link Result} (stored when {@code modificationNow} still equals the
	 * key's), a {@link Failure} (handed to every caller that joined this flight, all at once, and
	 * not stored), or null / throws when the leader was cancelled: then one waiter leads again.
	 * A waiter waits at most {@code waitNanos} (its own budget); then it gets
	 * {@link #WAIT_EXPIRED}.
	 *
	 * @return the outcome, or null when {@code cancelled} turned true while this caller waited
	 *         (or this caller led and {@code work} returned null)
	 */
	Outcome compute(Key k, BooleanSupplier cancelled, long waitNanos,
			LongSupplier modificationNow, Supplier<Outcome> work) {
		long deadline = System.nanoTime() + Math.max(0, waitNanos);
		while (true) {
			Result r = cached(k);
			if (r != null) {
				hits.incrementAndGet();
				return r;
			}
			CompletableFuture<Outcome> mine = new CompletableFuture<>();
			CompletableFuture<Outcome> other = inflight.putIfAbsent(k, mine);
			if (other == null) {
				return lead(k, mine, modificationNow, work);
			}
			joined.incrementAndGet();
			Outcome o;
			while (true) {
				long left = deadline - System.nanoTime();
				if (left <= 0) {
					expired.incrementAndGet();
					return WAIT_EXPIRED;
				}
				try {
					o = other.get(Math.min(left, 50_000_000L), TimeUnit.NANOSECONDS);
					break;
				}
				catch (TimeoutException e) {
					if (cancelled.getAsBoolean()) {
						return null;
					}
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return null;
				}
				catch (ExecutionException e) {
					o = null;
					break;
				}
			}
			if (o != null) {
				if (o instanceof Failure) {
					shared.incrementAndGet();
				}
				return o; // a result, or the failure of this flight: every waiter gets it at once
			}
			if (cancelled.getAsBoolean()) {
				return null;
			}
			// the leader was cancelled: try again (this caller may lead now)
		}
	}

	private Outcome lead(Key k, CompletableFuture<Outcome> mine, LongSupplier modificationNow,
			Supplier<Outcome> work) {
		Outcome o = null;
		try {
			// a leader that finished between the lookup and putIfAbsent stored its result already
			Result c = cached(k);
			if (c != null) {
				hits.incrementAndGet();
				o = c;
				return c;
			}
			misses.incrementAndGet();
			o = work.get();
			if (o instanceof Result r) {
				offer(k, r, modificationNow);
			}
			return o;
		}
		finally {
			inflight.remove(k, mine);
			mine.complete(o);
		}
	}

	/** Stores {@code r} of {@code k} when the program is still at the key's modification. */
	void offer(Key k, Result r, LongSupplier modificationNow) {
		if (modificationNow.getAsLong() == k.modification()) {
			store(k, r);
		}
		else {
			unstored.incrementAndGet();
		}
	}

	private synchronized Result cached(Key k) {
		return lru.get(k);
	}

	private void forget(Key k, Result r) {
		bytes -= r.weight();
		long[] p = programs.get(k.program());
		if (p != null && --p[1] <= 0) {
			programs.remove(k.program());
		}
	}

	private synchronized void store(Key k, Result r) {
		long w = r.weight();
		if (w > budget / 8) {
			unstored.incrementAndGet();
			return;
		}
		long[] p = programs.get(k.program());
		if (p != null && p[0] > k.modification()) {
			unstored.incrementAndGet();
			return; // the program changed since: this result can never be asked for again
		}
		if (p != null && p[0] < k.modification()) {
			// the program changed: its older entries are unreachable, drop them now
			Iterator<Map.Entry<Key, Result>> it = lru.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Key, Result> e = it.next();
				if (e.getKey().program() == k.program() &&
					e.getKey().modification() < k.modification()) {
					it.remove();
					forget(e.getKey(), e.getValue());
					dropped.incrementAndGet();
				}
			}
		}
		p = programs.computeIfAbsent(k.program(), x -> new long[2]);
		p[0] = k.modification();
		Result old = lru.put(k, r);
		if (old != null) {
			bytes -= old.weight();
		}
		else {
			p[1]++;
		}
		bytes += w;
		Iterator<Map.Entry<Key, Result>> it = lru.entrySet().iterator();
		while (bytes > budget && it.hasNext()) {
			Map.Entry<Key, Result> e = it.next();
			it.remove();
			forget(e.getKey(), e.getValue());
			evicted.incrementAndGet();
		}
	}

	/** The program tokens with entries (bounded by the entries: none leaks). */
	synchronized int programs() {
		return programs.size();
	}

	synchronized int entries() {
		return lru.size();
	}

	synchronized long bytes() {
		return bytes;
	}

	long hits() {
		return hits.get();
	}

	long misses() {
		return misses.get();
	}

	long joined() {
		return joined.get();
	}

	/** {@code health.decompileCache}. */
	com.google.gson.JsonObject describe() {
		com.google.gson.JsonObject o;
		synchronized (this) {
			o = Json.of("budgetBytes", budget, "bytes", bytes, "entries", lru.size());
		}
		Json.put(o, "hits", hits.get());
		Json.put(o, "misses", misses.get());
		Json.put(o, "joined", joined.get());
		Json.put(o, "evicted", evicted.get());
		Json.put(o, "dropped", dropped.get());
		Json.put(o, "unstored", unstored.get());
		Json.put(o, "sharedFailures", shared.get());
		Json.put(o, "waitsExpired", expired.get());
		Json.put(o, "inflight", inflight.size());
		return o;
	}
}
