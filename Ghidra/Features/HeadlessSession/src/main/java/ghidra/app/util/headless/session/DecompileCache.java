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
 * the leader, the others wait for its result; when the leader fails or is cancelled the next
 * waiter leads. The memory is bounded by a size-based LRU of {@code decompileCache} bytes
 * (default: 1/32 of the heap, at most 256 MB; off when that is below 8 MB, or with
 * {@code -set decompileCache=0}).
 */
final class DecompileCache {

	/** What one decompile answered: the signature and the full C text. */
	record Result(String signature, String c) {
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
	/** The newest modification number stored per program token. */
	private final Map<Long, Long> newest = new HashMap<>();

	private final ConcurrentHashMap<Key, CompletableFuture<Result>> inflight =
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
	 * The result of {@code k}: from the cache, from a concurrent leader, or from {@code work} run
	 * by this caller as the leader. {@code work} returns null when the decompile did not complete;
	 * its result is stored only when {@code modificationNow} still equals the key's.
	 *
	 * @return the result, or null when this caller led and {@code work} returned null, or when
	 *         {@code cancelled} turned true while it waited
	 */
	Result compute(Key k, BooleanSupplier cancelled, LongSupplier modificationNow,
			Supplier<Result> work) {
		while (true) {
			Result r = cached(k);
			if (r != null) {
				hits.incrementAndGet();
				return r;
			}
			CompletableFuture<Result> mine = new CompletableFuture<>();
			CompletableFuture<Result> other = inflight.putIfAbsent(k, mine);
			if (other == null) {
				return lead(k, mine, modificationNow, work);
			}
			joined.incrementAndGet();
			while (true) {
				try {
					r = other.get(50, TimeUnit.MILLISECONDS);
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
					r = null;
					break;
				}
			}
			if (r != null) {
				return r;
			}
			if (cancelled.getAsBoolean()) {
				return null;
			}
			// the leader failed or was cancelled: try again (this caller may lead now)
		}
	}

	private Result lead(Key k, CompletableFuture<Result> mine, LongSupplier modificationNow,
			Supplier<Result> work) {
		Result r = null;
		try {
			// a leader that finished between the lookup and putIfAbsent stored its result already
			r = cached(k);
			if (r != null) {
				hits.incrementAndGet();
				return r;
			}
			misses.incrementAndGet();
			r = work.get();
			if (r != null) {
				if (modificationNow.getAsLong() == k.modification()) {
					store(k, r);
				}
				else {
					unstored.incrementAndGet();
				}
			}
			return r;
		}
		finally {
			inflight.remove(k, mine);
			mine.complete(r);
		}
	}

	private synchronized Result cached(Key k) {
		return lru.get(k);
	}

	private synchronized void store(Key k, Result r) {
		long w = r.weight();
		if (w > budget / 8) {
			unstored.incrementAndGet();
			return;
		}
		Long prev = newest.get(k.program());
		if (prev != null && prev > k.modification()) {
			unstored.incrementAndGet();
			return; // the program changed since: this result can never be asked for again
		}
		if (prev != null && prev < k.modification()) {
			// the program changed: its older entries are unreachable, drop them now
			Iterator<Map.Entry<Key, Result>> it = lru.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Key, Result> e = it.next();
				if (e.getKey().program() == k.program() &&
					e.getKey().modification() < k.modification()) {
					bytes -= e.getValue().weight();
					it.remove();
					dropped.incrementAndGet();
				}
			}
		}
		newest.put(k.program(), k.modification());
		Result old = lru.put(k, r);
		if (old != null) {
			bytes -= old.weight();
		}
		bytes += w;
		Iterator<Map.Entry<Key, Result>> it = lru.entrySet().iterator();
		while (bytes > budget && it.hasNext()) {
			Map.Entry<Key, Result> e = it.next();
			bytes -= e.getValue().weight();
			it.remove();
			evicted.incrementAndGet();
		}
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
		Json.put(o, "inflight", inflight.size());
		return o;
	}
}
