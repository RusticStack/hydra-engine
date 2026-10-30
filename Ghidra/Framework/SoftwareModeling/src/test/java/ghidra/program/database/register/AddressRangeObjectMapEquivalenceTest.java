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
package ghidra.program.database.register;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

/**
 * Hydra: the skip-list {@link AddressRangeObjectMap} against the original ArrayList one
 * ({@link LegacyAddressRangeObjectMap}, test scope) and against a brute-force per-address model.
 * <ul>
 * <li>randomized equivalence: every operation and every query, on two small address spaces so
 * that space boundaries (min/max address, adjacency across spaces) are hit constantly;</li>
 * <li>scaling: key comparisons per operation stay logarithmic;</li>
 * <li>concurrency: lock-free readers never see a torn state while a writer updates.</li>
 * </ul>
 */
public class AddressRangeObjectMapEquivalenceTest extends AbstractGenericTest {

	private static final int SPACE_SIZE = 256;
	private static final Object ABSENT = new Object();
	private static final Integer[] VALUES = { null, 0, 1, 2 };

	private GenericAddressSpace spaceA;
	private GenericAddressSpace spaceB;
	private GenericAddressSpace[] spaces;

	@Before
	public void setUp() {
		spaceA = new GenericAddressSpace("A", 8, AddressSpace.TYPE_RAM, 0);
		spaceB = new GenericAddressSpace("B", 8, AddressSpace.TYPE_RAM, 1);
		spaces = new GenericAddressSpace[] { spaceA, spaceB };
	}

	private Address addr(int global) {
		return spaces[global / SPACE_SIZE].getAddress(global % SPACE_SIZE);
	}

	private static int global(Address a) {
		return (a.getAddressSpace().getSpaceID() == 0 ? 0 : SPACE_SIZE) + (int) a.getOffset();
	}

	// ---------------------------------------------------------------- randomized equivalence

	private static final class Stats {
		long ops, queries, legacyNpeFixed;
	}

	@Test
	public void testRandomizedEquivalenceWithLegacyAndModel() throws Exception {
		Stats stats = new Stats();
		for (long seed = 1; seed <= 400; seed++) {
			runRandomSequence(seed, 400, stats);
		}
		System.out.println("rangemap equivalence: ops=" + stats.ops + " queries=" + stats.queries +
			" legacyNpeFixed=" + stats.legacyNpeFixed);
		assertTrue(stats.ops >= 160_000);
		// the max-address edge must actually have been exercised
		assertTrue("max-address edge never hit", stats.legacyNpeFixed > 0);
	}

	private void runRandomSequence(long seed, int steps, Stats stats) throws Exception {
		Random rnd = new Random(seed);
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		LegacyAddressRangeObjectMap<Integer> legacy = new LegacyAddressRangeObjectMap<>();
		Object[] model = new Object[2 * SPACE_SIZE];
		Arrays.fill(model, ABSENT);

		for (int step = 0; step < steps; step++) {
			String op;
			int kind = rnd.nextInt(100);
			Throwable legacyError = null;
			if (kind < 60) {
				int[] r = randomRange(rnd);
				Integer v = VALUES[rnd.nextInt(VALUES.length)];
				op = "set " + r[0] + ".." + r[1] + "=" + v;
				map.setObject(addr(r[0]), addr(r[1]), v);
				try {
					legacy.setObject(addr(r[0]), addr(r[1]), v);
				}
				catch (NullPointerException e) {
					legacyError = e;
				}
				for (int i = r[0]; i <= r[1]; i++) {
					model[i] = v;
				}
			}
			else if (kind < 85) {
				int[] r = randomRange(rnd);
				op = "clear " + r[0] + ".." + r[1];
				map.clearRange(addr(r[0]), addr(r[1]));
				legacy.clearRange(addr(r[0]), addr(r[1]));
				for (int i = r[0]; i <= r[1]; i++) {
					model[i] = ABSENT;
				}
			}
			else if (kind < 98) {
				int base = rnd.nextInt(2) * SPACE_SIZE;
				int len = 1 + rnd.nextInt(rnd.nextBoolean() ? 8 : 64);
				int from = base + rnd.nextInt(SPACE_SIZE - len + 1);
				int to = base + rnd.nextInt(SPACE_SIZE - len + 1);
				op = "move " + from + "->" + to + " len " + len;
				map.moveAddressRange(addr(from), addr(to), len, TaskMonitor.DUMMY);
				try {
					legacy.moveAddressRange(addr(from), addr(to), len, TaskMonitor.DUMMY);
				}
				catch (NullPointerException e) {
					legacyError = e;
				}
				Object[] moved = Arrays.copyOfRange(model, from, from + len);
				Arrays.fill(model, from, from + len, ABSENT);
				for (int i = 0; i < len; i++) {
					if (moved[i] != ABSENT) {
						model[to + i] = moved[i];
					}
				}
			}
			else {
				op = "clearAll";
				map.clearAll();
				legacy.clearAll();
				Arrays.fill(model, ABSENT);
			}
			stats.ops++;
			String ctx = "seed " + seed + " step " + step + " (" + op + ")";

			// the new map must always match the per-address model and be fully coalesced
			checkAgainstModel(map, model, ctx);

			if (legacyError != null) {
				// The original throws a NullPointerException when a range ends at the top of its
				// space while a later space has a range, after it already dropped the overlapped
				// ranges. The model above shows the new map is right there; resync the legacy copy.
				stats.legacyNpeFixed++;
				legacy.clearAll();
				for (AddressRange r : map.getAddressRangeIterator()) {
					legacy.setObject(r.getMinAddress(), r.getMaxAddress(),
						map.getObject(r.getMinAddress()));
				}
			}
			assertEquals(ctx, describe(legacy.getAddressRangeIterator(), legacy::getObject),
				describe(map.getAddressRangeIterator(), map::getObject));
			assertEquals(ctx, legacy.isEmpty(), map.isEmpty());

			// interleaved queries, compared with the legacy implementation
			for (int q = 0; q < 6; q++) {
				Address a = addr(rnd.nextInt(2 * SPACE_SIZE));
				assertEquals(ctx + " contains " + a, legacy.contains(a), map.contains(a));
				assertEquals(ctx + " get " + a, legacy.getObject(a), map.getObject(a));
				assertEquals(ctx + " containing " + a, legacy.getAddressRangeContaining(a),
					map.getAddressRangeContaining(a));
				int s = rnd.nextInt(2 * SPACE_SIZE);
				int e = rnd.nextInt(4) == 0 ? rnd.nextInt(2 * SPACE_SIZE)
						: Math.min(2 * SPACE_SIZE - 1, s + rnd.nextInt(80));
				// (a query from one space into another throws in both, from AddressRangeImpl)
				assertEquals(ctx + " iter " + s + ".." + e,
					describeOrThrown(() -> legacy.getAddressRangeIterator(addr(s), addr(e))),
					describeOrThrown(() -> map.getAddressRangeIterator(addr(s), addr(e))));
				stats.queries += 4;
			}
			if (step % 50 == 0) {
				for (int g = 0; g < 2 * SPACE_SIZE; g++) {
					Address a = addr(g);
					assertEquals(ctx + " containing " + a, legacy.getAddressRangeContaining(a),
						map.getAddressRangeContaining(a));
					assertEquals(ctx + " get " + a, legacy.getObject(a), map.getObject(a));
				}
				stats.queries += 4 * SPACE_SIZE;
			}
		}
	}

	/** Mostly short ranges, often touching the space min/max, never crossing a space. */
	private int[] randomRange(Random rnd) {
		int base = rnd.nextInt(2) * SPACE_SIZE;
		int len = 1 + rnd.nextInt(rnd.nextInt(4) == 0 ? SPACE_SIZE : 16);
		int start;
		switch (rnd.nextInt(8)) {
			case 0:
				start = 0;
				break;
			case 1:
				start = SPACE_SIZE - len;
				break;
			default:
				start = rnd.nextInt(SPACE_SIZE - len + 1);
		}
		return new int[] { base + start, base + start + len - 1 };
	}

	private void checkAgainstModel(AddressRangeObjectMap<Integer> map, Object[] model,
			String ctx) {
		// expected ranges = maximal runs of equal values (null is a value) within each space
		List<String> expected = new ArrayList<>();
		for (int s = 0; s < 2; s++) {
			int g = s * SPACE_SIZE;
			int endOfSpace = g + SPACE_SIZE;
			while (g < endOfSpace) {
				if (model[g] == ABSENT) {
					g++;
					continue;
				}
				int runEnd = g;
				while (runEnd + 1 < endOfSpace && Objects.equals(model[runEnd + 1], model[g]) &&
					model[runEnd + 1] != ABSENT) {
					runEnd++;
				}
				expected.add(addr(g).toString(true) + "-" + addr(runEnd).toString(true) + "=" +
					model[g]);
				g = runEnd + 1;
			}
		}
		assertEquals(ctx + " vs model", expected,
			describe(map.getAddressRangeIterator(), map::getObject));
		assertEquals(ctx + " range count", expected.size(), map.getRangeCount());
		for (int g = 0; g < 2 * SPACE_SIZE; g += 7) {
			Address a = addr(g);
			assertEquals(ctx + " model contains " + a, model[g] != ABSENT, map.contains(a));
			assertEquals(ctx + " model get " + a, model[g] == ABSENT ? null : model[g],
				map.getObject(a));
		}
	}

	private interface Getter {
		Integer get(Address a);
	}

	private interface IteratorSupplier {
		AddressRangeIterator get();
	}

	private static String describeOrThrown(IteratorSupplier supplier) {
		try {
			return describe(supplier.get(), null).toString();
		}
		catch (RuntimeException e) {
			return "threw " + e.getClass().getName() + ": " + e.getMessage();
		}
	}

	private static List<String> describe(AddressRangeIterator it, Getter getter) {
		List<String> out = new ArrayList<>();
		while (it.hasNext()) {
			AddressRange r = it.next();
			out.add(r.getMinAddress().toString(true) + "-" + r.getMaxAddress().toString(true) +
				(getter == null ? "" : "=" + getter.get(r.getMinAddress())));
		}
		return out;
	}

	// ---------------------------------------------------------------- targeted edge cases

	@Test
	public void testRangeEndingAtSpaceMaxWithLaterSpaceRange() {
		// The original lost the new range and threw here; the new map stores it.
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		map.setObject(spaceB.getAddress(0), spaceB.getAddress(10), 1);
		map.setObject(spaceA.getAddress(200), spaceA.getAddress(255), 2);
		map.setObject(spaceA.getAddress(250), spaceA.getAddress(255), 3);
		assertEquals(List.of("A:c8-A:f9=2", "A:fa-A:ff=3", "B:00-B:0a=1"),
			describe(map.getAddressRangeIterator(), map::getObject));

		LegacyAddressRangeObjectMap<Integer> legacy = new LegacyAddressRangeObjectMap<>();
		legacy.setObject(spaceB.getAddress(0), spaceB.getAddress(10), 1);
		try {
			legacy.setObject(spaceA.getAddress(200), spaceA.getAddress(255), 2);
			fail("legacy behaviour changed: expected the original NullPointerException");
		}
		catch (NullPointerException expected) {
			// the original bug this replacement fixes: the new range is lost
		}
		assertEquals(List.of("B:00-B:0a=1"),
			describe(legacy.getAddressRangeIterator(), legacy::getObject));
	}

	@Test
	public void testNoCoalescingAcrossSpaces() {
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		map.setObject(spaceB.getAddress(0), spaceB.getAddress(3), 7);
		map.setObject(spaceA.getAddress(250), spaceA.getAddress(255), 7);
		assertEquals(2, map.getRangeCount());
		map.setObject(spaceA.getAddress(0), spaceA.getAddress(255), 7);
		assertEquals(2, map.getRangeCount());
		map.clearRange(spaceA.getAddress(0), spaceA.getAddress(255));
		assertEquals(List.of("B:00-B:03=7"),
			describe(map.getAddressRangeIterator(), map::getObject));
	}

	// ---------------------------------------------------------------- scaling (operation counts)

	private static final class CountingComparator implements Comparator<Address> {
		long count;

		@Override
		public int compare(Address a, Address b) {
			count++;
			return a.compareTo(b);
		}
	}

	/** Average key comparisons per setObject, for n disjoint ranges inserted in descending order. */
	private double comparisonsPerInsert(int n, GenericAddressSpace space) {
		CountingComparator cmp = new CountingComparator();
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>(cmp);
		for (int i = n - 1; i >= 0; i--) {
			Address a = space.getAddress(4L * i);
			map.setObject(a, a.add(1), i & 1);
		}
		assertEquals(n, map.getRangeCount());
		return (double) cmp.count / n;
	}

	@Test
	public void testScalingIsLogarithmic() {
		GenericAddressSpace big = new GenericAddressSpace("big", 32, AddressSpace.TYPE_RAM, 2);
		double small = comparisonsPerInsert(1 << 10, big);
		double large = comparisonsPerInsert(1 << 17, big);
		// log2 grows 10 -> 17 (1.7x); a linear structure would grow 128x.
		System.out.printf("rangemap scaling: cmp/insert n=1024: %.1f, n=131072: %.1f%n", small,
			large);
		assertTrue("comparisons per insert grew too fast: " + small + " -> " + large,
			large < small * 3.0);

		// Wall clock for the record (not asserted): the original shifts the whole ArrayList on
		// every insert in descending order, O(n^2) overall.
		int n = 1 << 16;
		long t0 = System.nanoTime();
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		for (int i = n - 1; i >= 0; i--) {
			Address a = big.getAddress(4L * i);
			map.setObject(a, a.add(1), i & 1);
		}
		long t1 = System.nanoTime();
		LegacyAddressRangeObjectMap<Integer> legacy = new LegacyAddressRangeObjectMap<>();
		for (int i = n - 1; i >= 0; i--) {
			Address a = big.getAddress(4L * i);
			legacy.setObject(a, a.add(1), i & 1);
		}
		long t2 = System.nanoTime();
		System.out.printf("rangemap scaling: %d descending inserts new %.1f ms, legacy %.1f ms%n",
			n, (t1 - t0) / 1e6, (t2 - t1) / 1e6);
		assertEquals(describe(legacy.getAddressRangeIterator(), legacy::getObject),
			describe(map.getAddressRangeIterator(), map::getObject));
	}

	// ---------------------------------------------------------------- concurrency

	/**
	 * A fixed range [100,199]=42 never changes value, but a writer keeps merging equal ranges into
	 * it (which removes and re-inserts the stored range) and splitting/clearing its neighbours.
	 * Lock-free readers must always see 42 inside it and never a torn state.
	 */
	@Test
	public void testLockFreeReadersSeeConsistentState() throws Exception {
		GenericAddressSpace sp = new GenericAddressSpace("C", 16, AddressSpace.TYPE_RAM, 3);
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		map.setObject(sp.getAddress(100), sp.getAddress(199), 42);

		AtomicBoolean stop = new AtomicBoolean();
		AtomicLong reads = new AtomicLong();
		int readers = Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors() - 1));
		ExecutorService pool = Executors.newFixedThreadPool(readers + 1);
		try {
			List<Future<?>> futures = new ArrayList<>();
			futures.add(pool.submit(() -> {
				Random rnd = new Random(7);
				long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(1500);
				while (System.nanoTime() < deadline) {
					int s = 100 + rnd.nextInt(100);
					int e = Math.min(199, s + rnd.nextInt(20));
					map.setObject(sp.getAddress(s), sp.getAddress(e), 42); // merge into fixed range
					int o = 210 + rnd.nextInt(50);
					map.setObject(sp.getAddress(o), sp.getAddress(o + rnd.nextInt(30)), o & 3);
					map.setObject(sp.getAddress(200), sp.getAddress(205), 42); // adjacent merge
					map.clearRange(sp.getAddress(200), sp.getAddress(205));
					map.setObject(sp.getAddress(90), sp.getAddress(99), rnd.nextInt(3));
					map.clearRange(sp.getAddress(0), sp.getAddress(99));
				}
				stop.set(true);
				return null;
			}));
			for (int r = 0; r < readers; r++) {
				final int seed = r;
				futures.add(pool.submit(() -> {
					Random rnd = new Random(seed);
					while (!stop.get()) {
						Address a = sp.getAddress(100 + rnd.nextInt(100));
						assertEquals(Integer.valueOf(42), map.getObject(a));
						assertTrue(map.contains(a));
						AddressRange c = map.getAddressRangeContaining(a);
						assertTrue(c.contains(a));
						assertTrue(c.getMinAddress().getOffset() <= 100);
						assertFalse(map.isEmpty());
						reads.incrementAndGet();
					}
					return null;
				}));
			}
			for (Future<?> f : futures) {
				f.get(60, TimeUnit.SECONDS);
			}
		}
		finally {
			pool.shutdownNow();
		}
		assertTrue("readers did not run", reads.get() > 1000);
	}
}
