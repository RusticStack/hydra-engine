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

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * The program journal: writers append in commit order, readers take no turn with them, and the
 * single ordered view is complete and ordered under concurrency and across the cap.
 */
public class JournalTest {

	private static Client client(int id) {
		Client c = new Client(id, "test", false, e -> {
		});
		c.name = "w" + id;
		return c;
	}

	private static JsonObject change(String op, String address, String rk) {
		JsonObject o = Json.of("op", op, "address", address, "new", "v");
		if (rk != null) {
			o.addProperty("rk", rk);
		}
		return o;
	}

	private static long seqOf(JsonObject e) {
		return e.get("seq").getAsLong();
	}

	/** Concurrent writers and readers: the journal is complete, gap-free and ordered. */
	@Test
	public void concurrentWritersGiveCompleteOrderedView() throws Exception {
		Journal j = new Journal();
		int writers = 8, per = 5_000;
		ExecutorService pool = Executors.newFixedThreadPool(writers + 2);
		CountDownLatch go = new CountDownLatch(1);
		AtomicBoolean done = new AtomicBoolean();
		AtomicReference<String> readerFault = new AtomicReference<>();
		List<Future<?>> fs = new ArrayList<>();
		for (int w = 1; w <= writers; w++) {
			Client c = client(w);
			int id = w;
			fs.add(pool.submit(() -> {
				go.await();
				for (int i = 0; i < per; i++) {
					j.add(c, "edit", change("rename", "w" + id + ":" + i, "rk" + id + "-" + i / 2));
				}
				return null;
			}));
		}
		List<Future<?>> rs = new ArrayList<>();
		for (int r = 0; r < 2; r++) {
			rs.add(pool.submit(() -> {
				long last = 0;
				while (!done.get()) {
					long hi = j.seq();
					JsonArray a = j.since(Math.max(0, hi - 50), null, 1000);
					long prev = -1;
					for (int i = 0; i < a.size(); i++) {
						long s = seqOf(a.get(i).getAsJsonObject());
						if (prev >= 0 && s != prev + 1) {
							readerFault.set("gap " + prev + " -> " + s);
						}
						prev = s;
					}
					if (hi < last) {
						readerFault.set("seq went back");
					}
					last = hi;
				}
				return null;
			}));
		}
		go.countDown();
		for (Future<?> f : fs) {
			f.get(60, TimeUnit.SECONDS);
		}
		done.set(true);
		for (Future<?> f : rs) {
			f.get(30, TimeUnit.SECONDS);
		}
		pool.shutdown();
		assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
		assertNull(readerFault.get(), readerFault.get());

		int total = writers * per;
		assertEquals(total, j.seq());
		assertEquals(0, j.dropped());
		JsonArray all = j.since(0, null, Journal.CAP);
		assertEquals(total, all.size());
		Map<Integer, Integer> nextOf = new HashMap<>();
		for (int i = 0; i < total; i++) {
			JsonObject e = all.get(i).getAsJsonObject();
			assertEquals(i + 1, seqOf(e));
			int c = e.get("client").getAsInt();
			int k = nextOf.merge(c, 1, Integer::sum) - 1;
			// each writer's entries appear in the order it wrote them
			assertEquals("w" + c + ":" + k, e.get("address").getAsString());
		}
		for (int w = 1; w <= writers; w++) {
			JsonArray mine = j.since(0, w, Journal.CAP);
			assertEquals(per, mine.size());
			for (int i = 0; i < per; i++) {
				assertEquals("w" + w + ":" + i,
					mine.get(i).getAsJsonObject().get("address").getAsString());
			}
			assertEquals(2, j.byRk("rk" + w + "-7").size());
			assertNotNull(j.lastAt("w" + w + ":" + (per - 1), "name"));
		}
		List<JsonObject> nf = j.newestFirst(total - 10);
		assertEquals(10, nf.size());
		assertEquals(total, seqOf(nf.get(0)));
		assertEquals(total - 9, seqOf(nf.get(9)));
	}

	/**
	 * Concurrent writers with a small cap, so entries are dropped while readers read: every read
	 * (all entries, one client's, one key's, newest first, the last of a field) stays ordered,
	 * gap-free where it must be, and only ever shows entries of what it asked for.
	 */
	@Test
	public void readsStayConsistentWhileTheCapDrops() throws Exception {
		int cap = 1000;
		Journal j = new Journal(cap);
		int writers = 4, per = 20_000;
		ExecutorService pool = Executors.newFixedThreadPool(writers + 3);
		CountDownLatch go = new CountDownLatch(1);
		AtomicBoolean done = new AtomicBoolean();
		AtomicReference<String> fault = new AtomicReference<>();
		List<Future<?>> fs = new ArrayList<>();
		for (int w = 1; w <= writers; w++) {
			Client c = client(w);
			int id = w;
			fs.add(pool.submit(() -> {
				go.await();
				for (int i = 0; i < per; i++) {
					j.add(c, "edit",
						change(i % 2 == 0 ? "rename" : "comment", "a" + (i % 50), "k" + id + "-" + i / 100));
				}
				return null;
			}));
		}
		List<Future<?>> rs = new ArrayList<>();
		rs.add(pool.submit(() -> { // all entries and newest first: contiguous, within the cap
			while (!done.get()) {
				long hi = j.seq();
				JsonArray a = j.since(0, null, Integer.MAX_VALUE);
				for (int i = 1; i < a.size(); i++) {
					if (seqOf(a.get(i).getAsJsonObject()) != seqOf(a.get(i - 1).getAsJsonObject()) + 1) {
						fault.compareAndSet(null, "since: gap at " + i);
					}
				}
				if (a.size() > cap || a.size() > 0 && seqOf(a.get(a.size() - 1).getAsJsonObject()) < hi) {
					fault.compareAndSet(null, "since: " + a.size() + " entries, " +
						(a.size() == 0 ? "" : seqOf(a.get(0).getAsJsonObject()) + ".." +
							seqOf(a.get(a.size() - 1).getAsJsonObject())) +
						", read after seq " + hi + ", now " + j.seq());
				}
				List<JsonObject> nf = j.newestFirst(0);
				for (int i = 1; i < nf.size(); i++) {
					if (seqOf(nf.get(i)) != seqOf(nf.get(i - 1)) - 1) {
						fault.compareAndSet(null, "newestFirst: gap at " + i);
					}
				}
			}
			return null;
		}));
		rs.add(pool.submit(() -> { // one client's entries, in that writer's order
			Random rnd = new Random(1);
			while (!done.get()) {
				int w = 1 + rnd.nextInt(writers);
				JsonArray a = j.since(j.seq() - cap / 2, w, Integer.MAX_VALUE);
				long prev = 0;
				for (int i = 0; i < a.size(); i++) {
					JsonObject e = a.get(i).getAsJsonObject();
					if (e.get("client").getAsInt() != w || seqOf(e) <= prev) {
						fault.compareAndSet(null, "since(client): " + e);
					}
					prev = seqOf(e);
				}
			}
			return null;
		}));
		rs.add(pool.submit(() -> { // one key's entries and the last of a field
			Random rnd = new Random(2);
			while (!done.get()) {
				String rk = "k" + (1 + rnd.nextInt(writers)) + "-" + rnd.nextInt(per / 100);
				long prev = 0;
				for (JsonObject e : j.byRk(rk)) {
					if (!e.get("rk").getAsString().equals(rk) || seqOf(e) <= prev) {
						fault.compareAndSet(null, "byRk: " + e);
					}
					prev = seqOf(e);
				}
				String addr = "a" + rnd.nextInt(50);
				JsonObject last = j.lastAt(addr, "name");
				if (last != null && (!last.get("address").getAsString().equals(addr) ||
					!Journal.fieldOf(last).equals("name"))) {
					fault.compareAndSet(null, "lastAt: " + last);
				}
			}
			return null;
		}));
		go.countDown();
		for (Future<?> f : fs) {
			f.get(60, TimeUnit.SECONDS);
		}
		done.set(true);
		for (Future<?> f : rs) {
			f.get(30, TimeUnit.SECONDS);
		}
		pool.shutdown();
		assertNull(fault.get(), fault.get());
		long total = (long) writers * per;
		assertEquals(total, j.seq());
		assertEquals(total - cap, j.dropped());
		assertEquals(cap, j.since(0, null, Integer.MAX_VALUE).size());
		int held = 0;
		for (int w = 1; w <= writers; w++) {
			held += j.since(0, w, Integer.MAX_VALUE).size();
		}
		assertEquals(cap, held);
	}

	/** lastAt is the newest entry of a field, rename and label sharing one. */
	@Test
	public void lastAtIsNewestOfField() {
		Journal j = new Journal();
		Client a = client(1), b = client(2);
		j.add(a, "rename", change("rename", "1000", null));
		long s2 = j.add(b, "edit", change("label", "1000", null));
		long s3 = j.add(a, "comment", change("comment", "1000", null));
		assertEquals(s2, seqOf(j.lastAt("1000", "name")));
		assertEquals(s3, seqOf(j.lastAt("1000", "comment:eol")));
		assertNull(j.lastAt("1000", "comment:pre"));
		assertNull(j.lastAt("2000", "name"));
	}

	/** The cap drops the oldest entries, and their indexes with them. */
	@Test
	public void capDropsOldestAndTheirIndexes() {
		Journal j = new Journal();
		Client a = client(1), b = client(2);
		j.add(b, "edit", change("rename", "dropme", "old"));
		for (int i = 0; i < Journal.CAP + 9; i++) {
			j.add(a, "edit", change("rename", "a" + (i % 100), i < 5 ? "kept" : null));
		}
		assertEquals(Journal.CAP + 10, j.seq());
		assertEquals(10, j.dropped());
		assertTrue(j.byRk("old").isEmpty());
		assertTrue(j.byRk("kept").isEmpty()); // seqs 2..6: dropped too
		assertNull(j.lastAt("dropme", "name"));
		assertEquals(0, j.since(0, b.id, 10).size()); // b's only entry was dropped
		assertNotNull(j.lastAt("a5", "name"));
		JsonArray all = j.since(0, null, Journal.CAP);
		assertEquals(Journal.CAP, all.size());
		assertEquals(11, seqOf(all.get(0).getAsJsonObject()));
		assertEquals(11, seqOf(j.since(0, a.id, 1).get(0).getAsJsonObject()));
		assertEquals(0, j.since(j.seq(), null, 10).size());
		assertEquals(0, j.since(Long.MAX_VALUE, null, 10).size());
		// past one full ring: slots are reused and the view stays right
		for (int i = 0; i < Journal.CAP; i++) {
			j.add(a, "edit", change("comment", "b" + (i % 7), null));
		}
		JsonArray tail = j.since(j.seq() - 3, null, 10);
		assertEquals(3, tail.size());
		assertEquals(j.seq(), seqOf(tail.get(2).getAsJsonObject()));
		assertEquals(Journal.CAP, j.newestFirst(0).size());
		assertEquals(Journal.CAP, j.since(0, a.id, Integer.MAX_VALUE).size());
	}

	/** A small journal (the self-test's) keeps exactly its cap, across several ring turns. */
	@Test
	public void smallCapKeepsItsWindow() {
		for (int cap : new int[] { 1, 2, 3, 300, 4095, 4096, 4097 }) {
			Journal j = new Journal(cap);
			Client a = client(1), b = client(2);
			int n = cap * 5 + 7;
			for (int i = 1; i <= n; i++) {
				j.add(i % 3 == 0 ? b : a, "edit", change("rename", "x" + (i % 4), "r" + (i % 2)));
			}
			String at = "cap " + cap;
			assertEquals(at, n, j.seq());
			assertEquals(at, n - cap, j.dropped());
			JsonArray all = j.since(Long.MIN_VALUE, null, Integer.MAX_VALUE);
			assertEquals(at, cap, all.size());
			assertEquals(at, n - cap + 1, seqOf(all.get(0).getAsJsonObject()));
			assertEquals(at, cap, j.newestFirst(Long.MIN_VALUE).size());
			int byKeys = j.byRk("r0").size() + j.byRk("r1").size();
			int byClients = j.since(0, a.id, Integer.MAX_VALUE).size() +
				j.since(0, b.id, Integer.MAX_VALUE).size();
			assertEquals(at, cap, byKeys);
			assertEquals(at, cap, byClients);
			assertEquals(at, n, seqOf(j.lastAt("x" + (n % 4), "name")));
		}
	}

	/**
	 * A reader never waits for a writer that is inside {@code add}: the test holds the journal's
	 * own monitor (which the synchronized journal's reads took) and, when there is one, the monitor
	 * appends are made under, while every read runs.
	 */
	@Test
	public void readersTakeNoTurn() throws Exception {
		Journal j = new Journal();
		Client a = client(1);
		j.add(a, "edit", change("rename", "1000", "k"));
		Object appendLock = new Object();
		try {
			Field f = Journal.class.getDeclaredField("append");
			f.setAccessible(true);
			appendLock = f.get(j);
		}
		catch (NoSuchFieldException e) {
			// a journal without one: its own monitor is the writer's lock
		}
		ExecutorService ex = Executors.newSingleThreadExecutor();
		try {
			synchronized (j) {
				synchronized (appendLock) {
					Future<Integer> r = ex.submit(() -> j.since(0, null, 10).size() +
						j.since(0, a.id, 10).size() + j.byRk("k").size() +
						(j.lastAt("1000", "name") != null ? 1 : 0) + j.newestFirst(0).size() +
						(int) j.seq() + (int) j.dropped());
					assertEquals(Integer.valueOf(6), r.get(5, TimeUnit.SECONDS));
				}
			}
		}
		finally {
			ex.shutdownNow();
		}
	}

	/**
	 * One {@code edit} journals every op of its batch under one idempotency key (and one client):
	 * appending such a batch, and dropping it again under the cap, is linear, not a copy of the
	 * key's list per entry.
	 */
	@Test(timeout = 20_000)
	public void largeOneKeyBatchIsLinear() {
		Journal j = new Journal();
		Client a = client(1);
		for (int i = 0; i < Journal.CAP; i++) {
			j.add(a, "edit", change("rename", "a" + i, "batch"));
		}
		assertEquals(Journal.CAP, j.byRk("batch").size());
		for (int i = 0; i < Journal.CAP / 2; i++) {
			j.add(a, "edit", change("rename", "b" + i, null));
		}
		List<JsonObject> held = j.byRk("batch");
		assertEquals(Journal.CAP / 2, held.size());
		assertEquals(Journal.CAP / 2 + 1, seqOf(held.get(0)));
		assertEquals(Journal.CAP, seqOf(held.get(held.size() - 1)));
		for (int i = 0; i < Journal.CAP / 2; i++) {
			j.add(a, "edit", change("rename", "c" + i, i % 3 == 0 ? "batch" : null));
		}
		held = j.byRk("batch");
		assertEquals((Journal.CAP / 2 + 2) / 3, held.size());
		long prev = 0;
		for (JsonObject e : held) {
			long s = seqOf(e);
			assertTrue(s > prev && s > j.dropped());
			prev = s;
		}
		assertEquals(Journal.CAP, j.since(0, a.id, Integer.MAX_VALUE).size());
	}

	/**
	 * A lock-free read never runs ahead of {@link Journal#seq()}: an entry that {@code byRk} or
	 * {@code lastAt} returns is already published, so a {@code seq()} read after it covers it (as
	 * under the synchronized journal). One writer appends to one address and key while readers
	 * check each answer against the {@code seq} they read just after it.
	 */
	@Test
	public void readsNeverRunAheadOfSeq() throws Exception {
		Journal j = new Journal(1000);
		Client a = client(1);
		AtomicBoolean done = new AtomicBoolean();
		AtomicReference<String> fault = new AtomicReference<>();
		ExecutorService pool = Executors.newFixedThreadPool(3);
		List<Future<?>> rs = new ArrayList<>();
		for (int r = 0; r < 2; r++) {
			boolean byKey = r == 0;
			rs.add(pool.submit(() -> {
				while (!done.get()) {
					long got;
					if (byKey) {
						List<JsonObject> l = j.byRk("k");
						got = l.isEmpty() ? 0 : seqOf(l.get(l.size() - 1));
					}
					else {
						JsonObject e = j.lastAt("x", "name");
						got = e == null ? 0 : seqOf(e);
					}
					long s = j.seq();
					if (got > s) {
						fault.compareAndSet(null,
							(byKey ? "byRk" : "lastAt") + " returned seq " + got + " while seq() was " + s);
					}
				}
				return null;
			}));
		}
		Future<?> w = pool.submit(() -> {
			long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
			while (System.nanoTime() < end && fault.get() == null) {
				j.add(a, "edit", change("rename", "x", "k"));
			}
			return null;
		});
		w.get(60, TimeUnit.SECONDS);
		done.set(true);
		for (Future<?> f : rs) {
			f.get(30, TimeUnit.SECONDS);
		}
		pool.shutdown();
		assertNull(fault.get(), fault.get());
	}

	/** A dropped entry is released at once (no strong reference left in the journal). */
	@Test
	public void droppedEntryIsReleased() throws Exception {
		Journal j = new Journal(10);
		Client a = client(1);
		JsonObject marker = change("rename", "first", "only");
		marker.add("payload", new JsonObject());
		j.add(a, "edit", marker);
		java.lang.ref.WeakReference<Object> payload = null;
		// the journal holds its own entry object; find the payload through a read
		payload = new java.lang.ref.WeakReference<>(j.newestFirst(0).get(0).get("payload"));
		marker = null;
		for (int i = 0; i < 10; i++) {
			j.add(a, "edit", change("rename", "x", null));
		}
		assertTrue(j.byRk("only").isEmpty());
		for (int i = 0; i < 50 && payload.get() != null; i++) {
			System.gc();
			Thread.sleep(10);
		}
		assertNull("the dropped entry is still referenced", payload.get());
		assertNotNull(j); // keep the journal reachable until here
	}
}
