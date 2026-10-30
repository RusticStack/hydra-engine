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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * The program journal: writers append in commit order, readers take no turn with them, and the
 * merged (single, ordered) view is complete and ordered under concurrency and across the cap.
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
		for (int r = 0; r < 2; r++) {
			pool.submit(() -> {
				long last = 0;
				while (!done.get()) {
					long hi = j.seq();
					JsonArray a = j.since(Math.max(0, hi - 50), null, 1000);
					long prev = -1;
					for (int i = 0; i < a.size(); i++) {
						long s = a.get(i).getAsJsonObject().get("seq").getAsLong();
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
			});
		}
		go.countDown();
		for (Future<?> f : fs) {
			f.get(60, TimeUnit.SECONDS);
		}
		done.set(true);
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
			assertEquals(i + 1, e.get("seq").getAsLong());
			int c = e.get("client").getAsInt();
			int k = nextOf.merge(c, 1, Integer::sum) - 1;
			// each writer's entries appear in the order it wrote them
			assertEquals("w" + c + ":" + k, e.get("address").getAsString());
		}
		for (int w = 1; w <= writers; w++) {
			JsonArray mine = j.since(0, w, Journal.CAP);
			assertEquals(per, mine.size());
			assertEquals(2, j.byRk("rk" + w + "-7").size());
			assertNotNull(j.lastAt("w" + w + ":" + (per - 1), "name"));
		}
		List<JsonObject> nf = j.newestFirst(total - 10);
		assertEquals(10, nf.size());
		assertEquals(total, nf.get(0).get("seq").getAsLong());
		assertEquals(total - 9, nf.get(9).get("seq").getAsLong());
	}

	/** lastAt is the newest entry of a field, rename and label sharing one. */
	@Test
	public void lastAtIsNewestOfField() {
		Journal j = new Journal();
		Client a = client(1), b = client(2);
		j.add(a, "rename", change("rename", "1000", null));
		long s2 = j.add(b, "edit", change("label", "1000", null));
		long s3 = j.add(a, "comment", change("comment", "1000", null));
		assertEquals(s2, j.lastAt("1000", "name").get("seq").getAsLong());
		assertEquals(s3, j.lastAt("1000", "comment:eol").get("seq").getAsLong());
		assertNull(j.lastAt("1000", "comment:pre"));
		assertNull(j.lastAt("2000", "name"));
	}

	/** The cap drops the oldest entries, and their indexes with them. */
	@Test
	public void capDropsOldestAndTheirIndexes() {
		Journal j = new Journal();
		Client a = client(1);
		j.add(a, "edit", change("rename", "dropme", "old"));
		for (int i = 0; i < Journal.CAP + 9; i++) {
			j.add(a, "edit", change("rename", "a" + (i % 100), i < 5 ? "kept" : null));
		}
		assertEquals(Journal.CAP + 10, j.seq());
		assertEquals(10, j.dropped());
		assertTrue(j.byRk("old").isEmpty());
		assertTrue(j.byRk("kept").isEmpty()); // seqs 2..6: dropped too
		assertNull(j.lastAt("dropme", "name"));
		assertNotNull(j.lastAt("a5", "name"));
		JsonArray all = j.since(0, null, Journal.CAP);
		assertEquals(Journal.CAP, all.size());
		assertEquals(11, all.get(0).getAsJsonObject().get("seq").getAsLong());
		assertEquals(0, j.since(j.seq(), null, 10).size());
		assertEquals(0, j.since(Long.MAX_VALUE, null, 10).size());
		// past one full ring: slots are reused and the view stays right
		for (int i = 0; i < Journal.CAP; i++) {
			j.add(a, "edit", change("comment", "b" + (i % 7), null));
		}
		JsonArray tail = j.since(j.seq() - 3, null, 10);
		assertEquals(3, tail.size());
		assertEquals(j.seq(), tail.get(2).getAsJsonObject().get("seq").getAsLong());
		assertEquals(Journal.CAP, j.newestFirst(0).size());
	}

	/**
	 * A reader never waits for another holder of the journal: before, every read was
	 * {@code synchronized} on the journal and waited here.
	 */
	@Test
	public void readersTakeNoTurn() throws Exception {
		Journal j = new Journal();
		Client a = client(1);
		j.add(a, "edit", change("rename", "1000", "k"));
		ExecutorService ex = Executors.newSingleThreadExecutor();
		try {
			synchronized (j) {
				Future<Integer> r = ex.submit(() -> j.since(0, null, 10).size() +
					j.byRk("k").size() + (j.lastAt("1000", "name") != null ? 1 : 0) +
					j.newestFirst(0).size() + (int) j.seq() + (int) j.dropped());
				assertEquals(Integer.valueOf(5), r.get(5, TimeUnit.SECONDS));
			}
		}
		finally {
			ex.shutdownNow();
		}
	}
}
