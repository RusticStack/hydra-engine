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
package db.buffers;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Process-wide interning of database pages by content (hydra shared views).
 * <p>
 * Every {@link BufferMgr} keeps its own memory cache of the pages it read. When many program
 * objects are opened over the same stored database (the shared view, every overlay, every
 * private script instance, every fork of the same project, the upgrade cache copy), each of them
 * held its own copy of the same immutable pages: about 4 MB per program object for KotOR, three
 * quarters of what an overlay costs. Here a page that was just read from a file is looked up by
 * its bytes: when an equal page is already held by some buffer, the buffer takes that array
 * instead of keeping its own, so one copy serves every view.
 * <p>
 * Safety rests on content equality alone (no file identity, no invalidation): two arrays that
 * hold the same bytes are interchangeable for reading. A shared array is never written:
 * {@link DataBuffer} copies it before its first change (copy-on-write) and drops it before it is
 * refilled from a file. The table holds weak references only, so it never keeps a page alive that
 * no buffer uses: the memory bound is the union of the per-view caches, which already have their
 * own limits, and is lower than their sum.
 * <p>
 * On by default; {@code -Dhydra.db.sharedPages=false} turns it off (pages are then private as in
 * Ghidra).
 */
public final class SharedPages {

	/** System property that turns interning off ({@code false}). */
	public static final String PROPERTY = "hydra.db.sharedPages";

	private static volatile boolean enabled =
		!"false".equalsIgnoreCase(System.getProperty(PROPERTY, "true"));

	private static final ConcurrentHashMap<Integer, PageRef> TABLE = new ConcurrentHashMap<>();
	private static final ReferenceQueue<byte[]> QUEUE = new ReferenceQueue<>();
	private static final LongAdder HITS = new LongAdder();
	private static final LongAdder MISSES = new LongAdder();
	private static final LongAdder COLLISIONS = new LongAdder();
	private static final LongAdder SIGHTINGS = new LongAdder();

	private SharedPages() {
	}

	/**
	 * A table entry. A <em>sighting</em> ({@code shared == false}) only records that one view read a
	 * page with this hash: its array stays private to that view and is never handed out, so a
	 * page that a single view reads costs no copy-on-write and no fresh array on eviction. When a
	 * second view reads the same content, its array is published ({@code shared == true}) and
	 * every later view takes it.
	 */
	private static final class PageRef extends WeakReference<byte[]> {
		final int hash;
		final long owner;
		final boolean shared;

		PageRef(byte[] page, int hash, long owner, boolean shared) {
			super(page, QUEUE);
			this.hash = hash;
			this.owner = owner;
			this.shared = shared;
		}
	}

	/** Whether pages are interned. */
	public static boolean isEnabled() {
		return enabled;
	}

	/** Turns interning on or off (tests; buffers already sharing a page keep it). */
	public static void setEnabled(boolean on) {
		enabled = on;
	}

	/**
	 * Interns the page {@code buf} was just filled with. When an equal page is already published,
	 * {@code buf} takes it and the private array it held is returned for reuse. When only a
	 * sighting of the hash exists and it came from another view, the buffer's array becomes the
	 * published copy (marked shared, so it is never written in place). On the first sighting, or
	 * when the same view reads the page again, the page stays private and only the sighting is
	 * recorded. Empty buffers, buffers without data and buffers that already share a page are
	 * left alone.
	 *
	 * @param buf a buffer that was just read from a file and that no one else uses yet
	 * @param owner a token identifying the view (the {@link BufferMgr}) that read it
	 * @return a spare private array of the same size, or null
	 */
	static byte[] intern(DataBuffer buf, long owner) {
		if (!enabled || buf.isEmpty() || buf.isShared()) {
			return null;
		}
		byte[] data = buf.data;
		if (data == null) {
			return null;
		}
		purge();
		int h = Arrays.hashCode(data) * 31 + data.length;
		PageRef ref = TABLE.get(h);
		byte[] page = ref != null ? ref.get() : null;
		if (page != null && ref.shared) {
			if (page != data && page.length == data.length && Arrays.equals(page, data)) {
				HITS.increment();
				return buf.shareData(page);
			}
			COLLISIONS.increment(); // a different page with the same hash: stays private
			return null;
		}
		if (page != null && ref.owner == owner) {
			return null; // the same view reads it again: still a single reader, stays private
		}
		boolean publish = page != null; // a second view reads this content
		if (publish) {
			buf.markShared(); // before it is published: from now on it is copied before a change
		}
		PageRef mine = new PageRef(data, h, owner, publish);
		boolean stored = ref == null ? TABLE.putIfAbsent(h, mine) == null
				: TABLE.replace(h, ref, mine);
		if (publish) {
			if (stored) {
				MISSES.increment();
			}
			// when another thread won the race the array is still marked shared: it is only copied
			// before its next change, which is safe
		}
		else if (stored) {
			SIGHTINGS.increment();
		}
		return null;
	}

	/** Drops the table entries of pages no buffer holds any more. */
	private static void purge() {
		PageRef r;
		while ((r = (PageRef) QUEUE.poll()) != null) {
			TABLE.remove(r.hash, r);
		}
	}

	/** Pages found already held by another buffer (each saved one page of memory). */
	public static long hits() {
		return HITS.sum();
	}

	/** Pages published as the shared copy of their content (read by a second view). */
	public static long misses() {
		return MISSES.sum();
	}

	/** First sightings: pages one view read, kept private until a second view reads them. */
	public static long sightings() {
		return SIGHTINGS.sum();
	}

	/** Pages left private because another page had the same hash. */
	public static long collisions() {
		return COLLISIONS.sum();
	}

	/** Live entries of the table (pages some buffer may still hold). */
	public static int size() {
		purge();
		return TABLE.size();
	}
}
