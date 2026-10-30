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
package generic.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.apache.commons.collections4.map.LRUMap;

/**
 * Generic cache implementation that removes items from the cache when they are no longer
 * referenced. It uses weak references for the values and a small hard cache
 * so that recent items don't get garbage collected immediately.
 * <P>
 * This class is thread safe. {@link #get(Object)} and {@link #size()} do not take the cache
 * monitor: the weak references live in a {@link ConcurrentHashMap} and a hit refreshes the hard
 * cache only when its lock is free, so the hard cache keeps an approximate recency order under
 * contention. All methods that change the cache are synchronized, so callers may still group
 * several changes in a {@code synchronized (cache)} block, but only against other writers:
 * {@code get} does not wait for such a block and may see its intermediate states (for example a
 * key deleted and not yet added again). Callers that need a reader to see only the final state
 * must order readers and writers themselves, as {@code DbCache} does with the database lock.
 * 
 * @param <K> The type of the object stored in this cache
 * @param <V> The type of the object stored in this cache
 */
public class WeakReferenceCache<K, V> {

	private Map<K, KeyedReference<K, V>> refsById;
	private ReferenceQueue<V> refQueue;
	private LRUMap<K, V> hardCache; // guarded by hardCacheLock
	private final ReentrantLock hardCacheLock = new ReentrantLock();

	/**
	 * Constructs a new WeakReferenceCache with a given hard cache size.  The hard cache size is
	 * the minimum number of objects to keep in the cache. Typically, the cache will contain
	 * more than this number, but the excess objects are subject to garbage collection.
	 * @param hardCacheSize the minimum number of objects to keep in the cache.
	 */
	public WeakReferenceCache(int hardCacheSize) {
		refsById = new ConcurrentHashMap<>();
		refQueue = new ReferenceQueue<>();

		hardCache = new LRUMap<>(hardCacheSize);
	}

	/**
	 * Retrieves the database object with the given key from the cache.
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public V get(K key) {
		KeyedReference<K, V> ref = refsById.get(key);
		if (ref == null) {
			return null;
		}
		V v = ref.get();
		if (v == null) {
			refsById.remove(key, ref);
			return null;
		}
		// a hit only refreshes the recency of the hard cache when nobody else is doing so, and
		// never puts back a value that add or delete has replaced since it was read
		if (hardCacheLock.tryLock()) {
			try {
				if (refsById.get(key) == ref) {
					hardCache.put(key, v);
				}
			}
			finally {
				hardCacheLock.unlock();
			}
		}
		return v;
	}

	/**
	 * Returns the number of objects currently in the cache.
	 * @return the number of objects currently in the cache.
	 */
	public int size() {
		return refsById.size();
	}

	/**
	 * Sets the number of objects to protect against garbage collection.
	 * @param size the minimum number of objects to keep in the cache.
	 */
	public synchronized void setHardCacheSize(int size) {
		hardCacheLock.lock();
		try {
			hardCache.clear();
			hardCache = new LRUMap<>(size);
		}
		finally {
			hardCacheLock.unlock();
		}
	}

	/**
	 * Adds the given database object to the cache.
	 * @param key the key for the cached object
	 * @param data the object to add to the cache
	 * @return the object that has been added to the cache
	 */
	public synchronized V add(K key, V data) {
		processQueue();
		hardCacheLock.lock();
		try {
			hardCache.put(key, data);
		}
		finally {
			hardCacheLock.unlock();
		}
		KeyedReference<K, V> ref = new KeyedReference<>(key, data, refQueue);
		refsById.put(key, ref);
		return data;
	}

	/**
	 * Returns an List of all the cached objects.
	 * @return an List of all the cached objects.
	 */
	public synchronized List<V> getCachedObjects() {
		List<V> list = new ArrayList<>();
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				list.add(v);
			}
		}
		return list;
	}

	/**
	 * Applies the given consumer to all values in the cache.
	 * @param consumer the consumer to apply to all values in the cache
	 */
	public synchronized void apply(Consumer<V> consumer) {
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				consumer.accept(v);
			}
		}
	}

	/**
	 * Removes the object with the given key from the cache.
	 * @param key the key of the object to remove
	 * @return the value that was removed from the cache
	 */
	public synchronized V delete(K key) {
		processQueue();
		KeyedReference<K, V> ref = refsById.remove(key);
		V v = null;
		if (ref != null) {
			v = ref.get();
			ref.clear();
		}
		return v;
	}

	public synchronized void deleteIf(Predicate<V> predicate) {
		Iterator<KeyedReference<K, V>> iterator = refsById.values().iterator();
		while (iterator.hasNext()) {
			KeyedReference<K, V> ref = iterator.next();
			V v = ref.get();
			if (v == null || predicate.test(v)) {
				iterator.remove();
			}
		}
	}

	// we know the cast is safe--we put them in there
	@SuppressWarnings("unchecked")
	private void processQueue() {
		KeyedReference<K, V> ref;
		while ((ref = (KeyedReference<K, V>) refQueue.poll()) != null) {
			// Only drop the entry if it still holds this reference: if another item has been
			// put in the cache with the same key after this one was removed, but before the
			// garbage collector queued this reference, we keep the last value that was added,
			// as it has not been deleted.
			refsById.remove(ref.getKey(), ref);
		}
	}

	private static class KeyedReference<K, V> extends WeakReference<V> {
		private K key;

		KeyedReference(K key, V obj, ReferenceQueue<V> queue) {
			super(obj, queue);
			this.key = key;
		}

		K getKey() {
			return key;
		}
	}

}
