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

import java.util.*;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.locks.StampedLock;

import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Associates objects with address ranges.
 * <p>
 * Hydra: the ranges are kept in a {@link ConcurrentSkipListMap} keyed by range start, so every
 * lookup and every update costs O(log n + k) (k = ranges removed or split by the update) instead
 * of the O(n) {@code ArrayList} insert/remove of the original. The semantics are unchanged: the
 * same ranges, the same coalescing of equal adjacent values within one address space, the same
 * iteration order and boundary handling (see {@code AddressRangeObjectMapEquivalenceTest}).
 * <p>
 * Concurrency: updates are serialised by the write side of a {@link StampedLock} (as the old
 * {@code synchronized} mutators were). Point reads ({@link #getObject}, {@link #contains},
 * {@link #getAddressRangeContaining}, {@link #isEmpty}) take no lock: they read the skip list
 * under an optimistic stamp and fall back to a read lock only if an update ran meanwhile, so they
 * always see a state between two complete updates, as before, without readers taking turns.
 * Iterators are weakly consistent views (the old ones were unsynchronized list walks).
 */
public class AddressRangeObjectMap<T> {

	/** A cached lookup result, valid only while no update has run since {@code stamp}. */
	private static final class CachedRange<T> {
		final AddressValueRange<T> range;
		final long stamp;

		CachedRange(AddressValueRange<T> range, long stamp) {
			this.range = range;
			this.stamp = stamp;
		}
	}

	private final ConcurrentSkipListMap<Address, AddressValueRange<T>> ranges;
	private final StampedLock lock = new StampedLock();
	private volatile CachedRange<T> lastRange;

	/**
	 * Constructs a new ObjectRangeMap
	 */
	public AddressRangeObjectMap() {
		ranges = new ConcurrentSkipListMap<>();
	}

	/**
	 * Test hook: orders keys with the given comparator (it must be consistent with
	 * {@link Address#compareTo}); used to count comparisons in the scaling test.
	 * @param comparator the address comparator
	 */
	AddressRangeObjectMap(Comparator<Address> comparator) {
		ranges = new ConcurrentSkipListMap<>(comparator);
	}

	/**
	 * Returns an {@link AddressRangeIterator} over all ranges that have associated objects.
	 * @return an {@link AddressRangeIterator} over all ranges that have associated objects.
	 */
	public AddressRangeIterator getAddressRangeIterator() {
		return new SimpleAddressRangeIterator();
	}

	/**
	 * Returns an {@link AddressRangeIterator} over all ranges that have associated objects within
	 * the given range.  Object Ranges that overlap the beginning or end of the given range are
	 * included, but have thier start or end index adjusted to be in the given range.
	 * @param start the first Address in the range to find all index ranges that have associated values.
	 * @param end the last Address(inclusive) in the range to find all index ranges that have associated
	 *  values.
	 * @return an {@link AddressRangeIterator} over all ranges that have associated objects within the
	 * given range.
	 */
	public AddressRangeIterator getAddressRangeIterator(Address start, Address end) {
		return new RestrictedIndexRangeIterator(start, end);
	}

	/**
	 * Move all values within an address range to a new range.
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor.
	 * @throws CancelledException if the user canceled the operation via the task monitor.
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		if (length <= 0) {
			return;
		}
		AddressRangeObjectMap<T> tmpMap = new AddressRangeObjectMap<T>();

		Address fromEndAddr = fromAddr.add(length - 1);
		for (AddressRange range : getAddressRangeIterator(fromAddr, fromEndAddr)) {
			monitor.checkCancelled();

			Address minAddr = range.getMinAddress();
			T value = getObject(minAddr);
			long offset = minAddr.subtract(fromAddr);
			minAddr = toAddr.add(offset);

			Address maxAddr = range.getMaxAddress();
			offset = maxAddr.subtract(fromAddr);
			maxAddr = toAddr.add(offset);

			tmpMap.setObject(minAddr, maxAddr, value);
		}
		clearRange(fromAddr, fromEndAddr);
		for (AddressRange range : tmpMap.getAddressRangeIterator()) {
			monitor.checkCancelled();
			T value = tmpMap.getObject(range.getMinAddress());
			setObject(range.getMinAddress(), range.getMaxAddress(), value);
		}
	}

	/**
	 * Associates the given object with all indices in the given range. The object may be null,
	 * but an association is still established.  Use the clearRange() method to remove associations.
	 * @param start the start of the range.
	 * @param end the end (inclusive) of the range.
	 * @param object the object to associate with the given range.
	 */
	public void setObject(Address start, Address end, T object) {
		long stamp = lock.writeLock();
		try {
			lastRange = null;
			setObjectLocked(start, end, object);
		}
		finally {
			lock.unlockWrite(stamp);
		}
	}

	private void setObjectLocked(Address start, Address end, T object) {
		AddressValueRange<T> newRange = new AddressValueRange<T>(start, end, object);

		// if the map is empty, just add the new entry
		if (ranges.isEmpty()) {
			ranges.put(start, newRange);
			return;
		}

		// Look at the stored range before the new range to see if it extends into the new range
		Map.Entry<Address, AddressValueRange<T>> previous = ranges.lowerEntry(start);
		if (previous != null) {
			newRange = adjustPreviousRangeForOverlap(start, end, object, newRange,
				previous.getValue());
		}

		// Every range that starts at or after 'start' and ends within the new range is replaced.
		// (A tail piece split off the previous range starts after 'end', so it is never removed.)
		Address newEnd = newRange.getEnd();
		removeCompletelyOverlappedRanges(start, newEnd);

		newRange = adjustRemainingRangeForOverlap(object, newRange, start, newEnd);

		ranges.put(newRange.getStart(), newRange);
	}

	private AddressValueRange<T> adjustRemainingRangeForOverlap(T object,
			AddressValueRange<T> newRange, Address start, Address newEnd) {

		Map.Entry<Address, AddressValueRange<T>> following = ranges.ceilingEntry(start);
		if (following == null) {
			return newRange; // no record to adjust
		}
		AddressValueRange<T> range = following.getValue();
		Address afterNew = newEnd.next();
		// afterNew == null: the new range ends at the top of its space, so any later range is in a
		// later space and cannot touch it (the original code threw a NullPointerException here,
		// after it had already removed the overlapped ranges, losing the new range).
		if (afterNew == null || range.getStart().compareTo(afterNew) > 0) { // no overlap
			return newRange;
		}

		ranges.remove(range.getStart());
		if (valuesEqual(range.getValue(), object)) { // merge records
			newRange = new AddressValueRange<T>(newRange.getStart(), range.getEnd(), object);
		}
		// overwrite the old record to start past the end of the new range
		else {
			ranges.put(afterNew, new AddressValueRange<T>(afterNew, range.getEnd(), range.getValue()));
		}

		return newRange;
	}

	private void removeCompletelyOverlappedRanges(Address start, Address newEnd) {
		Iterator<AddressValueRange<T>> it = ranges.tailMap(start, true).values().iterator();
		while (it.hasNext()) {
			AddressValueRange<T> range = it.next();
			if (range.getEnd().compareTo(newEnd) > 0) {
				return;
			}
			it.remove();
		}
	}

	private AddressValueRange<T> adjustPreviousRangeForOverlap(Address start, Address end,
			T object, AddressValueRange<T> newRange, AddressValueRange<T> previousRange) {

		Address beforeStart = start.previous();
		if ((beforeStart == null) || (previousRange.getEnd().compareTo(beforeStart) < 0)) {
			return newRange;  // no overlap
		}

		Address oldStart = previousRange.getStart();
		Address oldEnd = previousRange.getEnd();
		T oldValue = previousRange.getValue();

		if (valuesEqual(oldValue, object)) {  // same objects, merge
			ranges.remove(oldStart);
			newRange = new AddressValueRange<T>(oldStart, getMax(oldEnd, end), object);
		}
		// break previous record into sub-ranges that exclude the new range
		else {
			ranges.put(oldStart, new AddressValueRange<T>(oldStart, beforeStart, oldValue));

			// previous range extends past the new range
			if (oldEnd.compareTo(end) > 0) {
				Address afterEnd = end.next();
				ranges.put(afterEnd, new AddressValueRange<T>(afterEnd, oldEnd, oldValue));
			}
		}

		return newRange;
	}

	/**
	 * Clears all objects from map
	 */
	public void clearAll() {
		long stamp = lock.writeLock();
		try {
			ranges.clear();
			lastRange = null;
		}
		finally {
			lock.unlockWrite(stamp);
		}
	}

	/**
	 * Clears any object associations within the given range.
	 * @param start the first index in the range to be cleared.
	 * @param end the last index in the range to be cleared.
	 */
	public void clearRange(Address start, Address end) {
		long stamp = lock.writeLock();
		try {
			lastRange = null;
			clearRangeLocked(start, end);
		}
		finally {
			lock.unlockWrite(stamp);
		}
	}

	private void clearRangeLocked(Address start, Address end) {
		// check for range before that extends into cleared area
		Map.Entry<Address, AddressValueRange<T>> previous = ranges.lowerEntry(start);
		if (previous != null) {
			AddressValueRange<T> range = previous.getValue();
			if (range.getEnd().compareTo(start) >= 0) {		// truncate previous range if it needed
				ranges.put(range.getStart(),
					new AddressValueRange<T>(range.getStart(), start.previous(), range.getValue()));
			}
			if (range.getEnd().compareTo(end) > 0) {			// create leftover if previous range extends
				// beyond cleared area.
				Address afterEnd = end.next();
				ranges.put(afterEnd,
					new AddressValueRange<T>(afterEnd, range.getEnd(), range.getValue()));
			}
		}

		// now clear ranges until we find one past the cleared area
		Iterator<AddressValueRange<T>> it = ranges.tailMap(start, true).values().iterator();
		while (it.hasNext()) {
			AddressValueRange<T> range = it.next();
			if (range.getEnd().compareTo(end) <= 0) {			// range totally inside cleared area
				it.remove();
			}
			else if (range.getStart().compareTo(end) > 0) {		// range totally past clear area - done
				break;
			}
			else {											// intersects, fixup start
				it.remove();
				Address afterEnd = end.next();
				ranges.put(afterEnd,
					new AddressValueRange<T>(afterEnd, range.getEnd(), range.getValue()));
				break;
			}
		}
	}

	/**
	 * Returns the stored range starting at or before the address (it may not contain it), as a
	 * consistent read: optimistic and lock-free unless an update runs at the same time.
	 */
	private CachedRange<T> lookupAtOrBefore(Address address) {
		long stamp = lock.tryOptimisticRead();
		if (stamp != 0) {
			Map.Entry<Address, AddressValueRange<T>> e = ranges.floorEntry(address);
			if (lock.validate(stamp)) {
				return new CachedRange<>(e == null ? null : e.getValue(), stamp);
			}
		}
		stamp = lock.readLock();
		try {
			Map.Entry<Address, AddressValueRange<T>> e = ranges.floorEntry(address);
			return new CachedRange<>(e == null ? null : e.getValue(), stamp);
		}
		finally {
			lock.unlockRead(stamp);
		}
	}

	private AddressValueRange<T> cachedRangeContaining(Address address) {
		CachedRange<T> cached = lastRange;
		if (cached != null && cached.range.contains(address) && lock.validate(cached.stamp)) {
			return cached.range;
		}
		return null;
	}

	/**
	 * Returns true if the associated address has an associated object even if the assocated object
	 * is null.
	 * @param address the index to check for an association.
	 * @return true if the associated index has an associated object even if the assocated object
	 * is null.
	 */
	public boolean contains(Address address) {
		if (cachedRangeContaining(address) != null) {
			return true;
		}
		CachedRange<T> found = lookupAtOrBefore(address);
		if (found.range == null) {
			return false;
		}
		lastRange = found;
		return found.range.contains(address);
	}

	/**
	 * Returns the object associated with the given index or null if no object is associated with
	 * the given index.  Note that null is a valid association so a null result could be either
	 * no association or an actual association of the index to null.  Use the contains() method
	 * first if the distinction is important.  If the contains() method returns true, the result
	 * is cached so the next call to getObject() will be fast.
	 * @param address the index at which to retrieve an assocated object.
	 * @return the object (which can be null) associated with the given index or null if no such
	 * association exists.
	 */
	public T getObject(Address address) {
		if (address == null) {
			return null;
		}
		AddressValueRange<T> cached = cachedRangeContaining(address);
		if (cached != null) {
			return cached.getValue();
		}
		CachedRange<T> found = lookupAtOrBefore(address);
		if (found.range == null) {
			return null;
		}
		lastRange = found;
		if (found.range.contains(address)) {
			return found.range.getValue();
		}
		return null;
	}

	public boolean isEmpty() {
		long stamp = lock.tryOptimisticRead();
		if (stamp != 0) {
			boolean empty = ranges.isEmpty();
			if (lock.validate(stamp)) {
				return empty;
			}
		}
		stamp = lock.readLock();
		try {
			return ranges.isEmpty();
		}
		finally {
			lock.unlockRead(stamp);
		}
	}

	/** Number of stored ranges (test and diagnostics use). */
	int getRangeCount() {
		return ranges.size();
	}

	class SimpleAddressRangeIterator implements AddressRangeIterator {
		private final Iterator<AddressValueRange<T>> it = ranges.values().iterator();

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public AddressRange next() {
			AddressValueRange<T> valueRange = it.next();
			return new AddressRangeImpl(valueRange.getStart(), valueRange.getEnd());
		}

	}

	private boolean valuesEqual(Object value, Object obj) {
		if (value == null) {
			return obj == null;
		}
		return value.equals(obj);
	}

	private Address getMin(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) <= 0) {
			return addr1;
		}
		return addr2;
	}

	private Address getMax(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) >= 0) {
			return addr1;
		}
		return addr2;
	}

	class RestrictedIndexRangeIterator implements AddressRangeIterator {
		private final Address end;
		private final Iterator<AddressValueRange<T>> it;
		private AddressRange nextRange;

		RestrictedIndexRangeIterator(Address start, Address end) {
			this.end = end;
			Map.Entry<Address, AddressValueRange<T>> first = ranges.floorEntry(start);
			if (first != null) {
				AddressValueRange<T> range = first.getValue();
				it = ranges.tailMap(first.getKey(), false).values().iterator();
				if (range.contains(start)) {
					nextRange = new AddressRangeImpl(start, getMin(range.getEnd(), end));
				}
			}
			else {
				it = ranges.values().iterator();
			}
			if (nextRange == null) {
				getNextRange();
			}
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return nextRange != null;
		}

		@Override
		public AddressRange next() {
			AddressRange retRange = nextRange;
			if (nextRange != null) {
				getNextRange();
			}
			return retRange;
		}

		private void getNextRange() {
			nextRange = null;
			if (it.hasNext()) {
				AddressValueRange<T> range = it.next();
				if (range.getStart().compareTo(end) <= 0) {
					nextRange = new AddressRangeImpl(range.getStart(), getMin(range.getEnd(), end));
				}
			}

		}

	}

	/**
	 * Get the value or hole range containing the specified address
	 * @param addr
	 */
	public AddressRange getAddressRangeContaining(Address addr) {
		AddressValueRange<T> cached = cachedRangeContaining(addr);
		if (cached != null) {
			return new AddressRangeImpl(cached.getStart(), cached.getEnd());
		}

		long stamp = lock.tryOptimisticRead();
		if (stamp != 0) {
			try {
				AddressRange result = rangeContaining(addr, stamp);
				if (lock.validate(stamp)) {
					return result;
				}
			}
			catch (RuntimeException e) {
				// torn optimistic read during an update; retry under the read lock below
				if (lock.validate(stamp)) {
					throw e;
				}
			}
		}
		stamp = lock.readLock();
		try {
			return rangeContaining(addr, stamp);
		}
		finally {
			lock.unlockRead(stamp);
		}
	}

	private AddressRange rangeContaining(Address addr, long stamp) {
		Address min = addr.getAddressSpace().getMinAddress();
		Address max = addr.getAddressSpace().getMaxAddress();

		Map.Entry<Address, AddressValueRange<T>> before = ranges.floorEntry(addr);
		if (before != null) {
			AddressValueRange<T> range = before.getValue();
			if (range.getEnd().compareTo(addr) >= 0) {
				lastRange = new CachedRange<>(range, stamp);
				return new AddressRangeImpl(range.getStart(), range.getEnd());
			}
			if (min.getAddressSpace().equals(range.getEnd().getAddressSpace())) {
				min = range.getEnd().next();
			}
		}
		Map.Entry<Address, AddressValueRange<T>> after = ranges.higherEntry(addr);
		if (after != null) {
			AddressValueRange<T> range = after.getValue();
			if (max.getAddressSpace().equals(range.getStart().getAddressSpace())) {
				max = range.getStart().previous();
			}
		}
		return new AddressRangeImpl(min, max);
	}

	public void clearCache() {
		lastRange = null;
	}
}


/**
 * Associates an integer value with a numeric range.
 */
class AddressValueRange<T> implements Comparable<AddressValueRange<T>> {
	private Address start;
	private Address end;
	private T value;

	/**
	 * Constructor for numeric range with an associated value.
	 * @param start beginning of the range
	 * @param end end of the range
	 * @param value the value to associate with the range.
	 */
	public AddressValueRange(Address start, Address end, T value) {
		this.start = start;
		this.end = end;
		this.value = value;
	}

	/**
	 * Returns the beginning of the range.
	 */
	public Address getStart() {
		return start;
	}

	/**
	 * Returns the end of the range.
	 */
	public Address getEnd() {
		return end;
	}

	/**
	 * Returns the value associated with the range.
	 */
	public T getValue() {
		return value;
	}

	/**
	 * Determines whether or not the indicated index is in the range.
	 * @param address the index to check
	 * @return true if the index is in this range.
	 */
	public boolean contains(Address address) {
		return address.compareTo(start) >= 0 && address.compareTo(end) <= 0;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(AddressValueRange<T> otherRange) {
		return start.compareTo(otherRange.start);
	}

	@Override
	public String toString() {
		return start + ":" + end + "[" + value + "]";
	}
}
