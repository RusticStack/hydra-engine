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
package ghidra.app.plugin.processors.sleigh.template;

import java.util.HashMap;

import ghidra.program.model.address.AddressSpace;

/**
 * Hydra: a flyweight table for the immutable {@link ConstTpl} and {@link VarnodeTpl} objects
 * decoded from a {@code .sla} file.
 * <p>
 * A language's p-code templates hold hundreds of thousands of {@link ConstTpl} objects, almost
 * all of them repeats of a few thousand distinct values (the same constants, sizes, handle
 * selectors and space references). While a table is open on the decoding thread,
 * {@link ConstTpl#decodeShared} and {@link VarnodeTpl#decodeShared} return one shared instance
 * per distinct value instead of a new object per occurrence. Templates are never modified after
 * decode, and nothing compares them by identity, so sharing them changes no behavior.
 * <p>
 * The table only lives for one decode: {@link #close()} drops it, so nothing outlives the
 * language's own templates. Address spaces are compared by identity, so instances of one language
 * are never shared with another. With no table open, decoding allocates as before.
 */
public final class TemplateInterner implements AutoCloseable {

	private static final ThreadLocal<TemplateInterner> ACTIVE = new ThreadLocal<>();

	private final TemplateInterner previous;
	private final HashMap<ConstKey, ConstTpl> consts = new HashMap<>();
	private final HashMap<VarnodeKey, VarnodeTpl> varnodes = new HashMap<>();
	private long constLookups;
	private long varnodeLookups;
	private boolean closed;

	private TemplateInterner(TemplateInterner previous) {
		this.previous = previous;
	}

	/**
	 * Open a table on the current thread; templates decoded on this thread until {@link #close()}
	 * are shared through it.
	 * @return the table, to close in a try-with-resources
	 */
	public static TemplateInterner open() {
		TemplateInterner interner = new TemplateInterner(ACTIVE.get());
		ACTIVE.set(interner);
		return interner;
	}

	/**
	 * @return the table open on the current thread, or null
	 */
	static TemplateInterner active() {
		return ACTIVE.get();
	}

	@Override
	public void close() {
		if (closed) {
			return;
		}
		closed = true;
		if (previous == null) {
			ACTIVE.remove();
		}
		else {
			ACTIVE.set(previous);
		}
		consts.clear();
		varnodes.clear();
	}

	ConstTpl intern(ConstTpl c) {
		constLookups++;
		return consts.computeIfAbsent(new ConstKey(c), k -> c);
	}

	VarnodeTpl intern(VarnodeTpl v) {
		varnodeLookups++;
		return varnodes.computeIfAbsent(new VarnodeKey(v), k -> v);
	}

	/** @return the number of distinct {@link ConstTpl} values kept */
	public int distinctConsts() {
		return consts.size();
	}

	/** @return the number of {@link ConstTpl} objects decoded through this table */
	public long constLookups() {
		return constLookups;
	}

	/** @return the number of distinct {@link VarnodeTpl} values kept */
	public int distinctVarnodes() {
		return varnodes.size();
	}

	/** @return the number of {@link VarnodeTpl} objects decoded through this table */
	public long varnodeLookups() {
		return varnodeLookups;
	}

	/** Value of a ConstTpl, with the address space compared by identity. */
	private static final class ConstKey {
		private final int type;
		private final long real;
		private final AddressSpace space;
		private final int handle;
		private final int select;
		private final int hash;

		ConstKey(ConstTpl c) {
			type = c.getType();
			real = c.getReal();
			space = c.getSpaceId();
			handle = c.getHandleIndex();
			select = c.getSelect();
			int h = type;
			h = 31 * h + Long.hashCode(real);
			h = 31 * h + System.identityHashCode(space);
			h = 31 * h + handle;
			h = 31 * h + select;
			hash = h;
		}

		@Override
		public int hashCode() {
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ConstKey o)) {
				return false;
			}
			return type == o.type && real == o.real && space == o.space && handle == o.handle &&
				select == o.select;
		}
	}

	/** A VarnodeTpl by the identity of its three (already shared) parts. */
	private static final class VarnodeKey {
		private final ConstTpl space;
		private final ConstTpl offset;
		private final ConstTpl size;
		private final int hash;

		VarnodeKey(VarnodeTpl v) {
			space = v.getSpace();
			offset = v.getOffset();
			size = v.getSize();
			hash = 31 * (31 * System.identityHashCode(space) + System.identityHashCode(offset)) +
				System.identityHashCode(size);
		}

		@Override
		public int hashCode() {
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof VarnodeKey o)) {
				return false;
			}
			return space == o.space && offset == o.offset && size == o.size;
		}
	}
}
