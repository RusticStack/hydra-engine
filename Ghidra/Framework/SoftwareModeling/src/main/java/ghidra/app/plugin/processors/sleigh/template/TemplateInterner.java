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
	private final ConstTpl constScratch = new ConstTpl();
	private final VarnodeTpl varnodeScratch = new VarnodeTpl();
	// open-addressing tables (power-of-two size, linear probing): a lookup allocates nothing
	private ConstTpl[] consts = new ConstTpl[1 << 12];
	private int constCount;
	private VarnodeTpl[] varnodes = new VarnodeTpl[1 << 12];
	private int varnodeCount;
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

	/** @return the nearest table at or below t that is still open, or null */
	private static TemplateInterner firstOpen(TemplateInterner t) {
		while (t != null && t.closed) {
			t = t.previous;
		}
		return t;
	}

	@Override
	public void close() {
		if (closed) {
			return;
		}
		closed = true;
		// Tables may be closed out of order: only the active table hands the thread back, and
		// never to a table that is already closed. A table closed while another is active leaves
		// that one active; it is skipped when that one closes.
		TemplateInterner current = ACTIVE.get();
		if (current == this) {
			TemplateInterner next = firstOpen(previous);
			if (next == null) {
				ACTIVE.remove();
			}
			else {
				ACTIVE.set(next);
			}
		}
		consts = new ConstTpl[0];
		varnodes = new VarnodeTpl[0];
	}

	/** @return the object a ConstTpl is decoded into before {@link #intern(ConstTpl)} */
	ConstTpl constScratch() {
		return constScratch;
	}

	/** @return the object a VarnodeTpl is decoded into before {@link #intern(VarnodeTpl)} */
	VarnodeTpl varnodeScratch() {
		return varnodeScratch;
	}

	private static int mix(int h) {
		h *= 0x9E3779B9;
		return h ^ (h >>> 16);
	}

	private static int hash(ConstTpl c) {
		int h = c.getType();
		h = 31 * h + Long.hashCode(c.getReal());
		h = 31 * h + System.identityHashCode(c.getSpaceId());
		h = 31 * h + c.getHandleIndex();
		h = 31 * h + c.getSelect();
		return mix(h);
	}

	private static boolean same(ConstTpl a, ConstTpl b) {
		// the address space by identity: a table never mixes two languages' spaces
		return a.getType() == b.getType() && a.getReal() == b.getReal() &&
			a.getSpaceId() == b.getSpaceId() && a.getHandleIndex() == b.getHandleIndex() &&
			a.getSelect() == b.getSelect();
	}

	private static int hash(VarnodeTpl v) {
		int h = System.identityHashCode(v.getSpace());
		h = 31 * h + System.identityHashCode(v.getOffset());
		h = 31 * h + System.identityHashCode(v.getSize());
		return mix(h);
	}

	private static boolean same(VarnodeTpl a, VarnodeTpl b) {
		// the parts are shared already, so identity is equality
		return a.getSpace() == b.getSpace() && a.getOffset() == b.getOffset() &&
			a.getSize() == b.getSize();
	}

	/**
	 * @param c a template (possibly the scratch object, which is never stored)
	 * @return the shared template equal to c
	 */
	ConstTpl intern(ConstTpl c) {
		constLookups++;
		int mask = consts.length - 1;
		int i = hash(c) & mask;
		for (ConstTpl e; (e = consts[i]) != null; i = (i + 1) & mask) {
			if (same(e, c)) {
				return e;
			}
		}
		ConstTpl kept = c == constScratch ? new ConstTpl(c) : c;
		consts[i] = kept;
		if (++constCount * 2 > consts.length) {
			consts = grow(consts, new ConstTpl[consts.length * 2]);
		}
		return kept;
	}

	/**
	 * @param v a template (possibly the scratch object, which is never stored)
	 * @return the shared template equal to v
	 */
	VarnodeTpl intern(VarnodeTpl v) {
		varnodeLookups++;
		int mask = varnodes.length - 1;
		int i = hash(v) & mask;
		for (VarnodeTpl e; (e = varnodes[i]) != null; i = (i + 1) & mask) {
			if (same(e, v)) {
				return e;
			}
		}
		VarnodeTpl kept =
			v == varnodeScratch ? new VarnodeTpl(v.getSpace(), v.getOffset(), v.getSize()) : v;
		varnodes[i] = kept;
		if (++varnodeCount * 2 > varnodes.length) {
			varnodes = grow(varnodes, new VarnodeTpl[varnodes.length * 2]);
		}
		return kept;
	}

	private static ConstTpl[] grow(ConstTpl[] old, ConstTpl[] table) {
		int mask = table.length - 1;
		for (ConstTpl e : old) {
			if (e != null) {
				int i = hash(e) & mask;
				while (table[i] != null) {
					i = (i + 1) & mask;
				}
				table[i] = e;
			}
		}
		return table;
	}

	private static VarnodeTpl[] grow(VarnodeTpl[] old, VarnodeTpl[] table) {
		int mask = table.length - 1;
		for (VarnodeTpl e : old) {
			if (e != null) {
				int i = hash(e) & mask;
				while (table[i] != null) {
					i = (i + 1) & mask;
				}
				table[i] = e;
			}
		}
		return table;
	}

	/** @return the number of distinct {@link ConstTpl} values kept */
	public int distinctConsts() {
		return constCount;
	}

	/** @return the number of {@link ConstTpl} objects decoded through this table */
	public long constLookups() {
		return constLookups;
	}

	/** @return the number of distinct {@link VarnodeTpl} values kept */
	public int distinctVarnodes() {
		return varnodeCount;
	}

	/** @return the number of {@link VarnodeTpl} objects decoded through this table */
	public long varnodeLookups() {
		return varnodeLookups;
	}
}
