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
package ghidra.program.util;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import org.junit.After;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;

/**
 * The read-back overlay of {@link DeferredProgramWrites}: while a collector is open, a worker
 * sees the references it recorded earlier in the same location (as the immediate-write code
 * saw its own writes), and only its own.
 * <p>
 * Regression for the x64 fixtures: {@code mov rdi,[rdi+rax*8]} with rdi = 0x140022f70. The
 * load makes a READ reference on operand 1; the speculative DATA reference to the same
 * address then picks its operand with {@code getOperandType}/{@code getAddress}, which report
 * the operand's primary reference. With the READ reference only recorded, operand 1 looked
 * reference-less, the register operand 0 matched instead, and an extra operand-0 DATA
 * reference was created.
 */
public class DeferredProgramWritesReadBackTest {

	private static final AddressSpace SPACE =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

	private static Address a(long off) {
		return SPACE.getAddress(off);
	}

	private DeferredProgramWrites open;

	@After
	public void tearDown() {
		if (open != null) {
			open.close();
		}
	}

	/** An instruction at {@code at} whose program references are {@code programRefs}. */
	private static Instruction instr(Address at, List<Reference> programRefs) {
		return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
			new Class<?>[] { Instruction.class }, (p, m, args) -> {
				switch (m.getName()) {
					case "getMinAddress":
					case "getAddress":
						if (args == null || args.length == 0) {
							return at;
						}
						throw new UnsupportedOperationException(m.toString());
					case "getReferencesFrom":
						return programRefs.toArray(new Reference[0]);
					case "getOperandReferences": {
						int op = (Integer) args[0];
						return programRefs.stream()
								.filter(r -> r.getOperandIndex() == op)
								.toArray(Reference[]::new);
					}
					case "hashCode":
						return System.identityHashCode(p);
					case "equals":
						return p == args[0];
					case "toString":
						return "instr@" + at;
					default:
						throw new UnsupportedOperationException(m.toString());
				}
			});
	}

	private static Reference ref(Address from, Address to, RefType t, int op) {
		return new MemReferenceImpl(from, to, t, SourceType.ANALYSIS, op, true);
	}

	@Test
	public void testNoCollectorIsProgramView() {
		Address at = a(0x140009d1aL);
		List<Reference> prog = List.of(ref(at, a(0x140022f70L), RefType.READ, 1));
		Instruction in = instr(at, prog);
		DeferredProgramWrites.noteReferenceAdded(at, a(0x1000), RefType.DATA, 0); // ignored
		assertArrayEquals(prog.toArray(), DeferredProgramWrites.referencesFrom(in));
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 0));
		assertFalse(DeferredProgramWrites.hasPendingReferenceTo(a(0x1000)));
	}

	@Test
	public void testRecordedOperandReferenceIsPrimaryOfEmptyOperand() {
		Address at = a(0x140009d1aL);
		Address target = a(0x140022f70L);
		Instruction in = instr(at, new ArrayList<>());
		open = DeferredProgramWrites.open();
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 1));

		DeferredProgramWrites.noteReferenceAdded(at, target, RefType.READ, 1);
		assertEquals(target, DeferredProgramWrites.pendingOperandAddress(in, 1));
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 0));
		assertTrue(DeferredProgramWrites.hasPendingReferenceTo(target));

		// a later reference on the same operand does not become primary
		DeferredProgramWrites.noteReferenceAdded(at, a(0x140022f78L), RefType.DATA, 1);
		assertEquals(target, DeferredProgramWrites.pendingOperandAddress(in, 1));

		Reference[] refs = DeferredProgramWrites.referencesFrom(in);
		assertEquals(2, refs.length);
		assertEquals(target, refs[0].getToAddress());
		assertEquals(1, refs[0].getOperandIndex());
	}

	@Test
	public void testProgramReferenceOnOperandWins() {
		Address at = a(0x401000);
		Instruction in = instr(at, List.of(ref(at, a(0x402000), RefType.DATA, 1)));
		open = DeferredProgramWrites.open();
		DeferredProgramWrites.noteReferenceAdded(at, a(0x403000), RefType.READ, 1);
		// the program's reference stays the primary one: no overlay for this operand
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 1));
	}

	@Test
	public void testReferencesFromMergesInManagerOrder() {
		Address at = a(0x401000);
		Reference p0 = ref(at, a(0x402000), RefType.DATA, 0);
		Reference pParam = ref(at, a(0x404000), RefType.PARAM, -1);
		Instruction in = instr(at, List.of(p0, pParam));
		open = DeferredProgramWrites.open();

		DeferredProgramWrites.noteReferenceAdded(at, a(0x402000), RefType.READ, 0); // merges
		DeferredProgramWrites.noteReferenceAdded(at, a(0x405000), RefType.DATA, 1);
		DeferredProgramWrites.noteReferenceAdded(at, a(0x405000), RefType.DATA, 1); // dup
		DeferredProgramWrites.noteReferenceRemoved(at, a(0x404000), -1);

		Reference[] refs = DeferredProgramWrites.referencesFrom(in);
		assertEquals(2, refs.length);
		assertSame(p0, refs[0]);
		assertEquals(a(0x405000), refs[1].getToAddress());
		assertEquals(1, refs[1].getOperandIndex());

		// a recorded add after a recorded removal of the same reference brings it back
		DeferredProgramWrites.noteReferenceAdded(at, a(0x404000), RefType.PARAM, -1);
		assertEquals(3, DeferredProgramWrites.referencesFrom(in).length);

		// other instructions are untouched
		Address other = a(0x401010);
		assertEquals(0, DeferredProgramWrites.referencesFrom(instr(other, List.of())).length);
	}

	@Test
	public void testCloseDropsOverlay() {
		Address at = a(0x401000);
		Instruction in = instr(at, new ArrayList<>());
		DeferredProgramWrites d = DeferredProgramWrites.open();
		DeferredProgramWrites.noteReferenceAdded(at, a(0x402000), RefType.DATA, 0);
		d.close();
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 0));
		assertEquals(0, DeferredProgramWrites.referencesFrom(in).length);
		assertFalse(DeferredProgramWrites.hasPendingReferenceTo(a(0x402000)));

		open = DeferredProgramWrites.open(); // a new collector starts empty
		assertNull(DeferredProgramWrites.pendingOperandAddress(in, 0));
	}

	@Test
	public void testOtherWorkersDoNotSeeRecordedReferences() throws Exception {
		Address at = a(0x401000);
		Instruction in = instr(at, new ArrayList<>());
		open = DeferredProgramWrites.open();
		DeferredProgramWrites.noteReferenceAdded(at, a(0x402000), RefType.DATA, 0);

		ExecutorService ex = Executors.newSingleThreadExecutor();
		try {
			Future<Object[]> f = ex.submit(() -> {
				DeferredProgramWrites other = DeferredProgramWrites.open();
				try {
					return new Object[] { DeferredProgramWrites.pendingOperandAddress(in, 0),
						DeferredProgramWrites.referencesFrom(in).length,
						DeferredProgramWrites.hasPendingReferenceTo(a(0x402000)) };
				}
				finally {
					other.close();
				}
			});
			Object[] seen = f.get(30, TimeUnit.SECONDS);
			assertNull(seen[0]);
			assertEquals(0, seen[1]);
			assertEquals(false, seen[2]);
		}
		finally {
			ex.shutdownNow();
		}
		assertEquals(a(0x402000), DeferredProgramWrites.pendingOperandAddress(in, 0));
	}
}
