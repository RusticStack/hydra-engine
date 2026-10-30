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

import static ghidra.pcode.utils.SlaFormat.*;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;

/**
 * Hydra: equal sleigh templates decoded while a {@link TemplateInterner} is open share one object,
 * and decode exactly as without it.
 */
public class TemplateInternerTest {

	private AddressSpace ram;
	private AddressSpace unique;
	private AddressSpace constSpace;
	private AddressFactory addrFactory;

	@Before
	public void setUp() {
		AddressSpace spaces[] = new AddressSpace[3];
		spaces[0] = ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 2);
		spaces[1] = constSpace =
			new GenericAddressSpace("const", 32, AddressSpace.TYPE_CONSTANT, 0);
		spaces[2] = unique = new GenericAddressSpace("unique", 32, AddressSpace.TYPE_UNIQUE, 1);
		addrFactory = new DefaultAddressFactory(spaces);
	}

	private static void real(PatchPackedEncode enc, long v) throws IOException {
		enc.openElement(ELEM_CONST_REAL);
		enc.writeUnsignedInteger(ATTRIB_VAL, v);
		enc.closeElement(ELEM_CONST_REAL);
	}

	private static void space(PatchPackedEncode enc, AddressSpace spc) throws IOException {
		enc.openElement(ELEM_CONST_SPACEID);
		enc.writeSpace(ATTRIB_SPACE, spc);
		enc.closeElement(ELEM_CONST_SPACEID);
	}

	private static void handle(PatchPackedEncode enc, int index, int sel, long plus)
			throws IOException {
		enc.openElement(ELEM_CONST_HANDLE);
		enc.writeSignedInteger(ATTRIB_VAL, index);
		enc.writeSignedInteger(ATTRIB_S, sel);
		if (sel == ConstTpl.V_OFFSET_PLUS) {
			enc.writeUnsignedInteger(ATTRIB_PLUS, plus);
		}
		enc.closeElement(ELEM_CONST_HANDLE);
	}

	private static void varnode(PatchPackedEncode enc, AddressSpace spc, long off, long size)
			throws IOException {
		enc.openElement(ELEM_VARNODE_TPL);
		space(enc, spc);
		real(enc, off);
		real(enc, size);
		enc.closeElement(ELEM_VARNODE_TPL);
	}

	/**
	 * Two COPY ops: unique:0x100:4 = const:0x10:4, ram:0x10:4, [handle 0 offset+X], where X is
	 * 0x10003 in the first op and 0x20003 in the second.
	 */
	private byte[] encodeOps() throws IOException {
		PatchPackedEncode enc = new PatchPackedEncode();
		enc.clear();
		enc.openElement(ELEM_CONSTRUCT_TPL);
		for (int i = 0; i < 2; i++) {
			enc.openElement(ELEM_OP_TPL);
			enc.writeOpcode(ATTRIB_CODE, PcodeOp.COPY);
			varnode(enc, unique, 0x100, 4);
			varnode(enc, constSpace, 0x10, 4);
			varnode(enc, ram, 0x10, 4);
			enc.openElement(ELEM_VARNODE_TPL);
			handle(enc, 0, ConstTpl.V_SPACE, 0);
			handle(enc, 0, ConstTpl.V_OFFSET_PLUS, i == 0 ? 0x10003 : 0x20003);
			handle(enc, 0, ConstTpl.V_SIZE, 0);
			enc.closeElement(ELEM_VARNODE_TPL);
			enc.closeElement(ELEM_OP_TPL);
		}
		enc.closeElement(ELEM_CONSTRUCT_TPL);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		enc.writeTo(out);
		return out.toByteArray();
	}

	private OpTpl[] decodeOps(byte[] bytes) throws IOException, DecoderException {
		PackedDecode decoder = new PackedDecode(addrFactory);
		decoder.open(1 << 16, "test");
		decoder.ingestBytes(bytes, 0, bytes.length);
		decoder.endIngest();
		int el = decoder.openElement(ELEM_CONSTRUCT_TPL);
		OpTpl[] ops = new OpTpl[2];
		for (int i = 0; i < 2; i++) {
			ops[i] = new OpTpl();
			ops[i].decode(decoder);
		}
		decoder.closeElement(el);
		return ops;
	}

	@Test
	public void testEqualTemplatesAreShared() throws Exception {
		byte[] bytes = encodeOps();
		OpTpl[] ops;
		try (TemplateInterner interner = TemplateInterner.open()) {
			ops = decodeOps(bytes);
			assertEquals(8, interner.varnodeLookups());
			assertEquals(24, interner.constLookups());
			// unique, const and ram varnodes, and the two handle varnodes
			assertEquals(5, interner.distinctVarnodes());
			// spaces unique, const, ram; reals 0x100, 4, 0x10; handle space, size, two offset+
			assertEquals(10, interner.distinctConsts());
		}
		assertNull(TemplateInterner.active());

		// The same varnode in the two ops is one object
		assertSame(ops[0].getOutput(), ops[1].getOutput());
		assertSame(ops[0].getInput()[0], ops[1].getInput()[0]);
		assertSame(ops[0].getInput()[1], ops[1].getInput()[1]);
		// The same constant in different varnodes is one object
		assertSame(ops[0].getOutput().getSize(), ops[0].getInput()[0].getSize());
		assertSame(ops[0].getInput()[0].getOffset(), ops[0].getInput()[1].getOffset());
		assertSame(ops[0].getInput()[2].getSpace(), ops[1].getInput()[2].getSpace());

		// Different values stay apart: spaces by identity, offset+ by its truncation
		assertNotSame(ops[0].getInput()[0], ops[0].getInput()[1]);
		assertNotSame(ops[0].getInput()[0].getSpace(), ops[0].getInput()[1].getSpace());
		assertNotSame(ops[0].getInput()[2], ops[1].getInput()[2]);
		assertNotSame(ops[0].getInput()[2].getOffset(), ops[1].getInput()[2].getOffset());
		assertEquals(0x10003, ops[0].getInput()[2].getOffset().getReal());
		assertEquals(0x20003, ops[1].getInput()[2].getOffset().getReal());
	}

	@Test
	public void testSharedDecodeMatchesPlainDecode() throws Exception {
		byte[] bytes = encodeOps();
		OpTpl[] plain = decodeOps(bytes);
		OpTpl[] shared;
		try (TemplateInterner in = TemplateInterner.open()) {
			shared = decodeOps(bytes);
		}
		for (int i = 0; i < 2; i++) {
			assertEquals(plain[i].toString(), shared[i].toString());
			assertEquals(plain[i].getOpcode(), shared[i].getOpcode());
			assertConstEquals(plain[i].getOutput().getSpace(), shared[i].getOutput().getSpace());
			VarnodeTpl[] pin = plain[i].getInput();
			VarnodeTpl[] sin = shared[i].getInput();
			assertEquals(pin.length, sin.length);
			for (int j = 0; j < pin.length; j++) {
				assertConstEquals(pin[j].getSpace(), sin[j].getSpace());
				assertConstEquals(pin[j].getOffset(), sin[j].getOffset());
				assertConstEquals(pin[j].getSize(), sin[j].getSize());
			}
		}
		assertSame(constSpace, shared[0].getInput()[0].getSpace().getSpaceId());
		assertTrue(shared[0].getInput()[0].getSpace().isConstSpace());
		assertTrue(shared[0].getOutput().getSpace().isUniqueSpace());
	}

	private static void assertConstEquals(ConstTpl a, ConstTpl b) {
		assertEquals(a.getType(), b.getType());
		assertEquals(a.getReal(), b.getReal());
		assertSame(a.getSpaceId(), b.getSpaceId());
		assertEquals(a.getHandleIndex(), b.getHandleIndex());
		assertEquals(a.getSelect(), b.getSelect());
	}

	@Test
	public void testNoTableDecodesNewObjects() throws Exception {
		assertNull(TemplateInterner.active());
		OpTpl[] ops = decodeOps(encodeOps());
		assertNotSame(ops[0].getOutput(), ops[1].getOutput());
		assertNotSame(ops[0].getOutput().getSize(), ops[0].getInput()[0].getSize());
	}

	@Test
	public void testTablesNestAndDoNotLeak() throws Exception {
		byte[] bytes = encodeOps();
		try (TemplateInterner outer = TemplateInterner.open()) {
			OpTpl[] a = decodeOps(bytes);
			try (TemplateInterner inner = TemplateInterner.open()) {
				assertSame(inner, TemplateInterner.active());
				OpTpl[] b = decodeOps(bytes);
				// a separate table never hands out the other's objects
				assertNotSame(a[0].getOutput(), b[0].getOutput());
				assertSame(b[0].getOutput(), b[1].getOutput());
			}
			assertSame(outer, TemplateInterner.active());
			OpTpl[] c = decodeOps(bytes);
			assertSame(a[0].getOutput(), c[0].getOutput());
			outer.close();
			outer.close(); // closing twice is harmless
			assertNull(TemplateInterner.active());
		}
		assertNull(TemplateInterner.active());
	}
}
