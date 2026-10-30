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
package ghidra.program.database;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;

/**
 * Hydra (mem-views): {@link ProgramDB#disableChangeRecording()} and
 * {@link ghidra.framework.data.DomainObjectAdapterDB#setUndoDepth(int)}, what a light overlay of
 * the headless session uses.
 */
public class ProgramDBLightViewTest extends AbstractGenericTest {

	private ProgramDB p;
	private Listing listing;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Light", ProgramBuilder._X86);
		builder.createMemory("RAM", "0x1000", 0x1000);
		p = builder.getProgram();
		p.addConsumer(this);
		builder.dispose();
		// as if opened from a project file: changes count and are recorded (setDomainFile does that)
		p.setTemporary(false);
		p.setDomainFile(p.getDomainFile());
		p.clearUndo();
		listing = p.getListing();
	}

	@After
	public void tearDown() throws Exception {
		p.release(this);
	}

	private Address a(long off) {
		return p.getAddressFactory().getDefaultAddressSpace().getAddress(off);
	}

	private void comment(long off, String text, boolean commit) {
		int tx = p.startTransaction("c");
		try {
			listing.setComment(a(off), CommentType.EOL, text);
		}
		finally {
			p.endTransaction(tx, commit);
		}
	}

	private AddressSetView changes() {
		return p.getChanges().getAddressSet();
	}

	private String comment(long off) {
		return listing.getComment(CommentType.EOL, a(off));
	}

	@Test
	public void testDefaultRecordsChanges() {
		assertTrue(p.isRecordingChanges());
		comment(0x1010, "x", true);
		assertTrue(changes().contains(a(0x1010)));
	}

	@Test
	public void testDisableChangeRecording() {
		comment(0x1004, "before", true);
		p.disableChangeRecording();
		assertFalse(p.isRecordingChanges());
		// what was recorded is forgotten, nothing new is recorded, isChanged() still works
		assertTrue(changes().isEmpty());
		comment(0x1010, "x", true);
		assertTrue(p.isChanged());
		assertTrue(changes().isEmpty());
		assertEquals("x", comment(0x1010));
	}

	@Test
	public void testUndoDepthDefault() {
		assertEquals(50, p.getUndoDepth());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testUndoDepthZeroRefused() {
		p.setUndoDepth(0);
	}

	@Test
	public void testUndoDepthOneKeepsRollback() throws Exception {
		p.disableChangeRecording();
		p.setUndoDepth(1);
		assertEquals(1, p.getUndoDepth());
		for (int i = 0; i < 20; i++) {
			comment(0x1000 + (i % 4) * 4, "c" + i, true); // the same buffers again and again
		}
		comment(0x1100, "b", true);
		// a failing transaction after many packed ones restores exactly the state before it
		int tx = p.startTransaction("fail");
		listing.setComment(a(0x1200), CommentType.EOL, "never");
		listing.setComment(a(0x1000), CommentType.EOL, "overwritten");
		p.endTransaction(tx, false);
		assertNull(comment(0x1200));
		assertEquals("c16", comment(0x1000));
		assertEquals("c19", comment(0x100c));
		assertEquals("b", comment(0x1100));
		// the rollback used the one checkpoint besides the baseline: nothing is left to undo
		assertFalse(p.canUndo());
		// one undoable transaction is kept, not 50
		comment(0x1100, "b2", true);
		comment(0x1104, "d", true);
		assertTrue(p.canUndo());
		p.undo();
		assertNull(comment(0x1104));
		assertEquals("b2", comment(0x1100));
		assertFalse(p.canUndo());
	}

	@Test
	public void testUndoDepthRefusedInsideTransaction() {
		int tx = p.startTransaction("open");
		try {
			p.setUndoDepth(1);
			fail("setUndoDepth inside a transaction must be refused");
		}
		catch (IllegalStateException expected) {
			assertEquals(50, p.getUndoDepth());
		}
		finally {
			p.endTransaction(tx, true);
		}
	}

	@Test
	public void testLightDepthKeepsChangeRecording() {
		// what a light overlay does (PrivateInstance.lighten): depth 1 only, getChanges() works
		p.setUndoDepth(1);
		comment(0x1010, "x", true);
		comment(0x1020, "y", true);
		assertTrue(p.isRecordingChanges());
		assertTrue(changes().contains(a(0x1010)));
		assertTrue(changes().contains(a(0x1020)));
	}

	@Test
	public void testRestoredDepthKeepsManyUndosAgain() throws Exception {
		// PrivateInstance.unlighten before an overlay script: later transactions undo as by default
		p.setUndoDepth(1);
		comment(0x1000, "a", true);
		p.setUndoDepth(ProgramDB.DEFAULT_UNDO_DEPTH);
		assertEquals(50, p.getUndoDepth());
		for (int i = 0; i < 5; i++) {
			comment(0x1000, "c" + i, true);
		}
		for (int i = 0; i < 4; i++) {
			p.undo();
		}
		assertEquals("c0", comment(0x1000));
	}

	@Test
	public void testDefaultDepthKeepsManyUndos() throws Exception {
		for (int i = 0; i < 5; i++) {
			comment(0x1000, "c" + i, true);
		}
		for (int i = 0; i < 4; i++) {
			p.undo();
		}
		assertEquals("c0", comment(0x1000));
	}
}
