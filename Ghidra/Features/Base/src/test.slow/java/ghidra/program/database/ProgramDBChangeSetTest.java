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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.LinkedList;
import java.util.Random;

import org.junit.*;

import db.DBHandle;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class ProgramDBChangeSetTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDBChangeSet pcs;
	private AddressSpace space;
	private ProgramDB program;

	public ProgramDBChangeSetTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("TEST", "00000000", 0x100);
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		program.addConsumer(this);
		builder.dispose();

		pcs = new ProgramDBChangeSet(program.getAddressMap(), 20); // read not supported
	}

	@After
	public void tearDown() {
		program.release(this);
	}

	@Test
	public void testAddressDiffs() {
		pcs.startTransaction();
		pcs.addRange(addr(0), addr(9));
		pcs.endTransaction(true);
		assertEquals(10, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getAddressSet().getMaxAddress());

		pcs.startTransaction();
		pcs.addRange(addr(5), addr(14));
		pcs.endTransaction(true);
		assertEquals(15, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(14), pcs.getAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(10, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(0, pcs.getAddressSet().getNumAddresses());

		pcs.redo();
		assertEquals(10, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getAddressSet().getMaxAddress());

		pcs.redo();
		assertEquals(15, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(14), pcs.getAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(10, pcs.getAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getAddressSet().getMaxAddress());
	}

	@Test
	public void testRegAddressDiffs() {
		pcs.startTransaction();
		pcs.addRegisterRange(addr(0), addr(9));
		pcs.endTransaction(true);
		assertEquals(10, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getRegisterAddressSet().getMaxAddress());

		pcs.startTransaction();
		pcs.addRegisterRange(addr(5), addr(14));
		pcs.endTransaction(true);
		assertEquals(15, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(14), pcs.getRegisterAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(10, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getRegisterAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(0, pcs.getRegisterAddressSet().getNumAddresses());

		pcs.redo();
		assertEquals(10, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getRegisterAddressSet().getMaxAddress());

		pcs.redo();
		assertEquals(15, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(14), pcs.getRegisterAddressSet().getMaxAddress());

		pcs.undo();
		assertEquals(10, pcs.getRegisterAddressSet().getNumAddresses());
		assertEquals(addr(0), pcs.getRegisterAddressSet().getMinAddress());
		assertEquals(addr(9), pcs.getRegisterAddressSet().getMaxAddress());
	}

	@Test
	public void testDataTypeChanges() {
		pcs.startTransaction();
		pcs.dataTypeChanged(5);
		pcs.dataTypeChanged(6);
		pcs.endTransaction(true);
		pcs.startTransaction();
		pcs.dataTypeChanged(5);
		pcs.endTransaction(true);

		long[] changes = pcs.getDataTypeChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 || changes[1] == 5) &&
			(changes[0] == 6 || changes[1] == 6));

		pcs.undo();
		changes = pcs.getDataTypeChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 || changes[1] == 5) &&
			(changes[0] == 6 || changes[1] == 6));

		pcs.undo();
		changes = pcs.getDataTypeChanges();
		assertEquals(0, changes.length);
	}

	@Test
	public void testDataTypeChanges2() {
		pcs.startTransaction();
		pcs.dataTypeAdded(6);
		pcs.dataTypeChanged(5);
		pcs.dataTypeChanged(6);
		pcs.endTransaction(true);
		pcs.startTransaction();
		pcs.dataTypeChanged(5);
		pcs.endTransaction(true);

		long[] changes = pcs.getDataTypeChanges();
		assertEquals(1, changes.length);
		assertTrue(changes[0] == 5);

		pcs.undo();
		changes = pcs.getDataTypeChanges();
		assertEquals(1, changes.length);
		assertTrue(changes[0] == 5);

		pcs.undo();
		changes = pcs.getDataTypeChanges();
		assertEquals(0, changes.length);
	}

	@Test
	public void testDataTypeAdditions() {
		pcs.startTransaction();
		pcs.dataTypeAdded(5);
		pcs.dataTypeAdded(6);
		pcs.endTransaction(true);

		long[] adds = pcs.getDataTypeAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 5 || adds[1] == 5) && (adds[0] == 6 || adds[1] == 6));

		pcs.startTransaction();
		pcs.dataTypeAdded(15);
		pcs.endTransaction(true);

		pcs.undo();
		adds = pcs.getDataTypeAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 5 || adds[1] == 5) && (adds[0] == 6 || adds[1] == 6));

		pcs.undo();
		adds = pcs.getDataTypeAdditions();
		assertEquals(0, adds.length);
	}

	@Test
	public void testCategoryChanges() {
		pcs.startTransaction();
		pcs.categoryChanged(5);
		pcs.categoryChanged(6);
		pcs.endTransaction(true);
		pcs.startTransaction();
		pcs.categoryChanged(5);
		pcs.endTransaction(true);

		long[] changes = pcs.getCategoryChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 || changes[1] == 5) &&
			(changes[0] == 6 || changes[1] == 6));

		pcs.undo();
		changes = pcs.getCategoryChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 || changes[1] == 5) &&
			(changes[0] == 6 || changes[1] == 6));

		pcs.undo();
		changes = pcs.getCategoryChanges();
		assertEquals(0, changes.length);
	}

	@Test
	public void testCategoryChanges2() {
		pcs.startTransaction();
		pcs.categoryAdded(6);
		pcs.categoryChanged(5);
		pcs.categoryChanged(6);
		pcs.endTransaction(true);
		pcs.startTransaction();
		pcs.categoryChanged(5);
		pcs.endTransaction(true);

		long[] changes = pcs.getCategoryChanges();
		assertEquals(1, changes.length);
		assertTrue(changes[0] == 5);

		pcs.undo();
		changes = pcs.getCategoryChanges();
		assertEquals(1, changes.length);
		assertTrue(changes[0] == 5);

		pcs.undo();
		changes = pcs.getCategoryChanges();
		assertEquals(0, changes.length);
	}

	@Test
	public void testCategoryAdditions() {
		pcs.startTransaction();
		pcs.categoryAdded(5);
		pcs.categoryAdded(6);
		pcs.endTransaction(true);

		long[] adds = pcs.getCategoryAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 5 || adds[1] == 5) && (adds[0] == 6 || adds[1] == 6));

		pcs.startTransaction();
		pcs.categoryAdded(15);
		pcs.endTransaction(true);

		pcs.undo();
		adds = pcs.getCategoryAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 5 || adds[1] == 5) && (adds[0] == 6 || adds[1] == 6));

		pcs.undo();
		adds = pcs.getCategoryAdditions();
		assertEquals(0, adds.length);
	}

	@Test
	public void testSourceArchiveChanges() {
		pcs.startTransaction();
		pcs.sourceArchiveAdded(7);
		pcs.sourceArchiveChanged(5);
		pcs.sourceArchiveChanged(6);
		pcs.sourceArchiveChanged(7);
		pcs.endTransaction(true);
		pcs.startTransaction();
		pcs.sourceArchiveChanged(5);
		pcs.endTransaction(true);

		long[] adds = pcs.getSourceArchiveAdditions();
		assertEquals(1, adds.length);
		assertTrue(adds[0] == 7);

		long[] changes = pcs.getSourceArchiveChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 && changes[1] == 6) ||
			(changes[0] == 6 && changes[1] == 5));

		pcs.undo();
		changes = pcs.getSourceArchiveChanges();
		assertEquals(2, changes.length);
		assertTrue(changes[0] != changes[1] && (changes[0] == 5 && changes[1] == 6) ||
			(changes[0] == 6 && changes[1] == 5));

		pcs.undo();
		changes = pcs.getSourceArchiveChanges();
		assertEquals(0, changes.length);
	}

	@Test
	public void testSourceArchiveAdditions() {
		pcs.startTransaction();
		pcs.sourceArchiveAdded(3);
		pcs.sourceArchiveAdded(6);
		pcs.endTransaction(true);

		long[] adds = pcs.getSourceArchiveAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 3 && adds[1] == 6) || (adds[0] == 6 && adds[1] == 3));

		pcs.startTransaction();
		pcs.sourceArchiveAdded(15);
		pcs.endTransaction(true);

		pcs.undo();
		adds = pcs.getSourceArchiveAdditions();
		assertEquals(2, adds.length);
		assertTrue(
			adds[0] != adds[1] && (adds[0] == 3 && adds[1] == 6) || (adds[0] == 6 && adds[1] == 3));

		pcs.undo();
		adds = pcs.getSourceArchiveAdditions();
		assertEquals(0, adds.length);
	}

	@Test
	public void testAbort() {
		pcs.startTransaction();
		pcs.addRange(addr(0), addr(0));
		pcs.endTransaction(false);
		assertEquals(0, pcs.getAddressSet().getNumAddresses());
	}

	@Test
	public void getAddressSetCollectionSinceCheckout() throws IOException {
		pcs.startTransaction();
		pcs.addRange(addr(0), addr(9));

		AddressSetCollection addrsSinceCheckout = pcs.getAddressSetCollectionSinceCheckout();
		AddressSetCollection addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(addrsSinceCheckout.isEmpty());
		assertTrue(!addrsSinceSave.isEmpty());
		assertTrue(!addrsSinceCheckout.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(0)));

		pcs.endTransaction(true);

		addrsSinceCheckout = pcs.getAddressSetCollectionSinceCheckout();
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(!addrsSinceCheckout.isEmpty());
		assertTrue(!addrsSinceSave.isEmpty());
		assertTrue(addrsSinceCheckout.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(0)));

		DBHandle dbHandle = new DBHandle();

		// simulate saving a checked out program.
		pcs.write(dbHandle, false);
		pcs.clearUndo(true);

		addrsSinceCheckout = pcs.getAddressSetCollectionSinceCheckout();
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(!addrsSinceCheckout.isEmpty());
		assertTrue(addrsSinceSave.isEmpty());
		assertTrue(addrsSinceCheckout.contains(addr(0)));
		assertTrue(!addrsSinceSave.contains(addr(0)));

	}

	@Test
	public void getAddressSetCollectionSinceLastSave() {
		pcs.startTransaction();
		pcs.addRange(addr(0), addr(9));

		AddressSetCollection addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();

		assertTrue(addrsSinceSave.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(5)));
		assertTrue(addrsSinceSave.contains(addr(9)));
		assertTrue(!addrsSinceSave.contains(addr(10)));
		assertTrue(!addrsSinceSave.contains(addr(20)));
		assertTrue(addrsSinceSave.intersects(addr(5), addr(15)));
		assertTrue(!addrsSinceSave.intersects(addr(10), addr(15)));

		pcs.endTransaction(true);
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();

		assertTrue(addrsSinceSave.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(5)));
		assertTrue(addrsSinceSave.contains(addr(9)));
		assertTrue(!addrsSinceSave.contains(addr(10)));
		assertTrue(!addrsSinceSave.contains(addr(20)));
		assertTrue(addrsSinceSave.intersects(addr(5), addr(15)));
		assertTrue(!addrsSinceSave.intersects(addr(10), addr(15)));

		pcs.startTransaction();
		pcs.addRange(addr(5), addr(14));
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();

		assertTrue(addrsSinceSave.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(5)));
		assertTrue(addrsSinceSave.contains(addr(9)));
		assertTrue(addrsSinceSave.contains(addr(10)));
		assertTrue(!addrsSinceSave.contains(addr(20)));
		assertTrue(addrsSinceSave.intersects(addr(5), addr(15)));
		assertTrue(addrsSinceSave.intersects(addr(10), addr(15)));
		assertTrue(!addrsSinceSave.intersects(addr(15), addr(25)));

		pcs.endTransaction(true);

		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(addrsSinceSave.contains(addr(0)));
		assertTrue(addrsSinceSave.contains(addr(5)));
		assertTrue(addrsSinceSave.contains(addr(9)));
		assertTrue(addrsSinceSave.contains(addr(10)));
		assertTrue(!addrsSinceSave.contains(addr(20)));
		assertTrue(addrsSinceSave.intersects(addr(5), addr(15)));
		assertTrue(addrsSinceSave.intersects(addr(10), addr(15)));
		assertTrue(!addrsSinceSave.intersects(addr(15), addr(25)));

		pcs.undo();
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(!addrsSinceSave.contains(addr(10)));
		assertTrue(!addrsSinceSave.intersects(addr(10), addr(15)));

		pcs.redo();
		addrsSinceSave = pcs.getAddressSetCollectionSinceLastSave();
		assertTrue(addrsSinceSave.contains(addr(10)));
		assertTrue(addrsSinceSave.intersects(addr(10), addr(15)));

	}

	@Test
	public void testRandomCommitsUndoAndRedo() {
		// the change set must match a plain AddressSet model of the changes since the last save
		Random random = new Random(5678);
		AddressSet model = new AddressSet();
		AddressSet regModel = new AddressSet();
		LinkedList<AddressSet[]> undoDiffs = new LinkedList<>();
		LinkedList<AddressSet[]> redoDiffs = new LinkedList<>();
		for (int i = 0; i < 1000; i++) {
			int action = random.nextInt(10);
			if (action < 6) {
				AddressSet added = new AddressSet();
				AddressSet regAdded = new AddressSet();
				pcs.startTransaction();
				for (int n = random.nextInt(4); n >= 0; n--) {
					long start = random.nextInt(0x400);
					long end = start + random.nextInt(random.nextBoolean() ? 2 : 40);
					pcs.addRange(addr(start), addr(end));
					added.addRange(addr(start), addr(end));
					if (random.nextBoolean()) {
						pcs.addRegisterRange(addr(end), addr(end + 3));
						regAdded.addRange(addr(end), addr(end + 3));
					}
				}
				boolean commit = action != 0;
				pcs.endTransaction(commit);
				if (commit) {
					redoDiffs.clear();
					undoDiffs.addLast(
						new AddressSet[] { added.subtract(model), regAdded.subtract(regModel) });
					if (undoDiffs.size() > 20) {
						undoDiffs.removeFirst();
					}
					model.add(added);
					regModel.add(regAdded);
				}
			}
			else if (action < 8 && !undoDiffs.isEmpty()) {
				pcs.undo();
				AddressSet[] diff = undoDiffs.removeLast();
				model.delete(diff[0]);
				regModel.delete(diff[1]);
				redoDiffs.addLast(diff);
			}
			else if (!redoDiffs.isEmpty()) {
				pcs.redo();
				AddressSet[] diff = redoDiffs.removeLast();
				model.add(diff[0]);
				regModel.add(diff[1]);
				undoDiffs.addLast(diff);
			}
			assertTrue(model.hasSameAddresses(pcs.getAddressSet()));
			assertTrue(regModel.hasSameAddresses(pcs.getRegisterAddressSet()));
		}
	}

	@Test
	public void testCommitCostDoesNotGrowWithEarlierChanges() {
		// Count the address map calls of one small commit after many separate earlier changes.
		// The commit must only look at its own changes, not at all the changes since the save.
		AddressMap addrMap = program.getAddressMap();
		int[] calls = new int[1];
		AddressMap countingMap = (AddressMap) Proxy.newProxyInstance(
			AddressMap.class.getClassLoader(), new Class<?>[] { AddressMap.class },
			(proxy, method, args) -> {
				calls[0]++;
				try {
					return method.invoke(addrMap, args);
				}
				catch (InvocationTargetException e) {
					throw e.getCause();
				}
			});
		pcs = new ProgramDBChangeSet(countingMap, 20);

		pcs.startTransaction();
		for (int i = 0; i < 10000; i++) {
			pcs.addRange(addr(2 * i), addr(2 * i));
		}
		pcs.endTransaction(true);

		for (int i = 0; i < 10; i++) {
			pcs.startTransaction();
			pcs.addRange(addr(2 * i + 1), addr(2 * i + 1));
			calls[0] = 0;
			pcs.endTransaction(true);
			assertTrue("address map calls in one commit: " + calls[0], calls[0] < 100);
		}
		assertEquals(10000 - 10, pcs.getAddressSet().getNumAddressRanges());
		assertEquals(10010, pcs.getAddressSet().getNumAddresses());

		pcs.undo();
		assertEquals(10009, pcs.getAddressSet().getNumAddresses());
		assertTrue(!pcs.getAddressSet().contains(addr(19)));
	}

	private Address addr(long a) {
		return space.getAddress(a);
	}

}
