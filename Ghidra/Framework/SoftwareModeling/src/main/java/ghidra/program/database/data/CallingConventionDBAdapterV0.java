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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import com.google.common.collect.Range;
import com.google.common.collect.TreeRangeSet;

import db.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for the calling conventions tables adapter.
 * 
 */
class CallingConventionDBAdapterV0 extends CallingConventionDBAdapter {

	private static final int VERSION = 0;

	// Calling Convention Columns
	// Key field is the Calling convention ID, which is a Byte field.
	static final int V0_CALLING_CONVENTION_NAME_COL = 0;

	static final Schema V0_CALLING_CONVENTION_SCHEMA = new Schema(0, ByteField.INSTANCE, "ID",
		new Field[] { StringField.INSTANCE }, new String[] { "Name" });

	private Table callingConventionTable;

	/**
	 * The name/ID maps and the free keys, read lazily from the table. Readers hold only the data
	 * type manager's read lock (GP-6679), so several threads may read the cache at once (the
	 * decompiler callbacks of concurrent decompiles of one program): it is built in locals and
	 * then published whole through a volatile field, so a reader never sees it half built
	 * (before, a reader could find one map set and the other still null, a NullPointerException
	 * in {@link #getCallingConventionName(byte)}, or a map still being filled). Additions happen
	 * under the write lock; the maps are concurrent so readers may still look up meanwhile.
	 *
	 * @param nameToId calling convention name to ID
	 * @param idToName calling convention ID to name
	 * @param freeKeySet free IDs, closed ranges only. There is currently no method for removing
	 * an allocated calling convention name/ID, therefor we can assume key consumption will be
	 * sequential until the ability to delete is added. Use of freeKeySet can be eliminated if
	 * delete ability never added.
	 */
	private record Cache(Map<String, Byte> nameToId, Map<Byte, String> idToName,
			TreeRangeSet<Byte> freeKeySet) {}

	private volatile Cache cache;

	/**
	 * Gets a version 0 adapter for the calling convention database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if an IO error occurs
	 */
	CallingConventionDBAdapterV0(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + CALLING_CONVENTION_TABLE_NAME;
		if (create) {
			// No additional indexed fields.
			callingConventionTable =
				handle.createTable(tableName, V0_CALLING_CONVENTION_SCHEMA, new int[] {});
		}
		else {
			callingConventionTable = handle.getTable(tableName);
			if (callingConventionTable == null) {
				throw new VersionException(true);
			}
			if (callingConventionTable.getSchema().getVersion() != VERSION) {
				throw new VersionException(false);
			}
		}
	}

	/**
	 * Remove next available free key value from freeKeySet.
	 * @return the next available key. A negative value indicates that all allowed IDs have 
	 * been used.
	 */
	private static byte removeFirstAvailableKey(TreeRangeSet<Byte> freeKeySet) {
		Iterator<Range<Byte>> it = freeKeySet.asRanges().iterator();
		if (!it.hasNext()) {
			return -1;
		}
		Range<Byte> r = it.next();
		it.remove();
		byte nextId = r.lowerEndpoint();
		byte lastId = r.upperEndpoint();
		if (nextId != lastId) {
			freeKeySet.add(Range.closed((byte) (nextId + 1), lastId));
		}
		return nextId;
	}

	@Override
	void invalidateCache() {
		cache = null;
	}

	private Cache populateCache() throws IOException {
		Cache c = cache;
		if (c != null) {
			return c;
		}
		Map<String, Byte> callingConventionNameToIDMap = new ConcurrentHashMap<>();
		Map<Byte, String> callingConventionIDToNameMap = new ConcurrentHashMap<>();

		TreeRangeSet<Byte> freeKeySet = TreeRangeSet.create();
		int nextKey = FIRST_CALLING_CONVENTION_ID;
		RecordIterator iterator = callingConventionTable.iterator();
		while (iterator.hasNext()) {
			DBRecord rec = iterator.next();

			byte id = (byte) rec.getKey();
			String name = rec.getString(V0_CALLING_CONVENTION_NAME_COL);
			if (name != null) { // a concurrent map holds no null; a null name was never found
				callingConventionIDToNameMap.put(id, name);
				callingConventionNameToIDMap.put(name, id);
			}

			if (nextKey != id) {
				freeKeySet.add(Range.closed((byte) nextKey, (byte) (id - 1)));
			}
			nextKey = id + 1;
		}
		if (nextKey <= Byte.MAX_VALUE) {
			freeKeySet.add(Range.closed((byte) nextKey, Byte.MAX_VALUE));
		}
		c = new Cache(callingConventionNameToIDMap, callingConventionIDToNameMap, freeKeySet);
		cache = c;
		return c;
	}

	@Override
	byte getCallingConventionId(String name, Consumer<String> conventionAdded) throws IOException {
		if (CompilerSpec.isUnknownCallingConvention(name)) {
			return UNKNOWN_CALLING_CONVENTION_ID;
		}
		else if (name.equals(CompilerSpec.CALLING_CONVENTION_default)) {
			return DEFAULT_CALLING_CONVENTION_ID;
		}
		Cache c = populateCache();
		Byte id = c.nameToId().get(name);
		if (id != null) {
			return id;
		}

		byte newId = removeFirstAvailableKey(c.freeKeySet());
		if (newId < 0) {
			Msg.error(this, "Unable to assign calling convention `" + name +
				"` - allocation capacity exceeded");
			return UNKNOWN_CALLING_CONVENTION_ID;
		}

		DBRecord record = V0_CALLING_CONVENTION_SCHEMA.createRecord(new ByteField(newId));
		record.setString(V0_CALLING_CONVENTION_NAME_COL, name);
		callingConventionTable.putRecord(record);

		c.idToName().put(newId, name);
		c.nameToId().put(name, newId);
		conventionAdded.accept(name);
		return newId;
	}

	@Override
	String getCallingConventionName(byte id) throws IOException {
		if (id == DEFAULT_CALLING_CONVENTION_ID) {
			return Function.DEFAULT_CALLING_CONVENTION_STRING;
		}
		else if (id == UNKNOWN_CALLING_CONVENTION_ID) {
			return null;
		}
		return populateCache().idToName().get(id);
	}

	@Override
	Set<String> getCallingConventionNames() throws IOException {
		return populateCache().nameToId().keySet();
	}
}
