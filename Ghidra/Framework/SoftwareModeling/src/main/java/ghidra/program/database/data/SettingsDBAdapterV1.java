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

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 1 implementation for the accessing the data type settings database table.
 * This version stores settings name as an index in each record which corresponds 
 * to an entry in the into a second table for
 */
class SettingsDBAdapterV1 extends SettingsDBAdapter {

	private final short MIN_NAME_INDEX = 1; // first assigned name index value

	// Default Settings Columns
	static final int V1_SETTINGS_ASSOCIATION_ID_COL = 0; // e.g., Address-key, Datatype-ID
	static final int V1_SETTINGS_NAME_INDEX_COL = 1; // short
	static final int V1_SETTINGS_LONG_VALUE_COL = 2;
	static final int V1_SETTINGS_STRING_VALUE_COL = 3;

	private static int V1_SCHEMA_VERSION = 1;
	private static int V1_NAMES_SCHEMA_VERSION = 1;

	static final Schema V1_SETTINGS_SCHEMA = new Schema(V1_SCHEMA_VERSION, "SettingsID",
		new Field[] { LongField.INSTANCE, ShortField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE },
		new String[] { "AssociationID", "Settings Name Index", "Long Value", "String Value" });

	static final Schema V1_NAME_TABLE_SCHEMA = new Schema(V1_NAMES_SCHEMA_VERSION, "NameIndex",
		new Field[] { StringField.INSTANCE },
		new String[] { "Settings Name" });

	static final int V1_NAME_COL = 0;

	private Table settingsTable;
	private Table settingsNameTable;

	/**
	 * The setting names by index and the indexes by name, read lazily. Readers of the data type
	 * manager hold only its read lock (GP-6679), so several threads may get here at once (the
	 * decompiler callbacks of concurrent decompiles of one program): both maps are published
	 * together through one volatile reference, built completely before it is set, and are
	 * concurrent maps so that a name added later is safe beside readers. Before, one thread could
	 * see the first map set and the second still null (a NullPointerException in
	 * {@link #getNameIndex}).
	 */
	private record NameMaps(Map<Short, String> byIndex, Map<String, Short> byName) {
	}

	private volatile NameMaps nameMaps;

	SettingsDBAdapterV1(String tableName, DBHandle handle, boolean create)
			throws VersionException, IOException {
		String nameTableName = tableName + " Names";
		if (create) {
			settingsTable =
				handle.createTable(tableName, V1_SETTINGS_SCHEMA,
					new int[] { V1_SETTINGS_ASSOCIATION_ID_COL });
			settingsNameTable =
				handle.createTable(nameTableName, V1_NAME_TABLE_SCHEMA);
		}
		else {
			settingsTable = handle.getTable(tableName);
			if (settingsTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int ver = settingsTable.getSchema().getVersion();
			if (ver != V1_SCHEMA_VERSION) {
				throw new VersionException(ver < V1_SCHEMA_VERSION);
			}
			settingsNameTable = handle.getTable(nameTableName);
			if (settingsNameTable == null ||
				settingsNameTable.getSchema().getVersion() != V1_NAMES_SCHEMA_VERSION) {
				throw new VersionException("Missing expected table: " + nameTableName);
			}
		}
	}

	@Override
	String getTableName() {
		return settingsTable.getName();
	}

	@Override
	DBRecord createSettingsRecord(long associationId, String name, String strValue,
			long longValue) throws IOException {

		DBRecord record = V1_SETTINGS_SCHEMA.createRecord(settingsTable.getKey());
		record.setLongValue(V1_SETTINGS_ASSOCIATION_ID_COL, associationId);
		record.setShortValue(V1_SETTINGS_NAME_INDEX_COL, assignNameIndexValue(name));
		record.setString(V1_SETTINGS_STRING_VALUE_COL, strValue);
		record.setLongValue(V1_SETTINGS_LONG_VALUE_COL, longValue);
		settingsTable.putRecord(record);
		return record;
	}

	@Override
	public Field[] getSettingsKeys(long associationId) throws IOException {
		return settingsTable.findRecords(new LongField(associationId),
			V1_SETTINGS_ASSOCIATION_ID_COL);
	}

	@Override
	void removeAllSettingsRecords(long associationId) throws IOException {
		for (Field key : getSettingsKeys(associationId)) {
			removeSettingsRecord(key.getLongValue());
		}
	}

	@Override
	boolean removeSettingsRecord(long settingsID) throws IOException {
		return settingsTable.deleteRecord(settingsID);
	}

	@Override
	boolean removeSettingsRecord(long associationId, String name) throws IOException {
		short nameIndex = getNameIndex(name);
		if (nameIndex < MIN_NAME_INDEX) {
			return false; // no such name defined
		}
		for (Field key : getSettingsKeys(associationId)) {
			DBRecord rec = settingsTable.getRecord(key);
			if (nameIndex == rec.getShortValue(V1_SETTINGS_NAME_INDEX_COL)) {
				settingsTable.deleteRecord(key);
				return true;
			}
		}
		return false;
	}

	@Override
	String[] getSettingsNames(long associationId) throws IOException {
		ArrayList<String> list = new ArrayList<>();
		for (Field key : getSettingsKeys(associationId)) {
			DBRecord rec = settingsTable.getRecord(key);
			list.add(getSettingName(rec));
		}
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	@Override
	void addAllValues(String name, Set<String> set) throws IOException {
		short nameIndex = getNameIndex(name);
		if (nameIndex < MIN_NAME_INDEX) {
			return; // no such name defined
		}
		RecordIterator recIter = settingsTable.iterator();
		while (recIter.hasNext()) {
			DBRecord rec = recIter.next();
			if (nameIndex == rec.getShortValue(V1_SETTINGS_NAME_INDEX_COL)) {
				String s = rec.getString(V1_SETTINGS_STRING_VALUE_COL);
				if (!StringUtils.isBlank(s)) {
					set.add(s);
				}
			}
		}
	}

	private NameMaps initNameMaps() throws IOException {
		NameMaps maps = nameMaps;
		if (maps != null) {
			return maps;
		}
		Map<Short, String> byIndex = new ConcurrentHashMap<>();
		Map<String, Short> byName = new ConcurrentHashMap<>();
		RecordIterator it = settingsNameTable.iterator();
		while (it.hasNext()) {
			DBRecord nameRec = it.next();
			short nameIndex = (short) nameRec.getKey();
			String name = nameRec.getString(V1_NAME_COL);
			if (name != null) { // a concurrent map holds no null; get(null) answers null either way
				byIndex.put(nameIndex, name);
				byName.put(name, nameIndex);
			}
		}
		maps = new NameMaps(byIndex, byName);
		nameMaps = maps;
		return maps;
	}

	private short assignNameIndexValue(String name) throws IOException {
		NameMaps maps = initNameMaps();
		Short nameIndex = name == null ? null : maps.byName().get(name);
		if (nameIndex != null) {
			return nameIndex;
		}

		// 1 is the first assigned name key value which allows for short cast
		long key = Math.max(MIN_NAME_INDEX, settingsNameTable.getKey());
		if (key == Short.MAX_VALUE) {
			// 32766 should be way more than enough unique setting names
			throw new IOException("Too many settings names defined");
		}

		// Add new name record
		nameIndex = (short) key;
		DBRecord nameRec = V1_NAME_TABLE_SCHEMA.createRecord(key);
		nameRec.setString(V1_NAME_COL, name);
		settingsNameTable.putRecord(nameRec);

		if (name != null) {
			maps.byIndex().put(nameIndex, name);
			maps.byName().put(name, nameIndex);
		}

		return nameIndex;
	}

	@Override
	String getSettingName(DBRecord normalizedRecord) throws IOException {
		NameMaps maps = initNameMaps();
		short nameIndex = normalizedRecord.getShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL);
		return maps.byIndex().get(nameIndex);
	}

	@Override
	void invalidateNameCache() {
		nameMaps = null;
	}

	/**
	 * Get previously assigned name index.
	 * @param name setting name
	 * @return name index or a value less than {@code #MIN_NAME_INDEX} if not defined
	 * @throws IOException if an IO error occurs
	 */
	private short getNameIndex(String name) throws IOException {
		Short index = name == null ? null : initNameMaps().byName().get(name);
		if (index == null) {
			return -1; // undefined name
		}
		return index;
	}

	@Override
	DBRecord getSettingsRecord(long settingsID) throws IOException {
		return settingsTable.getRecord(settingsID);
	}

	@Override
	DBRecord getSettingsRecord(long associationId, String name) throws IOException {
		short nameIndex = getNameIndex(name);
		if (nameIndex < MIN_NAME_INDEX) {
			return null; // not found - name not defined
		}
		for (Field key : getSettingsKeys(associationId)) {
			DBRecord rec = settingsTable.getRecord(key);
			if (rec.getShortValue(V1_SETTINGS_NAME_INDEX_COL) == nameIndex) {
				return rec;
			}
		}
		return null;
	}

	@Override
	void updateSettingsRecord(DBRecord record) throws IOException {
		if (getSettingName(record) == null) {
			throw new IOException("Record refers to invalid setting name index value");
		}
		settingsTable.putRecord(record);
	}

	@Override
	DBRecord updateSettingsRecord(long associationId, String name, String strValue, long longValue)
			throws IOException {

		strValue = StringUtils.isBlank(strValue) ? null : strValue.trim();

		DBRecord record = getSettingsRecord(associationId, name);
		if (record == null) {
			return createSettingsRecord(associationId, name, strValue, longValue);
		}

		String recStrValue = record.getString(V1_SETTINGS_STRING_VALUE_COL);
		long recLongValue = record.getLongValue(V1_SETTINGS_LONG_VALUE_COL);

		if (recLongValue != longValue || !Objects.equals(recStrValue, strValue)) {
			record.setString(V1_SETTINGS_STRING_VALUE_COL, strValue);
			record.setLongValue(V1_SETTINGS_LONG_VALUE_COL, longValue);
			settingsTable.putRecord(record);
			return record;
		}
		return null;
	}

	@Override
	int getRecordCount() {
		return settingsTable.getRecordCount();
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return settingsTable.iterator();
	}

	@Override
	RecordIterator getRecords(long minAssociationId, long maxAssociationId) throws IOException {
		return settingsTable.indexIterator(V1_SETTINGS_ASSOCIATION_ID_COL,
			new LongField(minAssociationId),
			new LongField(maxAssociationId), true);
	}

	@Override
	void delete(long minAssociationId, long maxAssociationId, TaskMonitor monitor) throws CancelledException, IOException {
		DBFieldIterator it = settingsTable.indexKeyIterator(V1_SETTINGS_ASSOCIATION_ID_COL,
			new LongField(minAssociationId), new LongField(maxAssociationId), true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			settingsTable.deleteRecord(it.next());
		}
	}

}
