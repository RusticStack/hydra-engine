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
package ghidra.program.database.code;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicReferenceArray;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.DatabaseVersionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.MD5Utilities;
import ghidra.util.Msg;
import ghidra.util.datastruct.ObjectIntHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class maintain a list of prototypes and corresponding IDs.
 * NOTE: The prototype ID will be negative if the prototype is in a
 * delay slot.
 */
class PrototypeManager {

	// key=ProtoType, value=protoID. Filled only by populateAll(), which every user of it calls
	// first (Hydra: prototypes are created on demand, see getPrototype)
	private ObjectIntHashtable<InstructionPrototype> protoHt;
	private boolean allPopulated;

	// protoID is an index into the prototype array; an entry is created from its database record
	// the first time it is asked for (Hydra), by any reader, so the array is published through a
	// volatile reference and its entries have volatile semantics
	private volatile AtomicReferenceArray<InstructionPrototype> protoArray;
	private int nextKey;

	private Language language;
	private Table contextTable;
	private ProtoDBAdapter protoAdapter;
	private ProgramDB program;
	private AddressMap addrMap;
	private ProgramContext programContext;
	private Register baseContextRegister;

	final static int BYTES_COL = 0;
	final static int ADDR_COL = 1;
	final static int DELAY_COL = 2;

	final static String PROTO_TABLE_NAME = "Prototypes";
	final static Schema PROTO_SCHEMA = createPrototypeSchema();
	final static String CONTEXT_TABLE_NAME = "ContextTable";
	final static Schema REGISTER_SCHEMA = createRegisterSchema();

	private static Schema createPrototypeSchema() {
		Schema schema = new Schema(1, "Keys",
			new Field[] { BinaryField.INSTANCE, LongField.INSTANCE, BooleanField.INSTANCE },
			new String[] { "Bytes", "Address", "InDelaySlot" });
		return schema;
	}

	private static Schema createRegisterSchema() {
		Schema schema = new Schema(1, "Keys", new Field[] { StringField.INSTANCE },
			new String[] { "Register Context" });
		return schema;
	}

	private static final int CURRENT_VERSION = 1;
	private static final int CURRENT_CONTEXT_VERSION = 1;

	/**
	 * Constructs a new PrototypeManager
	 * @param dbHandle the database handle
	 * @param addrMap the address map.
	 * @param openMode the open mode
	 * @param monitor the task monitor.
	 * @throws VersionException thrown if the database version doesn't match this adapter version
	 * @throws IOException if a database io error occurs.
	 */
	PrototypeManager(DBHandle dbHandle, AddressMap addrMap, OpenMode openMode, TaskMonitor monitor)
			throws VersionException, IOException {

		this.addrMap = addrMap;

		if (openMode == OpenMode.CREATE) {
			createDBTables(dbHandle);
			contextTable = dbHandle.createTable(CONTEXT_TABLE_NAME, REGISTER_SCHEMA);
		}
		findAdapters(dbHandle, openMode);
		loadContextTable(dbHandle, openMode);

		if (openMode == OpenMode.UPGRADE) {
			upgradeTable(dbHandle, monitor);
		}
// debug for enormous prototype problem
//		Err.debug(this, "Instruction prototypes: " + protoAdapter.getNumRecords());
	}

	private void upgradeTable(DBHandle dbHandle, TaskMonitor monitor) throws IOException {
		if (protoAdapter.getVersion() != CURRENT_VERSION) {
			upgradeProtoTable(dbHandle, monitor);
		}
		if (contextTable.getSchema().getVersion() != CURRENT_CONTEXT_VERSION) {
			upgradeContextTable(dbHandle, monitor);
		}
	}

	private void upgradeContextTable(DBHandle dbHandle, TaskMonitor monitor) throws IOException {
		monitor.setMessage("Upgrading Table: " + CONTEXT_TABLE_NAME);
		DBHandle temp = dbHandle.getScratchPad();
		try {
			Table tempTable = temp.createTable(CONTEXT_TABLE_NAME, REGISTER_SCHEMA);
			int count = 0;
			monitor.initialize(protoAdapter.getNumRecords() * 2);
			RecordIterator it = contextTable.iterator();
			while (it.hasNext()) {
				monitor.setProgress(++count);
				if (monitor.isCancelled()) {
					throw new IOException("Upgrade Cancelled");
				}
				DBRecord rec = it.next();
				String oldValue = rec.getString(0);
				rec.setString(0, convertString(oldValue));
				tempTable.putRecord(rec);
			}
			dbHandle.deleteTable(CONTEXT_TABLE_NAME);
			contextTable = dbHandle.createTable(CONTEXT_TABLE_NAME, REGISTER_SCHEMA);

			it = tempTable.iterator();
			while (it.hasNext()) {
				monitor.setProgress(++count);
				if (monitor.isCancelled()) {
					throw new IOException("Upgrade Cancelled");
				}
				DBRecord rec = it.next();
				contextTable.putRecord(rec);
			}
		}
		finally {
			temp.deleteTable(CONTEXT_TABLE_NAME);
		}
	}

	private String convertString(String oldValue) {
		StringTokenizer tok = new StringTokenizer(oldValue, ",");
		int n = tok.countTokens();
		byte[] values = new byte[4 * n];
		int i = 0;
		while (tok.hasMoreTokens()) {
			String next = tok.nextToken();
			int value = Integer.parseInt(next);
			putInt(values, i, value);
			i += 4;
		}
		BigInteger newValue = new BigInteger(values);
		return newValue.toString();
	}

	private void putInt(byte[] bytes, int index, int value) {
		for (int i = 3; i >= 0; i--) {
			bytes[index + i] = (byte) value;
			value >>= 8;
		}
	}

	private void upgradeProtoTable(DBHandle dbHandle, TaskMonitor monitor) throws IOException {
		monitor.setMessage("Upgrading Table: " + PROTO_TABLE_NAME);
		DBHandle temp = dbHandle.getScratchPad();
		try {
			createDBTables(temp);
			ProtoDBAdapter tempAdapter = new ProtoDBAdapterV1(temp);
			int count = 0;
			monitor.initialize(protoAdapter.getNumRecords() * 2);
			RecordIterator it = protoAdapter.getRecords();
			while (it.hasNext()) {
				monitor.setProgress(++count);
				if (monitor.isCancelled()) {
					throw new IOException("Upgrade Cancelled");
				}
				DBRecord rec = it.next();
				tempAdapter.createRecord((int) rec.getKey(), rec.getLongValue(ADDR_COL),
					rec.getBinaryData(BYTES_COL), rec.getBooleanValue(DELAY_COL));
			}
			Table t = dbHandle.getTable(PROTO_TABLE_NAME);
			t.deleteAll();
			dbHandle.deleteTable(PROTO_TABLE_NAME);
			dbHandle.createTable(PROTO_TABLE_NAME, PROTO_SCHEMA);
			protoAdapter = new ProtoDBAdapterV1(dbHandle);
			it = tempAdapter.getRecords();
			while (it.hasNext()) {
				monitor.setProgress(++count);
				if (monitor.isCancelled()) {
					throw new IOException("Upgrade Cancelled");
				}
				DBRecord rec = it.next();
				protoAdapter.createRecord((int) rec.getKey(), rec.getLongValue(ADDR_COL),
					rec.getBinaryData(BYTES_COL), rec.getBooleanValue(DELAY_COL));

			}
		}
		catch (DatabaseVersionException e) {
			Msg.showError(this, null, "Unbelievable Error", "can't happen", e);
		}
		finally {
			temp.deleteTable(PROTO_TABLE_NAME);
		}
	}

	void setLanguage(Language lang) throws IOException {
		contextTable.deleteAll();
		protoAdapter.deleteAll();
		this.language = lang;
		init();
	}

	private void init() {
		programContext = program.getProgramContext();
		baseContextRegister = programContext.getBaseContextRegister();
		resetPrototypes();
	}

	/**
	 * Hydra: a program open used to parse every stored instruction prototype with Sleigh up front
	 * ({@code populatePrototypes}), whether or not the session ever looked at an instruction (most
	 * opens only read or rename). Prototypes are now created on first use; the by-prototype table
	 * (needed to add instructions) is built by {@link #populateAll()} before its first use.
	 */
	private void resetPrototypes() {
		protoHt = new ObjectIntHashtable<InstructionPrototype>();
		allPopulated = false;
		try {
			nextKey = (int) protoAdapter.getKey();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		protoArray = new AtomicReferenceArray<>(Math.max(nextKey, 4));
	}

	void setProgram(ProgramDB program) {
		this.program = program;
		this.language = program.getLanguage();
		init();
	}

	/**
	 * Get the unique ID for this prototype.  If a prototype matching
	 * this one doesn't exist yet, then this one is stored and given a
	 * new ID.  If a prototype already exists that matches this prototype,
	 * then the ID already assigned to that prototype is returned.  This
	 * relies on the assumption that the Language module provides a
	 * good equals() method.
	 */
	synchronized int getID(InstructionPrototype prototype, MemBuffer memBuf,
			ProcessorContextView context) {

		populateAll();
		try {
			return protoHt.get(prototype);
		}
		catch (NoValueException e) {
			// new prototype handled below
		}
		int protoID;
		try {
			protoID = (int) protoAdapter.getKey();
			nextKey = protoID + 1;
			int protoArrayIndex = protoID;
			AtomicReferenceArray<InstructionPrototype> a = protoArray;
			if (protoArrayIndex >= a.length()) {
				AtomicReferenceArray<InstructionPrototype> bigger =
					new AtomicReferenceArray<>(Math.max(protoArrayIndex + 1, a.length() * 2));
				for (int i = 0; i < a.length(); i++) {
					bigger.set(i, a.get(i));
				}
				protoArray = a = bigger;
			}
			a.set(protoArrayIndex, prototype);
			protoHt.put(prototype, protoID);

			byte[] b = new byte[prototype.getLength()];
			if (memBuf.getBytes(b, 0) != b.length) {
				throw new AssertException("Insufficient bytes for prototype");
			}
			Address address = memBuf.getAddress();
			long addr = addrMap.getKey(address, true);
			protoAdapter.createRecord(protoID, addr, b, prototype.isInDelaySlot());

			if (baseContextRegister != null) {
				RegisterValue registerValue = context.getRegisterValue(baseContextRegister);
				String valueStr =
					registerValue != null ? registerValue.getUnsignedValueIgnoreMask().toString()
							: "0";
				DBRecord record = REGISTER_SCHEMA.createRecord(protoID);
				record.setString(0, valueStr);
				contextTable.putRecord(record);
			}
			return protoID;
		}
		catch (IOException exc) {
			program.dbError(exc);
		}
		return 0;
	}

	/**
	 * Get the prototype with the given ID.
	 * @param protoID prototype ID
	 * @return instruction prototype or null if not found
	 */
	InstructionPrototype getPrototype(int protoID) {
		if (protoID < 0) {
			return null;
		}
		AtomicReferenceArray<InstructionPrototype> a = protoArray;
		InstructionPrototype p = protoID < a.length() ? a.get(protoID) : null;
		return p != null ? p : createOnDemand(protoID);
	}

	/** The prototype of a stored record, created (once) from the database on first use. */
	private synchronized InstructionPrototype createOnDemand(int protoID) {
		AtomicReferenceArray<InstructionPrototype> a = protoArray;
		if (protoID >= a.length()) {
			return null;
		}
		InstructionPrototype proto = a.get(protoID);
		if (proto != null) {
			return proto;
		}
		try {
			DBRecord record = protoAdapter.getRecord(protoID);
			if (record == null) {
				return null;
			}
			proto = program.isLanguageUpgradePending() ? new InvalidPrototype(language)
					: createPrototype(protoID, record);
			a.set(protoID, proto);
			return proto;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	///////////////////////////////////////////////////////

	/**
	 * Creates every stored prototype that is not yet created and fills the by-prototype table,
	 * in record order (a later record wins an equal prototype, as the up-front population did).
	 */
	private synchronized void populateAll() {
		if (allPopulated) {
			return;
		}
		try {
			RecordIterator iter = protoAdapter.getRecords();
			AtomicReferenceArray<InstructionPrototype> a = protoArray;
			while (iter.hasNext()) {
				DBRecord record = iter.next();
				int protoID = (int) record.getKey();
				if (protoID >= a.length()) {
					continue;
				}
				InstructionPrototype proto = a.get(protoID);
				if (proto == null) {
					proto = program.isLanguageUpgradePending() ? new InvalidPrototype(language)
							: createPrototype(protoID, record);
					a.set(protoID, proto);
				}
				protoHt.put(proto, protoID);
			}
			nextKey = (int) protoAdapter.getKey();
			allPopulated = true;
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	synchronized void clearCache() {

		try {
			if (nextKey != (int) protoAdapter.getKey()) {
				resetPrototypes();
			}

		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	int getOriginalPrototypeLength(int protoId) {
		try {
			DBRecord record = protoAdapter.getRecord(protoId);
			if (record != null) {
				byte[] bytes = record.getBinaryData(BYTES_COL);
				return bytes.length;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return 0;
	}

	RegisterValue getOriginalPrototypeContext(InstructionPrototype prototype,
			Register baseContextReg) throws NoValueException {
		populateAll();
		try {
			DBRecord record = contextTable.getRecord(protoHt.get(prototype));
			if (record != null) {
				String s = record.getString(0);
				BigInteger value = s != null ? new BigInteger(s) : BigInteger.ZERO;
				return new RegisterValue(baseContextReg, value);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	private InstructionPrototype createPrototype(long protoID, DBRecord record) {
		Address address = addrMap.decodeAddress(record.getLongValue(ADDR_COL));
		byte[] bytes = record.getBinaryData(BYTES_COL);
		MemBuffer memBuffer = new ByteMemBufferImpl(address, bytes, language.isBigEndian());
		ProcessorContext context = new ProtoProcessorContext(record.getKey(), address);
		try {
			return language.parse(memBuffer, context, record.getBooleanValue(DELAY_COL));
		}
		catch (Exception e) {
			Msg.error(this, "Bad Instruction Prototype found! Address: " + address + ", Bytes: " +
				String.copyValueOf(MD5Utilities.hexDump(bytes)));
			return new InvalidPrototype(language);
		}
	}

	/**
	 * @param handle
	 */
	private void createDBTables(DBHandle handle) throws IOException {
		handle.createTable(PROTO_TABLE_NAME, PROTO_SCHEMA);

	}

	private void findAdapters(DBHandle handle, OpenMode openMode) throws VersionException {
		try {
			protoAdapter = new ProtoDBAdapterV1(handle);
			return;
		}
		catch (DatabaseVersionException e) {
			// try old adapter below
		}

		protoAdapter = getOldAdapter(handle);

		if (openMode == OpenMode.UPDATE) {
			throw new VersionException(true);
		}
	}

	private void loadContextTable(DBHandle dbHandle, OpenMode openMode)
			throws VersionException, IOException {
		contextTable = dbHandle.getTable(CONTEXT_TABLE_NAME);
		if (contextTable == null) {
			contextTable = dbHandle.createTable(CONTEXT_TABLE_NAME, REGISTER_SCHEMA);
		}
		if ((openMode == OpenMode.UPDATE) &&
			(contextTable.getSchema().getVersion() != CURRENT_CONTEXT_VERSION)) {
			throw new VersionException(true);
		}
	}

	private ProtoDBAdapter getOldAdapter(DBHandle handle) throws VersionException {
		try {
			return new ProtoDBAdapterV0(handle);
		}
		catch (DatabaseVersionException e) {
			throw new VersionException(false);
		}
	}

	class ProtoProcessorContext implements ProcessorContext {

		// TODO: Only used to instantiate instruction prototype from DB record

		private long protoID;
		private Address address;

		ProtoProcessorContext(long protoID, Address address) {
			this.protoID = protoID;
			this.address = address;
		}

		@Override
		public Register getRegister(String name) {
			return programContext.getRegister(name);
		}

		@Override
		public List<Register> getRegisters() {
			return programContext.getRegisters();
		}

		@Override
		public boolean hasValue(Register register) {
			return false;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (register != baseContextRegister || baseContextRegister == null) {
				return null;
			}
			try {
				DBRecord record = contextTable.getRecord(protoID);
				if (record != null) {
					String s = record.getString(0);
					BigInteger value = s != null ? new BigInteger(s) : BigInteger.ZERO;
					return new RegisterValue(register, value);
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return programContext.getDefaultValue(baseContextRegister, address);
		}

		@Override
		public BigInteger getValue(Register register, boolean signed) {
			if (register != baseContextRegister || baseContextRegister == null) {
				return null;
			}
			try {
				DBRecord record = contextTable.getRecord(protoID);
				if (record != null) {
					String s = record.getString(0);
					BigInteger value = new BigInteger(s);
					return value;
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			RegisterValue value = programContext.getDefaultValue(baseContextRegister, address);
			if (value != null) {
				return signed ? value.getSignedValueIgnoreMask()
						: value.getUnsignedValueIgnoreMask();
			}
			return null;
		}

		@Override
		public void setValue(Register register, BigInteger value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setRegisterValue(RegisterValue value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clearRegister(Register register) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Register getBaseContextRegister() {
			return baseContextRegister;
		}
	}

}
