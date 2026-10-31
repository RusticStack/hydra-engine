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
package db;

import java.io.IOException;

import db.buffers.BufferMgr;
import db.buffers.DataBuffer;
import ghidra.util.exception.AssertException;

/**
 * The <code>NodeMgr</code> manages all database nodes associated with 
 * a table.  Each table should use a separate instance of a NodeMgr.
 * The NodeMgr is resposible for interacting with the BufferMgr performing 
 * buffer allocations, retrievals and releases as required.   The NodeMgr
 * also performs hard caching of all buffers until the releaseNodes
 * method is invoked. 
 * 
 * Legacy Issues (prior to Ghidra 9.2):
 * <ul>
 * <li>Legacy {@link Table} implementation incorrectly employed {@link VarKeyNode} 
 *   storage with primitive fixed-length primary keys other than {@link LongField} 
 *   (e.g., {@link ByteField}).  With improved support for fixed-length keys
 *   legacy data poses a backward capatibility issue.  This has been 
 *   addressed through the use of a hack whereby a {@link Schema} is forced to
 *   treat the primary key as variable length 
 *   (see {@link Schema#forceUseOfVariableLengthKeyNodes()}.  The detection
 *   for this rare condition is provided by {@link TableRecord} during
 *   schema instantiation.</li>
 *   
 * <li>Legacy {@link Table} implementation incorrectly employed variable 
 *   length storage when both primary key and indexed fields were 
 *   LongField types.  This issue has been addressed by treating the 
 *   {@link Field#LEGACY_INDEX_LONG_TYPE} (0x8) as variable-length (see 
 *   implementation {@link LegacyIndexField}).</li>
 * </ul>
 */
class NodeMgr {

	// Node Header - first byte is node type
	static final int NODE_TYPE_SIZE = 1;
	static final int NODE_TYPE_OFFSET = 0;
	static final int NODE_HEADER_SIZE = NODE_TYPE_SIZE;

	// Node Type Values

	/**
	 * Node type for long-key interior tree nodes
	 * @see db.LongKeyInteriorNode
	 */
	static final byte LONGKEY_INTERIOR_NODE = 0;

	/**
	 * Node type for long key variable-length record leaf nodes
	 * @see db.VarRecNode
	 */
	static final byte LONGKEY_VAR_REC_NODE = 1;

	/**
	 * Node type for long key fixed-length record leaf nodes
	 * @see db.FixedRecNode
	 */
	static final byte LONGKEY_FIXED_REC_NODE = 2;

	/**
	 * Node type for Field key interior tree nodes
	 * @see db.VarKeyInteriorNode
	 */
	static final byte VARKEY_INTERIOR_NODE = 3;

	/**
	 * Node type for Field key variable-length record tree nodes
	 * @see db.VarKeyRecordNode
	 */
	static final byte VARKEY_REC_NODE = 4;

	/**
	 * Node type for fixed-length key interior tree nodes
	 * @see db.FixedKeyInteriorNode
	 */
	static final byte FIXEDKEY_INTERIOR_NODE = 5;

	/**
	 * Node type for fixed-length key variable-length record leaf nodes
	 * @see db.FixedKeyVarRecNode
	 */
	static final byte FIXEDKEY_VAR_REC_NODE = 6;

	/**
	 * Node type for fixed-length key fixed-length record leaf nodes
	 * @see db.FixedKeyFixedRecNode
	 */
	static final byte FIXEDKEY_FIXED_REC_NODE = 7;

	/**
	 * Node type for chained buffer index nodes
	 * @see db.DBBuffer
	 */
	static final byte CHAINED_BUFFER_INDEX_NODE = 8;

	/**
	 * Node type for chained buffer data nodes
	 * @see db.DBBuffer
	 */
	static final byte CHAINED_BUFFER_DATA_NODE = 9;

	private BufferMgr bufferMgr;
	private Schema schema;
	private String tableName;

	private int leafRecordCnt = 0;

	private final NodeTable nodeTable = new NodeTable();

	/**
	 * Hydra: the nodes held between a table operation and the next {@link #releaseNodes} (usually
	 * one to three). A {@code HashMap<Integer, BTreeNode>} here allocated a map, a 16-slot table,
	 * an entry and an {@code Integer} per node and a new map per release, for every database read
	 * (a quarter of the daemon's allocation); this open-addressing int table is allocated on the
	 * first node and cleared in place, and a table that grew large is dropped on release.
	 */
	private static final class NodeTable {
		private static final int INITIAL = 8;
		private static final int KEEP = 64;
		private int[] ids;
		private BTreeNode[] nodes;
		private int size;

		private static int slot(int id, int mask) {
			int h = id * 0x9E3779B1;
			return (h ^ (h >>> 15)) & mask;
		}

		BTreeNode get(int id) {
			BTreeNode[] ns = nodes;
			if (size == 0) {
				return null;
			}
			int mask = ns.length - 1;
			for (int i = slot(id, mask);; i = (i + 1) & mask) {
				BTreeNode n = ns[i];
				if (n == null) {
					return null;
				}
				if (ids[i] == id) {
					return n;
				}
			}
		}

		void put(int id, BTreeNode node) {
			if (nodes == null) {
				ids = new int[INITIAL];
				nodes = new BTreeNode[INITIAL];
			}
			else if ((size + 1) * 2 > nodes.length) {
				grow();
			}
			int mask = nodes.length - 1;
			for (int i = slot(id, mask);; i = (i + 1) & mask) {
				BTreeNode n = nodes[i];
				if (n == null) {
					ids[i] = id;
					nodes[i] = node;
					size++;
					return;
				}
				if (ids[i] == id) {
					nodes[i] = node;
					return;
				}
			}
		}

		private void grow() {
			int[] oldIds = ids;
			BTreeNode[] oldNodes = nodes;
			ids = new int[oldIds.length * 2];
			nodes = new BTreeNode[oldIds.length * 2];
			size = 0;
			for (int i = 0; i < oldNodes.length; i++) {
				if (oldNodes[i] != null) {
					put(oldIds[i], oldNodes[i]);
				}
			}
		}

		void remove(int id) {
			if (size == 0) {
				return;
			}
			int mask = nodes.length - 1;
			int i = slot(id, mask);
			for (;; i = (i + 1) & mask) {
				if (nodes[i] == null) {
					return;
				}
				if (ids[i] == id) {
					break;
				}
			}
			// backward-shift deletion keeps probe sequences intact
			nodes[i] = null;
			size--;
			int j = i;
			for (;;) {
				j = (j + 1) & mask;
				if (nodes[j] == null) {
					return;
				}
				int k = slot(ids[j], mask);
				if ((j > i && (k <= i || k > j)) || (j < i && (k <= i && k > j))) {
					ids[i] = ids[j];
					nodes[i] = nodes[j];
					nodes[j] = null;
					i = j;
				}
			}
		}

		void releaseAll(NodeMgr mgr) throws IOException {
			BTreeNode[] ns = nodes;
			if (size == 0) {
				return;
			}
			for (int i = 0; i < ns.length; i++) {
				BTreeNode node = ns[i];
				if (node != null) {
					if (node instanceof RecordNode) {
						mgr.leafRecordCnt -= node.getKeyCount();
					}
					mgr.bufferMgr.releaseBuffer(node.getBuffer());
				}
			}
			if (ns.length > KEEP) {
				ids = null;
				nodes = null;
			}
			else {
				java.util.Arrays.fill(ns, null);
			}
			size = 0;
		}
	}

	/**
	 * Construct a node manager for a specific table.
	 * @param table associated table
	 * @param bufferMgr buffer manager.
	 */
	NodeMgr(Table table, BufferMgr bufferMgr) {
		this.bufferMgr = bufferMgr;
		this.schema = table.getSchema();
		this.tableName = table.getName();
	}

	/**
	 * Get the buffer manager used by this node manager.
	 * @return BufferMgr
	 */
	BufferMgr getBufferMgr() {
		return bufferMgr;
	}

	/**
	 * Get the table schema associated with this node manager
	 * @return table schema
	 */
	Schema getTableSchema() {
		return schema;
	}

	/**
	 * Get the table name associated with this node manager
	 * @return table name
	 */
	String getTableName() {
		return tableName;
	}

	/**
	 * Release all nodes held by this node manager.
	 * This method must be invoked before a database transaction can be committed.
	 * @return the change in record count (+/-)
	 * @throws IOException if IO error occurs on database
	 */
	int releaseNodes() throws IOException {
		nodeTable.releaseAll(this);
		int result = -leafRecordCnt;
		leafRecordCnt = 0;
		return result;
	}

	/**
	 * Release a specific read-only buffer node.
	 * WARNING! This method may only be used to release read-only buffers,
	 * if a release buffer has been modified an IOException will be thrown.
	 * @param bufferId buffer ID
	 * @throws IOException if IO error occurs on database
	 */
	void releaseReadOnlyNode(int bufferId) throws IOException {
		BTreeNode node = nodeTable.get(bufferId);
		if (node.getBuffer().isDirty()) {
			// There is a possible leafRecordCount error if buffer is released multiple times
			throw new IOException("Releasing modified buffer node as read-only");
		}
		if (node instanceof RecordNode) {
			leafRecordCnt -= node.getKeyCount();
		}
		bufferMgr.releaseBuffer(node.getBuffer());
		nodeTable.remove(bufferId);
	}

	/**
	 * Add a newly created node to the node list.
	 * This method must be invoked when new nodes are instantiated.
	 * @param node a new node.
	 */
	void addNode(BTreeNode node) {
		nodeTable.put(node.getBufferId(), node);
	}

	/**
	 * Delete a node.
	 * @param node node to be deleted.
	 * @throws IOException thrown if an IO error occurs
	 */
	void deleteNode(BTreeNode node) throws IOException {
		int bufferId = node.getBufferId();
		nodeTable.remove(bufferId);
		bufferMgr.releaseBuffer(node.getBuffer());
		bufferMgr.deleteBuffer(bufferId);
	}

	/**
	 * Perform a test of the specified buffer to determine if it is
	 * a VarKeyNode type.  It is important that the specified buffer
	 * not be in use.
	 * @param bufferMgr buffer manager
	 * @param bufferId buffer ID
	 * @return true if node found and is a VarKeyNode type
	 * @throws IOException thrown if an IO error occurs
	 */
	static boolean isVarKeyNode(BufferMgr bufferMgr, int bufferId) throws IOException {
		DataBuffer buf = bufferMgr.getBuffer(bufferId);
		try {
			int nodeType = getNodeType(buf);
			return nodeType == VARKEY_REC_NODE || nodeType == VARKEY_INTERIOR_NODE;
		}
		finally {
			bufferMgr.releaseBuffer(buf);
		}
	}

	/**
	 * Get a LongKeyNode object for a specified buffer
	 * @param bufferId buffer ID
	 * @return LongKeyNode instance
	 * @throws ClassCastException if node type is incorrect.
	 * @throws IOException if IO error occurs on database
	 */
	LongKeyNode getLongKeyNode(int bufferId) throws IOException {
		LongKeyNode node = (LongKeyNode) nodeTable.get(bufferId);
		if (node != null) {
			return node;
		}

		DataBuffer buf = bufferMgr.getBuffer(bufferId);
		int nodeType = getNodeType(buf);
		switch (nodeType) {
			case LONGKEY_VAR_REC_NODE:
				node = new VarRecNode(this, buf);
				leafRecordCnt += node.keyCount;
				break;
			case LONGKEY_FIXED_REC_NODE:
				node = new FixedRecNode(this, buf, schema.getFixedLength());
				leafRecordCnt += node.keyCount;
				break;
			case LONGKEY_INTERIOR_NODE:
				node = new LongKeyInteriorNode(this, buf);
				break;
			default:
				bufferMgr.releaseBuffer(buf);
				throw new AssertException(
					"Unexpected Node Type (" + nodeType + ") found, expecting LongKeyNode");
		}
		return node;
	}

	/**
	 * Get a FixedKeyNode object for a specified buffer
	 * @param bufferId buffer ID
	 * @return LongKeyNode instance
	 * @throws ClassCastException if node type is incorrect.
	 * @throws IOException if IO error occurs on database
	 */
	FixedKeyNode getFixedKeyNode(int bufferId) throws IOException {
		FixedKeyNode node = (FixedKeyNode) nodeTable.get(bufferId);
		if (node != null) {
			return node;
		}

		DataBuffer buf = bufferMgr.getBuffer(bufferId);
		int nodeType = getNodeType(buf);
		switch (nodeType) {
			case FIXEDKEY_VAR_REC_NODE:
				node = new FixedKeyVarRecNode(this, buf);
				leafRecordCnt += node.keyCount;
				break;
			case FIXEDKEY_FIXED_REC_NODE:
				node = new FixedKeyFixedRecNode(this, buf);
				leafRecordCnt += node.keyCount;
				break;
			case FIXEDKEY_INTERIOR_NODE:
				node = new FixedKeyInteriorNode(this, buf);
				break;
			default:
				bufferMgr.releaseBuffer(buf);
				throw new IOException(
					"Unexpected Node Type (" + nodeType + ") found, expecting FixedKeyNode");
		}
		return node;
	}

	/**
	 * Get a VarKeyNode object for a specified buffer
	 * @param bufferId buffer ID
	 * @return VarKeyNode instance
	 * @throws ClassCastException if node type is incorrect.
	 * @throws IOException if IO error occurs on database
	 */
	VarKeyNode getVarKeyNode(int bufferId) throws IOException {
		VarKeyNode node = (VarKeyNode) nodeTable.get(bufferId);
		if (node != null) {
			return node;
		}

		DataBuffer buf = bufferMgr.getBuffer(bufferId);
		int nodeType = getNodeType(buf);
		switch (nodeType) {
			case VARKEY_REC_NODE:
				node = new VarKeyRecordNode(this, buf);
				leafRecordCnt += node.keyCount;
				break;
			case VARKEY_INTERIOR_NODE:
				node = new VarKeyInteriorNode(this, buf);
				break;
			default:
				bufferMgr.releaseBuffer(buf);
				throw new AssertException(
					"Unexpected Node Type (" + nodeType + ") found, expecting VarKeyNode");
		}
		return node;
	}

	/**
	 * Get the node type associated with the specified data buffer.
	 * @param buffer data buffer.
	 * @return node type
	 */
	static byte getNodeType(DataBuffer buffer) {
		return buffer.getByte(NODE_TYPE_OFFSET);
	}

	/**
	 * Set the node type associated with the specified data buffer.
	 * @param buffer data buffer
	 * @param nodeType node type value.
	 */
	static void setNodeType(DataBuffer buffer, byte nodeType) {
		buffer.putByte(NODE_TYPE_OFFSET, nodeType);
	}
}
