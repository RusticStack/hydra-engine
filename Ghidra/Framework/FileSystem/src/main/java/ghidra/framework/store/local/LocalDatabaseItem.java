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
// Hydra Engine: modified from Ghidra's original (see NOTICE-HYDRA).
package ghidra.framework.store.local;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import db.buffers.*;
import ghidra.framework.store.*;
import ghidra.framework.store.db.*;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LocalDatabaseItem</code> provides a FolderItem implementation
 * for a local database.  This item wraps an underlying VersionedDatabase
 * if the file-system is versioned, otherwise a PrivateDatabase is wrapped.
 * <p>
 * This item utilizes a data directory for storing all files relating to the
 * database as well as history and checkout data files if this item is versioned.
 */
public class LocalDatabaseItem extends LocalFolderItem implements DatabaseItem {

	private PrivateDatabase privateDb;
	private VersionedDatabase versionedDb;
	private LocalVersionedDbListener versionedDbListener;

	private String deleteUser;

	/**
	 * Constructor for a new or existing local database item which corresponds to the specified 
	 * property file.  
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param create if true the data directory will be created
	 * @throws IOException
	 */
	private LocalDatabaseItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile,
			boolean create) throws IOException {
		super(fileSystem, propertyFile, true, create);
		if (isVersioned) {
			versionedDbListener = new LocalVersionedDbListener();
		}
	}

	/**
	 * Constructor for an existing local database item which corresponds to the specified 
	 * property file.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile)
			throws IOException {
		super(fileSystem, propertyFile, true, false);

		if (isVersioned) {
			// Hydra E8: the VersionedDatabase checks its newest version itself (see below)
			versionedDbListener = new LocalVersionedDbListener();
			// Hydra E8b: state the file system's read-only flag, so that the open-time check of
			// the database never repairs in a read-only file system (the two-argument
			// constructor assumes a writable one)
			versionedDb = new VersionedDatabase(getDataDir(), versionedDbListener,
				fileSystem.isReadOnly());
			versionedDb.setSynchronizationObject(fileSystem);
		}
		else {
			// Hydra E8/E8b: a newest version with an invalid header (an interrupted save) is
			// handled when the item is opened (openPrivate), not here: reading the header of
			// every item a listing constructs cost more than 5% of the listing time (measured).
			privateDb = new PrivateDatabase(getDataDir());
			privateDb.setIsCheckoutCopy(isCheckedOut());
			privateDb.setSynchronizationObject(fileSystem);
		}
	}

	/**
	 * Create a new local Database item which corresponds to the specified 
	 * property file.  The initial contents of the database are copied from the
	 * specified srcFile.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param srcFile open source Database buffer file
	 * @param contentType user content type
	 * @param fileID unique file ID
	 * @param comment if versioned, comment used for version 1 history data
	 * @param resetDatabaseId if true database ID will be reset for new Database
	 * @param monitor copy progress monitor
	 * @param user if versioned, user used for permission check and history data
	 * @throws IOException if error occurs
	 * @throws CancelledException if database creation cancelled by user
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile, BufferFile srcFile,
			String contentType, String fileID, String comment, boolean resetDatabaseId,
			TaskMonitor monitor, String user) throws IOException, CancelledException {
		super(fileSystem, propertyFile, true, true);

		if (StringUtils.isBlank(contentType)) {
			abortCreate();
			throw new IllegalArgumentException("Missing content-type");
		}

		boolean success = false;
		long checkoutId = DEFAULT_CHECKOUT_ID;
		try {
			if (fileID != null) {
				String oldFileId = propertyFile.getFileID();
				propertyFile.setFileID(fileID);
				fileSystem.fileIdChanged(propertyFile, oldFileId);
			}
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			if (isVersioned) {
				ItemCheckoutStatus coStatus = checkout(CheckoutType.NORMAL, user, null);
				checkoutId = coStatus.getCheckoutId();
				beginCheckin(checkoutId);
				versionedDbListener = new LocalVersionedDbListener();
				versionedDb = new VersionedDatabase(getDataDir(), srcFile, versionedDbListener,
					checkoutId, comment, monitor);
				versionedDb.setSynchronizationObject(fileSystem);
				terminateCheckout(checkoutId, false);
			}
			else {
				privateDb = new PrivateDatabase(getDataDir(), srcFile, resetDatabaseId, monitor);
				privateDb.setIsCheckoutCopy(isCheckedOut());
				privateDb.setSynchronizationObject(fileSystem);
			}

			propertyFile.writeState();
			success = true;
		}
		finally {
			if (!success) {
				if (isVersioned) {
					endCheckin(checkoutId);
				}
				abortCreate();
			}
		}
		fireItemCreated();
	}

	/**
	 * Create a new local Database item which corresponds to the specified 
	 * property file.  The initial contents of the database are copied from the
	 * specified packedFile.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param packedFile packed database file
	 * @param contentType user content type
	 * @param monitor copy progress monitor
	 * @param user if versioned, user used for permission check and history data
	 * @throws IOException if error occurs
	 * @throws CancelledException if database creation cancelled by user
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile, File packedFile,
			String contentType, TaskMonitor monitor, String user)
			throws IOException, CancelledException {
		super(fileSystem, propertyFile, true, true);

		if (isVersioned) {
			// no supported use case
			throw new UnsupportedOperationException();
		}

		boolean success = false;
		long checkoutId = DEFAULT_CHECKOUT_ID;
		try {
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			String oldFileId = propertyFile.getFileID();
			propertyFile.setFileID(FileIDFactory.createFileID());
			fileSystem.fileIdChanged(propertyFile, oldFileId);

//			if (isVersioned) { 
// unsupported operation
//				ItemCheckoutStatus coStatus = checkout(false, user, null);
//				checkoutId = coStatus.getCheckoutId();
//				beginCheckin(checkoutId);
//				String comment = "Unpacked " + packedFile;
//				versionedDbListener = new LocalVersionedDbListener();
//				versionedDb =
//					new VersionedDatabase(getDataDir(), packedFile, versionedDbListener, checkoutId, comment,
//						monitor);
//				versionedDb.setSynchronizationObject(fileSystem);
//				terminateCheckout(checkoutId, false);
//			}
//			else {
			privateDb = new PrivateDatabase(getDataDir(), packedFile, monitor);
			privateDb.setIsCheckoutCopy(isCheckedOut());
			privateDb.setSynchronizationObject(fileSystem);
//			}

			propertyFile.writeState();
			success = true;
		}
		finally {
			if (!success) {
				if (isVersioned) {
					endCheckin(checkoutId);
				}
				abortCreate();
			}
		}
		fireItemCreated();
	}

	/**
	 * Create a new LocalDatabaseItem and an empty updateable BufferFile which may be used
	 * to create the initial database content.
	 *  @param fileSystem file system
	 * @param propertyFile database property file
	 * @param bufferSize buffer size to be used for new database
	 * @param contentType user content type
	 * @param fileID unique file ID or null
	 * @param user if versioned, user used for permission check and history data
	 * @param projectPath path of project in versioned database checkout is done (may be null for non-versioned database)
	 * @return open updateable empty BufferFile for initial content writing
	 * @throws IOException if error occurs
	 */
	static LocalManagedBufferFile create(final LocalFileSystem fileSystem,
			ItemPropertyFile propertyFile, int bufferSize, String contentType, String fileID,
			String user, String projectPath) throws IOException {

		final LocalDatabaseItem dbItem = new LocalDatabaseItem(fileSystem, propertyFile, true);
		File dbDir = dbItem.getDataDir();

		long checkoutId = DEFAULT_CHECKOUT_ID;
		boolean success = false;
		try {
			if (fileID != null) {
				String oldFileId = propertyFile.getFileID();
				propertyFile.setFileID(fileID);
				fileSystem.fileIdChanged(propertyFile, oldFileId);
			}
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			LocalManagedBufferFile bfile;
			if (fileSystem.isVersioned()) {
				ItemCheckoutStatus coStatus =
					dbItem.checkout(CheckoutType.NORMAL, user, projectPath);
				checkoutId = coStatus.getCheckoutId();
				dbItem.beginCheckin(checkoutId);
				bfile = VersionedDatabase.createVersionedDatabase(dbDir, bufferSize,
					dbItem.versionedDbListener, checkoutId);
			}
			else {
				bfile = PrivateDatabase.createDatabase(dbDir, (db, version) -> {
					synchronized (fileSystem) {
						if (version == 1) {
							// The content is complete: only now does the item say what it is.
							// Until then its property file has no file type, so an item whose
							// process died while writing it is removed as "not properly created"
							// the next time it is listed, instead of being listed as a database
							// that cannot be opened.
							try {
								dbItem.propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
								dbItem.propertyFile.writeState();
							}
							catch (IOException e) {
								throw new UncheckedIOException(e);
							}
							if (dbItem.privateDb == null) {
								db.setSynchronizationObject(dbItem.fileSystem);
								dbItem.privateDb = (PrivateDatabase) db;
							}
							dbItem.log("file created", user);
							dbItem.fireItemCreated();
						}
					}
				}, bufferSize);
				// written without its file type until version 1 exists (above)
				propertyFile.remove(FILE_TYPE);
				propertyFile.writeState();
				propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
				success = true;
				return bfile;
			}

			propertyFile.writeState();
			success = true;
			return bfile;
		}
		finally {
			if (!success) {
				if (fileSystem.isVersioned()) {
					dbItem.endCheckin(checkoutId);
				}
				dbItem.abortCreate();
			}
		}
	}

	@Override
	public long length() throws IOException {
		if (isVersioned) {
			return versionedDb.length();
		}
		return privateDb.length();
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#moveTo(java.io.File, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	void moveTo(File newFolder, String newStorageName, String newFolderPath, String newName)
			throws IOException {
		super.moveTo(newFolder, newStorageName, newFolderPath, newName);
		if (isVersioned) {
			versionedDb.dbMoved(getDataDir());
		}
		else {
			privateDb.dbMoved(getDataDir());
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#fireItemChanged()
	 */
	@Override
	void fireItemChanged() {
		if (privateDb != null) {
			privateDb.setIsCheckoutCopy(isCheckedOut());
		}
		super.fireItemChanged();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCurrentVersion()
	 */
	@Override
	public int getCurrentVersion() {
		if (isVersioned) {
			return versionedDb != null ? versionedDb.getCurrentVersion() : 0;
		}
		return privateDb != null ? privateDb.getCurrentVersion() : 0;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getMinimumVersion()
	 */
	@Override
	public int getMinimumVersion() throws IOException {
		// The database object may be null during initial database creation,
		// although such an instance is private to the static create method.
		if (isVersioned) {
			if (versionedDb == null) {
				throw new IllegalStateException();
			}
			return versionedDb.getMinimumVersion();
		}
		if (privateDb == null) {
			throw new IllegalStateException();
		}
		return privateDb.getCurrentVersion();
	}

	/**
	 * <code>LocalVersionedDbListener</code> provides a listener 
	 * which maintains checkout and history data in response to 
	 * VersionedDatabase callbacks.
	 */
	private class LocalVersionedDbListener implements VersionedDBListener {

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionsChanged(int, int)
		 */
		@Override
		public void versionsChanged(int minVersion, int currentVersion) {
			synchronized (fileSystem) {
				if (minVersion == 0 && currentVersion == 0) {
					// file must have been removed

				}
				try {
					if (historyMgr.fixHistory(minVersion, currentVersion)) {
						fireItemChanged();
					}
				}
				catch (IOException e) {
					Msg.error(this, "Failed to update version history: " + getPathName(), e);
				}
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionCreated(ghidra.framework.store.db.VersionedDatabase, int, long, java.lang.String, long)
		 */
		@Override
		public boolean versionCreated(VersionedDatabase database, int version, long time,
				String comment, long dbCheckinId) {
			synchronized (fileSystem) {
				try {
					ItemCheckoutStatus coStatus = checkoutMgr.getCheckout(dbCheckinId);
					if (coStatus == null || LocalDatabaseItem.this.checkinId != dbCheckinId) {
						log("ERROR! version " + version + " created without valid checkin", null);
						return false;
					}
					if (version == 1 && versionedDb == null) {
						versionedDb = database;
						versionedDb.setSynchronizationObject(fileSystem);
					}
					String user = coStatus.getUser();
					historyMgr.versionAdded(version, time, comment, user);
					checkoutMgr.updateCheckout(dbCheckinId, version);
				}
				catch (IOException e) {
					Msg.error(getName() + " versioning error", e);
				}
			}
			if (version == 1) {
				fireItemCreated();
			}
			else {
				fireItemChanged();
			}
			return true;
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionDeleted(int)
		 */
		@Override
		public void versionDeleted(int version) {
			synchronized (fileSystem) {
				try {
					historyMgr.versionDeleted(version, deleteUser);
				}
				catch (IOException e) {
					Msg.error(this, "Failed to update version history: " + getPathName(), e);
				}
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#getCheckoutVersion(long)
		 */
		@Override
		public int getCheckoutVersion(long checkoutId) throws IOException {
			synchronized (fileSystem) {
				ItemCheckoutStatus coStatus = checkoutMgr.getCheckout(checkoutId);
				return coStatus != null ? coStatus.getCheckoutVersion() : -1;
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#checkinCompleted(long)
		 */
		@Override
		public void checkinCompleted(long dbCheckinId) {
			synchronized (fileSystem) {
				if (isVersioned) {
					endCheckin(dbCheckinId);
				}
				if (versionedDb == null || versionedDb.getCurrentVersion() == 0) {
					// remove item which was created during initial creation
					try {
						if (isVersioned) {
							checkoutMgr.endCheckout(dbCheckinId);
						}
						deleteContent(null);
						fileSystem.itemDeleted(getParentPath(), getName()); // de-allocates index entry
						fileSystem.deleteEmptyVersionedFolders(getParentPath());
					}
					catch (IOException e) {
						Msg.error(this, getName() + " versioning error", e);
					}
				}
			}
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteMinimumVersion()
	 */
	@Override
	void deleteMinimumVersion(String user) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				deleteUser = user;
				versionedDb.deleteMinimumVersion();
			}
		}
	}

	@Override
	public void clearCheckout() throws IOException {
		if (isVersioned) {
			throw new UnsupportedOperationException(
				"clearCheckout is not applicable to versioned item");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			privateDb.updateCheckoutCopy(); // removes change data
			super.clearCheckout();
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteCurrentVersion()
	 */
	@Override
	void deleteCurrentVersion(String user) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				deleteUser = user;
				versionedDb.deleteCurrentVersion();
			}
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open(int, int)
	 */
	@Override
	public LocalManagedBufferFile open(int version, int minChangeDataVer) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(version, minChangeDataVer);
			}
			if (version == LATEST_VERSION) {
				return openPrivate(false);
			}
			throw new IllegalArgumentException("only LATEST_VERSION may be opened");
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open(int)
	 */
	@Override
	public LocalManagedBufferFile open(int version) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(version, -1);
			}
			if (version == LATEST_VERSION) {
				return openPrivate(false);
			}
			throw new IllegalArgumentException("only LATEST_VERSION may be opened");
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open()
	 */
	@Override
	public LocalManagedBufferFile open() throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(LATEST_VERSION, -1);
			}
			return openPrivate(false);
		}
	}

	/**
	 * Open the latest database version for update.
	 * @param checkoutId reqiured for update to a versioned item, otherwise set to -1 for
	 * a non-versioned private database.
	 * @return open database handle
	 * @throws IOException
	 */
	@Override
	public LocalManagedBufferFile openForUpdate(long checkoutId) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			if (isVersioned) {
				beginCheckin(checkoutId);
				boolean success = false;
				try {
					LocalManagedBufferFile bfile = versionedDb.openBufferFileForUpdate(checkoutId);
					success = true;
					return bfile;
				}
				finally {
					if (!success) {
						endCheckin(checkoutId);
					}
				}
			}
			return openPrivate(true);
		}
	}

	/**
	 * Open the buffer file of the private database. Hydra E8/E8b: the header of the newest
	 * version (the file that is about to be opened, so no directory listing) is read first. In a
	 * writable disposable tree a newest version with an invalid header (an interrupted save) is
	 * quarantined and the database is scanned again, the previous version being the newest; anywhere
	 * else the answer is {@code corrupt_newest} instead of the buffer file's "Unrecognized file
	 * format". Nothing is read when the item is constructed (that cost more than 5% of the time of
	 * a project listing, measured). The check is made before the file is opened: a failed open
	 * keeps the file handle until it is collected, and an open file cannot be moved on Windows.
	 * Caller holds the file system lock.
	 */
	private LocalManagedBufferFile openPrivate(boolean forUpdate) throws IOException {
		// Hydra GATE8: this item's database keeps the current version it scanned. A save whose
		// commit took effect on disk but failed afterwards (before the database recorded the new
		// version) leaves a newer version file than the one recorded, and every open of this item
		// opened the older version again (and every save of it targeted the existing newer name),
		// until the item was rebuilt. A newer version file than the recorded one makes the
		// database scan its folder again, so that an open gets what a restart would get. One file
		// test on the healthy path, no listing.
		int recorded = privateDb.getCurrentVersion();
		if (new File(getDataDir(), "db." + (recorded + 1) + ".gbf").isFile()) {
			privateDb.refresh();
			Msg.warn(this, getDataDir() + ": version " + (recorded + 1) +
				" exists but version " + recorded + " was recorded as the newest (a save that " +
				"failed after its commit); scanned again, the newest is version " +
				privateDb.getCurrentVersion());
		}
		File newest = new File(getDataDir(), "db." + privateDb.getCurrentVersion() + ".gbf");
		if (!VersionFileCheck.hasValidMagic(newest)) {
			VersionFileCheck.Result r =
				VersionFileCheck.repairOnOpen(getDataDir(), !fileSystem.isReadOnly());
			// REPAIRED: this opener quarantined the newest version. OK: the file this item
				// expected is gone and the newest on disk is valid, so another opener (another
				// item of the same file, e.g. the project's format scan) quarantined it first
				// and this item's cached version is stale. Either way, scan the database again.
				if (r.status == VersionFileCheck.Status.REPAIRED ||
					r.status == VersionFileCheck.Status.OK) {
				privateDb = new PrivateDatabase(getDataDir());
				privateDb.setIsCheckoutCopy(isCheckedOut());
				privateDb.setSynchronizationObject(fileSystem);
			}
			else {
				VersionFileCheck.requireIntact(getDataDir());
			}
		}
		return forUpdate ? privateDb.openBufferFileForUpdate() : privateDb.openBufferFile();
	}

	/**
	 * @see ghidra.framework.store.FolderItem#canRecover()
	 */
	@Override
	public boolean canRecover() {
		synchronized (fileSystem) {
			return privateDb != null && privateDb.canRecover();
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#output(java.io.File, int version, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void output(File outputFile, int version, TaskMonitor monitor)
			throws CancelledException, IOException {
		synchronized (fileSystem) {

			String contentType = getContentType();
			if (UnknownFolderItem.UNKNOWN_CONTENT_TYPE.equals(contentType)) {
				throw new IOException("Unknown content type");
			}

			if (isVersioned) {
				versionedDb.output(version, outputFile, getName(), DATABASE_FILE_TYPE, contentType,
					monitor);
			}
			else {
				privateDb.output(outputFile, getName(), DATABASE_FILE_TYPE, contentType, monitor);
			}
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, boolean, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			long checkoutId = getCheckoutId();
			boolean exclusive = isCheckedOutExclusive();
			if (isVersioned || checkoutId == DEFAULT_CHECKOUT_ID) {
				throw new IOException(getName() + " is not checked-out");
			}
			DatabaseItem verDbItem = (DatabaseItem) versionedFolderItem;
			//ItemCheckoutStatus coStatus = verDbItem.getCheckout(checkoutId);
			//int coVer = coStatus.getCheckoutVersion();

			int ver = verDbItem.getCurrentVersion();

			if (updateItem) {
				ManagedBufferFile verBf = verDbItem.open(ver);
				try {
					privateDb.updateCheckoutCopy(verBf, getCheckoutVersion(), monitor);
				}
				finally {
					try {
						verBf.close();
					}
					catch (IOException e) {
						// ignored
					}
				}
			}
			else {
				privateDb.updateCheckoutCopy();
			}
			setCheckout(checkoutId, exclusive, ver, getCurrentVersion());
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, int)
	 */
	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			long checkoutId = getCheckoutId();
			if (isVersioned || checkoutId == DEFAULT_CHECKOUT_ID) {
				throw new IOException(getName() + " is not checked-out");
			}
			if (!(item instanceof LocalDatabaseItem)) {
				throw new IllegalArgumentException("Expected local database item");
			}
			LocalDatabaseItem dbItem = (LocalDatabaseItem) item;
			if (fileSystem != dbItem.fileSystem) {
				throw new IllegalArgumentException("Items must be from same file system");
			}
			try {
				privateDb.updateCheckoutFrom(dbItem.privateDb);
				setCheckout(checkoutId, isCheckedOutExclusive(), checkoutVersion,
					getLocalCheckoutVersion());
			}
			finally {
				item.delete(-1, null);
			}
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#lastModified()
	 */
	@Override
	public long lastModified() {
		if (privateDb != null) {
			return privateDb.lastModified();
		}
		return versionedDb.lastModified();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#refresh()
	 */
	@Override
	public LocalFolderItem refresh() throws IOException {
		if (super.refresh() == null) {
			return null;
		}
		if (isVersioned) {
			versionedDb.refresh();
		}
		else {
			try {
				privateDb.refresh();
			}
			catch (FileNotFoundException e) {
				// Hydra GATE8: the folder exists and the newest recorded version is there, but the
				// folder cannot be listed (on Windows, another process holds it without read
				// sharing). Thrown, it made the project drop the file (GhidraFolderData.fileChanged
				// removes an item whose refresh fails, and a visited folder is not listed again), so
				// a save that succeeded under such a hold left a program that could no longer be
				// saved ("File is read-only") until the project was refreshed. The item is kept
				// with what it recorded; the next refresh scans again.
				int cur = privateDb.getCurrentVersion();
				if (!getDataDir().isDirectory() ||
					!new File(getDataDir(), "db." + cur + ".gbf").isFile()) {
					throw e;
				}
				Msg.warn(this, getDataDir() + ": cannot be listed (" + e.getMessage() +
					"; another process holds it?); the item keeps version " + cur);
			}
			privateDb.setIsCheckoutCopy(isCheckedOut());
		}
		return this;
	}

	/**
	 * Removes the old presave files ({@code tmp<n>.ps}) below a writable file-system root, in the
	 * background, as Ghidra always did at open: every presave file whose time is before the open.
	 * <p>
	 * Hydra (H6): the open used to start a new {@code Database-Item-Cleanup} thread per call (a
	 * project open makes three calls, for its private, user and versioned file systems; every
	 * fork and every upgrade copy opens one more project), and each thread created and deleted a
	 * temporary file in the root and then stat'ed every entry of the tree. Now one low-priority
	 * daemon worker serves every root and ends when idle; a root that is already waiting is not
	 * queued twice (the later open's cutoff covers the earlier one); each folder is listed once
	 * with the attributes the listing returns, without a stat per entry; and the file-system clock
	 * (the temporary file) is read only when a presave file is found. The cutoff is the
	 * file-system time of the open itself, so a presave file that a save creates after the open
	 * is never taken, however long the worker's queue is.
	 * @param root file-system root directory
	 */
	static void cleanupOldPresaveFiles(File root) {
		PresaveCleanup.request(root);
	}

	/**
	 * The process-wide presave cleanup worker (see {@link #cleanupOldPresaveFiles(File)}).
	 */
	static final class PresaveCleanup {

		static final String THREAD_NAME = "Database-Item-Cleanup";
		/** How long the worker waits for more work before it ends. */
		static final long IDLE_MS = 1000;

		private static final Object LOCK = new Object();
		/** Roots waiting for a scan, by absolute path, with the time of their latest open. */
		private static final LinkedHashMap<String, Request> PENDING = new LinkedHashMap<>();
		private static Thread worker;
		private static boolean busy;
		// counters, for tests and diagnostics
		private static long requests;
		private static long scans;
		private static long threadsStarted;
		private static long clockProbes;

		private record Request(File root, long openNanos) {
		}

		private PresaveCleanup() {
		}

		static void request(File root) {
			File abs = root.getAbsoluteFile();
			Request r = new Request(abs, System.nanoTime());
			synchronized (LOCK) {
				requests++;
				// a root already waiting keeps its place; the newer open has the later cutoff,
				// which covers every file the earlier open's scan would have removed
				PENDING.put(abs.getPath(), r);
				if (worker == null) {
					Thread t = new Thread(PresaveCleanup::work, THREAD_NAME);
					t.setDaemon(true);
					t.setPriority(Thread.MIN_PRIORITY);
					worker = t;
					threadsStarted++;
					t.start();
				}
				else {
					LOCK.notifyAll();
				}
			}
		}

		private static void work() {
			for (;;) {
				Request r;
				synchronized (LOCK) {
					busy = false;
					LOCK.notifyAll();
					long deadline = System.nanoTime() + IDLE_MS * 1_000_000L;
					while (PENDING.isEmpty()) {
						long waitMs = (deadline - System.nanoTime()) / 1_000_000L;
						if (waitMs <= 0) {
							worker = null;
							return;
						}
						try {
							LOCK.wait(waitMs);
						}
						catch (InterruptedException e) {
							// keep serving: an interrupt must not drop a queued root
						}
					}
					Iterator<Request> it = PENDING.values().iterator();
					r = it.next();
					it.remove();
					busy = true;
				}
				try {
					scan(r);
				}
				catch (Throwable t) {
					Msg.error(PresaveCleanup.class, "Unexpected Exception: " + t.getMessage(), t);
				}
				finally {
					synchronized (LOCK) {
						scans++;
					}
				}
			}
		}

		/**
		 * Waits until no root is waiting and no scan is running. For tests.
		 * @param timeoutMs the longest wait
		 * @return true when idle
		 * @throws InterruptedException if interrupted
		 */
		static boolean awaitIdle(long timeoutMs) throws InterruptedException {
			long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
			synchronized (LOCK) {
				while (!PENDING.isEmpty() || busy) {
					long waitMs = (deadline - System.nanoTime()) / 1_000_000L;
					if (waitMs <= 0) {
						return false;
					}
					LOCK.wait(waitMs);
				}
				return true;
			}
		}

		/**
		 * The counters, for tests.
		 * @return requests, scans, threads started, file-system clock probes
		 */
		static long[] counters() {
			synchronized (LOCK) {
				return new long[] { requests, scans, threadsStarted, clockProbes };
			}
		}

		private static void scan(Request r) throws IOException {
			File root = r.root();
			List<File> found = new ArrayList<>();
			if (root.isDirectory()) {
				try {
					collect(root.toPath(), found);
				}
				catch (InvalidPathException e) {
					// a name java.nio refuses on this platform (on Windows, one that ends in a
					// space or a dot) that java.io accepts: the old recursion, which takes it
					found.clear();
					legacyDir(root, found);
				}
			}
			if (found.isEmpty()) {
				return;
			}
			// The file-system time of the open (the clock of the volume, which can differ from
			// this machine's on a network share): its time now, less the time since the open
			File f = File.createTempFile("tmp", ".tmp", root);
			long now = f.lastModified();
			f.delete();
			synchronized (LOCK) {
				clockProbes++;
			}
			long beforeNow = now;
			if (now != 0) {
				long sinceOpenMs = (System.nanoTime() - r.openNanos()) / 1_000_000L;
				beforeNow = Math.max(1, now - sinceOpenMs);
			}
			for (File oldFile : found) {
				if ((beforeNow == 0 || oldFile.lastModified() < beforeNow) && oldFile.delete()) {
					Msg.info(LocalBufferFile.class, "Removed old presave file: " + oldFile);
				}
			}
		}

		/**
		 * The presave files of the tree, chosen as the old recursion did: a non-hidden folder is
		 * entered; a hidden folder named {@code *.db} is a database folder, whose files named
		 * {@code *.ps} are taken (not its sub-folders); other hidden folders are skipped. One
		 * listing per folder, using the attributes it returns. A symbolic link is followed, as
		 * {@link File#isDirectory()} and {@link File#isFile()} did.
		 */
		private static void collect(Path root, List<File> found) throws IOException {
			Files.walkFileTree(root, new SimpleFileVisitor<>() {
				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
					if (dir.equals(root)) {
						return FileVisitResult.CONTINUE;
					}
					if (isDataDir(dir.getParent())) {
						return FileVisitResult.SKIP_SUBTREE;
					}
					String name = dir.getFileName().toString();
					return !LocalFileSystem.isHiddenDirName(name) ||
						name.endsWith(DATA_DIR_EXTENSION) ? FileVisitResult.CONTINUE
								: FileVisitResult.SKIP_SUBTREE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
					boolean inDataDir = isDataDir(file.getParent());
					if (attrs.isSymbolicLink()) {
						linked(file.toFile(), inDataDir, found);
					}
					else if (inDataDir && attrs.isRegularFile() &&
						file.getFileName().toString().endsWith(LocalBufferFile.PRESAVE_FILE_EXT)) {
						found.add(file.toFile());
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path file, IOException exc) {
					return FileVisitResult.CONTINUE; // as File.listFiles: lists nothing
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
					return FileVisitResult.CONTINUE;
				}

				/** A folder the walk entered is a database folder when hidden and *.db. */
				private boolean isDataDir(Path dir) {
					return dir != null && !dir.equals(root) && isDataDirName(dir.getFileName().toString());
				}
			});
		}

		private static boolean isDataDirName(String name) {
			return LocalFileSystem.isHiddenDirName(name) && name.endsWith(DATA_DIR_EXTENSION);
		}

		/** A symbolic link met in the walk: followed, as File.isDirectory and File.isFile do. */
		private static void linked(File link, boolean inDataDir, List<File> found) {
			if (inDataDir) {
				if (link.getName().endsWith(LocalBufferFile.PRESAVE_FILE_EXT) && link.isFile()) {
					found.add(link);
				}
				return;
			}
			if (link.isDirectory()) {
				String fname = link.getName();
				if (!LocalFileSystem.isHiddenDirName(fname)) {
					legacyDir(link, found);
				}
				else if (fname.endsWith(DATA_DIR_EXTENSION)) {
					legacyDataDir(link, found);
				}
			}
		}

		/** The old recursion, for a folder reached through a symbolic link. */
		private static void legacyDir(File dir, List<File> found) {
			File[] files = dir.listFiles();
			if (files != null) {
				for (File f : files) {
					if (f.isDirectory()) {
						String fname = f.getName();
						if (!LocalFileSystem.isHiddenDirName(fname)) {
							legacyDir(f, found);
						}
						else if (fname.endsWith(DATA_DIR_EXTENSION)) {
							legacyDataDir(f, found);
						}
					}
				}
			}
		}

		private static void legacyDataDir(File dir, List<File> found) {
			File[] files = dir.listFiles();
			if (files != null) {
				for (File f : files) {
					if (f.getName().endsWith(LocalBufferFile.PRESAVE_FILE_EXT) && f.isFile()) {
						found.add(f);
					}
				}
			}
		}
	}

}
