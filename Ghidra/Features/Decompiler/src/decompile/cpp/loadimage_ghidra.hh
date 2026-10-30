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
/// \file loadimage_ghidra.hh
/// \brief Use the Ghidra client as a load image
#ifndef __LOADIMAGE_GHIDRA_HH__
#define __LOADIMAGE_GHIDRA_HH__

#include "loadimage.hh"
#include "ghidra_arch.hh"

namespace ghidra {

class ArchitectureGhidra;

/// \brief A read-only, memory-mapped snapshot of a program's initialized memory (Hydra)
///
/// The Ghidra client writes the file once per program generation (the \e sealed-generation snapshot,
/// format version 1, documented in docs/hydra-snapshot.md and written by ProgramSnapshotFile).
/// The file never changes while it is mapped, so any number of readers use it with no lock.
/// A read is served only when the whole range lies inside one region; anything else is left to the caller.
class SnapshotImage {
  /// \brief One contiguous range of bytes in one address space
  struct Region {
    int4 spaceIndex;		///< Index into the space name table
    uintb offset;		///< First byte offset of the region in its space
    uintb length;		///< Number of bytes
    const uint1 *data;		///< The mapped bytes
  };
  vector<string> spaceNames;	///< Address space names, in file order
  vector<Region> regions;	///< Regions sorted by space index then offset, never overlapping
  const uint1 *base;		///< Start of the mapping
  uintb size;			///< Size of the mapping in bytes
  void *fileHandle;		///< Platform handle of the open file
  void *mapHandle;		///< Platform handle of the mapping (Windows only)
  void unmap(void);		///< Release the mapping and handles
  void parse(void);		///< Read the header, space table and region table
public:
  SnapshotImage(const string &path);	///< Map the given snapshot file (throws LowlevelError on any problem)
  ~SnapshotImage(void);			///< Unmap the file
  bool read(uint1 *ptr,int4 sz,const Address &addr) const;	///< Copy bytes if the snapshot covers the whole range
};

/// \brief An implementation of the LoadImage interface using a Ghidra client as the back-end
///
/// Requests for program bytes are marshaled to a Ghidra client which sends back the data.
/// When the client supplies a SnapshotImage, requests it covers are served from the mapping with no callback.
class LoadImageGhidra : public LoadImage {
  ArchitectureGhidra *glb;			///< The owning Architecture and connection to the client
  SnapshotImage *snapshot;			///< Mapped snapshot of the program's bytes (may be null)
public:
  LoadImageGhidra(ArchitectureGhidra *g);	///< Constructor
  virtual ~LoadImageGhidra(void);		///< Destructor
  void setSnapshot(const string &path);		///< Use the snapshot at the given path (an empty path drops it)
  //  virtual ~LoadImage(void) {}
  void open(void);				///< Open any descriptors
  void close(void);				///< Close any descriptor
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
  // Read only flags are all controlled through the database interface
  virtual string getArchType(void) const;
  virtual void adjustVma(long adjust);
};

} // End namespace ghidra
#endif
