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
#include "loadimage_ghidra.hh"

#include <cstring>

#ifdef _WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ghidra {

/// \param p points at the first byte
/// \param sz is the number of bytes (4 or 8)
/// \return the little-endian unsigned value stored there
static uintb readLittle(const uint1 *p,int4 sz)

{
  uintb res = 0;
  for(int4 i=sz-1;i>=0;--i)
    res = (res << 8) | p[i];
  return res;
}

/// The file is opened read-only and mapped in full. The header and tables are validated before any read is served.
/// \param path is the snapshot file written by the client
SnapshotImage::SnapshotImage(const string &path)

{
  base = (const uint1 *)0;
  size = 0;
  fileHandle = (void *)0;
  mapHandle = (void *)0;
#ifdef _WINDOWS
  HANDLE fh = CreateFileA(path.c_str(),GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,
			  FILE_ATTRIBUTE_NORMAL,NULL);
  if (fh == INVALID_HANDLE_VALUE)
    throw LowlevelError("Could not open snapshot: " + path);
  fileHandle = (void *)fh;
  LARGE_INTEGER fileSize;
  if (!GetFileSizeEx(fh,&fileSize) || fileSize.QuadPart == 0) {
    unmap();
    throw LowlevelError("Empty snapshot: " + path);
  }
  size = (uintb)fileSize.QuadPart;
  HANDLE mh = CreateFileMappingA(fh,NULL,PAGE_READONLY,0,0,NULL);
  if (mh == NULL) {
    unmap();
    throw LowlevelError("Could not map snapshot: " + path);
  }
  mapHandle = (void *)mh;
  base = (const uint1 *)MapViewOfFile(mh,FILE_MAP_READ,0,0,0);
#else
  int fd = ::open(path.c_str(),O_RDONLY);
  if (fd < 0)
    throw LowlevelError("Could not open snapshot: " + path);
  fileHandle = (void *)(intptr_t)(fd + 1);
  struct stat st;
  if (fstat(fd,&st) != 0 || st.st_size == 0) {
    unmap();
    throw LowlevelError("Empty snapshot: " + path);
  }
  size = (uintb)st.st_size;
  void *m = mmap((void *)0,size,PROT_READ,MAP_SHARED,fd,0);
  base = (m == MAP_FAILED) ? (const uint1 *)0 : (const uint1 *)m;
#endif
  if (base == (const uint1 *)0) {
    unmap();
    throw LowlevelError("Could not map snapshot: " + path);
  }
  try {
    parse();
  }
  catch(LowlevelError &err) {
    unmap();
    throw;
  }
}

SnapshotImage::~SnapshotImage(void)

{
  unmap();
}

void SnapshotImage::unmap(void)

{
#ifdef _WINDOWS
  if (base != (const uint1 *)0)
    UnmapViewOfFile((LPCVOID)base);
  if (mapHandle != (void *)0)
    CloseHandle((HANDLE)mapHandle);
  if (fileHandle != (void *)0)
    CloseHandle((HANDLE)fileHandle);
#else
  if (base != (const uint1 *)0)
    munmap((void *)base,size);
  if (fileHandle != (void *)0)
    ::close((int)(intptr_t)fileHandle - 1);
#endif
  base = (const uint1 *)0;
  mapHandle = (void *)0;
  fileHandle = (void *)0;
  regions.clear();
  spaceNames.clear();
}

/// Layout (format version 1, little-endian): the 8-byte magic "HYSNAP01", u32 version, u32 space count,
/// u32 region count, u32 reserved, u64 generation; then one 32-byte entry per region (u32 space index,
/// u32 reserved, u64 offset, u64 length, u64 file offset of the data); then each space name as a u32 length
/// followed by its UTF-8 bytes. Regions are sorted by space index and offset and never overlap.
void SnapshotImage::parse(void)

{
  if (size < 32 || memcmp(base,"HYSNAP01",8) != 0)
    throw LowlevelError("Not a snapshot file");
  if (readLittle(base+8,4) != 1)
    throw LowlevelError("Unsupported snapshot version");
  uintb spaceCount = readLittle(base+12,4);
  uintb regionCount = readLittle(base+16,4);
  if (regionCount > (size - 32) / 32)
    throw LowlevelError("Truncated snapshot region table");
  uintb pos = 32 + regionCount * 32;
  for(uintb i=0;i<spaceCount;++i) {
    if (pos + 4 > size)
      throw LowlevelError("Truncated snapshot space table");
    uintb len = readLittle(base+pos,4);
    pos += 4;
    if (len > size - pos)
      throw LowlevelError("Truncated snapshot space table");
    spaceNames.push_back(string((const char *)(base+pos),len));
    pos += len;
  }
  regions.resize(regionCount);
  for(uintb i=0;i<regionCount;++i) {
    const uint1 *entry = base + 32 + i * 32;
    Region &region(regions[i]);
    uintb spaceIndex = readLittle(entry,4);
    region.offset = readLittle(entry+8,8);
    region.length = readLittle(entry+16,8);
    uintb dataOffset = readLittle(entry+24,8);
    if (spaceIndex >= spaceCount)
      throw LowlevelError("Bad snapshot space index");
    region.spaceIndex = (int4)spaceIndex;
    if (region.length == 0 || dataOffset > size || region.length > size - dataOffset)
      throw LowlevelError("Bad snapshot region");
    if (region.offset + (region.length - 1) < region.offset)
      throw LowlevelError("Bad snapshot region");
    if (i > 0) {
      const Region &prev(regions[i-1]);
      if (prev.spaceIndex > region.spaceIndex ||
	  (prev.spaceIndex == region.spaceIndex && prev.offset + (prev.length - 1) >= region.offset))
	throw LowlevelError("Snapshot regions out of order");
    }
    region.data = base + dataOffset;
  }
}

/// The address space must be byte-addressable and the whole range must fall in one region;
/// a partial or uncovered range returns \b false so the caller can ask the client instead.
/// \param ptr is the buffer to fill
/// \param sz is the number of bytes requested
/// \param addr is the first address
/// \return \b true if the bytes were copied
bool SnapshotImage::read(uint1 *ptr,int4 sz,const Address &addr) const

{
  if (sz <= 0) return false;
  AddrSpace *spc = addr.getSpace();
  if (spc == (AddrSpace *)0 || spc->getWordSize() != 1) return false;
  const string &name(spc->getName());
  int4 spaceIndex = -1;
  for(int4 i=0;i<spaceNames.size();++i) {
    if (spaceNames[i] == name) {
      spaceIndex = i;
      break;
    }
  }
  if (spaceIndex < 0) return false;
  uintb off = addr.getOffset();
  int4 lo = 0;			// Find the first region that starts after (spaceIndex, off)
  int4 hi = regions.size();
  while(lo < hi) {
    int4 mid = lo + (hi - lo) / 2;
    const Region &r(regions[mid]);
    if (r.spaceIndex < spaceIndex || (r.spaceIndex == spaceIndex && r.offset <= off))
      lo = mid + 1;
    else
      hi = mid;
  }
  if (lo == 0) return false;
  const Region &r(regions[lo-1]);
  if (r.spaceIndex != spaceIndex) return false;
  uintb rel = off - r.offset;
  if (rel >= r.length || (uintb)sz > r.length - rel) return false;
  memcpy(ptr,r.data + rel,sz);
  return true;
}

LoadImageGhidra::LoadImageGhidra(ArchitectureGhidra *g)
  : LoadImage("ghidra_progam")

{
  glb = g;
  snapshot = (SnapshotImage *)0;
}

LoadImageGhidra::~LoadImageGhidra(void)

{
  if (snapshot != (SnapshotImage *)0)
    delete snapshot;
}

/// Any previous snapshot is released first. If the new file cannot be mapped, the error is thrown
/// and no snapshot is in use, so every request goes to the client.
/// \param path is the snapshot file, or an empty string to stop using a snapshot
void LoadImageGhidra::setSnapshot(const string &path)

{
  if (snapshot != (SnapshotImage *)0) {
    delete snapshot;
    snapshot = (SnapshotImage *)0;
  }
  if (path.size() != 0)
    snapshot = new SnapshotImage(path);
}

void LoadImageGhidra::open(void)

{
}

void LoadImageGhidra::close(void)

{
}

void LoadImageGhidra::loadFill(uint1 *ptr,int4 size,const Address &inaddr)

{
  if (snapshot != (SnapshotImage *)0 && snapshot->read(ptr,size,inaddr))
    return;
  glb->getBytes(ptr,size,inaddr);
}

string LoadImageGhidra::getArchType(void) const

{
  return "ghidra";
}

void LoadImageGhidra::adjustVma(long adjust)

{
  throw LowlevelError("Cannot adjust GHIDRA virtual memory");
}

} // End namespace ghidra
