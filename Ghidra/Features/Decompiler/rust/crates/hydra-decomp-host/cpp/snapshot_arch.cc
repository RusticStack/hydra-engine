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
#include "snapshot_arch.hh"
#include "loadimage_ghidra.hh"
#include "paramid.hh"
#include "libdecomp.hh"
#include "sleigh.hh"
#include "ghidra_translate.hh"

#include <cstdlib>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <sstream>

namespace ghidra {

// Defined by ghidra_process.cc in decompile.exe; the host does not link that file (it holds main
// and the per-process archlist), so the element the decompileAt response opens is defined here.
ElementId ELEM_DOC = ElementId("doc",229);

const char SnapshotChannel::MISS_TYPE[] = "hydra.SnapshotMiss";

static const string QUERY_OPEN("\000\000\001\004",4);
static const string QUERY_CLOSE("\000\000\001\005",4);
static const string STRING_OPEN("\000\000\001\016",4);
static const string STRING_CLOSE("\000\000\001\017",4);
static const string RESPONSE_OPEN("\000\000\001\010",4);
static const string RESPONSE_CLOSE("\000\000\001\011",4);
static const string EXCEPTION_OPEN("\000\000\001\012",4);

/// \param tp is the exception type
/// \param msg is the message
/// \return the bytes of an exception response, as DecompileProcess writes one
static string exceptionResponse(const string &tp,const string &msg)

{
  string res("\000\000\001\012",4);
  res += STRING_OPEN + tp + STRING_CLOSE;
  res += STRING_OPEN + msg + STRING_CLOSE;
  res.append("\000\000\001\013",4);
  return res;
}

string SnapshotStore::nativeReason;
/// Guards nativeReason: one thread writes it while another may read it (both on the error path).
static std::mutex nativeReasonLock;

/// Validation mode (diagnostics): decode natively and compare with the Java p-code answer, which
/// the Java side exports too (hydra.decomp.host.decodeValidate). A mismatch uses the Java answer.
/// Set from the environment at start, or by the client through hydra_snapshot_set_validate().
static std::atomic<bool> VALIDATE_NATIVE = []() {
  const char *v = getenv("HYDRA_SNAPSHOT_VALIDATE");
  return v != (const char *)0 && v[0] != 0 && v[0] != '0';
}();

/// Mismatch log lines printed so far (a bounded number: the status counts the rest).
static std::atomic<uint4> mismatchLogCount(0);

static uint4 mismatchLogs(void)

{
  return mismatchLogCount.fetch_add(1);
}

/// Records that native decode works for this generation (a later failure still disables it).
void SnapshotStore::enableNative(void)

{
  int4 expected = 0;
  nativeState.compare_exchange_strong(expected,1);
}

/// \param why is the reason, kept for the status report
void SnapshotStore::disableNative(const string &why)

{
  int4 expected = 0;
  if (nativeState.compare_exchange_strong(expected,-1)) {
    std::lock_guard<std::mutex> guard(nativeReasonLock);
    nativeReason = why;
  }
  else if (nativeState == 1)
    nativeState = -1;		// a late failure still turns this generation off
}

/// Records one native decode that fell back to the Java answer. A few are expected (an odd
/// instruction the local engine cannot reproduce); a run of them means the .sla or the snapshot
/// does not fit this generation, and native decode is turned off so the Java answers are exported
/// again instead of being learned one missed run at a time.
/// \param why is what failed
void SnapshotStore::nativeError(const string &why)

{
  uint8 count = nativeErrors.fetch_add(1) + 1;
  if (count >= 8) {
    std::ostringstream msg;
    msg << "native decode failed " << count << " times: " << why;
    string text(msg.str());
    disableNative(text);
  }
}

/// \param why receives the reason when native decode is disabled
/// \return 1 when native decode is usable, 0 before it was tried, -1 when disabled
int4 SnapshotStore::getNativeState(string &why) const

{
  int4 state = nativeState;
  if (state < 0) {
    std::lock_guard<std::mutex> guard(nativeReasonLock);
    why = nativeReason;
  }
  return state;
}

SnapshotStore::SnapshotStore(uint8 i,const string &p,const string &c,const string &t,const string &core,
			     const string &opt,const string &snap,const string &sla)
  : id(i), pspec(p), cspec(c), tspec(t), corespec(core), options(opt), snapshotPath(snap),
    slaPath(sla)

{
  bytes = 0;
  closed = false;
  nativeState = 0;
  nativeErrors = 0;
  validated = 0;
  mismatches = 0;
}

size_t SnapshotStore::shardOf(const string &key)

{
  return std::hash<string>()(key) & (SHARDS - 1);
}

/// An answer that is already present is kept (answers of one generation never change).
/// \param scope is the packed entry address of the function the answer depends on, or empty
/// \param query is the packed query payload
/// \param response is the complete response
void SnapshotStore::put(const string &scope,const string &query,const string &response)

{
  if (scope.empty()) {
    Shard &sh(global[shardOf(query)]);
    std::unique_lock<std::shared_mutex> guard(sh.lock);
    if (sh.map.emplace(query,response).second)
      bytes += query.size() + response.size();
  }
  else {
    string key(scope);
    key += '\0';
    key += query;
    Shard &sh(scoped[shardOf(key)]);
    std::unique_lock<std::shared_mutex> guard(sh.lock);
    if (sh.map.emplace(std::move(key),response).second)
      bytes += scope.size() + 1 + query.size() + response.size();
  }
}

/// The bulk form: one call adds every answer the Java side exported for a function, so a function
/// costs one crossing and a handful of map inserts instead of one crossing per answer.
/// \param blob is the packed block
/// \param len is its size in bytes
void SnapshotStore::putBulk(const char *blob,size_t len)

{
  size_t i = 0;
  auto read32 = [&](size_t &at,uint4 &v) -> bool {
    if (at + 4 > len) return false;
    v = (uint1)blob[at] | ((uint1)blob[at+1] << 8) | ((uint1)blob[at+2] << 16) | ((uint4)(uint1)blob[at+3] << 24);
    at += 4;
    return true;
  };
  while (i < len) {
    uint4 sn,qn,rn;
    if (!read32(i,sn) || i + sn > len) throw LowlevelError("snapshot store: bad bulk record (scope)");
    const char *sp = blob + i;
    i += sn;
    if (!read32(i,qn) || i + qn > len) throw LowlevelError("snapshot store: bad bulk record (query)");
    const char *qp = blob + i;
    i += qn;
    if (!read32(i,rn) || i + rn > len) throw LowlevelError("snapshot store: bad bulk record (response)");
    const char *rp = blob + i;
    i += rn;
    if (sn == 0) {
      Shard &sh(global[shardOf(string(qp,qn))]);
      std::unique_lock<std::shared_mutex> guard(sh.lock);
      auto res = sh.map.emplace(string(qp,qn),string(rp,rn));
      if (res.second)
	bytes += qn + rn;
    }
    else {
      string key(sp,sn);
      key += '\0';
      key.append(qp,qn);
      Shard &sh(scoped[shardOf(key)]);
      std::unique_lock<std::shared_mutex> guard(sh.lock);
      if (sh.map.emplace(std::move(key),string(rp,rn)).second)
	bytes += sn + 1 + qn + rn;
    }
  }
}

/// \The native-decode form: one record per function body. For each address space the
/// instructions live in, the space name and the addresses of the body's instructions. The host
/// decodes them itself, so their p-code is not exported at all; the instruction context comes
/// from the generation's context export (putContext) instead of a blob per instruction.
/// \param blob is the packed block (little endian): u32 name length + name, u32 count,
///   then count x u64 instruction offset
/// \param len is its size in bytes
void SnapshotStore::putDecode(const char *blob,size_t len)

{
  std::unique_lock<std::shared_mutex> guard(decodeLock);
  size_t i = 0;
  auto read32 = [&](size_t &at,uint4 &v) -> bool {
    if (at + 4 > len) return false;
    v = (uint1)blob[at] | ((uint1)blob[at+1] << 8) | ((uint1)blob[at+2] << 16) | ((uint4)(uint1)blob[at+3] << 24);
    at += 4;
    return true;
  };
  while (i < len) {
    uint4 namelen;
    if (!read32(i,namelen) || i + namelen > len)
      throw LowlevelError("snapshot store: bad decode record (space)");
    string name(blob + i,namelen);
    i += namelen;
    uint4 count;
    if (!read32(i,count))
      throw LowlevelError("snapshot store: bad decode record (count)");
    if ((uintb)count * 8 > len - i)
      throw LowlevelError("snapshot store: bad decode record (offsets)");
    std::unordered_set<uintb> &space(decode[name]);
    for(uint4 n=0;n<count;++n) {
      uintb offset = 0;
      for(int4 b=0;b<8;++b)
	offset |= ((uintb)(uint1)blob[i+b]) << (8*b);
      i += 8;
      space.insert(offset);
    }
  }
}

/// The instruction context of the generation: the program context register's default value and
/// the address ranges where it changes, exported once by the Java side (the native translator
/// needs it for every instruction it decodes, and it is the same for the whole generation).
/// \param blob is the packed block (little endian): u32 words, words x u32 default value,
///   u32 range count, then per range u32 name length + space name, u64 first, u64 last
///   (inclusive), words x u32 value
/// \param len is its size in bytes
void SnapshotStore::putContext(const char *blob,size_t len)

{
  contextBlob.assign(blob,len);
}

/// \param space is an address space name
/// \param offset is an address offset in it
/// \return true when the host decodes the instruction there itself
bool SnapshotStore::hasDecode(const string &space,uintb offset) const

{
  std::shared_lock<std::shared_mutex> guard(decodeLock);
  std::unordered_map<string,std::unordered_set<uintb> >::const_iterator iter(decode.find(space));
  if (iter == decode.end())
    return false;
  return (*iter).second.find(offset) != (*iter).second.end();
}

/// A scoped answer for the given scope wins over a global one.
/// \param scope is the scope of the current decompile (may be empty)
/// \param query is the packed query payload
/// \param composite is scratch for the scoped key (reused between lookups)
/// \return the answer, or null when the store does not hold one
const string *SnapshotStore::find(const string &scope,const string &query,string &composite) const

{
  if (!scope.empty()) {
    composite.assign(scope);
    composite += '\0';
    composite += query;
    const Shard &sh(scoped[shardOf(composite)]);
    std::shared_lock<std::shared_mutex> guard(sh.lock);
    unordered_map<string,string>::const_iterator iter = sh.map.find(composite);
    if (iter != sh.map.end())
      return &(*iter).second;
  }
  const Shard &sh(global[shardOf(query)]);
  std::shared_lock<std::shared_mutex> guard(sh.lock);
  unordered_map<string,string>::const_iterator iter = sh.map.find(query);
  if (iter == sh.map.end())
    return (const string *)0;
  return &(*iter).second;
}

uint8 SnapshotStore::count(void) const

{
  uint8 total = 0;
  for(size_t i=0;i<SHARDS;++i) {
    {
      const Shard &sh(global[i]);
      std::shared_lock<std::shared_mutex> guard(sh.lock);
      total += sh.map.size();
    }
    {
      const Shard &sh(scoped[i]);
      std::shared_lock<std::shared_mutex> guard(sh.lock);
      total += sh.map.size();
    }
  }
  return total;
}

uint8 SnapshotStore::size(void) const

{
  return bytes;
}

SnapshotChannel::OutBuf::int_type SnapshotChannel::OutBuf::overflow(int_type c)

{
  if (traits_type::eq_int_type(c,traits_type::eof()))
    return traits_type::not_eof(c);
  data.push_back(traits_type::to_char_type(c));
  return c;
}

std::streamsize SnapshotChannel::OutBuf::xsputn(const char *s,std::streamsize n)

{
  data.append(s,(size_t)n);
  return n;
}

/// The decompiler only reads after writing a whole query (and flushing), so a read past the end
/// of the current response means a new query sits at the end of the output.
SnapshotChannel::InBuf::int_type SnapshotChannel::InBuf::underflow(void)

{
  if (gptr() < egptr())
    return traits_type::to_int_type(*gptr());
  owner->answerNext();
  if (gptr() >= egptr())
    return traits_type::eof();
  return traits_type::to_int_type(*gptr());
}

/// The pending query is the last QUERY_OPEN ... QUERY_CLOSE block of the output (a packed
/// payload has no zero bytes, so the last QUERY_OPEN is its start). It is cut from the output,
/// which then holds only what the client would read as the command response. A stored response
/// is read in place; a miss is recorded and answered with an exception, so the decompiler unwinds
/// exactly as for an exception thrown by the Java client. Never returns an empty response: the
/// ArchitectureGhidra readers exit the process at end of input.
void SnapshotChannel::answerNext(void)

{
  string &d(outbuf.data);
  size_t pos = d.rfind(QUERY_OPEN);
  bool ok = false;
  if (pos != string::npos && d.size() >= pos + 16 &&
      d.compare(pos + 4,4,STRING_OPEN) == 0 &&
      d.compare(d.size() - 8,4,STRING_CLOSE) == 0 &&
      d.compare(d.size() - 4,4,QUERY_CLOSE) == 0) {
    payload.assign(d,pos + 8,d.size() - pos - 16);
    d.resize(pos);
    ok = true;
  }
  if (!ok) {
    protocolError = true;
    inbuf.set(exceptionResponse("alignment","snapshot channel: read with no pending query"));
    return;
  }
  prepare(payload);
}

/// \param payload is the packed query payload
/// \return true when the response is a stored answer, false for a miss (an exception is fed)
bool SnapshotChannel::prepare(const string &payload)

{
  const string *resp = store->find(scope,payload,keybuf);
  if (resp != (const string *)0) {
    answered += 1;
    if (!resp->empty()) {
      inbuf.set(resp->data(),resp->size());
      return true;
    }
  }
  misses.push_back(payload);
  if (misses.size() <= MAX_SPECULATED && speculate(payload,inbuf.owned)) {
    fed.push_back(inbuf.owned);
    inbuf.set(inbuf.owned.data(),inbuf.owned.size());
    return false;
  }
  fed.push_back(string());
  inbuf.set(exceptionResponse(MISS_TYPE,"query not in the program snapshot"));
  return false;
}

/// \param payload is the packed query payload
/// \return the stored answer, or null when there is none
const string *SnapshotChannel::peek(const string &payload) const

{
  return store->find(scope,payload,keybuf);
}

/// The command element id of a packed query payload (PackedEncode::writeHeader), or -1
static int4 commandOf(const string &payload)

{
  if (payload.empty()) return -1;
  uint1 h = (uint1)payload[0];
  if ((h & 0xc0) != 0x40) return -1;		// Not an element start
  if ((h & 0x20) == 0) return h & 0x1f;
  if (payload.size() < 2) return -1;
  return ((h & 0x1f) << 7) | ((uint1)payload[1] & 0x7f);
}

/// A run with a miss is discarded, so a missed query whose answer is optional (no symbol, no
/// external reference, no comments, no label, name not used) gets that neutral answer and the
/// run goes on: it reports the other queries it misses in the same run, instead of one miss per
/// run. Other queries end the run with an exception, as before.
/// \param payload is the missed query
/// \param resp receives the neutral response
/// \return \b true if the query has one
bool SnapshotChannel::speculate(const string &payload,string &resp) const

{
  static const string EMPTY("\000\000\001\010\000\000\001\011",8);
  static const string EMPTY_STRING("\000\000\001\010\000\000\001\016\000\000\001\017\000\000\001\011",16);
  static const string FALSE_STRING("\000\000\001\010\000\000\001\016f\000\000\001\017\000\000\001\011",17);
  switch(commandOf(payload)) {
    case 249:			// COMMAND_GETMAPPEDSYMBOLS
      // DecompileCallback answers an address with no symbol with a one-byte hole
      if (spaces != (const AddrSpaceManager *)0) {
	try {
	  PackedDecode decoder(spaces);
	  istringstream s(payload);
	  decoder.ingestStream(s);
	  uint4 el = decoder.openElement(ELEM_COMMAND_GETMAPPEDSYMBOLS);
	  Address addr = Address::decode(decoder);
	  decoder.closeElement(el);
	  ostringstream o;
	  o.write("\000\000\001\010\000\000\001\016",8);
	  PackedEncode encoder(o);
	  encoder.openElement(ELEM_HOLE);
	  encoder.writeSpace(ATTRIB_SPACE,addr.getSpace());
	  encoder.writeUnsignedInteger(ATTRIB_FIRST,addr.getOffset());
	  encoder.writeUnsignedInteger(ATTRIB_LAST,addr.getOffset());
	  encoder.closeElement(ELEM_HOLE);
	  o.write("\000\000\001\017\000\000\001\011",8);
	  resp = o.str();
	  return true;
	}
	catch(LowlevelError &err) {
	}
	catch(DecoderError &err) {
	}
      }
      resp = EMPTY;
      return true;
    case 248:			// COMMAND_GETEXTERNALREF
    case 245:			// COMMAND_GETCOMMENTS
    case 247:			// COMMAND_GETDATATYPE (no such type)
    case 255:			// COMMAND_GETSTRINGDATA (no string)
      resp = EMPTY;
      return true;
    case 254:			// COMMAND_GETREGISTERNAME (no register)
    case 244:			// COMMAND_GETCODELABEL
      resp = EMPTY_STRING;
      return true;
    case 239:			// COMMAND_ISNAMEUSED
      resp = FALSE_STRING;
      return true;
    default:
      return false;
  }
}

SnapshotChannel::SnapshotChannel(const std::shared_ptr<SnapshotStore> &st)
  : store(st), sin(&inbuf), sout(&outbuf)

{
  inbuf.owner = this;
  protocolError = false;
  answered = 0;
  spaces = (const AddrSpaceManager *)0;
}

/// \param sc is the packed entry address of the function about to be decompiled, or empty
void SnapshotChannel::begin(const string &sc)

{
  scope = sc;
  outbuf.data.clear();
  inbuf.reset();
  misses.clear();
  fed.clear();
  protocolError = false;
  sin.clear();
  sout.clear();
}

// ---- native instruction translation ---------------------------------------------------------
//
// The host translates instructions itself with the decompiler's own Sleigh engine instead of
// asking Java for their p-code (DecompileSnapshot exports, per instruction, only the context
// register value; the store's decode table). The engine is the one decompile.exe uses for a
// standalone binary, over the generation's byte snapshot; its p-code is the p-code the Java
// translator produces for the same bytes and context, which the engine's validation mode
// (`hydra.decomp.host.decodeValidate`) checks answer by answer.
//
// One translator is kept per worker and .sla file (a language) and reset per generation: reset
// rebuilds only the parse caches, the parsed SLEIGH tables stay (a .sla parse is the expensive
// part and a worker sees only a few languages).

/// \brief P-code emitter that re-owns the varnode address spaces of the native translator
///
/// The worker's native Sleigh has its own AddrSpace objects (parsed from the .sla), while Funcdata
/// holds the architecture's (from the tspec). Before native decode is enabled the two managers are
/// checked to describe the same spaces in the same order, so a varnode's space is replaced by the
/// architecture's space with the same index as it passes through.
class SpaceMapEmit : public PcodeEmit {
  PcodeEmit *inner;				///< The decompiler's emitter
  const Architecture *arch;			///< Owner of the destination spaces
  VarnodeData vars[12];				///< Mapped inputs
  VarnodeData out;				///< Mapped output
  void map(VarnodeData &dst,const VarnodeData &src) const {
    dst = src;
    if (src.space != (AddrSpace *)0)
      dst.space = arch->getSpace(src.space->getIndex());
  }
public:
  SpaceMapEmit(PcodeEmit *i,const Architecture *a) : inner(i), arch(a) {}
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,
		    int4 isize) {
    if (isize > 12)
      throw LowlevelError("native decode: p-code op with too many inputs");
    for(int4 i=0;i<isize;++i)
      map(this->vars[i],vars[i]);
    if ((opc == CPUI_LOAD || opc == CPUI_STORE) && isize > 0) {
      // The first input of a load/store names the address space as a pointer to the translator's
      // space object (SleighBuilder::dump); re-own it in the architecture's manager, as
      // PcodeOpRaw::decode does for a Java answer.
      const VarnodeData &in(vars[0]);
      AddrSpace *spc = (AddrSpace *)(uintp)in.offset;
      if (in.space != (AddrSpace *)0 && in.space->getType() == IPTR_CONSTANT &&
	  spc != (AddrSpace *)0)
	this->vars[0].offset = (uintb)(uintp)arch->getSpace(spc->getIndex());
    }
    if (outvar != (VarnodeData *)0) {
      map(out,*outvar);
      inner->dump(addr,opc,&out,this->vars,isize);
    }
    else
      inner->dump(addr,opc,(VarnodeData *)0,this->vars,isize);
  }
};

/// One worker's native translator for one language.
struct WorkerSleigh {
  Sleigh *sleigh;				///< The translator (parsed .sla)
  ContextInternal *context;			///< Instruction context of the generation it serves
  const SnapshotStore *store;			///< The generation it currently serves, or null
  WorkerSleigh(void) : sleigh((Sleigh *)0), context((ContextInternal *)0),
		       store((const SnapshotStore *)0) {}
};

/// Parsed translators of the calling worker, one per .sla file. Thread-local: a Sleigh is
/// thread-affine (its parse caches are), and each worker decodes only its own jobs.
static thread_local std::map<string,WorkerSleigh> workerSleighs;
/// The translator of this thread the caller last prepared (`SnapshotArchitecture` this), so a
/// decompile that runs right after the previous one on the same architecture skips the reset.
static thread_local const SnapshotArchitecture *nativeOwner = (const SnapshotArchitecture *)0;

/// Loads a .sla file into a translator: the format Sleigh::initialize reads is a tag whose content
/// is the file path (as SleighArchitecture::buildSpecFile builds it).
/// \param sleigh is the translator
/// \param path is the .sla file
static void parseSla(Sleigh *sleigh,const string &path)

{
  DocumentStorage store;
  istringstream s("<sleigh>" + path + "</sleigh>");
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());
  sleigh->initialize(store);
}

/// The process-wide parse of one .sla file. The .sla decode (its symbol table and constructors) is
/// the bulk of a translator's set-up, and the result is immutable after `Sleigh::initialize`: the
/// SLEIGH compiler builds patterns and decision trees, the .sla decode only reads them. One engine
/// per language is parsed and kept here; every worker adopts its tables and pays only a copy of the
/// containers (a few milliseconds) instead of the decode (~120 ms for x86).
struct SlaParse {
  std::unique_ptr<Sleigh> engine;		///< The parsed engine (the owner of the shared tables)
  std::unique_ptr<ContextInternal> context;	///< Its own context database (never used to decode)
};

static std::mutex slaParseLock;
static std::map<string,std::unique_ptr<SlaParse> > slaParses;

/// The process-wide parse for a .sla file, decoded by the first caller; null when it cannot load.
/// The path is the .sla file
static SlaParse *slaParseFor(const string &path)

{
  std::lock_guard<std::mutex> guard(slaParseLock);
  std::map<string,std::unique_ptr<SlaParse> >::iterator iter = slaParses.find(path);
  if (iter != slaParses.end())
    return (*iter).second.get();
  std::unique_ptr<SlaParse> made(new SlaParse());
  made->context.reset(new ContextInternal());
  made->engine.reset(new Sleigh((LoadImage *)0,made->context.get()));
  parseSla(made->engine.get(),path);
  SlaParse *res = made.get();
  slaParses.emplace(path,std::move(made));
  return res;
}

/// The calling worker's translator for PATH, adopted from the process-wide parse of that .sla file;
/// null when it cannot be used.
/// The path is the .sla file
static WorkerSleigh *workerSleighFor(const string &path)

{
  std::map<string,WorkerSleigh>::iterator iter = workerSleighs.find(path);
  if (iter != workerSleighs.end())
    return &(*iter).second;
  WorkerSleigh &w(workerSleighs[path]);
  try {
    w.context = new ContextInternal();
    SlaParse *shared = slaParseFor(path);
    if (shared == (SlaParse *)0)
      throw LowlevelError("native decode: the .sla file did not parse");
    w.sleigh = new Sleigh((LoadImage *)0,w.context);
    w.sleigh->adoptParse(*shared->engine);
  }
  catch(std::exception &e) {
    delete w.sleigh;
    delete w.context;
    w.sleigh = (Sleigh *)0;
    w.context = (ContextInternal *)0;
    throw LowlevelError("native decode: " + string(e.what()));
  }
  return &w;
}

/// \brief GhidraTranslate whose instructions are decoded by the host when it has their context
class SnapshotTranslate : public GhidraTranslate {
  SnapshotArchitecture *arch;			///< The architecture (and its store)
public:
  SnapshotTranslate(SnapshotArchitecture *a) : GhidraTranslate(a), arch(a) {}
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const;
};

int4 SnapshotTranslate::oneInstruction(PcodeEmit &emit,const Address &baseaddr) const

{
  int4 len = arch->nativeDecode(emit,baseaddr);
  if (len >= 0)
    return len;
  return GhidraTranslate::oneInstruction(emit,baseaddr);
}

// ---- validation of the native translation (diagnostics) --------------------------------------

/// One p-code op in a form both the Java encoding and the native translator decode into.
struct RawOp {
  OpCode opc;			///< The opcode
  bool hasOut;			///< True when the op has an output varnode
  VarnodeData out;		///< The output
  int4 isize;			///< Number of inputs
  VarnodeData in[8];		///< The inputs
};

/// \brief Collects p-code ops instead of emitting them (validation mode)
class RecordEmit : public PcodeEmit {
public:
  vector<RawOp> ops;		///< The ops, in order
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize) {
    if (isize > 8)
      throw LowlevelError("validation: p-code op with more than 8 inputs");
    ops.emplace_back();
    RawOp &op(ops.back());
    op.opc = opc;
    op.hasOut = (outvar != (VarnodeData *)0);
    if (op.hasOut)
      op.out = *outvar;
    op.isize = isize;
    for(int4 i=0;i<isize;++i)
      op.in[i] = vars[i];
  }
};

/// \brief Replays recorded p-code ops into the decompiler (validation mode)
class ReplayEmit : public PcodeEmit {
  const vector<RawOp> &ops;	///< The ops to replay
public:
  ReplayEmit(const vector<RawOp> &o) : ops(o) {}
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize) {}
  void replay(PcodeEmit &inner,const Address &addr) {
    for(vector<RawOp>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      const RawOp &op(*iter);
      inner.dump(addr,op.opc,op.hasOut ? (VarnodeData *)&op.out : (VarnodeData *)0,
		 (VarnodeData *)op.in,op.isize);
    }
  }
};

SnapshotArchitecture::SnapshotArchitecture(const std::shared_ptr<SnapshotStore> &st)
  : SnapshotChannelHolder(st),
    ArchitectureGhidra(st->pspec,st->cspec,st->tspec,st->corespec,channel.sin,channel.sout)

{
  registered = false;
  native = (Sleigh *)0;
  nativePrepared = false;
  nativeFailed = false;
  nativeWords = 0;
}

SnapshotArchitecture::~SnapshotArchitecture(void)

{
  // The worker's translator is shared with the other generations of this thread and is reset
  // before its next use; nothing here owns it.
  native = (Sleigh *)0;
  nativePrepared = false;
}

/// The Ghidra translator: registers, spaces and disassembly information come from the tspec as
/// before. Only the p-code of an instruction the host has a native decode record for comes from
/// the worker's Sleigh (SnapshotTranslate::oneInstruction).
Translate *SnapshotArchitecture::buildTranslator(DocumentStorage &store)

{
  return new SnapshotTranslate(this);
}

/// \return true when this generation can be decoded natively
/// \Apply the generation's instruction context to a worker's context database.
/// The database keeps the variables the .sla registered; only the values are replaced.
/// \param ctx is the worker's context database
/// \param blob is the Java side's export (see SnapshotStore::putContext)
/// \param words receives the number of context words, or -1 when the blob is unusable
/// \return an empty string on success, else why the blob cannot be used
static string applyContext(SnapshotArchitecture *arch,ContextInternal *ctx,
			   const string &blob,int4 &words)

{
  size_t i = 0;
  auto read32 = [&](uint4 &v) -> bool {
    if (i + 4 > blob.size()) return false;
    v = (uint1)blob[i] | ((uint1)blob[i+1] << 8) | ((uint1)blob[i+2] << 16) | ((uint4)(uint1)blob[i+3] << 24);
    i += 4;
    return true;
  };
  auto read64 = [&](uintb &v) -> bool {
    if (i + 8 > blob.size()) return false;
    v = 0;
    for(int4 b=0;b<8;++b)
      v |= ((uintb)(uint1)blob[i+b]) << (8*b);
    i += 8;
    return true;
  };
  uint4 count;
  if (!read32(count) || count == 0 || count > 16)
    return "bad context export (size)";
  words = (int4)count;
  if (ctx->getContextSize() != (int4)count)
    return "the context export has " + std::to_string(count) + " words, the .sla needs " +
      std::to_string(ctx->getContextSize());
  ctx->clearValues();
  vector<uintm> def(count);
  for(uint4 w=0;w<count;++w) {
    uint4 v;
    if (!read32(v)) return "bad context export (default)";
    def[w] = v;
  }
  ctx->setDefaultValues(def.data(),(int4)count);
  uint4 ranges;
  if (!read32(ranges))
    return "bad context export (ranges)";
  string lastSpace;
  AddrSpace *spc = (AddrSpace *)0;
  for(uint4 r=0;r<ranges;++r) {
    uint4 namelen;
    if (!read32(namelen) || i + namelen > blob.size())
      return "bad context export (space)";
    string name(blob,i,namelen);
    i += namelen;
    uintb first,last;
    if (!read64(first) || !read64(last))
      return "bad context export (range)";
    if (name != lastSpace) {
      spc = arch->getSpaceByName(name);
      if (spc == (AddrSpace *)0)
	return "context export: unknown space " + name;
      lastSpace = name;
    }
    vector<uintm> value(count);
    for(uint4 w=0;w<count;++w) {
      uint4 v;
      if (!read32(v)) return "bad context export (value)";
      value[w] = v;
    }
    Address lo(spc,first);
    Address hi;
    if (last < spc->getHighest())
      hi = Address(spc,last + 1);
    else
      hi = Address();		// through the end of the space
    for(uint4 w=0;w<count;++w)
      ctx->setContextRegion(lo,hi,(int4)w,0xffffffff,value[w]);
  }
  return "";
}

bool SnapshotArchitecture::prepareNative(void)

{
  if (nativePrepared)
    return true;
  if (nativeFailed)
    return false;
  SnapshotStore &st(*channel.getStore());
  nativeFailed = true;		// until every check passed
  if (st.slaPath.empty()) {
    st.disableNative("no .sla file for the language");
    return false;
  }
  if (st.snapshotPath.empty() || dynamic_cast<LoadImageGhidra *>(loader) == (LoadImageGhidra *)0) {
    st.disableNative("no byte snapshot");
    return false;
  }
  if (st.getContext().empty()) {
    st.disableNative("no instruction context export");
    return false;
  }
  WorkerSleigh *w;
  try {
    w = workerSleighFor(st.slaPath);
  }
  catch(LowlevelError &err) {
    st.disableNative(err.explain);
    return false;
  }
  if (w == (WorkerSleigh *)0 || w->sleigh == (Sleigh *)0) {
    st.disableNative("the .sla file did not load");
    return false;
  }
  // The translator's varnodes carry its own address spaces; the decompiler's carry this
  // architecture's. They must be the same spaces in the same order for the remap by index.
  if (w->sleigh->numSpaces() > numSpaces()) {
    st.disableNative("the .sla and the translator spec disagree on the address spaces");
    return false;
  }
  for(int4 i=0;i<w->sleigh->numSpaces();++i) {
    if (w->sleigh->getSpace(i)->getName() != getSpace(i)->getName()) {
      st.disableNative("address space " + w->sleigh->getSpace(i)->getName() +
		       " is not space " + getSpace(i)->getName() + " of the translator spec");
      return false;
    }
  }
  // The instruction context of this generation (the program context register's values); the
  // worker's database keeps the variables the .sla registered and takes the generation's values.
  int4 words = 0;
  string bad = applyContext(this,w->context,st.getContext(),words);
  if (!bad.empty()) {
    st.disableNative(bad);
    return false;
  }
  w->sleigh->reset(loader,w->context);
  w->sleigh->buildCaches();
  native = w->sleigh;
  nativeWords = words;
  nativePrepared = true;
  nativeFailed = false;
  st.enableNative();
  return true;
}

/// \param addr is an instruction address
/// \param payload receives the packed query payload ArchitectureGhidra::getPcode would send
static void pcodeQuery(const Address &addr,string &payload)

{
  ostringstream s;
  {
    PackedEncode encoder(s);
    encoder.openElement(ELEM_COMMAND_GETPCODE);
    addr.encode(encoder);
    encoder.closeElement(ELEM_COMMAND_GETPCODE);
  }
  payload = s.str();
}

/// The stored Java answer to a p-code query, decoded into ops (validation mode).
/// \param arch is the architecture (space manager of the packed encoding)
/// \param ch is the channel (the store and the scope)
/// \param addr is the instruction address
/// \param ops receives the Java p-code ops
/// \param length receives the instruction length from the answer's \<inst> element
/// \return true when the store holds a readable p-code answer
static bool javaPcode(SnapshotArchitecture *arch,SnapshotChannel &ch,const Address &addr,
		      vector<RawOp> &ops,int4 &length)

{
  string payload;
  pcodeQuery(addr,payload);
  const string *resp = ch.peek(payload);
  if (resp == (const string *)0 || resp->empty())
    return false;
  if (resp->size() < 8 || resp->compare(0,4,RESPONSE_OPEN) != 0)
    return false;			// an exception record: nothing to compare
  size_t pos = 4;
  if (resp->compare(pos,4,RESPONSE_CLOSE) == 0)
    return false;			// an empty answer: no p-code
  if (resp->compare(pos,4,STRING_OPEN) != 0)
    return false;
  pos += 4;
  size_t end = resp->find(STRING_CLOSE,pos);
  if (end == string::npos || end + 8 > resp->size())
    return false;
  istringstream s(resp->substr(pos,end - pos));
  PackedDecode decoder(arch);
  try {
    decoder.ingestStream(s);
    int4 el = decoder.openElement();
    length = decoder.readSignedInteger(ATTRIB_OFFSET);
    if (el == ELEM_UNIMPL)
      return false;
    Address pc = Address::decode(decoder);
    RecordEmit record;
    while(decoder.peekElement() != 0)
      record.decodeOp(pc,decoder);
    ops = record.ops;
    return true;
  }
  catch(DecoderError &err) {
    return false;
  }
  catch(LowlevelError &err) {
    return false;
  }
}

/// \return true when the two op lists are the same instruction's p-code (spaces by index)
static bool sameOps(const vector<RawOp> &a,const vector<RawOp> &b)

{
  if (a.size() != b.size())
    return false;
  for(size_t i=0;i<a.size();++i) {
    const RawOp &x(a[i]);
    const RawOp &y(b[i]);
    if (x.opc != y.opc || x.hasOut != y.hasOut || x.isize != y.isize)
      return false;
    if (x.hasOut) {
      if (x.out.size != y.out.size || x.out.offset != y.out.offset)
	return false;
      if ((x.out.space == (AddrSpace *)0) != (y.out.space == (AddrSpace *)0))
	return false;
      if (x.out.space != (AddrSpace *)0 && x.out.space->getIndex() != y.out.space->getIndex())
	return false;
    }
    for(int4 j=0;j<x.isize;++j) {
      if ((x.opc == CPUI_LOAD || x.opc == CPUI_STORE) && j == 0) {
	// The load/store space operand is a space pointer: compare the space, not the object address.
	AddrSpace *xs = (AddrSpace *)(uintp)x.in[0].offset;
	AddrSpace *ys = (AddrSpace *)(uintp)y.in[0].offset;
	if ((xs == (AddrSpace *)0) != (ys == (AddrSpace *)0))
	  return false;
	if (xs != (AddrSpace *)0 && xs->getIndex() != ys->getIndex())
	  return false;
	continue;
      }
      if (x.in[j].size != y.in[j].size || x.in[j].offset != y.in[j].offset)
	return false;
      if ((x.in[j].space == (AddrSpace *)0) != (y.in[j].space == (AddrSpace *)0))
	return false;
      if (x.in[j].space != (AddrSpace *)0 && x.in[j].space->getIndex() != y.in[j].space->getIndex())
	return false;
    }
  }
  return true;
}

/// \param emit is the decompiler's p-code emitter
/// \param addr is the instruction address
/// \return the instruction length, or -1 when the host has no decode record for the address (the
/// caller then asks the store for the Java answer)
int4 SnapshotArchitecture::nativeDecode(PcodeEmit &emit,const Address &addr)

{
  if (!nativePrepared)
    return -1;
  SnapshotStore &st(*channel.getStore());
  if (!st.hasDecode(addr.getSpace()->getName(),addr.getOffset()))
    return -1;
  try {
    if (!VALIDATE_NATIVE) {
      SpaceMapEmit mapped(&emit,this);
      return native->oneInstruction(mapped,addr);
    }
    // Validation (diagnostics): decode natively and compare with the Java answer; a mismatch is
    // counted and the Java p-code is used, so the output stays the process path's.
    RecordEmit record;
    int4 len = native->oneInstruction(record,addr);
    vector<RawOp> javaOps;
    int4 javaLen = -1;
    bool haveJava = javaPcode(this,channel,addr,javaOps,javaLen);
    st.countValidated();
    bool same = haveJava && javaLen == len && sameOps(record.ops,javaOps);
    if (haveJava && !same) {
      st.countMismatch();
      if (mismatchLogs() < 20) {
	std::ostringstream msg;
	msg << "native decode mismatch at " << addr.getShortcut() << ": native " << record.ops.size()
	    << " ops, len " << len << "; java " << javaOps.size() << " ops, len " << javaLen;
	string text(msg.str());
	fprintf(stderr,"%s\n",text.c_str());
      }
    }
    const vector<RawOp> &use(same || !haveJava ? record.ops : javaOps);
    SpaceMapEmit mapped(&emit,this);
    for(vector<RawOp>::const_iterator iter=use.begin();iter!=use.end();++iter) {
      const RawOp &op(*iter);
      mapped.dump(addr,op.opc,op.hasOut ? (VarnodeData *)&op.out : (VarnodeData *)0,
		  (VarnodeData *)op.in,op.isize);
    }
    return same || !haveJava ? len : javaLen;
  }
  catch(UnimplError &err) {
    throw;			// the decompiler handles an unimplemented instruction as before
  }
  catch(std::exception &err) {
    // Never fail the request on a native decode the Java answer can serve: the query becomes a
    // miss and the Java side exports the p-code (the run is then repeated).
    st.nativeError(err.what());
    nativePrepared = false;
    return -1;
  }
}

/// \param addr is the instruction address
/// \return true when the store holds the answer (or a miss exception is ready on the input stream)
bool SnapshotArchitecture::preparePcode(const Address &addr)

{
  pcodeQuery(addr,payload);
  return channel.prepare(payload);
}

/// The registerProgram command (RegisterProgram::rawAction: init from the spec strings), then
/// what DecompInterface sends after it: the byte snapshot (setSnapshot) and the options
/// (setOptions). The session's decompilers use the default action ("decompile", syntax tree
/// and C code on), so no setAction follows.
/// \return an empty string on success, else the error the process would report
string SnapshotArchitecture::registerHost(void)

{
  const SnapshotStore &st(*channel.getStore());
  channel.begin("");
  try {
    DocumentStorage docs;
    init(docs);
  }
  catch(DecoderError &err) {
    return "Marshaling error: " + err.explain;
  }
  catch(JavaError &err) {
    return "Java exception " + err.type + ": " + err.explain;
  }
  catch(RecovError &err) {
    return "Recoverable Error: " + err.explain;
  }
  catch(LowlevelError &err) {
    return "Low-level Error: " + err.explain;
  }
  if (!channel.getMisses().empty())
    return "missed queries";
  if (!st.snapshotPath.empty()) {
    LoadImageGhidra *image = dynamic_cast<LoadImageGhidra *>(loader);
    if (image != (LoadImageGhidra *)0) {
      try {
	image->setSnapshot(st.snapshotPath);
      }
      catch(LowlevelError &err) {
	// No byte snapshot: byte requests are answered from the store like any query
      }
    }
  }
  if (!st.options.empty()) {
    try {
      PackedDecode decoder(this);
      istringstream s(st.options);
      decoder.ingestStream(s);
      resetDefaults();
      options->decode(decoder);
    }
    catch(DecoderError &err) {
      return "Marshaling error: " + err.explain;
    }
    catch(LowlevelError &err) {
      return "Low-level Error: " + err.explain;
    }
  }
  if (!channel.getMisses().empty())
    return "missed queries";
  // DecompInterface.toggleSyntaxTree(false): the session's pooled decompilers are text-only
  // (ProgramEntry.DECOMPILER_SYNTAX_TREE = false), so the command that would send a syntax tree
  // and high variables is off here too. Sending it would encode, copy through the store and decode
  // in Java a tree that this path never reads, only to throw it away; the C markup is identical.
  setSendSyntaxTree(false);
  // Parse the language's .sla (once per worker and language) and check that its address spaces are
  // the ones of the translator spec, so the first decompile of this generation does not pay it.
  prepareNative();
  registered = true;
  channel.setSpaces(this);
  return "";
}

/// GhidraCommand::doit around DecompileAt::loadParameters / rawAction / sendResult, writing the
/// command response to the channel output exactly as decompile.exe writes it to its pipe.
/// \param addrBytes is the packed entry address (the decompileAt parameter)
void SnapshotArchitecture::decompileAt(const string &addrBytes)

{
  channel.begin(addrBytes);
  prepareNative();		// the worker's translator serves this generation for this run
  ostream &out(channel.sout);
  out.write("\000\000\001\006",4);		// Command response header
  string errorMsg;
  try {
    PackedDecode decoder(this);
    istringstream s(addrBytes);
    decoder.ingestStream(s);
    Address addr = Address::decode(decoder);

    Funcdata *fd = symboltab->getGlobalScope()->queryFunction(addr);
    if (fd == (Funcdata *)0) {
      ostringstream s2;
      s2 << "Bad decompile address: " << addr.getShortcut();
      addr.printRaw(s2);
      s2 << "\n";
      s2 << addr.getSpace()->getName() << " may not be a global space in the spec file.";
      throw LowlevelError(s2.str());
    }
    if (!fd->isProcStarted()) {
      allacts.getCurrent()->reset( *fd );
      allacts.getCurrent()->perform( *fd );
    }

    out.write("\000\000\001\016",4);

    if (fd->isProcComplete()) {
      PackedEncode encoder(out);
      encoder.openElement(ELEM_DOC);
      if (getSendParamMeasures() && (allacts.getCurrentName() == "paramid")) {
	ParamIDAnalysis pidanalysis( fd, true ); // Only send back final prototype
	pidanalysis.encode( encoder, true );
      }
      else {
	if (getSendParamMeasures()) {
	  ParamIDAnalysis pidanalysis( fd, false );
	  pidanalysis.encode( encoder, true );
	}
	fd->encode(encoder,0,getSendSyntaxTree(),false);
	if (getSendCCode()&&
	    (allacts.getCurrentName() == "decompile"))
	  print->docFunction(fd);
      }
      encoder.closeElement(ELEM_DOC);
    }
    out.write("\000\000\001\017",4);
  }
  catch(DecoderError &err) {
    errorMsg = "Marshaling error: " + err.explain;
  }
  catch(JavaError &err) {
    ArchitectureGhidra::passJavaException(out,err.type,err.explain);
    return;			// Abort sending any results
  }
  catch(RecovError &err) {
    errorMsg = "Recoverable Error: " + err.explain;
  }
  catch(LowlevelError &err) {
    errorMsg = "Low-level Error: " + err.explain;
  }
  out.write("\000\000\001\020",4);		// GhidraCommand::sendResult
  out << errorMsg;
  out.write("\000\000\001\021",4);
  out.write("\000\000\001\007",4);		// Command response closer
  out.flush();
}

/// FlushNative::rawAction: DecompInterface sends flushNative after every decompile, so each
/// function starts from the same (empty) symbol, type, comment and string caches.
void SnapshotArchitecture::flushNative(void)

{
  Scope *globscope = symboltab->getGlobalScope();
  globscope->clear();		// Clear symbols first as this may delete scopes
  symboltab->deleteSubScopes(globscope); // Flush cached function and globals database
  types->clearNoncore(); // Reset type information
  commentdb->clear();	// Clear any comments
  stringManager->clear();	// Clear string decodings
  cpool->clear();
}

/// The library is started once per process, by whichever entry (console scripts or snapshot
/// backend) comes first; a console start later only adds the Sleigh search paths.
/// \param root is the Ghidra root for Sleigh specs (console scripts), or null
/// \param err receives the reason of a failure
/// \return \b true on success
bool hydraLibraryStart(const char *root,string &err)

{
  static std::mutex startLock;
  static bool started = false;
  static string rootSeen;
  std::lock_guard<std::mutex> guard(startLock);
  try {
    if (!started) {
      startDecompilerLibrary((const char *)0);
      started = true;
    }
    if (root != (const char *)0 && rootSeen.empty()) {
      SleighArchitecture::scanForSleighDirectories(root);
      rootSeen = root;
    }
    return true;
  }
  catch(LowlevelError &e) {
    err = e.explain;
  }
  catch(std::exception &e) {
    err = e.what();
  }
  catch(...) {
    err = "unknown exception";
  }
  return false;
}

/// \brief One Architecture held by a worker for one generation
struct WorkerArch {
  std::shared_ptr<SnapshotStore> store;		///< The generation (keeps the answers alive)
  SnapshotArchitecture *arch;			///< Built and used by this worker only
};

/// Architectures a worker keeps (most recently used first). 4 generations per worker by default.
static thread_local std::list<WorkerArch> workerArchs;

static size_t maxArchsPerWorker(void)

{
  static size_t value = 0;
  if (value == 0) {
    const char *v = getenv("HYDRA_SNAPSHOT_ARCHS");
    long n = (v == (const char *)0) ? 0 : strtol(v,(char **)0,10);
    value = (n > 0 && n < 1000) ? (size_t)n : 4;
  }
  return value;
}

static void dropArch(WorkerArch &w)

{
  delete w.arch;
  w.arch = (SnapshotArchitecture *)0;
  w.store.reset();
}

/// \brief Inputs and outputs of one decompile job (plain data, so the SEH guard holds no C++ objects)
struct SnapshotJob {
  std::shared_ptr<SnapshotStore> *handle;	///< The client's handle
  const char *addr;				///< Packed entry address
  size_t addrlen;				///< Its length
  char *out;					///< Command response or failure message (malloc)
  size_t outlen;				///< Its length
  char *misses;					///< Missed queries: u32 little-endian length + payload, repeated (malloc)
  size_t misseslen;				///< Its length
  uint8 answered;				///< Queries answered from the store
};

static char *copyOut(const string &s,size_t *len)

{
  char *p = (char *)malloc(s.size() + 1);
  if (p == (char *)0) {
    *len = 0;
    return p;
  }
  memcpy(p,s.data(),s.size());
  p[s.size()] = 0;
  *len = s.size();
  return p;
}

static void appendRecord(string &res,const string &rec)

{
  uint4 n = (uint4)rec.size();
  for(int4 b=0;b<4;++b)
    res += (char)((n >> (8*b)) & 0xff);
  res += rec;
}

/// The misses buffer: for each miss, the query payload, then the answer fed for it (empty if an
/// exception ended the run there), each as u32 little-endian length + bytes
static void setMisses(SnapshotJob *job,const SnapshotChannel &ch)

{
  string res;
  const vector<string> &misses(ch.getMisses());
  const vector<string> &fed(ch.getFed());
  for(size_t i=0;i<misses.size();++i) {
    appendRecord(res,misses[i]);
    appendRecord(res,i < fed.size() ? fed[i] : string());
  }
  job->misses = copyOut(res,&job->misseslen);
}

/// Runs one job on the calling worker: find or build this worker's Architecture for the store,
/// decompile, flush. Every C++ exception is caught here.
static int runJob(SnapshotJob *job)

{
  try {
    std::shared_ptr<SnapshotStore> st(*job->handle);
    // Drop Architectures of generations the client released
    for(std::list<WorkerArch>::iterator iter=workerArchs.begin();iter!=workerArchs.end();) {
      if ((*iter).store->closed && (*iter).store != st) {
	dropArch(*iter);
	iter = workerArchs.erase(iter);
      }
      else
	++iter;
    }
    std::list<WorkerArch>::iterator cur = workerArchs.end();
    for(std::list<WorkerArch>::iterator iter=workerArchs.begin();iter!=workerArchs.end();++iter) {
      if ((*iter).store->id == st->id) {
	cur = iter;
	break;
      }
    }
    if (cur == workerArchs.end()) {
      while(workerArchs.size() >= maxArchsPerWorker()) {
	dropArch(workerArchs.back());
	workerArchs.pop_back();
      }
      WorkerArch w;
      w.store = st;
      w.arch = new SnapshotArchitecture(st);
      string err = w.arch->registerHost();
      SnapshotChannel &ch(w.arch->getChannel());
      job->answered += ch.getAnswered();
      if (!ch.getMisses().empty()) {
	setMisses(job,ch);
	dropArch(w);
	return SNAPSHOT_MISSES;
      }
      if (!err.empty() || ch.hadProtocolError()) {
	job->out = copyOut(err.empty() ? string("snapshot channel protocol error") : err,&job->outlen);
	dropArch(w);
	return SNAPSHOT_FAILED;
      }
      workerArchs.push_front(w);
    }
    else if (cur != workerArchs.begin())
      workerArchs.splice(workerArchs.begin(),workerArchs,cur);
    WorkerArch &w(workerArchs.front());
    SnapshotChannel &ch(w.arch->getChannel());
    uint8 before = ch.getAnswered();
    w.arch->decompileAt(string(job->addr,job->addrlen));
    job->answered += ch.getAnswered() - before;
    bool protocolError = ch.hadProtocolError();
    bool missed = !ch.getMisses().empty();
    if (missed)
      setMisses(job,ch);
    string out;
    out.swap(ch.output());
    try {
      w.arch->flushNative();
    }
    catch(...) {
      dropArch(w);
      workerArchs.pop_front();
    }
    if (missed) {
      // The output goes back too: when every miss got a neutral answer (speculate) and the
      // client's real answers are those same bytes, the run saw what the process path sees
      if (!protocolError)
	job->out = copyOut(out,&job->outlen);
      return SNAPSHOT_MISSES;
    }
    if (protocolError) {
      job->out = copyOut("snapshot channel protocol error",&job->outlen);
      return SNAPSHOT_FAILED;
    }
    job->out = copyOut(out,&job->outlen);
    return SNAPSHOT_OK;
  }
  catch(LowlevelError &e) {
    job->out = copyOut("host: " + e.explain,&job->outlen);
  }
  catch(std::exception &e) {
    job->out = copyOut(string("host: ") + e.what(),&job->outlen);
  }
  catch(...) {
    job->out = copyOut("host: unknown exception",&job->outlen);
  }
  return SNAPSHOT_FAILED;
}

} // End namespace ghidra

using namespace ghidra;

/// Called by the SEH guard (snapshot_seh.cc); not part of the C ABI
extern "C" int hydra_snapshot_run_job(void *job)

{
  return runJob((SnapshotJob *)job);
}

/// After a hardware exception the worker's Architectures may be corrupt: they are leaked, not
/// destroyed, and the worker starts over with none.
extern "C" void hydra_snapshot_poison_thread(void)

{
  for(std::list<WorkerArch>::iterator iter=workerArchs.begin();iter!=workerArchs.end();++iter)
    (*iter).arch = (SnapshotArchitecture *)0;
  workerArchs.clear();
}

extern "C" int hydra_snapshot_guarded(void *job);	// snapshot_seh.cc

extern "C" int hydra_snapshot_start(void)

{
  string err;
  return hydraLibraryStart((const char *)0,err) ? 0 : 1;
}

extern "C" void *hydra_snapshot_store_new(const char *pspec,size_t pspeclen,const char *cspec,size_t cspeclen,
					  const char *tspec,size_t tspeclen,const char *core,size_t corelen,
					  const char *opt,size_t optlen,const char *snap,size_t snaplen,
					  const char *sla,size_t slalen)

{
  static std::atomic<uint8> nextId(1);
  try {
    std::shared_ptr<SnapshotStore> st(new SnapshotStore(nextId++,string(pspec,pspeclen),string(cspec,cspeclen),
							string(tspec,tspeclen),string(core,corelen),
							string(opt,optlen),string(snap,snaplen),
							string(sla,slalen)));
    return new std::shared_ptr<SnapshotStore>(st);
  }
  catch(...) {
    return (void *)0;
  }
}

extern "C" int hydra_snapshot_store_put(void *h,const char *scope,size_t scopelen,const char *query,size_t querylen,
					const char *resp,size_t resplen)

{
  try {
    std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
    st->put(string(scope,scopelen),string(query,querylen),string(resp,resplen));
    return 0;
  }
  catch(...) {
    return 1;
  }
}

extern "C" int hydra_snapshot_store_put_bulk(void *h,const char *blob,size_t len)

{
  try {
    std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
    st->putBulk(blob,len);
    return 0;
  }
  catch(...) {
    return 1;
  }
}

extern "C" int hydra_snapshot_store_put_decode(void *h,const char *blob,size_t len)

{
  try {
    std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
    st->putDecode(blob,len);
    return 0;
  }
  catch(...) {
    return 1;
  }
}

extern "C" int hydra_snapshot_store_put_context(void *h,const char *blob,size_t len)

{
  try {
    std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
    st->putContext(blob,len);
    return 0;
  }
  catch(...) {
    return 1;
  }
}

extern "C" int hydra_snapshot_store_native(void *h,char **msg,size_t *msglen)

{
  std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
  string why;
  int4 state = st->getNativeState(why);
  *msg = (char *)0;
  *msglen = 0;
  if (state < 0 && !why.empty()) {
    char *p = (char *)malloc(why.size() + 1);
    if (p != (char *)0) {
      memcpy(p,why.data(),why.size());
      p[why.size()] = 0;
      *msg = p;
      *msglen = why.size();
    }
  }
  return state;
}

extern "C" void hydra_snapshot_set_validate(int on)

{
  VALIDATE_NATIVE = on != 0;
}

extern "C" void hydra_snapshot_store_validate(void *h,uint64_t *checked,uint64_t *mismatched)

{
  std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
  *checked = st->getValidated();
  *mismatched = st->getMismatches();
}

/// Parses the given .sla files on the calling (worker) thread, so no decompile pays the parse.
/// \param paths is the '\0'-separated file list
/// \param len is its size in bytes
/// \return 0 on success, 1 when a file did not load
extern "C" int hydra_snapshot_warm(const char *paths,size_t len)

{
  size_t i = 0;
  int4 res = 0;
  while (i < len) {
    size_t end = i;
    while (end < len && paths[end] != 0)
      ++end;
    if (end > i) {
      try {
	workerSleighFor(string(paths + i,end - i));
      }
      catch(...) {
	res = 1;
      }
    }
    i = end + 1;
  }
  return res;
}

extern "C" void hydra_snapshot_store_stats(void *h,uint64_t *count,uint64_t *bytes)

{
  std::shared_ptr<SnapshotStore> &st(*(std::shared_ptr<SnapshotStore> *)h);
  *count = st->count();
  *bytes = st->size();
}

extern "C" void hydra_snapshot_store_close(void *h)

{
  std::shared_ptr<SnapshotStore> *st = (std::shared_ptr<SnapshotStore> *)h;
  (*st)->closed = true;
  delete st;
}

extern "C" int hydra_snapshot_decompile(void *h,const char *addr,size_t addrlen,char **out,size_t *outlen,
					char **misses,size_t *misseslen,uint64_t *answered)

{
  SnapshotJob job;
  job.handle = (std::shared_ptr<SnapshotStore> *)h;
  job.addr = addr;
  job.addrlen = addrlen;
  job.out = (char *)0;
  job.outlen = 0;
  job.misses = (char *)0;
  job.misseslen = 0;
  job.answered = 0;
  int rc = hydra_snapshot_guarded(&job);
  if (rc == SNAPSHOT_CRASHED) {
    hydra_snapshot_poison_thread();
    free(job.out);
    free(job.misses);
    job.out = copyOut("host: hardware exception in the decompiler; this worker's Architectures were dropped",
		      &job.outlen);
    job.misses = (char *)0;
    job.misseslen = 0;
  }
  *out = job.out;
  *outlen = job.outlen;
  *misses = job.misses;
  *misseslen = job.misseslen;
  *answered = job.answered;
  return rc;
}

extern "C" void hydra_snapshot_free(char *p)

{
  free(p);
}

extern "C" void hydra_snapshot_release_thread(void)

{
  for(std::list<WorkerArch>::iterator iter=workerArchs.begin();iter!=workerArchs.end();++iter)
    dropArch(*iter);
  workerArchs.clear();
}
