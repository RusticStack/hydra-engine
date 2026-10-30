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

#include <cstdlib>
#include <cstring>
#include <list>
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

SnapshotStore::SnapshotStore(uint8 i,const string &p,const string &c,const string &t,const string &core,
			     const string &opt,const string &snap)
  : id(i), pspec(p), cspec(c), tspec(t), corespec(core), options(opt), snapshotPath(snap)

{
  bytes = 0;
  closed = false;
}

/// An answer that is already present is kept (answers of one generation never change).
/// \param scope is the packed entry address of the function the answer depends on, or empty
/// \param query is the packed query payload
/// \param response is the complete response
void SnapshotStore::put(const string &scope,const string &query,const string &response)

{
  std::unique_lock<std::shared_mutex> guard(lock);
  bool added;
  if (scope.empty())
    added = global.emplace(query,response).second;
  else {
    string key(scope);
    key += '\0';
    key += query;
    added = scoped.emplace(key,response).second;
  }
  if (added)
    bytes += scope.size() + query.size() + response.size();
}

/// A scoped answer for the given scope wins over a global one.
/// \param scope is the scope of the current decompile (may be empty)
/// \param query is the packed query payload
/// \param response receives the stored response
/// \return \b true if the store holds an answer
bool SnapshotStore::find(const string &scope,const string &query,string &response) const

{
  std::shared_lock<std::shared_mutex> guard(lock);
  if (!scope.empty() && !scoped.empty()) {
    string key(scope);
    key += '\0';
    key += query;
    unordered_map<string,string>::const_iterator iter = scoped.find(key);
    if (iter != scoped.end()) {
      response = (*iter).second;
      return true;
    }
  }
  unordered_map<string,string>::const_iterator iter = global.find(query);
  if (iter == global.end())
    return false;
  response = (*iter).second;
  return true;
}

uint8 SnapshotStore::count(void) const

{
  std::shared_lock<std::shared_mutex> guard(lock);
  return global.size() + scoped.size();
}

uint8 SnapshotStore::size(void) const

{
  std::shared_lock<std::shared_mutex> guard(lock);
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
  char *b = &cur[0];
  setg(b,b,b + cur.size());
  return traits_type::to_int_type(*gptr());
}

/// The pending query is the last QUERY_OPEN ... QUERY_CLOSE block of the output (a packed
/// payload has no zero bytes, so the last QUERY_OPEN is its start). It is cut from the output,
/// which then holds only what the client would read as the command response. A stored response
/// is fed back as is; a miss is recorded and answered with an exception, so the decompiler unwinds
/// exactly as for an exception thrown by the Java client. Never returns an empty response: the
/// ArchitectureGhidra readers exit the process at end of input.
void SnapshotChannel::answerNext(void)

{
  string &d(outbuf.data);
  size_t pos = d.rfind(QUERY_OPEN);
  bool ok = false;
  string payload;
  if (pos != string::npos && d.size() >= pos + 16 &&
      d.compare(pos + 4,4,STRING_OPEN) == 0 &&
      d.compare(d.size() - 8,4,STRING_CLOSE) == 0 &&
      d.compare(d.size() - 4,4,QUERY_CLOSE) == 0) {
    payload = d.substr(pos + 8,d.size() - pos - 16);
    d.resize(pos);
    ok = true;
  }
  if (!ok) {
    protocolError = true;
    inbuf.cur = exceptionResponse("alignment","snapshot channel: read with no pending query");
    return;
  }
  if (store->find(scope,payload,inbuf.cur)) {
    answered += 1;
    if (!inbuf.cur.empty())
      return;
  }
  misses.push_back(payload);
  if (misses.size() <= MAX_SPECULATED && speculate(payload,inbuf.cur)) {
    fed.push_back(inbuf.cur);
    return;
  }
  fed.push_back(string());
  inbuf.cur = exceptionResponse(MISS_TYPE,"query not in the program snapshot");
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

SnapshotArchitecture::SnapshotArchitecture(const std::shared_ptr<SnapshotStore> &st)
  : SnapshotChannelHolder(st),
    ArchitectureGhidra(st->pspec,st->cspec,st->tspec,st->corespec,channel.sin,channel.sout)

{
  registered = false;
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
					  const char *opt,size_t optlen,const char *snap,size_t snaplen)

{
  static std::atomic<uint8> nextId(1);
  try {
    std::shared_ptr<SnapshotStore> st(new SnapshotStore(nextId++,string(pspec,pspeclen),string(cspec,cspeclen),
							string(tspec,tspeclen),string(core,corelen),
							string(opt,optlen),string(snap,snaplen)));
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
