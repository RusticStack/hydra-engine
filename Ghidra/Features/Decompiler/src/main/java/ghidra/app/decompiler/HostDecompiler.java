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
package ghidra.app.decompiler;

import static java.lang.foreign.ValueLayout.*;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;

/**
 * Hydra: the callback-free decompile backend (plan rank 12;
 * {@code Decompiler/rust/crates/hydra-decomp-host/DESIGN.md}, step 6).
 *
 * <p>Decompiles a function in the {@code hydra_decomp_host} library's worker pool: N C++
 * {@code SnapshotArchitecture}s (the stock {@code ArchitectureGhidra} with its client streams
 * answered from a store), one per worker and program generation, called through FFM with plain
 * downcalls. The store of a generation holds the registerProgram strings, the options, the byte
 * snapshot file ({@link ProgramSnapshotFile}, format v1) and the answers of
 * {@link DecompileSnapshot} (format v2), each exported once per generation:
 * <ul>
 * <li>before the first decompile of a function, the answers its decompile asks for that the
 * program database names: the p-code of every instruction of its body, its own symbol, the
 * symbols of everything its body references, its tracked registers;</li>
 * <li>once per generation: the registration answers (user-op names) and every register by name;</li>
 * <li>a query the store does not hold yet is a <em>miss</em>: the native run is discarded, the
 * missed answers are exported and the decompile runs again (at most {@link #MAX_ROUNDS} runs).
 * A miss whose answer is optional (symbol, external reference, comments, code label, data type,
 * string, register name, name-in-use; for a symbol, the one-byte hole the client gives for an
 * address with no symbol) gets that neutral answer and the run goes on, so one run reports all of
 * those misses instead of one. The host returns the answers it fed: when each is, byte for byte,
 * the real answer, the run saw what the process path sees and its result is used as is;</li>
 * <li>the comment filter of the options is learned from the first getComments miss and
 * prefetched for every later function.</li>
 * </ul>
 * Nothing calls back into Java while the decompiler runs. Any case that is not covered (see
 * {@link #decompile}) returns a fallback and the caller uses {@link DecompInterface}; a hosted
 * result is the one the process path returns for the same answers, because the native components
 * and the answers are the same.
 */
public final class HostDecompiler {

	/** File of the host library, overriding the one found in the Decompiler module. */
	public static final String LIBRARY_PROPERTY = "hydra.decomp.host.library";
	/** Worker threads of the host pool (default: the CPUs the OS grants the process). */
	public static final String THREADS_PROPERTY = "hydra.decomp.host.threads";
	/** Native runs per decompile before falling back (property; default {@link #DEFAULT_ROUNDS}). */
	public static final String ROUNDS_PROPERTY = "hydra.decomp.host.rounds";
	/**
	 * A run stops at its first miss, so each run but the last learns one answer; answers are kept
	 * for the generation, so later functions need fewer runs.
	 */
	public static final int DEFAULT_ROUNDS = 12;
	/** Native runs per decompile before falling back (each but the last learns its misses). */
	public static final int MAX_ROUNDS = Math.max(1, Integer.getInteger(ROUNDS_PROPERTY, DEFAULT_ROUNDS));

	private static final int ABI_VERSION = 3;
	private static final int OK = 0;
	private static final int MISSES = 1;

	/**
	 * The outcome of a host decompile.
	 * @param results the results (non-null when hosted)
	 * @param fallback why the process path must decompile instead (non-null when not hosted)
	 */
	public record Outcome(DecompileResults results, String fallback) {
		static Outcome fallback(String why) {
			return new Outcome(null, why);
		}
	}

	private static final LongAdder HOSTED = new LongAdder();
	private static final LongAdder FALLBACKS = new LongAdder();
	private static final LongAdder ROUNDS = new LongAdder();
	private static final LongAdder EXACT_RUNS = new LongAdder();
	/** Diagnostics: log the first missed queries (property {@code hydra.decomp.host.traceMisses}). */
	private static final boolean TRACE_MISSES = Boolean.getBoolean("hydra.decomp.host.traceMisses");
	private static final AtomicLong TRACED = new AtomicLong();
	private static final LongAdder MISSES_LEARNED = new LongAdder();
	private static final LongAdder PREFETCHED = new LongAdder();
	private static final LongAdder ANSWERED = new LongAdder();
	private static final LongAdder NATIVE_NANOS = new LongAdder();
	private static final LongAdder EXPORT_NANOS = new LongAdder();
	private static final Map<String, LongAdder> REASONS = new ConcurrentHashMap<>();
	/** Missed queries by command element id ("again": the store already held the answer). */
	private static final Map<String, LongAdder> MISS_KINDS = new ConcurrentHashMap<>();

	private HostDecompiler() {
	}

	// ---- the native library -------------------------------------------------------------------

	private static final class Lib {
		final MethodHandle storeNew;
		final MethodHandle storePut;
		final MethodHandle storeStats;
		final MethodHandle storeClose;
		final MethodHandle decompile;
		final MethodHandle free;
		final int threads;
		final ExecutorService calls;

		Lib(SymbolLookup lookup, int threads) {
			Linker l = Linker.nativeLinker();
			storeNew = l.downcallHandle(lookup.findOrThrow("hydra_dhost_store_new"),
				FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS,
					JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
			storePut = l.downcallHandle(lookup.findOrThrow("hydra_dhost_store_put"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
					ADDRESS, JAVA_LONG));
			storeStats = l.downcallHandle(lookup.findOrThrow("hydra_dhost_store_stats"),
				FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS));
			storeClose = l.downcallHandle(lookup.findOrThrow("hydra_dhost_store_close"),
				FunctionDescriptor.ofVoid(ADDRESS));
			decompile = l.downcallHandle(lookup.findOrThrow("hydra_dhost_decompile"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS,
					ADDRESS, ADDRESS, ADDRESS));
			free = l.downcallHandle(lookup.findOrThrow("hydra_dhost_free"),
				FunctionDescriptor.ofVoid(ADDRESS));
			submit = l.downcallHandle(lookup.findOrThrow("hydra_dhost_submit"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, JAVA_LONG));
			completions = l.downcallHandle(lookup.findOrThrow("hydra_dhost_completions"),
				FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_LONG));
			this.threads = threads;
			int cap;
			try {
				cap = (int) l.downcallHandle(lookup.findOrThrow("hydra_dhost_queue_capacity"),
					FunctionDescriptor.of(JAVA_INT)).invokeExact();
			}
			catch (Throwable t) {
				cap = 0;
			}
			slots = new Semaphore(Math.max(1, cap));
			if (ASYNC) {
				// the caller's thread exports and waits on a future (a virtual thread unmounts);
				// one platform thread drains the host's completion queue for every request
				calls = null;
				Thread.ofPlatform().daemon().name("decomp-host-completions").start(this::drain);
			}
			else {
				// platform threads make the blocking downcall, so no virtual thread's carrier is pinned
				calls = Executors.newFixedThreadPool(Math.max(2, threads * 2), r -> {
					Thread t = new Thread(r, "decomp-host-call");
					t.setDaemon(true);
					return t;
				});
			}
		}

		final MethodHandle submit;
		final MethodHandle completions;
		/** Bounds the runs queued or running in the host (its queue capacity). */
		final Semaphore slots;
		final AtomicLong tickets = new AtomicLong();
		final ConcurrentHashMap<Long, Pending> pending = new ConcurrentHashMap<>();

		/** The completion thread: takes finished runs and completes their futures. */
		private void drain() {
			final long size = 48;	// struct Completion (snapshot.rs)
			final int batch = 64;
			MemorySegment buf = Arena.global().allocate(size * batch, 8);
			while (true) {
				int n;
				try {
					n = (int) completions.invokeExact(buf, (long) batch, 1000L);
				}
				catch (Throwable t) {
					Msg.error(HostDecompiler.class, "decompile host completions: " + t, t);
					return;
				}
				for (int i = 0; i < n; i++) {
					long b = i * size;
					long ticket = buf.get(JAVA_LONG, b);
					MemorySegment out = buf.get(ADDRESS, b + 8);
					long outlen = buf.get(JAVA_LONG, b + 16);
					MemorySegment miss = buf.get(ADDRESS, b + 24);
					long misslen = buf.get(JAVA_LONG, b + 32);
					long answered = Integer.toUnsignedLong(buf.get(JAVA_INT, b + 40));
					int rc = buf.get(JAVA_INT, b + 44);
					slots.release();
					Pending p = pending.remove(ticket);
					Run r = null;
					Throwable err = null;
					try {
						r = decodeRun(this, rc, out, outlen, miss, misslen, answered);
					}
					catch (Throwable t) {
						err = t;
					}
					if (p != null) {
						try {
							if (err != null) {
								p.future.completeExceptionally(err);
							}
							else {
								p.future.complete(r);
							}
						}
						finally {
							p.gen.release(this);
						}
					}
				}
			}
		}
	}

	/** A run submitted to the host: its future and the generation it keeps open. */
	private record Pending(CompletableFuture<Run> future, Gen gen) {
	}

	/**
	 * {@code hydra.decomp.host.async} (default true): runs are submitted to the host's bounded
	 * queue and completed by one thread; false: one platform thread per request makes a blocking
	 * downcall (the step 6 path).
	 */
	static final boolean ASYNC =
		Boolean.parseBoolean(System.getProperty("hydra.decomp.host.async", "true"));
	private static final int BUSY = 4;

	private static volatile Object lib;	// a Lib, or the String reason it is unavailable

	private static Object lib() {
		Object l = lib;
		if (l == null) {
			synchronized (HostDecompiler.class) {
				l = lib;
				if (l == null) {
					l = load();
					lib = l;
					if (l instanceof String why) {
						Msg.warn(HostDecompiler.class, "decompile host unavailable: " + why);
					}
					else {
						Msg.info(HostDecompiler.class,
							"decompile host: " + ((Lib) l).threads + " workers");
					}
				}
			}
		}
		return l;
	}

	private static Object load() {
		try {
			Path file = findLibrary();
			if (file == null) {
				return System.mapLibraryName("hydra_decomp_host") + " not found";
			}
			SymbolLookup lookup = SymbolLookup.libraryLookup(file, Arena.global());
			Linker l = Linker.nativeLinker();
			int abi = (int) l.downcallHandle(lookup.findOrThrow("hydra_dhost_abi_version"),
				FunctionDescriptor.of(JAVA_INT)).invokeExact();
			if (abi != ABI_VERSION) {
				return file + ": ABI " + abi + ", expected " + ABI_VERSION;
			}
			int want = Integer.getInteger(THREADS_PROPERTY, 0);
			int threads = (int) l.downcallHandle(lookup.findOrThrow("hydra_dhost_start"),
				FunctionDescriptor.of(JAVA_INT, JAVA_INT)).invokeExact(want);
			if (threads <= 0) {
				return file + ": the host did not start (" + threads + ")";
			}
			return new Lib(lookup, threads);
		}
		catch (VirtualMachineError e) {
			throw e;
		}
		catch (Throwable t) {
			return t.toString();
		}
	}

	private static Path findLibrary() {
		String explicit = System.getProperty(LIBRARY_PROPERTY);
		if (explicit != null && !explicit.isBlank()) {
			return Path.of(explicit);
		}
		try {
			File f = Application.getOSFile(System.mapLibraryName("hydra_decomp_host"));
			return f.toPath();
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * @return null when the host library is loaded and started, else why not
	 */
	public static String unavailableReason() {
		return lib() instanceof String why ? why : null;
	}

	// ---- generations --------------------------------------------------------------------------

	/** The store of one program generation (modification number + options) and its exporters. */
	private static final class Gen {
		final Program program;
		final long modification;
		final byte[] options;
		final MemorySegment store;
		final ProgramSnapshotFile snapshot;
		final ConcurrentLinkedQueue<DecompileSnapshot> answerers = new ConcurrentLinkedQueue<>();
		final DecompileOptions decompileOptions;
		final Set<Address> prefetched = ConcurrentHashMap.newKeySet();
		/** Functions whose p-code was exported after a p-code miss in their body. */
		final Set<Address> pcodeBodies = ConcurrentHashMap.newKeySet();
		final Set<ByteBuffer> sent = ConcurrentHashMap.newKeySet();	// keys in the store
		/** The options' comment filter, learned from the first getComments miss (-1: not yet). */
		volatile long commentFlags = -1;
		private int inflight;
		private boolean retired;
		private boolean closed;

		Gen(Program program, long modification, byte[] options, DecompileOptions decompileOptions,
				MemorySegment store, ProgramSnapshotFile snapshot) {
			this.program = program;
			this.modification = modification;
			this.options = options;
			this.decompileOptions = decompileOptions;
			this.store = store;
			this.snapshot = snapshot;
		}

		synchronized boolean acquire() {
			if (retired) {
				return false;
			}
			inflight++;
			return true;
		}

		/** Keeps the store open for a submitted run; the caller already holds an acquire. */
		synchronized void pin() {
			inflight++;
		}

		void release(Lib l) {
			boolean close;
			synchronized (this) {
				inflight--;
				close = retired && inflight == 0 && !closed;
				if (close) {
					closed = true;
				}
			}
			if (close) {
				close(l);
			}
		}

		void retire(Lib l) {
			boolean close;
			synchronized (this) {
				retired = true;
				close = inflight == 0 && !closed;
				if (close) {
					closed = true;
				}
			}
			if (close) {
				close(l);
			}
		}

		private void close(Lib l) {
			try {
				l.storeClose.invokeExact(store);
			}
			catch (Throwable t) {
				Msg.error(HostDecompiler.class, "closing a decompile snapshot store: " + t, t);
			}
			ProgramSnapshotFile.release(snapshot);
		}

		DecompileSnapshot borrow() {
			DecompileSnapshot a = answerers.poll();
			return a != null ? a : new DecompileSnapshot(program, decompileOptions);
		}

		void giveBack(DecompileSnapshot a) {
			answerers.offer(a);
		}
	}

	private static final Map<Program, Gen> GENS = new WeakHashMap<>();
	private static final AtomicLong STORE_ANSWERS = new AtomicLong();

	private static Gen generation(Lib l, Program program, DecompileOptions options)
			throws IOException {
		long mod = program.getModificationNumber();
		byte[] opts = DecompileSnapshot.encodeOptions(options);
		List<Gen> stale = new ArrayList<>();
		Gen g;
		synchronized (GENS) {
			for (Iterator<Map.Entry<Program, Gen>> it = GENS.entrySet().iterator(); it
					.hasNext();) {
				Map.Entry<Program, Gen> en = it.next();
				if (en.getKey().isClosed()) {
					stale.add(en.getValue());
					it.remove();
				}
			}
			g = GENS.get(program);
			if (g != null && (g.modification != mod || !Arrays.equals(g.options, opts))) {
				stale.add(g);
				GENS.remove(program);
				g = null;
			}
		}
		for (Gen s : stale) {
			s.retire(l);
		}
		if (g != null) {
			return g;
		}
		// one thread makes a program's generation; the others wait for it and use it (two makers
		// would race for the byte snapshot, and the loser's store would answer bytes by misses)
		Object lock;
		synchronized (CREATING) {
			lock = CREATING.computeIfAbsent(program, p -> new Object());
		}
		synchronized (lock) {
			synchronized (GENS) {
				g = GENS.get(program);
			}
			if (g != null && g.modification == mod && Arrays.equals(g.options, opts)) {
				return g;
			}
			return makeGeneration(l, program, options, mod, opts);
		}
	}

	/** Per-program lock held while a generation is made. */
	private static final Map<Program, Object> CREATING = new WeakHashMap<>();

	/**
	 * The byte snapshot of the program's current generation. {@link ProgramSnapshotFile#acquire}
	 * returns null while another user (a process decompiler) writes it: wait for that write
	 * (bounded) instead of making a store without bytes.
	 */
	private static ProgramSnapshotFile snapshotOf(Program program, long mod) {
		for (int i = 0; i < 100; i++) {
			ProgramSnapshotFile snap = ProgramSnapshotFile.acquire(program, null);
			if (snap != null || program.getModificationNumber() != mod) {
				return snap;
			}
			try {
				Thread.sleep(10);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return null;
			}
		}
		return null;
	}

	private static Gen makeGeneration(Lib l, Program program, DecompileOptions options, long mod,
			byte[] opts) throws IOException {
		List<Gen> stale = new ArrayList<>();
		long t0 = System.nanoTime();
		DecompileSnapshot first = new DecompileSnapshot(program, options);
		DecompileSnapshot.Specs specs = first.specs();
		ProgramSnapshotFile snap = snapshotOf(program, mod);
		String snapPath = snap == null ? "" : snap.getPath().toString();
		MemorySegment store;
		try (Arena a = Arena.ofConfined()) {
			byte[][] parts = { utf8(specs.pspec()), utf8(specs.cspec()), utf8(specs.tspec()),
				utf8(specs.coretypes()), opts, utf8(snapPath) };
			MemorySegment[] segs = new MemorySegment[parts.length];
			for (int i = 0; i < parts.length; i++) {
				segs[i] = segment(a, parts[i]);
			}
			store = (MemorySegment) l.storeNew.invokeExact(segs[0], (long) parts[0].length,
				segs[1], (long) parts[1].length, segs[2], (long) parts[2].length, segs[3],
				(long) parts[3].length, segs[4], (long) parts[4].length, segs[5],
				(long) parts[5].length);
		}
		catch (Throwable t) {
			ProgramSnapshotFile.release(snap);
			throw new IOException("creating the decompile snapshot store: " + t, t);
		}
		if (store.equals(MemorySegment.NULL)) {
			ProgramSnapshotFile.release(snap);
			throw new IOException("the host could not create a store");
		}
		Gen made = new Gen(program, mod, opts, options, store, snap);
		try {
			registrationAnswers(l, made, first);
		}
		catch (Throwable t) {
			made.retire(l);
			if (t instanceof Error e) {
				throw e;
			}
			throw new IOException("exporting the registration answers: " + t, t);
		}
		made.giveBack(first);
		EXPORT_NANOS.add(System.nanoTime() - t0);
		Gen winner;
		synchronized (GENS) {
			winner = GENS.get(program);
			if (winner == null || winner.modification != mod ||
				!Arrays.equals(winner.options, opts)) {
				if (winner != null) {
					stale.clear();
					stale.add(winner);
				}
				GENS.put(program, made);
				winner = made;
				made = null;
			}
		}
		if (made != null) {
			made.retire(l);	// another thread made the same generation first
		}
		else {
			for (Gen s : stale) {
				s.retire(l);
			}
		}
		return winner;
	}

	private static byte[] utf8(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	private static MemorySegment segment(Arena a, byte[] b) {
		MemorySegment s = a.allocate(Math.max(1, b.length));
		MemorySegment.copy(b, 0, s, JAVA_BYTE, 0, b.length);
		return s;
	}

	// ---- exporting answers --------------------------------------------------------------------

	/** Export one answer to the store; false when it must not be stored. */
	private static boolean put(Lib l, Gen g, Arena arena, byte[] scope,
			DecompileSnapshot.Answer ans, byte[] query) throws Throwable {
		if (ans.kind() == DecompileSnapshot.UNSTORABLE) {
			return false;
		}
		byte[] sc = ans.kind() == DecompileSnapshot.SCOPED ? scope : new byte[0];
		int rc = (int) l.storePut.invokeExact(g.store, segment(arena, sc), (long) sc.length,
			segment(arena, query), (long) query.length, segment(arena, ans.response()),
			(long) ans.response().length);
		if (rc != 0) {
			throw new IOException("the host refused an answer");
		}
		STORE_ANSWERS.incrementAndGet();
		return true;
	}

	private static ByteBuffer key(byte[] scope, byte[] query) {
		ByteBuffer b = ByteBuffer.allocate(scope.length + 1 + query.length);
		b.put(scope).put((byte) 0).put(query).flip();
		return b;
	}

	/**
	 * Export, once per generation, the answers the decompile of {@code f} asks for that the
	 * database names in advance. An unstorable one is simply left out (the run will miss it).
	 */
	private static void prefetch(Lib l, Gen g, DecompileSnapshot a, Function f, byte[] scope)
			throws Throwable {
		if (!g.prefetched.add(f.getEntryPoint())) {
			return;
		}
		Program p = g.program;
		Address entry = f.getEntryPoint();
		AddressSetView body = f.getBody();
		List<byte[]> queries = new ArrayList<>();
		queries.add(DecompileSnapshot.queryMappedSymbols(entry));
		queries.add(DecompileSnapshot.queryTrackedRegisters(entry));
		long flags = g.commentFlags;
		if (flags >= 0) {
			queries.add(DecompileSnapshot.queryComments(entry, flags));
		}
		FunctionManager fm = p.getFunctionManager();
		for (Instruction in : p.getListing().getInstructions(body, true)) {
			queries.add(DecompileSnapshot.queryPcode(in.getAddress()));
			if (in.getFlowType().isCall()) {
				// a call to a function with a call-fixup: its injection, asked per call site
				for (Address to : in.getFlows()) {
					Function callee = fm.getFunctionAt(to);
					String fixup = callee == null ? null : callee.getCallFixup();
					if (fixup != null) {
						queries.add(DecompileSnapshot.queryCallFixup(fixup, in.getAddress(), to));
					}
				}
			}
		}
		ReferenceManager rm = p.getReferenceManager();
		Set<Address> targets = new LinkedHashSet<>();
		for (Address from : rm.getReferenceSourceIterator(body, true)) {
			for (Reference r : rm.getReferencesFrom(from)) {
				Address to = r.getToAddress();
				if (to.isMemoryAddress() && !to.getAddressSpace().isOverlaySpace()) {
					targets.add(to);
				}
			}
		}
		for (Address to : targets) {
			queries.add(DecompileSnapshot.queryMappedSymbols(to));
			queries.add(DecompileSnapshot.queryCodeLabel(to));	// jump targets (LAB_...)
			queries.add(DecompileSnapshot.queryExternalRef(to));	// import pointers (PTR_...)
		}
		try (Arena arena = Arena.ofConfined()) {
			for (int i = 0; i < queries.size(); i++) {
				byte[] q = queries.get(i);
				ByteBuffer global = key(new byte[0], q);
				// queries[0], the function's own symbol, is scoped: the global answer for its entry
				// (stored while decompiling a caller) is not the one its own decompile gets
				if ((i > 0 && g.sent.contains(global)) || g.sent.contains(key(scope, q))) {
					continue;
				}
				DecompileSnapshot.Answer ans = a.answer(q);
				if (put(l, g, arena, scope, ans, q)) {
					g.sent.add(ans.kind() == DecompileSnapshot.SCOPED ? key(scope, q) : global);
					PREFETCHED.increment();
				}
			}
		}
	}

	/**
	 * Export the answers registration asks for one by one (each would otherwise cost a native run):
	 * the user-defined op names, index 0 up to the first empty one.
	 */
	private static void registrationAnswers(Lib l, Gen g, DecompileSnapshot a) throws Throwable {
		try (Arena arena = Arena.ofConfined()) {
			// every register by name: global answers that otherwise cost one run each
			for (String name : a.registerNames()) {
				byte[] q = DecompileSnapshot.queryRegister(name);
				DecompileSnapshot.Answer ans = a.answer(q);
				if (put(l, g, arena, new byte[0], ans, q)) {
					g.sent.add(key(new byte[0], q));
					PREFETCHED.increment();
				}
			}
		}
		try (Arena arena = Arena.ofConfined()) {
			for (int i = 0; i < 1 << 16; i++) {
				byte[] q = DecompileSnapshot.queryUserOpName(i);
				DecompileSnapshot.Answer ans = a.answer(q);
				if (!put(l, g, arena, new byte[0], ans, q)) {
					return;
				}
				g.sent.add(key(new byte[0], q));
				PREFETCHED.increment();
				byte[] r = ans.response();
				if (r.length < 4 || r[3] != 8 || DecompileSnapshot.isEmptyString(r)) {
					return;
				}
			}
		}
	}

	/**
	 * True if the host fed every missed query a neutral answer (none ended the run) and that
	 * answer is the real one, byte for byte: the run then saw exactly what the process path
	 * sees, so its result is the process path's result.
	 */
	private static boolean exactRun(DecompileSnapshot a, Run r) {
		for (int i = 0; i < r.misses().size(); i++) {
			byte[] fed = r.fed().get(i);
			if (fed.length == 0 || !Arrays.equals(fed, a.answer(r.misses().get(i)).response())) {
				return false;
			}
		}
		return true;
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < Math.min(b.length, 48); i++) {
			sb.append(String.format("%02x", b[i] & 0xff));
		}
		return sb.toString();
	}

	/**
	 * A p-code miss outside the decompiled function's body (flow into another function's code)
	 * is followed by one miss per instruction, one run each: export the p-code of the whole
	 * function that holds the missed address, once per generation.
	 */
	private static void pcodeAround(Lib l, Gen g, DecompileSnapshot a, Run r) throws Throwable {
		Program p = g.program;
		for (byte[] q : r.misses()) {
			Address at = a.pcodeAddressOf(q);
			if (at == null) {
				continue;
			}
			Function holder = p.getFunctionManager().getFunctionContaining(at);
			if (holder == null || !g.pcodeBodies.add(holder.getEntryPoint())) {
				continue;
			}
			try (Arena arena = Arena.ofConfined()) {
				for (Instruction in : p.getListing().getInstructions(holder.getBody(), true)) {
					byte[] pq = DecompileSnapshot.queryPcode(in.getAddress());
					ByteBuffer global = key(new byte[0], pq);
					if (g.sent.contains(global)) {
						continue;
					}
					DecompileSnapshot.Answer ans = a.answer(pq);
					if (put(l, g, arena, new byte[0], ans, pq)) {
						g.sent.add(global);
						PREFETCHED.increment();
					}
				}
			}
		}
	}

	/** Export the answers to missed queries; the reason when one cannot be stored, else null. */
	private static String learn(Lib l, Gen g, DecompileSnapshot a, byte[] scope, Run r)
			throws Throwable {
		pcodeAround(l, g, a, r);
		try (Arena arena = Arena.ofConfined()) {
			Set<ByteBuffer> seen = new HashSet<>();
			for (int i = 0; i < r.misses().size(); i++) {
				byte[] q = r.misses().get(i);
				if (!seen.add(ByteBuffer.wrap(q))) {
					continue;	// a run that goes on after a miss may ask the same query again
				}
				boolean again = g.sent.contains(key(new byte[0], q)) || g.sent.contains(key(scope, q));
				long flags = a.commentFlagsOf(q);
				if (flags >= 0) {
					g.commentFlags = flags;
				}
				DecompileSnapshot.Answer ans = a.answer(q);
				byte[] fed = r.fed().get(i);
				boolean neutral = fed.length > 0 && Arrays.equals(fed, ans.response());
				MISS_KINDS.computeIfAbsent(
					a.commandOf(q) + (neutral ? " neutral" : "") + (again ? " again" : ""),
					k -> new LongAdder()).increment();
				if (TRACE_MISSES && !neutral && TRACED.incrementAndGet() <= 400) {
					Msg.info(HostDecompiler.class, "decompile host miss for " +
						a.getFunctionEntry() + ": " + a.describe(q) + " fed " + hex(fed) +
						" real " + hex(ans.response()));
				}
				if (!put(l, g, arena, scope, ans, q)) {
					return "unstorable answer: " + ans.why();
				}
				g.sent.add(ans.kind() == DecompileSnapshot.SCOPED ? key(scope, q)
						: key(new byte[0], q));
				MISSES_LEARNED.increment();
			}
		}
		return null;
	}

	// ---- decompile ----------------------------------------------------------------------------

	/** One native run: status, the command response (or message) and the missed queries. */
	private record Run(int rc, byte[] out, List<byte[]> misses, List<byte[]> fed) {
	}

	private static Run run(Lib l, Gen g, byte[] addr) throws Throwable {
		long t0 = System.nanoTime();
		try (Arena a = Arena.ofConfined()) {
			MemorySegment as = segment(a, addr);
			MemorySegment out = a.allocate(ADDRESS);
			MemorySegment outlen = a.allocate(JAVA_LONG);
			MemorySegment miss = a.allocate(ADDRESS);
			MemorySegment misslen = a.allocate(JAVA_LONG);
			MemorySegment answered = a.allocate(JAVA_LONG);
			int rc = (int) l.decompile.invokeExact(g.store, as, (long) addr.length, out, outlen,
				miss, misslen, answered);
			return decodeRun(l, rc, out.get(ADDRESS, 0), outlen.get(JAVA_LONG, 0),
				miss.get(ADDRESS, 0), misslen.get(JAVA_LONG, 0), answered.get(JAVA_LONG, 0));
		}
		finally {
			NATIVE_NANOS.add(System.nanoTime() - t0);
			ROUNDS.increment();
		}
	}

	/** Takes (and frees) the buffers of a finished native run. */
	private static Run decodeRun(Lib l, int rc, MemorySegment out, long outlen, MemorySegment miss,
			long misslen, long answered) throws Throwable {
		ANSWERED.add(answered);
		byte[] o = take(l, out, outlen);
		byte[] m = take(l, miss, misslen);
		List<byte[]> misses = new ArrayList<>();
		List<byte[]> fed = new ArrayList<>();
		ByteBuffer mb = ByteBuffer.wrap(m).order(java.nio.ByteOrder.LITTLE_ENDIAN);
		while (mb.remaining() >= 4) {
			int n = mb.getInt();
			if (n < 0 || n > mb.remaining()) {
				break;
			}
			byte[] q = new byte[n];
			mb.get(q);
			if (misses.size() == fed.size()) {
				misses.add(q);	// records alternate: the query, then the answer fed for it
			}
			else {
				fed.add(q);
			}
		}
		if (fed.size() < misses.size()) {
			fed.add(new byte[0]);
		}
		return new Run(rc, o, misses, fed);
	}

	/**
	 * One native run through the host's bounded queue: the caller's thread waits on a future (a
	 * virtual thread unmounts; no platform thread is held per request) until the completion thread
	 * posts the run. A full queue (another user of the library) takes the blocking downcall.
	 * @param deadline {@link System#nanoTime} by which the run must be done (0: none)
	 * @throws TimeoutException past the deadline (the run finishes unseen; its completion releases
	 * the generation)
	 */
	private static Run runAsync(Lib l, Gen g, byte[] addr, long deadline) throws Throwable {
		long t0 = System.nanoTime();
		if (deadline != 0) {
			if (!l.slots.tryAcquire(Math.max(0, deadline - t0), TimeUnit.NANOSECONDS)) {
				throw new TimeoutException();
			}
		}
		else {
			l.slots.acquire();
		}
		long ticket = l.tickets.incrementAndGet();
		CompletableFuture<Run> fut = new CompletableFuture<>();
		g.pin();
		l.pending.put(ticket, new Pending(fut, g));
		int rc;
		try (Arena a = Arena.ofConfined()) {
			rc = (int) l.submit.invokeExact(g.store, segment(a, addr), (long) addr.length, ticket);
		}
		catch (Throwable t) {
			rc = -100;
		}
		if (rc != OK) {
			l.pending.remove(ticket);
			l.slots.release();
			g.release(l);
			if (rc == BUSY) {
				return run(l, g, addr);
			}
			return new Run(rc, ("host submit refused: " + rc).getBytes(StandardCharsets.UTF_8),
				List.of(), List.of());
		}
		try {
			if (deadline == 0) {
				return fut.get();
			}
			return fut.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
		finally {
			NATIVE_NANOS.add(System.nanoTime() - t0);
			ROUNDS.increment();
		}
	}

	private static byte[] take(Lib l, MemorySegment p, long len) throws Throwable {
		if (p.equals(MemorySegment.NULL)) {
			return new byte[0];
		}
		byte[] b = p.reinterpret(len).toArray(JAVA_BYTE);
		l.free.invokeExact(p);
		return b;
	}

	/**
	 * Decompile {@code f} in the host. Falls back (and says why) for: no host library; an external,
	 * undefined, overlay or stack-depth-overriding function; a program that is not a database
	 * program; a query whose answer cannot be stored; misses left after {@link #MAX_ROUNDS} runs;
	 * a run that failed or did not complete (the process path then gives the authoritative
	 * error); a run over {@code timeoutSecs}.
	 * @param program the program ({@code f}'s)
	 * @param f the function
	 * @param options the decompiler options, as the process decompilers use them
	 * @param timeoutSecs the decompile timeout (0 = none)
	 * @return the outcome
	 */
	public static Outcome decompile(Program program, Function f, DecompileOptions options,
			int timeoutSecs) {
		Outcome o;
		try {
			o = decompile0(program, f, options, timeoutSecs);
		}
		catch (RuntimeException e) {
			// a defect of the host path must never fail the request: the process path answers it
			Msg.error(HostDecompiler.class, "decompile host: " + e, e);
			o = Outcome.fallback("host error: " + e);
		}
		if (o.results() != null) {
			HOSTED.increment();
		}
		else {
			FALLBACKS.increment();
			String key = o.fallback().replaceAll("0x[0-9a-fA-F]+|\\b[0-9a-fA-F]{6,}\\b", "#");
			REASONS.computeIfAbsent(key, k -> new LongAdder()).increment();
		}
		return o;
	}

	private static Outcome decompile0(Program program, Function f, DecompileOptions options,
			int timeoutSecs) {
		Object lo = lib();
		if (lo instanceof String why) {
			return Outcome.fallback("host unavailable: " + why);
		}
		Lib l = (Lib) lo;
		if (!(program instanceof ghidra.program.database.ProgramDB)) {
			return Outcome.fallback("not a database program");
		}
		String why = DecompileSnapshot.hostable(f);
		if (why != null) {
			return Outcome.fallback(why);
		}
		Gen g;
		try {
			g = generation(l, program, options);
		}
		catch (IOException | IllegalArgumentException e) {
			return Outcome.fallback("snapshot: " + e.getMessage());
		}
		if (!g.acquire()) {
			return Outcome.fallback("generation retired");
		}
		if (ASYNC) {
			long deadline = timeoutSecs > 0
					? System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSecs) | 1
					: 0;
			try {
				return hosted(l, g, f, options, deadline);
			}
			catch (TimeoutException e) {
				return Outcome.fallback("host run over the timeout");	// the run finishes unseen
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return Outcome.fallback("interrupted");
			}
			catch (VirtualMachineError e) {
				throw e;
			}
			catch (Throwable c) {
				Msg.error(HostDecompiler.class, "decompile host: " + c, c);
				return Outcome.fallback("host error: " + c);
			}
			finally {
				g.release(l);
			}
		}
		Future<Outcome> fut;
		try {
			fut = l.calls.submit(() -> {
				try {
					return hosted(l, g, f, options, 0);
				}
				catch (Exception | Error e) {
					throw e;
				}
				catch (Throwable t) {
					throw new ExecutionException(t);
				}
				finally {
					g.release(l);
				}
			});
		}
		catch (RejectedExecutionException e) {
			g.release(l);
			return Outcome.fallback("host executor refused");
		}
		try {
			return timeoutSecs > 0 ? fut.get(timeoutSecs, TimeUnit.SECONDS) : fut.get();
		}
		catch (TimeoutException e) {
			return Outcome.fallback("host run over the timeout");	// the run finishes unseen
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return Outcome.fallback("interrupted");
		}
		catch (ExecutionException e) {
			Throwable c = e.getCause();
			Msg.error(HostDecompiler.class, "decompile host: " + c, c);
			return Outcome.fallback("host error: " + c);
		}
	}

	private static Outcome hosted(Lib l, Gen g, Function f, DecompileOptions options,
			long deadline) throws Throwable {
		DecompileSnapshot a = g.borrow();
		try {
			a.setFunction(f);
			byte[] addr = DecompileSnapshot.encodeAddress(f.getEntryPoint());
			long t0 = System.nanoTime();
			prefetch(l, g, a, f, addr);
			EXPORT_NANOS.add(System.nanoTime() - t0);
			for (int round = 1; round <= MAX_ROUNDS; round++) {
				if (deadline != 0 && System.nanoTime() - deadline >= 0) {
					throw new TimeoutException();
				}
				Run r = ASYNC ? runAsync(l, g, addr, deadline) : run(l, g, addr);
				if (r.rc() == MISSES && r.out().length > 0 && exactRun(a, r)) {
					// every miss was fed its real answer: the run is the process path's run
					EXACT_RUNS.increment();
					learn(l, g, a, addr, r);
					r = new Run(OK, r.out(), List.of(), List.of());
				}
				if (r.rc() == OK) {
					a.setFunction(f);	// fresh temporary ids for decoding, as the process path
					DecompileResults res =
						a.decodeResults(f, r.out(), options.getMaxPayloadMBytes());
					if (res == null) {
						return Outcome.fallback("host result not decodable");
					}
					if (!res.decompileCompleted()) {
						return Outcome.fallback("host decompile did not complete: " +
							res.getErrorMessage().trim());
					}
					return new Outcome(res, null);
				}
				if (r.rc() != MISSES) {
					return Outcome.fallback(
						"host failed: " + new String(r.out(), StandardCharsets.UTF_8));
				}
				if (round == MAX_ROUNDS) {
					break;
				}
				long t1 = System.nanoTime();
				String bad = learn(l, g, a, addr, r);
				EXPORT_NANOS.add(System.nanoTime() - t1);
				if (bad != null) {
					return Outcome.fallback(bad);
				}
			}
			return Outcome.fallback("queries still missing after " + MAX_ROUNDS + " runs");
		}
		finally {
			g.giveBack(a);
		}
	}

	// ---- statistics ---------------------------------------------------------------------------

	/** @return decompiles answered by the host */
	public static long hostedCount() {
		return HOSTED.sum();
	}

	/** @return decompiles handed to the process path */
	public static long fallbackCount() {
		return FALLBACKS.sum();
	}

	/**
	 * @return the counters: hosted, fallback, the fallback reasons, native runs, answers exported
	 * (prefetched and learned from misses), answers served by the stores, and times
	 */
	public static Map<String, Object> stats() {
		Map<String, Object> m = new LinkedHashMap<>();
		Object l = lib;
		m.put("library", l == null ? "not loaded" : l instanceof String s ? s : "loaded");
		m.put("workers", l instanceof Lib lb ? lb.threads : 0);
		m.put("submission", ASYNC ? "async" : "blocking");
		if (l instanceof Lib lb && ASYNC) {
			m.put("queued", lb.pending.size());
		}
		m.put("hosted", HOSTED.sum());
		m.put("fallback", FALLBACKS.sum());
		Map<String, Long> reasons = new TreeMap<>();
		REASONS.forEach((k, v) -> reasons.put(k, v.sum()));
		m.put("fallbackReasons", reasons);
		m.put("nativeRuns", ROUNDS.sum());
		m.put("exactRunsWithMisses", EXACT_RUNS.sum());
		m.put("prefetched", PREFETCHED.sum());
		m.put("missesLearned", MISSES_LEARNED.sum());
		Map<String, Long> kinds = new TreeMap<>();
		MISS_KINDS.forEach((k, v) -> kinds.put(k, v.sum()));
		m.put("missesByCommand", kinds);
		m.put("storeAnswers", STORE_ANSWERS.get());
		m.put("answeredFromStore", ANSWERED.sum());
		m.put("nativeMs", NATIVE_NANOS.sum() / 1_000_000);
		m.put("exportMs", EXPORT_NANOS.sum() / 1_000_000);
		return m;
	}

	/** Test hook: the library file in use, if any. */
	static Path libraryFile() {
		Path p = findLibrary();
		return p != null && Files.isRegularFile(p) ? p : null;
	}
}
