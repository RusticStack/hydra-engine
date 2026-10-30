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
package ghidra.program.util;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Per-thread collector of program writes made by an analysis worker.
 * <p>
 * Analyzers that run per-location work on several threads (constant propagation, stack
 * variables) normally write references, data and variables into the program while other
 * workers are still reading it, so each worker's result depends on what the other workers
 * already wrote, which depends on thread timing. When a collector is open on the current
 * thread, {@link #run(Runnable)} records the write instead of performing it. The caller
 * gathers one collector per location and applies them all, in a fixed order, after every
 * worker has finished. Every worker then reads the same program state, so the result does
 * not depend on the thread count or scheduling.
 * <p>
 * With no collector open, {@link #run(Runnable)} performs the write at once, which is the
 * original behaviour.
 * <p>
 * A worker that records a reference must still see it when it reads the instruction's
 * references back later in the same location (the original code read its own immediate
 * writes). Recorded reference additions and removals are therefore also noted with
 * {@link #noteReferenceAdded} / {@link #noteReferenceRemoved}, and read-backs go through
 * {@link #referencesFrom(Instruction)}, {@link #pendingOperandAddress(Instruction, int)} and
 * {@link #hasPendingReferenceTo(Address)}, which overlay the notes of the current thread's
 * open collector (only its own writes, never another worker's) on the program.
 */
public final class DeferredProgramWrites {

	private static final ThreadLocal<DeferredProgramWrites> CURRENT = new ThreadLocal<>();
	private static final ThreadLocal<TaskMonitor> APPLY_MONITOR = new ThreadLocal<>();

	private final List<Runnable> writes = new ArrayList<>();

	// read-back overlay of this collector's own recorded reference writes (see class javadoc);
	// allocated on first use, dropped by close()
	private Map<Address, List<Reference>> addedRefsFrom;
	private Map<Address, List<Reference>> removedRefsFrom;
	private Set<Address> addedRefTargets;

	/**
	 * Perform a program write now, or record it if a collector is open on this thread.
	 *
	 * @param write the write
	 */
	public static void run(Runnable write) {
		DeferredProgramWrites current = CURRENT.get();
		if (current == null) {
			write.run();
		}
		else {
			current.writes.add(write);
		}
	}

	/**
	 * @return true if writes on this thread are being collected
	 */
	public static boolean isCollecting() {
		return CURRENT.get() != null;
	}

	/**
	 * Open a new collector on the current thread. Must be paired with {@link #close()}.
	 *
	 * @return the collector
	 * @throws IllegalStateException if a collector is already open on this thread
	 */
	public static DeferredProgramWrites open() {
		if (CURRENT.get() != null) {
			throw new IllegalStateException("deferred program writes already open on this thread");
		}
		DeferredProgramWrites d = new DeferredProgramWrites();
		CURRENT.set(d);
		return d;
	}

	/**
	 * Stop collecting on the current thread. The recorded writes stay in this object.
	 */
	public void close() {
		if (CURRENT.get() == this) {
			CURRENT.remove();
		}
		addedRefsFrom = null;
		removedRefsFrom = null;
		addedRefTargets = null;
	}

	/**
	 * Note that a reference addition was recorded on this thread, so later read-backs in the
	 * same location see it. Does nothing when no collector is open.
	 *
	 * @param from reference source (instruction address)
	 * @param to reference target
	 * @param type reference type
	 * @param opIndex operand index, or {@link Reference#MNEMONIC}
	 */
	public static void noteReferenceAdded(Address from, Address to, RefType type, int opIndex) {
		DeferredProgramWrites d = CURRENT.get();
		if (d == null) {
			return;
		}
		if (d.addedRefsFrom == null) {
			d.addedRefsFrom = new HashMap<>();
			d.addedRefTargets = new HashSet<>();
		}
		List<Reference> removed =
			d.removedRefsFrom == null ? null : d.removedRefsFrom.get(from);
		if (removed != null) {
			removed.removeIf(r -> r.getOperandIndex() == opIndex && r.getToAddress().equals(to));
		}
		List<Reference> list = d.addedRefsFrom.computeIfAbsent(from, k -> new ArrayList<>(2));
		for (Reference r : list) {
			if (r.getOperandIndex() == opIndex && r.getToAddress().equals(to)) {
				return; // the reference manager merges a repeated (from, to, operand)
			}
		}
		list.add(new MemReferenceImpl(from, to, type, SourceType.ANALYSIS, opIndex, false));
		d.addedRefTargets.add(to);
	}

	/**
	 * Note that a reference removal was recorded on this thread. Does nothing when no
	 * collector is open.
	 *
	 * @param from reference source (instruction address)
	 * @param to reference target
	 * @param opIndex operand index
	 */
	public static void noteReferenceRemoved(Address from, Address to, int opIndex) {
		DeferredProgramWrites d = CURRENT.get();
		if (d == null) {
			return;
		}
		List<Reference> added = d.addedRefsFrom == null ? null : d.addedRefsFrom.get(from);
		if (added != null) {
			added.removeIf(r -> r.getOperandIndex() == opIndex && r.getToAddress().equals(to));
		}
		if (d.removedRefsFrom == null) {
			d.removedRefsFrom = new HashMap<>();
		}
		d.removedRefsFrom.computeIfAbsent(from, k -> new ArrayList<>(1))
				.add(new MemReferenceImpl(from, to, RefType.DATA, SourceType.ANALYSIS, opIndex,
					false));
	}

	/**
	 * The references from an instruction as the original (immediate-write) code would see
	 * them: the program's references, minus the removals and plus the additions recorded by
	 * this thread's open collector, in the order the reference manager would list them
	 * (additions after the existing references). Without an open collector, or with nothing
	 * recorded for this instruction, this is {@code instr.getReferencesFrom()}.
	 *
	 * @param instr the instruction
	 * @return the references from the instruction
	 */
	public static Reference[] referencesFrom(Instruction instr) {
		Reference[] refs = instr.getReferencesFrom();
		DeferredProgramWrites d = CURRENT.get();
		if (d == null || (d.addedRefsFrom == null && d.removedRefsFrom == null)) {
			return refs;
		}
		Address from = instr.getMinAddress();
		List<Reference> added = d.addedRefsFrom == null ? null : d.addedRefsFrom.get(from);
		List<Reference> removed = d.removedRefsFrom == null ? null : d.removedRefsFrom.get(from);
		if ((added == null || added.isEmpty()) && (removed == null || removed.isEmpty())) {
			return refs;
		}
		List<Reference> out = new ArrayList<>(refs.length + (added == null ? 0 : added.size()));
		for (Reference r : refs) {
			if (!contains(removed, r.getOperandIndex(), r.getToAddress())) {
				out.add(r);
			}
		}
		if (added != null) {
			for (Reference r : added) {
				if (!contains(out, r.getOperandIndex(), r.getToAddress())) {
					out.add(r);
				}
			}
		}
		return out.toArray(new Reference[out.size()]);
	}

	/**
	 * The target of the first reference this thread's open collector recorded on an operand
	 * that has no reference in the program. The reference manager makes the first reference
	 * on an operand its primary reference, and {@link Instruction#getAddress(int)} and
	 * {@link Instruction#getOperandType(int)} report the primary reference, so the original
	 * code saw this address on the operand.
	 *
	 * @param instr the instruction
	 * @param opIndex the operand index
	 * @return the target, or null if none is pending (or the program already has a
	 *         reference on the operand, or no collector is open)
	 */
	public static Address pendingOperandAddress(Instruction instr, int opIndex) {
		DeferredProgramWrites d = CURRENT.get();
		if (d == null || d.addedRefsFrom == null) {
			return null;
		}
		List<Reference> added = d.addedRefsFrom.get(instr.getMinAddress());
		if (added == null) {
			return null;
		}
		for (Reference r : added) {
			if (r.getOperandIndex() == opIndex) {
				return instr.getOperandReferences(opIndex).length == 0 ? r.getToAddress() : null;
			}
		}
		return null;
	}

	/**
	 * @param to a reference target
	 * @return true if this thread's open collector recorded a reference to {@code to}
	 */
	public static boolean hasPendingReferenceTo(Address to) {
		DeferredProgramWrites d = CURRENT.get();
		return d != null && d.addedRefTargets != null && d.addedRefTargets.contains(to);
	}

	private static boolean contains(List<Reference> refs, int opIndex, Address to) {
		if (refs == null) {
			return false;
		}
		for (Reference r : refs) {
			if (r.getOperandIndex() == opIndex && r.getToAddress().equals(to)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return number of recorded writes
	 */
	public int size() {
		return writes.size();
	}

	/**
	 * Monitor for a recorded write to use. While {@link #apply(TaskMonitor)} runs on this
	 * thread this is the apply-time monitor (the analysis monitor, which can still be
	 * cancelled); otherwise it is the given monitor (immediate mode).
	 *
	 * @param recordTimeMonitor monitor of the code recording the write
	 * @return the monitor to use
	 */
	public static TaskMonitor monitor(TaskMonitor recordTimeMonitor) {
		TaskMonitor m = APPLY_MONITOR.get();
		return m != null ? m : recordTimeMonitor;
	}

	/**
	 * Perform the recorded writes in the order they were recorded, with no cancellation.
	 *
	 * @return number of writes that threw a RuntimeException (logged and skipped)
	 * @see #apply(TaskMonitor)
	 */
	public int apply() {
		try {
			return apply(TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertionError(e); // DUMMY is never cancelled
		}
	}

	/**
	 * Perform the recorded writes in the order they were recorded. Must be called with no
	 * collector open on the current thread so that the writes really happen.
	 * <p>
	 * A write that throws a RuntimeException is logged and skipped and the remaining writes
	 * are still performed, so one failing write cannot drop the rest of the pass (the same
	 * write fails the same way for every thread count, so the outcome stays deterministic).
	 * Cancellation of {@code monitor} is checked before every write; recorded writes that
	 * take a monitor get {@code monitor} through {@link #monitor(TaskMonitor)}.
	 *
	 * @param monitor apply-time monitor
	 * @return number of writes that threw a RuntimeException
	 * @throws CancelledException if {@code monitor} is cancelled
	 */
	public int apply(TaskMonitor monitor) throws CancelledException {
		if (CURRENT.get() != null) {
			throw new IllegalStateException("cannot apply while collecting on this thread");
		}
		int failures = 0;
		APPLY_MONITOR.set(monitor);
		try {
			for (Runnable w : writes) {
				monitor.checkCancelled();
				try {
					w.run();
				}
				catch (RuntimeException e) {
					failures++;
					Msg.error(DeferredProgramWrites.class, "deferred program write failed", e);
				}
			}
			monitor.checkCancelled();
		}
		finally {
			APPLY_MONITOR.remove();
			writes.clear();
		}
		return failures;
	}
}
