# Shared database pages across views

Many agents work on the same program at once: the shared read-only view, an overlay per agent (its own program
object over the same stored file), private script instances, forks (byte copies of the project), the upgrade
cache copy. Every one of them is a separate `DBHandle` with its own `BufferMgr`, and each `BufferMgr` keeps its own
in-memory copy of every page it read: up to 4 MB per program object (256 pages of 16 KB). For KotOR that was about
three quarters of what an overlay costs (heap class histogram: `byte[]` 35.6 MB of 48.2 MB for 8 overlays).

`db.buffers.SharedPages` interns pages by content:

- When a `BufferMgr` reads a page from its source file (or reloads an unchanged stored page from its cache file), the
  page is looked up by its bytes (vectorised `Arrays.hashCode`, then `Arrays.equals`). When some other buffer already
  holds an equal page, this buffer takes that array and its own array is kept as a spare for the next read.
  Otherwise its array becomes the shared copy.
- A shared array is never written. `DataBuffer` copies it before its first change (copy-on-write in every mutator)
  and drops it, without copying, before the buffer is refilled from a file (`unshareForOverwrite`; `BufferMgr`
  recycles cache buffers through `privateArray`, and `LocalBufferFile.get` checks too).
- Safety rests on content equality only: no file identity, no invalidation, nothing that a save, a fork or a
  refresh could make stale. The table holds weak references, so it never keeps a page alive that no buffer uses;
  memory is bounded by the union of the per-view caches (each still limited as before), not their sum.
- Forks share too: a fork's database is a byte copy, so its pages intern to the same arrays as the base's.

Isolation is unchanged: an overlay's or a fork's change makes a private copy of the page in that view only
(`SharedPagesTest.testChangeInOneViewIsNotSeenByAnother`), undo restores the stored page, and nothing is written
to any file differently (buffers are written from their bytes, shared or not).

`-Dhydra.db.sharedPages=false` turns it off (pages are private, as in Ghidra).
