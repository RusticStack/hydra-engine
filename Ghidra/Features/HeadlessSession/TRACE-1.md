# TRACE-1: the Hydra semantic trace contract

Normative. Implements `hydra-semantic-trace.md` (cited as §N) under `hydra-semantic-trace-plan.md` (decisions D1-D10).
Windows x64 host and targets only in 12.3-hydra.6; the schema itself is OS-neutral. Rust reference implementation:
`Ghidra/Framework/HydraNative/crates/hydra-trace`. A capability is advertised in `Advertised` only after its gate passes.

## 1. Words

MUST, SHOULD and MAY are used in the RFC 2119 sense. A **source** is one observer (the in-process agent, `hydra-etw`, an
importer). A **segment** is one source's append-only raw file. A **session** is one bounded capture made of one or more
sources. The **index** is the derived per-session SQLite database; the segments are the truth and the index can always
be rebuilt from them.

## 2. Ownership: nobody takes turns

- Each source writes only its own segment. Exactly one ingester per session writes that session's index.
- Readers read committed snapshots and take no lock. A reader's **revision** is the committed high-water mark of the
  last group commit; a row is visible only whole.
- A trace request never waits on another request. Queries are served from committed snapshots in the quick lane;
  ingest, re-symbolization, export and over-budget diffs are background jobs.
- **Writer lease:** one owner capability per session. A reconnecting producer gets a new `producer_gen`; only the
  owner arms probes, changes scope or stops capture. Everyone else reads status.

## 3. Raw segment (identical to `durable.AppendLog`)

A segment is a sequence of lines `crc SP json LF`:

- `crc` is 8 lowercase hex digits, CRC-32 (IEEE 802.3, `zlib.crc32`) of the JSON bytes.
- `json` is the canonical record (section 4), ASCII only.
- Every record has `n` (0, 1, 2, ... with no gap), `prev` and `hash`. `prev` of record 0 is the **genesis hash**:
  `SHA-256("hydra.trace.segment/1\n" + segment_id)` in hex. `hash` is `SHA-256(canonical JSON of the record without
  "hash")` in hex; `prev` of record k is `hash` of record k-1.
- A reader accepts the valid prefix. A final line that is incomplete or has a bad CRC is a **torn tail**: reported,
  ignored, not an error. A bad line followed by more data is **corruption**; a valid line that breaks `n`, `prev` or
  `hash` is a **chain break**. Both stop the scan at the last good record and are reported with their byte offset.
- Distinct outcomes a reader MUST keep distinct: empty (zero records, clean), torn tail, corrupt, chain break, missing
  segment.

## 4. Canonical JSON

Sorted keys (ASCII keys), separators `,` and `:` with no spaces, strings escaped as `\"` `\\` `\n` `\r` `\t` `\b`
`\f`, every other character below 0x20 or above 0x7e as `\uXXXX` lowercase hex (UTF-16 surrogate pairs above the BMP).
**No floating point numbers** in a chained record: times are integer nanoseconds, ratios are integer parts per
million. This makes the Rust and Python encoders byte-identical (tested in both).

## 5. Event envelope (`hydra.trace.event/1`, schema `trace-schema/event.schema.json`)

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `core.*` from section 6, or `<ns>.<name>` for a profile (lowercase, digits, `_`; `<ns>` is not `core`) |
| `source_id`, `source_seq`, `producer_gen` | string, u64, u32 | the producer's own numbering; `(source_id, producer_gen, source_seq)` is unique. A jump in `source_seq` without a `core.capture.gap` is a **lost producer** |
| `clock_domain` | string | names a clock (section 8); `t_mono_ns` is meaningful only within it |
| `t_mono_ns` | u64 | monotonic nanoseconds in `clock_domain` |
| `t_wall_ns` | u64? | wall clock, for humans only |
| `process_id`, `thread_id` | u32? | OS ids; NOT identities (section 7) |
| `process_gen`, `thread_gen`, `module_instance` | u32? | session-local generation numbers |
| `module` | string? | module name |
| `confidence` | `exact`, `inferred`, `sampled` | summary only; relations carry evidence (section 9) |
| `acquisition` | `atomic`, `bracketed`, `snapshot`, `inferred`? | how a value was acquired (§14.3) |
| `va` | u64? | code address of the site; absent means not captured |
| `callstack` | u64[] | return addresses, innermost first; empty means not captured |
| `payload` | object | typed per kind |

Ingest adds, and a producer MUST NOT set: `seq` (collector ingestion ordinal, not execution order), `event_id`
(`ev_` + session + `seq`, stable), `static` (symbolization, section 10), `revision`.

## 6. Core kinds (§4.3)

`core.session.{start,end}`, `core.process.{start,exit}`, `core.module.{load,unload}`, `core.thread.{start,exit}`,
`core.function.{enter,exit}`, `core.resource.{open,close,read,write,missing}`, `core.object.{create,destroy}`,
`core.state.{read,write}`, `core.sync.{wait,signal}`, `core.error`, `core.marker`, `core.capture.{source,gap}`.
Payload keys are defined in `trace-schema/payloads.md`. An unknown `core.*` kind is rejected; an unknown profile kind is
accepted only if the session's profile declares it.

`core.capture.gap` payload: `reason` (`producer-lost`, `ring-overflow`, `filter`, `read-failure`, `restart`,
`budget`), optional `dropped`, `first_missing_source_seq`, `last_missing_source_seq`, `out_of_band`. Overflow counters
travel out of band so they survive a full ring.

## 7. Identity and lifetime (§14.3)

- Processes and threads are identified by `(session, pid/tid, generation)`. A start observation opens a generation; an
  exit closes it. A reused PID gets a new generation. If a start was not observed the lifetime is `unresolved`.
- Modules: build SHA-256 plus load instance (`module_instance`), base and lifetime. A reload at another base is a new
  instance.
- Objects, allocations and handles: location plus observed lifetime generation. An unobserved creation or retirement is
  `unresolved`. Identities never merge silently.
- Ingestion order, producer order and clock order are three separate orders. Concurrent events stay **partially
  ordered**; only causal relations (section 9) establish order.

## 8. Clock domains

Each source declares its domain: name, unit (Windows: QPC, 10 MHz = 100 ns ticks, converted to ns), resolution and the
calibration to others (offset, drift, uncertainty in ns, from shared markers or a declared sync exchange). A join across
domains MUST carry the uncertainty; without calibration it is `not_comparable`.

## 9. Relations (§14.2)

`{from, to, relation, basis[], status, unresolved[]}` stored apart from events. `relation` is one of `call-return`,
`request-completion`, `created-by`, `buffer-transform`, `field-write`, `async-handoff`, `observed-call`,
`temporal-only`. `status` is `supported`, `inferred` or `unresolved`. Relations are built from correlation ids and
observed call/return, never from timestamps alone; a `temporal-only` relation says exactly that.

## 10. Symbolization and interpretations (§6, §14.5)

Ingest resolves `va` + module instance to function and type against a pinned program revision (`symbol_revision`). An
unresolved frame keeps `function: null` and a `reason` (`no-stack`, `not-code`, `module-unknown`, `no-symbol`). The
original VA and module are never rewritten. Re-symbolization writes a new **interpretation revision**; queries default
to the latest and can pin one. Interpretations record codec and schema hashes, byte-range provenance and the context
interval they apply to. Original observations are immutable.

**Interpretation reprocess (§14.5).** `trace_reprocess` decodes the bytes an event carries (a hex `bytes` field, or a stored
artifact) under a codec table `{layout name: codec}`. Which layout is in force where comes from `contexts` (explicit `from_seq`
to `to_seq` ranges) or from `context`, a rule over the trace's own marker events (a marker's `layout` field names the layout in
force until the next marker, so two layouts can live in one trace). Each run is a new numbered revision; the codec and schema
hashes, the context interval and, per decoded field, the source byte range are recorded. A corrected codec is simply the next
revision: earlier ones stay readable, observations are never rewritten. Bytes no field covers are never dropped: they are kept as
`_unconsumed` {`hex`, `len`, `byte_off`, `byte_len`} and counted in the revision's `stats`. An unknown layout, bad hex or an
evicted artifact is an `_error` row. The revision is journalled in `interp.jsonl`, so `verify`, `rebuild` and recovery
restore it under the same number and the rebuilt digest equals the original.

**Session metadata, scope, retention.** The profile id and hash, scope, limitations, target, capture configuration and scenario
are stored in `session.json` (`meta`) and returned by `trace_info`. Correlation keys are scoped: `session:<id>` by default,
so the same value in two sessions is unlinkable; `shared:<name>` only when every session asks for the same shared scope with
the same key. A session may be evicted (to a quota or on request): its directory is removed and a tombstone is written; an export
bundle made from it is then reported not reproducible (`session-evicted`). `trace_info` is O(1); the store digest is computed
(and cached per revision) only on request and excludes the symbolization interpretations.

## 11. Values and payloads (§14.6)

- Scalars are stored as values with their acquisition semantics.
- Strings become **keyed correlation ids**: HMAC-SHA256 under a per-scope key, truncated to 128 bits, hex. The scope is
  recorded; the key is never exposed. Cross-session correlation needs an explicitly shared scope. Redacted previews
  (<= 256 bytes) appear only when the policy allows.
- **Payload mode** keeps selected byte ranges as private artifacts (declared scope, maximum bytes, retention,
  redaction), durable before any reference commits. Export omits them unless separately authorized.

## 12. Coverage and health (§14.1)

Separate claims, never implied by each other: finalized, attached, observing, data integrity, capture coverage,
scenario coverage, behavioral equivalence, and fault-free. Each source reports activation/deactivation, refusals,
filter policy, read failures, buffer loss and restarts. Producer, transport and writer counters are separate. A
zero-loss counter without an active observer is not coverage. Every query returns the coverage revision and the gaps
relevant to its answer.

## 13. Index (derived)

One SQLite database per session in WAL mode: `events`, `callstacks`, `resources`, `states`, `objects`, `processes`,
`threads`, `module_instances`, `clock_domains`, `sources`, `coverage_intervals`, `gaps`, `relations`, `artifacts`,
`interpretations`, `assertions`, `check_results`, `marks`, `tombstones`, plus indexes on `(kind, seq)`, `(function_id)`,
`(resource_key)`, `(state_key)` and `(process_gen)`. The index MUST be rebuildable from the segments and verifiable
against them: a rebuilt index equals the original.

## 14. Diff, explain, check

- **Diff** aligns before comparing (§14.7): scenario phase, operation identity, object role and lifetime, logical
  resource key, verified cross-build function maps, `(frame offset, phase)`. PIDs, addresses and timestamps are never
  default cross-run keys. Every normalization is disclosed with unmatched and ambiguous counts. Output classes:
  `only_a`, `only_b`, `different_under_matched_coverage`, `not_comparable`. Absence is never unreachability. Output
  ordering is byte-deterministic.
- **Explain** walks relations upstream or downstream with depth, event and byte budgets, path counts and explicit
  unresolved boundaries.
- **Check** (§14.8) is `pass`, `fail` or `unknown`, with coverage requirement, checked count, counterexample event ids
  and the assertion revision. Zero eligible cases is `unknown`. Missing observers, truncated data and overlapping gaps
  are `unknown`, and the valid part of the trace stays usable.

## 15. Limitation codes

Shared with `evidence.LIMITATIONS`: `no-stack`, `not-code`, `module-unknown`, `no-symbol`, `producer-lost`,
`ring-overflow`, `read-failure`, `observer-inactive`, `clock-uncalibrated`, `lifetime-unresolved`,
`alignment-ambiguous`, `budget-reached`, `artifact-evicted`, `payload-not-authorized`, `etw-not-elevated`,
`optional-hook-refused`.

## 16. Versioning

`hydra.trace.event/1`, `hydra.trace.session/1`. A change that removes or reinterprets a field is a new major. The
protocol advertises the `trace` capability with these versions; `minClient` stays `1.0.0`.
