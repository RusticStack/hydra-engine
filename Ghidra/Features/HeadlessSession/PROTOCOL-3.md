# Hydra Engine protocol 3: the engine contract, the Hydralysis obligations and the work plan

Status: **design, not implemented.** Nothing in this file describes shipped behaviour. The text
fixes one design for the eight problem areas the investigation raised (durable annotations,
concurrency, lanes and admission, script isolation, upgrade and backup, supervision, platform and
fork maintenance, import/export/golden gating) and orders the work to build it. How the session
works today is in [README.md](README.md) ("Protocol (version 2)") and
[ARCHITECTURE.md](ARCHITECTURE.md).

**Revision 6 (2026-10-27) adds the multi-agent objective.** The owner's objective is that several harnesses (Claude
Code, Codex, OpenCode, QoderCLI) work on several projects at once, that nothing they do corrupts a project or another
agent's work, and that no client's lock blocks another client; Hydra Engine and Hydralysis may be refactored for it.
Revision 6 synthesises one design from three competing drafts (isolation first, engine concurrency, verification first)
and three judges, on four measurement streams run on the real daemon (3.9): capacity (`_logs/measA`), a lock map
(`_logs/lockmap`), 952 forced kills (`_logs/crash-C`) and a claims audit (`_logs/claims-audit`). It reverses or changes
twelve rev5 positions (2.1: one reversed, six changed, one replaced, three removed, one found false and fixed), adds decisions D35-D58, a concurrency model (3.9), a blocking-point table (3.10), resource
governance (3.11), storage integrity and the corruption oracle (3.12), per-agent views and the publish queue (4.10), the
guarantees with their tests (6.1), the chaos and soak gate and seven more gates (9.12-9.19), the Z packages and the
claims packages (8.3), and a reordered wave plan with the release mapping (5.3). **Hydra Engine is headless only: there
is no GUI and none is planned.** Nothing here is implemented; the measurement figures are single runs under foreign
load unless stated.

**Revision 7 (2026-10-28) answers an adversarial review of revision 6** (`D:/Projects/Hydra/_logs/review-rev6/`: seven
experiments on the real daemon, an ownership check and a consistency check; six blocking defects and a list of nits). The
design changes where the review was right and the revision history ("Revision 7" table) says where it was not or only
partly right and what stands. In short: a candidate generation is writable until it is verified and sealed, and
"sealed" is an explicit seal record, never `disposable:false` alone (D38, 4.6, 4.10); the daemon creates its own Job
Object and the launcher owns none, so the shared daemon outlives the harness that started it (D60); one agent-identity
rule, and the isolation guarantee GR5 stated for distinct identities only (D59); the characterization goldens mask the
scheduler capacity numbers (D62); the Hydralysis background saver is deleted and `locks.py` has an owner (D61);
exactly one package and one release for each leave stall (D63). It records the owner-delegated defaults OD8-OD14 as
decided, moves the killable script worker E7 into hydra.4 as a gated package (D64) and drops the separate interim
integrity release (OD10). It adds decisions D59-D64, the spikes gate 9.20, the declared v2-visible change V11 and
section 8.4. Nothing is implemented, and no claim of "never corrupts" or "never blocks" is made anywhere: every claim
is a gated claim (6.1).

**Revision 8 (2026-10-28) answers an independent review of revision 7** (`D:/Projects/Hydra/_logs/review-rev7/`: five
blocking items and nine others, with experiments on Job Objects, a JVM that assigns itself to a job, and 14 mutation plants
of the proof). A daemon-owned Job Object contains the daemon's children but does **not** make the daemon outlive a harness
that runs in a kill-on-close job without breakaway rights; the launch sequence is now breakaway, then WMI, then a loud
`daemon_dies_with_harness` warning, and the claim is limited to `survival:"independent"` (D65); the containment tests use
suspended decompilers and a no-job control (D60); the killable worker works on a private writable clone of a view that its
owner saved (D64, D61); `HeadlessSession.java` has the owner of the lane default (E3a); the false README sentence about the
background save has an owner and a release note (Y2); the sealed predicate is the union of three records (D66); candidate
verification runs on a clone; the boot id and the adoption of orphaned views are defined; spikes are assigned to releases;
legacy backups are adopted; the lock order of FINALIZED is stated; and the replay cost of an idle return has a per-call
threshold. It adds D65 and D66, section 2.3, and a unbackticked-name check to the proof. Nothing is implemented.

**Revision 8.1 (2026-10-28) records seven amendments of the W1 coordinator to revision 8** (section 8.5; docs only, no design
decision changes). The package-id pattern of `examples/check_ownership.py` now sees every id of the plan (X0, S1, S2 and the
Z packages were invisible) and reads `then` cells and the site table (A2); E8 also owns `LocalDatabaseItem.java`, the
private-database open path (A3); E2a may add the capability name `forkAtomic` to `Advertised.java` after E1, a declared
sequence (A4); S1 owns `src/routes/embed/how-it-works.tsx` (A5); the kept corrupt forks of `crash-C` are nine, not twelve
(A6); the `--client {stock,install}` option of `characterization_tests.py` is recorded as an E0 amendment (A7); the grep
gate of R0 is Z13a's and S1's, and X0 needs no `certification.manifest` line for files that carry an IP header (A8).

Evidence conventions. Every `File.java:line` below was read on branch `feat/session-extract`
(commit `b6df709e1e`, the tree this file is committed on); every `file.py:line` was read on
Hydralysis branch `feat/hydralysis-0.5` (commit `d0466bc`, package `src/hydralysis`, formerly
RusticRE), unless the sentence says `@589432e`: that is the W0 integration tip on `feat/w0-integration`, a
descendant of `d0466bc`, which holds `durable.py`, `tests/test_durable.py` and Y0b's widened `EngineError`
(the write-gate counts of D14, 8.2 and Appendix A and the test files of 8.1 were read there). A third base,
`@f46788b`, is the tip of that branch after the W0 follow-ups and polish (`2bf90c7`, `33cb5ee`, `49d5bb6`,
`1584f6e`, `b0b947b`, `f45821b`, `5018367`, `f46788b`), and `@8e696e2` is Y0e on `feat/w1-hydralysis`; where
the code at those bases differs from what revision 4 said, revision 5 says what the code does (8.2, 7.6, 7.7).
The `hydra.py`
lines differ between the two bases, so 7.6 and Appendix A give both; the `query.py` lines are the same at
both. The one exception is `README.md`: its line numbers are those of the design branch tip
(`design/protocol-3`), where a two-line pointer to this file was inserted at `README.md:538`, so
every README citation below that point is two lines later than at `b6df709e1e` (where it helps, the
cited README phrase is quoted so the line can be found again after the branch moves). Three further
kinds of evidence are cited by path: the characterization and baseline runs of the engine packages
(`D:/Projects/Hydra/_logs/<stream>/`), the review runs (`.../spec-review/`, `.../review-spec-rev3/`, `.../review-spec-rev4/`) and the
experiments of revisions 3, 4 and 5 (`.../spec-rev3/`, `.../spec-rev4/`, `.../spec-rev5/`: scripts and their
recorded output, 3.5, 3.8 and 7.6). Revision 6 adds the
measurement streams of 3.9 and the proof `D:/Projects/Hydra/_logs/spec-rev6/prove_disjoint_rev6.py`; its code
citations were re-read on `feat/session-extract` (`b6df709e1e`) and the Ghidra core files of 3.12 in the same tree.
Revision 7 adds the review experiments (`D:/Projects/Hydra/_logs/review-rev6/`, cited as `review-rev6/<file>`) and the
proof `D:/Projects/Hydra/_logs/spec-rev7/prove_disjoint_rev7.py`. Revision 8 adds the experiments of the next review
(`D:/Projects/Hydra/_logs/review-rev7/`, cited as `review-rev7/<file>`) and the proof
`D:/Projects/Hydra/_logs/spec-rev8/prove_disjoint_rev8.py`.
Anything not
marked that way is a proposal. A number marked *unmeasured* has no
measurement behind it on this machine: it is a starting value to be replaced by the measurements in
[Release gates](#9-release-gates). Appendix A lists the code facts the design depends on and where
each was read; Appendix B lists what the three designs it was synthesised from got wrong or left
out, as found by reading the code.

## Contents

1. [What is decided](#1-what-is-decided)
2. [Conflicts resolved, one by one](#2-conflicts-resolved-one-by-one)
    - [2.1 Rev5 decisions that revision 6 reverses or changes](#21-rev5-decisions-that-revision-6-reverses-or-changes)
    - [2.2 Rev6 decisions that revision 7 changes](#22-rev6-decisions-that-revision-7-changes)
    - [2.3 Rev7 decisions that revision 8 changes](#23-rev7-decisions-that-revision-8-changes)
3. [The engine contract](#3-the-engine-contract)
    - [3.1 Negotiation, gating and capabilities](#31-negotiation-gating-and-capabilities)
    - [3.2 `hello`/`status` identity block (v3)](#32-hellostatus-identity-block-v3)
    - [3.3 Error model](#33-error-model)
    - [3.4 Commands](#34-commands)
    - [3.5 Lanes and admission rules](#35-lanes-and-admission-rules)
    - [3.6 Script isolation](#36-script-isolation)
    - [3.7 Daemon configuration](#37-daemon-configuration)
    - [3.8 Launcher (`support/ghidra_session.py`, P1a and P1b)](#38-launcher-supportghidra_sessionpy-p1a-and-p1b)
    - [3.9 The concurrency model (revision 6)](#39-the-concurrency-model-revision-6)
    - [3.10 Non-blocking engine: every blocking point, its decision and its test](#310-non-blocking-engine-every-blocking-point-its-decision-and-its-test)
    - [3.11 Resource governance (E9, hydra.4)](#311-resource-governance-e9-hydra4)
    - [3.12 Storage integrity and failure containment](#312-storage-integrity-and-failure-containment)
    - [3.13 Revision 6 additions to the commands and the error model](#313-revision-6-additions-to-the-commands-and-the-error-model)
4. [The Hydralysis state contract](#4-the-hydralysis-state-contract)
    - [4.1 Durable IO rules (Y0a, ships first, no engine change)](#41-durable-io-rules-y0a-ships-first-no-engine-change)
    - [4.2 Store v3: the op-log and the subject record (Y1)](#42-store-v3-the-op-log-and-the-subject-record-y1)
    - [4.3 Idempotency in the client (Y0b)](#43-idempotency-in-the-client-y0b)
    - [4.4 Lineage and generations (Y2)](#44-lineage-and-generations-y2)
    - [4.5 Backups (Y2 on hydra.2/3, switched to the engine's by Y4d)](#45-backups-y2-on-hydra23-switched-to-the-engines-by-y4d)
    - [4.6 Commit as a new generation (Y2)](#46-commit-as-a-new-generation-y2)
    - [4.7 When the master generation changes](#47-when-the-master-generation-changes)
    - [4.8 Publish and merge between named views (Y3, client only)](#48-publish-and-merge-between-named-views-y3-client-only)
    - [4.9 Annotation bundles (Y1)](#49-annotation-bundles-y1)
    - [4.10 Per-agent views, the shared base, write-ahead and the publish queue (revision 6)](#410-per-agent-views-the-shared-base-write-ahead-and-the-publish-queue-revision-6)
    - [4.11 Hydralysis obligations that follow from the measurements](#411-hydralysis-obligations-that-follow-from-the-measurements)
5. [Compatibility and the release train](#5-compatibility-and-the-release-train)
    - [5.1 Every change a protocol-2 client can observe](#51-every-change-a-protocol-2-client-can-observe)
    - [5.2 Release notes (R1) must say](#52-release-notes-r1-must-say)
    - [5.3 Release mapping (revision 6)](#53-release-mapping-revision-6)
6. [Guarantees and honest limits](#6-guarantees-and-honest-limits)
    - [6.1 What may be guaranteed, and the test of each (revision 6)](#61-what-may-be-guaranteed-and-the-test-of-each-revision-6)
    - [6.2 Limits](#62-limits)
7. [Client obligations (Hydralysis)](#7-client-obligations-hydralysis)
    - [7.1 Doctor module (`doctor.py`, Y4b)](#71-doctor-module-doctorpy-y4b)
    - [7.2 Supervisor policy (`hydra.py`, Y4a)](#72-supervisor-policy-hydrapy-y4a)
    - [7.3 Commit flow (Y2, Y4d)](#73-commit-flow-y2-y4d)
    - [7.4 View publish and merge, rebase, user scripts (Y3, Y4e)](#74-view-publish-and-merge-rebase-user-scripts-y3-y4e)
    - [7.5 Capability degrade (engine hydra.2/3)](#75-capability-degrade-engine-hydra23)
    - [7.6 Lane hints, deadlines, error contract (Y4a, Y0b)](#76-lane-hints-deadlines-error-contract-y4a-y0b)
    - [7.7 The 20 tools: where each feature lives](#77-the-20-tools-where-each-feature-lives)
    - [7.8 Multi-agent obligations (revision 6)](#78-multi-agent-obligations-revision-6)
8. [Work packages](#8-work-packages)
    - [8.1 File-ownership matrix (the disjointness assertion)](#81-file-ownership-matrix-the-disjointness-assertion)
    - [8.2 Ownership of what the first reviews found unowned](#82-ownership-of-what-the-first-reviews-found-unowned)
    - [8.3 Revision 6: the Z packages, the eight ownership conflicts and the claims](#83-revision-6-the-z-packages-the-eight-ownership-conflicts-and-the-claims)
    - [8.4 Revision 7: ownership additions and what the proof checks](#84-revision-7-ownership-additions-and-what-the-proof-checks)
    - [8.5 Revision 8.1: amendments of the W1 coordinator](#85-revision-81-amendments-of-the-w1-coordinator)
9. [Release gates](#9-release-gates)
10. [Open owner decisions](#10-open-owner-decisions)
11. [Appendix A: code facts and where they were read](#appendix-a-code-facts-and-where-they-were-read)
12. [Appendix B: what the source designs got wrong or left out](#appendix-b-what-the-source-designs-got-wrong-or-left-out)
13. [Revision history](#revision-history)

---

## 1. What is decided

The engine adds **facts and gates**; Hydralysis keeps the **record**.

- **One persistent op-log, and it is the Hydralysis overlay store** (store v3, written with
  fsync, sealed, with a previous-generation fallback). It is at the same time the journal, the
  crash-recovery record and the commit source. The engine's `Journal` and `Overlay` stay in
  memory and are documented as non-durable conveniences for direct clients. No engine-owned
  write-ahead log, view store, lineage or `view_*` command family is built in this train
  (reasons and the re-open criteria: D5).
- **Commit publishes a new generation, never a modified master.** Fork the current generation
  (`fork_project purpose:"generation"`), replay the records with `before` checks inside one
  transaction, verify, force every file to disk, then append one CRC'd record to an append-only
  `CURRENT.log`. That append is the single commit point. No directory is renamed, so Windows
  open handles, Defender and indexers cannot break a publish. Generation 0 (the adopted project)
  is never written. In-place replace and automatic deletion are not part of this train.
- **Backup is a fork** (`fork_project purpose:"backup"`) with one manifest schema, one
  implementation class (`ProjectBackup`), and a self-hash. Restore is a fork from the backup to a
  new path. There is no `restore_project` and no `replace_project`.
- **The upgrade gate** refuses `open_program writable upgrade:true` on anything not provably
  disposable unless a verified backup of that project's current revision is named.
- **Admission, isolation and supervision** are extensions of the existing seams (`Scheduler`,
  `Connection`, `Caller`, `ScriptCommands`, `Session.info`), plus one new inline command,
  `health`. There is no command table and no Java fault-injection layer; **revision 6 adds a resource governor behind
  an admission seam (E9, D46)**.
- **Protocol 3 is a negotiated contract level.** The engine serves protocols 2 and 3 on one
  port. A connection that does not ask for 3 sees byte-identical replies, which is checked by the
  existing 317-request characterization goldens, and today's behaviour, except for the short list
  of changes in [5.1](#51-every-change-a-protocol-2-client-can-observe) (each there with its reason
  and its own test, because the goldens see replies only). Everything else about 3 is additive.
- **Ordering.** Hydralysis durability and commit ship first, on hydra.2/3, with no engine change.
  The engine work follows in small packages that each pass the characterization diff. In-place replace is out.
  **Revision 6 reorders the train around the owner objective (D56)**: verification and the wording pass first (W0), the
  integrity packages that fix the two real corruptions next (W1), then lanes and the shared base, robustness, the
  non-blocking core and per-agent views, the governor and the soak gate. Per-agent default views are required, not
  deferred (D43); a killable script worker (E7) is a gated hydra.4 package (D47, D64).
- **Revision 6: concurrency by construction (D36-D58).** Agents never share a mutable program: readers read a sealed
  master or generation that has no exclusive holder, each writer works in its own view (a disposable fork whose truth is
  the Hydralysis store), and the only serialisation point is a leader-elected publish queue that no reader and no view
  waits on (3.9, 4.10). The remaining shared locks are bounded, capped and listed (3.9, 3.10); the engine refuses with
  `busy` before it runs out of memory (3.11); the two real corruptions are fixed at their source and an oracle with
  planted failures guards them (3.12, 6.1). Every claim is limited to what a named test proves (D52, D58).

## 2. Conflicts resolved, one by one

Each row: what collided in the source designs or in the judges' verdicts, what is decided, and why.
"Source" means the three synthesised designs (A: minimal additive; B: robustness first; C: agent
ergonomics) and the investigation's critic.

| # | Conflict | Decision | Why |
|---|---|---|---|
| D1 | Five analyses each wanted a `hydra.3`/protocol-3/`minClient` bump with different content; the upstream merge is also called hydra.3 | **hydra.3 is the upstream merge only** (no protocol change). **hydra.4 is protocol 3**, one tag. The engine packages merge separately to one integration branch and are gated one by one; the Hydralysis pin moves once. **Revision 6 (D35): CHANGED; revision 7 (OD10, decided): the separate interim release is dropped.** The protocol-neutral integrity packages (E8, E2a) land first, in W1, but ship inside hydra.4; the tag names stay `12.3-hydra.<n>`. | The merge was golden-gated on its own (KotOR 8616/8616 identical to hydra-2; report in `_golden/baselines/hydra-3-candidate`). Mixing protocol work into it would make a decompile difference unattributable. |
| D2 | `README.md:988-992` says additions need no protocol change; all three designs still bump to 3 | The bump is kept as a **negotiated contract level**, not a break. `hello` echoes the `protocol` the client sends (the hydra.2 client already sends `protocol=2`, `ghidra_session.py:850-852`), within `[2,3]`; absent means 2. Reply keys that only a v3 client can use are produced only for a v3 connection, at the bounded list of sites in 3.1 (thirteen reply-shape conditionals, C1 to C13, enumerated there). Behaviour that a v2 client could notice is gated on the same `Client.v3()` test (six behaviour gates) unless 5.1 declares it v2-visible with a reason and a test. | A v2 connection then stays byte-identical, so the seven existing scenarios (317 requests) remain an exact regression suite for a Java code base with no unit tests. Those goldens see replies only (they exclude progress events, older-format projects and lock timing: `characterization_tests.py` docstring), so each non-reply behaviour has a behaviour test of its own (5.1). The cost is thirteen reply-shape conditionals (C1 to C13, 3.1) plus six behaviour gates (5.1). The alternative (always additive reply keys, re-record goldens under a "superset of old keys" check) is wire-compatible and is the fallback if the **reply-shape** count (13 now, checked by listing C1 to Cn in 3.1) grows past twenty or a gate needs more than `Client.v3()`; it changes no wire rule and cannot replace the behaviour gates. |
| D3 | Endpoint file and `ready` event: protocol 3 only (A), or the lowest served plus a maximum (C) | Endpoint file and `ready` carry `"protocol": 2` (the lowest served), plus `protocolMin: 2`, `protocolMax: 3`. | The stock client refuses the endpoint on inequality (`ghidra_session.py:1000`) and the `hello` on inequality (`:113`). A hydra.4 client library accepts any overlap of `[2,3]` with the daemon's range and uses the highest. So: a hydra.2/3 stock client works against a hydra.4 daemon at protocol 2; a hydra.4 client works against a hydra.2/3 daemon at protocol 2. |
| D4 | `minClient` bump now (B asked), or never | `minClient` stays `1.0.0`. The new client library is `CLIENT_VERSION 1.1.0` (something added). The one bump is reserved for the release that drops protocol 2. | Nothing is non-additive for a client that does not opt in. A bump would reject every existing client for no safety gain. |
| D5 | Persistent op-log: engine WAL/ViewStore (B, C) versus the Hydralysis store (A) | **The Hydralysis store.** No engine-owned op-log in this train. Re-open only if (a) a non-Hydralysis client needs durable engine annotations, or (b) a spike shows bulk ops (`import_types`, `import_archive`, struct) replay on a changeable view program with the same result as the fork-based working copy. **Revision 6 (D43): PRESERVED.** The engine `view_*` family two drafts proposed is rejected; the write-ahead order of 4.10 is added to the store contract. | Hydralysis never uses the engine edit path: it forks, then replays RusticQuery `apply_overlays` (`workcopy.py:352-405`, `RusticQuery.java:2305-2345`). The five native engine ops cover rename, label, comment, signature and data_type only; struct, variable, function_create/body/delete and the two bulk imports exist only as RusticQuery code. An engine log would need a second Java implementation of all of them, the biggest risk any design carried. The store already has atomic writes, a monotone revision, per-edit `by`/`at`, a subject journal, and mandatory `expect_revision` with subject-aware rebase (`revisions.py`). What it lacks is hardening (D14), `before` values, a master binding and a commit path, which this design adds. |
| D6 | Three on-disk formats for "journal" (`<project>.journal`, view op-log, `recovery/*.ops.json`) | None of the three. Journal = recovery = commit source = the store v3 record set. An optional dump of an orphaned engine journal to `<stateDir>/recovery/` (E3b, default off) exists only for direct clients. | One format means one reader and one recovery rule. |
| D7 | Two subject/conflict models (store revision plus `before` drift; seq plus subject rebase) | **One subject record** `{subject, field, before, after, seq, by, at}` inside each edit's `effects[]` (4.2). Conflict decisions use the **coarse subject** (the strings of `revisions.subjects_of`, unchanged); `field` only refines drift checks and the probe. | Existing rebase tests stay valid; a rename and a comment at one address still count as one subject for conflicts but are two effects for drift. |
| D8 | Two backup components with different manifests | One: `fork_project purpose:"backup"` implemented in a new `ProjectBackup` class (not inside `ForkCommands`, 278 lines today). One manifest schema with a `writer` field (`engine` or `hydralysis`), so the Python-written manifest used on hydra.2/3 and the engine-written one are the same format. | The commit works before the engine change (H2 in design A) and later switches writer without a format change. |
| D9 | Commit mechanism: fork+replay+publish, promote a fork's DB into `.rep`, or apply and save in place | Fork+replay+verify+publish as a **new generation**. No Ghidra-internals write, no promote, no in-place save of a canonical project. | Nothing in the commit path can corrupt the master; the one-way format step lands on the new generation only. |
| D10 | Commit point: atomic replace of `targets.json` (A), pointer record in an append log (B), `lineage.json` replace (C) | **Append one CRC'd line to `CURRENT.log` and fsync.** `targets.json` is only a cache of it. | Replace-based pointers have no integrity check and no recovery rule; an append log with per-line CRC and a "last valid line wins, a torn tail is ignored by readers and repaired by the next writer on every acquisition of the writer lock (4.1), a mid-log gap is loud" rule does. |
| D11 | **New finding, in none of the three designs:** `target["key"]` is `sha256(resolved gpr + program)` (`targets.py:114-117`) and keys the overlay store (`workcopy.py:46-47`), the working directory (`:105-106`), the view re-key (`:36-43`), the export header (`exporting.py:118`) and `stop()` (`query.py:224`). A pointer flip that changes `gpr` would orphan every store. | The target keeps a **stable `key` for life**: at lineage creation the existing key is stored in the record (`lineage.origin_key`) and `resolve()` returns it; only `gpr` follows `CURRENT.log`. `stop()` releases the programs of every generation of the lineage. | Without this, the first commit silently abandons the analyst's overlay store. |
| D12 | "Canonical" for the upgrade gate: no sidecar (A, C) or not provably disposable (B) | **Decided from the project's own fork sidecar alone, because the engine cannot see `CURRENT.log` (Hydralysis-side).** A project is disposable iff its sidecar (`<name>.fork.json`) exists, parses, has `kind == "ghidra-session-fork"` and does not say `disposable:false`. A sidecar without the field (every hydra.2/3 fork: the sidecar is built at `ForkCommands.java:246-251`) is therefore disposable: that is the hydra.2/3 meaning of a fork and the only way Hydralysis's own base forks stay upgradable. hydra.4 `fork_project` writes `disposable:true` for `purpose:"fork"` and `disposable:false` for `purpose:"generation"` and `"backup"`. A generation made **before** the engine knows `purpose` (a commit on hydra.2/3, Y2) would carry no field and look disposable, so Hydralysis rewrites that sidecar to `disposable:false, purpose:"generation", state:"candidate"` through `durable` right after the fork and **before** step 7 hashes the folder (4.6); the rewrite is part of what the manifest covers, except the `state` field (4.6 step 7b). No sidecar, an unparseable one, a sidecar write that failed (`ForkCommands.java:255-257` only warns), or any doubt: canonical. **Revision 6 (D38, D41): CHANGED.** A seal registry joins the sidecar, the sidecar gains `state`, and a writable open of a sealed project is refused. **Revision 7 (B1):** `disposable:false` means only "non-disposable" (the upgrade gate wants a verified backup) and never means "sealed"; sealed is D38's explicit record, and a candidate generation is non-disposable and still writable until it is verified. | Generations are made by `fork_project`, so "no sidecar" would exempt every generation from the second one on, and "not a published generation" is not decidable in the engine. A sidecar is an ordinary file a local process can edit: the gate is a guard against accidents (section 6). |
| D13 | Backup freshness test | The gate checks `backup.source.revision == Revision.of(project)` **and** the manifest self-hash **and** every file's size. Integrity of content is the manifest's per-file SHA-256, re-verified by the client before it relies on a backup. | `Revision.of` identifies the large database files only by size and mtime (`Revision.java:51-80`, files above `HASH_LIMIT` = 1 MiB are not hashed): it proves "this is the same saved state", not "the bytes are intact". The engine gate is a guard against accidents, not a security boundary against a local process with the same rights. |
| D14 | Durable IO: skipped (A: "proven"), engine-side CRC/WAL (B), not mentioned (C) | **First thing shipped, on hydra.2/3, no engine change:** `durable.py` (fsync before replace, write-through replace on Windows, retry on `PermissionError`, sealed JSON with a previous-version fallback, never "start empty"). | `_save_store` (`workcopy.py:72-80`) and `write_json` (`backends.py:50-54`) do `write_bytes` then `replace` with no fsync: a power cut can leave a zero-length or stale store, which is the only record on hydra.2/3. Counted, not estimated: the AST write gate Y0a shipped (`tests/test_durable.py`, at Hydralysis `589432e`) finds **41 (file, function, kind) keys** outside `durable.py` (**43 call sites**: `hydra.install Path.rename` and `crossbuild.run open(w)` have two each, `COUNTS`): 11 keys that are not records in the four files Y0a owns (downloads, corpus copies, logs, markers), **8 keys (8 call sites) in 4 record-bearing writers that stay outside `durable`** (`analysis.save_overlay`, `hydra.write_daemon_config`, `runtime._write`, `runtime_worker._write`) and 22 artifact keys (24 sites: logs, exports, staged copies). The owner of each is the table in 8.2. |
| D15 | Idempotency: `rk`/`opId` everywhere (B, C) versus none (A) | Two parts. (1) The client **stops blindly retrying non-idempotent engine calls** after `closed` (`hydra.py:268-287` retries every command once), and reconciles through the program's `overlay_state` marker instead. (2) The engine's journaled edit commands (`edit`, `rename`, `comment`) accept an optional `rk` and answer a repeat with `replayed:true` (not `apply_overlay`: the engine's overlays have no journal, 3.4). Commit and backup jobs are idempotent by their own id and intent log. | The marker already makes `apply_overlays` recoverable; the blind retry is the real hole. `rk` costs little where `expect` is being added anyway. |
| D16 | Lanes: where `save` goes; explicit hint versus inference | New **MAINT** lane for `fork_project`, `refresh`, `reopen`, `promote_overlay` and `save`. `script` is `quick` **only with an explicit `lane:"quick"` and a `timeout` of at most `quickScriptMaxS`**; no inference from the timeout or from the script's directory. The lane move is **gated on v3** (a v2 connection keeps `save` and the others in `long`, 5.1). **Revision 6 (D40): CHANGED** defaults: `maintSlots` 4, `maxLong` `max(8, CPUs)`, and the per-client cap reaches v2 (V9). | RusticRE 0.4.x already sends `timeout_s+5` (`query.py:91`) but pins hydra.2 and refuses hydra.4, so inference would help no one it could reach; and silent lane changes for unknown clients are not worth a hidden behaviour. (Judges disagreed; this is the safer reading.) |
| D17 | Replace `Scheduler`/`ImportGate` with an `AdmissionController` (B, C), or extend | **Extend.** Fair key, caps, queue info, MAINT lane and the import wait fix are changes inside `Scheduler` and `ImportCommands`. **Revision 6 (D39, D40): CHANGED** only in the waiter caps (every v3 request) and the defaults. | `laneOf(String)` is static and cmd-only (`Scheduler.java:59-69`), and `Scheduler.admit(c, cmd, m, waitMs)` (`Scheduler.java:138`) is called from two places, `Session.execute` (`Session.java:248`) and `ImportCommands` (`ImportCommands.java:112`). Lane-by-request and validate-before-wait therefore change **two** signatures, `laneOf(cmd, req)` and `admit(c, cmd, req, m, waitMs)`, and both call sites. E1 makes those edits first, as behaviour-free seams (8.1), so that no later package edits `Session.java` for them. |
| D18 | Validate before queueing (C) | **Validate-before-wait:** the request-shape checks run only when the request would otherwise have to wait for a slot, and only for a v3 connection (5.1). | A request that is admitted at once keeps today's order of errors, so no existing golden changes; a v3 request that would sit in a queue for a minute and then fail `bad_request` fails at once instead. A v2 request keeps today's order and timing exactly. |
| D19 | Dead-client release | One design, owned by E3b: bounded wait, interrupt (and cancel delivered to lock waits by interrupting the registered waiting thread, 3.5), then release regardless, **including the 600 s waits in `leaveProject`/`releaseUse`** (found in the code, in none of the designs): `Session.disconnect` passes `CLEANUP_WAIT_MS` (600 000 ms, `Session.java:52,121`) to `leaveProject`, which takes the project lock and the program's exclusive lock with that wait (`ProjectCommands.java:286-322`, `ProgramCommands.java:480-520`). A stuck holder therefore blocks `disconnect` for 10 minutes per program even if `Connection.run` stops waiting. **Revision 5 adds the other half, measured:** the leave of a plain reader takes that exclusive lock too, and while it waits behind a running reader every new shared acquirer waits behind it (fair lock), so the leave of a client that is neither owner nor writer must take no exclusive lock (3.5; built once, in E3c, D63). **Revision 6 (D37): REVERSED in role.** A bounded wait still shows a 10 s refusal (measured); the leave of every reader becomes a refcount change (E3c), and E3b stays for the legacy owner and writer paths, cancel of lock waits and the post-acquire `leaving` check. **Revision 7 (D63) fixes the owners once:** (a) the leave of an owner, writer or overlay holder of an open (legacy) program, and the 600 s waits for them: E3b, W3, hydra.4 (bounded and attributed, not removed); (b) the leave of every other client, a plain reader at any user count: E3c, W4, hydra.4. | A bounded `awaitTermination` alone would not release anything. |
| D20 | Script isolation: exclusive by default (import-export item), private instance, or trust by directory (C) | Per-request `isolation: shared|private|exclusive`, default `shared` (today). RusticQuery stays `shared`. User `ghidra_run` uses `private` **only when the working copy has nothing unsaved**, else `exclusive`. RusticQuery is pinned by an optional `scriptSha256`. No trust by directory. **Revision 6 (D47): CHANGED.** A user `ghidra_run` never runs `shared`: `private` on a clean program, `exclusive` on a view. | `private` reads the **stored** file (`getReadOnlyDomainObject`), so it cannot see unsaved shared edits. Hydralysis working copies hold their edits unsaved in the daemon (`workcopy.py:352-359`), and since revision 7 nothing saves them in the background (D61), so a private or worker run on an edited view would silently answer from the master. Found in the code, in none of the designs. **Revision 8 (D61, D64):** before a private or worker clone of a view is made, the view's owner saves the fork under the per-view lock when it has unsaved edits. |
| D21 | Wedge detection and registry | `health` inline from a watchdog snapshot; wedge decided by the client after three probes. The daemon registry is launcher-side Python; an entry is live iff the instance lock is held (`Daemon.jvm_alive`, `ghidra_session.py:969-979`). | Pid reuse cannot fool a held OS lock. No Java registry class. |
| D22 | Fault injection compiled into the engine (B, C) | **No Java fault layer.** Engine tests kill and suspend processes from outside. One test hook is allowed: a launch property `-Dghidra.session.testHooks=true` registering `debug_stall`, advertised in `hello.platform.testHooks` and turning `health.state` to `degraded`. Hydralysis commit fault points are Python (`durable.fault(name)`, a no-op unless `HYDRALYSIS_TEST_FAULT` is set). **Revision 6 (D48): PRESERVED.** `crashAt`, `failWrite` and `mutant` switches were proposed and rejected; injection is external and trigger-timed. | A `Runtime.halt` in a release binary is a hazard larger than the bug it finds. |
| D23 | Doctor in five places | One module (`doctor.py`), read-only, never starts a JVM. The engine supplies `hello.paths/platform/analysisIdentity`, `format`, `health`. | |
| D24 | Ergonomics scope (C) against the correctness spec | Adopted because each is tied to a verified defect: error `next`/`retryAfterMs`, validate-before-wait, queue info, `applied` on cancel, widened `EngineError` (`hydra.py:61-63` drops `holderInfo`, `heldMs`, queue), a fast/engine tool pool split (`mcp.py:22-23`: four workers, eight outstanding). **Not adopted:** call detach/patience as a new state next to jobs (a bounded wait that returns the engine's structured `busy` achieves "never block long" without it), reply diet, a catalog-hash freeze beyond the one epoch in Y0d. | |
| D25 | 20 tools | A target, not a cap. Nothing here needs a 21st tool. One catalog epoch (Y0d; the number that ships is **2**, because epoch 1 never left the branch and its follow-up changed one description, 7.7) adds `backend.action` values `doctor` and `backups` and an `options` bag to `backend`, `ghidra_run`, `job`; every other feature rides existing `options` bags (`type_edit` kinds, `status` `show`). Section 7.7. | Running sessions cache tool lists (`mcp.py:45`, `listChanged: False`): schema changes must happen once. |
| D26 | Per-agent default views | **Revision 6: REVERSED (D43).** Per-agent views are the default and required (owner decision). Y5 moves from W7 to W4; its precondition list becomes gates (Y3 soaked, the agent id, view eviction, Z2's per-phase cost). | Needs publish/merge to have soaked, a stable agent id (`rusticre:<pid>` today) and a measured named-view cost (the 1.4 s figure is a single unreproduced run). |
| D27 | In-place replace / restore-replace | Not built. If ever: its own capability, own fault matrix on the owner's volumes, owner decision. | Directory renames over open handles are the Windows failure the generation design avoids. |
| D28 | Retention | **No automatic deletion** of backups, generations or candidates in this train. Unfinished candidates are invisible (no valid manifest) and listed by `backend action=backups` for manual removal. **Revision 6 (D41): PRESERVED**, with one carve-out: the engine may delete staging artefacts it created whose owning process is provably dead. | Every automatic delete is a data-loss surface; the disk cost of keeping is bounded by the 50 GB ask-first rule. |
| D29 | Baseline ordering | Golden baselines are captured on the released hydra.3 install from COW or full **copies** with tree hashes before and after, before any engine package merges (the hydra-3-candidate captures already exist). | The three comparisons (12.1.4 vs hydra.2, hydra.2 vs hydra.3, after-commit vs working copy) are never mixed in one diff. |
| D30 | Test-file collisions | `daemon_tests.py` and `characterization_tests.py` get an extension loader in E0 (`examples/dt_*.py`, `examples/char_*.py`), so every later package adds its tests in its own file. | Lets packages in one wave touch disjoint files. |
| D31 | Seams: which package may edit the cross-cutting files | **Seams first, then features.** E1 (W1) builds four small registries and makes the two signature changes of D17, so that later packages in one wave never edit the same shared file: `Advertised` (capabilities, limits, policy, 3.1), `Settings` (config keys, 3.7), `Preflight` (per-command request validators, 3.5), `DbVersions` (the constants behind `dbVersions`, 3.2). Ownership per file and wave is the matrix in 8.1. | The v1 plan said `Session.java` is edited by one package per wave while E2 and E3a both needed it in W2, and E1 needed a constant that only E2 could edit (review B4). |
| D32 | Commit state: watermark or ids | **A committed-id set, not a watermark.** A record is committed iff its id is in the `ids` of a live (not reverted) commit entry; the replay set is every other record, in `seq` order (4.2). `commit` can take a subset (`only`) and `on_drift:"skip"` leaves records pending, so a single `committed_through` number could mark a skipped record as committed. | Review B2. |
| D33 | Deadline on a stalled call against a hydra.2/3 engine (revision 2 said: `session.close()` on a timer; revision 3: half-close with a FIN) | **Abandon the connection with nothing more sent, and close it late, through a leave gate** (7.6): a worker thread owns `send`/`wait`, the caller waits on its own event, `cancel` goes through the same session, then the worker and the connection are abandoned (at most 8 for user calls, 3 for the supervisor probe, counted apart); when the engine's answer arrives the worker closes the session itself, but only when this process has no read in flight on a program that entry joined. Each attempt runs on its own pool entry, a connection plus the project and program it joined (a fresh connection answers `no_project`; re-establishing the context costs about 6 ms on a quiet daemon, measured), and nothing else shares an entry. The client never relies on an EOF or a reply coming back on hydra.3, and never sends a FIN to an entry that has joined a program. | `SocketSession.close()` hangs when another thread is in `wait()` (it closes the file objects before it shuts the socket down), measured on the real 1.0.0 object on Python 3.14.7 and 3.15.0. Revision 3 chose `shutdown(SHUT_WR)`; **revision 5 withdraws it**: a FIN adds nothing the `cancel` had not done (`Connection.run` calls the same `RequestMonitor.cancel()`), and its one distinct effect is that the engine **leaves** the program when the request ends, taking the program's exclusive lock, which makes every other reader of that program wait behind a running reader (measured: a new entry's `open_program` and an already-joined entry's script fail `busy` after their wait, 3.5, 7.6). Without the FIN the same release happens when the worker closes the session after the reply (measured), at a moment the client chooses. P1b/E3b change this on hydra.4: the deadline is the library's, and a plain reader's leave takes no exclusive lock. |
| D34 | Where each Python catalog stub gets its handler (Y0d left `not_available` stubs in `api.py`; the matrix gave `api.py` to Y2 and Y4b only, two packages in W6 needed it) | **A handler registry in `api.py`, built once by Y2 (W2)**; `backups.py`, `commits.py`, `doctor.py` and `userscripts.py` register their handlers and no later package edits `api.py` (8.2). | The seams-first rule of D31 applied to the Python side; it removes the one cell that two W6 packages would have shared. |
| D35 | **Revision 6.** The release train: hydra.3 is the upstream merge only (D1), but the one real corruption found (measurement C) and the atomic fork publish are protocol-neutral and cannot wait for protocol 3 | **Four releases, one wave numbering (5.3).** (1) **hydra.3** unchanged. (2) **Hydralysis 0.5.0, "qualified"** (owner decision): client only, on the hydra.2/3 pin: Y0a-Y0e, Y1, Y2 (shared base, `_sync` fix, `integrity.py`, launch config), Y3 (publish queue), Y5 (per-agent default views), Z-packages that need no engine change, R0/S1/Z13a wording. Its README states exactly the guarantees of 6.1 that hold on hydra.3 and what is not yet proven. (3) **hydra.4**: protocol 3, E1-E7, E8, E2a, E3c, E9, X0 and the gates 9.12-9.19; **Revision 7 (OD10, decided): there is no separate interim integrity release.** E8 and E2a are protocol-neutral and land first (W1), but they ship in hydra.4 and their kill batches (9.15) are part of its gate; the tag names stay `12.3-hydra.<n>`. E7, the killable script worker, is a gated hydra.4 package (D64). (4) **Hydralysis 0.6.0** pins hydra.4 (Y4a-Y4e, Z9-Z12, Z14; label OD11). **hydra.5**: E10, E11, E12, all conditional | The three drafts disagreed on labels (A: 0.6.0/0.7.0; B: hotfix, 0.5.0, hydra.4+0.6.0; C: 0.5.0 after W3, 0.6.0). The judges agreed that the corruption fix and the Hydralysis-only work must not wait for the XL engine packages. The owner fixed "0.5.0 qualified". |
| D36 | The owner objective as testable contracts; GUI | Six contracts, each a gate (9.12-9.19): **NB** (no client's request waits on a lock another client holds, except the listed residual points of 3.9), **ISO** (no agent sees another agent's unpublished edit unless it presents the same agent id, names the shared view or uses protocol-2 shared mode, D59), **COR** (sealed and published trees and other projects are never written; a kill damages at most a disposable unpublished artefact and is detected before it can be published), **DUR** (an acknowledged edit or publish survives a process crash; power loss is not promised), **RES** (overload is refused with `busy`, never an out-of-memory, and a runaway script or decompiler fault is contained), **COMPAT** (protocol 2 byte-identical except the declared rows of 5.1). **Headless only: there is no GUI, none is planned, and stock-GUI projects are not a goal.** OD2 and every "materialise a generation for the GUI" idea are removed, as are the GUI rows of 4.7, the stock-Ghidra clause of gate 9.6 and the GUI limit of section 6 | The owner (2026-10-27): multiple harnesses at once, never corrupt, locks must not block other clients, headless only. The site claims it (hydrare.dev); `claims-audit` found 11 sentences that measurement contradicts. |
| D37 | How readers stop blocking: A (refcounted immutable snapshots plus a replica pool), B (RCU with an XL rewrite), C (sealed immutable generations) | **Sealed generations are the read path (C), refcount for every reader's join and leave (all three), and the snapshot/replica machinery is conditional.** A published generation and the adopted master are opened only read-only and never have an exclusive holder, so their readers meet no lock another client can hold. Join and leave of a reader of **any** program is a counter change (E3c: the `releaseUse` fast path of 3.5 for everyone who is not owner, writer or last user, plus a deferred, non-blocking disposal of the last user). Read replicas of one stored file for DB-bound readers (E11) and an immutable-snapshot publish for programs under analysis are **not built in hydra.4**: they depend on spike SP1 (a read-only open of the stored file while another instance saves a new version) and SP8 (replica heap and scaling), and fail back to this decision. Legacy `open` projects (an in-place owner, protocol-2 shared mode) keep their locks with the bounds of 3.5; they carry **no** non-blocking claim | Judge 1 chose A as the base, judge 2 chose C, judge 3 chose B; all three agree on refcount leave and on the dependency of A and B on unmeasured Ghidra behaviour (a snapshot pinned while an owner saves N+1 on Windows). C has no such dependency, and a failed spike must fall back to it rather than weaken the claim. |
| D38 | Sealing: A `disposable:false` sidecar, B `canonical_readonly`, C a seal registry | **One predicate, `Seals.isSealed(project)`** (E2): defined from an **explicit seal record and never from `disposable:false`**: true when (1) the engine's seal registry (`<stateDir>/seals/`, written by the new v3 command `seal_project`, 3.4) holds the project's path with the `Revision` it was sealed at, **or** (2) the project's sidecar has `purpose` `generation` or `backup` **and** `state:"complete"`, a state that only `seal_project` (a generation, after verification) or a verified `fork_project purpose:"backup"` writes, **or** (3) a `SEALED.json` marker in the project folder; **the predicate is the union of the three (D66)**, so a torn or edited sidecar cannot unseal. `disposable:false` alone is **not** sealed: it only makes a project non-disposable for the upgrade gate (D12). **Lifecycle of a generation candidate (revision 7, B1):** `fork_project purpose:"generation"` writes `disposable:false, purpose:"generation", state:"candidate"`; a candidate is writable by the one publisher that created it (an ordinary writable open with `upgrade` and the backup of the gate, replay, save; the project OS lock makes a second writable opener `conflict`) and is never shared; after the publisher has verified it (4.6 step 7, 4.10 step 4) it calls `seal_project`, which records the registry entry and rewrites the sidecar to `state:"complete"`, and from then on every writable path is refused. **`seal_project` is the commit point of the candidate's immutability** (the publish itself stays the single `CURRENT.log` append, D10); a sealed but unpublished candidate is harmless (unreachable from head, listed for manual removal, D28). A sidecar whose `state` is `candidate` or `publishing`, a missing or an unparseable sidecar is never sealed (the last two are non-disposable: an accident guard). A sealed project is refused every writable path (`open_program writable`, `analyze`, `save`, owner scripts, edits, `promote_overlay` into it, `refresh` to a writable view) with the code `sealed` for v3 and `conflict` with `details.reason:"sealed"` for v2, and `next:{cmd:"fork_project"}`. **A project with no sidecar and no seal record is not sealed** (legacy in-place use is unchanged: B's rule would have broken it). The refusal is declared v2-visible (V8, 5.1) because it can only meet projects that hydra.4 itself marked | C measured that a writable open of a pristine project changes `~index.bak` and deletes `~journal.bak`; Hydralysis never opens its master writable, and the engine now says so. On hydra.2/3 sealing is client discipline plus `integrity.py` (G1 depends on the client behaving there, stated in 6.1). **Revision 7:** revision 6 took option A's `disposable:false` as the sealed marker, which made the candidate of 4.6 step 4 and 4.10 step 3 unwritable on hydra.4 (the reviewer's B1: replay and save would be refused with `sealed`); sealed is now an explicit record and a candidate is writable until it is verified. |
| D39 | Slot and lock order: A slot-yield, B lease first, C locks before slots (R-A) | **Slot first, then locks, as in rev5 (a lock holder never waits for a lane slot, so there is no slot/lock deadlock), bounded by waiter caps; C's reorder is rejected; slot-yield is an optional, gated step.** (1) Every v3 request, hinted or not, is subject to the per-resource waiter cap of 3.5 (`lock_queue_full`), now at most `max(2, slots/4)` waiters per program lock, per project lock and per overlay lock, so one program's lock queue cannot take a lane. (2) E3c may add `Ticket.yieldSlot/reacquire` behind the setting `yieldSlots` (default **off**) only if spike SP9 (a stress test with a reserved re-entry slot) shows no deadlock and measurement B's s5 improves; until then the residual (up to the cap of waiters hold slots) is stated in 3.10 | Judge 1 (must reject C's R-A: a lock holder that waits for a saturated lane blocks every reader of its program) and judge 2 (use caps and a raised `maxLong`, not a blanket reorder) agree. Rev5 already rejected parking a slot (3.5). |
| D40 | Lanes: A four lanes with a query lane and per-project shares, C maint/script/heavy, B sub-caps | **Three lanes as in rev5 (quick, long, maint) with new defaults and the per-client running cap extended to v2.** `maxLong` default `max(8, CPUs)` (was CPUs/4, at least 2: measurement A, six slots gave a 7th client 10.2-10.5 s for a script, save and fork; 24 slots gave 87, 281 and 531 ms); `maintSlots` default 4 (was 2); the work-conserving per-key cap of 3.5 also applies to **v2** connections (a v2 client could occupy 32 parallel requests, claims-audit U2), declared as V9 in 5.1. The `lane:"quick"` hint stays trust-based (D16). All numbers are `Settings` keys and appear in `hello.limits`. **Revision 7 (D62):** the v2 `status.scheduler.long.slots` follows the new default; the v2 goldens mask it and `cc_e3a` `v2_lane_defaults` asserts it | Judge 2: ship the lane taxonomy as defaults behind settings, decided by the lane test. A fourth lane is added only if the NB10 lane test fails with these defaults. |
| D41 | Fork publish protocol: A one directory rename (`layout:"dir"`), B intent file plus marker, C `.gpr` last | **`.gpr` last, with a `state` in the sidecar, an idempotency key and a sweeper (E2a).** The fork is staged in `.<name>.fork-<id>.tmp` with an intent record (`id`, `pid`, creation time of the process, `rk`); `.rep` is moved, then the sidecar with `state:"publishing"`, then `.gpr` (the commit point: if `.gpr` exists, `.rep` and the sidecar exist), then the sidecar is rewritten and flushed: `state:"complete"` for the purposes `fork` and `view` and for a verified `backup`, `state:"candidate"` for `generation` (the copy is complete, the candidate is still writable by the publisher that made it, and only `seal_project` writes `complete` for it after verification, D38; in W1, before E2 knows purposes, every fork ends `complete`). A repeat with the same `rk` and path returns the completed fork or resumes; without `rk` a half fork the engine itself made (intent present, owner dead) is resumed or removed instead of answering a bare `conflict`. **A concurrent publisher without `rk`** (a second `fork_project` to a path whose intent names a live request; measured in review: six simultaneous forks to one destination gave one success and five bare `failed` replies whose message names a `.rep` path, `review-rev6/exp1_fork_race.json`) answers `conflict` with `details.reason:"fork_in_progress"` (intent present, owner alive) or `"exists"` (a complete fork or a foreign folder), removes only its own staging folder and never disturbs the winner; with the same `rk` it waits for the winner's result and returns it. This is declared V11 (5.1). A **lazy sweeper** (the first `fork_project` under a parent directory) removes only artefacts the engine created and can prove dead: staging folders and `.rep` without `.gpr` whose intent names a dead process, `tmp*.tmp`, `tmp*.ps` and `.ghidra.test.lock~~` older than 10 minutes; everything else is reported by `health`/`doctor`. A client-side kill is unchanged (the `finally` already cleans) | Measurement C: 12 of 162 fork kills blocked a retry (4 `.rep` without `.gpr`, 8 without sidecar), 53 left a staging folder nobody removes. **Not reproduced in review:** the reviewer's 14 trigger-timed fork kills (`review-rev6/exp2_fork_kill.json`) gave 2 absent paths and 12 complete forks (each with its sidecar) and no `.rep` without `.gpr`, so the 4-of-162 and 8-of-162 figures are C's alone; the order change is kept because the code order (move `.rep`, then `.gpr`, sidecar written afterwards, `ForkCommands.java:246-257`) opens the window, not because of the count, and the 300-kill batch of 9.15 decides whether it is closed. A's single directory rename cannot cover a destination folder that already exists (`ProjectFork.copy` accepts one, `ProjectFork.java:155-159`), so `.gpr` last is used. |
| D42 | The version-file corruption (measurement C finding 1): A (rename after header, quarantine), B (F1a flush before rename, F1b quarantine on every open), C (temporary name, `StoreRecovery`) | **E8, in two parts, both in the Ghidra core and both protocol-neutral.** (1) **The root fix is an ordering fix**: `LocalManagedBufferFile.saveCompleted` renames the pre-save file to its final name `db.N+1.gbf` first (`saveFile.renameFile(newFile)`, `LocalManagedBufferFile.java:696`) and only then calls `saveFile.setReadOnly()` (`:709`), whose `flush()` writes the header and syncs (`LocalBufferFile.java:824`, `:768-790`); a kill between the two leaves a full-size file with an all-zero header. E8 calls `flush()` (header, `raf.getFD().sync()`) **before** `renameFile`. The pre-save file is already a temporary file (C's `.part` scheme is not needed). (2) **Repair on open, never destructive, never on a read-only tree**: an invalid-magic newest `db.N.gbf` (valid files begin `2f30312c34292c2a`) in a **writable disposable** project is moved to `<name>.quarantine/` and the previous version is used (`repairs[]` in the reply and in `health`); in a sealed, published or read-only-opened project nothing is written and the open answers `corrupt_newest` with the repair hint (reading must not mutate the master). `integrity.py` (Y2) does the same for Hydralysis-owned forks on hydra.2/3 | Verified in source (above) and by measurement: deleting the zero-header newest file reopened the last acknowledged save 12 of 12. Judge 1: B's rename on a read-only open would break the master-unchanged guarantee and could race a second daemon's in-flight save. |
| D43 | Per-agent views: A (engine `view_*` family with eviction events), B (overlay or fork backend by spike), C (forks) | **Per-agent views are the default and fork-backed; there is no engine `view_*` command family (D5 stands).** A view is a Hydralysis target: `(lineage, agent id)`, created lazily at the agent's first edit; reads of an agent without a view go to the sealed master. The agent id is `options.as`; the fallback is `<client name>@<boot id>`, never a process id (judge 3: a pid breaks resume). Callers that present the same agent id share one view (D59): sub-agents of one MCP server process that pass no `as` share the process default id and therefore one view, and the skills must tell harnesses that spawn editing sub-agents to pass a distinct `options.as` for each. The engine's part is **admission** (3.11): `fork_project purpose:"view"` (a disposable fork with the owner agent and lineage in its sidecar) and every open are refused with `busy{reason:"capacity"}` before heap, native memory or disk run out. **Eviction is the client's** (Y5: LRU, idle time, `max_views`; closing the program keeps the fork on disk and the next use reopens it, about 0.6 s measured for an upgrade open); the engine never closes a view it did not open. Overlay-backed views (E10) are decided by spike SP2 and only for direct clients | Owner decision: required, not deferred (reverses D26). A showed 12 and 24 writable forks on one daemon with zero failures: about 6.7 MB live heap and 10 MB JVM private memory per view, the first limit is CPU in the native decompilers. Judge 2: an engine view family duplicates `fork_project` plus the op-log. |
| D44 | `_base` "once per master revision" (rev5 4.4) is false in the code | **One shared base per `(lineage, generation, engine release)`, built once under a cross-process single-flight lock, cloned per view (Y2).** Measured (A): the base was rebuilt for every named view (`base_upgrade` 1103, 4754, 5594 ms for views 1-3; 243-346 MB per view on NTFS); 12 processes building views at once took 8.2-9.0 s each, 15.6-18.2 s while the master's 15-16.5 s upgrade-cache build ran. `prepare` finishes the upgrade-cache build (E2 `prepare_upgrade`, a job) before the first view is created. `_sync` no longer shares one process-wide writer connection (`workcopy._sync`'s `writer.reset()` in `finally` closed it under other threads: `no_project` with 4 threads, reproduced once, cause by code reading): each view has its own pool entry with a reference-counted reset, and the per-target `.sync.lock` (up to 900 s, one writer at a time across all clients) is replaced by a per-view lock with a bound (`SYNC_LOCK_S`, 30 s) and a structured `busy`. **Revision 7 (D61):** the second writer of a fork, the background saver `workcopy_saver.py` (a separate process that reopened the fork writable and took `.sync.lock` for 120 s), is deleted, so a view fork has exactly one writer. Z1 adds the failing test first | A, measurement section on the work-copy path; all three drafts agree. |
| D45 | Publish and merge: A (disk queue, leader on an OS lock, batches of 16), B (group commit), C (FIFO build lock, batching only if measured) | **One leader per lineage, a FIFO queue on disk, batch size 1 by default (`publishBatchMax`).** `publish`/`commit` seals a changeset record (flushed) and returns a job with a position at once; the leader holds a non-blocking OS lock on `publish.lock`, builds one candidate (fork of the head generation, replay with `before` checks, verify with the oracle subset K2/K3), appends **one** CRC line to `CURRENT.log` (D10) and writes the per-changeset result. **Exactly once**: the generation's manifest records the changeset ids it applied (the committed-id set of D32), so a leader that dies after the append and before the result file is resolved by reading the manifest. Optimistic parallel builds with compare-and-swap are rejected (with 24 publishers the losers rebuild O(N) times). Batching up to `publishBatchMax` changesets per generation is switched on only if Z2/SP7 show the p95 publish latency at 12 publishers above the budget; until measured no latency figure for publish is stated | Judge 1 (single leader, manifest ids), judge 3 and judge 2 (no group commit in the first cut). |
| D46 | Resource governance: three overlapping designs | **One governor (E9) behind two seams E1 builds (`Hooks.Admission`, `Guarded`).** Details in 3.11: minimum heap 512 MB; admission by measured heap after GC with a soft and a hard watermark; a decompiler semaphore of `min(CPUs, nativeBudget/200 MB)` permits, fair per client; a Windows Job Object that **the daemon creates for itself** at start-up, with kill-on-close (E9, D60), so native decompilers never outlive the daemon while the daemon outlives its launcher (revision 6 had the launcher own the job, P1b, which kills the shared daemon when its launcher exits); decompiler crash isolation and a small circuit breaker; Throwable-safe daemon threads; admission refusals as structured `busy`. **Rejected:** per-decompiler nested Job Object memory limits through the FFM API (unproven, judge 2) | Measurement A: `-Xmx128m` fails at 12 views, `-Xmx256m` ends in `OutOfMemoryError` at 24 and the session-reaper thread dies, `-Xmx512m` is fine; the decompiler pool is unbounded (one native process per concurrent client, 4.9 GB at 24 busy views). |
| D47 | Runaway and deaf scripts | **hydra.4 bounds them and kills them: E7, a gated hydra.4 package in W5 (D64).** A user `ghidra_run` never runs `shared` (it is `private` on a clean program and `exclusive` on a view, D20), so a deaf script holds only its owner's view and one slot. Per-client caps, a wall budget (`scriptMaxS`) and a quarantine (the slot counts against its owner and `health.leakedWorkers`; the owner's `long` cap drops to 1) bound the damage; the only hard remedy, a killable worker JVM on a private writable disposable clone of the saved view (the owner saves the fork first when the view is edited, D64), is E7 with spike SP10 for its start-up and RAM cost; revision 7 (OD12, decided) builds it in hydra.4, and the claim "a deaf script is killed" waits for its gate (9.14) | All three drafts agree; `Thread.stop` is gone in JDK 25. Measured (B): a deaf script ran to its end 22 s after cancel and held its long slot. |
| D48 | Verification: C's mutant switches in the shipping jar versus external injection | **Verification first, with no test code in the release jar (D22 stands).** X0 (W0) builds the corruption oracle K1-K17 (3.12, 6.1) with **planted-violation self-tests** (a zero-header version file, a flipped byte in a sealed file, a `.rep` without `.gpr`, a missing acknowledged op, mixed generation tags, an orphan decompiler, a leaked thread; and a torn last `CURRENT.log` line that must be **tolerated**), imports the measurement scripts of A, B and C as the regression suites, and records the **red table** on hydra-3-candidate. A fix is accepted only if its test was red on the old build and is green on the new one; where no old build exists, the old class is compiled back over the new engine through `Ghidra/patch/` (the technique of the rev5 experiments), not a switch in the jar. Injection is external: kill and suspend, **trigger-timed kills** (kill X ms after the version folder listing first changes, the method that found the corruption: 2/131 random-time against 7/95 trigger-timed), kill of the native decompiler, a handle holder | Judge 2 and judge 3 reject `mutant=`/`crashAt=` (test branches in release code, and a wider upstream-merge surface). |
| D49 | What gates "no client blocks another" | **The deterministic counter first:** `health.waits.foreignBlocked` (v3, 3.4) counts waits whose holder is another client's request, and must be 0 for reads of a sealed generation and for view operations throughout the regression suites and the chaos run (K13). Replies carry `waited` (`queueMs`, `lockMs`, `slotMs`) **only when the wait was 250 ms or more**, like `queue` (C9). Latency is secondary: a threshold is fixed from a quiet-machine run (foreign load recorded below 25% CPU), is reproduced twice before it fails, and on a loaded machine is report-only | Measurement A varied 2x between identical runs under foreign load, C saw 16-24 s stalls under load, B's baselines differ between scripts (1,200 against 610 calls/s). Judge 3: never gate on loaded-machine latency; no always-on reply fields. |
| D50 | The chaos/soak gate: A (24 agents x 6 projects, 4 h, three passes), C (L0-L4, up to 8 h and 1000 kills), B (counted batches) | **Counted kill batches plus a nightly soak plus one release run (9.17).** Batches (each with the oracle and Wilson bounds): at least 400 trigger-timed save kills (200 NTFS, 200 ReFS), 300 fork-publish kills, 200 publish and promote kills, 50 daemon kills with 8 clients; a nightly soak (16 agents x 4 projects, 2 h, fault classes with minimum hit counts); and **one** release soak of 24 agents x 6 projects for at least 4 hours. No single all-or-nothing 8-hour run. A zero count over 400 trials supports "below 0.75% at 95%" (rule of three), which is the wording, never "never" | Judge 2 (reject an 8-hour, 1000-kill gate on a loaded machine), judge 1 (counts and fault hits). |
| D51 | Reply semantics and size | **Nothing is added to every reply, and no read silently changes meaning.** `waited` appears from 250 ms; `asOf`, `stale` and `lease` appear only when they differ from "the live state of the program the caller joined"; a v3 reader of a legacy-open program reads the live program exactly as a v2 reader does (A's stored-file readers with `asOf` and B's snapshot-only reads are not adopted in hydra.4, D37). The tool catalog stays at 20 tools and under 8,192 bytes (8,172 today) | Judge 3: the catalog is at 8,172 of 8,192 bytes; agents pay tokens for every reply field; a silent staleness is an agent hazard. |
| D52 | Truthful claims and who owns the website | **A wording pass before any engine work (R0, S1, Z13a, W0), a claims ledger, and an owner for the site repo.** `docs/data/claims.json` (Z13a) holds one row per claim (id, text, class, evidence path, the package whose test flips it); `tests/test_claims.py` fails when a number differs from its source (the tool catalog's 8,172 bytes against the limit 8,192 generated from `tool_table()`, the KotOR function counts 8,966 total / 8,616 internal / 60 thunks, the X0 baselines); the site build checks its copy (S2); `tools/bump_hydra.py` (R1) is extended to the site's version constants (the rev5 rule for Hydralysis pins, 5). The **wording rule** until a claim's gate passes: "serialized", "never corrupt (in the tests listed)", "tested with up to N clients", "native commands", "by function size", "when you pass `expect`"; not allowed: "never collide", "any number", "never blocks", "cleaned up at once", "a deaf script is killed" before E7's gate (9.14), "7 ms" without its size qualifier. 8.3 lists the 25 claims and the package whose test flips each | Measurement D: 11 contradicted, 14 unsupported or stale, 5 future, 14 supported claims; the site (`projects.ts:7`, `index.tsx:18/108`, `scheduling.ts:36/48`, `architecture.ts:85/95`) still carries wording that the engine README and CHANGELOG already replaced. |
| D53 | The audit's Z1-Z15 packages (49 asks without a package) and its eight ownership conflicts | **All fifteen packages are in section 8 with waves, files and dependencies; the eight conflicts and two conditionals are resolved in 8.3 (table "The eight conflicts of the audit").** Waves: Z1 W1, Z4 Z5 Z7 W2, Z2 Z3 Z6 Z8 W3, Z13b Z15 W5, Z9 Z10 Z14 W6, Z11 Z12 W7. Z2 moves from W4 to W3 (the named-view benchmark must exist before Y5 and gate 9.16). Runtime evidence and coverage (Z9, Z10, Z11) come before memory write and watchpoints (Z12), which stay fixture-only (owner decision) | Audit 5.4; judge 3 adopted its resolutions. |
| D54 | An honest interim on hydra.2/3 for the lane starvation | **Y2 sets `maxLong` and `maxQuick` when it launches the daemon** (`hydra.write_daemon_config`, from the expected number of agents, default 16), which removed the 10.2-10.5 s waits in measurement A (`maxLong` 24: script 87 ms, save 281 ms, fork 531 ms). The website wording stays qualified until hydra.4 passes 9.13 | Judge 3 (must adopt). |
| D55 | Supervisor | Auto-restart (Y4a) is enabled only when `journal.durable` is true: the store v3 write-ahead record (4.10) exists and its start-up self-test (write, kill, read) passes. The supervisor waits for process exit before restarting (TerminateProcess to exit: median 2.1 s, p95 19.5 s, maximum 39 s in the loaded runs of measurement C) and treats every hard kill as a crash | Owner decision (OD4 changed). |
| D56 | Wave order | **W0 verification and wording (E0, X0, R0, S1, Z13a); W1 seams and the two integrity packages (P1a, E1, E8, E2a, Y0e, Y1, Z1); W2 (E2, E3a, Y2, Z4, Z5, Z7); W3 (E3b, Y3, Z2, Z3, Z6, Z8); W4 (E3c, E4, P1b, Y5); W5 (E5, E9, E6, E7, R1, Z13b, Z15, S2); W6 adoption (Y4a, Y4b, Y4d, Y4e, Z9, Z10, Z14); W7 (Z11, Z12); W8 hydra.5 (E10, E11, E12).** E5 moves from W4 to W5 because E3c owns `Session.java` in W4; E4 stays in W4 after E3b. **Revision 7:** E7 moves from W8 to W5 (D64) | Judge 2: do not stack E8, E2, E3a and E3c in one wave, and do not give `Session.java` four owners without a gate per wave. |
| D57 | Cross-project isolation | Every lineage has its own `CURRENT.log`, `publish.lock`, queue, base and views; the project registry is a per-project state machine (`OPENING`, `OPEN`, `CLOSING`) in a `ConcurrentHashMap`, and **no wait for a lock happens inside a monitor** (E3b un-nests the `makeWritable` wait first, E3c replaces the registry). The only daemon-wide resources are the lanes, the import gate, the decompiler gate, heap, native memory and disk, governed fairly (3.11). K9 (every uninvolved project's tree hash unchanged) and B's s5/s13 reruns are the tests | Measurement B: an unrelated project's `open_project` took 9,421 ms; 24 lock waiters took 24 of 24 quick slots. |
| D58 | The guarantees the documents may state | Exactly GR1-GR11 of 6.1, each with the test that can fail and the release it holds in; nothing else is claimed. The honest wording for the corruption window until E8 and the batches pass: "a hard kill during a save can make that fork's newest version unreadable; the fork is repaired to its last acknowledged save by an automatic check; the master is never at risk" | Measurement C recommendation; all three judges. |
| D59 | **Revision 7 (B3).** One agent-identity rule. Revision 6 said two things: 4.10 "the fallback is `<clientInfo name>@<boot id>`, a per-process default view" and 4.11 "not passing `as` falls back to the shared view's mandatory `expect_revision`"; and GR5 promised that no agent sees another agent's unpublished edit, which is false for sub-agents that share one MCP server process (one process, one `clientInfo`, one boot id) | **The view of a call is `(lineage, agent id)`. The agent id is `options.as` when the call carries it, otherwise the process default `<MCP clientInfo name>@<boot id of the server process>`. The reserved name `shared` is a collaboration view that anyone can name explicitly. Callers that present the same agent id share one view; there is no other fallback and no hidden "shared view" fallback.** Every edit to a view carries `expect_revision` (the store's existing rule, `revisions.py`), so two callers that share an id are serialised by the store revision and the subject-aware rebase, which refuses a stale edit naming the other editor instead of overwriting it: that is conflict control, **not isolation**. **GR5 is restated** (6.1): isolation holds between distinct agent ids and between distinct processes; callers that share an id share a view. `as` rides the free-form `options` bag of `ghidra_query` and `ghidra_run` (and of `job` and `backend` for their own records), so it needs no schema change and no catalog epoch (7.7); a tool without an `options` bag (the native address tools) takes no identity and reads the master, never a view. MCP carries no per-call identity (one `clientInfo` per connection), so the only way to separate sub-agents that share a process is `options.as`; the skills, `backend help` (`OPTION_BAGS`) and Y5's test `subagents_one_process` say and show both behaviours | Review experiment of B3 and the code: `mcp.py:57` reads one `clientInfo` per connection and `hydra.py:312` labels every engine request with it, so every sub-agent of one harness process has the same default id. The guarantee must be the one a test can fail: distinct ids are isolated (K11, 24 ids), shared ids share (K11p). **Revision 8, the boot id:** it is 16 random hex digits generated when the server process starts (logged in the first `status` of a session, stored in the view record with the agent name, the pid and a lease), so it changes at every restart of the harness's MCP server and a restart would strand the pending edits of the previous process under a dead id; the adopt and resume rule of 4.10 closes that. |
| D60 | **Revision 7 (B2), corrected in revision 8.** Containment: who owns the Windows Job Object, and how the JVM gets to create one. (Survival of the daemon after its harness exits is a different question, D65.) | **The daemon creates its own kill-on-close Job Object and assigns itself at start-up; the launcher owns none.** New `S/ProcessJob.java` (E9) calls `CreateJobObjectW`, `SetInformationJobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) and `AssignProcessToJobObject(GetCurrentProcess())` through the FFM API as the first statement of `HeadlessSession.launch` (the process enters through `SessionMain.main`, which hands over to `GhidraLauncher` and so to `HeadlessSession.launch`: `SessionMain.java:42-50`, `HeadlessSession.java:97`; revision 7 said "`HeadlessSession.main`", which does not exist). Every process the daemon spawns afterwards inherits the job (measured: 4 of 4 Java-spawned `decompile.exe` were in the job, `review-rev7/exp_jvm_job.json`) and dies when the daemon's last handle to the job closes, which happens when the daemon dies. **A busy decompiler also exits by itself when its pipe closes, so only a suspended or hung one proves the job** (D48, K7, SP3(b)). The FFM API needs `--enable-native-access=ALL-UNNAMED` on the JVM command line; **P1b owns it** (it builds the JVM arguments in `Launch`, `ghidra_session.py`; E9 depends on P1b for it); without it JDK 25 only warns, but a later denial would silently disable the job. If the FFM call cannot run, `health.processJob` is `unavailable` and the fallback is an orphan sweep at start-up that kills only a `decompile` process whose parent pid no longer exists **and whose image path is under this install's `Ghidra/Features/Decompiler/os/` directory** (a path match, never another install's decompiler) | Review experiments: `review-rev6/exp7_jobobject.json` (a launcher-owned job kills the daemon with the launcher) and `review-rev7/exp_jvm_job*.json` (a JVM that assigns itself to a job: its decompilers are in the job; busy decompilers die with or without the job; hung ones survive without the job and die when the job handle closes). SP3 repeats it with the real daemon. |
| D61 | **Revision 7 (B5).** `src/hydralysis/workcopy_saver.py` (spawned by `workcopy._start_saver`, `workcopy.py:421-437`) and `src/hydralysis/locks.py` had no row in 8.1, while D44 replaces the `.sync.lock` that the saver also takes | **The saver is deleted and folded into the per-view lifecycle (Y2); `locks.py` is Y2's.** The saver is one process per target (an OS lock `.saver.lock`) that, after a 600 s debounce, reopens the fork **writable with `upgrade` and `refresh`**, calls `save` with `wait=600000` (about 35 s for 1.5 GB, holding the program the whole time) and takes `.sync.lock` for up to 120 s to record `saved_at`: a second writer of a fork and a lock holder that stalls the fork's owner, which under the per-view lock of D44 is either a second writer or a process that cannot run. Decided: a view fork is a cache whose truth is the store (4.10, W1-W4); persistence to a generation is the publish queue; nothing saves a view fork in the background. `_start_saver`, `saver-settings.json`, `.saver.lock`, `saver.log`, the `saved_at` state key, the `saved` flag of `status` (`workcopy.py:119`) and the `overlay_save_debounce_s` setting go. Eviction closes the view's program with its discard option (the edits are in the store) and keeps the fork on disk; reopening replays what the program marker shows it lost. **The one save, and the replay cost (revision 8).** A view fork is saved in exactly one case: before a private or worker script clone is made when the view has unsaved edits (D64), by the view owner's own process, under the per-view lock, in the lane that `save` has (maint for a v3 connection, G2); one writer, never a second process. Eviction does not save. Closing a view with discard means that the next call after an idle eviction replays the whole pending store onto a fresh clone, in the long lane; Z2 measures that replay at 1, 100, 1,000 and 4,096 records and the **per-call threshold is 5 s**. If the replay at N records exceeds 5 s, (a) a view with N or more pending records is **kept warm**: idle time never closes it (`viewKeepWarmRecords`, 3.7; only `maxViews` pressure and the LRU order do), and (b) the store cap of 4,096 pending records is lowered to the largest N that replays within 5 s, so publishing becomes necessary sooner. There is no 30 s contingency and no save at eviction. `locks.py` gains a typed `LockBusy(ValueError)` (fields `what`, `path`, `waited_s`, `retry_after_ms`) so the bound of the per-view lock (`SYNC_LOCK_S`) becomes the structured `busy`, and keeps `LaneLock` (the non-blocking leader lock of 4.10) | Read in the code at `627b5b5`: `workcopy_saver.py:23-69` and `workcopy.py:421-437`. The saver existed to shorten a restart; with a shared base the replay of a second edit measured 0.23 s (3.9), and the store, not the fork, is the record. Open: the replay of a full store is unmeasured (Z2 adds it). |
| D62 | **Revision 7 (B4).** Six of the seven v2 goldens record `status.scheduler.quick.slots` and `long.slots` (24 and 6 on the recording machine) in 20 places (`clients` 2, `fork_refresh` 2, `import_script` 4, `overlays` 2, `readonly` 4, `session` 6; `edits.json` has none); `slots` is not in `VOLATILE` (`characterization_tests.py:150-169`); E3a (W2) changes the long default (D40) while the goldens are E0's in W0 only and gate 9.3 requires them identical at protocol 2 | **Mask, do not re-record per package.** An E0 amendment in W0 (A1, recorded in the E0 block and in 8.1) masks `slots` when it is a key of a lane dict under `scheduler` (asserting a positive integer, like the `bytes` mask of `f47ff15934`) and re-records the six goldens once (a masking diff: only the 20 `"slots": <n>` lines change). The number itself is asserted by `cc_e3a` `v2_lane_defaults` (V9). The other v2 behaviours E3a changes are listed in V9 and are invisible to the goldens (the per-key running cap acts under contention only; `status.scheduler` keeps its v2 shape; the `maint` lane is v3-only, G2). E3a therefore owns no golden file and the disjointness proof is unchanged in that respect | The goldens are already machine-dependent (the long default follows the CPU count), so masking removes a latent false failure as well; re-recording per package would give E3a a golden file that rule 3 of section 8 freezes after W0. Accepted trade-off: a regression of the slot counts at protocol 2 is no longer caught by the goldens; `v2_lane_defaults` catches it. |
| D63 | **Revision 7 (B6).** The package that removes the leave stall was attributed three ways: 6.2 and 3.5 said E3b's fast path, BP3 said "E3b (owner/legacy), E3c (all readers)", V3 and V10 split the plain reader between them, and the W3 and W4 texts differed | **Exactly one package and one release for each stall; both are in hydra.4.** (a) **Owner and legacy leave**: the leave of an owner, a writer or an overlay holder of an open (legacy) program, and the 600 s `CLEANUP_WAIT_MS` waits of `Session.disconnect` and `leaveProject` for them: **E3b, W3**. It is bounded (`cleanupGraceS + abandonWaitS`), attributed (`holder`) and cancel-aware, **not removed**: a writer's leave needs the exclusive lock, so this stall stays in the residual list of 3.9. (b) **Plain-reader leave**: the leave of every other client at any user count (a client that is neither owner, writer nor overlay holder, including the last user, whose disposal becomes deferred and non-blocking): **E3c, W4**. It takes a counter and no program lock. The rev5 one-class fast path (`spec-rev5/exp`, `hydra-spec-rev5-patched`) is E3c's design input and is built once, in E3c, not in E3b. V3 is the dead-client release only; V10 is the plain-reader leave; the NB tests `reader_leave_no_freeze`, `last_user_leave_disposes`, `reader_leave_all` and B's `s1` (a, b, c) belong to E3c; `dead_client_lock_wait`, `abandoned_holder`, `cancel_while_waiting` and `owner_leave_bounded` belong to E3b. Until hydra.4, both stalls exist and the client's leave gate (7.6) is the mitigation | The measured fast path and the 3.9 read path are the same mechanism (a refcount), which E3c rewrites anyway (`ProgramEntry` user count); building the fast path in E3b and again in E3c would be two implementations of one thing. |
| D64 | **Revision 7 (OD12, decided); revision 8 completes it.** E7, the killable script worker, was conditional in hydra.5 | **E7 is a gated package of hydra.4, in W5, after E4 (W4) and E9.** A deaf script that holds a slot and a lock is a measured blocking point (B: ran 22 s after cancel; BP13) and hydra.4 only bounded it. E7 owns `S/ScriptCommands.java` in W5 (E4 owned it in W4: two owners in different waves, E7 depends on E4) and creates `S/ScriptWorker.java`; it edits no `Session.java`, `Health.java` or `HeadlessSession.java` (the worker count reaches `health` through a contributor list that E5 builds; kill on disconnect rides E3a's `RequestMonitor.addCancelHook` and E3b's dead-client path; the process job is E9's, D60). **Revision 8 (the worker and the saver, D61):** the worker works on a clone of the *saved* view, and nothing saves a view fork in the background, so the clone of an edited view would be stale (and `attemptedChanges` could not be measured). Therefore (1) the engine refuses `isolation:"worker"` on a program with unsaved edits (`conflict`, `details.reason:"unsaved"`, `next:{cmd:"save"}`); (2) the view's owner (Y4e, `userscripts.py`) first **saves the fork under the per-view lock when the view has unsaved edits**, bounded by `SYNC_LOCK_S`, in the lane that `save` has (maint for a v3 connection, G2); the cost is one save, measured 0.1 to 0.8 s on NTFS for KotOR (`measA/out/forkcost-ntfs.json`: `save_solo` 128 ms, 12 concurrent 324 to 779 ms); (3) the worker opens a **private, writable, disposable clone** of the saved view (a `fork_project purpose:"fork"` copy in the worker's temp directory, 137 to 214 ms on NTFS, deleted after the run), runs the script in a transaction, reports `attemptedChanges` and discards the clone; nothing of the run reaches the view. The gate (9.14) tests an **edited** view. Its gate is part of 9.14 and SP10 (start-up and RAM) must pass before it starts. **The documents keep "bounded and quarantined" (6.1, 6.2, 8.3 C5) until that gate passes.** If SP10 or the gate fails, hydra.4 is not tagged and the owner chooses between a redesign and moving E7 back to hydra.5 by a new revision of this file, in which case the documents keep "bounded and quarantined" | Owner, 2026-10-28 (delegated defaults): deaf scripts holding a slot and a lock are a measured blocking point. Review of revision 7: the clone of a stale view cannot answer for an edited one. |
| D65 | **Revision 8 (review of revision 7, blocker 1).** A daemon-owned job does not make the daemon outlive its harness when the harness runs in a kill-on-close job without `BREAKAWAY_OK`: nested assignment always succeeds, so the revision 7 fallback "if the assignment fails" was dead code | **P1b's launch sequence, and its outcome is reported.** (1) The launcher detects whether it is in a job (`IsProcessInJob(self, NULL)`) and whether that job kills on close (`QueryInformationJobObject`): launch field `caller_in_job`. (2) Not in a job: the detached spawn of today, `spawn:"detached"`, `survival:"independent"`. (3) In a job: try `CREATE_BREAKAWAY_FROM_JOB`; success: `spawn:"breakaway"`, `survival:"independent"`. (4) Breakaway denied (WinError 5, which `_spawn` swallowed, `ghidra_session.py:1058-1065`): spawn **outside the job** through WMI `Win32_Process.Create` (`Invoke-CimMethod`; the WMI provider host creates the process, so it is not in the harness's job): `spawn:"wmi"`, `survival:"independent"`. The WMI route inherits neither environment nor handles, so the launcher puts every setting on the command line (`cmd.exe /d /c` with `set` for the few variables Ghidra reads and an output redirect to the daemon log) and waits for the endpoint file as it does today. (5) If WMI fails too: stay in the job, `spawn:"stayed"`, `survival:"bound_to_harness"` and a loud warning `daemon_dies_with_harness` in the connect result (`warnings[]`), in `Daemon.health()` and in the doctor (7.1). The daemon records `health.processJob{own, inCallerJob, callerKillOnClose}`, read before it assigns itself, so the doctor can warn about a daemon that another launcher left inside a job. **Wording rule:** "the shared daemon survives the exit of the harness that started it" is claimed only for `survival:"independent"`; otherwise the documents say it dies with the harness. SP3(a) and the P1b test list both variants | Reviewer's experiment (Python stand-ins, ctypes; `review-rev7/job_exp.py`, `job_exp_wmi.py`): harness in a kill-on-close job without breakaway rights: `CREATE_BREAKAWAY_FROM_JOB` fails with WinError 5 and the child stays in the job (`job_nobreak.json`); with `BREAKAWAY_OK` the child leaves the job (`job_breakok.json`); a spawn through WMI from inside the job leaves it (`job_wmi.json`, `used_breakaway:"wmi"`). The JVM, the real launcher and the harnesses that run in such jobs are SP3's. |
| D66 | **Revision 8 (review of revision 7, item 14).** The sealed predicate of D38 depended on one sidecar field and a per-`stateDir` registry: a torn, hand-edited or lost sidecar could unseal a generation | **The seal record is written in three places and the predicate is their union: if any says sealed, the project is sealed.** (1) The registry `<stateDir>/seals/`; (2) the sidecar `state:"complete"`; (3) a marker file `SEALED.json` in the project folder (`{revision, manifestSha256, sealedAt, by}`), written by `seal_project` (on hydra.2/3 by the client through `durable`) and excluded from the manifest hash like `projectState`. The engine cannot read `CURRENT.log` (D12), so the marker file takes its place in the engine's union; the fourth witness is Hydralysis's own: every generation named by a `CURRENT.log` line is treated as sealed by the client (never opened writable), and `integrity.py` and the doctor reconcile the two (a generation named in `CURRENT.log` with no engine-readable seal record is re-sealed with `seal_project` after its manifest is re-verified). Unsealing (`seal_project unseal:true, force:true`) must remove all three. This remains an accident guard, not a security boundary (6.2); GR1 says so. Test K1u (E2 `seal_union`, planted violation X11) | A sealed project whose only protection is a file a local process can edit is unsealed by one bad write. |

### 2.1 Rev5 decisions that revision 6 reverses or changes

Revision 6 does not delete the rev5 rows above; each is marked in place and listed here with the decision that
carries the change. **REVERSED** means the rev5 position is no longer the plan; **CHANGED** means the row stands
with the stated difference; **PRESERVED** means a row someone proposed to drop stands.

Counted (revision 7 corrects the "nine" of revision 6): of the 19 rows below, **12** reverse or change a rev5
position (D26 reversed; D19, D16/D17, D20, D12, D1 and OD4 changed, six rows; gate 9.5 replaced; OD2, the stock-Ghidra
clause of gate 9.6 and the two GUI rows of 4.7 removed, three rows; the rev5 4.4 statement found false and fixed),
5 are preserved (D5, D22, D28, D9/D27, D13/D25/D32/D33/D34) and 2 are decided (OD1, OD7).

| Rev5 decision | Status | Carried by | What changed and why |
|---|---|---|---|
| D26 per-agent default views not in this train | **REVERSED** | D43, D44, D45 | Required by the owner; measured: 12 and 24 writable forks, zero failures. Y5 moves from W7 to W4 and its preconditions become gates (Y3 soaked, stable agent id, view eviction, Z2's per-phase cost) |
| D19 bounded release and interruptible waits as the fix for dead and leaving clients | **CHANGED** (reversed in role) | D37, D39, 3.10 | Measured: a bounded wait still shows a 10 s refusal (B s1); the leave of a plain reader becomes a refcount operation for **every** reader, the 600 s cleanup waits go, and E3b stays for what remains (legacy owner and shared paths, the post-acquire `leaving` check, cancel of lock waits) |
| D16 and D17 lanes (`maintSlots` 2, `maxLong` CPUs/4, v3-only per-key cap) | **CHANGED** | D40, D54 | New defaults, the per-client running cap also for v2 (V9), waiter caps for every v3 request, no fourth lane unless NB10 fails |
| D20 script isolation (RusticQuery `shared`; user scripts `private` only when nothing is unsaved) | **CHANGED** | D47, 3.6 | A user `ghidra_run` never runs `shared`: `private` on a clean program, `exclusive` on a view (only its owner waits); contained scripts on a shared program keep the documented dirty-read limit and are not claimed isolated |
| D12 "disposable" decided from the sidecar alone | **CHANGED** | D38, D41 | A seal registry joins the sidecar; the sidecar gains `state`; a writable open of a sealed project is refused (revision 7: sealed is the explicit record, never `disposable:false` alone) |
| D5 persistent op-log is the Hydralysis store, no engine `view_*` family | **PRESERVED**, narrowed | D43 | A and B wanted an engine view family; rejected. Re-open criterion (a) is not triggered. The write-ahead order W1-W4 (4.10) is added to the store contract |
| D22 no Java fault layer | **PRESERVED** | D48 | C's `crashAt`, `failWrite` and `mutant` switches rejected; injection is external and trigger-timed |
| D28 no automatic deletion | **PRESERVED**, with one carve-out | D41 | The engine may delete only staging artefacts it created whose owning process is provably dead (never a backup, generation, published fork, candidate or user file). New risk accepted: generation disk growth (OD8) |
| D1 hydra.3 is the upstream merge only | **CHANGED** | D35 | A protocol-neutral integrity cut (E8, E2a) may ship before hydra.4 (revision 7, OD10: dropped, they ship in hydra.4) |
| D9 and D27 no rename, no in-place replace | **PRESERVED** | D41 | The fork publish moves files inside a destination the engine owns; a generation is still never replaced |
| D13/D25/D32/D33/D34 | **PRESERVED** | | Backup freshness, 20 tools, committed-id set, the hydra.2/3 deadline, the handler registry are unchanged |
| OD1 backup policy | **DECIDED** | D35 | A second independent backup copy by default (`backup_min_independent` 1; the second root is configured, OD9); the 50 GB ask-first rule stays |
| OD2 generation mode against the GUI | **REMOVED** | D36 | Headless only |
| OD4 supervisor auto-restart on | **CHANGED** | D55 | On only when a durable journal exists |
| OD7 per-agent views and who may commit | **DECIDED** | D43, D45 | Views are the default; any holder of the confirmation may publish through the queue; an optional `publish_policy` can name one integrator identity (client-side) |
| Rev5 gate 9.5 (12-client soak against E0's p99) | **REPLACED** | D49, D50 | By 9.17 and the oracle K1-K17; E0's recorded failing latency is not a bound |
| Rev5 gate 9.6 stock-Ghidra clause | **REMOVED** | D36 | Headless only; the one-way format step is asserted by `format_gate.py` |
| Rev5 4.4 "`_base` once per master revision" | **false in the code**, fixed | D44 | Measured per-view rebuild |
| Rev5 4.7 rows "A GUI user saving a generation" and "The Ghidra GUI opening the original .gpr" | **REMOVED** | D36 | Replaced by process-neutral rows |

### 2.2 Rev6 decisions that revision 7 changes

Revision 7 answers an adversarial review of revision 6 (`review-rev6/`). Counted: **11** positions of revision 6 change
or are restated; the revision history ("Revision 7") maps every finding, including the ones where the review was
only partly right.

| Rev6 position | Status | Carried by | What changed and why |
|---|---|---|---|
| D38 sealed = sidecar `disposable:false` or a registry record | **CHANGED** | D38, D12, D41, 3.4, 4.6, 4.10 | sealed is an explicit record (`seal_project`, or `state:"complete"` on a generation or backup sidecar); a generation candidate is `state:"candidate"` and writable until verified; B1 |
| D41 fork publish sidecar `state` and the failing retry | **CHANGED** | D41, V11 | the `candidate` state; a concurrent publisher without `rk` answers `conflict`; the 4-of-162 kill figure is cited as not reproduced in review |
| D46 / 3.8 / 3.11 / P1b: the launcher owns a kill-on-close Job Object | **CHANGED** | D60, E9, SP3, K7 | the daemon owns its own job; the launcher owns none; B2 |
| D43 fallback agent id; GR5 | **RESTATED** | D59, 4.10, 4.11, 6.1, Y5 | one identity rule; isolation guaranteed between distinct ids and processes; B3 |
| D44 `.sync.lock` replaced by a per-view lock | **CHANGED** | D61, Y2 | the saver process is deleted; `locks.py` has an owner; B5 |
| D19 / D37 which package removes the leave stall | **RESTATED** | D63, 3.5, 6.2, E3b, E3c | E3b owner/legacy, E3c plain readers, both hydra.4; B6 |
| D40 / E3a against the v2 goldens | **CHANGED** | D62, E0 (A1), V9 | the goldens mask scheduler capacity numbers; B4 |
| D47 E7 in hydra.5 | **CHANGED** | D64, OD12 | E7 is a gated hydra.4 package in W5 |
| D35 optional interim integrity release | **CHANGED** | OD10 | dropped: E8 and E2a land in W1 and ship in hydra.4; the tag names stay `12.3-hydra.<n>` |
| D56 wave order | **CHANGED** | D64 | E7 moves from W8 to W5 |
| OD8 to OD14 | **DECIDED** | section 10 | owner delegated defaults |

### 2.3 Rev7 decisions that revision 8 changes

Revision 8 answers an independent review of revision 7 (`review-rev7/`): five blocking items and nine others. Counted: **9**
positions of revision 7 change; the revision history ("Revision 8") maps every item.

| Rev7 position | Status | Carried by | What changed and why |
|---|---|---|---|
| D60 / P1b / SP3(a) / GR9: a daemon-owned job makes the daemon outlive its harness | **CORRECTED** | D60 (containment only), D65 (survival), P1b, SP3 | nested assignment always succeeds, so a daemon inside the harness's kill-on-close job dies with it; breakaway, then WMI, then a loud warning |
| SP3(b), K7, GR9, E9 test, X9: containment tests | **CHANGED** | SP3, K7, X9, E9 | suspended or hung decompilers and a no-job control that must show survivors; a busy decompiler exits on a closed pipe anyway |
| D61 / D64 / E7: the worker clones the saved view, nothing saves it | **CHANGED** | D61, D64, D20, D47, 3.6, 7.4, E7, E4, Y4e | the owner saves the fork once before the clone; the worker uses a private writable disposable clone; the 9.14 test is for an edited view |
| E3a and the `maxLong` default | **CHANGED** | 8.1 (`HeadlessSession.java`), E3a, 8.4 | the default lives in `HeadlessSession.java`; E3a gets a W2 cell; the proof reads unbackticked names |
| the saver removal and the 0.5.0 README | **CHANGED** | Y2, Y5, 5.2, 8.1 (`README.md`) | the false sentence and the removed key get an owner and a release note |
| D38 sealed predicate, one sidecar field | **CHANGED** | D66, D38, K1u, X11 | the union of registry, sidecar and `SEALED.json` |
| D59 boot id | **CLARIFIED** | D59, 4.10, Y5 | defined; adopt and resume rule |
| 4.6 / 4.10 candidate verification | **CHANGED** | 4.6 step 7, 4.10 step 4, K3 | verification runs on a disposable clone; the candidate is never reopened |
| 9.20 / 5.3 / D64 / E7 ordering | **CLARIFIED** | 9.20, 5.3, SP table, D64 | which spikes gate which release; no contradiction on the tag |

## 3. The engine contract

All of this is the target for hydra.4. "v3" means a connection whose `hello` asked for `protocol:3`.

### 3.1 Negotiation, gating and capabilities

**Request.** The client library already sends the field:

```json
{"id":1,"cmd":"hello","token":"<endpoint token>","client":"hydralysis","harness":"claude-code","clientVersion":"1.1.0","protocol":3}
```

**Rule.** `reply.protocol` = the requested value when it is in `[2,3]`; 3 when it is larger;
2 when absent or smaller. The connection records it (`Client.protocol`, helper `Client.v3()`).
A client library that cannot speak `reply.protocol` raises `IncompatibleError` naming both
sides, as today.

**The first `hello` fixes the protocol of the connection for its life.** The first request of a
connection is handled synchronously on its reader thread (`Connection.authenticate`,
`Connection.java:187-205`, which calls `respond` itself), before the next line is read, so every
later request, progress event and reply is gated against a value that is already final and no
gating decision can race the handshake. A later `hello` runs on the worker pool (`Session.execute`,
`case "hello"`, `Session.java:230`; `hello` is not inline) and never changes `Client.protocol`
(written once, before the first reply is sent, and then read-only); it is answered with the
connection's own protocol whatever it asks for. A `protocol` that is not a JSON integer (a string,
a float, `true`, `null`) is treated as absent, i.e. 2: the request is not refused, so no existing
client can be broken by the type of the field. This is argued from the code, not run (no protocol-3
engine exists yet); E1's contract tests pin it (a second `hello` asking 3 on a protocol-2
connection answers 2 and adds no v3 key; `"protocol":"3"` answers 2).

**Endpoint file and `ready` event** (`HeadlessSession.java:187`, `:356`):

```json
{"protocol":2,"protocolMin":2,"protocolMax":3,"minClient":"1.0.0","hydraVersion":"12.3-hydra.4", "...":"..."}
```

`protocol` means "the contract a client that knows nothing newer can use". It is deliberately
the lowest served; the honest statement is `protocolMin`/`protocolMax`.

**Where v3 gating applies to replies (the complete list; everything else a v2 reply carries is
byte-identical).** Thirteen reply-shape conditionals, **C1 to C13**, one per row, each a single
`if (v3)` at the one place that builds the key (the number D2 and 5.1 refer to):

| # | The one site | v3-only content |
|---|---|---|
| C1 | `Session.info(c)` (one method builds the hello result and the `status` header) | `protocolMin`, `protocolMax`, `capabilities`, `limits`, `policy`, `paths`, `platform`, `analysisIdentity` |
| C2 | `Scheduler.describe(boolean v3)` (`status.scheduler`; E1 adds the argument, 8.1) | `maint` lane, `waiting[].position`, `waiting[].estimatedWaitMs`, `oldestWaitMs`, `longestRunningMs`, `starving`, `perKeyCap`, the per-key waiter counts, and the `{"unavailable":true,"waitedMs":250}` form (the `tryLock(250 ms)` itself is behaviour gate 5, G6) |
| C3 | the program description in `status.programs[]` | `abandonedRequests[]` |
| C4 | `Scheduler.admit`: the `m.waiting(lane + " slot", ...)` call (`Scheduler.java:155`, one-argument today) | the `queue` key of a **slot wait**: in its progress events and in `status.requests[].queue` (3.4) |
| C5 | `ImportGate.queueInfo(e)` (`ImportGate.java:309-315`) | `estimateScope:"load"` and nothing else. The `queue` object and the progress key of an **import** wait **already exist in protocol 2** (`m.waiting("import queue", q)`, `ImportGate.java:188-194`; `status.requests[].queue`, `RequestMonitor.describe`, `RequestMonitor.java:111`) and stay exactly as they are |
| C6 | `ProjectEntry.info(client)` (callers: `openProject`, `ProjectCommands.java:92`; the `project` command, `Session.java:265`; `status.projects[]`, `Session.java:333`, `:427`) | `format` |
| C7 | `ForkCommands.forkProject` success | `cost`, `warnings`, `purpose`, `manifest` (backup) |
| C8 | `ScriptCommands.script` reply | `isolation`, `lane`, `laneNote`, `attemptedChanges`, `attemptedChangesCount`, `basedOn`, `unsavedIgnored` |
| C9 | `Connection.respond`, success | top-level `queue` and `waited{queueMs, lockMs, slotMs}` (waited 250 ms or more, D49) |
| C10 | `Connection.error` (gets the client, E1) | `error.next` and `error.retryAfterMs` |
| C11 | `Connection.respond`, the `cancelled` path | `error.details.applied` and `error.details.phase` (3.3) |
| C12 | the one busy-details helper that `Scheduler.admit`, `Access.lockProject`, `ProgramEntry.acquire` and the overlay lock call | `details.reason`, `queue`, `abandoned` (`retryAfterMs` is **not** a details key: it sits in `error`, 3.3) |
| C13 | the one `bad_request` helper of `Requests`/`Preflight` | `details.field` and `allowed[]` (3.3; today a `bad_request` carries no `details`, `Json.java:36-80`) |

Keys that have **no conditional of their own** because only a v3 request can provoke them (a v2
connection cannot send the field, behaviour gate 1), so no v2 reply can contain them:
`lock_queue_full` (any v3 request, revision 6), `rk_expired` (needs `rk`), `script_changed` (needs
`scriptSha256`). The v3 error code `backup_required` is a code choice, not a reply key: behaviour
gate 6.

**Behaviour gates (six).** These are not reply shapes, so the goldens cannot see them; each has its
own v2 test (5.1): (1) every **new request field** takes effect only on a v3 connection (one helper
reads it: `purpose`, `open`, `verify`, `lane`, `isolation`, `scriptSha256`, `rk`, and `expect` on
`signature`/`data_type`; a v2 request carrying one is exactly as before); the one exception is
`backup` on `open_program`, which any protocol may present because the upgrade gate applies to every
protocol (5.1); (2) `laneOf(cmd, req, v3)` moves `save`, `fork_project`, `refresh`, `reopen`,
`promote_overlay` to `maint` only for v3; (3) the fair key `connection id + scope` applies only to a v3 connection's requests (a v2 request keeps the key
`connection id`, 3.5); **the per-key running cap reaches v2 too (V9, revision 6)**;
(4) validate-before-wait runs only for v3; (5) `describe`'s `tryLock(250 ms)` (C2 is its reply shape); (6) the upgrade gate's refusal is
`conflict` with `details.reason:"backup_required"` for v2 and the code `backup_required` for v3.

`health` is available at any protocol (a new command cannot change an old transcript).

**Capabilities** (object, name to integer version; a new minor feature raises the number and needs no
new protocol): `errorNext`, `expectAll`, `idempotency`, `laneHint`, `maintLane`, `queueInfo`,
`cancelWait`, `forkReport`, `format`, `backup`, `upgradeGate`, `scriptIsolation`, `scriptSha256`,
`attemptedChanges`, `health`, `identity`, and (revision 6, 3.13) `seal`, `forkAtomic`, `admission`, `waitsAttribution`. A client uses a feature only if its capability is present.
An engine without `capabilities` (hydra.2/3) is "degraded": 7.5.

**Who registers what.** Only E1 owns `hello`/`Session.info`, but every package adds its own
capabilities, limits and policy values. E1 therefore ships the **advertisement registry**
`Advertised.java`: all capability, limit and policy **names** are declared up front (the lists of
3.2; a registration of an unknown name throws, so a typo in a capability, a limit or a policy key
fails a test); a package **enables** its own capability from a class it owns
(`Advertised.capability("queueInfo", 1)` in the `Scheduler` constructor; `limit("maxMaint", supplier)`,
`policy("requireBackupForUpgrade", supplier)` likewise) and never edits `Session.java`.
`Session.info(c)` renders `capabilities`, `limits` and `policy` from the registry, in declaration
order, so key order is stable. The v3 hello golden therefore changes **deliberately once per wave**,
and not only in `capabilities`: `limits` and `policy` grow too (E3a: `maxMaint`, `quickScriptMaxS`,
`maxRunningPerKey`; E3b: `cleanupGraceS`, `abandonWaitS`; E2: `requireBackupForUpgrade`) and
`platform.testHooks` appears in W4 (E5). To keep one package from re-recording another's golden,
`char_e1.py` compares **`capabilities`, `limits` and `policy` as required subsets** (every key E1
itself sets must be present with its value; further keys are allowed and not compared), **masks**
`paths`, `platform` and `analysisIdentity` (hashes, build date, versions and machine facts) and
compares everything else exactly; each later package asserts its own names and values in its own
`char_<package>.py`, `platform.testHooks` is asserted only by `dt_e5`/`cc_e5`, and R1 records the full
release golden of the whole hello. A capability a merged package does not enable is absent, which
is what a client must handle anyway (7.5).

### 3.2 `hello`/`status` identity block (v3)

New keys are appended after `memory` and before `projects` (their order is part of the v3 golden):

```json
{
  "protocol": 3, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3",
  "...": "existing keys unchanged", "memory": {"usedMb": 310, "committedMb": 700, "maxMb": 8192},
  "protocolMin": 2, "protocolMax": 3,
  "capabilities": {"errorNext":1,"expectAll":1,"idempotency":1,"laneHint":1,"maintLane":1,"queueInfo":1,
                   "cancelWait":1,"forkReport":1,"format":1,"backup":1,"upgradeGate":1,
                   "scriptIsolation":1,"scriptSha256":1,"attemptedChanges":1,"health":1,"identity":1},
  "limits": {"maxQuick": 16, "maxLong": 4, "maxMaint": 2, "maxImports": 2, "quickScriptMaxS": 60,
             "cleanupGraceS": 15, "abandonWaitS": 5,
             "maxRunningPerKey": {"quick": 8, "long": 3, "maint": 1}},
  "policy": {"requireBackupForUpgrade": true, "requireExpect": false},
  "paths": {"stateDir": "F:\\...\\state", "instance": "rusticre", "endpointFile": "...", "logFile": "...",
            "scriptPath": [], "tmpDir": "...", "upgradeCacheDir": "...", "install": "..."},
  "platform": {"os": "Windows 11", "osVersion": "10.0.26300", "arch": "amd64", "cpus": 16,
               "javaVendor": "Eclipse Adoptium", "javaVersion": "25.0.4", "maxHeapMb": 8192,
               "fileSystems": {"stateDir": "ReFS", "tmpDir": "NTFS", "upgradeCacheDir": "ReFS"},
               "cow": {"stateDir": true, "tmpDir": false}, "testHooks": false},
  "analysisIdentity": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3", "buildDate": "...",
                       "dbVersions": {"program": 33, "dataTypes": 3},
                       "decompiler": {"path": "...\\decompile.exe", "sizeBytes": 0, "sha256": null}},
  "projects": []
}
```

- `limits` values shown are examples; real ones are the configured slots.
- `analysisIdentity.decompiler.sha256` is `null` until a background hash (computed once, cached
  by path, size and mtime) finishes; `hello` never waits for it.
- `dbVersions.program` is read reflectively from `ProgramDB.DB_VERSION`. Today that read is
  `UpgradeCache.currentDbVersion()`, **private static** (`UpgradeCache.java:1056-1065`, `-1` on
  failure, stored in `CURRENT_DB_VERSION` at `:107`); E1, which needs it first, moves it into the
  package-visible holder `DbVersions.program()` (same code, same `-1`) and makes `UpgradeCache` call
  it, so E2 builds on a constant E1 already owns (8.1). A `-1` is reported as `null`, `health.state` is `degraded`, and
  the DB-version release gate (9) fails. `dbVersions.dataTypes` is `null` until it is read and
  tested against 12.1.4 data (E2); it is never guessed. `DbVersions.java` is created by E1 with
  `program()` and a `dataTypes()` that returns `null`; E2 fills `dataTypes()` in W2 (8.1 gives it the
  W2 cell of `DbVersions.java`, so the registry needs no other mechanism).
- `cow` reuses `ProjectFork.clones` (`ProjectFork.java:138-141`): Windows and ReFS only. No other
  copy-on-write file system is claimed.

### 3.3 Error model

Existing codes and their meanings are unchanged (`SessionException.java:27-51`). Additions:

| Code | When | `details` (besides the ones named) |
|---|---|---|
| `backup_required` | `open_program writable:true upgrade:true` on a non-disposable project whose program is in an older or unknown format, without a valid `backup`. A **v2** connection gets the existing code `conflict` with `details.reason:"backup_required"` (and the same other details), the code its sibling refusal already uses (`ProgramCommands.java:428-431`), so protocol 2's error vocabulary does not grow | `project`, `program`, `format`, `suggest:"fork_project purpose backup"` |
| `script_changed` | `scriptSha256` does not match the script file | `expected`, `actual`, `script` |
| `bad_request` with `details.field` | unchanged code; v3 adds `field` and `allowed[]` where the value set is closed (`lane`, `isolation`, `purpose`, `verify`), and `field:"expect"` for `requireExpect` (conditional C13, 3.1) | |
| `bad_request` with `details.reason:"rk_expired"` | an `rk` whose multi-op entries were partly evicted from the journal (3.4); only a request that carries `rk` (v3) can get it | `rk`, `foundOf`, `expectedOf` |

`busy` gains `details.reason` (`slot_wait`, `lock_wait`, `lock_queue_full`, `abandoned`) for v3
(conditional C12). `lock_queue_full` answers any v3 request (revision 6, D39; rev5 limited it to
requests that carry the v3-only `lane:"quick"`). `cancelled` gains `details.phase` (`queued` for a slot wait, `lock_wait`, `running`)
and, for the commands listed below, `details.applied`, both for v3 (conditional C11).
`conflict` for `expect` on `signature` and `data_type` (v3 only, 3.4) has the same shape as for name and comment
(`reason:"changed"`, `address`, `field`, `expected`, `current`, plus `lastEdit` and `holderInfo`
when the journal knows the editor). The fields are `"signature"` and `"type"`.

**v3 error additions** (inside `error`, next to `code`, `message`, `details`):

- `retryAfterMs`: **the one location is `error.retryAfterMs`** (a sibling of `details`, never inside
  it; 3.1, 3.5 and 7.6 all mean this key). Present when waiting can help (`busy`). From the lane's
  median hold time or the lock holder's history; clamped to `[250, 10000]`; `1000` when there is no
  history.
- `next`: a ready request in the same shape as the existing `suggestion` objects, for the cases
  where the engine knows the move. `details.suggest` keeps its string vocabulary unchanged.

Examples (all v3):

```json
{"id":7,"ok":false,"error":{"code":"busy","message":"all 4 long slots are in use (a:b script X.java); retry, or pass a longer \"wait\"",
 "details":{"reason":"slot_wait","lane":"long","slots":4,"queued":3,"waitedMs":10000,"running":["a:b script X.java"],
            "queue":{"lane":"long","position":3,"ahead":2,"estimatedWaitMs":null,"estimate":true}},
 "retryAfterMs":5000},"ms":10003}
```

```json
{"id":9,"ok":false,"error":{"code":"backup_required","message":"swkotor.exe in F:\\...\\kotor was saved by an older Ghidra (program database version 32, this engine 33); upgrading it is one-way and the project is not a disposable fork",
 "details":{"project":"p1","program":"p1:/swkotor.exe","format":{"programDb":{"min":32,"max":32,"current":33},"upgradeRequired":true,"oneWay":true},"suggest":"fork_project purpose backup"},
 "next":{"cmd":"fork_project","project":"p1","purpose":"backup","open":false,"path":"<a folder for the backup>","verify":"hash"}},"ms":4}
```

```json
{"id":12,"ok":false,"error":{"code":"conflict","message":"the signature at 0x401000 is 'void f(void)', not the expected 'int f(int)': someone changed it since you read it",
 "details":{"reason":"changed","address":"0x401000","field":"signature","expected":"int f(int)","current":"void f(void)",
            "lastEdit":{"seq":41,"op":"signature","client":3,"name":"hydralysis","harness":"codex"},
            "holderInfo":{"client":3,"name":"hydralysis","harness":"codex","command":"edit","seq":41},"suggest":"reread"},
 "next":{"cmd":"decompile","address":"0x401000"}},"ms":2}
```

```json
{"id":15,"ok":false,"error":{"code":"cancelled","message":"cancelled while queued for a long slot",
 "details":{"phase":"queued","applied":false}},"ms":812}
```

`details.applied` on `cancelled` is present for `rename`, `comment`, `edit`, `apply_overlay`
(the engine's overlay command: always `false`: they are transactional and cancel only reaches them
while queued or before the transaction), for `script` in owner mode (`applied` = the program's modification number moved,
the existing `changed`), and for `save` (`applied:false`: the stored file is untouched until the
save completes). For other commands the key is absent, not guessed.

### 3.4 Commands

#### `health` (new, inline, any protocol)

Answered on the reader thread like `ping` (add to `Session.isInline`, `Session.java:219-221`) from
a snapshot published by a watchdog thread. It never takes the scheduler lock or any project lock.

```json
{"id":3,"cmd":"health"}
```

```json
{"id":3,"ok":true,"result":{
  "state":"ok","pid":18220,"uptimeMs":3600000,"protocol":3,
  "tick":{"n":3601,"ageMs":420,"lateMs":3},
  "schedulerLockOk":true,
  "lanes":{"quick":{"inUse":1,"queued":0,"oldestWaitMs":0,"longestRunningMs":812,"starving":false},
           "long":{"inUse":2,"queued":3,"oldestWaitMs":41000,"longestRunningMs":600000,"starving":true},
           "maint":{"inUse":0,"queued":0,"oldestWaitMs":0,"longestRunningMs":0,"starving":false}},
  "deadlocked":[],
  "abandoned":[{"program":"p1:/swkotor.exe","cmd":"script X.java","runningMs":412000,"client":"a:b (gone)",
                "stack":["java.lang.Thread.sleep(Native Method)","..."]}],
  "memory":{"usedMb":310,"committedMb":700,"maxMb":8192},"testHooks":false},"ms":0}
```

- `state`: `ok`; `degraded` (an abandoned holder exists, `dbVersions.program` unreadable, or
  test hooks on); `suspect` (the watchdog tick is older than `watchdogStallMs`, or the scheduler
  lock could not be taken in 200 ms, or `ThreadMXBean.findDeadlockedThreads()` returned threads).
  The engine never says `wedged`: the client decides (7.2).
- `tick`: a daemon thread increments `n` once a second and records its own scheduling lateness.
- `schedulerLockOk`: `tryLock(200 ms)` on the scheduler lock. `status` is changed the same way:
  `Scheduler.describe()` takes `lock.lock()` unconditionally today (`Scheduler.java:285-290`), so a
  held scheduler lock hangs `status` too and `status` cannot be a health check. For a **v3** connection `describe`
  becomes `tryLock(250 ms)` and returns `{"unavailable":true,"waitedMs":250}` when it fails; a v2
  `status` keeps the unconditional lock (G6, 5.1).
- `starving`: `queued > 0` and `oldestWaitMs > starveMs` (30 000 by default).
- `stack`: at most eight frames of the abandoned thread, so an operator can see what it is doing.
- Never claims a long request is a wedge: lane figures are informational.

#### `open_project`, `project`, `info`: `format` (v3)

```json
"format": {"programDb": {"min": 32, "max": 32, "current": 33}, "dataTypeDb": null,
           "upgradeRequired": true, "oneWay": true, "newerThanEngine": false,
           "programsScanned": 1, "truncated": false,
           "engine": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3"}}
```

- Computed by a new static `ProjectFormat` from the same reads as `UpgradeCache.olderFormat`
  (`UpgradeCache.java:986-1042`): the program table's `DB Version` and `Language Version` of
  each program, read from the database header **without opening the program**, cached per
  project `Revision`. At most 64 programs are scanned (`truncated:true` beyond that).
- **Correction to the source designs:** `olderFormat` swallows `IOException` and
  `RuntimeException` and returns `null`, which callers read as "current"
  (`UpgradeCache.java:1032-1036`), and `currentDbVersion()` returns `-1` on failure so that
  `stored < CURRENT_DB_VERSION` is never true. `ProjectFormat` must distinguish
  **unknown** from **current**: an unreadable header or a `-1` constant yields
  `upgradeRequired:null` and the gate treats null as required. `olderFormat` is refactored to
  return the stored numbers (`readStored`) and keep its string for existing callers.
- `newerThanEngine:true` when any stored version exceeds `current`: the engine cannot read it.
  Backups and generations written by a newer engine are detected here.
- It never opens a program and writes nothing; a test checks the project tree hash before and
  after (E2).

#### `open_program` with `writable:true, upgrade:true`: the gate

Added request field `backup`: the path of a backup's `backup.json` (schema below). It is read at any protocol, because the gate applies to every protocol.

```json
{"cmd":"open_program","project":"p2","path":"/swkotor.exe","writable":true,"upgrade":true,
 "backup":"F:\\backups\\kotor\\20261027T143015Z-3fa9c2d1-pre-commit\\backup.json"}
```

Rule (`ProgramCommands.openWritable`, `ProgramCommands.java:408-439`, before `df.getDomainObject`
at `:426`): refuse with `backup_required` when **all** hold: `upgrade` is true; the project is
not disposable (D12); `ProjectFormat` says the program is older or unknown; no valid `backup`.
A `backup` is valid when: it parses; `format == 1`; `kind == "ghidra-session-backup"`;
`verify.ok == true`; `selfSha256` matches the engine's recomputation; `source.revision` equals
`Revision.of` of the project being opened; and every listed file exists with its recorded size.
On success the entry records `upgradeBackup` and a later `save` stamps its comment
`Hydra <release> upgrade from <stored version>; backup <id>`. The `requireBackupForUpgrade`
switch (default true, config and flag) turns the gate off. Opens of forks (`disposable:true`) and of
upgrade-cache copies keep today's path; read-only opens never write and are unchanged.

This gate is **declared v2-visible, not gated** (5.1): a request that used to succeed on a
canonical older-format project is refused (with `conflict` for a v2 connection, 3.3), because
protecting the canonical project is the point and a gate only a v3 client meets would protect
nothing from the clients that most need it. It enforces what `README.md:1011-1014` already tells
people to do by hand ("do it in a copy"). The 317-request goldens cannot see it (they use no
older-format project), so a v2 behaviour test against the legacy fixture covers it (5.1). Hydralysis
itself only upgrades disposable forks (`workcopy.py:312, 377, 394`), so it is unaffected until commit.

#### `fork_project`

Existing fields: `project`, `path` (destination folder or `.gpr`), `name`, `mode`
(`auto|copy-on-write|full`), `writable`, `maxCopyMb`, `wait` (`ForkCommands.java:54-103`).
New request fields (read only on a v3 connection, 3.1; a v2 request carrying one behaves as today):

| Field | Meaning |
|---|---|
| `purpose` | `fork` (default), `backup`, `generation`. Recorded in the sidecar. `fork`: `disposable:true`. `generation`: `disposable:false, state:"candidate"`, the candidate of a commit: **writable by the publisher that created it until `seal_project` seals it** (D38). `backup`: a backup, `disposable:false`, `state:"complete"` (sealed) once its `verify` passed. `view` (3.13): `disposable:true`. |
| `open` | default `true`. `false` skips registering the fork (required for `backup`). |
| `verify` | `none`, `size`, `hash`; only for `backup`; default `hash`. |

Example, a backup:

```json
{"cmd":"fork_project","project":"p1","path":"F:\\backups\\kotor\\20261027T143015Z-3fa9c2d1-pre-commit",
 "name":"kotor","purpose":"backup","open":false,"verify":"hash","mode":"auto"}
```

v3 reply additions (the success reply today has `method`, `cloned`, `clonedBy`, `bytes`, `files`,
`copyMs`, `freeSpaceUsedBytes`, `depth`, `sidecar`, `ms` and **no** file-system fields; those exist
only in refusals, `ForkCommands.java:262-277` against `:174-197`):

```json
{"project":null,"path":"F:\\backups\\kotor\\2026...","purpose":"backup","method":"clone","cloned":true,
 "cost":{"bytes":128000000,"mb":122.1,"files":14,"sameVolume":true,"sourceFileSystem":"ReFS",
         "destinationFileSystem":"ReFS","cloneCapable":true,"destFreeBytes":91000000000},
 "warnings":["a block clone shares blocks with its source: it protects against a bad commit, not against loss of the volume"],
 "manifest":{"path":"F:\\backups\\kotor\\2026...\\backup.json","sha256":"...","verified":true,"files":14},
 "sidecar":"F:\\backups\\kotor\\2026...\\kotor.fork.json","ms":912}
```

- `cost` is `ProjectFork.Cost.json()` unchanged (`ProjectFork.java:101-109`).
- `warnings[]` states a fork that is a full copy (`cloneCapable:false`: file system and size)
  and, for a backup, `independent:false` (same volume and cloned).
- A backup runs in the MAINT lane (3.5; for a v3 connection, 5.1). It keeps every existing
  guarantee: it is first copied into `.<name>.fork-<hex>.tmp` and moved into place
  (`ProjectFork.java:160-179`), checks `Revision.of` before and after (`ForkCommands.java:200-215`),
  refuses a source another process holds writable, and never overwrites. A cancelled or failed
  backup leaves no project in the destination.
- `verify:"hash"` hashes every file of the copy **and** of the source after the copy, and
  compares. **A failed verify is a failed backup, with one rule for both:** the engine removes
  its own copy exactly as it already does when the source changed during the copy
  (`ForkCommands.java:205-214`: "the copy was removed"), writes no `backup.json`, and answers
  `failed` with `details.verify:{ok:false, mismatches:[{path, expected, actual}]}` (at most 20
  entries). So a published `backup.json` always says `verify.ok:true`; the gate's check of that
  field is a defence, not a state. (The Hydralysis writer on hydra.2/3, 4.5, cannot remove an
  engine-made fork without breaking D28; it simply never writes the manifest, and the folder stays
  invisible and listed by `backups` for manual removal.) Cost: one more read of the project from
  each side (*unmeasured*; KotOR is 122 MB; the 1.5 GB benchmark program is the stress case).
- The sidecar (`.fork.json`, format 1) gains `purpose`, `disposable`, `manifest` and `state`. **Two different questions, two
  different fields (revision 7, B1):** `disposable:false` answers "does an upgrade need a verified backup?" (D12) and says
  nothing about writing; "sealed" (no writable path at all, D38) is a seal-registry record or `state:"complete"` on a
  `generation` or `backup` sidecar. A `generation` fork therefore ends `state:"candidate"` (writable by its publisher),
  and `seal_project` turns it into `state:"complete"` after the publisher verified it; a `backup` ends `complete` when its
  `verify` passes.

#### Backup manifest, `backup.json` (one schema, two writers)

Written last, after the files, in the backup folder; never modified afterwards.

```json
{
  "format": 1, "kind": "ghidra-session-backup", "writer": "engine",
  "id": "20261027T143015Z-3fa9c2d1-pre-commit", "purpose": "pre-commit",
  "createdAt": "2026-10-27T14:30:15Z", "createdBy": {"client": "hydralysis", "harness": "claude-code"},
  "source": {"gpr": "F:\\...\\kotor.gpr", "name": "kotor", "revision": "3fa9c2d1aa01bb42",
             "lineage": "L-9c1e", "generation": 2},
  "engine": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3",
             "dbVersions": {"program": 33, "dataTypes": 3}},
  "stored": {"programDb": {"min": 32, "max": 32}, "programs": 1, "scanned": 1, "truncated": false},
  "files": [{"path": "kotor.gpr", "size": 1234, "sha256": "..."}, {"path": "kotor.rep/...", "size": 0, "sha256": "..."}],
  "filesetSha256": "...",
  "copy": {"method": "clone", "sameVolume": true, "sourceFileSystem": "ReFS", "destinationFileSystem": "ReFS",
           "independent": false, "ms": 812},
  "verify": {"level": "hash", "ok": true, "at": "2026-10-27T14:30:17Z", "sourceRevisionAfter": "3fa9c2d1aa01bb42"},
  "selfSha256": "<sha256 of the canonical form (below) of this object without selfSha256>"
}
```

- `writer` is `engine` (E2) or `hydralysis` (the Python path used on hydra.2/3 in Y2). The
  schema, hashes and self-hash rule are identical, so a backup made by either is accepted by
  either.
- **Canonical form** (what `selfSha256` and `filesetSha256` hash; both writers must produce the
  same bytes, so it is pinned and does not rely on a library default). UTF-8 without a BOM; no
  whitespace outside strings; separators `,` and `:`; object keys sorted by code point (every key
  of a manifest is fixed ASCII, so code-point and UTF-16 order agree); numbers are integers only
  (no floats, no exponents: sizes and counts fit in 2^53); strings escape exactly the quote, the
  backslash and the control characters U+0000 to U+001F (as `\b \t \n \f \r` where those exist,
  else `\u00xx` with lower-case hex) and **nothing else**: `<`, `>`, `&`, `'`, U+007F and every
  non-ASCII character, including U+2028 and U+2029, are written literally as UTF-8; an unpaired
  surrogate is refused **in a manifest** (it has no UTF-8 form, and a manifest is verified by two
  languages). `filesetSha256` is the sha256 of the canonical form of the `files` array.
  Python writes it with `json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
  sort_keys=True).encode("utf-8")`. Gson cannot be configured to this form (even with
  `disableHtmlEscaping()` it escapes U+2028 and U+2029, and it does not sort keys), so the engine
  writes the manifest with a small canonical serializer in `ProjectBackup` instead of Gson.
  **Test (required, both writers):** a manifest whose `files[].path` holds non-ASCII (an accented
  letter, a CJK name, a supplementary character such as U+1F600) and U+2028 is written by the engine
  and by Python, each is verified by the other, and both match one fixed vector
  (`examples/vectors/canonical-manifest.json` with its expected sha256) checked in both languages.
  The store `seal` and `bundle_sha256` (4.1, 4.9) use the same form but are Python-only, so they may
  contain floats (Python's `repr`) **and tolerate an unpaired surrogate** (Y0a's `canonical()` encodes
  with `surrogatepass`, so a lone surrogate that came from a bad decode in an analyst's note does
  not make the store unwritable; decided in revision 3, a deviation from "refused" that is confined
  to forms nothing outside Python verifies).
- `independent` is true only for a real copy on a different volume. A block clone on the same
  volume is `false` and the doctor says what that means.
- The files are not touched after writing (read-only attribute set best-effort). Further copies
  of the same backup are recorded in Hydralysis's own append log (4.5), not by rewriting this file.

#### `edit`, `rename`, `comment`: `expect` and `rk`

`expect` already exists for rename, label and comment (`Operations.java:48-60`, calls at `:229,
237, 242, 271`). It is added to the two ops that already compute the old value and never compare
it: `signature` (`oldSig`, `:157`) and `data_type` (`oldType`, `:186`), about six lines. Today a
request that carries `expect` on those two ops is **silently ignored**, and the goldens contain no
such request (their `expect` steps are `rename` and `comment` only), so enforcing it for every
protocol would turn a succeeding v2 request into a `conflict` with nothing to catch it. It is
therefore **gated on v3** (behaviour gate 1, 3.1): on a v2 connection `expect` on `signature` and
`data_type` stays ignored, and a v2 behaviour test pins that (5.1).

```json
{"cmd":"edit","program":"p1:/x.exe","ops":[
  {"op":"signature","address":"0x401000","signature":"int f(int a)","expect":"void f(void)"},
  {"op":"data_type","address":"0x403000","type":"char[16]","expect":null}],"rk":"c-4f2a9e"}
```

`expect` is the old signature text (as `getPrototypeString()` renders it) or the old type's
display name; `null` means "no defined data". `withLastEditor` (`EditCommands.java:49-70`) is
extended: today it maps field `name` to `lastAt(.., "name")` and everything else to
`"comment:..."`, which is wrong for `signature` and `type`; it must map them to the journal's
`signature` and `data_type` fields (`Journal.fieldOf`, `Journal.java:117-125`, which returns the
op name for everything but `rename`/`label` and `comment`; `Journal.lastAt`, `:103-114`).

`config requireExpect` (default `false`; applies to v3 connections): shared-writer edits without
`expect` get `bad_request` with `details.field:"expect"`. It is a guard for direct clients; Hydralysis enforces
`expect_revision` itself. `struct` and `variable` edits are not engine ops, so their
compare-and-set remains `verify_before` inside RusticQuery (4.2). This gap is stated, not hidden.

`rk` (string, at most 64 characters; v3 only) on `edit`, `rename`, `comment`: the journal entry
stores it. **Not `apply_overlay`**: the engine's overlay commands have no journal at all
(`OverlayCommands.java` and `Overlay.java` contain none), so there is nowhere to store a key, and
`OverlayCommands.java` is not in E1's files; idempotency of the Hydralysis `apply_overlays` script
action is the `overlay_state` marker (D15, 4.3). The owners are E1 (`EditCommands`, `Journal`;
`Session.java:282` and `:290` are the rename and comment dispatch). What a journal entry stores is a deep copy of the **per-op result**
(`EditCommands.journal`, `EditCommands.java:76-88`: the op's own fields such as `address`, `old`,
`new`, `op`, plus `seq`, `at`, `client`, `name`, `harness`, `cmd`, and now `rk`); it does **not**
store the reply envelope (`applied`, `seqs`, `unsavedEdits`). A second request with the same `rk` on
the same program is therefore not applied and answers a **reconstructed** reply:
`{"replayed":true, "seq":<original seq>, "result":<the stored per-op result>}`, and for a multi-op
`edit` `{"replayed":true, "program":..., "applied":n, "seqs":[...], "results":[<stored results>]}`
with `unsavedEdits` recomputed. It promises the stored fields, not byte equality with the first
reply. If part of a multi-op request's entries has been evicted from the journal, the whole `rk` is
treated as unseen and the answer is `bad_request` `rk_expired` (never a partial replay). The window
is the in-memory journal (cap 200 000 entries, `Journal.java:35`), so it does not survive a daemon
restart; that is consistent, because a restart also loses the unsaved edit it would deduplicate.
It is not a durability feature.

#### `script`: lane, isolation, pinning, reply

```json
{"cmd":"script","script":"RusticQuery.java","program":"p1:/x.exe","args":["{...}"],
 "timeout":35,"lane":"quick","isolation":"shared","scriptSha256":"<sha256 of the script file>","wait":180000}
```

- `lane`: `quick` or `long`. `quick` is honoured only when `0 < timeout <= quickScriptMaxS`
  (default 60, hard maximum 120); otherwise the request stays `long` and the reply carries
  `laneNote`. Absent means `long` (today). `Scheduler.laneOf(cmd)` becomes
  `laneOf(cmd, req, v3)` and the decision (lane and note) is stored on the request's
  `RequestMonitor` by E3a, who owns it; E4's `ScriptCommands` only copies `lane` and `laneNote`
  from the monitor into the reply, so no two packages write the same field (8.1). The deadline is
  enforced by `m.deadline(...)` (`ScriptCommands.java:75`), which only sets the cancel flag: a
  script that never polls it keeps its quick slot past its `timeout` (section 6).
- `isolation`: `shared` (default; the program is shared, the outer transaction is always rolled
  back: `ScriptCommands.java:174-188`), `exclusive` (the program's write lock for the run, today's
  `"exclusive":true`, `:92`), `private` (3.6).
- `scriptSha256`: if present, the engine hashes the resolved script file (cached by path, size
  and mtime) and refuses a mismatch with `script_changed`. Hydralysis sends it for RusticQuery, so
  a planted or stale file in the staged script folder cannot run under the shared read lock.

v3 reply additions:

```json
{"script":"...\\RusticQuery.java","mode":"contained","isolation":"shared","lane":"quick",
 "program":"p1:/x.exe","seconds":0.31,"chars":812,"truncated":false,"output":"...","changed":false,
 "unsaved":false,"attemptedChanges":false,"attemptedChangesCount":0}
```

`attemptedChanges` is the program's modification-number delta **measured before the rollback**
(`runScript` reads `modBefore` at `:172` and today reports `changed:false` by construction when
contained, `:195-196`). In `shared` mode it is a program-wide indicator, not a per-script one:
with several shared scripts running at once, one script's rolled-back write can show in another's
delta. A non-zero value for a RusticQuery read action is a test failure in Hydralysis (7.4).

#### `cancel`

Unchanged request and reply. The v3 addition is on the **cancelled request's** error
(`details.phase`, `details.applied`, 3.3).

#### Every queued request: `queue`

A v3 success reply that waited 250 ms or more for a slot carries, next to `result` and `ms`:

```json
{"id":5,"ok":true,"result":{"...":"..."},"ms":4210,"queue":{"lane":"long","waitedMs":4000,"positionAtStart":3}}
```

While it waits **for a slot**, the existing progress event carries `queue` **for a v3 connection
only** (the plumbing exists: `RequestMonitor.waiting(what, queueInfo)`, `RequestMonitor.java:98-101`,
and `:191-193`, but `Scheduler.admit` calls the one-argument form, `Scheduler.java:155`; E3a passes
the queue information only when the client is v3, so a v2 slot-wait progress event and a v2
`status.requests[]` entry for a slot wait are unchanged, 5.1; conditional C4). This is about the
**slot** wait only: a wait in the **import queue** already carries `queue` in protocol 2 (3.5, C5) and
is not touched:

```json
{"event":"progress","id":5,"message":"waiting for a long slot","queue":{"lane":"long","position":3,"ahead":2,"estimatedWaitMs":null,"estimate":true}}
```

### 3.5 Lanes and admission rules

| Lane | Commands | Slots (config) |
|---|---|---|
| `quick` | `list`, `functions`, `decompile`, `rename`, `comment`, `open_program`, `switch`, `open_project`; **`script` only with `lane:"quick"` and a bounded `timeout`**; `health`, `ping`, `status`, `cancel` need none | `maxQuick` (CPU count) |
| `long` | `analyze`, `import`, `script` (default) | `maxLong` (revision 6, D40: `max(8, CPUs)`; rev5 CPUs/4, at least 2) |
| `maint` (new) | `fork_project`, `refresh`, `reopen`, `promote_overlay`, `save`, **for a v3 connection**; a v2 connection keeps them in `long` | `maintSlots` (revision 6: 4; rev5 2) |

`save` moves from long to maint: a 35 s save of the 1.5 GB benchmark program (*unmeasured on this
machine*, from the durable-annotations analysis) must not wait behind two analyses, and a
Hydralysis commit that holds `.commit.lock` must not queue behind a four-hour analysis. This is a
behaviour change, so it is **gated on v3** (behaviour gate 2, 3.1): a v2 connection keeps today's
lane, today's busy text and today's queueing for these five commands, and the two kinds of
connection share one scheduler, so a v2 `save` still queues in `long` while a v3 `save` runs in
`maint` (test `v2_lane_unchanged`, 5.1). `import` and `analyze` stay long. `ImportGate` keeps its own queue and its own
estimate; it is not rewritten. Two things change in it, both E3a's (8.1 gives `ImportGate.java` to
E3a in W2): the estimate gains `estimateScope:"load"` for a v3 connection (it excludes analysis;
conditional C5), and, because `ImportGate.enter` receives only the client **id**
(`ImportGate.java:165`, called with `c.id` from `ImportCommands.java:100`; the `Client` and so
`Client.v3()` are not available inside the gate), `enter` takes the `Client` (or a `boolean v3`) and
stores it on its `Entry`, so that `queueInfo(e)` can decide. What does **not** change: the `queue`
object that an import wait already puts in its progress events (`m.waiting("import queue", q)`,
`ImportGate.java:188-194`) and in `status.requests[].queue` (`RequestMonitor.java:111`) is
**protocol 2 behaviour today**, so it is not new v3 content and not gated: only the `queue` key of
a *slot* wait (C4) and `estimateScope` (C5) are new. `v2_progress_keys` (5.1, G5) pins the exact key
set of both kinds of wait.

**Fair key.** The round-robin map in `Scheduler.State.queue` is keyed by connection id
(`Scheduler.java:84,152`). For a **v3 connection** it becomes keyed by `connection id +
Caller.Identity.scope()` (`Caller.java:44`), so ten harnesses multiplexed over one Hydralysis
connection are ten queues; a v2 connection keeps the key `connection id` (a v2 client that labels
its requests would otherwise see its own requests reordered). Unlabelled requests share one key
per connection, as today. The key is attribution, not access control (any holder of the token can
forge it; the README already says so).

**Per-key running cap**, work-conserving (v3 keys; **revision 6 extends the cap to v2 connections, V9**, keyed by `connection id` as before): a key at its
cap is held back **only while another key waits for that lane that is itself under its own cap**
(a key that has reached its cap and whose next request is queued does not count as "another key
waiting", so two keys that each run one request and queue another never leave slots idle: with
`maint` slots 4, cap 1 and two such keys, the cap does not apply and both queued requests run).
Defaults: quick `max(1, slots/2)`, long `max(1, slots-1)`, maint `1`. It is one extra
condition in `admit` and in `release`'s hand-over loop (`Scheduler.java:266-277`).

**Queue information.** `Ticket` computes `position` and `ahead` on demand. ETA:
`null` until the lane has recorded 5 completions; then
`ceil((ahead + 1) / slots) * median(last 20 hold times of the lane)`; `null` again when any running
holder has already run longer than 5 times that median (the lane is dominated by a long job and
the median says nothing); always `estimate:true`. This is deliberately crude: the long lane mixes
100 ms scripts and hour-long analyses.

**Validate-before-wait (v3 only).** `Session.execute` admits first and validates later
(`Session.java:248` against `Access.withProgram`). `admit` gains the request
(`admit(c, cmd, req, m, waitMs)`, D17) and, for a v3 client whose request **would have to
enqueue**, runs `Preflight.run(cmd, req)` before it queues: missing or ill-typed fields, unknown
`op` kinds, bad `lane`/`isolation`/`purpose`/`verify`, `expect` types. `Preflight` is a registry
(D31): E3a registers the generic checks under the key `*`, E2 registers `fork_project`'s
(`purpose`, `verify`) from `ForkCommands`, E4 registers `script`'s (`lane`, `isolation`) from
`ScriptCommands`, each by **extracting** the command's own validation into one method used by the
command and by the preflight (so the two cannot drift). A request admitted at once keeps today's
order of errors, and a v2 request is never preflighted, so no existing golden changes.

**Import wait fix (all protocols, declared v2-visible, 5.1).** `ImportCommands` waits for the import
gate without a deadline, then calls `scheduler.admit(c, "import", m, waitMs(req))` and
`lockProject(p, false, waitMs(req), "import")` (`ImportCommands.java:112-114`) with `waitMs`
defaulting to 10 s (`Requests.java:30`): an import that waited an hour for its turn can fail `busy`
ten seconds after reaching the front. Both calls take the remaining wait computed from
`limited`/`deadline` (`:79-81`), unlimited when unlimited. **This moves a v2 outcome in both
directions, and both are declared (V2, 5.1):** (1) a v2 import **without** a `wait` field, which
waits unlimited in the gate, now also waits unlimited for the slot and the project lock instead of
failing `busy` after 10 s (a failure becomes a success); (2) a v2 import with an **explicit numeric**
`wait` that spent most of it in the gate now fails `busy` at the end of that one budget, where today
its slot and lock waits each got a fresh full `wait` and it could succeed (a success can become a
failure; the total is now what the caller asked for). The goldens cannot see either, so the tests
`import_wait` (no `wait`) and `import_wait_explicit` (a numeric `wait` spent in the gate) run on a v2
connection.

**Cancel-aware lock waits (one timed `tryLock`, cancel by interrupting the waiting thread).**
`Caller.enter(c, id)` (`Caller.java:86`, called from `Connection.respond`) also stores the request's
`RequestMonitor`; `Caller.monitor()` returns it. The three locks a request waits on are **fair**
`ReentrantReadWriteLock`s (`ProgramEntry.java:115`, `ProjectEntry.java:43`, `Overlay.java:54`), and
today each of those waits is **one** timed `tryLock(wait)` (`ProgramEntry.java:195`,
`Access.java:109`, `OverlayCommands.java:142`). **These three request-bound timed waits are what this
section converts, and the claim stops there.** The overlay lifecycle also takes **untimed,
uncancellable** `lock()` calls (`OverlayCommands.java:228`, `:238`, `:251` in `openOverlay`, `:319`
in `rebuildOverlays`, `:352` in `dropOverlays`, which also runs from the cleanup path, and `:404` in
`promoteOverlay`, which this design moves to the `maint` lane). They are **out of scope** of E3b: a
request blocked there ignores `cancel`, the deadline and the dead-client release exactly as today
(they are short, overlay-local critical sections, and an overlay is not the shared program), the
limit is listed in section 6, and E3b's `abandoned_holder` test does not cover them. Converting
them to `Waits.tryLock` is a later, separate decision (it needs a lock-order review of
`promoteOverlay`). The timed `tryLock(long, TimeUnit)` honours the fair policy: the thread
joins the lock's FIFO queue once and keeps its place for the whole wait, and while an exclusive
locker is queued no later reader gets in ahead of it. Two obvious ways to make the wait cancellable
break that, and both are **rejected**:

- *Polling in 100 ms slices of a timed `tryLock`*: when a slice times out the thread's queue node is
  cancelled and removed (AQS), and the next slice enqueues a **new node at the tail**. An exclusive
  locker (a `save`, a `refresh`, an exclusive script, maintenance work) would lose its place every
  100 ms and wait behind every reader that arrived meanwhile, so steady readers could starve it.
- *Polling the untimed `tryLock()`*: it is documented to **barge** (it takes a free lock whether or
  not threads are queued, even on a fair lock), so a poller never queues and a reader's poll
  overtakes a queued writer.

The design keeps today's single wait and delivers cancel from outside. A new static
`Waits.tryLock(Lock, waitMs)` (E3b; same call shape, so no signature changes) does one
`l.tryLock(waitMs, MILLISECONDS)` on the request's own thread, so queue position and fairness are
exactly today's, with a small registration state machine on the request's `RequestMonitor`
(`IDLE`, `WAITING`; all transitions under one mutex):

1. *Enter.* Under the mutex: if the monitor is already cancelled, throw `cancelled` without
   touching the lock; else record `thread = currentThread` and set `WAITING`.
2. *Wait.* `l.tryLock(waitMs, MILLISECONDS)`. Nothing polls and nothing slices; `client.leaving`
   needs no check of its own, because `Connection.run` sets it and then cancels every running
   monitor (`Connection.java:95-97`), which takes the path below.
3. *Cancel.* `RequestMonitor.cancel()` (overridden; it is what `Session.cancel`, `Connection.run` and
   the deadline timer already call, `Session.java:393,409`, `RequestMonitor.java:118-121`) sets the
   flag as before and then, under the mutex, **if the state is `WAITING`, sets `interruptSent` and
   interrupts the registered thread**. In any other state it only sets the flag. An interrupt is
   therefore sent only while the thread is inside this wait and can never reach later work: an
   interrupt that lands in Ghidra's database I/O can close a channel (`ClosedByInterruptException`),
   which is the hazard this ordering prevents.
4. *Leave.* In a `finally`, under the same mutex: set `IDLE`, read and clear `interruptSent`, and if
   it was set clear the thread's own interrupt flag (`Thread.interrupted()`) **before anything else
   runs on the thread**; an interrupt that arrived after `tryLock` returned but before this step
   is cleared here too. An interrupt that was **not** ours (`shutdownNow()` in `Connection.run`)
   leaves the flag set, as `ProgramEntry.java:197-200` does today.
5. *Outcome.* Lock obtained and `interruptSent` or the monitor cancelled: `unlock()` it and throw
   `cancelled` (a lock acquired while a cancel raced is never held across the error). Not obtained
   and `interruptSent`: `cancelled`. Not obtained by timeout: today's `busy`, with `reason` and
   holder detail. A monitor-less caller (the cleanup waits) gets the plain timed `tryLock`.

The request-bound waits it replaces are `Access.lockProject` (`Access.java:109`),
`ProgramEntry.acquire` (`ProgramEntry.java:195`) and the overlay lock (`OverlayCommands.java:142`).
The scheduler slot wait is not an AQS lock: it already waits on its own condition in 100 ms
steps and checks the monitor (`Scheduler.java:157-183`), keeps its own FIFO per key, and is
unchanged. A `timeout` deadline that fires during a lock wait now ends that wait too (today the
timer cancels a monitor nobody on that wait reads). The cleanup waits (`CLEANUP_WAIT_MS`:
`ProgramCommands.java:622`, `ProjectCommands.java:408`) are not request-bound and are handled by
the dead-client rule below.

*Tests (E3b, all on a protocol-2 and a protocol-3 connection).* `writer_vs_steady_readers`: eight
readers loop (each holding the shared lock about 50 ms, arriving so that the lock is never free for
long) and one exclusive request (an exclusive script) arrives: it must acquire within the longest
reader hold times the readers already queued ahead of it plus a margin, and every reader that
arrived **after** it must start after it (ordering read from the request timestamps), so the writer
is not starved and the FIFO is preserved; before the implementation exists the same test is run
against a build that polls in slices, and the run must fail (the premise check of the E0
convention), the result recorded. `cancel_while_waiting`: a request queued behind an exclusive
holder is cancelled by id and answers `cancelled` within 1 s, the requests queued behind it keep
their order and run when the holder ends, the holder is unaffected; 200 iterations of a cancel
sent at the instant the holder releases end only in `cancelled` or success, never a leaked lock
(`status.programs[]` shows no reader or writer afterwards) and never a stray interrupt (a `save`
and a decompile on the same connection afterwards succeed, and the daemon log has no
`ClosedByInterruptException`). `deadline_in_lock_wait`: a request with `timeout` shorter than its
lock wait answers `cancelled` at the deadline.

**Lock-queue cap (v3; revision 6 applies it to every v3 request, D39).** At most
`max(2, slots/4)` requests may wait on one program's lock (`ProgramEntry.waiters`), one project's lock or one
overlay's lock; further ones get `busy`
at once with `reason:"lock_queue_full"` and a `retryAfterMs`. The wait then happens in the client
(Hydralysis already treats `busy` as retryable and has its own budget), not in an engine slot.
Parking a waiter's slot is **not** attempted by default (revision 6, D39: `Ticket.yieldSlot` behind the setting `yieldSlots`, off, gated by SP9): it breaks "lock holders never wait for a slot"
(`Scheduler.java:42-43`), which is what makes slot-then-lock deadlock-free, and it needs a written
lock order and a stress test of its own.

**Dead clients: bounded release (all protocols, declared v2-visible, 5.1).** It changes how long
*other* clients wait for a dead one, not any reply shape. `Connection.run` (`Connection.java:93-108`) cancels the
client's requests, then `awaitTermination(1, HOURS)` on both executors before
`session.disconnect`. Replaced by: cancel; wait `cleanupGraceS` (15); `shutdownNow()` (interrupts
lock waits and I/O, not busy loops); wait `abandonWaitS` (5); then call `session.disconnect`
regardless. And `disconnect` itself must not wait 600 s: `Session.disconnect` passes
`CLEANUP_WAIT_MS` to `leaveProject` (`Session.java:121`), whose `lockProject` and
`releaseUse` calling `e.acquire(true, wait)` use that wait. For a leaving client both use
`abandonWaitS`; if the exclusive lock cannot be had, the program entry is flagged
`abandoned {cmd, since, thread, client}` and:

- the dead client's ownership bits (`owner`, `writers`, `users`, which are guarded by
  `synchronized (e.users)`, not by the program lock) are removed so it no longer blocks others;
  if that cannot be made safe in E3b's review, the fallback is to leave them until the holder ends
  and still report `abandoned`;
- other requests for that program get `busy` immediately instead of a silent wait, with
  `holder`/`holderInfo` saying "abandoned request <cmd>, client gone, running N s" (the existing
  `busy` keys, so a v2 client reads it unchanged) and, for v3 only, `details.reason:"abandoned"`;
- `status.programs[].abandonedRequests[]` and `health.abandoned[]` list it;
- **the program object is not disposed** while the abandoned thread runs (`Session.reap` already
  uses non-blocking `tryLock`, `Session.java:194-199`, so it cannot).

What this cannot do: Java cannot kill a thread that ignores cancel and interrupt, and cannot
unlock a `ReentrantReadWriteLock` held by another thread. A non-cooperative script keeps its
program lock after its client is gone; the design bounds the wait, makes the state visible and
keeps everything else running. The only hard remedy is a helper JVM for user scripts, which is out
of scope and said so in the README. `RusticQuery` calls `monitor.checkCancelled()` at 17 sites
(`RusticQuery.java:126, 254, ...`); new loops must call it.

A client that abandons a stalled call without closing its connection (the hydra.2/3 deadline of 7.6) is
such a client from the engine's side until its worker closes the session: on hydra.3 it is released when its
request ends and the worker closes (measured in 7.6), on hydra.4 by this rule after about
`cleanupGraceS + abandonWaitS` once the connection is closed or has sent a FIN.

**A reader's leave takes no exclusive lock (E3c, W4, hydra.4, D63; all protocols, declared with V10 in 5.1; found in
revision 5, BLOCKING 3, and attributed to E3b there; revision 7 builds it once, in E3c).** `ProgramCommands.releaseUse` (`:480`, called by `close_program`, by `leaveProject` and so by
`Session.disconnect`) takes the program's **exclusive** lock for every leave (`e.acquire(true, wait, ...)`),
although a plain reader has nothing to dispose, downgrade or discard. The program lock is a fair
`ReentrantReadWriteLock` (`ProgramEntry.java:115`), so while that exclusive waits behind a running reader every
**new** shared acquirer (an `open_program`, a script, a decompile) waits behind it. Measured on the real
daemon (hydra-3-candidate and the refactor build, same results): with one 6 s read running, a clean `close()`
of an entry that had joined the program, a FIN of such an entry, and the end of an abandoned entry's request
after a FIN each made a **new** entry's `open_program` and an **already-joined** entry's script fail `busy`
(`wanted:"shared"`, `readers:1`) after their 1.5 s wait, and did not before the leave (join 3 ms, script
36 ms); an entry abandoned with no FIN and never closed caused nothing (`exp11_rerun`, `exp12_rerun`,
`exp13` A, C, E in `D:/Projects/Hydra/_logs/spec-rev5/exp/`). The stall lasts until the running readers end
(at most the longest `timeout`), and a waiter whose own `wait` is shorter gets `busy`. It is not new with the
pool in kind (any client that leaves, and Hydralysis's own `close_program` in `stop`, does it today); the pool
makes it frequent.

E3c therefore adds a **fast path** to `releaseUse`: a client that is neither the owner nor a shared writer of
the program, has no overlay of its own on it and is **not the last user** is removed from `e.users` and from
its own bookkeeping (`c.programs`, `c.active`) and the call returns **without the program lock**. The
check and the removal are one step under `synchronized (e.users)`, so two concurrent leavers can never both
conclude that the other remains: the last user always takes today's exclusive path and disposes (or keeps
warm) exactly as before; owners, writers, overlay holders and `discard` are unchanged. It is not gated on v3:
it changes how long *others* wait, no reply shape (V3). **Measured** with this one change compiled over the
same engine (`D:/Projects/Hydra/_engines/hydra-spec-rev5-patched`, one class in `Ghidra/patch/`; source
`D:/Projects/Hydra/_logs/spec-rev5/patch/src/ProgramCommands.java`; an experiment, not a package): the three
freezing scenarios show no stall (join 3 ms, script 44 / 42 / 189 ms), and `exp14` gives identical `users`
lists and dispose behaviour on the patched and the unpatched engine (six entries closed concurrently, five
rounds; the sole user; a second user; each ending with the same `users` and a program that still reads).
Tests (E3c): `reader_leave_no_freeze` (the three scenarios as assertions: during a running read a clean close, a
FIN, and the end of an abandoned request each leave the next join and the next script of a joined entry
answered within their `wait`; it must **fail on hydra.3**, the premise check of E0's convention),
`last_user_leave_disposes` (N concurrent leavers: nobody registered afterwards, the program disposed or kept
warm as before) and, with the stock 1.0.0 client, `cc_e3c` `reader_leave`. Until E3c ships, the client avoids
its own leaves while its own reads run (the leave gate, 7.6) and the rest is a limit (6).

**Who removes which leave stall (revision 7, D63; one package and one release each, both hydra.4).** (a) The leave of an
**owner, writer or overlay holder of an open (legacy) program**, and the 600 s `CLEANUP_WAIT_MS` waits of
`Session.disconnect` and `leaveProject` for them: **E3b (W3)**. It stays a lock wait (a writer's leave needs the
exclusive lock) but is bounded by `cleanupGraceS + abandonWaitS`, attributed with `holder`, cancel-aware and flagged
`abandoned` when it cannot be had; it is a residual point of 3.9 and its test is `owner_leave_bounded`. (b) The leave
of **every other client**, a plain reader at any user count (the rev5 fast path above, and the deferred, non-blocking
disposal of the last user): **E3c (W4)**; no reader of a program waits behind it, and its tests are
`reader_leave_no_freeze`, `last_user_leave_disposes`, `reader_leave_all` and B's `s1` (a, b, c). In the rev5 experiment
the last user still took today's exclusive path; E3c makes that disposal deferred (D37).

**Orphan TTL (E3b, optional, default off).** With `orphanKeepS > 0`, `Session.reap` ages the
unsaved edits of a shared program whose last writer died (`ProgramEntry.holdsOrphanedWork`,
`orphanedSince`, `Session.java:171`), writes `<stateDir>/recovery/<project>-<program>-<ts>.journal.json`
(the `Journal` entries, which carry old and new values, plus revision and sha256), then discards.
Hydralysis never needs it (its work copies are replayable from the store).

### 3.6 Script isolation

| Mode | What runs on what | Readers | Sees unsaved shared edits | `attemptedChanges` |
|---|---|---|---|---|
| `shared` (default) | the shared `Program`, shared read lock, outer transaction rolled back | not blocked; may observe transient writes of a script that mutates | yes | program-wide delta (approximate under concurrency) |
| `exclusive` | the shared `Program`, its write lock, outer transaction rolled back | blocked for the run | yes | exact |
| `private` | a throwaway program object from the **stored** file | not blocked, never see it | **no** (`unsavedIgnored` in the reply says how many edits it missed) | exact |

`private` reuses the mechanism of `OverlayCommands.loadOverlay` (`OverlayCommands.java:277-314`:
`getReadOnlyDomainObject`, or `UpgradeCache.openReady` when the shared program came from the
cache): extracted to `PrivateInstance.java`, with a transient consumer, disposed in a `finally`,
never put in the `overlays` map. The extraction touches `OverlayCommands`, so E4 follows E3b. Open
cost is the README figure for an unedited overlay (two README rows, not one: 26 ms and +3 MB on the
174-function project, `README.md:410`; 116 ms and +54 MB on the 243,855-function benchmark program,
`README.md:409`) and is *unmeasured on KotOR*: `private` becomes the Hydralysis default for `ghidra_run` only
after that measurement (7.4). Reply adds `"basedOn":{"saved":true,"programRevision":"..."}` and
`"unsavedIgnored":0`.

A spike in E4 tests whether `Program.lock(reason)` on the shared program turns a mutation attempt
into an exception without disturbing concurrent readers. If it does, `shared` gains enforcement;
if not, the guarantee for `shared` stays "rolled back, measured, and RusticQuery is source-controlled
and hash-pinned", and the README says so. A script is still Java with the daemon's rights: this
is containment of the current program, not a sandbox (`ScriptCommands.java:67`).

**Revision 6 (D47).** The default isolation of a user `ghidra_run` is never `shared`: `private` when the program has
nothing unsaved (the stored file is the whole truth), `exclusive` on a view (only its owner exists, so only the owner
waits). `shared` stays the default of a direct client and of RusticQuery's read actions, which do not write
(`attemptedChanges` must be false). A contained script on a program that other clients read keeps the measured limit
that its uncommitted changes are visible to them while it runs (94 of 114 polls); no document may call that isolated.
The killable worker (E7) is a gated hydra.4 package (D64); until its gate passes a deaf script is bounded and quarantined, not killed. **A worker never works on the stored file of an edited view** (revision 8): the engine refuses `isolation:"worker"` on a program with unsaved edits (`conflict`, `details.reason:"unsaved"`, `next:{cmd:"save"}`), the view's owner saves the fork first under the per-view lock, and the worker opens a private, writable, disposable clone of the saved view, so that `attemptedChanges` is measured and then discarded. `private` (E4) stays read-only on the stored file and keeps `unsavedIgnored`.

### 3.7 Daemon configuration

New keys, in `<state>/config.json` and as command-line flags (`HeadlessSession.java:64-86`,
`README.md:121-150`). All have safe defaults. Today every key needs an edit to `HeadlessSession`'s
option parser and to the launcher, so five packages would collide on both files. E1 therefore adds
one generic route and no package adds a flag of its own: the launcher (P1a) passes every entry of
a new `engine` object in `config.json` to the JVM as repeatable `-set key=value` flags, the parser
(E1) stores them in `Settings.java`, and each package reads its own keys in its own classes
(`Settings.integer("maintSlots", 2)`). The table lists the keys and their owners; R1 documents
them in the README. No new environment variable is added.

| Key | Default | Meaning | Read by |
|---|---|---|---|
| `maintSlots` | 4 (rev5 2) | maint lane slots | E3a |
| `maxLong` | `max(8, CPUs)` (rev5 CPUs/4, at least 2) | long lane slots | E3a |
| `quickScriptMaxS` | 60 (hard max 120) | longest `timeout` for `lane:"quick"` scripts | E3a (the lane decision) |
| `maxRunningPerKey` | quick `max(1,slots/2)`, long `max(1,slots-1)`, maint 1 | work-conserving per-key cap | E3a |
| `cleanupGraceS` / `abandonWaitS` | 15 / 5 | dead-client release | E3b |
| `requireExpect` | false | shared-writer edits need `expect` | E1 |
| `requireBackupForUpgrade` | true | the upgrade gate | E2 |
| `orphanKeepS` | 0 (never) | orphan dump and discard | E3b |
| `watchdogStallMs` / `starveMs` | 15000 / 30000 | `health` thresholds | E5 |
| `minXmxMb`, `maxViews`, `maxViewsPerClient`, `heapSoftPct`, `heapHardPct`, `nativeBudgetMb` | 512, 32, 4, 70, 85, 50% of RAM minus `-Xmx` | the governor (3.11) | E9 |
| `scriptMaxS`, `yieldSlots`, `writeStallMs` | 600, off, 5000 | runaway-script wall budget, the optional slot yield (D39), the stalled-socket disconnect | E4, E3c, E3b |
| `viewDiskBudget`, `diskReserve`, `viewIdleEvictS` | 20 GB, `max(5 GB, 5%)`, 600 | disk admission (3.11) and the client-side eviction time | E9, Y5 |
| `publishBatchMax`, `SYNC_LOCK_S`, `BASE_WAIT_S` | 1, 30, 30 | Hydralysis: changesets per generation, the per-view lock bound, the shared-base wait (4.10) | Y3, Y2 |
| `generationKeep`, `viewIdleDeleteS`, `viewKeepWarmRecords` | 3, 86400, 1000 (*unmeasured*, set from Z2's replay run, D61) | Hydralysis, retention (OD8, decided): the doctor lists every generation except the newest 3, generation 0, the head, a revert target and any live view's base as removable, and `backend action=backups options.op=remove` deletes one only on `confirm:true`, never automatically (D28); a view idle for 24 h has its fork folder deleted, which loses nothing because the store holds its records (a disposable cache, D43); a view with at least `viewKeepWarmRecords` pending records is never closed by idle time (D61). All three are configurable | Y2, Y5 |

`-Dghidra.session.testHooks=true` is not a config key: a launch property only.

### 3.8 Launcher (`support/ghidra_session.py`, P1a and P1b)

- **P1a.** `PROTOCOL = 3`, new `PROTOCOL_MIN = 2`; the hello sends `protocol=3`; `check_compatible`
  accepts a reply in `[PROTOCOL_MIN, PROTOCOL]` and exposes `session.protocol`; the endpoint check
  accepts any overlap of `[2,3]` with `[protocolMin, protocolMax]` (absent: the single `protocol`).
- **P1b.** `SocketSession.call(cmd, deadline=None)`: replaces `sock.settimeout(None)`
  (`ghidra_session.py:845`) for the wait on that reply; on expiry sends `cancel target=<id>` and
  raises `SessionError("deadline_exceeded")`; the connection stays usable (the library owns its
  reader, so its own `wait` can be timed and no thread is ever left blocked in `readline`). This exists only in the
  1.1.0 library that ships with hydra.4: the hydra.2/3 install ships 1.0.0, whose `call` waits
  without a limit, and Hydralysis loads the session module **from the engine install**
  (`hydra.py:48` `SESSION_MODULE`, `:229-233` `Engine.module()` and its use in `_connect`), so against a hydra.2/3 engine it cannot
  use P1b and runs the deadline helper of 7.6 instead (abandon without a FIN and a gated close, tested
  there; **not** `session.close()`, which hangs on 1.0.0). Structured
  `LaunchError` (`:89`, stays a `RuntimeError`) with `code` in `no_jdk | jdk_too_old | bad_install |
  lock_held | heap_too_large | exited_early | no_answer | duplicate_daemon` and `details`
  (`javaMin`, `tried[]`, `logTail`, `holder`, `suggest`). `Daemon.health()`; `Daemon.attach()`
  = `connect(start=False)` (exists: `Daemon.connect(..., start=True)`, `:1004`) for the doctor.
  **Registry**: once the endpoint is ready the launcher writes
  `<userStateRoot>/registry/<sha256(install|stateDir|instance)>.json`
  `{pid, stateDir, instance, install, hydraVersion, startedAt}`; `<userStateRoot>` is the launcher's
  default state root, independent of `-stateDir` (so daemons started with different roots see each
  other; `GHIDRA_SESSION_HOME` relocates it). An entry is live iff its instance lock is held
  (`Daemon.jvm_alive`, `:969-979`). Before spawning, the launcher looks for a live daemon of the
  same install under another state dir. Default policy `warn`: a structured warning in the connect
  result. `singleton:"per-install"` raises `DuplicateDaemonError(holder pid, stateDir, instance,
  three ways out)`. Enforcement is opt-in until the owner consolidates the two live daemons
  (pids 18220 and 17936, which this design never touches). No Java registry class.
- **Revision 8 (D60, D65, replaces the revision 7 text of this bullet).** P1b **never creates or owns a kill-on-close Job
  Object that contains the daemon**: revision 6 did, and a shared daemon in a launcher-owned job is dead as soon as the
  launcher exits (`review-rev6/exp7_jobobject.json`). Process containment (decompilers and workers die with the daemon) is the
  **daemon's own** job, created at start-up by E9 (3.11). Survival (the daemon outlives its harness) is a separate matter that
  a daemon-owned job does not provide: a harness that runs in a kill-on-close job without breakaway rights keeps the daemon in
  that job, because nested assignment always succeeds. P1b therefore detects the caller's job, tries
  `CREATE_BREAKAWAY_FROM_JOB`, falls back to a spawn outside the job through WMI `Win32_Process.Create`, and as a last resort
  stays in the job with the warning `daemon_dies_with_harness` (D65); the existing detached spawn (`DETACHED_PROCESS` and
  `CREATE_NEW_PROCESS_GROUP`, `ghidra_session.py:1058-1065`, which swallows the breakaway failure silently) is step 2 and 3 of
  that sequence. P1b also adds `--enable-native-access=ALL-UNNAMED` to the JVM arguments (D60). A supervisor that restarts a daemon waits for the process object to exit first (D55). No nested
  per-decompiler memory limits (rejected, D46).

### 3.9 The concurrency model (revision 6)

**What this section is for.** The owner objective is that several harnesses (Claude Code, Codex, OpenCode,
QoderCLI) work on several projects at once, that nothing they do corrupts a project or another agent's work, and
that a lock held for one client does not make another wait. Four measurement streams, run on the real daemon in
October 2026, say how far rev5 is from that; all numbers below are single runs or small repeat counts on one
24-CPU machine under uncontrolled foreign load (A varied about 2x between identical runs), and every one of them
has a script and an output file:

| Stream | What it measured | Where |
|---|---|---|
| A (capacity) | 12 and 24 agents on their own writable forks, one daemon; fork, memory and throughput cost; heap probes; the long lane; the Hydralysis work-copy path | `D:/Projects/Hydra/_logs/measA/` (`scripts/`, `out/`; `out/ramp3-scale.json`, `out/ramp4-p1.json`, `out/lane-def.json`, `out/lane-ml24.json`, `out/forkcost-ntfs.json`, `out/hlm-c.json`, `out/hlm-d.json`) |
| B (lock map) | every blocking point of the engine, static and on real daemons, 19-row `lock_matrix.json`, scripts `s1` to `s13`, `t3_scaling` | `D:/Projects/Hydra/_logs/lockmap/` |
| C (crash) | 952 forced kills (`TerminateProcess`) with a fresh daemon and an oracle after each | `D:/Projects/Hydra/_logs/crash-C/` (`final_numbers.json`, `run/<run>/results.jsonl`, `run/repair-check/repair_result.json`) |
| D (claims) | about 45 claims of the site and READMEs against the measurements | `D:/Projects/Hydra/_logs/claims-audit/` |

**Topology.** One daemon per state root (OD3: no consolidation yet). K harness processes, each with its own
Hydralysis server process serving one or more agents (`options.as`). Therefore **every piece of Hydralysis
coordination is cross-process**: OS byte-range locks (released by the kernel when the holder dies), atomic
markers and append logs. In-process state is a cache. Measurement A saw separate processes avoid the in-process
`_sync` bug, but also saw 12 of them rebuild 12 bases because nothing was shared between them (D44).

**Objects.**

| Object | Definition | Who may write it |
|---|---|---|
| **Master** | the lineage's current generation (generation 0 is the adopted project itself, never written) | nobody; opened read-only only |
| **Generation** | an immutable project folder: a verified fork plus the replay of a changeset batch, named by a line of `CURRENT.log` (D10). **Sealed** (D38) | nobody after the append |
| **View** | an agent's private world `(lineage, agent id)`: a base generation, the agent's pending records in the Hydralysis store (the truth) and, once the agent has edited, a disposable writable fork of the shared base (the cache) | its one owner |
| **Candidate** | a fork being turned into the next generation: `state:"candidate"`, writable, until it is verified and sealed (D38) | the publisher that created it |
| **Open project** | a project nobody sealed: today's in-place use, protocol-2 shared mode, owner mode, rooms of shared writers | as today, with the bounds of 3.5; opt-in; **no non-blocking claim** |

**Roles.**

| Concern | Engine (hydra.4) | Client (Hydralysis) |
|---|---|---|
| Reads | read-only opens, refcount join and leave, native decompile through a governed pool | chooses the master or the agent's view; sends lane hints and the agent label |
| Writes | the private writable fork of one owner; hard caps independent of client behaviour; sealing refusals | write-ahead record, replay, rebase, publish |
| Truth | none for annotations (D5) | the store; a view fork is a rebuildable cache |
| Generations | `fork_project` with the atomic publish of D41, `seal_project` | lineage, `CURRENT.log`, publish queue, verify, rebase |
| Limits | admission, caps, watermarks, decompiler gate (3.11) | soft policy: LRU, idle time, `max_views`, friendly errors |
| Faults | contains script, decompiler and out-of-memory faults; sweeps its own staging | crash-safe store, idempotent replay, orphan candidate listing |

**Read path (no lock another client can hold).**

1. A read-only `open_project` or `open_program` of the master or of any generation finds the program entry,
   increments the user count and returns. A sealed program has no exclusive holder at all (D38), so there is
   nothing to wait for. Join and leave of **any** reader change a counter only (E3c; 3.5, the reader-leave fast
   path extended to every non-owner, non-writer). Measured: readers of one program never block each other,
   native decompile scaled 9.6x at 24 clients (87 to 840 calls/s, `lockmap/t3_scaling.json`); 12 clients on one
   shared read-only program ran at a median 160.4 funcs/s against 163.9 on 12 forks, interleaved
   (`measA/out/ramp4-p1.json`), with a live heap of 51 MB that does not grow with the number of clients.
2. DB-bound reads (`functions` with a regex, xref scans) of one `Program` instance are capped by Ghidra's one
   `DBHandle` monitor at 1.4x to 1.8x (41 of 114 sampled session-thread stacks `BLOCKED` on `db.DBHandle`);
   eight separate instances reached 4.1x (`lockmap/s12_instances.json`, `s9_threaddump.txt`). That is
   **inherent to Ghidra** and is not refactored away; read replicas are E11, conditional on SP1 and SP8 (D37).
3. A program being imported or analysed answers a v3 join **at once** with `busy{reason:"analyzing"}` and the
   job's progress and ETA (E3c), instead of failing after `wait` (B: `open_program` busy for 162.8 s behind a
   `notepad` analysis). Hydralysis never analyses in place: it analyses a fork and publishes a generation.
4. A v3 reader of an open (legacy) program sees the live program exactly as a v2 reader does (D51).

**Write path.** An agent that has not edited has no view and costs nothing. Its first edit creates the view
(D43). Measured per view on KotOR (8,966 functions, `measA/out/`; the fork times are all in
`forkcost-ntfs.json` and `forkcost-refs.json`, keys `seq` and `conc`): NTFS fork 214 ms for a single fork
(`seq[0]`; 137 ms in the single run of `conc[0]`), 121 to 222 ms (median 147) for 12 forks one after the other
(`seq[2]`) and **364 to 1,184 ms (median 751.5) with 12 at once** (`conc[2]`); **127.7 MB of disk per fork on the
engine's own path** (the fork copies two database versions, 63.8 MB each; 121.8 MB after a save), whereas Hydralysis'
old per-view path, which rebuilt the base for every view, measured **243 to 346 MB per view** (`hlm-d.json` 3,166 MB for
13 views and `hlm-b.json` 4,506 MB for 13 projects, `working_dir_mb` divided by the views; D44); ReFS clone 142 ms for a
single fork, 125 to 213 ms (median 160.5) for 12 in sequence and 361 to 805 ms (median 582.5) with 12 at once, 2.1 to
13.2 MB; live heap about 6.7 MB, JVM private
memory about 10 MB, daemon temp 19 to 26 MB while the format is upgraded, native decompiler 22.6 MB idle and about
161 MB busy. First decompile on a fresh fork 1.07 s alone (fork ~150, open with upgrade ~640, decompile ~265 ms)
and 2.2 to 2.8 s with 12 at once, on a warm daemon. Through Hydralysis today the first edit costs 1.86 s alone,
3.1 s with 4 agents, 8.2 to 9.0 s with 12 (15.6 to 18.2 s while the master's upgrade-cache build runs); **the 1.4 s
figure of rev5 is retired**. With the shared base of D44 the construction is fork + open + replay; **a prediction,
not a result: 0.3 to 0.55 s alone**, to be measured by Z2 and gated by 9.16 before it is quoted anywhere. These are
KotOR figures; a 1.5 GB, 244k-function project costs about 1.5 GB of disk per writing agent on NTFS and its heap
per view is **unmeasured** (SP2), which is why admission (3.11) uses the measured cost of each open and not a
formula.

**Write-ahead (the four steps of the store contract, 4.10).** An edit is sealed in the Hydralysis store and
flushed (W1); applied to the view's fork with `rk` = the record id (W2); acknowledged (W3); and on recovery any
record without an `applied` mark is replayed idempotently (W4). The fork is therefore a pure cache: its loss,
eviction or corruption costs a rebuild (base clone + replay: 0.23 s for a second edit measured), never data.

**Publish: the one serialisation point (D45).** Described in 4.10. Other views are snapshots of their base
generation; a publish invalidates nothing and blocks nothing (4.7).

**Residual serialisation points (complete; each has a bound and a counter, and nothing else may be called a lock
that blocks another client).**

| Point | Why it is inherent | Bound | Counter |
|---|---|---|---|
| The publish leader of one lineage | linear history of generations | async job with position and ETA; never on a read or view path | `publish.queue` in `status` |
| An open (legacy) program: owner mode, protocol-2 shared mode, rooms | several writers on one Ghidra `Program` (one transaction at a time) | the waiter caps and bounds of 3.5; `analyze`, owner scripts and `save` hold the program exclusive and its other readers wait; an owner's or writer's leave queues the exclusive lock, bounded by `cleanupGraceS + abandonWaitS` (E3b, D63a) | `waits.foreignBlocked` is expected non-zero here |
| One view | one owner | none needed | |
| One `DBHandle` monitor per `Program` instance | Ghidra internal | replicas (E11, conditional) | |
| Lane slots, import gate, decompiler gate | CPU and memory | per-key caps, round-robin, structured `busy` | `status.scheduler` |
| The project OS lock across daemons | safety | a second daemon's writable open is `conflict` in 112 ms; its read-only open always works (`lockmap/s8_overlay.json`) | |
| First build of a base | one build per generation and release | single-flight lock; followers read the master meanwhile (no wait) | `last_sync.phases_ms` |
| Waiters for one program, project or overlay lock | fair `ReentrantReadWriteLock` | `lock_queue_full` beyond `max(2, slots/4)` (D39) | `waits` |

### 3.10 Non-blocking engine: every blocking point, its decision and its test

The matrix `lockmap/lock_matrix.json` has 19 rows (L1, L2a to L2g, L3, L3x, L4 to L12; revisions up to E3c said 17, which was wrong; the copy the test reads is `examples/lock_matrix.json`). **E3c's acceptance includes a test that enumerates its rows and
fails if a row has no decision here.** The lock order today is lane slot (`Session.java:248`), project lock
(`Access.java:105-109`), program lock (`ProgramEntry.java:191-196`), overlay lock (`OverlayCommands.java:139-143`);
all three read/write locks are **fair** (`ProgramEntry.java:115`, `ProjectEntry.java:43`, `Overlay.java:54`), so
a queued exclusive refuses every later reader. Contract **NB**, as asserted by the tests of 9.13:
NB1 a read of a sealed generation takes no lock another client can hold exclusively; NB2 the join, leave or open
of a read-only handle takes no program or project lock; NB3 no wait for a lock happens inside a monitor; NB4 every
blocking wait is interruptible, bounded, attributed (`holder`, `retryAfterMs`) and cancelled on client death, and
**a dead client's queued write is never applied**; NB5 the waiters of one lock are capped so they cannot take a
lane; NB6 the residual list of 3.9 is complete.

| # | Blocking point | Measured (stream, file) | Decision | Package | Test that is red on hydra.3 |
|---|---|---|---|---|---|
| BP1 | reader against reader | none; decompile 9.6x at 24 (B `t3_scaling.json`) | KEEP | | NB0 control |
| BP2 | one `DBHandle` monitor per `Program` | DB reads 1.4-1.8x (B `s9_threaddump.txt`) | KEEP (inherent); replicas conditional | E11 | `s12_instances` |
| BP3 | every leave takes the program **exclusive**, plain readers included (`ProgramCommands.java:480-481`, `releaseUse`, `leaveProject` `ProjectCommands.java:286`, `Session.disconnect` `:109`/`:121` with `CLEANUP_WAIT_MS` 600 s `:52`) | new readers and joins refused 2.5-12.0 s behind one 20 s read; on a socket close until the read ended (20.1 s) (B `s1_xqueue.json`; the same on `hydra-session-after`) | REFACTOR AWAY for plain readers (E3c, D63b): refcount leave for every non-owner, non-writer client; deferred non-blocking disposal of the last user. BOUND for owner and legacy leave (E3b, D63a): the exclusive leave of an owner or writer waits at most `cleanupGraceS + abandonWaitS` | E3c (plain readers), E3b (owner/legacy) | `s1_xqueue` a, b, c (E3c); `owner_leave_bounded` (E3b) |
| BP4 | fair program lock: one queued exclusive refuses later readers | a comment queued behind a 6 s read stalled every reader up to 5,131 ms (B `s2_writer.json`) | REFACTOR AWAY for sealed and views (no exclusive exists); BOUND for open programs (waiter cap, `lock_queue_full`) | E2, E3c | `s2_writer` |
| BP5 | `analyze` holds the program exclusive 19.8-162.8 s; `open_program` busy throughout | 28 of 28 probes refused (B `s4_dead.json`, `s6_import.json`) | REFACTOR: analysis runs on a fork and is published; a join of a program being analysed answers `analyzing` at once | E3c, Y2 | `s6_import` |
| BP6 | owner scripts, `save`, READ_ONLY-to-writable swap hold the program (`ScriptCommands.java:90-93`, `ProgramCommands.java:180`) | an 8 s owner script refused 4 of 4 reader probes | REFACTOR AWAY for sealed and views (a writable view is a fork); KEEP for open programs | E3c | `s4_dead` |
| BP7 | the fair project lock is held for the whole command; a queued `refresh` or writable `open_project` refuses everything in the project | all 9 probes (other program, list included) refused 10 s (B `s7_project.json`) | REFACTOR AWAY: commands pin; the project lock covers structure changes only; a sealed project needs no `refresh` | E3c | `s7_project` |
| BP8 | `synchronized (s.registry)` around `makeWritable`, which waits on the project lock (`ProjectCommands.java:70-77`; the same monitor in `leaveProject` `:309` and `Session.reap` `:177`) | an **unrelated** project's `open_project` took 9,421 ms (B `s13_registry.json`) | REFACTOR AWAY: un-nest first (E3b), then a per-project state machine in a `ConcurrentHashMap` (E3c) | E3b, E3c | `s13_registry` |
| BP9 | a request waiting for a lock keeps its lane slot (`Session.java:248` admits before the locks) | 24 waiters took 24 of 24 quick slots; a client on another project was `busy` 6 of 6 (B `s5_lanes.json`) | BOUND: waiter caps for every v3 request (D39); slot-yield optional and gated | E3b, E3c | `s5_lanes` |
| BP10 | six long scripts block another project's `save`, `fork_project`, `refresh`, `analyze`, `script` | 5 of 5 busy; with `maxLong` 24 the waits fell to 87/281/531 ms (A `lane-ml24.json`) | REFACTOR: new defaults, maint lane, per-client cap for v2 too (D40) | E3a | `lanetest` |
| BP11 | `cancel` does not interrupt lock waits (`ProgramEntry.java:195`, `Access.java:109`, `OverlayCommands.java:142`); a dead client's queued exclusive keeps refusing readers and then **applies its write** | readers busy 3.8-15.8 s, journal seq 1 written by the dead client (B `s4_dead.json`); cancel answered `busy` 6,498 ms late (D N7) | REFACTOR AWAY: `Waits.tryLock` registered and interrupted by cancel and disconnect (3.5), `client.leaving` re-checked after acquire | E3b | `s4_dead` S4b, `cancel_while_waiting` |
| BP12 | `Connection.run` waits for the dead client's running request (`Connection.java:99-102`, 1 hour) | dead-client slots held 40 s, released 0.5 s after the holder ended (D N3) | REFACTOR (3.5 bounded release) | E3b | `dead_client_lock_wait` |
| BP13 | a deaf script cannot be stopped in-process | ran to its end 22 s after cancel; timeout answered 16.7 s late (B `s4_dead.json`, `s10_misc.json`) | BOUND in E4 (per-client caps, `scriptMaxS`, quarantine, D47) and REMOVE in E7 (a killable worker, hydra.4, D64) | E4, E7 | `s10` S10a |
| BP14 | a contained script shares the live `Program` (`ScriptCommands.java:174-176`; Ghidra joins concurrent `startTransaction` calls) | the rename was visible to another client in 94 of 114 polls (D N5, B `s9_script_db.json`) | REFACTOR: user scripts never `shared` (D47); RusticQuery read actions do not write | E4, Y4e | `script_shared_visibility` |
| BP15 | one connection is serial (`Connection.java:63`, the worker is a single thread) | `info` behind a 4 s script took 3.85 s, 1.1 ms with `parallel:true` | REFACTOR (v3): read-class commands dispatch in parallel unless the request says `ordered` | E3b | `s7c` |
| BP16 | the import gate (4 permits) | queues only imports; readers unaffected (B `s6_import.json`) | KEEP; fix the double wait (3.5) | E3a | `import_wait` |
| BP17 | the project OS lock across daemons (`ProjectLocks.java:44`) | writable `conflict` in 112 ms | KEEP | | `s8` |
| BP18 | shared-mode writer storm | four writers cut readers from 610 to 167 calls/s, p50 8.7 to 37.7 ms (B `s11_storm.json`); four writers in private overlays left readers at 606/s with 2,921 writes/s at p50 0.5 ms | KEEP the serialisation of shared writers; per-agent views are the default so most writers are private | Y5 | `s11_storm` |
| BP19 | Hydralysis per-target `.sync.lock` (up to 900 s) | one writer at a time across all clients of a shared view | REFACTOR: per-view lock, 30 s bound | Y2 | Z1 |
| BP20 | Hydralysis `_sync` shares one writer connection per process | `no_project` error, 4 threads (A `hl_multi.py`; one reproduction, cause by reading) | FIX | Y2 | Z1 (known-issue until Y2) |
| BP21 | the upgrade-cache build on the first read-only open of an old-format program | 15-16.5 s background; 12 concurrent first views took 16-18 s | KEEP, make explicit: `prepare_upgrade` is a job that finishes before the first fork | E2 | `named_view_cost` |
| BP22 | the decompiler pool is unbounded | one native process per concurrent client; 4.9 GB at 24 busy views | REFACTOR: decompiler gate (3.11) | E9 | `-Xmx` laps |
| BP23 | a progress event written from a lock-holding thread to a client that stopped reading (`Connection.java:289`) | untested | TEST FIRST, then a bounded per-connection outbound queue (events dropped, a reply stalled over `writeStallMs` disconnects that client) | E3b | `stalled_socket` |
| BP24 | `OverlayCommands` lifecycle `lock()` calls are untimed | opening a new overlay during a base exclusive hold was `busy` (B `s9_script_db.json`) | OUT of E3b (3.5); E4 opens overlays from the stored file with a timed wait | E4 | `s8` |
| BP25 | Hydralysis `workcopy_saver.py`: a second process that reopens the fork writable, saves for minutes holding the program (`wait=600000`) and takes `.sync.lock` for up to 120 s (`workcopy_saver.py:23-69`) | by code reading; not measured | DELETE: a view fork is a cache, persistence is the publish queue (D61) | Y2 | Z1 (no saver process), Y2 `test_view_lifecycle` |

**Rejected as a way to meet NB:** dropping lock fairness globally (readers no longer need the lock on the sealed
path; writers keep it), forking Ghidra's `DBHandle` locking (replicas reach the same effect without touching the
database layer), and an engine-owned op-log (D5).

### 3.11 Resource governance (E9, hydra.4)

**Principle.** Overload yields an immediate structured `busy{reason:"capacity"}` and never an out-of-memory or a
hang. Measured (A): the first throughput limit is **CPU in the native decompiler processes**, not heap, disk or a
Java lock (12 session threads all in `FileInputStream.readBytes` waiting on decompiler pipes, no blocked thread in
three dumps; the JVM used 1 to 1.6 cores at 12 views; 0 full GCs and 1.58 s of pauses in 24 views at the default
heap); aggregate throughput plateaued at 12 to 24 views (about 200 to 417 funcs/s depending on foreign load; 0.031
to 0.041 CPU-seconds per function regardless of N). Heap bites only below about 512 MB: `-Xmx128m` fails to open
12 views, `-Xmx256m` runs 12 views with 297 full GCs (27.7 s) and ends in `OutOfMemoryError` at 24 **and the
session-reaper thread dies**, `-Xmx512m` runs 24 views (`measA/out/ramp3-h128m.json`, `ramp3-h256m.json`,
`ramp3-h512m.json`). The default heap (a quarter of RAM, 15 GB here) is about 30x what 24 KotOR views need.

| Control | Rule (every value a `Settings` key and advertised in `hello.limits`) | Basis |
|---|---|---|
| Minimum heap | the daemon refuses to start with `-Xmx` below `minXmxMb` (512) unless forced | A: 128 and 256 MB failed |
| Admission seam | E1 builds `Hooks.Admission` (default: allow). Called before `open_project`, `open_program`, `fork_project`, `import` | seam, behaviour-free in E1 |
| Heap admission | admit iff `heapAfterGc + 1.5 x estHeap <= 0.70 x Xmx` and `views < maxViews` (default 32; tested 24) and the per-client cap `maxViewsPerClient` (4). `estHeap` starts at `max(8 MB, 6% of the stored database size)` (KotOR: 6.7 MB for 127.7 MB, 5.2%) and is replaced by the measured delta of the first open of that program. Above 85% after a GC the daemon is `degraded`: it refuses opens, forks and imports and keeps serving reads | A; the percentages are *unmeasured* defaults checked by the squeeze laps |
| Decompiler gate | a fair counting semaphore of `min(CPUs, nativeBudget / 200 MB)` permits (`nativeBudget` = 50% of RAM minus `-Xmx`), round-robin by client, taken where a decompiler is borrowed (`ProgramEntry.java:287`, `Overlay.java:89`); idle decompilers are disposed after 60 s | A: 161 MB busy, 22.6 MB idle, CPU plateau |
| Job Object | the **daemon** creates its own Job Object with kill-on-close at start-up and assigns itself as the first statement of `HeadlessSession.launch` (`S/ProcessJob.java`, E9, D60); the launcher owns none; a killed daemon takes every native decompiler and worker with it (K7: no orphan processes, tested with hung decompilers and a no-job control, SP3(b)). **Whether the daemon outlives its harness is D65's launch sequence, not the job's** | `review-rev6/exp7_jobobject.json`, `review-rev7/exp_jvm_job*.json`; SP3 |
| Decompiler faults | a native crash, hang or timeout fails that one request (`decompiler_failed{function}`, retryable); `returnDecompiler(d, false)` already disposes (`Decompilers.java:27`) and the next borrow creates a fresh one (`ProgramEntry.java:299`); more than 3 failures in a minute on one function trip a 10-minute negative cache. SP4 checks that an in-process `DecompInterface` can be disposed and recreated | design; test: kill -9 a decompiler during 12-client load |
| Daemon threads | accept, reaper, watchdog and governor threads run under `Guarded`: catch `Throwable`, log, restart with backoff, count in `health`; an 8 MB emergency reserve is released on an out-of-memory so the reaper can run | A: the reaper thread died at 256 MB |
| Disk | a fork, base or view requires `free >= estimate + max(5 GB, 5%)` (NTFS estimate = database bytes, ReFS 5%); the machine policy's ask-first rule above 50 GB stays | A |
| Client-side eviction | Y5: LRU, idle time (`viewIdleEvictS`, default 600), `max_views`; only views whose edits are all in the store (always true for Hydralysis views); closing the program (with its discard option: the edits are in the store) keeps the fork on disk, and a reopen replays the pending store (kept warm instead when it has at least `viewKeepWarmRecords` records, D61); an idle view's fork folder is deleted after `viewIdleDeleteS` (86400) | D43, D61, OD8 |
| Runaway scripts | hydra.4: per-client `long` cap, `scriptMaxS` wall budget, CPU and allocated-bytes sampling (`ThreadMXBean`) that set the cancel flag, and a quarantine for a script that ignores cancel (`health.leakedWorkers`, the owner's long cap drops to 1); E7 (hydra.4, W5, D64) kills a script that ignores cancel in a worker JVM once its gate (9.14) passes | D47, D64 |

**Safe eviction is a compare against a pin count**, not a check of "no running request": a view is evictable only
if it has no running request, no lease and no mid-publish step, tested atomically with the close (Y5).

### 3.12 Storage integrity and failure containment

**What was found (measurement C, `crash-C/final_numbers.json`).** 825 kills of the daemon in scenarios a to d, 25
with 8 clients on 8 forks, 102 client kills: no acknowledged commit was lost (0), every readable program matched a
pre-kill or a post-save baseline exactly, the canonical copy kept its tree hash in every counted iteration as long
as it was never opened writable, and a client death never harmed the daemon (102 of 102). Two real defects:

1. **Version-file poison.** A kill during a program save can leave the newest `db.N.gbf` at full size with an
   all-zero header; Ghidra then fails with "Unrecognized file format" and neither falls back to `db.N-1` nor
   repairs it. 12 of 363 kills in scenario (a): 2 of 131 NTFS random-time, 7 of 95 NTFS trigger-timed, 0 of 57
   ReFS random-time, 3 of 80 ReFS trigger-timed (so ReFS is no protection). Deleting that file reopened the last
   acknowledged save in 12 of 12. **Cause, read in the source:** `LocalManagedBufferFile.saveCompleted` renames
   the pre-save file to its final name (`LocalManagedBufferFile.java:696`) and only then calls `setReadOnly()`
   (`:709`) whose `flush()` writes the header and syncs (`LocalBufferFile.java:824`, `:768-790`). D42.
2. **Fork publish is not atomic.** `ProjectFork.copy` moves `.rep`, then `.gpr` (`ProjectFork.java:155-185`); the
   sidecar is written afterwards (`ForkCommands.java:246-257`, a failure only warns). Of 162 kills, 4 left `.rep`
   without `.gpr`, 8 a complete fork without a sidecar (12 retries blocked with `conflict`), 53 an orphan staging
   folder that nothing removes. D41.

**Also found:** a writable open of a pristine project changed `~index.bak` and deleted `~journal.bak` with no edit
(D38); overlays are RAM-only (52 of 52 kills lost them), a killed `promote_overlay` leaves absent, a fork without
the edits, or a fork with them, and a fork without them looks like a good one (the sidecar gains
`promote:"in-progress"` until it is acknowledged, E2); the stale `.lock` and `.lock~` of a killed writable fork
were taken over without error in every case (131 of 131, 95 of 95, 57 of 57, 80 of 80) and are only reported; a
killed import leaves one of three consistent states (absent, imported but not analysed, complete: 15, 25, 5 of 45);
and `TerminateProcess` to process exit took a median of 2.1 s, p95 19.5 s and up to 39 s under load.

**The corruption oracle.** Run after every injected fault and periodically while agents work (X0 builds it,
E6 and every package's own test use it). Each invariant has a planted-violation self-test (D48).

| ID | Invariant |
|---|---|
| K1 | the sealed master and every sealed generation: sha256 of every file unchanged (the hash of a generation equals its `MANIFEST.json` hash from the moment it is sealed, excluding `projectState`, lock files, the sidecar's `state` field and `SEALED.json`), and the engine log shows no writable open of one. **K1u (seal union, D66):** after the sidecar of a sealed generation is edited back to `candidate` or deleted, a writable open is still refused while the registry record or `SEALED.json` stands, and the doctor reports the discrepancy |
| K2 | every `db.N.gbf` of every project (master, views, generations, backups) has the magic at offset 0 and the newest is valid; a 50 ms watcher also fails on any **visible** final-named `db.*.gbf` with an invalid header during writes |
| K3 | every program opens read-only and, for forks and for the disposable clone of a candidate or a generation, writable (a candidate or generation itself is never opened again after its save, and a sealed project never writable); function count and names hash equal an allowed generation; 50 sampled decompile hashes equal the baseline and contain the current function name |
| K4 | generation atomicity: a tagged edit set shows one generation G with acknowledged <= G <= sent |
| K5 | no acknowledged save, import, promote or publish is missing after recovery (the harness's own fsynced ledger is the witness) |
| K6 | a fork path is absent or complete (`.gpr`, `.rep`, a sidecar with `state:"complete"`, or `"candidate"` for a generation, data equal to its base); no staging folder after the next sweep |
| K7 | residue: `.lock` only for live processes, no orphan `tmp*`, JVM temp not growing across restarts, no orphan decompiler or worker process (none left within 5 s of a `TerminateProcess` of the daemon, tested with **suspended** decompilers and a no-job control that must show survivors, SP3(b)), handles and threads bounded |
| K8 | op-log consistency: replaying the store onto the base generation equals each view's state; an interrupted publish or promote is detectable from its record |
| K9 | cross-project isolation: the tree hash of every project not involved is unchanged |
| K10 | liveness: after a client kill the daemon answers `ping`, no request or slot is held for the dead client |
| K11 | view isolation: each agent id writes a unique tag; no view of another agent id and not the head ever shows an unpublished tag. **K11p** (Y5 `subagents_one_process`): two sub-agents in one MCP server process; without `as` they share one view and see each other's tag (documented, D59); with distinct `options.as` they do not |
| K12 | publish linearisation: `CURRENT.log` generations are consecutive, each equals its parent plus exactly the changesets its manifest lists, none acknowledged is missing, none applied twice |
| K13 | non-blocking attribution: `waits.foreignBlocked` is 0 for reads of sealed generations and for view operations; the engine-reported lock wait p99 of reads is **recorded**, and report-only on a loaded machine: its threshold (5 ms is a placeholder) is fixed from a quiet-machine run (foreign load below 25% CPU) and reproduced twice before it fails (D49). The deterministic part of K13 is `foreignBlocked` = 0 |
| K14 | resources: no `OutOfMemoryError`, heap after GC below the hard watermark, `slots inUse` 0 after drain, no dead daemon thread |
| K15 | cache equivalence: a view rebuilt from base + store equals the live view |
| K16 | model equivalence: a sequential reference model folds the changesets in `CURRENT.log` order, conflicts rejected exactly as the engine claims, and equals the head (catches a silent lost update, which no file check can) |
| K17 | store integrity: every sealed record file validates or falls back to its previous version; `CURRENT.log` may have a torn **last** line only (tolerated), never a torn middle |

**Planted violations (X0's self-test, run on every commit).** X1 a zero-header newest version; X2 one flipped
byte in a sealed file; X3 a `.lock` for a live process; X4 a duplicate generation line; X5 an acknowledged op
missing; X6 a torn last `CURRENT.log` line (**must be tolerated**); X7 `.rep` without `.gpr`; X8 mixed generation
tags; X9 an orphan decompiler process that is **suspended** (a busy one exits by itself when its pipe closes, so only a suspended or hung one is a violation the oracle must see); X10 a leaked thread; X11 a generation whose sidecar was edited back to `state:"candidate"` while its registry record or `SEALED.json` says sealed (it must still be reported sealed, D66). The oracle must flag X1-X5 and X7-X11 and pass X6.

**Containment after revision 6.**

| Failure | Blast radius | Recovery |
|---|---|---|
| Client crash | its requests are cancelled, its leases drop, its queued write is not applied, its view fork is a cache | reconnect; the view is rebuilt from the store |
| Script crash or deaf script | one slot and one view, quarantined (D47) | E7 kills the worker (hydra.4, once its gate passes; until then the script runs to its end) |
| Native decompiler crash | one request | pool respawn, negative cache |
| Overload or out-of-memory risk | refusal at admission | evict (client side), retry hint |
| Daemon kill | all in-memory state; on disk: the master untouched (K1), generations only after verification and the `CURRENT.log` append, store records flushed before acknowledgement, forks possibly mid-save | E8 prevents the poisoned header and quarantines an existing one on a disposable fork; E2a sweeps partial forks; views are rebuilt; the supervisor restarts after the process object exits (D55) |
| Kill during fork publish | the path is absent or complete | rk retry or the sweeper |
| Kill during publish | nothing published (`CURRENT.log` unchanged) or fully published; the changeset is durable | the next leader resumes; the orphan candidate is listed (D28) |
| Kill during `promote_overlay` | unknown until acknowledged | the `promote:"in-progress"` marker; Hydralysis does not use `promote_overlay` for publishing |
| Disk full | admission refusal; publish aborts with the staging removed | free space and retry; OD13 (decided): no quota volume, disk-full is exercised through the fault seam (Hydralysis: a patched write raising `ENOSPC`; engine: `diskReserve` above the free space, which must answer `busy{resource:"disk"}`); a real ENOSPC inside a Ghidra save is neither tested nor claimed |
| Power loss or OS crash | **not tested**; a kill is `TerminateProcess` and the OS page cache survives | stated as process-crash scope everywhere (6.1); E12 |

### 3.13 Revision 6 additions to the commands and the error model

- **`seal_project` (v3, E2).** `{"cmd":"seal_project","project":"p1","lineage":"L-9c1e"}` records the project's
  path and its current `Revision` in `<stateDir>/seals/`, writes the marker `SEALED.json` into the project folder and, for a sidecar
  of purpose `generation` or `backup`, `state:"complete"` (the three records of D66; the predicate is their union); `{"cmd":"seal_project","project":"p1","unseal":true,
  "force":true}` removes the record (owner action, logged). Reply `{sealed:true, revision}`. Capability `seal`. It refuses a project that is open writable (`conflict`), and for a sidecar of purpose `generation` or `backup` it rewrites `state:"complete"` (D38). `unseal` removes all three records. The publisher calls it after verification and before the `CURRENT.log` append (4.6, 4.10).
- **`fork_project purpose:"view"`** (v3): a disposable fork whose sidecar carries `owner` (the agent id),
  `lineage` and `base` (generation); admission (3.11) applies. `purpose:"generation"` and `"backup"` stay
  non-disposable (D12) and are not sealed until `seal_project` (generation) or a verified backup (D38).
- **Errors (v3):** `sealed` (`details.next` = `fork_project`), `busy` with `details.reason` in `capacity`
  (`{resource: views|heap|native|disk|client_cap, have, need, retryAfterMs}`), `analyzing` (`{job, progress,
  etaMs}`), `lock_queue_full` for any v3 request (D39), `corrupt_newest` (`{project, program, file, repair}`),
  `decompiler_failed`, `runaway_quarantined`. v2 receives `conflict` or `busy` with the same `details.reason`
  where the situation exists in v2 (V8, V9).
- **`health` additions:** `waits.foreignBlocked` (count since start and in the last minute), `governor{views,
  maxViews, heapAfterGcMb, heapState, decompilers, tokens, nativeBudgetMb}`, `leakedWorkers`, `repairs[]`
  (E8 quarantines and E2a sweeps, each with path and time). The engine knows no lineage; publish queue figures
  are Hydralysis's (`status show=queue`).
- **`status.scheduler`** gains the per-key waiter counts; **replies** gain `waited{queueMs, lockMs, slotMs}` from
  250 ms (D49).
- **Capabilities** added to the list of 3.1: `seal`, `forkAtomic`, `admission`, `waitsAttribution`.

---

## 4. The Hydralysis state contract

This section is the contract for what Hydralysis persists. It is implemented in Hydralysis
(packages Y0a, Y1, Y2, Y3); the engine only supplies the commands in section 3. Everything here
works against hydra.2/3 except where a step says it uses an engine capability.

### 4.1 Durable IO rules (Y0a, ships first, no engine change)

A new `src/hydralysis/durable.py` is the only way record-bearing state is written.

1. `atomic_write(path, bytes)`: temporary file in the same directory, write, `flush`, `os.fsync`,
   then replace. On Windows the replace is `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
   MOVEFILE_WRITE_THROUGH)` (documented to return only when the move is on disk); elsewhere
   `os.replace` plus an fsync of the directory. `PermissionError` (Defender, an indexer holding the
   target) is retried with backoff (50 ms doubling to 500 ms, up to 10 s). Whether write-through is
   honoured by the owner's ReFS Dev Drive is **not verified**; no test can cut power. The claims are
   tested by kill -9 and by torn-file injection, and rest on the documented flags.
2. **Sealed JSON.** A record file carries a top-level `seal: {"algo":"sha256","value":...}` over its
   canonical body (the canonical form of 3.4, Python-only here, so floats are allowed). A reader that finds a zero-length, unparseable or mis-sealed file falls back to
   `<file>.bak` (the previous sealed version, kept by the writer) and, failing that, raises
   `store_corrupt` with both paths. It **never starts empty** (today `load_store` raises on a
   bad file but treats a missing one as "no edits", `workcopy.py:50-58`).
3. `AppendLog` for CRC-framed JSON lines (used by `CURRENT.log`, intent logs, the backup log).
   **Checksum: CRC-32 (IEEE 802.3) as `zlib.crc32` from the standard library**, written as 8
   lower-case hex digits. Hydralysis depends only on `pefile` and `capstone` (`pyproject.toml:9-12`)
   and Python's stdlib has no CRC-32C, so CRC-32C would need a new dependency or a pure-Python
   table; CRC-32 detects torn and garbled lines, which is all it is for (it is not a defence against
   tampering). A **line** is `crc-hex8 SP json LF`. A line is **valid** only if it is complete (ends
   in LF), its CRC matches its JSON bytes and the JSON parses; a final fragment without LF is never
   valid, even if its CRC happens to match, because no append is acknowledged before its LF is on
   disk. Each append is written with `O_APPEND`, then `os.fsync`.

   *Readers* (read-only, hold no lock, never write: the doctor is one) take the longest prefix of
   valid lines. An invalid **suffix** (one or more invalid lines or an unterminated fragment, with
   no valid line after it) is a **torn tail**: it is ignored, not an error, and is reported
   (`torn_tail:{offset, bytes}` in `status` and the doctor). An invalid line **followed by a valid
   one** is corruption (4.4).

   *Writers* repair before they append, **on every acquisition of the log's writer lock**. The
   trigger is **not** "the first append in a process": a long-lived writer process (an MCP process
   doing `commit_revert`, a rollback, a `recover` or `backups.log` appends) has long since made its
   first append, and a second process can damage the log after the first released the lock. **What the
   rule adds, corrected in revision 5** (found by the Y0a polish review, which ran the tests against
   `589432e`): that first code already repaired a fragment **without a final LF** on every append
   (`_clean_tail()`, `durable.py:466`, tested in `_append_locked`, `:531-548`, which also ran the repair on
   the first append of a process and after a failed append), so a second process killed mid-line was already handled, and appending
   after such a fragment would have merged two lines into one that fails its CRC (the commit point
   lost) or, were a fresh line started instead, made the fragment an invalid line before a valid one,
   which the reader rule calls corruption. What the first code did **not** see is **LF-terminated
   damage left by another process** (a complete but invalid line): the long-lived writer appended
   behind it, the invalid line then sat before a valid one and every reader called it corruption
   (`LineageCorrupt: invalid line at byte 17 followed by a valid line`, measured on `589432e`). The
   size comparison below is what catches that, so the rule is new for LF-terminated damage, and the
   no-LF case is covered by both versions. Only the commit job (a new worker process per commit, 4.6)
   would have been safe by accident. So, under the
   log's writer lock (`.commit.lock` for `CURRENT.log` and the intent logs, the log's own `.lock`
   for `backups.log`), on **every acquisition**, the writer first makes the **cheap check**: the
   file ends in LF **and** its size equals the end of the last valid line it knows (the end it
   verified, or wrote itself, at its previous acquisition in this process; nothing remembered
   means a scan from the start; a failed append forgets what was remembered). Unchanged and clean:
   append. Otherwise (another process appended, or the last byte is not LF): (a) scan from the last
   known valid end (from the start when none is known); (b) on corruption (an invalid line before
   a valid one) refuse with `lineage_corrupt` and append nothing; (c) on a torn tail first copy the
   tail bytes to `<log>.torn-<offset>-<sha8>` and force that copy, then truncate the log to the
   end of its last valid line and force it, then append one line to `<log>.repairs` (`{at, offset,
   bytes, sha256, by}`; best effort, its loss costs only the record of the repair); (d) append its
   own line. The check costs a `stat` and one byte when nothing changed, and the bytes another
   process added otherwise. Every step is idempotent, so a crash inside the repair is repaired by
   the next writer. **The whole of it is one hold of the lock.** Acquisition, the cheap check, the repair and
   the append with its `fsync` all run inside a single hold of the writer lock, and the lock is released only
   after the appended line is forced to disk (`AppendLog.append` calls `_append_locked` inside
   `file_lock`, `durable.py:451-457`, and `_raw_append` writes and `fsync`s before it returns, `:531-547`).
   Both locks, `.commit.lock` and the `.lock` of `backups.log`, are **OS locks** (`locks.LaneLock`:
   `msvcrt.locking` or `fcntl.flock`, released by the OS when the holder dies, `locks.py:1`, `:39-41`, at
   589432e), **never an `O_EXCL` lock file with a stale-lock reclaim**: a killed writer leaves no lock that
   another writer has to guess about, and no reclaim can race a live append. A *reader* takes no lock, so
   one that reads while a writer is in the middle of an append can see that writer's unterminated line and
   reports a transient `torn_tail`; that is benign (readers never repair, above) and the next read sees the
   finished line. The tail is never part of a hash chain (`prevHash` is the hash of the previous
   **valid** line). Truncating loses nothing acknowledged, because only a fully written, fsynced
   line is ever acknowledged.

   *Reading budget (done; revision 5).* The Y0a code of `589432e` read a whole log through
   `localio.read_bytes` (`durable.py`, `AppendLog.scan`, `repair`, `last`), which has a hard 32 MiB budget
   (`localio.DEFAULT_MAX_BYTES`). The W0 follow-up `2bf90c7` streams logs in 1 MiB chunks, with no
   `localio` budget (a test builds a log of about 34.8 MB); `last()` reads a bounded tail window by
   default and does **not** look for earlier corruption (`last(strict=True)` scans the whole log), and
   nothing in `src` calls `AppendLog` yet. **Y2 chooses the strictness each caller needs** (a reader needs
   only the last valid line; the lineage open, `verify` and the doctor scan everything) and owns any
   rotation or checkpoint policy (`lineage.py`, 6). No Y0e task remains here (8.2).

   *Tests* (`tests/test_durable.py`): for every byte offset of the last line of a log, cut the file
   there, read (the valid prefix, `torn_tail` reported, no error), append (the repair is recorded, the
   copy exists, the log is clean) and read again (the prefix plus the new line, never
   `lineage_corrupt`); a mid-log invalid line followed by a valid one is refused by the writer and
   by the reader; a crash injected inside the repair (`durable.fault`) heals on the next append;
   a log larger than 32 MiB is appended to and read without error. **Two-process tests**
   (`TwoProcessWriters`, black box over the public API; Y0a's polish `b0b947b` and Y0e's `8e696e2`): process A
   appends a line, releases the lock **and stays alive**; then (1) process B appends through a fault
   (`torn:<n>`) and is killed mid-line, and A appends again: a `.repairs` record and a `.torn-*` copy
   exist, the log is clean and holds A's two lines and no fragment, and **no `lineage_corrupt`** is raised
   by A or by a reader (**a contract guard**: it passes on `589432e` too, because `_clean_tail` already
   repaired a no-LF tail); (2) process B writes an **LF-terminated invalid line** and A appends again: the
   repair is recorded, the invalid line is kept aside, no `lineage_corrupt` (**the discriminating test**:
   on `589432e` it fails with `LineageCorrupt`, on the follow-up it passes); (3) a control in which B
   appends a valid line (no repair). The same with a rollback append (`reason:"rollback"`) and a
   `backups.log` append.
   The commit-level test is `publish_torn` followed by a successful new commit (4.6).
4. Routed through `durable`: `workcopy._save_store`, `backends.write_json` (and so `targets.register`,
   `working/state.json`, job records in `overlayjobs`), and every new file of 4.4-4.6. A write gate in the
   test suite (Y0a's AST gate, `tests/test_durable.py`) fails when a new `write_text`, `write_bytes` or
   `replace` of a record appears outside `durable`; the sites it freezes today, and who moves them, are
   in 8.2.
5. Test hook: `durable.fault(name)` is a no-op unless `HYDRALYSIS_TEST_FAULT=<name>:<action>` and
   `HYDRALYSIS_TEST_MODE=1` are both set (actions: `exit`, `raise`, `torn:<n>`).

The evidence database is SQLite in WAL mode (`evidence.py:42-47`) and is already crash-safe; it is out
of scope here.

### 4.2 Store v3: the op-log and the subject record (Y1)

The store stays one JSON file per target and view (`overlays/<key>.json`), at most 20 MiB
(`MAX_HISTORY_BYTES`), rewritten whole under the view's lock (`.sync.lock` in the code of `627b5b5`). v2 loads and migrates on first write; the
migration only adds keys, writes `<file>.v2.bak` once, and a v2 reader refuses a v3 file
(`record.get("version") not in (1, 2)`, `workcopy.py:57`) so the file is preserved.

```json
{
  "version": 3, "sha256": "<program sha256>", "revision": 41,
  "base": {"lineage": "L-9c1e", "generation": 2, "master_revision": "3fa9c2d1aa01bb42",
           "engine": {"hydraVersion": "12.3-hydra.3", "ghidraVersion": "12.3"}},
  "edits": [
    {"id": "e1...", "address": "0x401000", "options": {"kind": "rename", "name": "Foo", "source": "..."},
     "by": {"client": "hydralysis:123", "harness": "codex"}, "at": 1793100000.1, "batch": null, "seq": 40,
     "effects": [{"subject": "address:0x401000", "field": "name", "before": "FUN_00401000", "after": "Foo"}]}
  ],
  "reverted": [], "journal": [{"revision": 40, "op": "edit", "subjects": ["address:0x401000"], "by": {}, "at": 0}],
  "commits": [{"cid": "c-71ab", "generation": 2, "snapshot": 38, "ids": ["e1...", "e7...", "e9..."],
               "skipped": [{"id": "e4...", "reason": "drift", "subject": "address:0x402000", "field": "name"}],
               "ids_sha256": "...", "bundle_sha256": "...", "at": 1793100500.0, "reverted": false}],
  "archived": [],
  "stale": null,
  "seal": {"algo": "sha256", "value": "..."}
}
```

- `seq` equals the store revision at append. `journal` keeps its shape and is the cheap rebase
  index; its `subjects` are exactly the **coarse subject** strings of `revisions.subjects_of`
  (`address:0x...`, `type:/path`, `structure:functions`, `*`; `revisions.py:30-48`). Rebase
  (`revisions.reconcile`, `:81-110`) is unchanged.
- **Subject record = one entry of `effects[]`:** `{subject, field, before, after}` plus the edit's
  `seq`, `by`, `at`. `field` is one of `name`, `comment:<type>`, `signature`, `type`,
  `variable:<name>`, `definition` (a struct), `body`, `existence`, `report`. `before` and `after` are
  canonical text: a name, a comment, a prototype string, a type's display name, `sha256:<hex>` of a
  structure definition, `absent` for none. Bulk kinds (`import_types`, `import_archive`) record one
  effect `{subject:"*", field:"report", before:null, after:"sha256:<report>"}`; drift for them is
  checked by input hash (corpus or archive sha256, already stored), not per subject.
- Where it comes from: `RusticQuery.java`'s `typeEdit` already reads the old value for each kind it
  applies; **`effects` output does not exist today** (nor `verify_before` nor `annotation_probe`:
  `RusticQuery.java:2305-2345` returns only `applied`, `import_report`, `overlay_state`). Y1
  adds them. This is the largest piece of Java in the Hydralysis train and is sized accordingly.
- v2 records get `effects: null` and `before_unknown:true`; a commit that includes them needs
  `allow_unverified_before:true`.
- The same record serves: (a) rebase (journal strings); (b) drift at commit (`before` against a
  read-only probe of the master); (c) bundles (4.7); (d) publish and merge (4.8); (e) evidence
  provenance: `evidence_add` records `{view, seq, lineage, generation, hydraVersion}` and a claim
  citing a subject can later be flagged `superseded` when the subject's latest effect moved.
- **Commit state is a committed-id set, not a watermark (D32).** There is no `committed_through`
  number: a record is **committed** iff its `id` is in the `ids` of a commit entry whose `reverted`
  is false, and **pending** otherwise. A single watermark (`seq > N` is pending) cannot represent
  a commit that takes a subset (`only`) or that leaves a drifted record pending (`on_drift:"skip"`),
  because a pending record can sit below a committed one: it would be taken for committed and never
  replayed. The entry's fields: `ids` (committed, authoritative), `skipped` (selected but left
  pending, with the reason; informational, never read to decide state), `snapshot` (the store revision
  `upTo` at step 1; informational), `ids_sha256` (over the sorted `ids`), `reverted`. At most one
  commit entry exists per `cid`.
- **Replay set.** The working copy replays `pending`: the edits that are not committed, **in `seq`
  order**, onto a base that already contains the committed ones. The program's `overlay_state` marker
  (`RusticQuery.java:2300-2339`; `workcopy.state_of`, `:83-91`) is extended from
  `{revision, edits, ids_sha256}` to also carry `base:{lineage, generation}` and `committed_sha256`
  (the sha256 of the sorted committed ids), and `_prefix_matches` (`workcopy.py:341-349`) compares the
  marker's ids against the **pending** list and requires `base` and `committed_sha256` to match. A
  program built before a commit therefore never matches after it, and a v2-style marker (no `base`)
  matches only generation 0 with an empty committed set. Without this a commit would be applied
  twice. `state_of` reading `store["edits"]` becomes `pending_of(store)`.
- **What a subset or skipping commit does, exactly.** The unit is the **record** (one edit with all
  its effects): it is committed whole or stays pending whole. A selection `only:{ids, authors}` names
  the records `S`. A record depends on every earlier pending record that shares a coarse subject with
  it (the strings of `revisions.subjects_of`; a record with subject `*`, a bulk import, shares one
  with every other); `S` must be closed under that relation, else the commit refuses
  `selection_not_closed` with the missing ids, or adds them when `include_dependencies:true`. The
  records are applied in `seq` order. **A `batch` is selected whole or not at all**: an `only` that
  names some records of a batch (or an author who owns only part of one) selects the rest of it too
  through the closure (`selection_not_closed` names them, or `include_dependencies:true` adds
  them), because `revert` already treats a batch as one unit and a commit must not split what a
  revert cannot. With `on_drift:"skip"`, a record whose first effect on a
  `(subject, field)` no longer matches the master (4.6 step 5) is skipped **together with every
  later record of `S` that depends on it**; the rest of `S` is committed. The commit entry then holds
  `ids` = the committed records and `skipped` = the rest of `S`; records outside `S` are simply
  not in `ids`. Skipped and unselected records stay pending, keep their `seq` and their place in
  the replay order, and are replayed onto the new generation; their `before` values are checked
  again at the commit that takes them. **Invariant:** for any coarse subject, the committed
  records are a prefix, in `seq` order, of that subject's non-reverted records. Only the dependency
  closure and skip propagation can keep it true, and it is what makes replaying a pending record
  after a committed record with a later `seq` safe (they never share a subject). **The invariant is
  per coarse subject, not semantic.** A subject is an address, a type path or `structure:functions`
  (`revisions.subjects_of`), so a subset commit can ship a `signature` or `data_type` edit (subject
  `address:...`) without the pending `struct` edit it uses (subject `type:...` or
  `structure:functions`); the closure cannot see that (section 6 already said a rebase cannot).
  What happens is not assumed but tested (Y2, `subset_missing_type`): applying the signature in the
  candidate must **fail closed**, i.e. `apply_overlays` rolls the whole transaction back and the
  commit ends `ABORTED` with the effect named, and nothing is published. If the engine instead
  accepts the signature and quietly substitutes an undefined type, the test fails and the closure
  must be extended with type references (a `uses` list recorded in `effects`) before subset commits
  ship; until then `only` is documented as "no semantic dependency tracking".
- **`revert` of records.** `revert` of a record whose id is in a live commit's `ids` is refused
  (`already_committed`); undo it with a new inverse edit or `commit_revert`. `revert` of a
  **pending** record removes it from `edits[]` and accepts a record id or a `batch` id
  (`workcopy.py:569-591`). Removing an earlier record leaves a later pending record on the same
  `(subject, field)` with a stale `before` (it equals the removed record's `after`): the step 5
  chain check and `verify_before` of 4.6 would flag it as drifted against the master, and with no
  `overwrite` the owner could not commit it. **Rule: a `revert` that would leave such a record is
  refused with `has_dependents` and the ids of the later records; `cascade:true` reverts the named
  records and every later pending record of the same `(subject, field)` (a batch always goes
  whole).** Recomputing the `before` chain is rejected: a recomputed `before` is no longer the value
  the analyst saw when the edit was made. Test (Y1): the earlier record of a chain is refused with
  its dependents named; `cascade` removes the chain; the last record of a chain reverts freely;
  reverting by `batch` id removes the batch.
- **Compaction (policy; the caps are real).** `MAX_OVERLAYS = 4096` (`analysis.py:26`) is checked on
  every `edit()` (`workcopy.py:~547`) and the 20 MiB `MAX_HISTORY_BYTES` on every load and save
  (`workcopy.py:54,74`); `effects` with `before` and `after` make a record larger than today's.
  Committed records are history, not state, so they are **archived, never deleted**: when a commit
  reaches `FINALIZED`, the records of the **previous** live commit are moved out of `edits[]` into
  `overlays/archive/<store key>/<cid>.records.json` (a sealed file written through `durable` before the store
  rewrite that drops them), and the store keeps only that commit's entry reduced to `{cid, generation,
  count, ids_sha256, archive}` under `archived[]`. The latest commit's records stay in the store,
  because `commit_revert` needs them (a revert makes them pending again). Rebase and bundle export read
  an archive on demand; the committed ids needed by other views' rebase come from the generation
  manifests (4.4), which list them. A reverted entry is kept as history (its ids are pending) and archiving skips it. **`commit_revert`
and the archive:** after the latest commit c2 is reverted, the latest *live* commit is c1 again, but
c1's records were archived when c2 finalised, so they are **not** in `edits[]`. `commit_revert` of
c1 therefore **rehydrates**: it reads `overlays/archive/<store key>/<cid>.records.json`, verifies the
file's seal and its `ids_sha256` against the entry, and in the same atomic store write moves the
records back into `edits[]` (as pending, in `seq` order), drops c1's `archived[]` entry and marks
the commit entry `reverted:true`; if the rehydrated records would exceed the 4096-record or
20 MiB caps the revert is refused with `store_full` and nothing changes (the owner commits or
exports first). A missing or mis-sealed archive refuses with `archive_unreadable`. The statement
"the records are still in the store" holds only for the *latest* commit; for an earlier one the
archive is the source. Test (Y2, `revert_chain`): commit c1, commit c2, revert c2 then c1: the
records of both are pending again, in `seq` order, and the generation pointer is back at 0. After this the 4096 and 20 MiB limits bound the **live**
  records (pending plus the latest commit's), not the history. A store with more than 4096 pending
  records still cannot take another edit: commit it (a subset commit is allowed), or export a bundle
  (section 6).

**Journal = recovery = commit source, stated once.** The store is written, sealed and fsynced
inside the view's lock **before** `edit()` returns (`.sync.lock` in the code of `627b5b5`, `workcopy.py:543-554`). So (1) an acknowledged edit
is in the record; (2) the only crash window is "applied to the working copy but not yet stored",
which is self-healing: the program's marker then claims more records than the store has,
`_prefix_matches` returns `None` (`workcopy.py:341-349`) and the next sync rebuilds from the store;
(3) the commit reads the same record set. There is no second log. The edit's lifecycle: `proposed`
(request) -> `applied` (working copy, in the daemon) -> `recorded` (sealed store; the acknowledgement)
-> `committed` (its id is in a live commit's `ids`) -> `archived` (a later commit finalised) ->
`superseded` (a later generation changed the subject).

### 4.3 Idempotency in the client (Y0b)

`hydra.Engine.call` retries **every** command once after `closed` (`hydra.py:268-287`). That is
correct for reads and wrong for a mutating call whose reply was lost. Rules: reads, opens, `status`,
`hello` and `script` with a read action are retried; `script apply_overlays`, `save`, `import`,
`fork_project`, `edit`, `rename`, `comment` are **not**: they raise `EngineError` with
`code:"closed"`, `details.ambiguous:true`, and the caller reconciles (`_sync` re-reads the marker;
`fork_project` checks whether the destination appeared). Hydralysis edits are identified by their
`id`; a commit by its `cid`. What Y0b shipped beyond that list, recorded as decided: `close_project`,
`refresh`, `switch` and `reopen` are also retried (a repeat of a close that landed answers `not_found`,
which the caller reads as done); a lost `apply_overlays` reply now fails the **current** sync with
`details.ambiguous` and the **next** sync self-heals from the marker (where the old blind re-send hid
it); a mutating call on a connection that died before it was sent is reported ambiguous too
(conservative: a cheap `ping` before the call would reduce false ambiguity, optional, not required);
user scripts (`userscripts.py`) and `RusticSetup.java` are not re-sent after a drop, since 4.3 allows
only a read action of `script`.

### 4.4 Lineage and generations (Y2)

Layout, under the Hydralysis root (not beside the project: adoption never writes the project
folder; the root is on the owner's Dev Drive so forks are block clones, and `generations_root` can
override it, with a doctor warning when it is not the volume of the current generation):

```
<root>/lineages/<lineage id>/
    lineage.json                {format, id, origin_key, origin_gpr, program, sha256, createdAt}
    CURRENT.log                 append-only, CRC'd lines (+ .repairs, .torn-* after a tail repair, 4.1)
    commits/<cid>.intent.log    CRC'd lines (4.6), one log per cid, lines carry an `attempt` number
    backups.log                 CRC'd lines (4.5)
    gen/0002/<name>.gpr, <name>.rep, <name>.fork.json, MANIFEST.json
    .commit.lock                OS lock: one commit per lineage
```

Generation 0 is the adopted project in place, never written. `CURRENT.log` line:

```json
{"seq":3,"gen":2,"cid":"c-71ab","reason":"commit","gpr":"<root>\\lineages\\L-9c1e\\gen\\0002\\kotor.gpr",
 "manifestSha256":"...","engine":{"hydraVersion":"12.3-hydra.4"},"at":"2026-10-27T15:00:00Z","prevHash":"..."}
```

`reason` is `register`, `commit`, `rollback` or `recover`. The reader takes the last valid line.

- **Torn tail** (an invalid suffix with no valid line after it, 4.1 item 3): a **reader** ignores it
  and reports it in `status` and the doctor; it never repairs and never raises. It can only show an
  older, consistent state, because a line is forced before any acknowledgement or later step. The
  **next writer** repairs it first, **on every acquisition of** `.commit.lock`, before any append (4.1 item 3: not only on a process's first append): it preserves the
  fragment as `CURRENT.log.torn-<offset>-<sha8>`, truncates the log to its last valid line and
  records the repair in `CURRENT.log.repairs` (the same rule applies to the intent logs and
  `backups.log`). So a crash in the middle of the commit-point append is followed by a normal,
  successful new commit, not by a lost line or a false `lineage_corrupt`. A long-lived writer process
  is covered by the same rule: the two-process test of 4.1 is part of the Y2 fault matrix.
- **Mid-log gap** (an invalid line with valid lines after it): `lineage_corrupt`. Reads resolve to
  the last good line before the gap with the error shown on every `status`; commits and reverts are
  refused until the owner repairs it. Silent repair of a mid-log gap is not done; the torn-tail
  repair above is the only automatic one, and it is recorded.
- `MANIFEST.json` in a generation folder: `{format, cid, base:{generation, revision}, engine,
  dbVersions, files:[{path,size,sha256}], filesetSha256, backups:[manifest sha256...], store:{view,
  revision, snapshot, ids:[committed record ids], skipped:[ids], ids_sha256, bundle_sha256}, selfSha256}`
  (the ids make the manifest the durable source for step 9 and for other views' rebase). **A generation folder is invisible until its manifest
  exists and verifies**; it is built directly in its final folder, so no rename publishes it.
- **Registry is a cache.** `targets.json` records `lineage: {id, origin_key}` and keeps `gpr`
  as the adopted path. `targets.resolve` (`targets.py:90-111`) returns `gpr` from `CURRENT.log`
  and **`key` from the stored `origin_key`** (D11), so overlay stores, working directories and
  view keys survive a flip. A crash between the `CURRENT.log` append and any `targets.json` write is
  harmless. `query.stop` (`query.py:224`) releases the programs of every generation.
- Existing targets with no lineage resolve exactly as today (`key = target_key(gpr, program)`).
  The lineage is created lazily at the first commit; creating it records the current key.

### 4.5 Backups (Y2 on hydra.2/3, switched to the engine's by Y4d)

- Policy (Hydralysis config): `backup_roots: [{path, mode: auto|copy, required}]`
  (first is primary; a block clone on the same volume), `backup_min_verified` (default 1),
  `backup_min_independent` (default 0; the owner can set 1 for a real copy on another volume such as
  `E:\dev-cold`), `backup_confirm_gb` (default 50: above it a backup needs `confirm_large:true`; the
  machine rule is ask before creating anything over 50 GB). That threshold is **per backup**, so many
  below-threshold backups add up unbounded. The confirmation text and the doctor therefore always
  state the **cumulative** cost: the sum of the sizes of the lineage's verified backups under each
  root (from `backups.log`) plus this one, the free space of the root's volume, and, for a clone, the
  caveat that its logical size overstates the physical blocks it adds. `backup_root_warn_gb`
  (default 200) makes the doctor warn when a root's cumulative logical size passes it; no backup
  is deleted automatically (D28).
- A block clone protects against a bad commit, **not** against loss or corruption of the volume. The
  manifest says `independent:false`; the doctor shows the count of independent verified copies.
  Secondary roots are always `mode:"full"` copies (a clone shares blocks with its source).
- Layout `<backup root>/<lineage id>/<UTC yyyymmddThhmmssZ>-<revision8>-<purpose>/` with the project
  files and `backup.json` written last. A folder without a verifying `backup.json` is invisible.
- Before relying on a backup (commit, or the upgrade gate's `backup` argument) the client re-reads and
  re-hashes every file against the manifest with `hashlib` and checks the self-hash. The engine's check
  is the cheap one (3.4); it is not a security boundary.
- `backups.log` records `{id, manifestSha256, root, verifiedAt}` per copy so that a deleted or replaced
  backup is detectable.
- **Sealing a backup (revision 8, D66).** A verified backup is sealed. On hydra.4, `fork_project purpose:"backup"` writes
  `purpose:"backup", disposable:false`, the registry record, `SEALED.json` and `state:"complete"` after its `verify`. On
  hydra.2/3, after its own re-hash and `backup.json`, Hydralysis rewrites the fork's sidecar to `purpose:"backup",
  disposable:false, state:"complete"` and writes `SEALED.json` through `durable`. A backup made on hydra.2/3 and met by a
  hydra.4 engine without an engine-readable seal record is **legacy**: `backend action=backups` lists it with `sealed:false`
  and `op=verify` **adopts** it (re-hash against `backup.json`, then `seal_project`); a legacy backup that fails the re-hash is
  labelled `legacy_unverified`, is never used as a restore source or as the `backup:` of an upgrade open, and is listed for
  manual removal (D28). Until adopted it is protected by client discipline only, which the listing says.
- On hydra.2/3 (no `purpose`, no `open`): `fork_project` into the backup folder with **`writable:false`**
  (the field defaults to true, `ForkCommands.java:82`, and a writable registration would hold the
  backup open for writing), then `close_project`; the fork's sidecar is that of any fork. Python
  hashes the files and writes `backup.json` with `writer:"hydralysis"`; if the hash check fails it
  writes no manifest (the folder stays invisible, 3.4).

### 4.6 Commit as a new generation (Y2)

A commit is a Hydralysis job of kind `commit` (`overlayjobs`/`jobowner`: a worker process, so it
survives the MCP process). Request: `ghidra_query action=type_edit options.kind=commit`.

```json
{"kind":"commit","expect_revision":41,"confirm_one_way_upgrade":true,"on_drift":"refuse",
 "only":{"ids":null,"authors":null},"include_dependencies":false,"dry_run":false,"backup":"auto"}
```

`only` null means every pending record. A non-null `only` selects a subset and `on_drift:"skip"`
leaves drifted records pending; what both do to the store is fixed in 4.2 (committed-id set,
dependency closure, skip propagation).

Preconditions (checked first, in order; any failure creates nothing): `expect_revision` equals the
store revision; `base.master_revision` equals the current generation's revision, else `master_drifted`
(rebase first, 4.7); a non-empty effective record set; no `before_unknown` records unless
`allow_unverified_before`; `confirm_one_way_upgrade:true` whenever `open_project.format.upgradeRequired`
is true **or unknown** (always the case on hydra.2/3, which has no `format`); `.commit.lock` and
the committing view's lock (D44) held briefly to snapshot `upTo = store.revision` and the reference texts of step 1.
`dry_run` runs the preconditions, the selection closure and the drift pre-pass of step 5 against a
read-only probe of the current generation and returns the plan (the `ids` it would commit, `skipped`,
`excluded` functions, the cumulative backup cost); it has no side effects (tree-hash tested).

The confirmation text names what is lost: after the commit only engines at program DB version >= the
engine's can open the generation. Versions are read from `analysisIdentity.dbVersions`; for the other
Ghidra releases the client uses the repository's `format-matrix.json` (E2), which at this commit
records what `README.md:1003-1004` states (program database 33 on main and 32 in 12.1.4; data type
database 3 and 2) and is checked by the DB-version gate.

Steps. Each step is preceded by a forced line in `commits/<cid>.intent.log`:

1. `PREPARE` - preconditions above, then, still holding the committing view's lock (the only moment edits are held
   up, bounded by `snapshot_budget_s`, default 20, after which the sample shrinks): record `upTo`, the
   selected set `S` after the dependency closure of 4.2 and its `ids_sha256`; and capture the
   **reference**: the decompile text, taken from the working copy at `upTo` (the working copy is
   in sync with the store here, and its `overlay_state` marker is written to the intent log as the
   proof), of the sampled functions (default cap 25 per effect kind) touched by `S`. The reference
   is a **snapshot at `upTo`**, not the live working copy, which keeps changing while steps 2-7 run.
   A function whose subject also appears in a pending record outside `S` is excluded from the
   comparison of step 7 (reported as `excluded`), because the working copy differs from the
   candidate there by design.
2. `BACKUP_DONE {backup, manifestSha256}` - a fresh backup of the **current generation** per policy,
   re-hashed. A failed primary aborts. A failed secondary aborts or warns per `backup_min_verified`.
3. `CANDIDATE_RESERVED {gen}` - the generation number is reserved in the log **before** the folder
   exists, so a crash cannot reuse a number for a different candidate.
4. Fork: `fork_project(project=<current generation>, path=gen/000N, purpose:"generation")`; open the
   candidate writable owned by the job only, `open_program writable:true upgrade:true backup:<manifest>`
   (the gate passes because the backup is of this revision; D12/D13). The candidate is never shared, and it is
   **writable on purpose** (revision 7, B1): its sidecar says `state:"candidate"`, which D38 does not seal, so the replay of
   step 5 and the save are not refused; it becomes unwritable only at step 7b.
   On hydra.2/3, which has no `purpose`, the job rewrites the new fork's sidecar to
   `disposable:false, purpose:"generation", state:"candidate"` through `durable` right after the fork, so that a later
   hydra.4 engine does not take the generation for a disposable fork (D12) and does not take it for a sealed one
   (D38); this happens before step 7 hashes the folder.
5. `APPLIED {ids_sha256, n, skipped[]}` - first a **drift pre-pass**, read-only on the opened candidate
   (nothing written yet): for the first effect of each `(subject, field)` among `S` in `seq` order,
   `annotation_probe` compares its `before` with the live value; every later effect on the same
   `(subject, field)` is chain-checked offline (its `before` must equal the previous effect's
   `after`). A record with any mismatch is **drifted**. `on_drift`: `refuse` (default) returns the
   full list and publishes nothing; `skip` removes each drifted record and every later record of
   `S` that depends on it (4.2) from the set, leaving them pending, and commits the rest (`C`, the
   ids that go into the commit entry; `skipped[]` is the removed list with reasons). There is no
   `overwrite`. Then, inside **one transaction**, run RusticQuery `apply_overlays` on `C` with
   `verify_before:true`: every effect's `before` is compared with the live value again before it is
   written, as the authoritative check (nothing else writes the candidate, so a mismatch here after
   a clean pre-pass is a defect): it rolls the whole transaction back and names the effect, and the
   commit aborts. Write the program option `hydralysis_commit {cid, lineage, base_generation, snapshot,
   ids_sha256, bundle_sha256, engine}` (provenance inside the data) and **clear the
   `overlay_state` option** that `apply_overlays` writes into the program (`RusticQuery.java:2334-2335`):
   the candidate is a published generation, not a working copy, so it must carry exactly one
   marker, `hydralysis_commit`; a stale `overlay_state` would be read by any fork of the generation
   (`_marker`, `workcopy.py`) as a claim about records it does not hold. Y1 gives `apply_overlays` a
   `state:null` form for this, and Y2's base builder treats a non-empty `overlay_state` on a
   freshly forked generation base as stale and clears it (a second check that also covers a
   generation made some other way; the marker's `base` and `committed_sha256`, 4.2, make a leftover
   mismatch anyway). Then `save`, `close_project`.
6. `FILES_FORCED` - Python opens every candidate file and `os.fsync`s it (Ghidra's save does not promise
   an fsync; whether it does is **not verified**, so it is done unconditionally).
7. `MANIFEST` - hash every file, write `MANIFEST.json` (forced, write-through replace), then
   `VERIFIED` after: make a disposable **clone** of the candidate (`fork_project purpose:"fork"`), open the clone read-only (and writable for the K3 check), never the candidate itself, so that the hash of this step is the hash that 7b seals, and check the program `sha256` equals the
   master's; function count and analysed flag equal; `annotation_probe` on every applied effect gives
   `after == actual` (same normaliser); the decompile of each sampled touched function (default cap 25
   per effect kind) succeeds and equals the **reference captured at `upTo` in step 1** (same engine,
   so identical), except the `excluded` functions; and a
   spot-check of 25 functions the commit did **not** touch decompiles identically to the previous
   generation (a regression guard for the engine upgrade). Any failure: `ABORTED`, the candidate is
   left unregistered for inspection, nothing else changes. The hash of the sidecar in `MANIFEST.json` is taken **with its
   `state` field removed**, because `state` is the lifecycle marker that step 7b changes.
7b. `SEALED` (revision 7, B1) - the job calls `seal_project` on the verified candidate (hydra.4: the registry record,
   `SEALED.json` and the sidecar's `state:"complete"`, 3.13, D66) or, on hydra.2/3, writes `SEALED.json` and rewrites the sidecar
   to `state:"complete"` through `durable` (client discipline; a hydra.4 engine reads either as sealed). From here on a writable open, `analyze`, `save`
   or an owner script on the candidate is refused with `sealed`. A forced `SEALED` line is written to the intent log.
   `seal_project` is the commit point of the candidate's **immutability**; the commit point of the **publish** is
   step 8. A sealed candidate that is never published is harmless: it is unreachable from head and listed for manual
   removal (D28).
8. `PUBLISHED` - append the `CURRENT.log` line and fsync. **This is the commit point of the publish** (the candidate has been immutable since 7b).
9. `FINALIZED` - idempotent, keyed by `cid`, holding the committing view's lock, in **one atomic store write**: append
   the commit entry (`cid`, `generation`, `ids` and `skipped` read from the generation's
   `MANIFEST.json`, `snapshot`, hashes), set `base` to the new generation, archive the previous
   commit's records (4.2); then mark every other view's store stale (4.7; **lock order:** the committing view's lock first, then the *record* lock of one other view at a time, never two at once and never another view's edit lock; the mark is an atomic replace of `views/<id>.json`, so a view that is editing is not waited for and meets the stale mark at its next call); mirror to `targets.json`;
   release the locks. If an entry for this `cid` already exists the step does nothing.

Edits are **not** blocked during steps 2-7: records added meanwhile have `seq > upTo`, are in no
commit's `ids`, and so stay pending whatever their `seq`. Their `before` is the pre-commit state if
they touch a subject of `C` (the next commit's drift pre-pass reports that; it is not hidden), and
the post-commit state otherwise.

**Recovery table** (run when a lineage is opened and by `commit --resume`, under `.commit.lock`):

| Last durable intent | Observed | Action |
|---|---|---|
| none or `PREPARE` | no candidate folder | `ABORTED`, nothing to clean |
| `BACKUP_DONE` | a verified backup exists | keep it (it is never deleted), `ABORTED` |
| `CANDIDATE_RESERVED` ... `FILES_FORCED` | a partial or unverified `gen/000N` | invisible (no valid manifest); left in place, listed by `backups`; `ABORTED`; the client may resubmit with the same `cid` as a **new attempt** (the intent log's `attempt` number grows and a **new generation number** is reserved; the abandoned folder is never reused) |
| `VERIFIED` or `SEALED`, no `CURRENT.log` line | a verified, unpublished candidate (sealed, or still `state:"candidate"`) | left unpublished; a resubmission re-hashes it against its manifest, seals it if it is not sealed yet and publishes it (opt-in `resume_verified`, default false) |
| `PUBLISHED` written, `CURRENT.log` line torn or missing | the tail fails its CRC or has no LF | before the commit point: `ABORTED`. Readers ignore the torn tail and the **next writer repairs it** (4.1, on every acquisition of the lock: preserve the fragment, truncate to the last valid line, record the repair) before any append, so a resubmission as a new attempt appends a clean line; the verified but unpublished candidate stays unpublished (`resume_verified` applies as in the row above) |
| `CURRENT.log` line valid for this `cid` | `FINALIZED` missing | **roll forward**: re-hash the candidate against the manifest named in the line; equal: run step 9 (its ids come from that manifest, so the store ends in the same state whenever and however often this runs); not equal: append a `rollback` line to the previous generation (`reason:"candidate_failed_reverify"`), report |
| `FINALIZED` or `ABORTED` | | done |

`commit_abort` is honoured before step 8; after it the answer is `cancel_too_late`.

**Revert** (`options.kind=commit_revert`): only the latest **live** (not reverted) commit. Check the
previous generation's manifest still verifies; append a `rollback` line; the commit entry is marked
`reverted:true` and its `ids` become pending again (for the latest commit its records are still in
`edits[]`, because archiving leaves the latest commit's records in place; for the commit that becomes
the latest after an earlier revert they are **rehydrated from the sealed archive** in the same
atomic store write, or the revert is refused with `store_full` or `archive_unreadable`, all in 4.2)
and every view is marked stale. Restoring from a
backup is `fork_project` from the backup into a new generation folder, verified and registered the
same way; nothing touches an existing folder.

Fault points (`durable.fault`): `commit.after_prepare`, `after_backup`, `after_reserve`, `after_fork`,
`mid_apply`, `after_save`, `after_force`, `after_manifest`, `after_verify`, `after_seal`, `before_publish`,
`publish_torn`, `after_publish`, `finalize_mid`. A fault at or after `after_seal` leaves a sealed candidate; by default (`resume_verified` false) a new attempt never reuses it and reserves a new generation number, and with the opt-in `resume_verified:true` a resubmission re-hashes the sealed candidate against its manifest and publishes it without rebuilding (the recovery row above); the test `candidate_writable_until_seal` asserts that the candidate opens writable and saves before 7b and that a writable open, `save` and `analyze` are refused with `sealed` after it (red on a build whose sealed predicate is `disposable:false`). `publish_torn` writes the first `n` bytes of the
`CURRENT.log` line and exits (`torn:<n>`); the test then runs recovery and a **successful new
commit** with the same `cid` (a new attempt), for `n` at several offsets including 0, mid-line and
every byte but the LF, and asserts the repair record and the preserved fragment, one published line
for the `cid`, and O1-O6. Further faults: `intent_torn` (the same for an intent log) and a
subset-commit variant of `mid_apply` and `finalize_mid` (4.2: the skipped record is still pending and
is replayed, and is not taken for committed). The oracle after every fault run and recovery:
**O1** every file of generation 0 and of the previous generation is byte-identical (tree hash, excluding
`projectState` and lock files); **O2** every acknowledged store revision is present and the store's committed-id set agrees with the generations: the `ids` of each live commit entry equal the `store.ids` of that commit's published manifest (an archived entry is compared by `ids_sha256` with its archive file), no id is in two entries, and every skipped record is still pending, so nothing is committed twice or lost; **O3** `CURRENT.log`'s
last valid line names the old or the new generation and, if new, its manifest verifies and a read-only
open succeeds; **O4** no folder without a verifying manifest is offered anywhere; **O5** resubmitting the
same `cid` yields exactly one published `CURRENT.log` line and one commit entry; **O6** killing during recovery and recovering again reaches the
same state.

### 4.7 When the master generation changes

Other views (a named view forks from the master, not from `shared`; `workcopy.with_view`, `:36-43`):

| Thing | Behaviour |
|---|---|
| The committing view | The new commit entry's `ids` join the committed set; its working copy is rebuilt from the new generation's base, replaying only the pending records (those not in any live commit's `ids`, in `seq` order), including any the commit skipped or did not select. |
| Other views' stores | `stale: "master_generation_changed"` and `base` unchanged; reads keep answering from their working copy, labelled with the generation they came from; mutations are refused with `stale_view` until `rebase`. |
| `rebase` (`type_edit kind=rebase`) | Per record: drop it if it is already in the master, that is if its id (or, for a record that came from another view by publish or merge, its `merged_from` `{view, id}`) is in the `store.ids` of the manifest of a generation after this view's base (the committing view's store may be archived or another store, so the manifests are the source, 4.4); `converged` if the new master's value already equals its `after`; keep if a probe shows the master's value equals its `before`; otherwise list a conflict `{subject, field, before, master_now, after}`. The view's base binding moves only when the list is empty or resolved. The outcome is recorded in one atomic store write. |
| Working copies and bases | Keyed by `(lineage origin_key, generation, master revision, engine release)`; a different key means a different directory (`workcopy._base` keyed by master revision and engine release already, `:304-307`; the key adds the lineage and generation). **One** shared base per key across all views, so a new view costs one clone, one writable open and a replay. A replay that was running against the old base cannot be adopted (its marker names the old base: `base` and `committed_sha256`, 4.2). A base forked from a generation holds no `overlay_state` (commit step 5 cleared it; a non-empty one is treated as stale and cleared), so the first sync replays the whole pending list onto it. |
| In-flight exports | They snapshot at start; the header records `{lineage, generation, master_revision, engine release}` and resume is refused if any differ (`exporting.py:115-118` records the engine release and query key today). |
| Open programs of other clients | The old generation is immutable, so their reads stay consistent; they get the existing `refreshed`/`stale` marker through `Session.annotate` only if the registered path changes, which it does not for them. A client that wants the new generation reopens. |
| Runtime sessions and evidence | Not invalidated; provenance names the generation and a claim is flagged `superseded_by_generation` on read. |
| A process that writes into a generation folder (an editor tool, another daemon) | `Revision.of` of a generation folder differs from its manifest: the lineage is flagged `tampered`, commits are refused until the owner re-adopts, and the engine refuses a writable open of a sealed generation (D38). (`projectState` is already excluded from `Revision`.) |
| Any other process reading the original `.gpr` | Sees generation 0 with none of the committed annotations; this is by design (the master is never written, D9, D38) and there is no GUI that could expect otherwise (headless only, D36). |

### 4.8 Publish and merge between named views (Y3, client only)

`type_edit kind=publish|merge` with `expect_revision` of the destination. For each effect of the source
view's edits after its `published_through`, compare its `before` with the destination's current value
of that subject. All match: append the edits to the destination with new ids and
`merged_from:{view, id, seq}`; otherwise return conflicts `{subject, theirs, mine}` and accept
`resolve:{<subject>: take_mine | keep}`. Idempotent through `published_through`. Locks of two views are taken in lexicographic order of their keys. **Per-agent default views are enabled by default in revision 6** (D43, 4.10).

### 4.9 Annotation bundles (Y1)

`*.hydralysis-annot.json`: `{format, program:{sha256, language, compiler, image_base, name}, base:{lineage,
generation, master_revision, engine, dbVersions}, store:{view, revision, ids_sha256}, records:[{id,
address, va, rva, kind, options, source, by, at, effects, committed}], bundle_sha256}`; the hash is over
the canonical JSON of 3.4 (sorted keys, minimal separators; Python-only here) without the hash field;
absolute paths and personal data are stripped; **no game-derived bytes are embedded**. `export_bundle`
is read-only (filter by id, author, revision range, and `state` = `pending`, `committed` or `all`;
it reads archived records on demand, 4.2). It exports each selected record whatever its commit state,
with `committed:true|false` as information only: it is not an input of import, and the committed-id set
is store state, not bundle content, so the store schema change of 4.2 leaves the bundle format as it
was. `import_bundle` is a dry run by default: it validates `bundle_sha256`, program `sha256`,
language and compiler, probes every record's `before` against the target, and reports `base_drift`; with
`apply:true` it adds the records to a **named** view as proposals (`imported_from`). It never writes a
generation. Cross-build address mapping stays in `crossbuild.py` and is out of scope.

### 4.10 Per-agent views, the shared base, write-ahead and the publish queue (revision 6)

This section replaces the rev5 statement that per-agent default views are not enabled (4.8, D26). The contract
is the Hydralysis half of 3.9; the packages are Y2 (base, connections, locks, `integrity.py`), Y3 (publish
queue, rebase) and Y5 (the default view, identity, eviction).

**Records in the lineage folder** (all written through `durable` and sealed, 4.1; `CURRENT.log` is unchanged):
`views/<viewid>.json` (agent id, agent name, boot id, pid, lease, base generation, state, last seen), `pending/<csid>.json` (a sealed changeset),
`done/<csid>.json` (its outcome), `publish.lock` (an OS byte-range lock file), `_base/<generation>-<release>/`
(the shared base, D44) and its completion marker. A reader that finds a newer `format` refuses (5.2).

**Identity (one rule, D59; 4.11 and GR5 say the same).** The view of a call is `(lineage, agent id)`. The agent id is
`options.as` when the call carries it, otherwise the process default `<MCP clientInfo name>@<boot id of the server
process>`; a process id is never used (D43). That default is an ordinary per-agent view and **not** the shared view:
callers that present the same id (all the sub-agents of one MCP server process that pass no `as`) share one view, see
each other's unpublished edits, and are kept from overwriting each other by `expect_revision` and the subject-aware
rebase, which is conflict control and not isolation. The name `shared` is reserved for the shared collaboration view,
which a caller must name explicitly (`view:"shared"`; mandatory `expect_revision`, per-view lock). `options.as` rides
the `options` bag of `ghidra_query` and `ghidra_run`; a tool without an `options` bag (the native address tools) takes
no identity and reads the master. A call that names no view and has no edits reads the master.

**Boot id, adopt and resume (revision 8).** The boot id is 16 random hex digits generated at server start; a restart of the
harness's server therefore starts a new default id, and the previous process's pending edits stay in the store under the old
id. The rule: (a) the view record carries `agent name` (the `clientInfo` name), `boot id`, `pid` and `lease_until`
(refreshed on every call); (b) the first reply of a default-id process on a lineage, and `status show=views`, list the views of
the same lineage with the same agent name whose lease has expired or whose pid is dead as `orphaned`, with their pending record
counts, in `adoptable`; (c) `options.as:"<old id>"` re-attaches to an orphaned view (refused with `view_in_use` naming the live
owner while its lease holds); (d) the environment variable `HYDRALYSIS_AGENT_ID`, read at server start, makes the default id
stable across restarts, which is what the skills recommend for a long-lived agent; (e) an orphan nobody adopts keeps its records
pending in the store (never dropped, listed by the doctor) and has its fork folder deleted after `viewIdleDeleteS`; (f) a call
whose view fork was evicted answers once with `view_rebuilt{replayed, ms}`.

**Lazy creation and routing.** The first edit of an agent creates its view: take the base of the master's
generation (build it once, single-flight, 4.10 "shared base"), fork it with `purpose:"view"`, open it writable,
replay the agent's pending records onto it. Reads of an agent with a view go to its view; `scope:"master"`
bypasses it. Every reply names `view`, `base` and, when behind, `stale:{base, head, behind}`.

**Shared base.** `base_key = sha256(origin_key, generation, engine release, analysisIdentity, format)`. The first
caller takes the OS lock `_base/<key>.lock`, builds the upgraded and saved base in a staging folder, writes a
completion marker and renames it; every other caller reads the master meanwhile (**no waiter blocks a reader**)
and polls the marker, bounded by `BASE_WAIT_S` (30, *unmeasured*). A generation is itself a verified saved fork, so
after the first publish the new generation **is** the base of the next views (no extra build). `prepare` finishes
the master's upgrade-cache build first (E2 `prepare_upgrade`).

**Write-ahead.** For every edit: (W1) seal and flush the record in the store; (W2) apply it to the view's fork
with `rk` = the record id, so a replay is idempotent (D15); (W3) acknowledge; (W4) on recovery, any record without
an `applied` mark is replayed. A view's fork can be dropped at any time (eviction, a kill, a corrupt version file
quarantined by E8) and is rebuilt from the base and the store (K15). No second process writes a fork: the rev5 background saver is deleted (D61), eviction closes the program with its discard option and keeps the folder, and a view idle for `viewIdleDeleteS` (24 h, OD8) has its folder deleted. `journal.durable` (D55) is true when the
store is v3 and a start-up self-test (write a record, kill the writer, read it back) passes.

**Publish (the one serialisation point, D45).** `type_edit kind=publish` (and `commit`, 4.6) is a job:

1. Seal `pending/<csid>.json` (a changeset: the view's records, the base generation, the agent id) and return
   `{job, position, etaMs}` at once. No engine call, no other view and no reader is involved.
2. The caller or any other waiting caller tries a non-blocking OS lock on `publish.lock`; the winner is the leader
   and drains `pending/` in id order, `publishBatchMax` (1) changesets per generation.
3. The leader forks the head generation (`purpose:"generation"`), replays the changeset subject-aware with
   `before` checks (D7, 4.2) and records, per changeset, `applied`, `rebased`, `converged`, `conflict` (it names
   the other editor; the records stay pending in the view and are never dropped) or `skipped`. The candidate is `state:"candidate"`, so the leader's writable open, replay and save are allowed (D38). It saves and closes.
4. **Verify before it can be head:** K2 and K3 on the candidate's files and on a **disposable clone** of it (`fork_project
   purpose:"fork"`; the candidate itself is only read by the fork and by the hash and is never opened again, because a writable
   open changes `~index.bak` and `~journal.bak`): the header magic of the candidate's newest version, the clone opening
   read-only and writable, function count, names hash equal to the parent plus the applied effects, K sampled
   decompiles succeed and contain the current names). A candidate that fails is never published; it stays listed
   for manual removal (D28), the changesets stay pending, the job reports `candidate_failed` and the doctor shows it. A candidate that passes is **sealed** before step 5 (`seal_project`; on hydra.2/3 the sidecar's `state:"complete"`), so from then on every writable path is refused (D38); a sealed candidate that is never published is harmless and stays listed for manual removal.
5. Commit point: append one CRC line to `CURRENT.log` (D10, naming the changeset ids, D32) and flush. Then write
   `done/<csid>.json` and release the lock. A leader that dies after step 5 and before the `done` file is
   resolved by the manifest's ids; a leader that dies earlier published nothing.
6. A follower never waits on the leader inside a call: it polls its job (`publish_pending{position, etaMs}`).
   Bound: a changeset waits for the build in progress plus its own, about two builds; 24 simultaneous publishers
   are served in turn. T_build (fork + replay + save + verify) is **unmeasured** (SP7, Z2); no publish latency is
   stated before it is.

**What other views see** is 4.7: snapshot isolation; nothing blocks; `rebase` builds a new view fork from the head
generation, replays the unpublished records, verifies with the oracle subset and switches the view pointer in one
atomic store write. A view without edits may set `follow:"head"`. A dirty view that edits while behind gets a
clean-only automatic rebase first; on conflict the edit is refused with `stale_view` naming the editors.

**Per-view and publish locks.** The per-target `.sync.lock` is replaced by a per-view lock (Y2; `locks.py` raises a typed `LockBusy`; bound
`SYNC_LOCK_S`, 30 s, then a structured `busy`); readers take none; the owner's save before a script clone (D64) is taken under it; two views' locks are taken in lexicographic
order (4.8); `publish.lock` is held only by the leader.

**Interim on hydra.2/3** (Hydralysis 0.5.0): everything above works on the hydra.2/3 engine except the
engine-side admission and sealing (G1 and GR8 depend on the client behaving there, 6.1); Y2's launch
configuration sets `maxLong` and `maxQuick` from the expected number of agents (D54) and `integrity.py` checks and
quarantines the header of every Hydralysis-owned fork before opening it.

### 4.11 Hydralysis obligations that follow from the measurements

- **Thread safety first** (Z1, then Y2): the multithread `_sync` test exists, marked a known issue, before the
  fix; the fix is a per-sync or reference-counted connection per view.
- **Pre-build before agents start**: `prepare` (adopt) produces generation 0 with the upgrade-cache build
  finished; the doctor warns when a master's cache is building while views are created.
- **Never open the master or a generation writable**, not even to check (K1); `integrity.py` reads headers without
  opening programs.
- **Agent identity in the skills** (one rule, D59): harnesses that start editing sub-agents must pass a distinct
  `options.as` for each; the skills and `backend help` say so (D43). Not doing so means the sub-agents share the process
  default view `<clientInfo name>@<boot id>` (it is not the `shared` view): they see each other's unpublished edits, and
  `expect_revision` with the subject-aware rebase keeps one from overwriting the other. That is conflict control, not
  isolation, and GR5 does not cover it (6.1).
- **Structured `busy` to `next`**: capacity, `analyzing`, `lock_queue_full`, `sealed` and `corrupt_newest` map to
  a ready `next` call; a view that the engine refuses (`capacity`) is retried after `retryAfterMs` or an LRU
  eviction by Y5.

---

## 5. Compatibility and the release train

**Train.** hydra.3: the upstream merge only (branch `sync/upstream-2026-10-27`, `6d266ebcff`, golden gate
PASS). hydra.4: this design. Inside hydra.4 the engine packages E1 to E5, E2a, E3c, E6, E8, E9 and X0 and the client packages P1a,
P1b each merge to one integration branch, each gated by the characterization run, `daemon_tests`,
`contract_tests` and `session_smoke`; one tag; one Hydralysis pin bump generated by a new `tools/bump_hydra.py` (it does not exist
in the Hydralysis tree today; the source designs assumed it). **R1 owns the script** (writes and
tests it); Y4a only runs it to produce the pin bump and **owns the files it edits, which are exactly these
(8.1 gives each a W6 cell for Y4a; `tests/test_bump_hydra.py` asserts that the script edits no other file;
the proof's pinned-literal scan finds every `12.3-hydra.<n>` in the tree and requires it to be in this list
or in the historical list below)**: `hydra.py` (`RELEASE`, `PROTOCOL`, `ASSETS` with the SHA-256 and sizes);
`tests/fakehydra.py` (the release, protocol and capability constants of the fake daemon); and the three
pin statements of the Hydralysis documents, one sentence each: `README.md` (`backend install` paragraph),
`THIRD_PARTY.md` (the engine row) and `docs/upstream-setup.md`. **Frozen tests never carry the literal**:
`tests/test_backends.py` (`:21`, `:101`) and `tests/test_query.py` (`:285-296`) hard-code `12.3-hydra.2`
and `12.3-hydra.3` today, and `hydra.py` builds the message the first one asserts from `RELEASE`
(`:29`, `:190-191` at `589432e`; `:30`, `:216-217` at `f46788b`), so Y4a rewrites them **once**, in W6,
to read the release from `hydra.RELEASE` and from the fake daemon's own constant (decided: derive, not
edit per bump), after which no bump touches a test. **Historical, not edited by the script**:
`docs/golden-harness.md`, `docs/verification-nct-2.5.md`, `docs/verification-fixtures.md` and `docs/pr6-traceability.md` (dated
reports: the hydra.2 baseline and the PR #6 audit). The release workflow gets a
`workflow_dispatch` dry run first (the hydra.2 release failed once before succeeding, per the critic).

**Matrix** (what "keeps working" means, exactly):

| Client | hydra.2/3 engine | hydra.4 engine |
|---|---|---|
| Any raw JSON-line client speaking protocol 2 | works | works; replies byte-identical (characterization at protocol 2); behaviour identical except the declared changes of 5.1 (V1 to V11, the first of which is the upgrade gate, 3.4) |
| stock `ghidra_session.py` 1.0.0 (protocol 2) | works | works at protocol 2 (endpoint says `protocol:2`) |
| `ghidra_session.py` 1.1.0 (protocol 2..3) | works at protocol 2, capabilities absent | full |
| Hydralysis 0.4.x | works (its own pin) | **refuses by its own pin** (`hydra.py:104-105`, `:246-249`) unless `hydra_allow_unpinned`; this cannot be fixed on the engine side and is stated, not hidden |
| Hydralysis 0.5.0 (this train, client only, pinned to hydra.2/3; 5.3) and 0.6.0 (pinned to hydra.4, OD11) | 0.5.0: degraded set (7.5) | 0.6.0: full |

The doctor shows connected clients by protocol so a mixed fleet is visible. The legacy window:
hydra.4 and hydra.5 serve protocol 2; whether to refuse it from hydra.6 is for the owner then (OD6).

### 5.1 Every change a protocol-2 client can observe

The upgrade gate is **not** the only behaviour change a protocol-2 client can observe: the lane move,
`expect`, validate-before-wait, the import wait, the release of dead clients, cancel of lock waits, the
`status` lock, the progress event and the new request fields all reach a v2 client unless something stops
them. This table is the complete list. **G** rows are gated on `Client.v3()` (a v2 connection sees today's behaviour exactly);
**V** rows are deliberately visible to v2, each with its reason. The 317 request goldens
(`examples/characterization/*.json`, seven scenarios) record **replies only**: their own
docstring excludes progress events, older-format projects, lock timing and file-system dependent
copies, and none of the 317 steps carries `expect` on `signature` or `data_type`. So every row has a
behaviour test of its own, written against the **stock 1.0.0 client** (P1a vendors it as
`examples/stock/ghidra_session_1_0_0.py`, so the test is a real protocol-2 client) in a file
`examples/cc_<package>.py` loaded by `examples/client_compat_tests.py` (the loader is P1a's, like E0's
`dt_*` and `char_*` loaders; each file also runs on its own). Each test records its hydra.3 behaviour
first and must pass unchanged on the hydra.4 candidate.

| # | Change | What a v2 client would notice | Decision and reason | Test (package) |
|---|---|---|---|---|
| G1 | `expect` enforced on `signature` and `data_type` (3.4) | a request that carries `expect` there is ignored today (`Operations.java:157,186` compute the old value and never compare); enforced it would turn a success into `conflict` | **Gated on v3.** Enforcing it for a v2 client that sent a stale `expect` would be a break with no benefit to that client | `cc_e1`: v2 `edit` signature and data_type with a wrong `expect` still succeed; the same request on v3 conflicts (E1) |
| G2 | `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay` move from `long` to `maint` (3.5) | queueing, ordering and the text of `busy` for these commands | **Gated on v3** (`laneOf(cmd, req, v3)`). The benefit is for the Hydralysis commit path, which is v3 | `cc_e3a` `v2_lane_unchanged`: long saturated, a v2 `save` waits and fails `busy` in `long` as on hydra.3; a v3 `save` runs (E3a) |
| G3 | fair key `connection + scope` and the per-key cap (3.5) | the order in which a v2 client's own labelled requests are served | **Key gated on v3**: a v2 request keeps the key `connection id`; the per-key cap itself reaches v2 as V9 (revision 6) | `cc_e3a` `v2_queue_order`: the hydra.3 service order of two labels on one v2 connection is reproduced (E3a) |
| G4 | validate-before-wait (3.5) | a bad request on a full lane fails at once instead of after its wait | **Gated on v3**: timing and which error wins (`bad_request` or `busy`) are observable | `cc_e3a` `v2_no_preflight` (E3a) |
| G5 | the `queue` key of a **slot wait**'s progress events and `status.requests[].queue`, and the import estimate's `estimateScope` (3.4; conditionals C4 and C5) | one more key in an event or a `status` entry. **Premise corrected in revision 3:** an **import** wait already carries `queue` in its progress events and in `status.requests[].queue` in protocol 2 today (`m.waiting("import queue", q)`, `ImportGate.java:188-194`; `RequestMonitor.java:111`), so for the import wait the `queue` key is **not new v3 content and not gated**; only the slot-wait `queue` key (today `Scheduler.admit` calls the one-argument `waiting`, `Scheduler.java:155`) and `estimateScope` are new | **Gated on v3**: `Scheduler.admit` keeps the one-argument `waiting(what)` for a v2 connection, and `ImportGate` (E3a's file, which needs the client: `enter` receives only `c.id`) adds `estimateScope` only for a v3 entry. Events are not replies, so the goldens cannot see them | `cc_e3a` `v2_progress_keys`: the exact key set of every progress event during a slot wait **and** an import wait, equal to hydra.3's (the import wait still carries `queue`, without `estimateScope`) (E3a) |
| G6 | `Scheduler.describe` takes the scheduler lock with `tryLock(250 ms)` and may answer `unavailable` (3.4, `health`) | `status.scheduler` could say `unavailable` instead of blocking | **Gated on v3** (E1 adds the `describe(boolean v3)` overload, which does not exist yet: `Scheduler.java:285` takes no argument; the `tryLock` is behaviour gate 5, the reply shape C2) | `cc_e5` (with `-Dghidra.session.testHooks=true` and `debug_stall` holding the scheduler lock): v2 `status` blocks as on hydra.3, v3 answers `unavailable` (E5) |
| G7 | new request fields: `purpose`, `open`, `verify`, `lane`, `isolation`, `scriptSha256`, `rk` (3.1, 3.4) | a v2 request that already used one of these names with another meaning would change behaviour. None is known (Hydralysis `workcopy.py:266` sends `writable` and a path; the 1.0.0 client and the README examples use none), which is a check, not a proof | **Gated on v3**: one helper reads them, so the answer does not depend on a search. (`backup` on `open_program` is the exception: it is read at any protocol because V1 applies to any protocol) | `cc_e1` (`rk` twice is applied twice), `cc_e2` (`purpose:"backup", open:false` is a plain fork, opened), `cc_e4` (`isolation`, `lane`, a wrong `scriptSha256` have no effect) |
| G8 | the upgrade gate's refusal code (3.3) | a new error code | **Gated**: v2 gets the existing `conflict` with `details.reason:"backup_required"`; v3 gets `backup_required` | `cc_e2` (E2) |
| V1 | the upgrade gate (3.4) | `open_program writable upgrade:true` on a canonical older-format project without a valid `backup` is refused, where it succeeded | **Visible to v2, by design.** The gate exists to stop a one-way upgrade of a project that is not a copy; gating it on v3 would protect nothing from the clients least likely to know. `README.md:1011-1014` already tells people to do it in a copy | `cc_e2` on the legacy fixture (`--legacy-project`): refused for v2 with `conflict`, allowed on a fork and with a valid `backup` (E2) |
| V2 | import wait fix (3.5) | **both directions** (revision 3 corrected "can only gain"): (1) an import without a `wait` field no longer fails `busy` ten seconds after reaching the front; it waits unlimited for the slot and the project lock, as it already does for the gate; (2) an import with an explicit numeric `wait` that spent most of it in the gate now fails `busy` when that one budget is used up, where today its slot and lock waits each got a fresh full `wait` and it could succeed | **Visible to v2**: (1) is a defect fix, (2) makes `wait` the total a caller asked for; no client can depend on either behaviour (a 10-second failure after an hour is not a contract) | `cc_e3a` `import_wait` (no `wait`) and `import_wait_explicit` (a numeric `wait` spent in the gate) on a v2 connection (E3a); `import_wait` fails on hydra.3 by E0's premise test |
| V3 | bounded release of a dead client (3.5): `shutdownNow()` after `cleanupGraceS`, `disconnect` bounded by `abandonWaitS`; the 600 s `CLEANUP_WAIT_MS` waits of `Session.disconnect` and `leaveProject` for owners and writers become the same bounded waits (the leave of a plain reader is V10, E3c; D63) | other clients get a dead client's slots and locks after about 20 s instead of after an hour (`awaitTermination(1, HOURS)`) or 10 minutes per program (`CLEANUP_WAIT_MS`) | **Visible to v2**: it changes how long *others* wait, no reply shape | `cc_e3b` `dead_client_lock_wait` with a 1.0.0 client killed while blocked, and `owner_leave_bounded` (a 1.0.0 client that owns a program is killed while another client reads it: the exclusive leave is bounded and the program's readers wait at most `cleanupGraceS + abandonWaitS`) (E3b) |
| V4 | a request for a program held by an **abandoned** request answers `busy` at once (3.5) | `busy` immediately, with the existing `holder`/`holderInfo` keys saying "abandoned", instead of waiting out `wait` | **Visible to v2**: waiting for a holder that is gone helps nobody; `details.reason` is v3 only | `cc_e3b` `abandoned_holder` (E3b) |
| V5 | `cancel` (and a `timeout` deadline) now ends a lock wait (3.5) | a cancelled request that waits for a program, project or overlay lock answers `cancelled` within a second; today it keeps waiting until its `wait` ends in `busy` | **Visible to v2**: it is what `cancel` is documented to do. The single timed `tryLock` and its FIFO order are unchanged | `cc_e3b` `cancel_while_waiting` (E3b) |
| V6 | endpoint file and `ready` event gain `protocolMin`, `protocolMax` (3.1) | two extra keys in a file and an event; `protocol` stays 2 | **Visible, additive**: needed for negotiation (D3); the 1.0.0 client reads `protocol` and `minClient` and ignores the rest | `cc_e1` (first test): the 1.0.0 client against the E1 engine connects and works (E1; the harness is P1a's) |
| V7 | every `fork_project` sidecar gains `purpose` and `disposable` (3.4, D12) | a few keys in a file beside the fork; the reply is unchanged | **Visible, additive**: the upgrade gate decides from the sidecar | `cc_e2` `fork_sidecar` (E2) |
| V8 | a project that hydra.4 marked sealed (any of the registry record, `SEALED.json` or a `generation` or `backup` sidecar with `state:"complete"`, D38 and D66; `disposable:false` alone is not sealed) refuses every writable path | `open_program writable`, `analyze`, `save`, owner scripts, `promote_overlay` into it: `conflict` with `details.reason:"sealed"` and a `fork_project` `next` for v2, the code `sealed` for v3. A project with no sidecar and no seal record behaves exactly as before | **Visible to v2, by design, but only for projects hydra.4 itself marked**; no existing v2 transcript can meet one. Protects the master and every generation from the clients least likely to know | `cc_e2` `sealed_refusal` on a v2 connection against a sealed fork, and `candidate_then_seal` (a candidate is writable and saves, the same project after `seal_project` is refused; E2) |
| V9 | the work-conserving per-key running cap (3.5) applies to **v2** connections too, with the new lane defaults (D40) | a v2 connection that held up to 32 parallel requests and every running slot is held back only while another key waits under its own cap; the order in which one connection's own requests run is unchanged (D18's v2 key `connection id` is kept) | **Visible to v2**: under contention only, measured starvation (claims-audit U2: no per-client running cap; A: a 7th client waited 10.2-10.5 s) | `cc_e3a` `v2_running_cap`: one v2 connection with 32 parallel scripts cannot starve a second connection's script; on an idle daemon nothing changes; and `v2_lane_defaults`: `status.scheduler.long.slots` of a v2 connection equals `max(8, CPUs)`, the one number of the v2 `status` reply that E3a changes (the goldens mask it, D62) (E3a) |
| V10 | the leave of a plain reader (a client that is neither owner, writer nor overlay holder) takes no exclusive program lock at any user count, and `Session.disconnect` no longer waits 600 s for it (E3c, D63b; the rev5 fast path of 3.5, built once; the owner and writer side is V3, E3b) | no reader of a program waits behind another client's leave or disconnect (today a leave queues the exclusive lock behind the running readers and every new reader waits behind it, measured, 3.5) | **Visible to v2**: it changes how long others wait, no reply shape | `cc_e3c` `reader_leave` (a 1.0.0 client closes its connection while another client's read runs: the next join and script are answered within their `wait`) and `reader_leave_all` (E3c) |
| V11 | a concurrent `fork_project` to a path that another request is publishing (3.4, D41) answers `conflict` with `details.reason` `fork_in_progress` or `exists`; with the same `rk` the loser returns the winner's result | six simultaneous forks to one destination gave one success and five bare `failed` replies whose message names a `.rep` path (`review-rev6/exp1_fork_race.json`) | **Visible to v2**: only racing requests can see it and `failed` carried no information; the goldens run one request at a time and cannot see it | `cc_e2a` `fork_race_conflict`: six concurrent forks by the stock 1.0.0 client, exactly one success, five `conflict`, no leftover staging folder (E2a) |

The release identity strings (`hydraVersion`, `buildDate`) change with every release; the goldens mask
them (`"hydraVersion": "<masked>"`). `health` is a new command, so an old transcript contains none.
The counts D2 refers to: **thirteen reply-shape conditionals, C1 to C13, one per row of the table in
3.1**; G5 is the behaviour test of C4 and C5, which are events and `status` entries that the goldens
cannot see, while the other eleven are reply shapes that the seven v2 scenarios at `--protocol 2`
check directly (a v2 reply must stay byte-identical); six behaviour gates (G1 and G7 share the
request-field helper; G2, G3, G4, G6 and G8 are one gate each); eleven declared visible changes (V1 to
V11; revision 6 adds V8 to V10, revision 7 adds V11).

### 5.2 Release notes (R1) must say

**Hydralysis 0.5.0 (revision 8; Y2 writes it in `README.md` under "Changes in 0.5.0", Z14 carries it into `CHANGELOG.md`):**
the `saved` key of `ghidra_query action=status` and the setting `overlay_save_debounce_s` are removed, and the background
saver process is gone: a working copy is no longer saved after edits pause, unsaved changes are replayed from the store
(D61); the per-target `.sync.lock` is replaced by a per-view lock that answers a structured `busy`; default views are per
agent (`options.as`, D59) and callers that share an id share a view; the engine-side sealing and admission need hydra.4.

**Hydra Engine (R1):**

- `minClient` stays `1.0.0` (D4): no existing client is rejected by a hydra.4 engine, and hydra.4
  serves protocol 2 and 3 on one port. The one bump is reserved for the release that drops protocol 2.
- Hydralysis 0.4.x refuses a hydra.4 engine by its own pin (the matrix above); hydra.2/3 clients
  keep working at protocol 2.
- The declared protocol-2-visible changes V1 to V11 of 5.1, by name.
- A harness restart is needed once after the Hydralysis catalog epoch (7.7).

**State formats written by hydra.4 / Hydralysis** (`CURRENT.log`, `MANIFEST.json`, `backup.json`, store v3) carry a
`format` number and are forward-checked: a reader that finds a newer `format` refuses with
`format_unreadable` and says which writer wrote it; it does not guess.

### 5.3 Release mapping (revision 6)

One wave numbering, three release trains (D35; revision 7 drops the interim integrity release, OD10). A release makes only the claims that its gates passed (D52).

| Release | Contents | Gate | Claims it may make |
|---|---|---|---|
| **hydra.3** | done: the upstream merge, tag `v12.3-hydra.3` | its own golden gate (KotOR 8,616 of 8,616 identical to hydra.2) | unchanged; the README and CHANGELOG already carry the qualified wording |
| **Hydralysis 0.5.0, qualified** | client only, pinned to hydra.2/3 (7.5 degraded set): Y0a-Y0e, Y1, Y2, Y3, Y5, R0/S1/Z13a wording, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8 | Hydralysis unit and integration suites; the chaos PR lane against hydra.3 (9.17); 9.16 measured; `test_claims` | exactly the GR rows of 6.1 marked "0.5.0", with "the engine's locking is hydra.3's; heavy parallel use is something to measure". **No non-blocking and no "any number" claim**; the doctor warns when the engine is older than hydra.4 (E8) |
| **hydra.4** | protocol 3: P1a, E1, E8, E2a, E2, E3a, E3b, E3c, E4, E5, E9, E7, P1b, E6, X0, R0, R1. E8 and E2a land first (W1) and ship here; there is no separate integrity release (OD10, decided) | 9.1-9.4, 9.7-9.20 (9.15 is E8's and E2a's gate; 9.14 includes E7's; 9.20 is limited to SP3-SP7 and SP10 for this release, SP1, SP2, SP8 and SP9 gate hydra.5 or optional work) | the GR rows marked "hydra.4"; "a kill during a save no longer leaves an unopenable newest version; a partial fork is swept and retryable" with the rule-of-three bound (9.15); "a deaf script is killed" only after E7's items of 9.14 pass; the site flips each claim only when its test flips (S2) |
| **Hydralysis 0.6.0** (label OD11) | pins hydra.4: Y4a, Y4b, Y4d, Y4e, Z9, Z10, Z14, later Z11, Z12 | 9.8 and 9.17 against hydra.4 | adoption of the engine's capabilities; the supervisor's auto-restart only with a durable journal |
| **hydra.5** | E10 (overlay-backed views), E11 (read replicas), E12 (power-loss durability); each only if its spike says go | each package's spike and gate | DB-bound read scaling on a hot program; a power-loss claim only after E12's simulated matrix |

Nothing in this file tags, pushes or publishes; every tag and every label is the owner's (OD5; OD10 and OD11 are decided: the labels are Hydralysis 0.5.0 "qualified", client only on the hydra.3 pin, and 0.6.0, which pins hydra.4, and the tag names stay `12.3-hydra.<n>`).

---

## 6. Guarantees and honest limits

### 6.1 What may be guaranteed, and the test of each (revision 6)

Each guarantee names the test that can fail (a test counts only if it was red on the old build, D48), the
release it holds in and its scope. **Scope everywhere: a process crash (`TerminateProcess`, a client kill), not a
power loss or an OS crash.** These eleven rows are the only things the documents and the site may claim (D58).

| # | Guarantee | Test | Holds in | Basis |
|---|---|---|---|---|
| GR1 | The master, every published generation and every project not involved in an operation are never written: their tree hashes are unchanged | K1 and K9 in every chaos iteration; `cc_e2` `sealed_refusal` and `candidate_then_seal`, `dt_e2` `seal_union` (K1u); the 100-iteration writable-attempt loop (a writable open of a pristine project changed `~index.bak` and deleted `~journal.bak`) | 0.5.0 by client discipline plus `integrity.py`; hydra.4 refuses every writable path of a sealed project (the union of three records, D66; an accident guard, not a security boundary, 6.2) | C: 0 changes in 825 + 25 + 102 kills when never opened writable |
| GR2 | Corruption can only touch a disposable, unpublished artefact, and a candidate generation is verified before it can become head; after E8 a kill during a save does not leave an unopenable newest version | K2 watcher, K3, K6; at least 300 trigger-timed kills during a candidate save with the head verifying every time; at least 400 trigger-timed save kills (200 NTFS, 200 ReFS) with 0 unopenable; the planted X1 | hydra.4 (E8, E2a); 0.5.0 repairs its own forks on hydra.2/3 | C: 12 of 363, rule of three |
| GR3 | An acknowledged edit survives a client or daemon process crash | K5 and K15; the kill matrix between W1 and W3 of the store write-ahead (torn file, kill -9 between seal and apply) | 0.5.0 | C: 0 acknowledged losses |
| GR4 | An acknowledged publish is never lost and is applied exactly once; the history is linear | K12 and K16; a publish storm with kills of leaders and of the daemon | 0.5.0 | 4.10, D32, D45 |
| GR5 | **Between distinct agent ids (`options.as`) and between distinct processes**, no agent sees another agent's unpublished edit, except through the explicitly named `shared` view or protocol-2 shared mode. Callers that present the same agent id, including every sub-agent of one MCP server process that passes no `as`, share one view: they see each other's unpublished edits and are covered by `expect_revision` and the subject-aware rebase, which is conflict control and not isolation (D59) | K11 with 24 agents (24 ids, separate processes) **and K11p**, Y5 `subagents_one_process` (two sub-agents in one MCP process: no `as` gives a shared view, distinct `options.as` gives isolated views) | 0.5.0 (per-agent views); hydra.4 | B: 94 of 114 polls red on hydra.3 |
| GR6 | No client's request waits on a lock another client holds, outside the residual list of 3.9 | K13 (`waits.foreignBlocked` = 0 on sealed reads and views) and the reruns of B's `s1`, `s2`, `s4`, `s5`, `s7`, `s11`, `s13` and A's lane test | **hydra.4 only**; on hydra.3 only Y2's `maxLong` mitigation (D54). Leave stalls: a plain reader's leave is removed by E3c, an owner's or writer's leave of an open program is bounded by E3b and stays in the residual list (D63) | B, A |
| GR7 | A client crash never harms the daemon or the other clients, and a dead client's queued write is never applied | K10; B `s4_dead` S4b; C scenario e | hydra.4 (the write part); the rest already holds | C: 102 of 102 |
| GR8 | At the configured budgets the daemon answers `busy` instead of running out of memory, and its own threads survive | `-Xmx256m` with 24 views and `-Xmx512m` with the full agent set; a 100-view probe; K14 | hydra.4 | A: OOM and a dead reaper at 256 MB |
| GR9 | A native decompiler crash, hang or kill fails one request; a daemon kill leaves no orphan decompiler | the decompiler-kill lap (a **suspended** decompiler, then `TerminateProcess` of the daemon; the no-job control must show survivors); K7 | hydra.4, once SP3(b) passes with hung decompilers and its no-job control (the daemon-owned job, D60; the claim is not made on the launcher-owned job of revision 6, which kills the shared daemon). "The daemon survives its harness" is a separate claim and holds only for `survival:"independent"` (D65) | 3.11 |
| GR10 | A fork path is absent or complete, and no staging artefact survives the next sweep | K6; at least 300 kills during `fork_project` | hydra.4 (E2a) | C: 12 of 162 (not reproduced in review, D41) |
| GR11 | A killed daemon is recoverable without manual repair, and operations in one project never change or delay another | K8, K9, K10 and B's `s5`/`s13` reruns; restart timing recorded (median 1.4 to 1.9 s measured) | 0.5.0 and hydra.4 | C, B |

**Not guaranteed, and said so in the documents:** power loss and OS crash (E12); the protocol-2 connections and the
open (legacy) projects, where the locks of 3.5 apply and their holders block their readers; the shared view's
writers among themselves; isolation between callers that share an agent id (sub-agents of one MCP process that pass no `as`, D59); the `DBHandle` ceiling per `Program` instance until E11; seeing another client's unsaved
live state; killing a deaf script until E7's gate (9.14) passes (D64); unsaved overlays and protocol-2 shared edits across a daemon kill;
`promote_overlay` atomicity; latency under foreign load; scale beyond the soak that passed (24 agents, 6 projects,
4 hours); the cost of a program much larger than KotOR; ReFS as protection (3 of 80 trigger-timed kills still
poisoned a version file before E8); whether the version-file defect also exists in stock Ghidra (not run).

### 6.2 Limits

- **Non-cooperative threads.** Java cannot kill a thread that ignores cancel and interrupt, nor release a
  `ReentrantReadWriteLock` from another thread. A script that never polls `monitor.checkCancelled()`
  keeps its program lock after its client is gone. The design bounds the wait, shows the holder and
  keeps the rest of the daemon running; restart is safe for Hydralysis work (the store is the
  record). Only a helper JVM for user scripts would be a hard guarantee; it is E7 (hydra.4, gated, W5, D64). Until E7's gate (9.14) passes, a deaf
  script is confined to its owner's view and one slot, counted against the owner's cap and quarantined.
- **The overlay lifecycle waits are not cancel-aware.** `openOverlay`, `rebuildOverlays`,
  `dropOverlays` and `promoteOverlay` take untimed `lock()` calls on an overlay's lock
  (`OverlayCommands.java:228, 238, 251, 319, 352, 404`). `cancel`, a `timeout` deadline and the
  dead-client release do not reach a request blocked there (3.5); the three request-bound timed
  waits are what E3b converts.
- **A stalled call on hydra.2/3 is abandoned, not ended.** The client's deadline sends `cancel`, then
  abandons a worker thread and its connection with nothing more sent (7.6); the engine keeps the request,
  its slot and any lock until it ends by itself, and a request in a script that never polls its monitor can
  hold them for as long as it runs. At most 8 abandoned user connections per process are tolerated (the
  supervisor probe has its own budget of 3), and each is also a `users` entry of the programs it joined
  until its request ends and its worker closes it (7.6); the real remedy is E3b's bounded release on hydra.4.
- **A leave can stall the other readers of a program (revision 5, measured).** On hydra.2 and 3, and in any hydra.4 build before E3c (3.5, D63), the engine's release of a client takes the program's exclusive lock;
  while it waits behind a running read, every new `open_program`, script or decompile of that program waits
  behind it, up to the longest running read (at most its `timeout`), and a waiter whose own `wait` is
  shorter gets `busy`. Hydralysis avoids **its own** leaves while its own reads run on the program (the
  leave gate, 7.6, which is why entries are not closed early and no FIN is sent); it cannot avoid another
  process's leave (another agent, a harness exit) or a `close_program` from anyone, and it cannot see
  another process's reads. The stall is bounded and visible (`busy` with the engine's holder details), never
  a hang or a loss; on hydra.4 it does not occur for a plain reader (E3c), while the leave of an owner or writer of an open
  (legacy) program still queues the exclusive lock, bounded by `cleanupGraceS + abandonWaitS` (E3b).
- **The `lane:"quick"` hint is trust-based.** The engine cannot know that a script is quick. It
  honours the hint for `0 < timeout <= quickScriptMaxS`, and the `timeout` only sets the request's
  cancel flag (`m.deadline`, `ScriptCommands.java:75`): a script that never polls
  `monitor.checkCancelled()` keeps its **quick** slot past its timeout, and enough of them starve the
  quick lane, which the long lane would otherwise absorb. RusticQuery polls (17 sites) and is hash-pinned;
  an arbitrary user script that claims `quick` is not policed. The lane figures in `health` show it
  (`longestRunningMs` past the hint), and the remedy is the same helper JVM (E7, D64) once its gate passes.
- **History is capped by records and bytes, and pending records are not compacted.** Committed records
  are archived (4.2), but a store with 4096 pending records, or 20 MiB of them (`effects` make a
  record larger than a v2 one), cannot take another edit until some are committed (a subset commit
  works) or exported as a bundle; nothing is dropped automatically.
- **An append log has no rotation yet.** The streamed reads and the bounded tail window of 4.1 landed in
  the W0 follow-up `2bf90c7` (no 32 MiB `localio` budget any more); what remains for Y2 is the strictness
  each caller needs and a rotation or checkpoint policy. A `CURRENT.log` or `backups.log` is read in full
  by the lineage open, `verify` and the doctor, which is linear in its size; at one line per commit or
  backup this is far from any realistic size.
- **Copy-on-write is ReFS only** (`ProjectFork.clones`: Windows and ReFS). On NTFS a fork is a full
  copy bounded by `forkCopyLimitMb`; NTFS CI cannot validate ReFS clone claims, so those tests run on
  the owner's Dev Drive and are recorded as manual gate evidence. A clone backup is not protection
  against volume loss.
- **Windows x64 and JDK 25 only.** No Linux or macOS claim is made.
- **No power-cut test.** Durability is by documented flags (fsync, write-through), kill -9 and torn-file
  tests. Directory-entry durability cannot be forced from Java or Python on Windows; the design never
  relies on it (every state is self-validating and the reader picks the last valid record).
- **`Revision.of` is metadata for large files** (size and mtime above 1 MiB): it proves the saved state
  is the same, not that bytes are intact. Integrity is the manifest hash.
- **A backup verifies bytes read back through the OS cache after a flush**, not the media. Latent errors
  are found by re-hashing (`backend backups verify`) and by keeping an independent copy.
- **Bulk edits have no per-subject `before`** (`import_types`, `import_archive`): drift is input-hash based.
  Subject granularity is the address, type path and `structure:functions`; a struct change and a
  prototype that uses it are different subjects (a dependency the rebase cannot see; as in `revisions.py`
  today). **The same blindness reaches a subset commit** (4.2): the selection closure is per coarse
  subject, so `only` can ship a `signature` or `data_type` edit without the pending struct it uses.
  4.2's `subset_missing_type` test decides whether that fails closed; until it has run, subset commits
  carry "no semantic dependency tracking" in their documentation.
- **The upgrade gate and the backup check are guards against accidents**, not a security boundary: a local
  process with the daemon's rights can forge a manifest.
- **`private` isolation reads the stored file**, not unsaved edits; `shared` `attemptedChanges` is
  program-wide, not per script.
- **ETA is a rough estimate**, `null` without history, and `null` when the lane is dominated by a long job.
- **Headless only.** There is no GUI. Projects Hydra Engine writes cannot be opened by Ghidra 12.2 or 12.1.4, and opening them in a stock Ghidra is not a goal (D36).
- **The data-type database version** is `null` until it can be read and tested against 12.1.4 data.
- **Sources of numbers:** save time (about 35 s) and clone/hash costs come from the 1.5 GB /
  243,855-function benchmark; the golden baseline is KotOR (122 MB). Every timing constant here is
  *unmeasured* on the target until the gate-9 measurements are recorded.
- **Revision 6 limits.** (1) Every measurement of A, B, C and D is a single run or a handful on one 24-CPU machine under
  foreign load (A varied about 2x between identical runs), on KotOR (8,966 functions) only; heap per view, fork time,
  publish latency and the soak result do not transfer to a 244k-function, 1.5 GB program (SP2). (2) The kill tests
  are `TerminateProcess`: the OS page cache survives, so fsync and power loss are not measured (E12). (3) Kills in the
  write window are rare in random-time mode (2 of 131), so the batches use trigger-timed kills, a biased sample that
  gives bounds, not field rates; intervals are wide (Wilson 95%). (4) Open (legacy) projects, protocol-2 connections,
  rooms of shared writers and the shared view keep their locks and block their own readers (3.9); the non-blocking
  contract is for sealed generations and views. (5) One `Program` instance serves DB-bound reads at 1.4x to 1.8x
  until E11. (6) a deaf script cannot be killed until E7's gate (9.14) passes. (7) A native decompiler is one process per concurrent request
  until E9 bounds it. (8) The unmeasured values (heap watermarks, eviction times, quotas, `BASE_WAIT_S`) are
  starting points checked by the squeeze laps of 9.14. (9) ReFS gives a disk saving and no protection. (10) Whether the
  version-file defect exists in stock Ghidra was not run. (11) The foreign-load sampler is an estimate.

---

## 7. Client obligations (Hydralysis)

What Hydralysis must do for the engine contract to hold. Package ids refer to section 8.

### 7.1 Doctor module (`doctor.py`, Y4b)

One module, one shape: `backend action=doctor` and the CLI command that wraps the same handler.
`cli.py` had **no owner**, so Y0d could not expose `backend --action doctor|backups` or `--options`
there; it is Y0e's in W1 (8.2): the CLI passes the action and an `--options` JSON object straight
through to the same dispatcher as the MCP tool, so no later package edits `cli.py`. It is read-only and **never starts a JVM
or a daemon**: it reads the endpoint file and the launcher registry, attaches with
`Daemon.attach()` (connect without start) only if the instance lock is held, and calls `hello`/`health`.
Findings are `{id, level, what, why, fix}`; `fix` is a ready tool call or command.
Sections: root and why; engine (pin, release, protocol range, `analysisIdentity`, decompiler hash); JDK
against the required 25; file systems and COW of root, state dir and the volume of the current generation
(warn on the system drive or a non-ReFS volume, say what a fork costs there); daemon (`health`, memory,
restart history); other daemons from the registry; lanes (starving, abandoned holders); lineage
(current generation, `CURRENT.log` torn tail or gap, unfinished candidates, tampered); backups (count,
verified, independent, last, one-way status); stores (stale views, `before_unknown` records); clients by
protocol; the launch outcome of the daemon (`spawn`, `survival`, `health.processJob`): `daemon_dies_with_harness` is a warning, as is a daemon found inside a kill-on-close job (D65). Default output is findings only.

### 7.2 Supervisor policy (`hydra.py`, Y4a)

- **Probe** `health` every 5 s while the engine is in use, on **its own connection** (outside the entries
  of user calls, 7.6) and with a
  deadline: P1b's `deadline` on a hydra.4 client library, the deadline helper of 7.6 (abandon, no FIN)
  against a hydra.2/3 engine (where `health` does not exist either and the probe is `ping`,
  7.5). A probe that expires abandons its connection and the next probe opens a new one; that connection
  has joined no project or program, so closing it when its answer arrives takes no program lock and needs
  no gate. Abandoned probes
  have **their own budget of 3** (7.6, step 5), separate from the 8 of user calls: eight stuck lock waits
  of user calls on a program held by a long analysis must not make a busy but healthy daemon look as if
  it did not answer `ping` (which is answered inline, outside the scheduler), and a user-call cap is never
  reported as `daemon_unhealthy`, which is the restart-budget code below. The supervisor reports both
  counts as a finding of its own.
- **Wedged** only when the pid is alive **and**, for 3 consecutive probes 5 s apart, one of: no answer
  to `ping`, `health.state == "suspect"`, `tick.ageMs > watchdogStallMs`, `schedulerLockOk == false`.
  A long request is never a wedge; lane figures are informational.
- **Dead** (pid gone, instance lock free): restart.
- **Budget**: 3 restarts per 10 minutes, then `daemon_unhealthy` with the doctor summary and no further
  attempt. Every event is appended to `supervisor.json` through `durable`.
- **`lost_on_restart`.** At each probe the supervisor keeps the last `status` (programs with
  `unsavedEdits`, running jobs). Before restarting a wedged daemon it computes what dies with it:
  programs under `working/` or a commit candidate are *recoverable* (the store or the intent log is the
  record; a marker mismatch triggers a replay); every other program with unsaved edits, and every
  in-flight import or export, is listed in `lost_on_restart:[{program, unsavedEdits, by}]` and marks
  in-flight Hydralysis jobs `lost_on_restart` in their records. A daemon that is merely slow is **not**
  restarted while the list is non-empty, unless the call carries `force:true`.
- Killing a daemon on ReFS can leave project locks for seconds: keep the existing wait for the pid to exit.
- Tests use fresh state roots only. Pids 18220 and 17936 are never touched.
- **Revision 6 (D55).** Auto-restart is enabled only when `journal.durable` is true (the store v3 write-ahead record of
  4.10 and its start-up self-test). A restart waits for the process object to exit (median 2.1 s, up to 39 s under load
  after `TerminateProcess`), treats every hard kill as a crash, and is refused while a publish is mid-flight without a
  recorded intent. The doctor warns when the engine is older than hydra.4, which carries the integrity packages E8 and E2a (5.3) and lists unfinished
  candidates and `repairs[]`.

### 7.3 Commit flow (Y2, Y4d)

As 4.6. The client: checks capabilities (`format`, `backup`, `upgradeGate`) and degrades per 7.5;
always supplies `expect_revision`; shows the one-way confirmation text before any step; runs the
commit as a worker-process job and reports `cid`, step and queue position; re-hashes the backup
itself; treats `CURRENT.log` as the truth and `targets.json` as a cache; never writes into a
generation; and after `FINALIZED` tells the caller the new generation and what moved (other
views stale). On engines with `purpose:"backup"` (Y4d) the backup is the engine's, same schema.

### 7.4 View publish and merge, rebase, user scripts (Y3, Y4e)

`rebase`, `publish`, `merge` as 4.7-4.8; a stale view's mutation returns `stale_view` with the rebase
action as `next`. **`ghidra_run`**: passes `isolation:"private"` only when the target's working copy has
no unsaved edits (`info.unsaved == false`) and the capability exists and the measured open cost on KotOR
is accepted; else `exclusive`; on an engine without the capability it behaves as today. **From E7 on (revision 8)** a user script on a view runs with `isolation:"worker"`: Y4e takes the per-view lock, saves the fork if `info.changed` (a bounded save, D64), passes the saved revision as `basedOn` and submits the script; a script that ignores cancel is killed at its timeout and the view is untouched. It surfaces
`attemptedChanges`, `isolation`, `basedOn`. RusticQuery calls always send `isolation:"shared"`,
`lane:"quick"` with their `timeout`, and `scriptSha256`; a non-zero `attemptedChanges` on a read action
is a test failure.

### 7.5 Capability degrade (engine hydra.2/3)

| Feature | On an engine without the capability |
|---|---|
| lane hint, queue info, `next` | not sent; waits use the existing client budgets |
| `format` | treated as **unknown**: the commit always needs the one-way confirmation |
| backup | Python-written manifest (`writer:"hydralysis"`) over a plain fork |
| `ghidra_run` isolation | stays today's contained mode, no `private` |
| `health` | `ping` with a deadline (the deadline helper of 7.6 on the **probe's own connection**, which is not one of the pool entries: a `ping` needs no project or program, so there is no context to re-establish; P1b is not available there); wedge detection needs the pid and the lock only |
| deadlines (`deadline_s`) | the 7.6 helper (worker thread, `cancel`, abandon, gated close; one deadline per attempt); P1b's `deadline` only when the engine ships library 1.1.0 |
| `rk`, `expect` on signature/type | not used; Hydralysis does not rely on them |

### 7.6 Lane hints, deadlines, error contract (Y4a, Y0b)

- Reads: `query.run_script` (`query.py:76-91`) adds `lane:"quick"` (its `timeout` already is
  `timeout_s + 5`); `fork_project` and `save` need no hint (they are maint by command on a v3 connection).
- Deadlines: a quick-lane call carries `deadline_s` (default 60 s); long-lane calls none. The mechanism
  depends on the engine, because Hydralysis loads the session library **from the engine install**
  (`hydra.py:229-233` at d0466bc; `:315-321` at 589432e; this sub-section uses both bases and says which):
  - *hydra.4 (library 1.1.0, P1b):* `call(cmd, deadline=...)`; on expiry the library sends `cancel
    target=<id>` and raises `deadline_exceeded`, and the connection stays usable. Nothing is
    abandoned.
  - *hydra.2/3 (library 1.0.0): abandon, close late.* Revision 2 specified `session.close()` on a
    timer; **that does not work on 1.0.0** (it hangs and sends nothing, shown below) and is withdrawn.
    Revision 3 replaced it by a half-close (`shutdown(SHUT_WR)`); **revision 5 withdraws that too**: the
    FIN makes the engine leave the program when the request ends, which stalls every other reader of
    the program ("Leaving a program", below). The mechanism was chosen by experiment against the real
    1.0.0 library and a real hydra.3 daemon and is the sub-section that follows. In one line: the
    deadline is a worker-thread `send`/`wait` that the **caller** never enters; on expiry send `cancel`
    through the same session, wait a grace, then **abandon** the worker thread and the connection with
    nothing more sent (no `shutdown`, no `close()`, no touching the library's file objects); the worker
    closes the session itself when the engine's answer arrives, through the leave gate. The engine's
    view on hydra.3 is that the request goes on until it ends by itself, so the client **never relies on
    an EOF or a reply coming back** to end its own wait. A lock wait (case L below) is not left to this
    mechanism: the client sends `wait` below `deadline_s` and the engine answers `busy` itself
    (measured, below).
- Waits: `BUSY_WAIT_MS` (180 s, `query.py:29`) and `SYNC_LOCK_S` (900 s, `workcopy.py:33`) shrink to a
  patience budget (default 25 s) once the engine reports queue information; beyond it the tool call
  returns the engine's structured `busy` (queue position, `retryAfterMs`, `next`), not a hang. No
  detached-call state is introduced (D24). On hydra.2/3, which report no queue information, a
  quick-lane read sends `wait = min(25 s, remaining / 2)` on **each call of its attempt**, the two opens
  included, instead (7.6, "The unit of the pool is the attempt" and "A lock wait needs no abandon"); a call
  without a deadline keeps today's budgets.
- `EngineError` (`hydra.py:51-63` at `d0466bc`; `:121-177` at `f46788b`) keeps `holder`, `holderInfo`, `heldMs`,
  `queue`, `retryAfterMs`, `current`, `next`. **What shipped (Y0b follow-up `33cb5ee` and polish `5018367`), and
  so what this section decides:** the **informational lists** (the holder lists, `running`, `alternatives`,
  and every other list in the payload) are capped at `LIST_CAP` = 5 entries plus a `more` map; **`next` and
  `retryAfterMs` are never capped** (`UNCAPPED`: a ready request must reach the caller exactly as the engine
  sent it; the first Y0b code cut `next.args` to 5 entries); **the lists inside `queue`**, the engine's own
  queue structure, are capped at `QUEUE_CAP` = 64 entries, with the count left out in `more["queue.waiting"]`
  (or `queue.<key>`), because that the structure is small by construction was never verified against a real
  engine. `EngineError.queue` keeps the structure as the engine sent it; only the JSON text of `str()` is
  bounded. Y0e has no task here (8.2).
- Pools: the MCP server splits PE-only tools (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`,
  `callers`, `callees`, `function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_*`) from tools
  that talk to the daemon, so four blocked engine calls (`TOOL_WORKERS = 4`, `mcp.py:22`) cannot starve
  them (Y0c). **`MAX_OUTSTANDING` is per lane** (decided; it is what Y0c shipped): each pool has its
  own budget of 8 accepted calls and its own 4 workers, so the total outstanding can reach 16 and a
  saturated engine lane never makes a local tool answer `busy`. The `busy` answer of the MCP layer
  names the lane and carries its retry hint **twice**: as text (`retryAfterMs=2000` in the message) and as
  `structuredContent {error:"busy", lane, outstanding, retryAfterMs}` (Y0c follow-up `49d5bb6`; a client that
  predates `structuredContent` ignores the field and still has the text), until the engine's structured
  `busy` (queue position, `retryAfterMs`) exists. Known edge: `prologue` with `checks` and a `session` can call the
  runtime runner on the fast lane (`api.py`, a runtime call that may block outside the engine lane);
  it stays on the fast lane because the PE-only list above names `prologue`, and enough hung live-session
  prologue calls could occupy the four fast workers: a follow-up for Y4b's doctor to report, not a
  change here.

#### The hydra.2/3 deadline mechanism (tested)

**What is wrong with `session.close()`** (the finding of the second review, reproduced here on the real
object). `SocketSession.close()` (`ghidra_session.py:866-874`) closes the two `makefile` objects (`_w`
then `_r`) and only then calls `sock.shutdown`. A thread inside `wait()` sits in `_r.readline()`
(`:753`) holding `_read_lock` (`:748`); closing `_r` waits for the buffer lock that `readline` holds,
so `close()` called from a second thread never gets as far as `shutdown`: nothing is sent, the
engine sees no FIN, and the blocked `wait` does not raise. `sock.shutdown(...)` on its own returns at
once and **does** deliver the FIN, but it does not wake the blocked reader either. Candidates
tested: **(a)** abandon the session and its reader thread without touching it; **(b)**
`shutdown(SHUT_WR)` only, makefiles untouched; (b') (b) plus `sock.close()` (deferred by the
makefile references); `SHUT_RDWR`; **(c)** detach the OS handle and close it abortively
(`SO_LINGER` 0); and the withdrawn `close()`. Scripts and recorded output are in
`D:/Projects/Hydra/_logs/spec-rev3/`: `exp1_client_matrix.py` (real `SocketSession`, fake server,
`exp1_out_py3.14.txt` and `exp1_out_py3.15.txt`), `exp2_engine.py` (real `hydra-3-candidate`
daemon, fresh state root `work-*/state`, output `run1/exp2_run_with_cancel_L_S.log`,
`exp2_run_nocancel_LSC.log`, digest `exp2_summary.txt`) and `exp3_lifecycle.py` (`exp3_out_py*.txt`).
Python 3.14.7 and 3.15.0 on Windows 11 gave identical rows; the library of `hydra-2`
(`_engines/hydra-2/client/hydra-client-12.3-hydra.2/ghidra_session.py`, LF line endings) and the one in
`hydra-3-candidate` (CRLF) differ only in `HYDRA_RELEASE` (`:77`, `"12.3-hydra.2"` against `"dev"`),
**modulo line endings**: `diff --strip-trailing-cr` prints that one line, while a plain `diff` reports
every line as changed (LF against CRLF).

*Client side* (`exp1`; one thread blocked in `wait(rid)`, a second thread applies the mechanism; the
server is silent or closes its end when it sees EOF, which is what a cooperative engine does):

| Mechanism | The call | Reaches the server | Blocked `wait`, engine silent | Blocked `wait`, engine closes | A later `send` |
|---|---|---|---|---|---|
| `session.close()` (revision 2) | **hangs** (> 5 s) | nothing | still blocked | still blocked | `ValueError` |
| (a) abandon | returns | nothing | still blocked | still blocked | works |
| (b) `sock.shutdown(SHUT_WR)` | returns at once | **FIN** | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| (b') `SHUT_WR`, then `sock.close()` | returns | FIN | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| `sock.shutdown(SHUT_RDWR)` | returns | FIN | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| (c) detach, `SO_LINGER` 0, close | returns | **RST** | raises `OSError` (WinError 10053) at once | same | `OSError` |

*Engine side, real hydra.3* (`exp2`: the 'doomed' client's request is **L** a `decompile` blocked
for the program lock that another client's cooperative script holds (about 35 s), **S** a script
that ignores `cancel` and swallows interrupts for 40 s, **C** a cooperative script; the client
sends `cancel` after 3 s and the mechanism 3 s later (run 1) or only the mechanism (run 2, to see
the effect of the FIN alone); an observer connection reads `status` every few seconds):

| Mechanism | L: lock wait | S: non-cooperative script | C: cooperative script (run 2) |
|---|---|---|---|
| `close()` | call hangs; the engine sees nothing: client and request stay registered, released 0.5 s after the holder ended | hangs; released when the script ends (40.1 s) | not run |
| (a) abandon | **never released**: 30 s after the holder ended the client is still listed and still a `users` entry of the program (`users:[2,4]`, `registered:true`) | **never released**: still listed, `requests:[]`, after the script ended | not run |
| (b) `SHUT_WR` | `status.requests[].cancelled` false then true within 1 s of the FIN (run 2); the request stays registered with its lock wait until the holder ends, released 0.5 s later; the reply `cancelled` reaches the client then (after 21.3 s) | cancelled flag set, the script runs on, released when it ends (40.1 s), reply `cancelled` | **released 0.1 s after the FIN; the reply reached the client's waiter 0.01 s after it** |
| (c) abort | as (b); the daemon log says `client N (...): Connection reset` | as (b) | released 0.1 s after the RST; the waiter raised `ConnectionAbortedError` |

*Revision 5 note on the rows above.* Row (a), "never released", was measured with a worker that never closed its
session, which is why revision 3 added the FIN. The mechanism that ships keeps (a) and adds what that experiment
lacked: the worker closes its session itself when the engine's answer arrives (every request ends in a reply), through
the leave gate. Measured in 7.6 ("Leaving a program", `exp13` D): the entry is released at that moment and nothing else
is disturbed. The FIN of row (b) released the client at the moment the request ended, which is exactly when the release
stalled the other readers of the program (`exp13` C).

**What the engine sees on hydra.3, in words.** A FIN (or RST) ends `Connection.run`'s read loop; its
`finally` sets `client.leaving`, calls `cancel()` on every running monitor (seen: the request's
`cancelled` goes false to true within a second) and then waits in `awaitTermination(1, HOURS)`
(`Connection.java:93-108`) for the request threads. It does **not** close the socket and does not
unregister the client until they end. A request that polls its monitor ends at once and the
client is released and answered (C). A request in a **lock wait** keeps its place in the lock's
queue (hydra.3 does not end a lock wait on `cancel`, E0 `cancel_lock_wait`) and the program stays
held by its client until the lock frees (L). A request in a script that **never polls** the monitor
keeps its slot, and any lock, until the script ends (S). Therefore **the client must never rely on
an EOF, or on any reply, coming back from hydra.3** to end its wait: only the cooperative case
answers.

**The mechanism (specified; Y4a, `hydra.py` and `query.py`).**

*Scope.* The helper serves **deadline-bound** calls only: the quick-lane reads of `ghidra_query`
(`query.run_script` and the `open_project` and `open_program` it needs) and the supervisor's `ping`
(7.2). Everything else (long-lane calls, every mutating call, the working copy's writer and saver, and
`crossbuild.py`, which passes its own `Engine`, `crossbuild.py:70`, and `userscripts.py`, which calls
`runner.engine.call("script", ...)` itself for a long-lane user script) keeps the shared `Engine`
connection, its retry rule (4.3) and its `_keys` cache exactly as today: `QueryRunner.engine` stays the
shared `Engine`, and only `_ask` and `query` take entries (`program_for(target, engine=...)` defaults to it). A mutating call never gets a
deadline that abandons (4.3). Citations in this sub-section read `hydra.py` at both bases: `Engine`
`:209` (589432e `:295`), its `key` `:227` (`:313`), `module()` `:229` (`:315`), `_connect` `:232`
(`:318`), `call` `:268` (`:385`), `EngineError` `:51` (`:102`); `query.py` is identical at both
(`_keys` `:33`, `open_program` `:46`, `forget` `:70`, `run_script` `:76`, `_ask` `:184`).

*The unit of the pool is the attempt, not the call (N1, N2; revision 5).* One `QueryRunner._ask` attempt
acquires **one entry** and runs on it, in order, `open_project` and `open_program` (when the `_keys` cache
misses: a new or replacement entry always does) and then the `script`: up to three engine calls
(`query.py:54`, `:58`, `:90`). **`deadline_s` (default 60 s) is the deadline of the attempt, not of each
call**: one clock starts when the entry is acquired, the caller waits for the attempt on its own event, and
every engine call of the attempt takes what is left. The two opens are deadline-bound like the script: they
send `wait = min(25 s, remaining / 2)` instead of today's `wait=BUSY_WAIT_MS` (180 s, `query.py:29`, `:54`,
`:58`), where `remaining` is `deadline_s` minus the time the attempt has spent when the call is sent, so
that an open that has to wait for a held lock (a save, another client's leave, 3.5) is answered `busy` by the
engine before the deadline instead of abandoning a freshly made entry (measured: both opens with
`wait=1500` on a program whose lock was queued behind a leave were answered `busy` after 1,509 ms,
`exp13`, `exp11_rerun`). A call still in flight when the clock runs out gets `cancel`, the grace, and then
the abandon of step 4, and takes its entry with it. `_ask`'s second attempt (I3) starts a new clock on
another entry, so a stuck call can cost the caller up to two deadlines and two graces (about 130 s with the
defaults); that is the existing retry rule, not a new one. The `script`'s own `timeout` (`timeout_s + 5`) is
unchanged: the engine's cancel flag for the script.

*A lock wait needs no abandon (measured).* Hydralysis already sends `wait=` (`query.py:90-91`, with
`BUSY_WAIT_MS` 180 s at `:29`), and the engine returns `busy` itself when that wait ends. `deadline_s`
is 60 s, so today a read blocked on a lock gives up at the deadline and abandons a connection for up to
120 s more. On hydra.2/3 a quick-lane attempt therefore sends `wait = min(25 s, remaining / 2)` on each of its calls
(`remaining` is `deadline_s` minus what the attempt has already spent, above; the 25 s
patience budget of the Waits rule above; the value is an *unmeasured policy*): the engine's own bound
ends case L on a healthy connection and leaves abandonment to the running cases (S, C). Measured on the
real hydra.3 (`D:/Projects/Hydra/_logs/spec-rev4/exp6_wait_and_collateral.py`, `exp6_out.txt`, section
N2): a reader's `decompile` with `wait=3000` for a program held by another client's cooperative script
was answered `busy` after **3.0 s** (`details`: `holder`, `holderInfo`, `heldMs`, `waitedMs`,
`suggest`), the client had no request left in `status.clients[]`, its connection answered the next
`ping`, and the holder's script went on untouched. Two limits, stated: `wait` is given in full to
**each** timed wait of a request (the slot, `Session.java:248`; the project lock, `Access.lockProject`;
the program lock, `ProgramEntry.java:191-196`), so a request that waits more than once can exceed it,
and it does not bound a script that is already running; `deadline_s` remains the bound that always holds.

*The pool entry: a connection and the context it holds (measured).* Engine-side a connection is a
**client**, and the project and the program a call acts on belong to the client, not to the engine:
`Access.projectFor` refuses a project the client has not joined (`Access.java:82-85`), and a script's
`program` key must be one the client opened. Today this is invisible, because `hydra.Engine` is "one
connection per process and root, shared by every thread" (`hydra.py:295-297` at 589432e) and
`query.run_script` sends `program=<key>` on it. One connection per call, with nothing more, is
therefore wrong. The third review ran it on the real hydra.3 daemon and the check was repeated here on
Python 3.15.0 (`exp5_pool_entry.py`; `exp5_small_out.txt` for a 3-function fixture and
`exp5_kotor_out.txt` for the 122 MB KotOR copy, fresh state roots under
`D:/Projects/Hydra/_logs/spec-rev4/`; the reviewer's script is
`.../review-spec-rev3/mine/exp5_conn_state.py`):

| On a connection | Small fixture (`alpha.exe`) | KotOR copy (`swkotor.exe`, 8,966 functions) |
|---|---|---|
| c1 did `open_project`, `open_program` (key `p1:/alpha.exe`); `script program=key` on c1 | works | works |
| the same script on a **fresh** c2 | `no_project: this client has not joined project p1; send open_project` | same |
| `functions` on the fresh c2 | `no_program: no active program; send open_program first` | same |
| c2 after `open_project` only, `script program=key` | `no_program: p1:/alpha.exe is not open for this client; send open_program first` | same, for `p1:/swkotor.exe` |
| connect and `hello` (10 cold entries, median / worst) | 3.3 / 19.5 ms | 3.4 / 19.0 ms |
| `open_project` (a join: the project is already open) | 1.9 / 6.2 ms | 2.0 / 3.0 ms |
| `open_program` (a join: engine `openMs` 0) | 0.7 / 0.8 ms | 0.7 / 1.2 ms |
| first 50 ms script on the new entry against a warm entry (median) | 78.8 against 77.5 ms | 79.8 against 78.5 ms (one entry of ten took 1,553 ms for its first script; cause not investigated) |
| the very first `open_program` of the program in a fresh daemon (once per program and daemon, **not** per entry) | 1,363 ms (`open_project` 86 ms) | 1,945 ms (`open_project` 92 ms) |

So both opens are required, and **re-establishing a context costs about 6 ms at the median** (3.3 + 1.9
+ 0.7 ms; 27 ms if the worst of each of the three coincided) on a daemon that has the program open, for
the small fixture and the KotOR copy alike: a join does not depend on the program's size. The cold open
of 1.4 to 1.9 s is paid by whoever opens the program first after a daemon start or after `keepWarm` closed
an unused program, exactly as today. While **any** client holds the program (`users` not empty)
`Session.reap` does not close it (`Session.java:171-173`), so a replacement entry that replaces an
abandoned one joins a warm program. (Python 3.15.0 only; the figures are one machine, one run per
fixture.)

**Quiet and busy (N4; revision 5).** Every figure above was measured on a **quiet** daemon. On a busy one
(another script running on the program) the join does not change (`open_project` 3.1 ms and `open_program`
1.3 ms with an 8 s script running, `exp15`, three runs of the same experiment as the third review's
`exp9.py`) and the first script of a new entry costs 46.6 ms when the script file is already warm in the
daemon (42.1 ms quiet; its second script 41.2 ms; `exp16`). One cost is **not per entry**: the **first-ever**
run of a script file in a daemon, while another instance of it is still running, is slow, 1,626 to
2,157 ms for the first new entry in three runs (`exp15`: 1,813, 2,157, 1,626) and 2,130 ms in `exp16c`
(a cold script), while the **next** new entry's first script took 37.7 ms in the same run: it is paid once
per script file and daemon. The third review's 325 ms and 1.70 s and the one 1.55 s KotOR outlier of the
table above are consistent with it but were not diagnosed. RusticQuery is compiled once per daemon, so a
replacement entry does not pay it; this is another reason the four live entries are never closed for being
idle (rule L3 below).

An **entry** is therefore a connection **plus its context**: `{session (from `module.connect`, which
sends `hello`), key = "<root>|<role>|<serial>", the projects it joined, the programs it opened
read-only}`. Nothing in the context is shared between entries. Rules:

- *Who re-establishes it.* The `query` layer does, by the code it already has and no new path:
  `QueryRunner._ask` acquires **one entry for the attempt** and runs `program_for` (which sends
  `open_project` and `open_program`, `query.py:46-67`, and, for a target with overlays, goes through
  `workcopy.reader`) and `run_script` on that same entry, passing it where today's code passes
  `self.engine` (all of them already take the engine as an argument; `query.py:111-115`, `:169`,
  `:184-210` and `stop` at `:220` are the sites Y4a changes). A new entry has no `_keys` row, so its first
  use misses the cache and sends the two opens; nothing else sends them. The creation of an entry is
  `module.connect` plus the identity check of `Engine._connect`, and **not** `sync_scripts` and
  `write_daemon_config`, which run once per process when the shared `Engine` connects (`hydra.py:318-321`
  at 589432e): a replacement must not do an fsynced config write per abandon.
- *Per-connection invalidation of `_keys`.* The cache key is `(engine.key, gpr, program, writable)`
  (`query.py:49`), so an entry's rows are exactly the rows whose first element is its `key`. Three
  invariants, which Y4a's tests assert: **(I1)** an entry's `key` carries a serial that is never reused in
  the process, so no row can describe a connection that is gone; **(I2)** retiring an entry (abandoned,
  `closed`, `OSError`, daemon restart) calls `forget(entry)`, which drops its rows and no other entry's;
  **(I3)** the existing retry on `no_program`, `no_project`, `not_found` or `closed` (`query.py:191-192`,
  `:203`) forgets the entry it used and takes **another** entry; it never sends again on a connection it
  has abandoned. A role-wide invalidation (the repair path of `_ask`, a refresh, a daemon restart) is
  `forget(role)`, which drops every row whose key begins `<root>|<role>|`.
- *Read-only already.* A quick-lane read already opens read-only (`open_project` and `open_program`
  without `writable`, `query.py:46-58`, `writable=False`), so the question whether a read can run on a
  connection that opens the program read-only has the answer that it already does; the join in the table
  is the least a script with `program=<key>` needs (`open_project` alone is refused). A read-only entry is
  never a writer, so closing it discards no unsaved changes: the discard paths of `releaseUse` concern a
  writer or the owner (`ProgramCommands.java:473-540`). `releaseUse` does take the program's **exclusive**
  lock (`e.acquire(true, ...)`, `:480`), so the engine's release of an entry waits behind running requests
  on that program. The client does not wait for it (`close()` of an idle entry returned in 0.1 ms), but
  revision 4's conclusion that the release is therefore harmless to everyone else was **wrong**: while the
  release waits, every new reader of the program waits behind it ("Leaving a program", below).
- *Pool size.* At most `TOOL_WORKERS` = 4 live entries per role (the MCP engine pool never has more calls
  in flight, `mcp.py:22`; this connection pool is not the two tool pools of the Pools rule above, only its
  size follows their workers), plus the probe's one connection, which needs no context (`ping`). An entry
  is created lazily by the next `acquire`, not at retirement.
- *`users` and the cap.* Every entry that opened a program is one more element of that program's `users`
  set (`ProgramCommands.java:236-237`, a `LinkedHashSet` with no limit; `ProjectCommands.java:83-84` for
  the project). Measured on hydra.3 (`exp5`, part D, identical rows for both fixtures): the first
  connection alone `[2]`; with an idle entry open `[2, 14]`; **after a clean `close()` of that entry
  `[2]` again** (sampled 1 s later); an idle entry that sent the FIN (`SHUT_WR`) left in the same way (1.5 s);
  an entry **abandoned with no FIN and never closed stays** (`[2, 16]` 3 s later and at the end of the run; 30 s in
  revision 3); an entry with a cooperative 6 s script that got the FIN after 1 s was gone 1.5 s later and its
  waiter raised `SessionError`; twelve entries open on one program at once listed fourteen ids with no
  refusal, and all twelve left when closed cleanly. Revision 5 adds the case the design now relies on
  (`exp13` D): an entry abandoned with **no FIN** whose worker received the reply and closed the session
  afterwards left, and `users` returned to the live entries. So the abandoned-connection leak is prevented
  by the **worker closing its session once the engine has answered** (step 5), not by a FIN; abandoning an
  entry and never closing it is the one leak, and **the cap of 8 abandoned requests, with the closing list
  of 8 (rule L3), is the bound on it**: the `users` entries that **one Hydralysis process** holds on a
  program are at most 1 (the shared connection) + 4 (live entries) + 8 (abandoned, request still running) + 8
  (closing list) = **21**, each gone when its request has ended and the gate has let its worker close. The
  engine has **no cap** of its own (a `LinkedHashSet`; twelve entries listed fourteen ids with no refusal), and
  other processes and agents add their own. `leaveProject` and `releaseUse` still wait up to
  `CLEANUP_WAIT_MS` (600 s, D19) for the locks of a held program, so an abandoned entry of a program under a
  long exclusive hold can stay listed for as long; E3b bounds it on hydra.4.
  **`QueryRunner.stop` (`query.py:220-251`; N7)** releases this process's use of **the target's** programs.
  Today it sends `close_program` on the shared connection for each daemon program key found in the `_keys`
  rows of the shared `Engine` (`released` lists those keys, `failed` the ones that raised `EngineError`, `ok`
  is `not failed`). After the pool: (1) it waits for the leave gate for the target's programs, at most
  `deadline_grace_s` (5 s); (2) it sends `close_program` for each daemon program key of the target on the
  shared connection (as today) **and on every pool entry that joined it** (an idle entry at once; a
  checked-out entry is marked to close that program when it is returned), and drops those rows (`belongs()`
  matches the rows of the shared engine and of the entries of the role, not only `self.engine.key`); (3) it
  never closes a connection, because an entry may serve other targets (the entries are closed at exit, after
  the gate). The reply keeps its shape: **`released`** lists each daemon program key **once**, when at least
  one `close_program` for it succeeded (the key `p1:/alpha.exe` is the daemon's, the same on every
  connection); **`failed`** has one object `{program, entry, error}` per failed close (`entry` is the entry's
  key, or `"shared"`); `ok` is `not failed`; one additive key, `entries: {closed, deferred}`, counts the
  entries whose `close_program` was sent and those left to their return or to the gate (a deferred entry is not
  in `released` until it has closed). `close_program` is itself a leave, so it passes the gate too (a close
  that the gate defers is reported as `deferred`, never as a failure); the note text is unchanged.
- *Leaving a program (measured, revision 5; rules L1 to L3).* An entry that joined a program and then
  **leaves** (a clean `close()`, a FIN, the end of an abandoned request after a FIN) queues the engine's
  exclusive `releaseUse` (3.5). On the real daemon, with one read of 6 s running on the program and
  entries that had joined it (`exp13`, a fresh state root per scenario, the 1.0.0 library; `exp11_rerun` and
  `exp12_rerun` reproduce the third review's runs on hydra-3-candidate), every shared acquire was refused
  `busy` after its 1.5 s wait while that release was queued, for a **new** entry's opens **and** for the script
  of an **already-joined** entry:

  | Scenario (`exp13`) | Engine as today (hydra.3 behaviour) | Engine with E3c's fast path (3.5) |
  |---|---|---|
  | A, revision 4 rule: an idle entry is closed cleanly while a read runs | new join `busy` after 1,509 ms; joined entry's script `busy` after 1,506 ms (`wanted:shared`, `readers:1`); both fine once the read had ended (3 ms, 43 ms) | join ok 3 ms, script ok 44 ms |
  | B, revision 5 rule: the same entry stays open and is closed when the read has ended | join ok 3 ms and script ok 41 ms during the read; the close returned in 0.3 ms; join 4 ms and script 42 ms after | not run |
  | C, revision 3 and 4 mechanism: a non-cooperative script, `cancel`, FIN; another entry starts an 8 s read; the script ends and the engine leaves the entry | join `busy` after 1,510 ms, script `busy` after 1,507 ms | join ok 3 ms, script ok 42 ms |
  | D, revision 5: the same without the FIN; the worker receives the reply (`cancelled` at 5,036 ms) and defers its close to the end of the other read | join ok 4 ms, script ok 43 ms; the deferred close returned in 0.1 ms; `users` back to the live entries | not run |
  | E, control: no FIN, but the worker closes at once after the reply | join `busy` after 1,511 ms, script `busy` after 1,505 ms | join ok 3 ms, script ok 189 ms |

  An entry abandoned with no FIN and never closed caused nothing (`exp11_rerun`: join 4 ms, script 35.5 ms),
  and the control without any leave gave join 3 ms and script 36.4 ms. (In that run the first join of the
  `clean_close` mode was itself refused: the closes of the previous mode's entries reached the engine just
  after the next read had started, the same effect by accident.) The rules, for an engine without E3b's
  fast path (hydra.2 and hydra.3; hydra.4 does not use the pool, below):
  - **L1. No FIN, no `shutdown`, no `close()` on an entry that joined a program while a request is in
    flight on it.** A FIN adds nothing `cancel` had not done, and its one distinct effect is a leave at the end
    of the request (scenario C). Step 4 is therefore the abandon, nothing more.
  - **L2. The leave gate.** A joined entry is **closed only when this process has no read in flight on any
    program the entry joined**, per program key `(root, gpr, program)`, counting abandoned requests that the
    engine has not answered yet; until then it waits in a **closing list**, which is drained when the last
    such read ends. The closes it covers: the abandoned worker after its late reply (step 5), the retirement
    of an entry after `no_project`, `no_program` or `not_found` (I3), `QueryRunner.stop` and the exit of the
    process. An entry whose connection already failed (`closed`, `OSError`, a daemon restart) has nothing to
    leave and is dropped. The gate lives in `hydra.py` (Y4a); it never delays a **reply** and never blocks a
    caller.
  - **L3. Bounds.** The closing list holds at most 8 entries; past that the oldest is closed regardless (the
    stall above is then possible, and the doctor reports the count). Idle entries are **not closed at all**:
    the four live entries of a role stay open for the life of the process (no idle timeout, no shrink), so a
    quiet process has no churn, and the one leave happens at `stop` or at exit, through the gate (at exit the gate waits at
    most `deadline_grace_s`, then everything is closed: a process that is going away cannot wait for reads it cannot see).
  The gate mitigates what the **client** causes. It cannot see another process's reads (limit in 6), and on
  hydra.4 it is not needed: E3c's fast path makes a plain reader's leave harmless, and P1b's deadline keeps
  the connection, so the entry pool and the gate serve the hydra.2/3 helper only.
- *Fairness, unmeasured.* Each entry is its own client for the scheduler's round-robin release
  (`Scheduler.java:266-277`), so up to five connections of one process compete where one did; on hydra.2/3
  the key is the connection id and is never capped (G3). The effect on other agents' share of the lane was
  not measured.

**Numbered steps.**
1. *One attempt, one entry.* A deadline-bound **attempt** (a `QueryRunner._ask` attempt: `open_project` and
   `open_program` on a cache miss, then the `script`; or the supervisor's `ping` on the probe's own
   connection) takes an idle entry of its `role` (or creates one, up to the pool size) and returns it to the
   pool only after an attempt that ended with a reply that leaves the connection healthy: a result, or a
   structured engine error such as the `busy` above. An entry that was abandoned or broke is never reused;
   its replacement is a new entry with a new serial. **Invariant: no other request is ever in flight on an
   entry.** Y4a's code and tests enforce it (an entry is checked out by exactly one attempt; a second `send`
   on a checked-out entry raises): an entry is abandoned as a whole, so a second request on it would be
   abandoned with it, and the answer of an abandoned request must never be taken for another's. (The measured
   reason revision 4 gave still holds: a FIN ends **every** request in flight on the connection. With a
   non-cooperative script A and a cooperative script B on one connection, `cancel` for A and the FIN 3 s
   later ended **B** at once, `SessionError cancelled` 0.02 s after the FIN, while A went on until its own
   end, 12.1 s, `exp6` N3 and the reviewer's `exp4_adversarial.py`, X1 and X2; it is one more reason that the
   shared `Engine` connection, on which several threads have requests in flight, is never half-closed.)
2. The call is `rid = session.send(...)` plus `session.wait(rid)` **in a daemon worker thread** of
   Hydralysis, once per engine call of the attempt; the caller waits on its own `threading.Event` until the
   **attempt's** deadline (`deadline_s` from the acquire, "The unit of the pool is the attempt") and never
   enters `wait`. A mutating call never gets a deadline that abandons (4.3).
3. On expiry the worker's session gets `session.send("cancel", target=rid)` (thread-safe, `:732-738`; it ends
   a request still waiting for a slot, and a cooperative one) and the caller waits `deadline_grace_s` (5 s)
   more for the reply.
4. If there is still none: **abandon, and send nothing**: no `shutdown` (revision 3's `SHUT_WR` is withdrawn,
   rule L1), no `session.close()`, no `_r.close()`, no `sock.close()` while the worker is alive, and no
   `send` on that session afterwards. The caller gets `deadline_exceeded` with
   `details.connection_abandoned:true` after `deadline_s + deadline_grace_s` (measured 2.01 s for 1 s + 1 s,
   `exp3`, C; that timing does not depend on the FIN).
5. The worker ends by itself when the engine answers or the connection fails. On the **answer** the request
   is over: the abandoned **count** drops (it counts requests the engine has not answered), the entry's rows
   leave `_keys` (`forget(entry)`, I2), and the worker hands its session to the **closing list** of the leave
   gate (rule L2), which closes it when this process has no read in flight on a program the entry joined
   (closing at the end of another read: `exp13` D; closing at once while another read runs stalls it:
   `exp13` E). Abandoned workers are counted in a process-wide registry with **two budgets**: **at most 8**
   abandoned user calls at a time (*unmeasured policy*: 40 abandoned connections cost 40 daemon threads and
   40 sockets and all end when the engine closes them, `exp3`, B; the `users` arithmetic is above), and
   **at most 3** abandoned supervisor probes, the number of consecutive misses that makes a wedge (7.2). The
   probe is **exempt** from the 8: eight stuck lock waits of user calls on a program held by a long analysis
   must never make a busy but healthy daemon look as if it did not answer `ping`, and `ping` is answered
   inline outside the scheduler (`Session.java:219-221`), so a missing answer is the wedge signal itself.
   Beyond the user budget a deadline-bound call fails fast, **before anything is sent**, with the Hydralysis
   code `abandoned_cap` (details `{cap, abandoned:[{cmd, label, program, ageS}]}`, `next` the doctor call),
   **not** `daemon_unhealthy`, which stays the restart-budget code of 7.2; the doctor (7.1) lists both
   registries and the closing list, which is what an operator needs on a daemon where eight requests ignore
   cancel.
6. Rejected: `close()` on a timer (hangs); the half-close of revision 3 (a FIN makes the engine leave the
   program when the request ends, and that leave stalls the other readers, `exp13` C; it adds nothing the
   `cancel` had not done); abandon **and never close** (the engine keeps the client and the program's `users`
   entry for good, which `exp2` (a) measured with a worker that never closed its session; the worker of step 5
   does close it); closing the abandoned session at once on the answer (it stalls the other readers while
   one runs, `exp13` E); the abortive close (c), which works on Windows and wakes the reader, but reaches
   into the library's private `sock` with `detach()`, raises a raw `OSError` out of `wait` that 1.0.0 does not
   handle (`_closed` stays unset), depends on Winsock behaviour, and buys only the early end of one thread.

**What changes with P1b and E3b.** On a hydra.4 engine the library is 1.1.0 and P1b's `deadline`
replaces steps 1 to 5 (the library times its own `wait`; the connection survives, so nothing is
abandoned, no entry is replaced and the leave gate is not used). E3b (V3, V5) also changes what the engine
does with a connection of an old library that is closed or sends a FIN: a request in a lock wait now ends
within a second of the `cancel` or the FIN, a request that does not end is released after
`cleanupGraceS + abandonWaitS` (about 20 s) with the program flagged `abandoned`, instead of staying
registered for as long as it runs, and **the leave of a plain reader takes no exclusive lock** (3.5), so the
stall of "Leaving a program" does not occur. Until then the cap of step 5 and the leave gate are the
protection.

**Tests (Y4a).** New files: `tests/test_deadline.py` for the helper, the pool, the registry and the leave gate,
and `tests/test_supervisor.py` for 7.2. Against the fake: a blocked session never has `close()` called while its
worker is alive and **never receives a `shutdown`** (a fake that fails the test if either happens; `SHUT_WR` is
no longer part of the mechanism); the caller gets `deadline_exceeded` at `deadline_s + deadline_grace_s`
**for the attempt** (a fake whose `open_program` takes 40 s and whose script then takes 40 s gives it at 60 s
plus the grace, not at 120 s: the unit is the attempt, N1); the abandoned count never passes 8 and returns to 0
when the fake answers; with the user budget of 8 full a probe is still sent, and `abandoned_cap` (not
`daemon_unhealthy`) is the answer to the ninth user call; a fake that answers `no_project` or `no_program` to
any call on a connection that has not seen both opens (the engine's rule) proves **I1 to I3**: an entry's first
use sends `open_project` and `open_program`, a retired entry's `key` is never reused and `forget(entry)`
leaves another entry's rows, and a retry after `closed` takes another entry; a second `send` on a
checked-out entry raises; **the leave gate**: a fake that records the instant of every `close` per connection
and the reads in flight: no entry is closed while a read is in flight on a program it joined, the closing list
drains when the last such read ends, a ninth entry in the list closes the oldest, an entry whose connection
failed is dropped without a close, and `stop` waits for the gate (at most the grace) and reports `released`,
`failed` and `entries` as in the `users` bullet. Against the **real hydra.3**, one test per case above (L, S,
C of `exp2`, reduced in time), plus the context, `wait` and leave cases:
- **`replacement_context`** (the experiment above as a test, **deterministic**: every wait is a poll of
  `status` for a condition with a bound of 10 s, never a fixed sleep, and the script that plays S is
  `TestNoCoop` with a length that does not depend on a race): (1) a fresh connection without the two opens
  answers `no_project` and `no_program` (a documented premise: if it stops failing, the context step is dropped
  from the design, as E0's convention says); (2) the entry of case S is abandoned at its deadline and **the
  very next read takes a new entry, re-establishes its context and is answered, with no `no_project`**
  (asserted on the answer and on the engine's `status.clients[]`: exactly one new client, which sent the two
  opens); (3) the other entries' connections in `status.clients[]` are unchanged (the same ids, no request
  added); (4) the program's `users` is `live + 1 (the new entry) + 1 (the abandoned one)` while S runs;
  (5) when S ends, the abandoned worker receives the reply and the entry goes to the closing list; with no other
  read in flight the gate closes it and `users` returns to the live entries; and with **another** read R in
  flight when S ends (a cooperative 8 s script), the entry's close is **deferred until R ends**: while R runs
  `users` still lists it and a further read is **answered, not `busy`** (`exp13` D), and when R ends `users`
  drops and both the registry and the closing list are empty.
- **`wait_below_deadline`**: a read for a program held by another client's script returns the engine's
  `busy` at `wait` (about 3 s in the test), the entry returns to the pool, nothing is abandoned and the
  registry stays at 0 (`exp6`, N2, as a test); **and the same for the two opens** (N2): with the program's
  lock queued behind another client's leave during a running read (the hazard of 3.5, made real on hydra.3 by
  the test itself) a new entry's `open_program` is answered `busy` at its `wait` (`exp13` A), the entry
  returns to the pool and nothing is abandoned.
- **`leave_gate_no_freeze`** (`exp13` D and E as one test): the abandoned worker's close, deferred, leaves a
  concurrent read and a new join answered; the same close done at once is the control that must stall
  (it is expected to, on hydra.3, and the test says so: if it stops stalling, rule L2 is dropped, as E0's
  convention says).
- the entry of the stalled call is replaced and the other entries are untouched; the engine shows the
  cancelled flag within 1 s of the **`cancel`** (nothing else is sent any more); C is released within 1 s and
  the call returns the engine's reply; L and S stay registered until the holder or the script ends and then
  the abandoned worker ends and the registry is empty.

### 7.7 The 20 tools: where each feature lives

The 20 tools stay (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`, `callers`, `callees`,
`function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_add`, `evidence_list`, `ghidra_run`,
`ghidra_query`, `backend`, `prepare`, `job`, `runtime`). One catalog epoch in Y0d, before the 0.5.0
tag, then a hash-checked freeze. **What shipped, and so what this section decides (revision 5, from the code
at `1584f6e`):** the number is **2**. Epoch 1 (the table with the `doctor` and `backups` enum values and the
`options` bags) never left the branch; its follow-up changed one description, so the table changed and the epoch
was bumped: the `pe_address` text of the eight address tools keeps **only the refusal clause** ("Use rva:/va:;
ambiguous unprefixed addresses are refused."), **not** the epoch-0 examples ("rva:0x... or va:0x..."), because
the long form costs 104 bytes more (8,276 against 8,172 advertised bytes) and the table has a budget of 8,192
(`tests/test_contracts.py`, `test_catalog_stays_small_in_bytes_as_well_as_count`). **Where the epoch is
reported: `catalog:{epoch, hash}` is carried by `backend action=status`, `backend help` and `backend inspect`
(`api.py`), and by the MCP `initialize` result under `_meta["hydralysis/catalog"]` (`mcp.py`)**;
`ghidra_query action=status` is a target status built in `query.py` (a different file, owned by Y1/Y2/Y3) and
is about a target, not about the tool surface, and the CLI does not carry it. The hash covers only the advertised tool
table (names, descriptions, input schemas), **not** the `instructions()` text or the help output
(a deviation Y0d disclosed and this section accepts): a change to either needs a manual epoch bump,
which a reviewer checks, because no test can see it.

| Feature | Carrier |
|---|---|
| edit with `expect_revision`, named view | `ghidra_query action=type_edit options.{kind,expect_revision,view}` (exists) |
| commit, revert, rebase, publish, merge, export/import bundle | `type_edit options.kind = commit | commit_revert | rebase | publish | merge | export_bundle | import_bundle` (no address needed, like `struct` and `revert` today) |
| changes against master, views, lineage, queue, health | `ghidra_query action=status options.show = changes | views | lineage | queue | health` |
| commit/backup/publish jobs | `job` (existing `status`/`cancel`), jobs of kind `commit` |
| doctor | `backend action=doctor` (new enum value, Y0d; the handler is `doctor.py`, Y4b; reachable from the CLI too, 7.1) |
| list, verify backups and generations; remove one generation | `backend action=backups` with `options.op` set to `list`, `verify` or `remove` (new enum value and an `options` bag, Y0d; `remove` is a dry run unless `confirm:true`, OD8) |
| agent identity (D59) | `options.as` on `ghidra_query` and `ghidra_run` (the free-form `options` bag: no schema change, no catalog epoch); a tool without an `options` bag takes none and reads the master; listed in `OPTION_BAGS` (`backend help`, outside the catalog hash) by Y2 |
| user-script mode | `ghidra_run options.{isolation, readonly}` (`options` bag added in Y0d; `view` exists; until Y4e ships a non-empty bag answers `not_available` instead of running, a Y0d decision that is kept: nothing is silently dropped) |
| lane hints, deadlines, identity | internal to the client; no schema |
| format, health, platform facts | surfaced in `backend action=status` and the doctor |

Until the engine capability exists a new action returns `{"not_available":"<capability>"}`, not an
error (the dispatcher answers it when the handler module of `api.HANDLER_MODULES` does not exist; **no frozen
test may assert it through the real dispatcher**: Y2 rewrites the existing ones against the registry, 8). Running sessions cache tool lists (`mcp.py:45`): after the epoch, features arrive only through
`options`, and `backend help` and the 0.5.0 release notes say a harness restart is needed once.

### 7.8 Multi-agent obligations (revision 6)

The obligations that follow from 3.9 to 3.12 are in 4.10 and 4.11: a stable agent id and a distinct `options.as` for each
editing sub-agent (one rule, D59), a lazily created fork-backed view per agent, the shared base, write-ahead before apply, the publish
queue, client-side eviction, structured `busy` mapped to `next`, and never opening a master or generation writable.

---

## 8. Work packages

Repos: **Hydra** = `Ghidra/Features/HeadlessSession` in the Hydra Engine repo (paths below are relative
to it; Java is under `src/main/java/ghidra/app/util/headless/session/`, abbreviated `S/`).
**Hydralysis** = `src/hydralysis`. Each package lists: goal; files owned; depends on; parallel with;
protocol surface; tests (Python integration or characterization; new behaviour gets **new** goldens, old
goldens must still pass for unchanged commands); fault injection; acceptance; size (S, M, L).

Conventions that make the waves disjoint (the matrix in 8.1 is the authority; this is how it is kept true):

- **One owner per file per wave.** 8.1 lists, for every file a package edits, the one package that may
  edit it in each wave. Two packages in one wave never share a cell. A package that needs a file that
  another package owns in its wave waits for the next wave or asks for a seam first (D31). A new file
  belongs to the package that creates it, in that wave and later ones until another is named. **One
  declared exception to "two packages never share a file in a wave"**: a file that two packages must both
  change in one wave, because each changes the part that is its own and both change the same assertions,
  gets **two rows** in 8.1, the second marked "second step of Wn, after <package>", and the later package
  declares the dependency. There is exactly one, `tests/test_durable.py` in W1 (Y0e, then Y1, 8.2); the
  proof script requires both rows, the dependency and the wave, and prints the sequence.
- **Seams first (D31).** The shared files every feature wants to touch are opened once, early, as
  behaviour-free seams by E1 (W1): the two signature changes of D17 and their call sites
  (`Scheduler.laneOf`/`admit`, `Session.java:248`, `ImportCommands.java:112`), the call sites of
  `ProjectEntry.info(client)` (a signature only, so that E2's `format` needs no `Session.java` edit), and
  four registries (`Advertised`, `Settings`, `Preflight`, `DbVersions`). Later packages
  register into them from classes they own. So `Session.java` is edited by E1 (W1), E3b (W3), E3c (W4) and
  E5 (W5) and by no one in W2, and E2 and E3a, which run in parallel in W2, share no file.
- E0 adds loaders so each package adds tests in its **own** files: `examples/dt_<package>.py` for
  daemon tests (each exposes `TESTS = {name: fn}`; `daemon_tests.py` imports `dt_*.py`),
  `examples/char_<package>.py` for characterization scenarios, with goldens in
  `examples/characterization/v3/<id>-<scenario>.json` (recorded with `--protocol 3`; the file name starts with the package id, rule 2 below), and P1a adds the third
  loader, `examples/cc_<package>.py` for the protocol-2 behaviour tests of 5.1. The seven existing
  scenarios run at `--protocol 2` and must stay `identical`.
- **`certification.manifest` is the one deliberate exception** to "one owner per file per wave": every
  package appends its new files to it (the `buildHeadless` IP check fails otherwise for a file that carries no `IP:` header of its own: 8.5, A8), it is append-only,
  and a textual merge conflict is resolved by keeping both lines. (R1's own line items are its
  release entries; the append rule holds for every package, R1 included.) **`PROTOCOL-3.md` is the
  design**, a different file: packages do not edit it (a design change is a new revision by the
  coordinator, with the history at its end), and status lives in the stream reports under
  `D:/Projects/Hydra/_logs/<stream>/`. README and CHANGELOG are edited by R1 alone, from the
  packages' hand-over notes.
- **A package that changes the format of a stored file owns the existing tests that write that file by
  hand.** Y0a sealed every record file, so two older tests that hand-edit a store or a record and keep
  its stale seal had to drop the seal (`record.pop("seal")`, commit `c78be27`: `tests/test_address_maps.py`
  and `tests/test_query.py`); 8.1 now gives those two files to Y0a explicitly (W0), and Y1 owns the
  tests that hand-write or patch a store when it moves to store v3, which 8.1 now **names**:
  `tests/test_analysis.py` (the 15 calls of the deleted `save_overlay`), `tests/test_exporting.py`,
  `tests/test_crossbuild.py`, `tests/test_revisions.py`, `tests/test_query_script.py` and `tests/test_query.py`.
  The same applies to later format changes. (Y0e's sealed `runtime._write` needed no edit of
  `tests/test_runtime.py`, which is therefore frozen and has no row any more.)
- **A package that makes a frozen test's assertion false owns that test, or the test must not assert it
  (revision 5; the class of the fourth review's BLOCKING 1 and 2).** Rule 3 freezes a test file after the wave
  that creates it, and rule 4 refuses any edit, so a later package that makes an old assertion false could
  not fix it. Two kinds were found, each with a decision. (1) **Stub answers:** `tests/test_contracts.py`
  (`NotAvailableCarriers`, `:105-164`) and Y0e's `tests/test_cli.py` assert `not_available` for `backend`
  `doctor` and `backups`, for `ghidra_run` `options` and for `job` `options`, through the real dispatcher with
  nothing patched; Y2 (backups and job options, W2), Y4b (doctor) and Y4e (isolation) each make one of them
  false. **Decided: Y2 owns both files in W2 and rewrites those tests once, against the handler registry** (the
  `api.py` bullet below), so Y4b and Y4e edit neither. (2) **Pinned values:** `tests/test_backends.py` (`:21`,
  `:101`), `tests/test_query.py` (`:285-296`) and `tests/fakehydra.py` (`:28`) carry the pinned release
  `12.3-hydra.2`, and `hydra.py` builds the message the first asserts from `RELEASE`. **Decided: Y4a (W6)
  rewrites the two tests to derive the release from `hydra.RELEASE` and from the fake's own constant**, owns
  the files `tools/bump_hydra.py` edits (5), and no bump edits a test after that. The proof script scans for
  both kinds (below).
- **Every test, example, tool and benchmark file has an owner: four rules that a script checks.** (1) A file
  with a row in 8.1 follows its row; a package that **creates** a test or example file gives it a row (bold),
  whatever its name. (2) `examples/dt_<id>.py`, `examples/char_<id>.py` and `examples/cc_<id>.py`, with
  `<id>` the package id in lower case (`dt_e3a.py`), belong to package `<id>` and to nobody else, and so do the
  goldens its `char_<id>.py` records, named `examples/characterization/v3/<id>-<scenario>.json`: the file
  carries the name of its owner. (3) Every other file under `tests/`, `examples/`, `tools/` and
  `benchmarks/` at the two code bases is **frozen**: no package edits it. That is `examples/session_smoke.py`, the two
  probes and `examples/scripts/ExportJsonl.java`, `tests/support.py` (shared helpers: a package that needs a
  change asks for a seam, D31), `tools/golden.py` and its helpers, `benchmarks/`, and the existing test
  files that no row names (the proof script lists them). The seven v2 goldens `examples/characterization/*.json`
  are **not** in this list: they have an E0 row in W0 (8.1), which covers the deliberate re-records of
  `f47ff15934` and of amendment A1 (E0, below; D62); they must stay `identical`, and after W0 nobody edits them. (4) `examples/check_ownership.py` fails a package
  branch that changes a frozen file even when the package text names it. The file is E0's and was written
  before the ids `Y0e` and `Y4e` existed: its pattern `[EPYR]\d+[a-d]?` cannot see them
  (`examples/check_ownership.py:57`, `:145` on the E0 branch), so **E1's first commit** makes it read the
  package ids from the wave plan table, accept the golden prefix of rule 2, enforce rule 4 and resolve the
  repository-root documents of the Hydralysis table (`README.md`, `THIRD_PARTY.md`, `docs/...`, which it would
  look for under `src/hydralysis/` today) (a row in 8.1, W1); until E1 merges, Y0e's branch is checked with E1's copy of the script. **Revision 8.1 (A2, 8.5):** the
  coordinator has already widened the id pattern to all 52 ids, made the script read the docs and site column of the wave
  plan, `then` cells and the site table; what stays in E1's first commit is the resolution of the Hydralysis root documents. The proof that these rules hold
  for this file is `D:/Projects/Hydra/_logs/spec-rev8/prove_disjoint_rev8.py` (the descendant of the scripts of `spec-rev5/`, `spec-rev6/` and `spec-rev7/`, which stay as history; revisions 7 and 8 add the checks of 8.4): besides the revision 3 and 4
  checks it lists every file that appears in **no** row yet is edited by some package's text, every file that
  two packages of one wave cite, the existing files that are frozen, **and (revision 5) every frozen test that
  asserts a stub answer (`not_available`) or a pinned release literal (`12.3-hydra.<n>`) that a later package
  changes**, requiring a row for the package that changes it or a declared waiver, and every pinned literal of
  the Hydralysis tree to be in the edit list of `bump_hydra.py` (5) or the historical list; the revision
  table quotes its output.
- Hydralysis hotspot files (`workcopy.py`, `query.py`, `analysis.py`, `hydra.py`, `api.py`,
  `tests/fakehydra.py`) have one owner per wave (8.1). **`api.py` is opened once**: Y2 (W2) replaces
  Y0d's `not_available` stubs with a **handler registry** (a capability name to a handler module, held in
  `api.HANDLER_MODULES = {"backups": "hydralysis.backups", "doctor": "hydralysis.doctor", "jobOptions":
  "hydralysis.commits", "scriptIsolation": "hydralysis.userscripts"}`, read at call time so that a test can
  patch it; the names are the `not_available` values Y0d ships; `backups.py`, `commits.py`, `doctor.py` and
  `userscripts.py` register their handlers, and `api.py` imports the module lazily and answers
  `not_available` when it does not exist yet), so Y4b, Y4d and Y4e never edit `api.py`: the `ghidra_run`
  `options` (`isolation`, `readonly`) dispatch, the `job` `options` and the `backend` `doctor` and `backups`
  actions each have a named owner and wave in 8.2, which is the seams-first rule of D31 applied to the Python
  side. **The tests of the stubs move with it (revision 5):** Y2 rewrites, in W2, the four tests of
  `NotAvailableCarriers` in `tests/test_contracts.py` (`:111-157`) and the two stub tests of
  `tests/test_cli.py` so that each **patches `api.HANDLER_MODULES` with a module that never exists** (for
  example `"hydralysis._no_such_handler"`) for the capability it tests: the dispatcher's own `not_available`
  path stays asserted whichever handler modules exist, and neither Y4b nor Y4e edits a frozen file. The
  four tests are `:111-124` (doctor and backups), `:126-130` (the same through MCP), `:140-153` (`ghidra_run`
  options) and `:155-163` (job options); the assertions inside them that are **not** stubs (a plain `ghidra_run`
  and a plain `job` call, with and without an empty `options`, still reach their real functions, `:142-143`,
  `:158-161`) and the option-validation test (`:132-138`) stay as they are and must still pass unchanged.
- `examples/check_ownership.py` (E0) reads the matrix in 8.1 and fails when a wave cell names two packages
  or when the files changed on a package branch (`git diff --name-only` against its base) are not
  all in that package's rows for its wave; it runs at every package merge (gate 9.11). Its package-id parser and
  its handling of frozen files are E1's first commit (the rules above), except that revision 8.1 (A2) fixed the id pattern,
  the docs and site column, the `then` cells and the site table in the script itself.
- **In-wave order (revision 7, completed in revision 8).** The proof prints every dependency between two packages of one wave;
  there are **23** (revision 8.1, A4, adds E2a after E1), and this is the whole list: E1 after P1a; E2a after P1a and E1; E6 after E5, E7 and E9; E7 after E5 and E9; E9
  after E5; R1 after E5, E6, E7 and E9; S2 after R1 and Z13b; X0 after E0; Y1 after Y0e and Z1; Y4b, Y4d and Z14 after Y4a;
  Z10 after Z9; Z5 after Y2. Each is named in the later package's `Depends on:`. Only three of them are also **file
  sequences** and declared in the script's sequence form (a `**then**` cell, or a "second step" row that also requires the
  dependency and the wave): `S/HeadlessSession.java`, E5 then E9; `tests/test_durable.py`, Y0e then Y1; and (A4) `S/Advertised.java`, E1 then E2a. The others share no
  file (Y4b, Y4d and Z14 after Y4a: the registry the doctor lists, the fake daemon Y4d's tests run on, the pin Z14 documents;
  E7 after E5 and E9: the `Health` contributor list, the process budgets; E6 and R1 after the packages whose gates they run
  and document), so the sequence form would be a false statement for them.
- All engine tests use fresh state roots under `D:/Projects/Hydra/_logs/<stream>/` and a fresh
  `--tmpdir`; they never touch the live daemons.

### Wave plan (compact)

| Wave | Hydra (engine) | Hydralysis | Docs, site, policy | Notes |
|---|---|---|---|---|
| W0 verification and wording | E0, X0 | Y0a, Y0b, Y0c, Y0d | R0, S1, Z13a | no engine behaviour change; all parallel; disjoint files (8.1). X0 builds the oracle K1-K17 with its planted-violation self-tests, imports the measurement scripts of A, B and C as regression suites and records the **red table** on hydra-3-candidate (9.12). R0, S1 and Z13a correct the wording of the engine documents, the website and the Hydralysis documents to what is true today (D52, 8.2). |
| W1 foundation, seams, integrity | P1a, then E1; E8; E2a | Y0e, then Y1; Z1 | | E1 owns every shared-file seam (`Session.java`, `Scheduler`, `ImportCommands`, `UpgradeCache`, `ProjectCommands`, `ProjectEntry` (signature only), `HeadlessSession`, and the new `Advertised`, `Settings`, `Preflight`, `DbVersions`, **`Hooks` and `Guarded`**; **E2a** adds the capability name `forkAtomic` to `Advertised` after E1, a declared `then` sequence on that one file, A4); P1a owns `ghidra_session.py` and the protocol-2 compatibility harness and lands first; **E8** fixes the version-file ordering in the Ghidra core and **E2a** makes the fork publish atomic and sweepable (E8 is not protocol-visible and E2a only through V11; together they are the integrity packages of 5.3, which ship in hydra.4, OD10); Y0e takes the W0 review follow-ups (8.2); **Z1 merges before Y1** (it pins the concurrency behaviour Y1 and Y2 must keep, and holds the multithread `_sync` test as a known issue); disjoint except two declared sequences, `tests/test_durable.py`: Y0e, then Y1, and `S/Advertised.java`: E1, then E2a |
| W2 facts, gates, lanes, shared base | E2, E3a | Y2; Z4, Z5, Z7 | | **neither E2 nor E3a edits `Session.java`** (E3a edits the lane defaults in `HeadlessSession.java`; the owners of that file are E1, E3a, then E5 and E9, one per wave, 8.4). E2: format, backup, gate, fork purposes, **seal**, `prepare_upgrade`, the second independent backup; it names no lane. E3a: `Scheduler`, `ImportCommands`, `ImportGate`, `Requests`, `Connection.respond`, `RequestMonitor`; lanes, caps (v2 too), the import wait. Y2: lineage, commit, backups, **the shared base, the per-view connection and lock, `integrity.py`, the launch configuration (`maxLong`, `maxQuick`)** the stub-test rewrites (8, 8.2) and **the removal of the saver process `workcopy_saver.py` with the `locks.py` changes the per-view lock needs (D61)**. Z4, Z5, Z7 need no engine change |
| W3 robustness | E3b | Y3; Z2, Z3, Z6, Z8 | | E3b owns `Waits`, `Caller`, `Access`, `ProgramEntry`, `OverlayCommands` (lock site), `Connection`, `RequestMonitor`, `Session.disconnect`, `ProjectCommands` (the registry un-nesting and `leaveProject`), `ProgramCommands.releaseUse` (the owner and writer leave, bounded; the plain-reader fast path is E3c's, D63). Y3: rebase, publish queue, merge. Z2 measures the named-view cost and the publish latency (9.16, SP7) |
| W4 the non-blocking core, isolation, launcher, views | E3c, E4, P1b | Y5 | | **E3c** owns `Session.java`, `Access`, `ProgramEntry`, `ProgramCommands`, `ProjectCommands`, `ProjectEntry` and the new `ProjectRegistry`: refcount join and leave for every reader (the plain-reader leave stall, D63b), the per-project state machine, `analyzing`, waiter caps; **E4** owns `ScriptCommands`, `OverlayCommands`, `PrivateInstance`; the two share no file. P1b is the launcher (deadline, `LaunchError`, registry) and owns no Job Object (D60). **Y5** makes per-agent views the default (it does not need E3c: it works on hydra.3 through forks) |
| W5 health, governor, killable script worker, soak and release prep | E5, E9, E6, E7, then R1 | Z13b; (R1's bump script) | S2, Z15 | E5 (moved from W4 because E3c owns `Session.java` in W4) owns `Session.java`, `Scheduler`, `Health`, `Watchdog` and starts the watchdog in `HeadlessSession` **then E9** starts the governor there; E9 owns the governor, the decompiler gate, the decompiler borrow sites and `ProcessJob` (the daemon's own Job Object, D60); **E7** (moved from W8, D64) owns `ScriptCommands` and the new `ScriptWorker` after E4 and E9 and edits no seam file; E6 is the gate runner (PR, nightly, release lanes); R1 owns `tools/bump_hydra.py` (now also the site constants) and the docs and runs after E6; then **gate G** (section 9) |
| W6 adoption on hydra.4 | | Y4a, then Y4b and Y4d, and Y4e; Z9, Z10, Z14 | | disjoint files; **Y4b, Y4d and Z14 merge after Y4a** (an in-wave dependency named in each package's `Depends on:`, not a file sequence: they share no file with Y4a, 8); Y4a runs R1's `bump_hydra.py` and owns the files it edits (5, 8.1). Z9 (evidence v2) and Z10 (runtime evidence on the existing fixtures) run in parallel; Z14 closes the wave. The package ids are Y4a, Y4b, Y4d and Y4e: **there is no Y4c** |
| W7 runtime scenario | | Z11, Z12 | | Z11 (fixture-first scenario) then Z12 (memory write and watchpoints, fixture-only, after the owner's decisions N2 and N3 of the audit): runtime evidence and coverage come first |
| W8 hydra.5, conditional | E10, E11, E12 | | | each only if its spike says go (9.20) |

### 8.1 File-ownership matrix (the disjointness assertion)

Every file a package edits, by wave. `S/` is `src/main/java/ghidra/app/util/headless/session/`; **bold**
marks a file the package creates. A blank cell means no package edits the file in that wave. **Assertion:
no cell names more than one package** (so each wave is disjoint by construction, and
`check_ownership.py` verifies it); `certification.manifest` is the one stated exception (above). A file has two rows only as the declared sequence of section 8. Test, example and tool files follow
the four rules of section 8: a row here, the package id in the file's name, or frozen.

**Hydra (engine repo)**

Paths are relative to `Ghidra/Features/HeadlessSession` unless they begin with `/`, which is the repository root
(the Ghidra core, `NOTICE-HYDRA`, the root documents and `.github`). The wave columns are W0 to W5 and W8
(W6 and W7 have no Hydra cell).

| File | W0 | W1 | W2 | W3 | W4 | W5 | W8 |
|---|---|---|---|---|---|---|---|
| `S/Session.java` | | E1 (hello, `info`, `admit` call with the request, the call sites of `ProjectEntry.info(client)` at `:265`, `:333`, `:427`, the admission and `Guarded` seam call sites, `isInline` stays) | E2 (A13: the `seal_project` and `prepare_upgrade` dispatch) | E3b (`disconnect`, `reap`) | E3c (the join of a program under analysis, the registry as a state machine, refcount disposal in `reap`; A32: `completeLeaves` closes the idle project through `registry.closeIdle`) | E5 (`isInline`, `case health`, watchdog start) **then** E9 (A33: `Governor.admit` before the slot wait of a request and the close of its reservation; `reap(warmMs)`, the overload the governor calls with 0 before it refuses an open) | |
| `S/Scheduler.java` | | E1 (`laneOf(cmd, req, v3)`, `admit(c, cmd, req, m, waitMs)`, `describe(boolean)`, all behaviour-free) | E3a (maint lane, fair key, cap, queue info, ETA, `Preflight` call, `Ticket.yieldSlot`) | | | E5 (`describe` `tryLock`, lane stats) | |
| `S/ImportCommands.java` | | E1 (the `admit` call at `:112` only) | E3a (remaining wait; the `ImportGate.enter` call at `:100` passes the client) | | | | |
| **`S/ImportGate.java`** | | | E3a (`enter` takes the `Client`, `Entry` keeps it, `queueInfo` adds `estimateScope` for v3) | | | | |
| `S/Connection.java` | | E1 (`error()` gets the client and emits `next`, `retryAfterMs`) | E3a (`respond`: `queue` header) | E3b (`run`: grace, `shutdownNow`; `respond`: `cancelled` details; the bounded outbound queue; parallel dispatch for v3) | | | |
| `S/RequestMonitor.java` | | | E3a (queue, lane and lane-note carriers, `addCancelHook`) | E3b (wait registration, `cancel()` override) | | | |
| `S/Requests.java` | | | E3a (generic `Preflight` checks) | | | | |
| `S/Caller.java` | | | | E3b | | | |
| **`S/Waits.java`** | | | | E3b | E3c (A25: the `Waits.lock(ReentrantLock, long, AtomicInteger)` overload and `contended`, for the waiter caps) | | |
| `S/Access.java` | | | E2 (A13: `Seals.requireNotSealed` in the writable-command check) | E3b | E3c (project pin instead of the whole-command project lock) | | |
| `S/ProgramEntry.java` | | | | E3b (waiters, `abandoned`) | E3c (refcount users, deferred disposal) | E9 (the decompiler gate at `borrowDecompiler`) | E11 |
| `S/Overlay.java` | | | | | | E9 (the decompiler gate at `borrowDecompiler`) | E10 |
| `S/OverlayCommands.java` | | | E2 (A13: `ProjectFork.markPromote` and `clearPromote` around the promote reply) | E3b (lock site) | E4 (`loadOverlay` extracted, overlay open from the stored file) | | E10 |
| `S/ProjectCommands.java` | | E1 (the call sites of `ProjectEntry.info(client)` at `:92`, `:395`) | E2 (`openProject` `format`, the `sealed` refusal) | E3b (`leaveProject`, the `makeWritable` wait taken out of the registry monitor) | E3c | | |
| `S/ProgramCommands.java` | | | E2 (`openWritable` gate, `sealed`, `upgradeBackup`) | E3b (`releaseUse` for owners and writers, bounded; `closeEntry`) | E3c (the plain-reader leave: the fast path and the deferred disposal, D63b) | | |
| **`S/ProjectRegistry.java`** | | | | | E3c | | |
| `S/UpgradeCache.java` | | E1 (`currentDbVersion` moved to `DbVersions`) | E2 (`readStored`, `prepare_upgrade` single flight) | | | | |
| `S/EditCommands.java` | | E1 (`withLastEditor`, `rk`) | E2 (`save` stamp) | | | | |
| `S/ForkCommands.java`, `S/ProjectFork.java` | | E2a (the `.gpr`-last order, the intent, `rk`, the sidecar `state`) | E2 (purpose, open, verify, cost, warnings, sidecar fields, `view`, `promote` marker; A26, after the land: the fix package F1 made the sidecar writes of `setPromote` and the rollback of `publish` retry) | | | | |
| **`S/ForkSweeper.java`**, **`S/ForkIntent.java`** | | E2a | E2 (A13: `ForkSweeper`, the process start-time check against pid reuse) | | | | |
| **`S/ProjectFormat.java`**, **`S/ProjectBackup.java`**, **`S/Seals.java`** | | | E2 | | | | |
| `S/ProjectEntry.java` | | E1 (`info(Client)`: the signature only, same value) | E2 (`format` for v3) | | E3c (state machine fields) | | |
| **`S/DbVersions.java`** | | E1 (`program()`, `dataTypes()` returning `null`) | E2 (`dataTypes()`) | | | | |
| `S/Operations.java`, `S/Journal.java`, `S/Client.java`, `S/SessionException.java`, **`S/Identity.java`**, **`S/Settings.java`**, **`S/Preflight.java`**, **`S/Hooks.java`** | | E1 (`SessionException`: the new codes, the busy-details and the bad-request-details helpers; `Hooks.Admission`, inert) | | | | | |
| **`S/Guarded.java`** | | | | | | E9 (A37: E9 creates it; E1 left no `Guarded` seam: the restart loop, the backoff, the per-thread `beat` and `states`, the emergency reserve, the test fault `inject`) | |
| **`S/Advertised.java`** | | E1 (capability, limit and policy names declared up front) **then** E2a (adds the capability name `forkAtomic`, A4) | E2 (A13: the capability name `seal`, inserted before `forkAtomic`, A9) | | | E9 (A35: the capability name `admission` after `forkAtomic`; the limit names `minXmxMb` to `decompilerNegativeS` after `maxRunningPerKey`) | |
| `S/HeadlessSession.java` | | E1 (endpoint and `ready`, `-set`) | E2 **then** E3a (A13, E2: the self-check of `DbVersions.dataTypes()` at `:762`, 5 lines; E3a: the `maxLong` and `maintSlots` defaults at `:133-134` and the usage text at `:78-79`; the option parser stays as it is) | | | E5 **then** E9 (E5: the watchdog and `testHooks`; E9: the governor start and the process job) | |
| `S/HydraInfo.java` | | E1 (protocol constants) | | | | R1 (version) | |
| `S/ScriptCommands.java` | | | | | E4 | E7 (the routing to a worker, D64) | |
| **`S/PrivateInstance.java`** | | | | | E4 | | |
| **`S/Health.java`** | | | | | | E5 **then** E9 (A34: `state` is `degraded` while `Governor.degraded()`; `debug_stall` `what:"thread"` plants one fault in a guarded thread, behind the test hooks) | |
| **`S/Watchdog.java`** | | | | | | E5 | |
| `S/QueryCommands.java` | | | | | | E9 (A36: the circuit breaker before the borrow in `decompile`, the error `decompiler_failed{function, entry, reason, retryable, negativeCache}` for protocol 3) | |
| **`S/Governor.java`**, **`S/Budgets.java`**, **`S/DecompilerGate.java`**, **`S/ProcessJob.java`** | | | | | | E9 (`ProcessJob`: the daemon's own Job Object, D60) | |
| **`S/ScriptWorker.java`** | | | | | | E7 | |
| **`S/ReplicaPool.java`** | | | | | | | E11 |
| `/Ghidra/Framework/DB/src/main/java/db/buffers/LocalManagedBufferFile.java` | | E8 | | | | | E12 |
| `/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/db/VersionedDatabase.java`, **`/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/db/VersionFileCheck.java`** | | E8 | | | | | |
| `/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/local/LocalDatabaseItem.java` | | E8 (the private-database open path, so that repair-on-open reaches forks, A3; revision 8.2, A14, the follow-up recorded after the W2 land: the versioned branch uses the read-only constructor and read-only items never repair, no header read at construction; and the reopen when another opener quarantined the newest version first, commit `862f134874`, found by the R-V1 verification) | | | | | |
| `/NOTICE-HYDRA` | | E8 (the three patched core files and the one added class, A3) | | | | R1 | |
| `support/ghidra_session.py` | | P1a (range, `engine` pass-through) | | | P1b **then** E3c (P1b: deadline, `LaunchError`, registry; the caller-job detection and the breakaway-then-WMI spawn of D65; the JVM flag `--enable-native-access` of D60; the `maxLong` comment `:425-426`; no Job Object; E3c, A25: the module-level PE32 class and the lock around the Toolhelp `argtypes`; note, A29: the fix package R-V3 sets the Toolhelp signatures once inside the locked `_pe32_class()`, after P1b and E3c) | | |
| `examples/daemon_tests.py` | E0 | | | E3b (A24: `t_shared_stress` connects at protocol 2 through `c.connect`, because the waiter cap of 3.5 refuses eight protocol 3 writers; note, A30: the fix package R-V3 adds the `Skipped` status, the SKIP tally and `Ctx.release()`) | | | |
| `examples/characterization_tests.py`, **`examples/dt_baseline.py`**, `examples/characterization/v3/` (created by E0 as an empty directory with the loader) | E0 | | | | | | |
| **`examples/characterization/v3/e3a-busy.json`** (E3a's golden; A31) | | | E3a (recorded) | | E4 (re-recorded in `48d3da27b9`: the reply keys `isolation`, `lane`, `attemptedChanges`, `attemptedChangesCount`) | | |
| `examples/characterization/clients.json`, `examples/characterization/edits.json`, `examples/characterization/fork_refresh.json`, `examples/characterization/import_script.json`, `examples/characterization/overlays.json`, `examples/characterization/readonly.json`, `examples/characterization/session.json` | E0 (the seven v2 goldens; `fork_refresh.json` and `overlays.json` were re-recorded once, in `f47ff15934`, to mask the copied project's total size, E0; **amendment A1, revision 7, D62: six goldens are re-recorded once more to mask the scheduler `slots`**; no later package edits them, E3a included) | | | | | | |
| **`examples/oracle.py`**, **`examples/chaos_lib.py`** | X0 | | | | | | |
| **`examples/conc/`** | X0 | | E2 (A14: the red-table base script only, `mkbase.py`: the red-table base is built as a disposable fork because the E2 upgrade gate refuses a canonical copy; commit `683fd092ca`) | | | | |
| **`examples/check_ownership.py`** | E0 (revision 8.2, A12, amendment A1 of revision 7, commit `6fccf3c65c`: `python -I` works and the Hydralysis root documents resolve) | E1 (its first commit: the package ids read from the wave plan, the `<id>-` golden prefix, the frozen files; section 8, rule 4) | | | | | |
| `examples/contract_tests.py` | | E1 (the protocol and first-`hello` tests) | E2 (A13: `dbVersions.dataTypes` may be a positive integer, and `seal` in the capability order) | | | | |
| **`examples/client_compat_tests.py`**, **`examples/stock/ghidra_session_1_0_0.py`** | | P1a | E3a (A12: no edit is planned; both files name a launch value (`maintSlots` as a passed `-set` flag, the comment `CPU/4` of the stock client's own default) and the proof demands a lane-package owner of every frozen file that names a lane default; the stock copy stays byte-identical unless D40 forces a comment) | | | | |
| `examples/char_e1.py`, `examples/characterization/v3/e1-hello.json`, `examples/characterization/v3/e1-expect.json`, `examples/characterization/v3/e1-require-expect.json`, `examples/characterization/v3/e1-rk.json` | | E1 (revision 8.2, after the W2 land: A13, the `dbVersions` assertions of `char_e1.py` and the goldens it records follow `DbVersions.dataTypes()` once it is read; A12, amendment A1: `e1-hello.json` is re-recorded once with `"slots": "<masked>"`, which makes the 4-line scheduler mask that another branch adds to `head()` of `char_e1.py` redundant) | E3a (A23: the 9-line scheduler mask in `head()` of `char_e1.py`, added after the W1 cell) | | | | |
| **`examples/soak_tests.py`**, **`examples/chaos_tests.py`** | | | | | | E6 | |
| **`format-matrix.json`**, **`examples/format_gate.py`**, **`examples/make_legacy_fixture.py`**, **`examples/vectors/canonical-manifest.json`**, **`examples/fixtures/legacy-12.1.4/`** | | | E2 | | | | |
| `README.md`, `ARCHITECTURE.md` (the module's) | R0 | | | | | R1 | |
| `/README.md`, `/CHANGELOG.md` | R0 | | | | | R1 | |
| `/.github/CONTRIBUTING.md`, `/.github/SECURITY.md`, **`/.github/workflows/upstream-sync.yml`**, **`/.github/hydra-touched-files.txt`** | | | | | | Z15 | |
| **`/.github/scripts/upstream-sync-report.sh`**, **`/.github/scripts/test-upstream-sync-report.sh`**, **`/.github/scripts/check-archive-notices.sh`**, **`/.github/scripts/test-check-archive-notices.sh`** | | | | | | Z15 (A11: the guard must be runnable and testable locally, and the Tests line 'release archives contain LICENSE, NOTICE and NOTICE-HYDRA' needs a test that builds the client zip) | |

**Hydralysis (`src/hydralysis`, `tests/`, `tools/`, and the repository-root documents)**

| File | W0 | W1 | W2 | W3 | W4 | W5 | W6 | W7 |
|---|---|---|---|---|---|---|---|---|
| `backends.py` | Y0a | | Z5 (A16: `ensure()` waits up to 30 s for `.backend.lock`, honours `cancelled()` and re-reads `inspect(settings)` after taking the lock; 12 lines, `ensure()` only) | | | | | |
| **`durable.py`** | Y0a | | | | | | | |
| `tests/test_durable.py` | Y0a | Y0e (**the ratchet table**: the six rows of the three writers Y0e moves and the three count assertions, 8.2; the two-process and large-log tests had landed in the W0 follow-up `2bf90c7`) | Y2 (the ratchet allow-list row of `_start_saver` leaves with the function, D61) | Z3 (A15: two FOLLOW_UP rows of the frozen write-site gate for `environment.py`) | | | | |
| `tests/test_durable.py` (**second step of W1, after Y0e**) | | Y1 (the two `save_overlay` rows and the counts, in the commit that deletes the function, 8.2) | | | | | | |
| `tests/test_address_maps.py` | Y0a (one line: drop the stale seal of a hand-edited record; commit `c78be27`) | | | | | | | |
| `tests/test_query.py` | Y0a (one line, the same) | Y1 (`status show=changes`) | Y2 (`stop`, `show=lineage`; the `_start_saver` patch of the fixture removed, D61) | Y3 (rebase, `stale_view`) | | | Y4a (lane hint, `wait` on every call of the attempt, the pool entry in `_ask`, `stop` over the entries; the release literals `:285-296` derived from the fake) | |
| `hydra.py` | Y0b | Y0e (`write_daemon_config` through `durable.atomic_write`) | Y2 (the launch configuration: `maxLong`, `maxQuick` from the expected number of agents; the `saver` comment of `Engine`, D61) | | | | Y4a (capabilities, the pin bump by `tools/bump_hydra.py`, `Supervisor`, the helper, the pool, the leave gate) | |
| `tests/test_client.py` | Y0b | | | | | | | |
| `tests/fakehydra.py` | Y0b | | Y2 (fork purposes) | | | | Y4a (the v3 fake, the E2 surface for Y4d's tests, the opt-in connection scope; the release constant is edited by the bump script, 5) | |
| `mcp.py` | Y0c | | | Z3 (the launch banner) | | | | |
| `tests/test_mcp_transport.py` | Y0c | | | | | | | |
| `api.py` | Y0d | | Y2 (the handler registry that replaces the Y0d stubs, 8, with the capability names `views`, `publish`, `environment`, `evidenceBundle`; the `OPTION_BAGS` lines for `options.as` and `options.op=remove`, help only, D59, OD8) | Z3 (A15: the `backend status` branch sends status through `dispatch("environment", ...)`, about 15 lines, so that status starts no JVM; 8.3 row 2) | Y5 (A18: `ghidra_run` `options.as`) | | | |
| `workflow_help.py` | Y0d | | | | | | | |
| `tests/test_contracts.py` | Y0d | | Y2 (the four stub tests of `NotAvailableCarriers`, `:111-157`, rewritten against the handler registry, 8; one assertion that `backend help` lists `options.as`, D59) | | | | | |
| **`cli.py`** | | Y0e (`backend --action doctor` and `--action backups`, `--options` and `--options-file`, passed through to the dispatcher) | | | | | | |
| **`tests/test_cli.py`** | | Y0e | Y2 (its two stub tests rewritten against the handler registry, 8) | | | | | |
| **`runtime_actions.py`**, **`runtime_agents.py`**, **`runtime_capture.py`**, **`runtime_events.py`**, **`runtime_exports.py`**, **`runtime_snapshot.py`** | | | | | | | Z10 (A21: the worker is split into agent templates, event log, action handlers and lifecycle, as the Z10 text requires) | |
| `runtime.py`, `runtime_worker.py` | | Y0e (`_write` through `durable.write_sealed`; the readers unseal and fall back to the `.bak`) | | | | | Z10 | Z12 |
| `workcopy.py` | Y0a (`_save_store`, `load_store`) | Y1 (v3 store, `has_overlays` and `expected_state` through `durable.exists`, `require_seal=True`) | Y2 (shared base, per-view connection, per-view lock; `_start_saver`, the saver state keys and the `saved` flag removed, D61) | Y3 (publish, rebase) | Y5 (lazy view routing, eviction) | | | |
| `workcopy_saver.py` | | | Y2 (**deleted**, D61) | | | | | |
| `locks.py`, **`tests/test_locks.py`** | | | Y2 (a typed `LockBusy`; `LaneLock` unchanged, D61) | | | | | |
| `config.example.json` | | | Y2 (`overlay_save_debounce_s` out; `generationKeep` and `viewIdleDeleteS` in) | | | | | |
| `targets.py`, `overlayjobs.py` | Y0a | | Y2 (stable key, `CURRENT.log` resolve, `adopt` derives `copied` and `imported` by observation; `overlayjobs.py` drops `overlay_save_debounce_s` from its settings keys, D61) | | | | | |
| `tests/test_overlayjobs.py` | | | Y2 (kind `commit`) | | | | | |
| `revisions.py`, `analysis.py`, **`annotations.py`**, `scripts/RusticQuery.java` | | Y1 (`analysis.py`: new kinds, and the legacy v1 writer `save_overlay` and its reader `load_overlays` are deleted, 8.2) | | | | | | |
| `tests/test_analysis.py` | | Y1 (the 15 `save_overlay` calls and the import, `:7`, `:111-204`: fixtures through `workcopy._save_store`, assertions retargeted, 8.2) | | | | | | |
| `tests/test_exporting.py` | | Y1 (`:94-98` appends an edit to a store and calls `_save_store`) | Y2 (header, resume refusal) | Z6 (the resume refusal if the snapshot at export start is built) | | | | |
| `tests/test_crossbuild.py` | | Y1 (store-shaped dict literals patched into `workcopy.load_store`, `:81`, `:205`, `:218`, `:253`) | | | | | | |
| `tests/test_revisions.py` | | Y1 (effect and field vocabulary) | | | | | | |
| `tests/test_query_script.py` | | Y1 (the RusticQuery structure guards, which the new outputs must keep passing) | | | | | | |
| `tests/test_engine_integration.py` | | Y1 (real-engine round trip, env-gated) | Y2 (additions; the `overlay_save_debounce_s` setting of its fixture removed, D61) | | | | | |
| **`tests/test_store_v3.py`**, **`tests/test_bundles.py`** | | Y1 | | | | | | |
| `tests/test_store_v3.py` (**after Y1**) | | | Y2 (A17: the fixture mentions `_start_saver`, which D61 deletes) | | Y5 (A18: the fixture follows the default view and `options.as`) | | | |
| `tests/support.py`, `tests/test_commit.py`, `tests/test_integrity.py` (**after Y2**) | | | | | Y5 (A18: fixtures follow the default view and `options.as`; `tests/support.py` was frozen, D31) | | | |
| `query.py` | | Y1 (`status show=changes`) | Y2 (`stop`, `show=lineage`) | Y3 | Y5 (the default view, `options.as`) | | Y4a (lane hint, `wait`, the pool entry in `_ask`, `forget(entry)`, `stop` over the entries and its report, 7.6) | |
| `exporting.py` | | | Y2 | Z6 (the snapshot at export start) | | | | |
| `export_worker.py` | | | | Z6 | | | | |
| **`lineage.py`**, **`commits.py`**, **`backups.py`** | | | Y2 | | | | Y4d | |
| **`tests/test_lineage.py`**, **`tests/test_commit.py`**, **`tests/test_backups.py`** | | | Y2 | | | | Y4d (the fault matrix re-run, the engine-written backup) | |
| **`tests/vectors/canonical-manifest.json`** | | | Y2 | | | | | |
| **`integrity.py`**, **`tests/test_integrity.py`** | | | Y2 | | | | | |
| **`views.py`**, **`tests/test_views.py`** | | | | Y3 | Y5 | | | |
| **`viewgov.py`**, **`tests/test_viewgov.py`** | | | | | Y5 | | | |
| **`doctor.py`**, **`tests/test_doctor.py`** | | | | | | | Y4b | |
| `userscripts.py`, **`tests/test_userscripts.py`** | | | | | Y5 (A18: `run(who=)`) | | Y4e | |
| **`tests/test_deadline.py`**, **`tests/test_supervisor.py`** | | | | | | | Y4a | |
| `tests/test_backends.py` | | | | | | | Y4a (the pinned release literals, `:21` and `:101`, derive from `hydra.RELEASE`, 5) | |
| `README.md` | Z13a (the wording pass, the GUI removal) | | Y2 (the sentence on the background save and `overlay_save_debounce_s`, the per-target lock sentence and the "Changes in 0.5.0" note, D61) | | Y5 (the sentence "Clients share the default view", D43, D59) | Z13b (numbers regenerated from the ledger) | Y4a (the one sentence that names the pinned release, edited by `tools/bump_hydra.py`, 5) | |
| `THIRD_PARTY.md` | Z13a (the wording pass, the GUI removal) | | | | | Z13b (numbers regenerated from the ledger) | Y4a (the one sentence that names the pinned release, edited by `tools/bump_hydra.py`, 5) | |
| `docs/upstream-setup.md` | | | | | | | Y4a (the pin sentence, edited by `tools/bump_hydra.py`, 5) | |
| `docs/golden-harness.md` | Z13a (one phrase: "parity with the Ghidra window" becomes `DecompileOptions.grabFromProgram`; the file stays a dated report) | | | | | | | |
| `skills/evidence/SKILL.md`, `skills/hooks/SKILL.md` | | | Z4 (A22: the front matter `name` equals the directory, X28) | | | | | |
| `skills/hydralysis/SKILL.md`, `skills/ghidra-project/SKILL.md` | Z13a (the wording pass; the contained-script sentences, the GUI sentences) | | Z4 (frontmatter names, the harness audit) | | Y5 (one paragraph each: pass a distinct `options.as` for each editing sub-agent, D59) | | | |
| **`docs/data/claims.json`**, **`tests/test_claims.py`** | Z13a | | | | | Z13b | | |
| **`tools/bump_hydra.py`**, **`tests/test_bump_hydra.py`** | | | | | | R1 | | |
| **`tests/test_concurrency.py`** | | Z1 | Y2 (flips the known-issue marker of the `_sync` test) | | | | | |
| **`benchmarks/mcp_latency.py`**, **`benchmarks/concurrency_bench.py`**, **`benchmarks/named_view_cost.py`**, **`benchmarks/bench_cold_start.py`**, **`benchmarks/bench_install.py`**, **`benchmarks/budgets.json`**, **`tests/test_output_size.py`** | | | | Z2 | | | | |
| **`environment.py`**, **`tests/test_environment.py`**, `config.py`, `paths.py` | | | | Z3 | | | | |
| **`tests/test_engine_nostock.py`**, **`tools/audit_harness.py`**, `docs/ci.md`, `.github/workflows/tests.yml` | | | Z4 | | | | | |
| **`tests/test_engine_prepare.py`**, **`tests/test_engine_scripts.py`**, **`docs/verification-prepare.md`** | | | Z5 | | | | | |
| **`tools/golden_classify.py`**, **`tests/test_golden_classify.py`**, **`docs/verification-golden.md`** | | | Z7 (A19: the test file of the classifier) | | | | | |
| **`tests/test_engine_export.py`**, `tools/verify_corpus.py` | | | | Z6 | | | | |
| **`tests/test_parity_surface.py`** | | | | Z8 | | | | |
| `tests/fixtures/verify_fixtures.py` | | | | Z8 (new check groups `listing`, `callgraph`, `namemap`) | | | Z10 (`break_continue`, `export_hook`, `capture`, `snapshot`) | Z11 (`scenario`) |
| `tests/fixtures/flow_fixture.c`, `tests/fixtures/build_fixtures.py` | | | | | | | Z10 (an exported function; `runtime_fixture.c` folded into `BUILDS`) | Z12 (a watch case) |
| `tests/fixtures/runtime_fixture.c` | | | | | | | Z10 | |
| `tests/fakefrida/` | | | | | | | Z10 | |
| **`tests/test_runtime_capture.py`**, **`tests/test_runtime_snapshot.py`** | | | | | | | Z10 | |
| `evidence.py`, **`evidence_bundle.py`**, `docs/upstream-runtime.md` | | | | | | | Z9 | |
| **`tests/test_evidence_model.py`**, **`tests/test_evidence_bundle.py`**, **`tests/test_evidence_parity.py`** | | | | | | | Z9 | |
| **`tools/scenarios/kotor_vfs_lookup.py`**, **`tests/test_runtime_scenario_fixture.py`** | | | | | | | | Z11 |
| **`tools/watch_conformance.py`**, **`tests/test_runtime_watch.py`**, **`tests/test_runtime_write.py`**, **`runtime_memory.py`**, **`tests/fakememory.py`** | | | | | | | | Z12 (A20: `runtime_memory.py` is a new mixin of `runtime_worker.RuntimeAgent`, `tests/fakememory.py` a shared helper of the two watch tests) |
| `docs/tool-mapping.md`, **`docs/data/tool-surfaces.json`**, `docs/verification.md`, **`tools/count_surfaces.py`**, **`tests/test_tool_mapping.py`** | | | | | | Z13b | | |
| **`CHANGELOG.md`**, **`.github/workflows/release.yml`**, **`docs/versioning.md`**, **`tests/test_release.py`** | | | | | | | Z14 | |

**Site (`F:/Projects/hydra-engine-site`, the website repository; it had no owner in revision 5)**

| File | W0 | W5 |
|---|---|---|
| `src/routes/index.tsx`, `src/routes/changelog.tsx`, `src/routes/integrations.tsx` | S1 (the wording of 8.3: `index.tsx:18`, `:108`, `:38`, `:48`; the GUI mentions) | S2 (the claims that a passed gate flips) |
| `src/docs/pages/projects.ts`, `src/docs/pages/scheduling.ts`, `src/docs/pages/architecture.ts`, `src/docs/pages/mcp-server.ts`, `src/docs/pages/core-concepts.ts`, `src/docs/pages/installation.ts`, `src/docs/pages/evidence-ledger.ts`, `src/docs/pages/quick-start.ts`, `src/docs/pages/clients.ts`, `src/docs/pages/api-reference.ts` | S1 | S2 (version constants through `tools/bump_hydra.py`, 5) |
| `src/lib/site.ts`, `src/lib/llms.ts`, `src/lib/seo.ts` | S1 | S2 (the release and protocol constants, edited by `tools/bump_hydra.py`) |
| `src/components/landing/Hydralysis.tsx`, `src/components/landing/HowItWorks.tsx` | S1 (panels labelled illustrative; unsourced figures removed) | S2 |
| `src/routes/embed/how-it-works.tsx` | S1 (the embed route of the HowItWorks panel: its notes repeat claim C3, A5) | S2 |

Per wave the disjointness reads off the columns. Hydra: W0 = {E0 | X0 | R0}; W1 = {P1a, then E1 | E8 | E2a (after E1 on `S/Advertised.java` only)}; W2 =
{E2 | E3a}; W3 = {E3b}; W4 = {E3c | E4 | P1b}; W5 = {E5 then E9 | E6 | E7 | R1 | Z15}; W8 = {E10 | E11 | E12}.
Hydralysis: W0 = {Y0a | Y0b | Y0c | Y0d | Z13a}; W1 = {Y0e | Y1 | Z1} (Y1 after Y0e on the second
`tests/test_durable.py` row only, and after Z1); W2 = {Y2 | Z4 | Z5 | Z7}; W3 = {Y3 | Z2 | Z3 | Z6 | Z8}; W4 = {Y5};
W5 = {Z13b}, with R1's `tools/bump_hydra.py`; W6 = {Y4a | Y4b | Y4d | Y4e | Z9 | Z10 | Z14} (Y4b, Y4d and Z14 after Y4a, for the
registry the doctor lists, for the fake daemon Y4d's tests run on and for the pin Z14 documents; an in-wave dependency, not a file); W7 = {Z11 | Z12}. Site:
W0 = {S1}, W5 = {S2}. Across waves a file may change hands only in the order the columns show, and a package depends
on the packages whose files it builds on (the lists below).

### 8.2 Ownership of what the first reviews found unowned

Reviews of the W0 packages (Y0a to Y0d, E0) found files and behaviours that the matrix of revision 2
gave to nobody. Each now has one owner and one wave. Y0e is the package that carries the W0 follow-ups
no W0 package could take (the W0 packages are closed; Y0e's files are disjoint from Y1's in W1 except `tests/test_durable.py`, the one declared sequence).

| Gap found | Owner | Wave | Decision |
|---|---|---|---|
| `cli.py` had no owner: spec 7.1 says doctor is also a CLI command, and Y0d could not expose `backend` `doctor`, `backups` or `options` there | **Y0e** | W1 | `cli.py` passes `--action` and an `--options` JSON object through to the same dispatcher as the MCP tool; no later package edits it |
| `api.py`: Y0d's stubs (`ghidra_run` `options.isolation`/`readonly`, `job` `options`, `backend` `doctor`, `backups`) need a replacement in the waves where Y2, Y4b, Y4d, Y4e deliver their handlers, and the matrix gave `api.py` to Y2 and Y4b only (two packages in W6 would have needed it) | **Y2** | W2 | Y2 builds a **handler registry** once (8, `api.HANDLER_MODULES`): `backend backups` goes to `backups.py` (Y2, W2); `job` `options` (`kind`, `cid`) to `commits.py` (Y2, W2); `backend doctor` to `doctor.py` (Y4b, W6); `ghidra_run` `options` to `userscripts.py` (Y4e, W6). `api.py` has a cell in W0 (Y0d) and W2 (Y2) and none after; until a handler's module exists the answer stays `not_available` |
| `tests/test_contracts.py` (`NotAvailableCarriers`, `:105-164`) and `tests/test_cli.py` (Y0e's two stub tests) assert `not_available` for `doctor`, `backups`, `job` `options` and `ghidra_run` `options` through the real dispatcher with nothing patched, so Y2 (backups, job options), Y4b (doctor) and Y4e (isolation) each make one false while rule 3 froze both files (revision 5, BLOCKING 1) | **Y2** | W2 | each stub test patches `api.HANDLER_MODULES` with a module that never exists, once, in W2; 8.1 gives both files a W2 cell for Y2; Y4b and Y4e edit neither; the detector of `prove_disjoint_rev5.py` scans every frozen test for `not_available` |
| `tests/test_backends.py` (`:21`, `:101`), `tests/test_query.py` (`:285-296`) and `tests/fakehydra.py` (`:28`) carry the pinned release; `hydra.py` builds the message the first asserts from `RELEASE`; the text said Y4a "owns the files the script edits" and named none (revision 5, BLOCKING 2) | **Y4a** | W6 | the two tests derive the release from `hydra.RELEASE` and the fake's own constant, once, in W6 (`tests/test_backends.py` gets a W6 cell; the other two already had one); `tools/bump_hydra.py` (R1) edits exactly `hydra.py`, `tests/fakehydra.py` and the three pin statements of `README.md`, `THIRD_PARTY.md` and `docs/upstream-setup.md` (5), and `tests/test_bump_hydra.py` asserts it edits nothing else |
| `tests/fakehydra.py` must emulate what Y4d's tests need (`format`, `backup_required`, `fork_project purpose:"backup"` with `writer:"engine"`) and a connection-scoped project and program context (N5, N9) | **Y4a** | W6 | Y4a adds the E2 surface and the connection scope to the fake (the file is Y4a's in W6); the scope is **opt-in** (`Daemon(connection_scoped=True)`, default off), so every frozen test that uses the fake keeps the single-context fake, and Y1 keeps the signatures that frozen tests call (`workcopy._apply(settings, engine, program, records, state, timeout)` and `workcopy._replayable(settings, target, edit)`, `tests/test_client.py:144-170`, `tests/test_archive_import.py:33-38`; its acceptance runs them unchanged); Y4d merges after Y4a |
| the seven v2 goldens `examples/characterization/*.json` had no E0 row, so `check_ownership --package E0` exited 1 on `fork_refresh.json` and `overlays.json` (E0's review of `f47ff15934`) | **E0** | W0 | a row of 8.1 lists the seven files; the re-record of two of them masks the copied project's total size (E0, below); they must stay `identical`, and no later package edits them |
| `workcopy.has_overlays` and `workcopy.expected_state` pre-check the **main** store path (`_store_path(...).is_file()`) and so bypass the `.bak` fallback: with the main file deleted and `.bak` intact, `load_store` answers but these two say "no overlays" | **Y1** | W1 | both use `durable.exists` (a store exists if the main file or its `.bak` does) and call `load_store`; test: delete the main store, keep the `.bak`, both report the overlays |
| A v3 store is read with `require_seal=True`: with the default (`False`) a hand-stripped seal loads as a "pre-seal" v2 record and gives no tamper or truncation signal | **Y1** | W1 | `load_store` reads a version-3 file with `require_seal=True` (a file without a seal is `store_corrupt`); a version-1 or -2 file is still accepted unsealed once and sealed by its first write |
| `AppendLog` read whole logs through `localio.read_bytes` (32 MiB budget) and checked the tail on the first append of a process | (W0 follow-up) | W0 | **done** in `2bf90c7` (streamed reads, a bounded tail window, the every-acquisition check with the size comparison, the two-process tests) and verified, not redone, by Y0e (`8e696e2`); what remains is Y2's: the strictness each caller needs (`last()` is tail-only by default) and a rotation or checkpoint policy (4.1, 6) |
| `EngineError` capped every list recursively, including `next.args` | (W0 follow-up) | W0 | **done** in `33cb5ee` and `5018367`: `next` and `retryAfterMs` are never capped, the lists inside `queue` keep 64 entries, the other lists 5 plus `more` (7.6); verified by Y0e |
| `tests/test_client.py` put the `EngineRetryPolicy` class after `if __name__ == "__main__"` | (W0 follow-up) | W0 | **done** in `33cb5ee`: the guard is at the end of the file; verified by Y0e |
| `examples/check_ownership.py` (E0) cannot see the package ids `Y0e` and `Y4e` (its pattern `[EPYR]\d+[a-d]?`, `:57`, `:145`), accepts a frozen file when a package text names it, and resolves the Hydralysis table's root documents under `src/hydralysis/` | **E1** | W1 | the ids are read from the wave plan table, the golden prefix `<id>-` is accepted, a frozen file is refused (section 8, rule 4), `README.md`, `THIRD_PARTY.md` and `docs/...` rows of the Hydralysis table resolve to the repository root; E1's first commit, with a unit check that every id of the plan parses; the matrix has the row. Confirmed by the fourth review: the checker as committed reports "22 packages" and, with the pattern widened to `[a-e]`, "24 packages, 0 violations" |
| Y0a edited `tests/test_address_maps.py` and `tests/test_query.py`, which it did not own | **Y0a** | W0 | amended: the two files are Y0a's explicitly in 8.1 (a package that changes a stored format owns the tests that hand-write it, 8) |
| `MAX_OUTSTANDING` per lane or global (Y0c) | decision | | **per lane** (7.6): 8 for the engine pool and 8 for the fast pool, total up to 16; the `busy` answer carries the retry hint as text **and** as `structuredContent.retryAfterMs` (`49d5bb6`) |
| Where `catalog:{epoch, hash}` is reported (Y0d), and which epoch | decision (what shipped, `1584f6e`) | | `backend action=status`, `backend help` and `backend inspect`, and the MCP `initialize` result under `_meta["hydralysis/catalog"]`; not `ghidra_query action=status`, not the CLI; the epoch number is 2 (7.7) |
| `canonical()` seals an unpaired surrogate (`surrogatepass`) while 3.4 says it is refused | decision | | tolerated in **seals and bundles** (Python-only forms; 3.4, 4.1 item 2), refused in **manifests** (cross-language); 3.4 says so |
| `*.tmp` files of killed writers are never swept | **Y4b** | W6 | the doctor reports and offers the removal; nothing deletes automatically (D28) |

**Record-bearing writers that stay outside `durable` after Y0a** (the AST write gate in
`tests/test_durable.py` at `589432e` freezes them as a ratchet; a **new** write site fails the gate and
its author adds it to this table):

| Writer | What it writes | Owner | Wave | How |
|---|---|---|---|---|
| `analysis.save_overlay` | the legacy v1 overlay store (no production caller; tests only) | Y1 | W1 | deleted **together with its two rows and the counts in `tests/test_durable.py`**, which is the second step of W1, after Y0e has removed its own six rows (after Y0e the table has 2 record rows, 24 keys and 26 call sites; after Y1, 0, 22 and 24), and with `load_overlays`, whose only caller it was (Y1 searches before deleting; `load_store` reads a version-1 file itself, `workcopy.py:59` at 589432e); the 15 calls of `tests/test_analysis.py` (`:111-204`, import `:7`) write their fixtures through `workcopy._save_store`, with the assertions retargeted as below |
| `hydra.write_daemon_config` | the daemon's `config.json` | Y0e | W1 | `durable.atomic_write` (fsync and write-through replace) **without a seal**: the engine's launcher reads this file and must see the plain JSON it expects (`8e696e2`) |
| `runtime._write` | runtime session state | Y0e | W1 | `durable.write_sealed` (sealed; its readers unseal, accept pre-seal files and fall back to the `.bak`) (`8e696e2`) |
| `runtime_worker._write` | runtime worker state | Y0e | W1 | `durable.write_sealed` (the same) (`8e696e2`) |
| 22 artifact keys (24 write sites: logs, exports, staged script copies, download and install renames) and 11 non-record keys in the four owned files | logs, exports, copies | none | | not records; frozen by the ratchet |

**What the deletion of `analysis.save_overlay` does to the tests (Y1, W1).** Nine of the ten tests of
`DurableOverlays` in `tests/test_analysis.py` go through the legacy writer or its reader. They are not
deleted: each assertion moves to the production function that has the same rule, with the fixture written
through `workcopy._save_store` and read through `workcopy.load_store` (`workcopy.py:50-78`; every `workcopy.py` line of this paragraph is at 589432e). The **byte
cap** (`overlay history would exceed 20 MiB; existing history preserved`, the old history and no `.tmp`
left) is asserted against `_save_store`, with the patch target now `hydralysis.workcopy.MAX_HISTORY_BYTES`
(`workcopy` imports the name, `:28`). The **count cap** (4096 records, the `scale` test) is asserted against
`load_store` (`:62-63`: a history written with 4097 edits is refused) and against `workcopy.edit` (`:545-546`, with
the fake engine of `tests/fakehydra.py`: the 4097th edit is refused with the same message). **Another
build's store** and **duplicate ids** are asserted against `load_store` (`:59-60`, `:68-69`); a **bad target
key** and a **missing address** against `_overlay_path` (`analysis.py:279`) and `_edit`; the **order** of
corrections and the **batch snapshot** as a `_save_store` and `load_store` round trip. `_save_store`
itself enforces only the byte cap: the count cap and the duplicate-id rule live in `load_store` and `edit`.
Two assertions exist **only** in `save_overlay` and are dropped with it, on purpose and recorded here:
appending the same id twice is one record, and a changed edit under an existing id is refused; production
`edit()` mints a new id for every edit (`workcopy.py:539`), so no production path has either rule. The cap
and validation coverage therefore cannot fall without anyone noticing: Y1's review checks the ten tests
against this paragraph.

### 8.3 Revision 6: the Z packages, the eight ownership conflicts and the claims

**The Z packages.** `D:/Projects/Hydra/wt/rre-trace/docs/pr6-traceability.md` (at `627b5b5`) turned the 109 asks of the
two PR #6 review comments into 15 packages Z1-Z15 for the 49 asks that had none. All fifteen are packages of this
file now (their blocks are in the wave sections, their files in 8.1):

| Package | Wave | Repo | What | Depends on |
|---|---|---|---|---|
| Z1 | W1 | Hydralysis | concurrency regression guard, with the failing-by-design `_sync` and single-base tests | none, merges before Y1 |
| Z2 | W3 (the audit said W4) | Hydralysis | measurement harness; the named-view cost and publish latency | Y2, Y1 |
| Z3 | W3 | Hydralysis | environment, configuration, an early doctor slice | Y2, Y0c |
| Z4 | W2 | Hydralysis | no-stock end-to-end proof and harness audit | Z13a |
| Z5 | W2 | Hydralysis | real-engine matrix for prepare, adopt, scripts | Y2 |
| Z6 | W3 | Hydralysis | corpus export parity, resume, snapshot | Y2 |
| Z7 | W2 | Hydralysis | 12.1.4 to 12.3 golden classification, **reported never gated** | none |
| Z8 | W3 | Hydralysis | surface parity tests | none |
| Z9 | W6 | Hydralysis | evidence v2 and bundles | Y1, Y2 |
| Z10 | W6 | Hydralysis | runtime evidence, capture, snapshot, export-name hooks, on the fixtures | Y0e, Z8, Z9 |
| Z11 | W7 | Hydralysis | runtime scenario end to end, fixture-first | Z9, Z10 |
| Z12 | W7 | Hydralysis | memory write and watchpoints, **fixture-only, gated by the owner's decisions** | Z10 |
| Z13 | W0 (a) and W5 (b) | Hydralysis | documentation, surfaces, the claims ledger and its test | Z13a; Z13b: Z13a, Z4 |
| Z14 | W6 | Hydralysis | Hydralysis release process | R1, Y4a, Z13b |
| Z15 | W5 | Hydra | fork maintenance and policy, the patched-core-file guard | E8 |

Order (owner decision): runtime evidence and coverage (Z9, Z10, Z11) first; memory write and watchpoints (Z12) later
and only on fixtures.

**The eight conflicts of the audit (its 5.4) and the two conditional ones, resolved.** Revision 5's rule is that a
file has one owner per wave and a package that makes a frozen assertion false owns the test.

| # | Conflict | Resolution |
|---|---|---|
| 1 | Z3 `init` in `cli.py` (Y0e's, "no later package edits it") | no `init` in `cli.py`; Z3 ships `python -m hydralysis.environment init`; Y0e's `backend --action doctor` stays the CLI surface |
| 2 | Z3 `backend status` with `start=False` in `api.py` (opened once, by Y2) | Z3 registers an `environment` handler through Y2's `api.HANDLER_MODULES`; Y2 adds the capability name `environment` in W2 |
| 3 | Z5 tree-hash adopt test in `tests/test_engine_integration.py` (Y1, Y2) | the test lives in Z5's new `tests/test_engine_prepare.py`; the Y1/Y2 file is not edited |
| 4 | Z5 `targets.py`: `adopt` derives `copied` and `imported` by observation (Y2's file in W2) | the edit is Y2's (8.1 cell); Z5 asserts it in its own file |
| 5 | Z8 `tests/fixtures/verify_fixtures.py` (an existing file, frozen, no row) | an 8.1 row hands it over: Z8 (W3), then Z10 (W6), then Z11 (W7); a second harness file would duplicate `Running`, `target` and `McpClient` |
| 6 | Z9 bundle CLI and `api.py` | the `evidenceBundle` capability name in Y2's registry; Z9's `evidence_bundle.py` has its own `__main__`; neither `cli.py` nor `api.py` is edited again |
| 7 | Z10 fixture sources (`flow_fixture.c`, `runtime_fixture.c`, `build_fixtures.py`) | 8.1 rows: Z10 (W6) extends, never replaces; `flow_fixture.c` and `build_fixtures.py` pass to Z12 (W7) |
| 8 | Z10 `tests/fakefrida/` | an 8.1 row: Z10 (W6) |
| c1 | Z6 snapshot at export start changes the resume refusal asserted by the exporting test | Z6 owns that file in W3 (Y1 W1, Y2 W2, Z6 W3: a valid hand-over) |
| c2 | Z7 dropping `maxBadData` from the options hash would edit the frozen `tools/golden.py` | the other option: capture with the option held equal; no frozen file is edited |
| collision | Z5 and Z7 both named `docs/verification-import-export.md` | Z5 `docs/verification-prepare.md`, Z7 `docs/verification-golden.md` |

New rows the audit did not foresee: the Hydralysis table gains W4, W6 and W7 columns (W4: Y5; W6: Y4a, Z9, Z10,
Z14; W7: Z11, Z12); Z15's root-level `.github` rows are disjoint from R1's; the **site repository** gets its own table
and owners S1 (W0) and S2 (W5); `docs/data/claims.json` and `tests/test_claims.py` are Z13a's (W0) and Z13b's (W5).

**The claims audit as packages R0, S1, Z13a (W0) and S2, Z13b (W5).** Wording until the flipping test is green;
"flips" is the package whose test, red today, turns the sentence true. IDs are those of
`D:/Projects/Hydra/_logs/claims-audit/` (11 contradicted C, 14 unsupported or stale U; 5 future F and 14 supported S
claims need no change or wait for a package). The rule: nothing gets stronger without its test.

| Claim | True-today wording (replaces) | Flips when |
|---|---|---|
| C1 "writes never collide" (`index.tsx:18`, `:108`, `projects.ts:7`, `changelog.tsx:35`) | "Writes are serialized and never corrupt a program in the tests listed; collisions are only detected when you pass `expect`." Tagline: "Open in place, import once, write through the mode that fits." | Y5 (a view per agent), Y3 (`before` checks at publish), Z1 `SameAddressRace`, the chaos gate 9.17 |
| C2 "a contained script cannot change what others see" (`projects.ts:149`, README) | "A contained script's changes are rolled back and never saved; while it runs, other clients can see them. RusticQuery's read actions do not modify the program." | E4 (`script_shared_visibility` flips), Y4e (`ghidra_run` never `shared`) |
| C3 "analysis never slows questions" (`index.tsx:38`, `:48`, `HowItWorks.tsx`, README) | "Native commands stay in the quick lane while imports and analyses run in the long lane. Questions asked through Hydralysis are scripts and share the long lane; a full long lane delays them (measured up to about 8 s). Readers of the program being analysed wait for its lock." | E3a (lane defaults, caps), Y2 (launch configuration) on hydra.3; E3c (`analyzing`, sealed generations) on hydra.4; 9.13 |
| C4 "different programs and projects never wait on each other" (`scheduling.ts:36`) | "Each program and project has its own lock. They share the daemon's lane slots and import gate, so enough long work anywhere can delay a save or fork elsewhere." | E3a maint lane and caps, E3c (no wait inside a monitor, waiter caps); `s5`, `s13` |
| C5 "cleaned up at once", "clean release" (`architecture.ts:85`, `:95`, `clients.ts:88`) | "A disconnected client's requests are cancelled and its uncommitted changes rolled back when its running request ends. A request blocked on a lock, or a script that ignores cancel, keeps its place until the lock frees or the script ends." | E3b (`dead_client_lock_wait`, `owner_leave_bounded`) and E3c (`reader_leave_no_freeze`); non-cooperative scripts stay a limit until E7's gate (9.14) passes |
| C6 "a queued import waits until it runs or is cancelled" (`scheduling.ts:48`) | "An import waits in the import queue; at the front it still needs a long slot and fails `busy` after `wait` (10 s default)." | E3a import wait fix (`import_wait`) |
| C7 "cancel: one of your requests, running or queued" (`scheduling.ts:68`) | "cancel stops requests waiting for a slot and cooperative scripts; a request waiting for a program lock stays until its `wait` runs out." | E3b (`cancel_while_waiting`) |
| C8 "one daemon per user" (`architecture.ts:35`) | "One daemon per state directory and instance; Hydralysis uses its own instance and data root." | no change now (OD3) |
| C9 "about 7 ms" through Hydralysis (`Hydralysis.tsx`, `HowItWorks.tsx`) | "native decompile about 1 to 45 ms by function size; through Hydralysis about 25 ms on a small program and about 60 ms on KotOR (single runs)" | Z2 medians, or the quick-lane hint |
| C10 "20 tools in about 7.4 KB" (`mcp-server.ts:35`) | "20 tools in about 8 KB of schema (8,172 bytes as the catalog test counts them)", generated from `tool_table()` | Z13a/Z13b `test_claims` |
| C11 "two small fixes to Ghidra classes" (`architecture.ts:104`) | "three small fixes" today; "five" after E8 | E8 |
| U1 "any number of agents" (`index.tsx:39`, README) | "several agents on several projects (tested with up to 4 clients)" | 9.17: then "tested with 24 agents on 6 projects, 4 hours" |
| U2 "ten agents on one daemon, an agent that sends a hundred requests can't starve one that sends one" | "Waiting requests are admitted round-robin by connection; there was no cap on how many slots one connection ran" | E3a (V9) and 9.17 |
| U3 "serialized and never corrupt" (unconditional) | "no corruption was seen in the tests listed" | E8, 9.15, 9.17 |
| U4 "an unsaved change is replayed from the store, never lost" | "replayed from the store after a restart; the store is flushed and sealed; no power-loss test has been run; corrections are not committed back to the analysed project" | Y1, Y2, 9.15 (E12 for power loss) |
| U5 demo scenarios shown as real work | label the panels "illustrative", or replace them by a recorded PE session | a recorded run exists |
| U6 animation figures without a source (journal 1.9 ms, 12 functions 3 ms, 55 as seconds) | remove, or source each | S1 |
| U7 "10,849 functions decompiled" (showcase) | "8,616 internal / 8,966 total" or the owner's confirmed denominator | owner |
| U8 "your Ghidra scripts work unchanged" | "scripts that use the headless API run unchanged; GUI-only extensions do not apply" | |
| U9 heading "No lost updates" | "No lost updates, when you pass `expect`" | Y5, 9.17 |
| U10 "6.7-7.1 ms" without the size qualifier | "about 1 to 45 ms by function size (7 ms in the benchmark function)" | |
| U11 "the same question through stock analyzeHeadless 7.0-7.8 s" under the 12.3 machine | "(stock Ghidra 12.1.4)" | |
| U12 smaller items (a to e: parallel at the connection only; no commit-back yet; "the same saved state, not a byte check"; an orphaned shared writer keeps the project; the 1,971 changed KotOR functions) | the sentences of `D:/Projects/Hydra/_logs/claims-audit/` | |
| U13 stale versions (`site.ts:9`, `installation.ts:34-35`, `clients.ts:71`, `:79`, `mcp-server.ts:60`, `api-reference.ts:7`) | the current release and protocol | R1's `bump_hydra.py` (extended to the site) |
| U14 GUI mentions (`core-concepts.ts:54`, `projects.ts:25`, `installation.ts:54`; engine README lines 61, 170, 299; module README 193, 203, 692, 696; Hydralysis README 119-121, THIRD_PARTY.md:10) | "There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by Ghidra 12.2 or 12.1.4." Replace "a Ghidra window can read it" by "other processes can read it" | R0, S1, Z13a |

The five FUTURE claims stay future until their packages land: F1 per-agent views by default (Y5), F2 durable
commit-back and the second backup (Y2, E2), F3 supervision with auto-restart (E5, Y4a, with the journal), F4
quick-lane scripts and the maint lane (E3a), F5 runtime evidence (Z9-Z11), memory write and watch only on fixtures
(Z12).

### 8.4 Revision 7: ownership additions and what the proof checks

The review of revision 6 found files with no owner and an ownership claim the code contradicted. Every addition below
has a row in 8.1, a package that names it in its `Files` text and a check in the proof.

| Addition | Owner, wave | Where | Check in `prove_disjoint_rev7.py` |
|---|---|---|---|
| `src/hydralysis/workcopy_saver.py` deleted, with `workcopy._start_saver`, the saver state keys, the `saved` flag of `status` and `overlay_save_debounce_s` (D61) | Y2, W2 | 8.1 rows `workcopy_saver.py`, `workcopy.py`, `overlayjobs.py`, `hydra.py`, `config.example.json`, `tests/test_durable.py` (the allow-list row), `tests/test_query.py`, `tests/test_engine_integration.py` | the symbol-deletion check finds `_start_saver` in two existing tests and requires Y2's W2 cell for each; a new frozen-value scan for `_start_saver`, `workcopy_saver`, `.saver.lock`, `saver-settings` and `overlay_save_debounce_s` requires Y2 as owner of every test file that carries one |
| `src/hydralysis/locks.py` (`LockBusy`) and `tests/test_locks.py` | Y2, W2 | 8.1, D61 | the matrix row exists, the file exists in the tree, Y2's `Files` text names it |
| `examples/characterization/*.json`: `slots` masked (amendment A1) | E0, W0 | D62, the E0 block, 8.1 goldens row | the proof lists every v2 golden that carries an unmasked `"slots": <n>`, requires the E0 amendment text and requires that no E3a cell names a golden |
| `S/ProcessJob.java` (the daemon's own Job Object) | E9, W5 | D60, 3.11, 8.1 | the file is bold in the matrix and in E9's `Files` text; `support/ghidra_session.py` has no Job Object word in P1b's cell |
| E7 (`S/ScriptCommands.java`, `S/ScriptWorker.java`) in W5 | E7, W5 | D64, 8.1, the wave plan | the proof's own wave plan has E7 in W5; E7 depends on E4 (W4) and E9 (W5); `S/Session.java` has the same four owners as before |
| `skills/hydralysis/SKILL.md`, `skills/ghidra-project/SKILL.md`: the sentence on `options.as` | Y5, W4 | D59, 8.1 | a W4 cell for Y5; Y5 depends on Z4 and so on Z13a, the two earlier owners |
| `examples/cc_e2a.py` (V11) | E2a, W1 | 5.1, E2a | rule-owned file; E2a depends on P1a |

**Revision 8 additions to the table above.** `S/HeadlessSession.java` has one owner per wave and the chain is declared by the
matrix cells themselves: E1 (W1, the option parser and `ready`), E3a (W2, the lane defaults and the usage text at `:133-134`
and `:78-79`), E5 then E9 (W5, the declared `then` sequence); each later owner depends, directly or through its dependencies,
on the earlier ones, which the proof checks. `README.md` (Hydralysis) has the owners Z13a (W0), Y2 (W2), Y5 (W4), Z13b (W5)
and Y4a (W6). `support/ghidra_session.py`: P1a (W1), P1b (W4, including the `maxLong` comment and the JVM flag). The orphan
sweep and `ProcessJob` are E9's; the `--enable-native-access` flag is P1b's.

**What the revision 8 script adds to the revision 7 script:** it reads unbackticked names of source files in a `Files`
paragraph (the plant `S/SessionMain.java` in E9 without backticks must exit 1); it accepts `.properties`, `.cfg`, `.toml`,
`.sh` and `.ps1` as file names, so `support/launch.properties` is an unresolved file and not invisible; it widens the saver
scan to `README.md`, `docs` and `skills`; it checks that every file whose text names a default that a package changes
(`maxLong`, `maintSlots`) has a cell for that package; and it re-runs the mutation plants of the review of revision 7.

**What the revision 7 script adds to the revision 6 script:** the plan has E7 in W5; R1 depends on E7; the three checks of
the table above; the existence of a gate numbered 9.20 and of every `9.<n>` the text cites; and the sealed-predicate,
leave-stall and identity statements are not checked by the script but by the consistency check of the revision history
(`consistency_rev7.txt`).

### 8.5 Revision 8.1: amendments of the W1 coordinator

Revision 8.1 records what the W1 coordinator found while integrating W0 and W1 on `feat/w1-hydra`. It changes no design
decision of revision 8; each amendment is an ownership or a wording correction, with a row in 8.1 or a sentence in the
package it concerns. A1 is the amendment of revision 7 (E0, D62).

| Amendment | What changes | Owner, wave | Where in this file | Check |
|---|---|---|---|---|
| A2 | the package-id pattern of `examples/check_ownership.py` sees all 52 ids; the docs and site column, `then` cells and the site table are read | E0's file, changed by the coordinator in W1; E1's first commit keeps the Hydralysis root documents | E0 (amendment A2), section 8 rule 4, the `check_ownership.py` bullet | `check_ownership.py --selftest`: 36 checks, 0 failures; the script on this file: 123 rows, 52 packages, 0 violations; run on the package branches of W0 and W1 (below) |
| A3 | E8 also owns `LocalDatabaseItem.java`, the private-database open path | E8, W1 | 8.1 (new row), E8 Files, `/NOTICE-HYDRA` row | the proof: matrix and Files text agree; the file exists in the tree |
| A4 | E2a may add the capability name `forkAtomic` to `Advertised.java`, declared as the sequence E1 then E2a | E1 then E2a, W1 | 8.1 (`S/Advertised.java` has its own row), E2a Files, Depends on and Surface, wave plan W1, the in-wave list (23 dependencies, three file sequences) | the proof: the `then` cell needs E2a to depend on E1, both in W1 |
| A5 | S1 owns `src/routes/embed/how-it-works.tsx` (and S2 in W5, like the other panels) | S1, W0; S2, W5 | 8.1 site table, S1 Files | the proof: the site pin-literal scan needs S1 and S2 cells; the file exists in the site repository |
| A6 | the kept corrupt forks of `crash-C` are nine, not twelve | X0 | X0 Tests | text only |
| A7 | `characterization_tests.py --client {stock,install}` is an E0 amendment | E0 (W0 row), edit by the coordinator in W1 | E0 (amendment A7) | `characterization_tests.py --selftest`; the seven goldens `identical` at `--protocol 2` |
| A8 | the grep gate of R0 is Z13a's `tests/test_claims.py` and the site claims gate of S1; X0 needs no manifest line for headered files | Z13a, S1 (W0); X0 | R0 Tests, Z13a Tests, X0 Manifest paragraph, section 8 (manifest bullet) | read of `gradle/support/ip.gradle` and of `gradle/hydra/headless.gradle`; the IP scan of the X0 tree finds no file without an IP |
| A9 | E2a may add `forkAtomic` to `Advertised.java` and to the capability order list in `examples/contract_tests.py` (`gs_capability_order`): the sequence E1 then E2a for both files, one line each; E2 inserts `seal` before it | E1 then E2a (W1) | E2a Files, 8.1 rows of `Advertised.java` and `contract_tests.py` | `examples/check_ownership.py --package E2a` after this row |
| A10 | E8 edits `LocalDatabaseItem.java` (A3) and also the daemon-side `dt_e8.py`; S1 owns `scripts/claims-gate.mjs` and `src/routes/embed/how-it-works.tsx` (A5); the repair policy stays off in production until E2/E5 pass `hydra.storage.repairRoots` | E8, S1 (W1, W0) | E8 Files, S1 Files | `daemon_tests.py e8_private_open`, the site claims gate |

**What the IP check really does (A8).** The coordinator's premise was that `buildHeadless` does not list `examples/` files. It
does scan them: `buildHeadless` depends on `assembleHeadless`, which depends on `assembleDistribution`, which depends on the
`ip` task of every module (`gradle/support/ip.gradle`, line 58); the task walks every file of the module directory except
`bin`, `build`, the manifests and a few IDE files, reads the IP from the header of a C-style or Bash-style source file, and falls
back to `certification.manifest` only for a file without a header. The conclusion for X0 is the same: its files are `.py`,
`.ps1` and `.java` with headers, so no line is needed. The manifest already lists the JSON goldens and the Markdown files for
that reason.

### 8.6 Revision 8.2: amendments recorded while implementing W2-W7

Revision 8.2 records what the coordinator found while the W2 to W7 packages were implemented on `integration/w2` of both
repositories (Hydra at `47cf7db64b` before this section, Hydralysis at `bb3fa88`). It changes no design decision and
weakens no gate: each amendment is an ownership row or a wording correction, and every gate of section 9 keeps its
text, except the two sentences listed in part (4), which the measurement contradicts. Each package report is the source of
the facts here, and a fact that a report did not state is not recorded. The proof `prove_disjoint_rev8.py` (run with the Hydra inventory
`c55c5e3568` and the Hydralysis `main`) and `examples/check_ownership.py` both exit 0 on this file: 130 matrix rows, 52
packages. Before this section the proof reported four violations against the current inventories
(`tests/test_store_v3.py` twice, `examples/client_compat_tests.py`, `examples/stock/ghidra_session_1_0_0.py`); A12 and
A17 close them.

**(1) Ownership amendments.** The "Where" column names the 8.1 row that changed. A package that needs a file it does not
own makes the smallest edit and lists it; the coordinator records the row. Two items are not rows: they need a decision
(below the table).

| Amendment | File | Package, wave | Reason | Where in this file |
|---|---|---|---|---|
| A11 | `.github/scripts/upstream-sync-report.sh`, `test-upstream-sync-report.sh`, `check-archive-notices.sh`, `test-check-archive-notices.sh` (new) | Z15, W5 | the guard must be runnable and testable locally (it now uses `git diff --no-renames`, shown RED on the unfixed script and green on the fixed one); the Tests line "release archives contain LICENSE, NOTICE and NOTICE-HYDRA" needs a test that builds the real client zip | 8.1 Hydra table (new bold row), Z15 Files |
| A12 | `examples/check_ownership.py` (E0's file): `python -I` works, the Hydralysis root documents resolve; `examples/characterization/v3/e1-hello.json` (E1's golden): the four `"slots"` lines became `"<masked>"`; `examples/client_compat_tests.py`, `examples/stock/ghidra_session_1_0_0.py`: a grant to E3a, no edit planned | A1 (amendment of E0, D62), W2; E3a | the slots mask applies to every golden, so the v3 hello golden could not be `identical` at `--protocol 3 --require-v3`; the proof demands a lane-package owner for a frozen file that names a lane default | 8.1 (`check_ownership.py`, the `char_e1.py` row, the P1a row), E3a Files |
| A13 | `S/Session.java` (`seal_project`, `prepare_upgrade` dispatch), `S/Access.java` (`Seals.requireNotSealed`), `S/Advertised.java` (`seal` before `forkAtomic`, A9), `S/OverlayCommands.java` (`markPromote`, `clearPromote`), `S/ForkSweeper.java` (process start-time check against pid reuse), `S/HeadlessSession.java` (the `DbVersions.dataTypes()` self-check, 5 lines), `examples/contract_tests.py`, `examples/char_e1.py` and the goldens `e1-expect.json`, `e1-require-expect.json`, `e1-rk.json` | E2, W2 | the E2 brief itself requires each edit (seal dispatch, pid-reuse check, the `dataTypes` value that E1 left null) | 8.1 (one cell each; the `char_e1.py` family sits in the E1 cell), E2 Files |
| A14 | `examples/conc/mkbase.py` (X0): the red-table base is built as a disposable fork; `LocalDatabaseItem.java` (E8): the versioned branch uses the read-only constructor and read-only items never repair, no header read at construction (E8b), and the reopen when another opener quarantined the newest version first (`862f134874`) | E2 (the gate that refuses a canonical copy); E8 follow-up, W1 cell | E2's upgrade gate refuses a canonical copy, so the base must be a fork; the repair path is E8's | 8.1 (`examples/conc/` row split from `oracle.py`; E8 W1 cell) |
| A15 | `api.py`: the `backend status` branch sends status through `dispatch("environment", ...)`; `tests/test_durable.py`: two FOLLOW_UP rows of the frozen write-site gate | Z3, W3 | without it `backend status` still starts a JVM and the registered handler is never called | 8.1 (`api.py`, `tests/test_durable.py` W3 cells), Z3 Files; **the sentence "Z3 does not edit `api.py`" was wrong** |
| A16 | `backends.py`: `ensure()` waits up to 30 s for `.backend.lock`, honours `cancelled()`, re-reads `inspect(settings)` after the lock (12 lines) | Z5, W2 | `BackendEnsureRace` is red without it: the race is in `ensure()` itself | 8.1 (`backends.py` W2 cell), Z5 Files |
| A17 | `tests/test_store_v3.py` | Y2, W2 | the fixture mentions `_start_saver`, which D61 deletes | 8.1 (new row after Y1), Y2 Files |
| A18 | `api.py` (`ghidra_run` `options.as`), `userscripts.py` (`run(who=)`), `tests/support.py`, `tests/test_commit.py`, `tests/test_integrity.py`, `tests/test_store_v3.py` (fixtures) | Y5, W4 | the default view and `options.as` reach the fixtures; `tests/support.py` was frozen (D31); Y5 now depends on Z3 and Y4e on Y5 for the two shared files | 8.1 (cells), Y5 Files, the Depends on lines of Y5 and Y4e |
| A19 | `tests/test_golden_classify.py` (new) | Z7, W2 | the test file of the classifier | 8.1 (Z7 row), Z7 Files |
| A20 | `runtime_memory.py` (new mixin of `runtime_worker.RuntimeAgent`), `tests/fakememory.py` (new shared helper) | Z12, W7 | the memory code and the helper of two watch tests; folding about 500 lines into other files was the alternative the reviewer allowed | 8.1 (Z12 row), Z12 Files |
| A21 | `runtime_actions.py`, `runtime_agents.py`, `runtime_capture.py`, `runtime_events.py`, `runtime_exports.py`, `runtime_snapshot.py` (new) | Z10, W6 | the Z10 text requires the split of the worker into agent templates, event log, action handlers and lifecycle | 8.1 (new bold row), Z10 Files |
| A22 | `skills/evidence/SKILL.md`, `skills/hooks/SKILL.md`: the front matter `name` equals the directory | Z4, W2 | the harness audit checks it (X28); `skills/ghidra-project/SKILL.md` is Z4's own | 8.1 (new row), Z4 Files |

The in-wave order of `S/HeadlessSession.java` in W2 is now a declared sequence, E2 **then** E3a, so E3a depends on E2 from
this revision (E3a no longer says "Parallel with: E2"). The E3a branch also edits `char_e1.py` and re-records
`e1-hello.json` (a 4-line scheduler mask in `head()`); amendment A1 makes both redundant, so E3a does not keep them and
the integrator takes the A1 and E2 versions. `certification.manifest` is the stated exception to disjointness: a merge
conflict there (E3b found one between the E3a and E2 lines) is resolved by keeping both sets of lines.

Items that need a decision and are **not** rows: (a) the Z15 sentence of `NOTICE-HYDRA` that names `hydra-touched-files.txt`
and `upstream-sync.yml` is in a file that R1 owns in W5 and E8 in W1 (the Z15 report was clipped when this section was
written, so the sentence was not re-read here); the integrator decides between an R1 then Z15 sequence and moving the
sentence. (b) `check_ownership.py` reported `docs/upstream-runtime.md` as "in no row" for Z9 in the Z9 report; the file has a
Z9 row, and the checker on this revision names no violation for it (Hydralysis, `--package Z9`), so the gap was not
reproduced.

**(2) Spike outcomes.** All were run on a Windows 11 machine shared with other agents; no spike had a calm window, so
gate 9.20's "quiet machine" part is **not met** by any of them and stays open: the numbers are load-affected and the
ratios are the more robust figures. No spike committed or pushed.

| Spike | Result and numbers | Go or no-go | Decision taken |
|---|---|---|---|
| SP1 read-replica opens (E11) | 8 runs, 1,720 saves, 60 kills of the saving daemon: 0 corrupt reads, 0 saver failures, 0 unexpected exceptions, 0 unopenable newest versions. 1.5 to 4% of fresh opens were refused at about 2.5 saves/s, each a clean "file not found" that one `refresh` and retry cleared (76 of 76 on the second attempt). About 30 min wall; NTFS on D: only, ReFS and power loss untested | GO with conditions | E11 is built with refresh-and-retry in the open path; a replica is never claimed "never refused" |
| SP2 overlay views against fork views (E10) | KotOR copy, 8,966 functions, 122 MB project: about 6 MB per view against 170 to 190 MB; first edit about 1.5 to 2x faster at N=4 and N=12; heap is a tie within noise. No 1.5 GB program exists locally, so the large case was not run | NO-GO for E10 now (acceptance is "go only if both measures win"); a conditional GO follows if the owner relaxes heap to "not worse" | E10 does not start; the relaxation is the owner's decision and cannot be tested here |
| SP3 (pre-spike: D60 job object, D65 spawn sequence) | on the real `hydra-integ` daemon, every variant (kill-on-close Job Object through `java.lang.foreign`; breakaway, then WMI, then a scheduled task, then stay) passed in two full passes at 23 to 100% total CPU; negative controls gave the opposite result | GO for D60 and D65 | P1b and E9 keep the sequence as written |
| SP4 in-process decompiler recreate (E9) | 6 runs, about 1,100 cycles with `decompile.exe` killed by `TerminateProcess`: `dispose()` then a new `DecompInterface` worked every time; 0 poisoned decompiles, 0 hung threads; threads back to baseline, handles settle after a GC lag, no linear growth up to 450 cycles; a second client in the same JVM undisturbed. Not verified: a real daemon with real clients (the "other client" was a thread), a calm machine | GO for the in-process part of E9 crash isolation | E9 builds the in-process recreate; the daemon-level isolation needs its own test |
| SP8 separate read-only instances (E11) | on a KotOR copy with `hydra-integ`: DB-bound reads scale about 2.4 to 3.5x at K=4 to 8 (4.6x best run, 2.3 to 3.0x worst); one shared instance stays at about 1.0 to 1.2x and is slower on xrefs and data; at K=8 separate against shared is a median 3.0 to 6.3x. The earlier 4.1x is not reproduced in the median. Decompile is not DB-bound and gains nothing | GO for E11, conditional and load-sensitive | E11 uses separate instances of the one stored file, not a shared Program |
| SP10 worker JVM start (E7) | a second JVM opening a clone of KotOR read-only reaches a trivial script in a median of about 4.3 s calm and 6.4 s under heavy foreign load; a worker uses about 350 to 450 MB resident; 12 concurrent workers all succeeded (13.6 to 26.8 s each, all ready within 14.5 to 28.6 s); `TerminateProcess` ends a deaf worker in about 50 ms (1) or 0.1 to 2.0 s (12 at once) and the clone is deletable right after; AOT cache and class-data sharing give no usable gain. Cold start was NOT measured (the OS file cache could not be flushed without privileges) | GO for E7 on `hydra-integ` | E7 builds the worker route with no AOT or CDS |

**(3) Per-package status.** "Landed" means merged into `integration/w2` of its repository (the merge commit is given);
nothing is pushed. "Tests" is what the package report showed; a count is the report's.

| Package | Landed | What its tests showed | What remains open |
|---|---|---|---|
| A1 (E0 amendment, Hydra) | yes, `e925a7973c` | capacity keys `slots`, `cap`, `perKeyCap` masked (value must still be a positive int); the six v2 goldens re-recorded; base scenarios protocol-2 only; four new selftest checks; `python -I characterization_tests.py` works | the seven base scenarios no longer run at protocol 3; the four proof violations of the old inventories (closed by A12 and A17) |
| Z15 | yes, `28c27eca1e` | rename test RED on the unfixed script (2 FAIL), green on the fixed (8 of 8); `--require-v3` in the golden step; archive notice check 4 of 4 including negative cases on the real client zip | the workflow dry run on GitHub, the open-PR skip (`gh pr list`), N9 numbers are labelled defaults, supported-versions wording in two files |
| E8b (E8 follow-up) | yes, `e2eefb3d34` | `e8_item_readonly` new; the whole `e8_*` family and the default `daemon_tests`: 55 of 55 on build h-E8b (6 expected-fail baseline tests not run); +19% listing cost of the header check removed | the Java unit tests of the FileSystem module were not run; a private item with an invalid newest header is repaired when opened, not when constructed |
| E2 | yes, `9c7cdef9e4` | a `dt_e2` case now fails when the `ProjectFork.publish` refusal is removed; the ownership gate had 11 violations, closed by A13 and A14 | no failing test for the `ProjectFork.RETRIES` change; no deterministic test for `ForkSweeper.removeIfNamed`; the `repairable()` cache and the `upgradeStamp` key for protocols 2 and 3 are untested; `ProjectBackup.forget()` is dead API; `verify:none` and `verify:size` backups still write `verify.ok:true` |
| R-V1, R-V2, V1, V2 (verification) | R-V1 `47cf7db64b`; V1, V2 are read-only runs | V2 on `9c7cdef9e4`: build OK, every suite green except two `daemon_tests` failures that fail identically on V1; V1: 9 of 10 suites and the ownership checker pass, but the red table is unusable (5 rows gave no output, 2 control scripts failed), almost certainly because the KotOR copy needs a DB upgrade and the measurement scripts do not pass `upgrade:true` (read from logs, not tested) | the red table must be re-run with `upgrade:true` (or on a fork, as `mkbase.py` now does) before gate 9.12 is claimed |
| E3a | no (`6e0750239a`, reviewer green) | `lane_starvation`-family dt tests for BP10, BP9(b) and `import_wait` ran green | **BP9(a) (24 waiters take all 24 quick slots) stays RED**: it needs the E3b/E3c waiter caps; gate 9.1 and the full `red_table.py` were not run; E3a follows E2 on `S/HeadlessSession.java` and drops its `char_e1.py` and `e1-hello.json` edits (A12) |
| E3b | no, blocked in setup | none written | merging `w2/E2` conflicts only in `certification.manifest`, both sides add distinct list lines; the fix is to keep both sets of lines (stated exception) |
| P1b | no (`94b78d5c83`) | blocking defect fixed: connect, `_wait_ready`, status, stop dial with a hello deadline from the remaining time; the real-wedge test (a daemon suspended with `NtSuspendProcess`) gave `no_answer` in 3.5 s (connect) and 3.0 s (attach), `status()` None in 5.0 s, and the daemon answered after resume; 7 of 7 p1b tests, exit 0 | the task route stops the task on `no_answer` while the direct and WMI routes leave the JVM running, and it is outside the text of D65 as P1b read it: needs an owner decision or an amendment of D65; `registry_write` prune treats any read error as gone; no test that the real registry stays untouched; a locked-down harness was not tried |
| Y2 (Hydralysis) | yes, `58c5116` | root cause of the `commit_in_flight` refusal fixed in `commits.py` (`finalize` writes FINALIZED when the store already holds the commit); run on the hydra-3-released pin | no real second OS process test of the commit-lock probe; the hydra-2 pin run was not done; the `generationKeep` retention decision, the step 9 stale-view wording, a 1.5 s sleep in the LineageCreation test |
| Y3 | yes, `bb3fa88` | five new `VerificationCanFail` tests; full suite 873 tests OK, 39 skipped (real-engine ones), exit 0, fake daemon only | nothing ran on a real engine; two nits without a proving test (`store["stale"]`, the real `python -m` run) |
| Y5 | no | blocking findings 1 to 3 fixed (idle-delete guard test turns 2 tests red under the mutation `if False:`) | ownership closed by A18; nits listed in the report; nothing run on a real engine |
| Z2 | yes, `ade5911` | ownership fixed without an amendment (the helper folded into `mcp_latency.py`, `bench_common.py` deleted); unit tests pass | SP7 publish latency (1, 4, 12 publishers) pending because Y3's real-engine run does not exist; KotOR figures and the cold OS-cache run; engine-backed tests not rerun after the fold |
| Z3 | yes, `ec238f6` | `backend status` starts no daemon; no config lookup in the working directory; every launch reports root, configuration source, engine release and file system | the system-drive warning was not measured on a machine whose data root is truly on C:; Linux and macOS untested; row C2-04 of `docs/pr6-traceability.md` still to flip |
| Z4 | yes, `b9854fb` | `NoStockEndToEnd` passes on the real pinned engine (12.3-hydra.2) with a decoy stock install and a canary; `audit_harness.py` exits 0 | not run on GitHub Actions; one flake (`PermissionError [WinError 5]` on the rename of the unpacked directory, once) |
| Z5 | yes, `7246a79` | the ensure race test (`BackendEnsureRace`) is red without A16 | engine suites, the KotOR local run and the legacy 12.1.4 test not re-run after the last commit; 10 functions of difference between fresh analysis (8,956) and the adopted project (8,966) unexplained |
| Z6 | yes, `ffaffdd` | a full KotOR copy run gave 8,616 of 8,616 rows, 797 s wall, 11 rows/s; per-row cost 81 ms to 15.6 ms (fake runner); resume refuses a missing or edited snapshot | **C1-38 not met**: 1,363 of 8,616 `c_sha256` differ from the golden production rows and are unclassified; local tier only, not in CI |
| Z7 | no (`dbdd508`) | polarity acceptance narrowed (swapped branches or pure operand mirror only; De Morgan for compound conditions); a mutation test fails when the final check is `return True` | the 21 "variable naming only" functions were not traced; accepted figures are by class only; pinned captures depend on a scratch-modified `GoldenExport.java`; see part (4) |
| Z8 | yes, `7bf3524` | the `\b` regex of `test_every_check_a_row_cites_exists_in_the_harness` held a raw 0x08 byte and matched nothing; fixed, each cited label must exist in its group | protocol 3 untested; engine-gated parity tests not re-run |
| Z9 | yes, `3c96af3` | `check_content` rejects a hash-consistent record with invalid claims | `evidence_add` and the MCP surface forward none of the v2 fields; the MAX_STRING guard, sorted-ledger check and symlink refusal untested |
| Z10 | no (`e817bd1`) | real-Frida checks (break_continue, export_hook, capture, snapshot, hooked on x64 and x86) were last run at `6047932` | A21 closes the ownership gate; those checks were not re-run at `e817bd1` (docstring only); the view-revision assertion of `mcp_typed_read` is mock-covered only |
| Z11 | no (`1486409`) | 23 unit tests pass; the real-process `scenario` check passes on x64 and x86 | the full suite had not finished (baseline 581 tests, 27 skipped); the writers and export-hook steps were skipped in every run; no live KotOR run |
| Z12 | no | the real-process conformance exits 0 for both architectures after the `detach_reason` fix | A20 closes the ownership gate; real Frida detach reasons unproven (fake only); acceptance needs the owner decisions N2 and N3 |
| Z13b | no (`b229f7f`) | 13 tests in `test_tool_mapping.py`; the GhidraMCP 30 and REA 207 counts are recorded, not reproduced | the full suite was not re-run after the last reword; `docs/tool-mapping.md` is still a skeleton with "to verify" rows |
| HVF (Hydralysis golden fixtures, on `bb3fa88`) | verification only | unit suite 1,015 tests OK (66 skipped); catalog 8,172 of 8,192 bytes; golden fixtures 8 of 8 programs at 100.00%, gate PASS | the real-engine run fails against the engine as built: its client speaks protocol 3 and Hydralysis still requires protocol 2 (Y4a not landed); with the released hydra.3 client, one thread-leak assertion failed once and passed on rerun |

**(4) Statements of this file that the implementations proved wrong.**
1. Gate 9.18 and the owner row "12.1.4-against-12.3 decompile diff reported, never gated" said the 77.124% figure is
   "confounded by `maxBadData` 4". Z7 captured the 12.3 side with `maxBadData` pinned to 1,000,000 and with the default 4: both
   gave the same 6,645 of 8,616 identical and the same 1,971 changed functions. The sentence is replaced in both places; the
   cause of the difference is not established.
2. "Z3 does not edit `cli.py` or `api.py`" (Z3 Files): Z3 edits `api.py` (A15). The `cli.py` half stands.
3. The A1 text (8.5, 8.1 `clients.json` row) lists the six v2 goldens and the key `slots`: the masked key set is `slots`,
   `cap` and `perKeyCap`, and the v3 golden `e1-hello.json` is masked too (seven goldens; A12).
4. E3a's `Scheduler.java` caps are not the close of BP9(a). BP9(a) closes with the E3b/E3c waiter caps; the red-table row stays
   RED at the E3a merge and must not be marked closed.
5. 8.1 gave Z10 two worker files; the Z10 text itself requires a split, so six more files are needed (A21). It gave Z5 no
   file in W2 for `backends.py`, Z3 none for `api.py`, Y5 none for `api.py` and `userscripts.py` (A15, A16, A18).
6. 8.5 reports "123 rows" for `check_ownership.py` on the file; the count on this revision is 130 rows, 52 packages.
7. D65 as written lists breakaway, WMI, scheduled task, stay and SP3 confirms it; P1b read the scheduled-task route as outside
   D65. One of the two readings is wrong; the text of D65 is not changed here and the owner decides (see P1b above).

### 8.7 Revision 8.3: stage A2 (the unlanded packages finished, W8 candidates)

Revision 8.3 records stage A2: the packages that were not landed when 8.6 was written were finished, reviewed and, for
some, landed on `integration/w2` (Hydra at `42d1eab507` before this section, Hydralysis at `9218dd6`). It changes no design
decision and weakens no gate. Section 8.6 is not rewritten: where a status or a sentence of 8.6 is superseded, this section
says so and governs. The facts come from the package reports of the stage; **several reports reached this revision
clipped** (their tail is missing), so a field that a clipped report did not show is not recorded, and each such report is marked
"clipped" below. A fact that no report stated is not recorded. Nothing is pushed. `prove_disjoint_rev8.py` (Hydra inventory
`c55c5e3568`, Hydralysis `main`) and `examples/check_ownership.py` both exit 0 on this file after the 8.1 edits listed in part (1):
132 matrix rows (the rows of `examples/daemon_tests.py` and of `S/Waits.java` are split from their former shared rows, A24 and A25), 52 packages.

**(1) Ownership amendments.** Continues 8.6 after A22. "Where" names the 8.1 row that changed. F1 and F2 are fix packages of
this stage that are not among the 52 package ids; their amendments are recorded as a note in the owner's cell (F1) or only here
(F2), so that the id list of the proof stays at 52.

| Amendment | File | Package, wave | Reason | Where in this file |
|---|---|---|---|---|
| A23 | `examples/char_e1.py` (9 lines in `head()`: `status.scheduler` loses `maint`, and in the `quick` and `long` lanes the keys `oldestWaitMs`, `longestRunningMs`, `starving`, `perKeyCap`, `perKey`) | E3a, W2 (landed `827828ddc9`, commit `11b9215336`) | amendment A1 masks only `slots`, `cap` and `perKeyCap`; E3a adds scheduler fields that a golden recorded at the protocol-3 base does not have, so the status step stays at the base shape only with this mask. 8.6 said E3a drops this edit; that was wrong (part 4, item 8). `check_ownership.py --package E3a --base integration/w2` reported exactly one violation, for this file, until this row | 8.1 (`char_e1.py` row, W2 cell: E1 then E3a) |
| A24 | `examples/daemon_tests.py`, function `t_shared_stress`: `d.connect(f"agent-{i}", f"harness-{i}")` became `c.connect(d, f"agent-{i}", f"harness-{i}", 2)`, plus a 5-line comment | E3b, W3 (not landed, `0e20a14a05`) | eight protocol 3 writers on one shared program now get `busy{lock_queue_full}` beyond `max(2, slots/4)` waiters (3.5, 3.10); `shared_stress` does not exercise that refusal and must connect at protocol 2. The file is E0's (W0). Until this row, `check_ownership.py --package E3b --base f7b2af85b2` reported one violation (13 changed files, 1 outside) | 8.1 (the `daemon_tests.py` row is split from the `characterization_tests.py` row; W3 cell E3b) |
| A25 | `support/ghidra_session.py` (module-level `_K32_LOCK` and `_PE32`, `_kernel32()` under the lock, new `_toolhelp()` that builds the one PE32 class and sets the Toolhelp `argtypes` once, `_children_of` uses it); `S/Waits.java` (new overload `Waits.lock(ReentrantLock, long, AtomicInteger)` and the private `contended(ReentrantLock)`; the E3c report is clipped after this item, so further files, if any, are not recorded) | E3c, W4 (not landed, `4e575f175d`) | review finding 1: `e2a_kill_fork` failed because `_children_of` made a new PE32 ctypes class on every call and set `argtypes` on the shared kernel32 functions; 8 threads calling it 200 times each gave 7 of 8 threads the `ArgumentError` on the old file and 0 on the new. The `Waits.java` overload serves the waiter caps (BP9) | 8.1 (`ghidra_session.py` W4 cell becomes P1b **then** E3c; `S/Waits.java` W4 cell E3c) |
| A26 | `S/ProjectFork.java`: `writeSidecarRetrying`, `backoff` and `removeRetrying`; `setPromote` writes the sidecar with retries; the rollback in `publish` removes the destination `.rep`, the sidecar and its `.tmp` with retries | F1 (fix package, landed `1b841eef74`, commit `ea5ee8f769`) | `promote_marker` lost its marker and `fork_publish` left `H.fork.json` alone (`sidecar_only`) when a reader held the sidecar open: single attempts. Both were engine weaknesses, not pure test flakes | 8.1 (`ProjectFork.java` row, E2 cell, as a note naming F1) |
| A27 | `src/hydralysis/proc.py` (`_reap_children` returns, under the registry lock, once the last child is reaped, clears `_reaper`, and `popen` starts a new reaper on demand) | F2 (fix package, landed `75e25a0`) | a daemon thread `hydralysis-child-reaper` outlived every child after any `proc.popen` and failed the leak check of `test_mcp_transport` in a full discovery run. The file has no row in the Hydralysis table; it is an existing source that no package of the 52 edits | here only (no cell: F2 is not a package id) |
| A28 | wording, not a file: `PROTOCOL-3.md` 3.4 and 6.2 | E4, W4 | E4 (report clipped) cannot edit the spec and lists the sentences the coordinator must add | here, part (4), item 13 |

**What A25 needs besides the row.** E3c's `Depends on` line says "Parallel with: E4, P1b, Y5", but E3c edits `support/ghidra_session.py`
after P1b did; the cell now declares the sequence P1b **then** E3c, which makes E3c depend on P1b from this revision. P1b is landed,
so nothing is delayed.

Items that need a decision and are **not** rows: (a) E5 is blocked (part 3): `w2/E3b` and `w2/E3c` conflict in `S/ProjectCommands.java`
(one hunk, about lines 429-469: E3b keeps `synchronized(s.registry)` plus the `completeLeaves` retry loop, E3c replaces the
block with `s.registry.closeIdle(...)`). The 8.1 row lists E3b (W3) then E3c (W4) and E3c depends on E3b, so the resolution belongs
to E3c: merge `w2/E3b` into `w2/E3c`, resolve that hunk, and re-run the waiter-cap tests. This revision does not choose the
resolution. (b) The ownership-bits decision of E3b and the two wording findings of its review round 1 (findings 2 and 3) were
for the coordinator to record in 3.5 and elsewhere; the E3b report is clipped, so they are **not** recorded here and stay open.

**(2) Spike outcomes.** No new spike was run in stage A2; the figures below are those of 8.6 (2), repeated here with the decision
each took, and stay load-affected: gate 9.20's "quiet machine" part is still **not met** by any of them. No spike committed or
pushed.

| Spike | Numbers | Go or no-go | Decision taken, and where it stands |
|---|---|---|---|
| SP1 read-replica opens (E11) | 8 runs, 1,720 saves, 60 kills of the saving daemon: 0 corrupt reads, 0 saver failures, 0 unexpected exceptions, 0 unopenable newest versions; 1.5 to 4% of fresh opens refused at about 2.5 saves/s, each a clean "file not found" that one `refresh` and retry cleared (76 of 76 on the second attempt); NTFS on D: only, ReFS and power loss untested | GO with conditions | E11 is built with refresh-and-retry in the open path and never claims "never refused". E11 is not started in stage A2 |
| SP2 overlay views against fork views (E10) | KotOR copy, 8,966 functions, 122 MB: about 6 MB per view against 170 to 190 MB; first edit about 1.5 to 2x faster at N=4 and N=12; heap a tie within noise; the 1.5 GB case not run (no such program locally) | NO-GO for E10 now (go only if both measures win) | E10 does not start; a conditional GO needs the owner to relax heap to "not worse" |
| SP3 D60 job object and D65 spawn sequence | real `hydra-integ` daemon, every variant passed in two full passes at 23 to 100% total CPU; negative controls gave the opposite result | GO for D60 and D65 | P1b (landed) and E9 keep the sequence as written. The P1b task-route reading of D65 is still the owner's decision (8.6 (4) item 7) |
| SP4 in-process decompiler recreate (E9) | 6 runs, about 1,100 cycles with `decompile.exe` killed by `TerminateProcess`: 0 poisoned decompiles, 0 hung threads, no linear handle growth up to 450 cycles; the "other client" was a thread; no calm machine | GO for the in-process part of E9 | E9 builds the in-process recreate; daemon-level isolation needs its own test. E9 is not started in stage A2 |
| SP8 separate read-only instances (E11) | KotOR copy, `hydra-integ`: DB-bound reads scale about 2.4 to 3.5x at K=4 to 8 (4.6x best, 2.3 to 3.0x worst); one shared instance stays at about 1.0 to 1.2x; at K=8 separate against shared is a median 3.0 to 6.3x; the earlier 4.1x is not reproduced in the median; decompile gains nothing | GO for E11, conditional and load-sensitive | E11 uses separate instances of the one stored file |
| SP10 worker JVM start (E7) | median about 4.3 s calm and 6.4 s under heavy foreign load to a trivial script; 350 to 450 MB resident per worker; 12 concurrent workers all succeeded (13.6 to 26.8 s each); `TerminateProcess` ends a deaf worker in about 50 ms (1) or 0.1 to 2.0 s (12 at once); AOT and class-data sharing give no usable gain; cold start NOT measured | GO for E7 on `hydra-integ` | E7 builds the worker route with no AOT or CDS |

**(3) Per-package status.** "Landed" means merged into `integration/w2` of its repository; the merge commit is given (checked with
`git log --first-parent`). Where a row differs from the same package in 8.6 (3), this row governs. A count is the report's.

| Package | Landed | What its tests showed | What remains open |
|---|---|---|---|
| E3a (Hydra) | yes, `827828ddc9` (branch head after merging `integration/w2`: `1957b8c999`) | the decompile preflight defect is fixed; the `e1-hello` scheduler mask is in; all suites passed on the rebuilt install h-E3a; no timing flake occurred | **BP9(a) (24 lock waiters on 24 connections take all 24 quick slots) is still RED** and must not be marked closed at the E3a merge: it belongs to E3b and E3c. Gate 9.1 (golden decompile diff) and the full `conc/red_table.py` were not rerun in this round; only the dt versions of BP10, BP9(b) and `import_wait` ran. Hydra suites ran at `--protocol 2` and `3` only, not with the Hydralysis tests. One merge conflict in `certification.manifest` was resolved by keeping both sets of lines (the stated exception) |
| P1b | yes, final merge `42d1eab507` (earlier `27d84a9082`); last commit `2a3c863fce` | the reviewer's one blocking item (the `Daemon.connect` docstring said `timeout` bounds the whole call) is fixed by rewording only; the report's author read the diff and compiled the file and **ran no tests**; earlier rounds: 7 of 7 p1b tests, a real wedge gave `no_answer` in 3.5 s | reviewer nits not addressed: `p1b_wedged_connect` still allows `stop(timeout=3)` up to 15 s (a bound such as 4.5 to 9 s would catch a second 5 s dial); no test makes `status()` raise `deadline_exceeded` on a daemon that answers hello but not status; no comment in `stop()` on why the parallel cancel at the shutdown deadline cannot abort a healthy shutdown, and no test that a healthy `stop()` is unchanged; after `deadline_exceeded` on shutdown `stop()` still waits `timeout` (default 60 s) and then raises `LaunchError`; the report is clipped after these |
| F1 (fix package) | yes, `1b841eef74` | `promote_marker`, the `fork_publish` rollback and `e2a_handle_holder` pass 30 of 30 runs under 12 busy threads (run times 25 to 135 s; "alone" still had other agents' load); the engine fix (single-attempt sidecar writes and deletes) and the test changes both stand | the "marker seen" check of `promote_marker` is still a sampling check (seen in attempt 1 in all 30 loaded runs); one daemon-stop `LaunchError` ("did not exit within 60 s") under load, not recurring in 120+ runs, not investigated; an external scanner holding the sidecar longer than the 1.6 s retry budget would still leave a fork in `sidecarState` "publishing" (report clipped) |
| E3b | **no** (`0e20a14a05`, review round 1 fixed) | finding 1 (`dt_e3b t_applied_flag`) fixed in code: the warm run renamed the first function, so the loop rerun was a no-op and `applied == changed` held as false == false; the new script `E3bRenamer` makes the assertion see `applied` False for `TestSleep` and True after a real rename; before the fix the scenario printed (False, False), after it (True, True) | red-before-green for the new assertion is by reasoning and the reviewer's observation, not a mutation build; findings 2 and 3 and the ownership-bits decision are for the coordinator (part 1, item b); A24 until recorded; what was not rerun this round: clipped |
| E3c | **no** (`4e575f175d`) | both blocking findings of review round 1 fixed in one commit; finding 1 is `e2a_kill_fork` (the Toolhelp race, A25), finding 2 is clipped; the 15-test set passed 15 of 15 after the registry fix; the full daemon suite was 108 of 111 before it | the two remaining reds are pre-existing and not caused by E3c: `p1b_daemon_survives_launcher_exit` (`WinError 5` on the breakaway route, same on h-E3b; not rerun) and `legacy_overlay` (timing flake, fails in the full run under load, passes alone); the orchestrator must accept them in writing or assign owners; red-table rows BP4 and BP6 were not re-run (run3, about 436 s); no claim that the caps close BP4 or BP9; the conflict with E3b (part 1, item a) |
| E4 | **no** (`9421985e55`) | the one blocking finding (a protocol 3 `script` on an overlay skipped `checkSha`) is fixed: `ScriptCommands.runOverlayScript` now calls `isolationOf(req)` and `checkSha(req, src)` for protocol 3 clients, so a wrong `scriptSha256` gives `script_changed`, a malformed digest or invalid `isolation` gives `bad_request`, and protocol 2 clients are unaffected; the package tests pass | the full `daemon_tests.py` finished 107 of 110: `e2a_kill_fork` (the ctypes `LP_PE32` error, fixed by E3c in A25) and `p1b_daemon_survives_launcher_exit` (breakaway spawn) fail for environmental reasons, reproduced by the reviewer on the h-E4 install and reported failing on an unmodified `integration/w2`; `oracle_live_engine` failed once in the full run with `K14:slots_in_use` (`daemon_tests.py` line 727) and passed alone (exit 0, 1 of 1) on a shared, loaded machine; the report is clipped |
| E5 | **no, blocked at setup** | nothing: no E5 commit, no build, no test, no daemon; branch `w2/E5` and worktree `h-E5` were created from `integration/w2` (`42d1eab507`); `copy-deps.ps1` exit 0; `w2/E3b` merged cleanly (`c5c790c328`); `w2/E3c` (`cb99c188ab` at that time) conflicts | the `ProjectCommands.java` conflict (part 1, item a); nothing of E5 is implemented (no `health` command, no `debug_stall` launch property, no Health contributor list, no lane stats); `D:/Projects/Hydra/_logs/E5` does not exist |
| E12 | **no** (`c960f189bb`; two new commits, the first `f92e25cc46`, nothing amended) | the blocking finding is fixed: the early-closed version file `db.N.vf` was deleted on every failure of `saveCompleted`, including a failure after the commit, and a failure in `versionCreated` left `db.N+1` in place while the previous version's reverse-delta file was gone, so that version could no longer be rebuilt; the cleanup now runs only while the save file still has its pre-save name | `syncDirectory()` is a no-op on this Windows machine (`AccessDeniedException` is swallowed), so the Windows result rests on directory-entry model J, an assumption about NTFS and ReFS that nothing measures; the Linux and POSIX effect was not observed; the fork-publish matrix is a hand-written model of the documented step order, not a trace of the running NIO publish, and its "forced" variant models a change that does not exist; `UpgradeCache.copyProject` and `ProjectFork.publish` do not force their copies, a finding in files E12 does not own, reported only; report clipped. **No power-loss claim may be made** (6.1, E12 Acceptance) |
| Y5 (Hydralysis) | yes, `7a1614d` (branch merge `b3c23e0`) | the merge of `integration/w2` conflicted in two files, one hunk each, resolved by keeping both behaviours; the Hydralysis unit suite on the merged tree: 1,065 tests OK, 66 skipped, exit 0 (482 s) | nothing ran against a real engine (fake daemon only: eviction, `close_project` discard, `status.projects` and the real busy refusal are unverified); the publish job worker `python -m hydralysis.views` has no end-to-end run in a separate process with per-agent views; nits and deviations of the previous report unchanged. **Suspected regression:** see the HVF row |
| Z7 | yes, `26554b4` (branch merge `2598434`) | review round 3 blocking defect fixed in commit `c592368`: in `_flipped`, when the operands keep their order `==` must become `!=` and `!=` must become `==`; only a single comparison with swapped operands may keep its operator; KotOR re-run on the pinned captures | accepted figures are text heuristics by class, never checked per function; the 21 former "variable naming only" functions are still not traced; the pinned captures depend on a scratch-modified `GoldenExport.java`, so they are not reproducible from the repository; no header check that the unpinned capture really has `maxBadData` 4; fixture comparison tables not regenerated (clipped); the statements the report asked to amend (9.18, line 4737) were already replaced by 8.6 (4) item 1 |
| Z10 | yes, `9c53dec` | the ownership item is cleared (15 changed files, 0 outside Z10's rows, 0 matrix violations; A21 covers the six `runtime_*.py` files); `integration/w2` merged into the recreated branch by fast-forward, no new commits | the full unit suite had one failure, a flaky test not in Z10's files: `test_four_processes_opening_an_old_ledger_at_once_agree` (Z9's `evidence.py`, sqlite "database is locked" on `PRAGMA journal_mode=WAL`), intermittent on `integration/w2` too, needs an owner (Z9 or the coordinator); Z10's own diff has had no code review; the real-Frida checks were not re-run (66 tests skipped); trailers and identity checked only for the newest three commits |
| Z11 | yes, `1b96bd0` | no change in this stage; commit `1486409` and the nit-fix `ffbfa9f` are ancestors of `integration/w2` (the tautological assertion at `tests/test_runtime_scenario_fixture.py:206` and other nits fixed there) | the whole unit suite was not run on `integration/w2` by this stage (baseline 581 tests, 27 skipped); the writers and export-hook steps skip in the fixture scenario |
| Z12 | yes, `04712d9` | no change in this stage; `ccdde9f` makes `_pid_gone` treat `OSError(87)` (winerror 87, errno 87, `ESRCH`, `ENOENT`) as gone; access denied (5) stays alive; `tests/test_runtime_watch.py` has the test | red-before-green for the `OSError(87)` test was not re-demonstrated in this stage; the full suite was not re-run on `integration/w2`; real Frida detach reasons unproven (fake only); acceptance needs the owner decisions N2 and N3 |
| Z13b | yes, `a13001a` and `9218dd6` | `integration/w2` and the Y5 merge are in the branch with no conflicts; full suite 1,260 tests OK, 66 skipped, exit 0; tool counts unchanged (hydralysis 20, ghidramcp 30, rea 207); `test_tool_mapping`, `test_claims`, `test_no_stock_ghidra`, `test_contracts` passed | `docs/tool-mapping.md` is still a skeleton (rows say "to verify"); the GhidraMCP 30 and REA 207 counts are recorded, not reproduced; the reviewer's nit ("counted" should say "recorded" in `docs/data/tool-surfaces.json` and `docs/tool-mapping.md`) is not applied; only merge commits are new, so the merge resolutions need review; the LF/CRLF mismatch on new files is unchanged |
| F2 (fix package) | yes, `75e25a0` | the leaked `hydralysis-child-reaper` thread was a product defect, not a test-order artifact; fixed in `proc.py` (A27) | an earlier full run on the fixed code (`D:/Projects/Hydra/_logs/F2/discovery-fixed2-loadfail.log`, 1,603 s, about twice the normal duration) failed in `test_concurrency.EngineConcurrency.test_a_query_while_an_edit_is_in_flight_is_answered_not_refused`: the engine answered "script timed out" and "cancelled" for 3 queries and both `tearDownClass` calls hit "daemon pid ... did not exit within 60 s"; the failure is in engine script time-outs under heavy load, not the reaper; report clipped |
| HVF (on `integration/w2`, Hydralysis `9218dd6`) | verification only | 1,260 tests, 1 error, 21 skipped; golden fixtures 8 of 8 programs at 100.00% identical (decompile output unchanged); all real-engine classes, claims and catalog size green except one test | `test_engine_integration.EngineCommit.test_commit_round_trip_archival_and_revert_chain` errors with "no pending record to commit" and fails the same way on the published hydra-3-released engine, so it is not engine-caused; F2 saw it pass before the Y5 merge, so it looks like a Y5 regression (the test's edit lands in the agent's per-agent default view, while `commit` selects view ""); **not fixed, not diagnosed further**. The Y5 landing is therefore not clean against a real engine |

Whether Y4a (the Hydralysis protocol 3 client) is closed is not stated by any report of stage A2 and is not recorded here. Packages
R-V1, Z2, Z3, Z4, Z5, Z6, Z8, Z9, Y2 and Y3 keep their 8.6 (3) rows.

**(4) Statements of this file that the implementations proved wrong.** Numbering continues from 8.6 (4) item 7.
8. 8.6 (after the table of part (1)) and the 8.6 (3) E3a row say E3a "does not keep" its `char_e1.py` edit because amendment A1
   makes it redundant. Wrong: A1 masks `slots`, `cap` and `perKeyCap` only; E3a's new scheduler fields (`maint`, `oldestWaitMs`,
   `longestRunningMs`, `starving`, `perKey`) need the 9-line mask in `head()` of `char_e1.py`. It is kept and recorded as A23.
9. 8.6 (3) lists E3b as "blocked in setup" and "none written". Superseded: E3b was implemented and reviewed (part 3); it is not landed.
10. 8.6 (3) lists P1b, Y5, Z7, Z10, Z11, Z12 and Z13b as not landed. Superseded: all seven are landed (part 3). The P1b statement in
    its docstring that `timeout` bounds the whole `connect` call was wrong and is reworded in the code: the timeout is a budget **per
    phase** (the hello dials share one timeout, up to 0.5 s over; the start-lock wait takes up to `timeout`; the spawned-daemon wait
    takes up to `timeout` again), so the worst case is about 2 x `timeout` plus spawn time. Any sentence of this file that gives
    `connect` one overall deadline must be read with that bound.
11. 3.5 and 3.10 (waiter cap `max(2, slots/4)`) against `examples/daemon_tests.py` `t_shared_stress`: the test assumed eight protocol 3
    writers on one shared program were admitted; with the cap they get `busy{lock_queue_full}`. The test was wrong, the cap stands (A24).
12. 8.6 (4) item 4 stands and is confirmed: BP9(a) was still RED at the E3a merge. Added: the E3b and E3c waiter caps are not
    landed either, so **BP9 is open** at this revision, and gate 9.1 and the full red table were not rerun after E3a.
13. Sections 3.4 and 6.2 (D47) on a protocol 3 `script` on an overlay (E4, not landed; the E4 report is clipped and only these
    statements were shown). The text must read, when E4 lands: for a protocol 3 `script` on an overlay, `scriptSha256` is verified (a
    mismatch is `script_changed`) and `isolation` is validated but otherwise ignored on purpose; the reply value `isolation:"overlay"`
    is outside the closed request enum (shared, exclusive, private); the legacy `exclusive:true` is ignored when `isolation` is also
    given; and D47 as implemented refuses the owner's second script while one of its scripts is quarantined, including quick-lane
    scripts, which is stricter than the text on long calls (the report is cut off there, so the exact wording of 6.2 is not changed
    here). Recorded as the wording amendment A28; 3.4 and 6.2 themselves are not edited in this revision.
14. 8.6 (4) item 1 (the `maxBadData` sentence): the Z7 report of this stage asked for 9.18 and line 4737 to be amended. They already
    were; the only remaining occurrence of the word "confounded" in the file is the quotation in 8.6 (4) item 1. Its caveat stays: the
    pinned captures are not reproducible from the repository.
15. E12 Acceptance ("only after it passes may a document say anything about power loss"): the E12 matrix rests on model J, a
    hand-written model, and `syncDirectory()` is a no-op on the test machine, so **E12 has not passed that acceptance** and no
    document may say anything about power loss. The E12 Tests line asks for "a virtual machine or a crash simulator"; none was used.
16. 8.1 gave `S/Waits.java` to E3b alone and `support/ghidra_session.py` in W4 to P1b alone while E3c's work edits both (A25), and
    `S/ProjectFork.java` to E2a and E2 only while F1 edited it after they landed (A26).
17. The 8.6 HVF row said one thread-leak assertion failed once and passed on rerun. The thread leak was a real product defect (A27),
    now fixed. The new HVF result is the `EngineCommit` error of part 3, a suspected Y5 regression, not an engine defect.

**Gates.** No gate of section 9 is weakened, none is flipped to passing by this revision, and no sentence of the engine or
Hydralysis documents is strengthened by it. Gates and rows that still need work: 9.1 and the BP9 row (E3b, E3c, E5), gate 9.20
(quiet machine), the power-loss claim (E12), and the Hydralysis real-engine run (the Y5 regression).

### 8.8 Revision 8.4: stage A3 (the non-blocking core landed, the release path)

Revision 8.4 records stage A3: E3b, R-V3 and E4 were merged into `integration/w3` of Hydra (merge commits `8c9df389a8`,
`67cd6fe8d4`, `164204446b`; `integration/w3` is `d6f3281307`, the stage A2 land, plus those three merges and the E3b/E4/R-V3
commits), E3c was merged with `integration/w3` but not landed, and Z4b and Y6 were finished on branches of Hydralysis
(`w2/Z4b` at `903e080`, `w2/Y6` at `2a4d007`, both on `1e6ae67`, which is the head of `integration/w3` there). It changes no
design decision and weakens no gate. Sections 8.6 and 8.7 are not rewritten: where a status or a sentence of either is
superseded, this section says so and governs. The facts come from the package reports of the stage; **the reports of R-V3,
Z4b, E4, Y6 and E3c reached this revision clipped** (the tail of the report is missing), so a field that a clipped report did
not show is not recorded, and each such report is marked "clipped" below. A fact that no report stated is not recorded;
the commit lists were read from `git log` on `integration/w3`. Nothing is pushed. `prove_disjoint_rev8.py` (Hydra inventory
`c55c5e3568`, Hydralysis `c059a46`, the site repository at `D:/Projects/hydra-engine-site`, the core inventory the Hydra
repository at `b6df709e1e`) and `examples/check_ownership.py` both exit 0 on this file after the 8.1 edits listed in part (1):
133 matrix rows (one row is new: the E3a golden `e3a-busy.json`, A31), 52 packages. The proof needed the site repository
path as an argument: the `F:` drive no longer exists and the proof's default site path (`F:/Projects/hydra-engine-site`) does
not resolve.

**(1) Ownership amendments.** Continues 8.7 after A28. "Where" names the 8.1 row that changed. R-V3 is a fix package of this
stage that is not among the 52 package ids; like F1 in 8.7, its amendments are a note in the owner's cell, so that the id
list of the proof stays at 52. E3b, Z4b and Y6 reported no amendment. E4 repeated one (A31); E3c reported A25 again (already
recorded) and one new one (A32).

| Amendment | File | Package, wave | Reason | Where in this file |
|---|---|---|---|---|
| A29 | `support/ghidra_session.py` (owned by P1b then E3c): the Toolhelp signatures (`CreateToolhelp32Snapshot.restype`, `Process32FirstW` and `Process32NextW` `argtypes`) are set once inside the locked `_pe32_class()` instead of on every `_children_of` call; this builds on the earlier R-V3 commit `0f9104db01` | R-V3 (fix package), landed `67cd6fe8d4` (commit `225b23cce5`) | the integration check V3 found `e2a_kill_fork` failing: the structure class was made on every call and the signatures were set on the shared kernel32 functions from several threads. A25 recorded the same defect for E3c; the final code names the function `_pe32_class()`, not `_toolhelp()` (part 4, item 20) | 8.1 (`ghidra_session.py` W4 cell, a note naming R-V3) |
| A30 | `examples/daemon_tests.py` (E0's file, with the E3b cell of A24): a `Skipped` exception and a `skipped` status (also for notes that start with "skipped"), printed `SKIP`, counted apart in the tally (`N/M passed, k SKIPPED (names)`) and not failing the run; a new `Ctx.release()` that runs before the daemons of a failed test are stopped (the report is clipped after "runs befo", so the rest of this item is not recorded) | R-V3 (fix package), landed `67cd6fe8d4` (commits `436414ea1c`, `44cfdb7c3f`) | the three failure groups of the hosted runner run 40831873385: a skipped test counted as ok, daemons of a failed test left running, and the P1b cases D and N that need a breakaway the hosted job object does not give | 8.1 (`daemon_tests.py` row, W3 cell, a note naming R-V3) |
| A31 | `examples/characterization/v3/e3a-busy.json` (E3a's golden, recorded in W2): re-recorded in `48d3da27b9`; the only difference is the four new reply keys `isolation`, `lane`, `attemptedChanges` and `attemptedChangesCount` of a protocol 3 `script` reply | E4, W4 (landed `164204446b`) | E4 adds those keys to the reply (3.4); a golden recorded at the E3a base cannot be `identical` without them | 8.1 (new row after `characterization_tests.py`: E3a in W2, E4 in W4) |
| A32 | `S/Session.java`: `completeLeaves` closes the idle project through `registry.closeIdle(...)` instead of the hunk of `integration/w3` (`synchronized (registry)` plus `closeProjectEntry`); a semantic resolution of an auto-merged hunk | E3c, W4 (not landed, inside merge commit `3eaea8840c`) | no monitor over a project close (BP8) | 8.1 (`S/Session.java` row, W4 cell) |

Items that are **not** rows: (a) the `ProjectCommands.java` conflict that blocked E5 (8.7 (1) item a) was resolved by E3c in
the `leaveProject` hunk of merge `3eaea8840c`; the report is clipped before it describes the resolution, so the choice made is
**not recorded here** and the reviewers must read the merge. It is inside E3c's row and changes no ownership. (b) R-V3's commits
also changed `examples/dt_e2.py`, `examples/cc_e2.py`, `examples/char_e2.py` (E2's test files) and `examples/dt_p1b.py`
(P1b's), and `integration/w3` carries `6d9cf93c89` (`dt_e2.py`: the ReFS scratch directory comes from `HYDRA_REFS_SCRATCH`).
None of the reports lists them as amendments, the checker names no violation for them, and no matrix row exists for a `dt_`
file; they are recorded as a fact only. (c) The wording amendment A28 (3.4 and 6.2, the overlay `script` sentences) is still
**not applied** to those sections: E4 is landed now, but this revision edits only section 8 (part 4, item 15).

**(2) Spike outcomes.** No spike was run in stage A3. The figures below are those of 8.6 (2) and 8.7 (2), repeated with the
decision each took and where it stands. All stay load-affected: gate 9.20's "quiet machine" part is still **not met** by any
of them. One fact changed: the `F:` ReFS volume was ejected on 2026-10-29, so "ReFS untested" (SP1) is now also "no ReFS
volume on this machine"; tests that need one are skipped when `HYDRA_REFS_SCRATCH` is unset.

| Spike | Numbers | Go or no-go | Decision taken, and where it stands |
|---|---|---|---|
| SP1 read-replica opens (E11) | 8 runs, 1,720 saves, 60 kills of the saving daemon: 0 corrupt reads, 0 saver failures, 0 unexpected exceptions, 0 unopenable newest versions; 1.5 to 4% of fresh opens refused at about 2.5 saves/s, each a clean "file not found" that one `refresh` and retry cleared (76 of 76 on the second attempt); NTFS on D: only, ReFS and power loss untested | GO with conditions | E11 is built with refresh-and-retry in the open path and never claims "never refused". E11 is not started |
| SP2 overlay views against fork views (E10) | KotOR copy, 8,966 functions, 122 MB: about 6 MB per view against 170 to 190 MB; first edit about 1.5 to 2x faster at N=4 and N=12; heap a tie within noise; the 1.5 GB case not run | NO-GO for E10 now (go only if both measures win) | E10 does not start; a conditional GO needs the owner to relax heap to "not worse" |
| SP3 D60 job object and D65 spawn sequence | real `hydra-integ` daemon, every variant passed in two full passes at 23 to 100% total CPU; negative controls gave the opposite result | GO for D60 and D65 | P1b (landed) and E9 keep the sequence as written. The P1b task-route reading of D65 is still the owner's decision (8.6 (4) item 7). R-V3 shows a second environment where the breakaway route does not work (a restricted job object): cases D and N of `p1b_daemon_survives_launcher_exit` now SKIP there (A30) |
| SP4 in-process decompiler recreate (E9) | 6 runs, about 1,100 cycles with `decompile.exe` killed by `TerminateProcess`: 0 poisoned decompiles, 0 hung threads, no linear handle growth up to 450 cycles; the "other client" was a thread; no calm machine | GO for the in-process part of E9 | E9 builds the in-process recreate; daemon-level isolation needs its own test. E9 is not started |
| SP8 separate read-only instances (E11) | KotOR copy, `hydra-integ`: DB-bound reads scale about 2.4 to 3.5x at K=4 to 8 (4.6x best, 2.3 to 3.0x worst); one shared instance stays at about 1.0 to 1.2x; at K=8 separate against shared is a median 3.0 to 6.3x; the earlier 4.1x is not reproduced in the median; decompile gains nothing | GO for E11, conditional and load-sensitive | E11 uses separate instances of the one stored file. E11 is not started |
| SP10 worker JVM start (E7) | median about 4.3 s calm and 6.4 s under heavy foreign load to a trivial script; 350 to 450 MB resident per worker; 12 concurrent workers all succeeded (13.6 to 26.8 s each); `TerminateProcess` ends a deaf worker in about 50 ms (1) or 0.1 to 2.0 s (12 at once); AOT and class-data sharing give no usable gain; cold start NOT measured | GO for E7 on `hydra-integ` | E7 builds the worker route with no AOT or CDS. E7 is not started |

**(3) Per-package status.** "Landed" means merged into `integration/w3` of its repository; the merge commit is given. Where a
row differs from the same package in 8.6 (3) or 8.7 (3), this row governs. A count is the report's. A report that was clipped
is marked.

| Package | Landed | What its tests showed | What remains open |
|---|---|---|---|
| E3b (Hydra) | yes, `8c9df389a8` | accepted by the independent review of stage A2 (round 2: accept, 0 blocking). Two landing attempts failed only because the Gradle daemon died with "device not ready" on the removed `F:` drive; the report states no test count for the landing | nothing stated by the report. **BP9 is still open** at this revision because the E3c waiter caps are not landed (item 24); the ownership-bits decision and review findings 2 and 3 of 8.7 (1) item b are not shown to be recorded in 3.5 |
| R-V3 (fix package) | yes, `67cd6fe8d4` | all three failure groups of the hosted runner run 40831873385 fixed in tests and test tooling, no Java changed. The full `daemon_tests` run on NTFS (E:) gave 86 of 88 passed, 1 SKIPPED (`legacy_overlay`), 1 FAIL (`e2a_handle_holder` under foreign load) that passed on its one allowed rerun. The merge of `integration/w3` was clean (it changed only `examples/dt_e2.py`); `baseSha` `e0bcee7716`. Report clipped | the hosted runner was not re-run (no push): the fixture owner is simulated with a copy owned by `runneradmin` and the restricted job with a job object, so the hosted run must show SKIP for `p1b_daemon_survives_launcher_exit` (D and N); `sidecar_unfinished` is still probabilistic (it needs the polling holder in a window of a few milliseconds within 5 attempts) and on a much slower runner can fail with "the premise never held", an honest failure, never a pass; more is clipped |
| E4 | yes, `164204446b` | merged with `integration/w3` without conflict; the package suites pass on the rebuilt install; no new E4 code and no commit beyond the merge in this stage. In the dedicated `dt_e4` run `runaway_bounds` failed once at `dt_e4.py` line 802 ("the owner is still limited after the deaf script ended"): the reply was `cancelled` with "wall budget scriptMaxS (6 s) exceeded" after 9.98 s, and a `TestSleep` script asked to sleep 10 ms printed "start" and did not finish for about 10 s. Report clipped | the cause of that stall is **not found** (most likely a stall of the script thread or the JVM under foreign load; the report is cut off at the load figures); the test was not loosened; the wording amendment A28 (item 15); the E4 report of stage A2 listed `e2a_kill_fork` as environmental, and it was a defect (A25, A29) |
| E3c | **no** (merge `3eaea8840c`, status partial) | `integration/w3` (`8c9df389a8`) merged into `w2/E3c` and rebuilt; the package tests and the suites re-run; the full daemon suite is **109 of 112**. Report clipped | the three failures are timing tests under heavy foreign load (other agents' `java.exe` processes and a shared Gradle daemon since 08:30): `legacy_overlay` (a comparison of two small numbers; 455 ms against 143 ms on the rerun; passes alone), `sidecar_unfinished` (12.85 s and then 5.91 s against 1.6 s expected in the full run and the 3-test rerun; 3.40 s alone on `h-E3c`; passes on `h-E4` with the same test code; cause not found), and a third that the report does not show. **The red-table rows BP4, BP5 and BP6 are still RED**; the E3c waiter caps are therefore not shown to close BP9. The `leaveProject` resolution (part 1 item a) and A32 need review |
| E5 | **no** | no report this stage; 8.7 (3) stands (blocked at setup; the `ProjectCommands.java` conflict is now resolved in E3c's merge, but E3c is not landed, so E5 still cannot start from `integration/w3`) | everything in 8.7 (3) |
| Z4b (Hydralysis) | **no** (`w2/Z4b`, `903e080`; commit "audit_harness: end the audited server's whole process tree before removing its private root") | cause: `tools/audit_harness.py` `launch()` ran the audited server with its cwd set to the private temp root and ended it with `terminate()` only; on Windows a cwd pins the directory and a helper the server started kept it, so the cleanup raised `WinError 32`, the tool died without JSON and two tests failed. Fix: the server no longer gets the root as its cwd; `stop_tree()` ends the whole tree (`taskkill /T /F` on Windows, `killpg` elsewhere) before stdin is closed. The `WinError 32` was reproduced with a deterministic test on Python 3.15; the full suite had 4 failures on the first run (two `test_durable` cross-process tests, `test_evidence` `test_concurrent_writers_all_land` with `LockBusy` timeouts, `test_exporting` `test_job_json_is_not_rewritten_for_every_row` with 4 writes against a limit of 3) and all 4 passed on one rerun; the first run took 3,541 s with a dozen other agents active. Report clipped | the original CI failure was on Python 3.11.9 and **was not reproduced**: Python 3.11 is not installed here (oldest used 3.12.14), only the equivalent mechanism was; hosted CI on 3.11 must confirm; the four load-sensitive tests are not shown to be deterministic fixes |
| Y6 (Hydralysis) | **no** (`w2/Y6`, `2a4d007`) | the 8.7 HVF error `EngineCommit.test_commit_round_trip_archival_and_revert_chain` ("no pending record to commit") was a **test** defect, not a Y5 regression: since Y5 (D43, D59) a call with neither `view` nor `as` runs in the caller's own per-agent view; `edit()` goes through `runner.query` and lands in the agent view while `commit()` called `commits.run_commit` on the shared view `""`, which holds no records. The product path (`QueryRunner._commit`, `type_edit kind=commit`) uses the caller's own view as D43 requires. The fix is test-only (`tests/test_engine_integration.py`; commit message: the test names the shared view and adds an own-view commit guard). Report clipped | the unit suite is **not green** in this session: `test_exporting.ExportTests.test_job_json_is_not_rewritten_for_every_row` (8 job-json writes against a bound of 3 in the full run, 7 on the rerun) and `test_runtime_capture.CaptureWindow.test_state_is_published_at_a_bounded_rate_not_per_message` (128 != 300 in the full run, 10 not less than 6 on the rerun) fail again on isolated reruns. Both assert a rate bound and look load-sensitive, and the Y6 diff touches only a file neither imports, but the report did **not** confirm this on the base commit `1e6ae67` (clipped there). The same `test_exporting` test failed once in Z4b |

Packages and fix packages that this stage did not touch keep their 8.6 (3) and 8.7 (3) rows. Whether Y4a is closed is still
not stated by any report.

**(4) Statements of this file that the implementations proved wrong.** Numbering continues from 8.7 (4) item 17.
18. 8.7 (3) lists E3b and E4 as not landed. Superseded: both are landed on `integration/w3` (part 3). E3c is not, and 8.7 (1)
    item a (the `ProjectCommands.java` conflict) is resolved in E3c's merge, not in a landing.
19. 8.7 (3) HVF row and 8.7 (4) item 17 call the `EngineCommit` error "a suspected Y5 regression". Wrong: the test was wrong and
    the product was right (D43, D59); Y6 fixes the test (part 3). 8.7 (3) Y5 row says "Suspected regression: see the HVF row";
    that suspicion is withdrawn. The sentence of 8.7 (3) HVF row that the Y5 landing "is therefore not clean against a real
    engine" no longer stands for this error; the real-engine claims of Y5 that no test ran (eviction, `close_project` discard,
    `status.projects`, the real busy refusal) stay unverified.
20. A25 (8.7 (1)) says E3c adds a `_toolhelp()` function. The code on `integration/w3` has no `_toolhelp`: the one structure class
    and the one-time signatures live in `_pe32_class()` (`_PE32`, the lock `_K32_LOCK`). Both R-V3 and A29 name `_pe32_class()`.
21. 8.7 (3) E3c and E4 rows call `p1b_daemon_survives_launcher_exit` "environmental" (`WinError 5` on the breakaway route) and
    `e2a_kill_fork` "environmental" (E4). Part of that was wrong: `e2a_kill_fork` was a product-side race (A25, A29). The breakaway
    failure is an environment property and the test now SKIPs it (A30), which is a test-tooling decision, not a fix of the
    route; it does not close the P1b task-route question of 8.6 (4) item 7.
22. Section 8.6 (3) Z4 row names the Z4 flake as "`PermissionError [WinError 5]` on the rename of the unpacked directory, once".
    The hosted-runner failure of `audit_harness.py` was `WinError 32` on the cleanup of the private temp root, a different
    mechanism; Z4b fixes it (part 3) and does not claim to have reproduced the 3.11.9 failure.
23. `F:` is gone. Lines of this file that name it are out of date and are **not edited here** (this revision appends only):
    the site repository path `F:/Projects/hydra-engine-site` (the Site table heading in 8.1, and the S1 and S2 notes) is now
    `D:/Projects/hydra-engine-site`; OD3 names two daemons at `F:\dev-cache\...` that no longer exist; the history row of
    OD14 names the same path; and `prove_disjoint_rev8.py` has the old path as its default `--site-root`, so it must be run with
    the argument shown in the introduction of this section. Gate wording about a ReFS volume stays; a ReFS test is skipped, not
    passed, when `HYDRA_REFS_SCRATCH` is unset.
24. 8.7 (4) item 12 ("BP9 is open") stands. The E3b waiter caps are landed; the E3c caps are not; BP4, BP5 and BP6 are still
    RED in the E3c report. No sentence of this file may say BP9 is closed, and gate 9.1 and the full `conc/red_table.py` were not
    rerun in stage A3 by any report.
25. 8.7 (4) item 13 and A28 (the 3.4 and 6.2 sentences on an overlay `script`) were to be written "when E4 lands". E4 is landed
    and the text of 3.4 and 6.2 is **still unchanged**; this revision does not edit them (docs append only). The sentences listed
    in item 13 are therefore a debt, not text. One more fact for them, from the E4 stage report: the E3a golden `e3a-busy.json`
    now carries `isolation`, `lane`, `attemptedChanges` and `attemptedChangesCount` on a protocol 3 `script` reply (A31).
26. The 8.7 (3) E3c and E4 rows say `p1b_daemon_survives_launcher_exit` fails for environmental reasons. Superseded for the
    hosted runner: with A30, cases D and N SKIP and the tally shows them as SKIPPED. A skipped case proves nothing; the survival of
    a daemon after its launcher exits is **not demonstrated** on a runner whose job object forbids breakaway.

**Gates.** No gate of section 9 is weakened, none is flipped to passing by this revision, and no sentence of the engine or
Hydralysis documents is strengthened by it. Gates and rows that still need work: 9.1 and the BP9, BP4, BP5 and BP6 rows (E3c,
E5), gate 9.20 (quiet machine), the power-loss claim (E12, 8.7 (4) item 15), the hosted-runner confirmation of R-V3 and Z4b, the
load-sensitive Hydralysis tests named in the Y6 and Z4b rows, the A28 sentences, and the Hydralysis real-engine run of Y5/Y6
(none ran in this stage).

### 8.9 Revision 8.5: the E9 amendments (finishing round, `w2/E9b`)

Revision 8.5 records the ownership amendments of E9, which `integration/w3` carries since the merges `f194c2ed9b` and
`57fd751d5e` (E9 commits `e321eca763`, `256a9f784f`, `c1a0bff962`, `fc8fd7e3d0`, branched from `47a43f6b06`). It changes no
design decision and weakens no gate. `examples/check_ownership.py --package E9 --base 47a43f6b06` on the E9 branch reported
5 violations (14 changed files, 5 outside its rows) before the 8.1 edits below and 0 after them; the matrix check reports
136 rows, 52 packages, 0 violations (three rows are new: `S/Guarded.java` and `S/Watchdog.java` are split from their former
shared rows, and `S/QueryCommands.java` had no row).

| Amendment | File | Package, wave | Reason | Where in this file |
|---|---|---|---|---|
| A33 | `S/Session.java`: `Governor.admit(c, cmd, req)` before the slot wait in the dispatch of a request, its reservation closed on every exit; `reap(long warmMs)`, the overload of `reap()` the governor calls with 0 before it refuses an open | E9, W5 (after E5) | 3.11 puts the admission seam before `open_project`, `open_program`, `fork_project` and `import`, and E1 built no `Hooks.Admission` call site that an E9 class could fill; reclaiming idle views before a refusal needs a retention of 0 | 8.1 (`Session.java` W5 cell: E5 **then** E9), E9 Files |
| A34 | `S/Health.java`: `state` is `degraded` while the governor is above the hard watermark; `debug_stall` `what:"thread"` plants one fault in the next lap of a guarded thread (test hooks only) | E9, W5 (after E5) | 3.11 says the daemon is `degraded` above 85% and 3.13 reports it in `health.state`; the restart of a guarded thread cannot be tested in a running daemon without a planted fault | 8.1 (`Health.java` split from `Watchdog.java`, W5 cell: E5 **then** E9), E9 Files |
| A35 | `S/Advertised.java`: the capability name `admission`; the limit names `minXmxMb`, `maxViews`, `maxViewsPerClient`, `heapSoftPct`, `heapHardPct`, `nativeBudgetMb`, `viewDiskBudget`, `diskReserve`, `decompilerIdleS`, `decompilerWaitS`, `decompilerFailLimit`, `decompilerNegativeS` | E9, W5 | `Advertised` declares every name up front and throws on an undeclared one (3.1); 3.11 requires every value in `hello.limits`. The values are set from `Governor` (E9's file); `examples/char_e9.py` and its golden `e9-limits.json` assert them (3.1: each package in its own `char_<package>.py`) | 8.1 (`Advertised.java` W5 cell), E9 Files |
| A36 | `S/QueryCommands.java`: the circuit breaker before the decompiler borrow in `decompile` (the negative cache), the fault classification after it, and `decompiler_failed{function, entry, reason, retryable, negativeCache}` with `retryAfterMs` for a protocol 3 client (a protocol 2 client keeps `completed:false` and `error`) | E9, W5 | 3.11 "Decompiler faults" needs the outcome of one decompile, which only `decompile` sees; the borrow sites named in E9's Files (`ProgramEntry`, `Overlay`) hand out the decompiler and never see the result | 8.1 (new row), E9 Files |
| A37 | `S/Guarded.java` (new): created by E9, not by E1; E1's W1 cell said "`Hooks.Admission` and `Guarded`, both inert", but no `Guarded` class existed before `e321eca763` | E9, W5 | 3.11 "Daemon threads" (restart with backoff, counted in `health`, the 8 MB emergency reserve) is E9's behaviour; the file is new and has no other editor | 8.1 (`Guarded.java` split from the E1 row; the E1 cell keeps `Hooks.Admission` only), E9 Files |

Items that are **not** rows: (a) E7 (`5e5f95cb37`) added one line to `S/Session.java` (`Health.contribute("scriptWorkers", ...)`)
although its package text says "E7 does not edit `Session.java`"; it is not an E9 edit, so this revision records it as a fact
and leaves the cell to E7's amendment. (b) BP22 (3.10) names "`-Xmx` laps" as its red test, not a script of `examples/conc/`:
`conc/red_table.py` has no BP22 row, and `--only BP22` runs nothing. Its laps are `dt_e9` `e9_gate` (a third decompile
waits, then `busy{capacity, resource:"native"}`), `e9_admission_256` and `e9_admission_512`; they and the X9 plant of
`dt_x0` (`oracle_selftest`: X9 flagged `K7:orphan_decompiler`) pass on the E9b build. Red on hydra.3 is shown for the
containment test by its no-job control (`e9_job_containment`), not by a hydra.3 run of `e9_gate`.

### W0

**X0 (Hydra, L): the oracle, the regression suites and the red table.**
Goal: verification before any fix (D48): every guarantee of 6.1 has a test that can fail, and every fix of
revision 6 has a test that was red on hydra.3.
Files (8.1): new `examples/oracle.py` (the invariants K1-K17 of 3.12, a tree hash, a header-magic scan, a 50 ms
watcher for any visible invalid final-named version file, the witness ledger, the sequential model fold, residue
accounting, the evidence writer), `examples/chaos_lib.py` (the injectors: kill a client, kill the daemon at
random and trigger-timed, suspend and resume, kill a native decompiler, a handle holder, and the disk-full seam of OD13: no quota volume; a patched write that raises `ENOSPC` on the Hydralysis side and `diskReserve` set above the free space on the engine side),
`examples/conc/` (the measurement scripts imported as repeatable regression suites: the lock-map scenarios `s1`
to `s13` and the helper `hx`, the capacity harness `lanetest`, `ramp`, `forkcost`, `savetest`, and the crash harness
`run_c`, `run_ef`, `c_lib`), `examples/dt_x0.py` (the self-test).
Depends on: E0. Parallel with: R0, S1, Z13a, Y0a-Y0d.
Surface: none (no engine file is edited).
Tests: the self-test plants X1-X11 (3.12) and the oracle must flag X1-X5 and X7-X11 and pass X6; it runs against
the nine kept corrupt forks of `crash-C` (the zero-header newest version files) and against an unkilled
control; each imported scenario reproduces its recorded defect on `hydra-3-candidate` and on `hydra-session-after`
(the red table, with the recorded numbers beside the new ones) and is deterministic in two runs; every daemon uses a
fresh state root under `D:/Projects/Hydra/_logs/<stream>/` and the F: KotOR original is never opened (copies
only, its tree hash `6d8ced789b9f0945ee2ade42e75cf6db0a92c97ea4e65b8a353fd624860240df` is checked before and after).
Acceptance: gate 9.12; the red table is committed as a stream report, not into the repository.

**Manifest (revision 8.1, A8).** X0 needs no `certification.manifest` line for the files it creates: `buildHeadless` runs the
`ip` task of every module (`assembleDistribution` depends on it, `gradle/support/ip.gradle`), the task scans every file under
the module directory including `examples/`, and it reads the IP of a `.py`, `.ps1` or `.java` file from an `IP:` header in
its first four lines; only a file of a type that cannot carry the header (`.json`, `.md`, `.properties`) needs a manifest
line. X0 creates `.py`, `.ps1` and `.java` files only, each with the header. A package that adds a JSON, Markdown or
properties file (E2's vectors and fixtures, any `v3` golden) appends its line.

**R0 (Hydra docs, M): the wording pass on the engine documents.**
Goal: the engine documents say what is true today and nothing stronger (D52), and say that there is no GUI.
Files (8.1): the module `README.md` (the "window" comparisons and the sentence that a Ghidra window can read the
project; the claims C1-C7 of 8.3 for the lanes, scripts, dead clients and cancel), `ARCHITECTURE.md`, and at the
repository root `/README.md` (the line that names the full GUI build) and `/CHANGELOG.md`.
Depends on: none. Parallel with: X0, S1, Z13a.
Surface: none.
Tests: a grep gate over the listed files for the banned phrases of D52 and for "GUI" or "window" used as a
recommendation; each replaced sentence names its claim id. Acceptance: the replacement texts of 8.3 are applied.
No claim becomes stronger. **Revision 8.1 (A8): R0 does not edit `tests/test_claims.py`; the grep gate over R0's files is owned by Z13a's tests/test_claims.py (Hydralysis, W0, 9.19), and for the site by the site claims gate of S1 (9.19); R0 has no test file.**

**S1 (site, M): the wording pass on hydrare.dev.**
Goal: the website, which is where the strongest false claims live, says what is true today.
Files (8.1): `src/routes/index.tsx`, `src/routes/changelog.tsx`, `src/routes/integrations.tsx`,
`src/docs/pages/projects.ts`, `src/docs/pages/scheduling.ts`, `src/docs/pages/architecture.ts`,
`src/docs/pages/mcp-server.ts`, `src/docs/pages/core-concepts.ts`, `src/docs/pages/installation.ts`,
`src/docs/pages/evidence-ledger.ts`, `src/docs/pages/quick-start.ts`, `src/docs/pages/clients.ts`,
`src/docs/pages/api-reference.ts`, `src/lib/site.ts`, `src/lib/llms.ts`, `src/lib/seo.ts`,
`src/components/landing/Hydralysis.tsx`, `src/components/landing/HowItWorks.tsx`, `src/routes/embed/how-it-works.tsx` (the repository had no owner in
revision 5).
Depends on: none. Parallel with: X0, R0, Z13a.
Surface: none.
Tests: a grep gate over the site source for the banned phrases; the 25 claims of 8.3 each map to a sentence
changed or kept. Acceptance: no sentence of the audit's 45-claim list stays CONTRADICTED; panels that are
illustrations are labelled so; the unsourced figures (journal 1.9 ms, 12 functions 3 ms, 55 as seconds) are
removed; the non-PE demo targets (a jar, an ELF, an ARM image) are not shown for Hydralysis. **Revision 7 (OD14, decided):** S1's wording edits are prepared on a local branch of
`F:/Projects/hydra-engine-site` and are **not deployed**; deploying hydrare.dev stays an owner action, and S2 follows the same rule.

**Z13a (Hydralysis, S): wording and the claims ledger.**
Goal: C1-16, C1-50, C1-51, C2-30, C2-50 of the audit that need no engine change, and a ledger that makes the numbers
checkable.
Files (8.1): `README.md` (the "Ghidra GUI" section and the claims C2, C3, C9 of 8.3), `THIRD_PARTY.md` (the GUI
sentence), `docs/golden-harness.md` (one phrase), `skills/hydralysis/SKILL.md` and `skills/ghidra-project/SKILL.md`
(the contained-script sentences), new `docs/data/claims.json` (one row per claim: id, text, class, evidence path, the
package whose test flips it), new `tests/test_claims.py`.
Depends on: none. Parallel with: X0, R0, S1.
Surface: none.
Tests: `tests/test_claims.py` fails when a ledger number differs from its source: the catalog size generated from
`tool_table()` (8,172 bytes against the limit 8,192), the KotOR counts 8,966 / 8,616 / 60, the X0 baselines, and when a
claim marked "gated" has no passing test. Acceptance: it passes; the no-stock tests keep passing (the files must
never spell the stock-install names). **Revision 8.1 (A8):** the same test carries the grep gate for the banned phrases of D52
over the engine documents that R0 edits (the list of 9.19); R0 has no test file of its own.

**E0 (Hydra, M): failing tests first and the test loaders.**
Goal: baselines and loaders before any engine change.
Files: `examples/daemon_tests.py` (loader for `dt_*.py`, `--only` over them), `examples/characterization_tests.py`
(`--protocol {2,3}` sent in `hello`; loader for `char_*.py`; goldens dir `characterization/v3/`),
new `examples/dt_baseline.py`, new `examples/check_ownership.py` (the 8.1 assertion; its package-id parser is fixed by E1, section 8),
and the seven v2 goldens `examples/characterization/*.json` (8.1; two were re-recorded once, below, and six again by amendment A1).
Depends on: the hydra.3 install (`D:/Projects/Hydra/_engines/hydra-3-candidate`).
Parallel with: Y0a-d.
Surface: none.
Tests (each **must fail on hydra.3 for the stated reason**; a test that does not fail on its premise is
recorded as a finding and dropped, not weakened): `lane_starvation` (`maxLong=2`, two long sleep scripts,
ten RusticQuery-style scripts with a `timeout`: they queue behind the sleeps, `Scheduler.java:61`);
`dead_client_lock_wait` (a client killed while blocked in `wait=3600000` on a program lock stays
registered until the lock frees: `Connection.java:101`); `import_wait` (`maxImports=2`, `maxLong=2`: a
queued import reaching the front fails `busy` after 10 s: `ImportCommands.java:112`);
`script_shared_visibility` (a mutating contained script and a concurrent reader: expected to show the
transient write; if it does not, the premise "readers can observe transient writes" is dropped from
3.6; on hydra.3 it did show it: 94 of 115 polls, so the premise stays); `fork_save_behind_analysis` (timing of `fork_project`/`save` while the long lane is saturated);
`cancel_lock_wait` (a request waiting on a program lock is cancelled by id: today it keeps waiting and
ends `busy` when its `wait` ends, `ProgramEntry.java:195`; this is the premise of V5 and of 3.5's
cancel-aware waits).
`import_wait` must fail on its premise for the **third** import, the one that reaches the front: it
shows about 20 s (10 s in the gate and 10 s for the slot), not merely `busy` at 10 s for every import
(the first two fail at 10 s because they were admitted to the gate at once); the test asserts that the
slowest import ends within `SLOWEST_IMPORT_MIN_MS` 19000 .. `SLOWEST_IMPORT_MAX_MS` 23000 ms **and** that the
spread between the slowest and the fastest is within `SPREAD_MIN_MS` 8000 .. `SPREAD_MAX_MS` 12000 ms
(`dt_baseline.py:55-58`, as committed in `f47ff15934`); any other observation that is busy at 10 s is a plain
failure that carries its observation, so a loaded machine that pushes the slowest import past 23 s turns a
CONFIRMED baseline into a failure, never into a pass. The evidence keys are `earlierImportsMs`,
`slowestImportMs`, `spreadMs` and the two bounds (`:361-365`); the failure paths of the new bounds have not
been exercised on a real failing observation. `characterization_tests.py --protocol 3` against an engine that serves no v3
returns a SKIP (exit 0) unless `--require-v3` is given; **gate 9.3 always passes `--require-v3`**.
Acceptance: the seven scenarios report `identical` at `--protocol 2`; the tests fail on hydra.3 as stated,
or, for a premise that does not hold, are dropped from the design and recorded as a finding (E0's
own convention above; at `c774d9e7b1` all six were `CONFIRMED` on hydra.3 in two runs,
`D:/Projects/Hydra/_logs/E0/baseline1.log` and `baseline2.log`); the loaders work with an empty `dt_*.py`
set. Exit codes verified.

**The v2 goldens and the copied project's total size (E0 follow-up `f47ff15934`; revision 5).** The two
goldens `fork_refresh.json` and `overlays.json` carry the byte total of the project that `fork_project` and
`refresh` copy (`"bytes"` in the dicts that also have `mode`). That total is **not a function of the request**:
the fixture project stores each program's `FILE_ID` three times (in `~index.dat`, `~journal.bak` and the `<n>.prp`
file), and Ghidra builds the id as `hex(host IPv4 octets) + hex(port) + System.nanoTime()`
(`FileIDFactory.java:33-54`), so its length follows the address the host resolves to: a machine resolving to
`100.123.249.118` gives 27-character ids and 4,425,400 bytes, and two earlier project directories differed by
18 bytes (4,425,382) in four files (6 occurrences of 3 characters). A golden that records the total therefore
fails 5 of the 7 scenarios on a machine whose address changes. `characterization_tests.py` now **masks
`bytes` in a dict that also has `mode`** (the fork descriptor and the `fork_project` and `refresh` answers; the
value must still be a positive integer, so key presence, key order and the `files` count are compared); the two
goldens were re-recorded on `hydra-3-candidate` with exactly 14 lines changed (`"bytes": <n>` to
`"bytes": "<masked>"`, 11 in `fork_refresh.json` and 3 in `overlays.json`; the other five goldens and the 317
requests are unchanged), and the program-file sizes (`1032192` and `1179648`, multiples of 4 KiB) stay
unmasked. Verified at 7/7 identical on the refactor build, on hydra-3-candidate in work directories of
different path lengths and on a simulated 24-character fixture (which failed 5 of 7 on the unmasked script,
only on the `bytes` lines). Accepted trade-off: a regression in the **size** of what a fork copies is no longer
caught by the goldens (the `files` count still is). That the earlier 24-character ids came from a 5-hex-digit
address is an inference from the lengths, not an observation. The same commit adds
`characterization_tests.py --selftest` (9 checks) and `daemon_tests.py --selftest --ghidra <install>` (15 checks
of the client-protocol shim).

**Amendment A1 (revision 7, D62): the scheduler capacity numbers in the v2 goldens.** Six of the seven goldens record
`status.scheduler.quick.slots` and `long.slots` (24 and 6 on the recording machine) in 20 places (`clients` 2,
`fork_refresh` 2, `import_script` 4, `overlays` 2, `readonly` 4, `session` 6; `edits.json` has none). `slots` is not in
`VOLATILE` (`characterization_tests.py:150-169`), the long default follows the CPU count, and E3a (W2) raises it (D40)
while these files are E0's in W0 only (section 8, rule 3) and gate 9.3 requires them `identical` at protocol 2. E0
therefore masks `slots` when it is a key of a lane dict under `scheduler` (the value must still be a positive integer,
so key presence, key order and the lane shape are compared, as for `bytes` above) and re-records the six goldens once on
`hydra-3-candidate`: exactly the 20 `"slots": <n>` lines change to `"slots": "<masked>"`, and the amendment's diff script
fails on any other changed line. E3a edits no golden; the number itself is asserted by `cc_e3a` `v2_lane_defaults` (V9).
Accepted trade-off: the goldens no longer catch a regression of the slot counts; that test does.

**Amendment A2 (revision 8.1): the package ids of `examples/check_ownership.py`.** The file is E0's and its pattern was
`[EPYR]\d+[a-e]?`: it could not see `X0`, `S1`, `S2` or any `Z` package, so on the matrix of revision 8 it stopped at the wave
plan ("the package id(s) X0 are not parsed", exit 2). The coordinator changed the script (W1, not a package): the pattern is
the 52 ids of the plan (E0 to E12 with E2a and E3a to E3c, X0, P1a, P1b, Y0a to Y0e, Y1 to Y3, Y4a, Y4b, Y4d, Y4e, Y5, R0, R1,
S1, S2, Z1 to Z15 with Z13a and Z13b; a typo such as Y0f or an invented Y4c is still an error); the wave plan is read in its
three package columns (Hydra, Hydralysis, docs, site and policy); a cell `A **then** B` is the declared sequence and not two
owners; the site table is read as a third repository; the package paragraphs are found by the same pattern. `--selftest` has
36 checks (it had 24), among them every one of the 52 ids and the parse of the spec next to the script. Run against the
package branches the script also showed two more defects, fixed in the same change: a root path of the Hydra table (`/NOTICE-HYDRA`,
`/README.md`, the Ghidra core files) was looked up inside the module, so E8's and R0's files were all reported as outside
their rows; and a row that names a directory (`examples/conc/`) granted nothing, so every X0 file was reported (the directory row of
`examples/characterization/v3/` stays a plain directory: rule 2 gives each golden to the package whose id it carries). The
remaining item of E1's first commit is the resolution of the Hydralysis root documents.

**Amendment A7 (revision 8.1): `characterization_tests.py --client {stock,install}`.** The W1 coordinator (commit
`c37b0e73b4` on `feat/w1-hydra`, not a package) added the option to E0's `examples/characterization_tests.py`. At
`--protocol 2` (the default for the seven v2 goldens) the harness now loads the vendored stock 1.0.0 client
(`examples/stock/ghidra_session_1_0_0.py`, P1a's file), because the goldens record the client's own `clientVersion` 1.0.0 and
the 1.1.0 client made six of the seven differ in that one field; at `--protocol 3` the default is the install's client
(`install`), and `--client stock` with `--protocol 3` is refused. The seven goldens are unchanged (no re-record). This is
recorded here because the file is E0's (W0 row) and the edit came in W1.

**Y0a (Hydralysis, M): durable IO.** Goal: 4.1.
Files: new `durable.py`; `backends.py` (`write_json`); `workcopy.py` (only `_save_store`, `load_store`);
`targets.py` (`register`); `overlayjobs.py` (job record writes); new `tests/test_durable.py`;
`tests/test_address_maps.py` and `tests/test_query.py` (one line each, 8.1).
Depends on: none. Parallel with: E0, Y0b-d.
Surface: none. Ships in 0.5.x against hydra.2/3.
Tests: torn, zero-length, mis-sealed and missing-with-`.bak` files each return the old or new content,
never empty-as-no-edits; the `AppendLog` tests of 4.1 item 3 (CRC-32 from `zlib.crc32`; a cut at every
offset of the last line, then a repairing append; mid-log corruption refused by reader and writer; a
crash inside the repair); `PermissionError` retry through a monkeypatched replace; the grep gate; v2
store loads. Fault: kill a writer process between tmp write and replace (`durable.fault`).
Acceptance: `store_corrupt` raised, not "start empty"; no record-bearing write outside `durable`.

**Y0b (Hydralysis, S): client retry policy and `EngineError`.** Files: `hydra.py` (retry only
idempotent commands after `closed`, `details.ambiguous`; widened `EngineError`; `Engine.capabilities()`
returning `{}` on protocol 2), `tests/fakehydra.py` (connection drop after a mutating call; busy with
holderInfo), `tests/test_client.py`. Review follow-ups **done** in `33cb5ee` and `5018367` (8.2, 7.6): `next` and
`retryAfterMs` are never capped, the lists inside `queue` keep 64 entries, the `unittest.main()` guard is at the
end of `tests/test_client.py`; and one addition that shipped: `Engine.call` pings before the first mutating call
on a connection idle for 30 s (`STALE_S`), so that a dead socket is replaced before the call is sent and is
not reported as ambiguous. Surface: none. Tests: a dropped `apply_overlays` reply is not
re-sent and the marker reconciles; reads are retried. Acceptance: no mutating call is blindly re-sent.

**Y0c (Hydralysis, S): fast/engine pools.** Files: `mcp.py`, `tests/test_mcp_transport.py`.
Tests: four blocked engine calls do not delay `fingerprint` or `disasm`. Acceptance: `MAX_OUTSTANDING`
still answers `busy` with a retry hint. **`MAX_OUTSTANDING` is per lane** (7.6): 8 on the engine pool and
8 on the fast pool, so the total outstanding can reach 16; the hint is text (`retryAfterMs=2000` in the
message) **and** `structuredContent.retryAfterMs` (`49d5bb6`) until the engine's structured `busy` exists.

**Y0d (Hydralysis, S): the one catalog epoch.** Files: `api.py` (`backend.action += doctor, backups`;
`options` bag on `backend`, `ghidra_run`, `job`; pass-through to stub handlers returning
`not_available`), `workflow_help.py`, `tests/test_contracts.py` (catalog hash, `CATALOG_EPOCH`).
Acceptance: `catalog:{epoch, hash}` is reported by `backend action=status`, `help` and `inspect` and by the MCP
`initialize` result (7.7: what shipped; the epoch number is 2); changing the tool table without bumping the epoch fails the test (the hash covers the
tool table only, not `instructions()` or the help output). Later packages never edit the schema. A
non-empty `ghidra_run` or `job` `options` bag answers `not_available` until its handler is registered
(8.2); `cli.py` exposure is Y0e's.

### W1

**E8 (Hydra, M): storage integrity in the Ghidra core.**
Goal: no unopenable newest version file after a hard kill during a save (D42, 3.12).
Files (8.1): `/Ghidra/Framework/DB/src/main/java/db/buffers/LocalManagedBufferFile.java` (`saveCompleted`:
`saveFile.flush()` before `saveFile.renameFile(newFile)`, `:696`), `/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/db/VersionedDatabase.java`
(the check of the newest version at open), `/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/local/LocalDatabaseItem.java`
(revision 8.1, A3: the private-database open path; the class wraps a `PrivateDatabase` when the file system is not
versioned, so the check of `VersionedDatabase` alone would not reach the programs of a fork, and repair-on-open is added here) and the new `/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/store/db/VersionFileCheck.java`
(header-magic validation, the quarantine of a writable disposable fork, the `corrupt_newest` report for a
read-only or sealed tree), `/NOTICE-HYDRA` (the three core files and the added class), `examples/dt_e8.py`.
Depends on: X0 (the oracle and the trigger-timed kill recipe). Parallel with: E1, E2a, Y0e, Y1, Z1.
Surface: none protocol-visible; `repairs[]` in `health` once E5 exists.
Tests: unit tests where the fork runs the DB module's tests; the trigger-timed kill loop of C (kill X ms after the
version folder listing first changes) on NTFS and ReFS; a zero-header fixture (the kept evidence of `crash-C`) opens at
`N-1` on a disposable fork and logs a repair, and a **read-only open of the same tree writes nothing** (tree hash
before and after); SP5: the second `flush()` in `setReadOnly()` is idempotent and the version chain and index are
unaffected; save time before and after (median and p95); the golden decompile diff identical.
Acceptance: 9.15 (at least 400 trigger-timed kills, 0 unopenable and 0 unrepaired); no save-time regression beyond
the recorded noise; the fourth, fifth and sixth patched Ghidra files (the sixth is LocalDatabaseItem, A3) are named in `/NOTICE-HYDRA`, and Z15's guard lists them.

**E2a (Hydra, M): atomic, retryable fork publish and the sweeper.**
Goal: a fork path is absent or complete, and a retry never meets a bare `conflict` caused by the engine's own
half-finished fork (D41).
Files (8.1): `S/ForkCommands.java` and `S/ProjectFork.java` (the order: stage with an intent record, `.rep`, the
sidecar with `state:"publishing"`, `.gpr` last, the sidecar rewritten `state:"complete"`; `rk`; the retry that
resumes or removes the engine's own half fork), new `S/ForkSweeper.java` (the lazy sweep at the first
`fork_project` under a parent directory: dead-owner staging folders, `.rep` without `.gpr` whose intent names a
dead process, `tmp*.tmp`, `tmp*.ps`, `.ghidra.test.lock~~` older than 10 minutes; everything else only reported),
new `S/ForkIntent.java`, `S/Advertised.java` (only the capability name `forkAtomic`, after E1: a `then` cell in 8.1, A4),
`examples/dt_e2a.py`, `examples/cc_e2a.py`.
Depends on: X0, P1a (`cc_e2a.py`) and E1 (`S/Advertised.java`, A4). Parallel with: E8, Y0e, Y1, Z1 (and E1 except for that file).
Surface: sidecar field `state` (every fork ends `complete` here; E2 makes a `generation` fork end `candidate`, D41); capability
`forkAtomic` (E1 registers the names of 3.13 up front; E2a adds the name to `Advertised` when E1's list does not hold it, A4; enabled here); V11 (5.1: a racing publisher answers `conflict`); no other reply
change.
Tests: at least 300 kills (random and trigger-timed) during `fork_project` on NTFS and ReFS: the path is absent or
complete, never `.rep` alone, never without a sidecar, and a retry to the same path succeeds; no staging folder
after the next fork; a client-side kill still leaves nothing (0 of 18 measured); the sweeper never touches a path
whose intent names a live process; `promote_overlay` is untouched (E2); `fork_race_conflict` (V11, `cc_e2a`, the stock 1.0.0 client): six concurrent forks to one
destination give exactly one success and five `conflict` (`fork_in_progress` or `exists`), no leftover staging folder, the
winner's fork opens, and with one shared `rk` all six return the winner's result. The review's 14 trigger-timed kills
(`review-rev6/exp2_fork_kill.json`) did not reproduce a `.rep` without `.gpr`; this batch decides. Acceptance: 9.15 and K6;
the v2 reply goldens identical.

**Z1 (Hydralysis, S): concurrency regression guard.**
Goal: pin the behaviour the owner measured, on the path agents use, before Y1 and Y2 rewrite it.
Files (8.1): new `tests/test_concurrency.py` only.
Depends on: none; **merges before Y1** (Y1 rewrites `workcopy.py` and `revisions.py`). Parallel with: E1, E8, E2a, Y0e.
Surface: none.
Tests: (1) a source guard that `query.py` and `hydra.py` never import `LaneLock` or create `.request.lock`; (2) an
env-gated real-engine test, Barrier-started threads at N = 2, 3 and `maxLong`+1 through `QueryRunner.query`: all ok,
no `busy`, no `EngineError`; (3) `SameAddressRace`: N threads with one `expect_revision` on one address, exactly one
ok, N-1 conflicts, journal +1, plus a two-process variant; (4) `TwoWriters`: each of two clients sees the other's edit
at once; (5) two-author journal; (6) a process killed holding the per-view lock mid-edit does not block the next edit;
(7) **the multithread `_sync` test** (4 and 12 threads building 4 and 12 views in one process; the measured
`no_project` error) marked a known issue until Y2 flips it; (8) N concurrent first-view builds produce one base
build (counted), also marked until Y2.
Acceptance: the file exits 0 in the CI engine job; no timing assertion.

**Y0e (Hydralysis, S): W0 review follow-ups.** Goal: the work that the W0 reviews found but no W0 package
could own (8.2). **Status (revision 5): landed as `8e696e2` on `feat/w1-hydralysis`.** Three items of revision 4
had **already** been done by the W0 follow-up commits on `feat/w0-integration` and were verified, not redone:
the streamed `AppendLog` reads and the every-acquisition tail check with their two-process tests (`2bf90c7`,
`b0b947b`), the `EngineError` cap that exempts `next` (`33cb5ee`, `5018367`) and the `__main__` guard of the
client tests (`33cb5ee`). Files: `cli.py` (`backend` `doctor` and `backups` actions, `--action` as well as the
positional action, `--options` and `--options-file`, passed straight to `api.call`; new `tests/test_cli.py`),
`hydra.py` (`write_daemon_config` through `durable.atomic_write` without a seal), `runtime.py` and
`runtime_worker.py` (`_write` through `durable.write_sealed`; their readers unseal, accept pre-seal files and
fall back to the `.bak`), `tests/test_durable.py` (the ratchet rows of the writers it moves, below; new tests for
the config, the mailbox writers and readers, and the two-process repair test with a rollback append and a
`backups.log` append). Depends on: Y0a, Y0b, Y0d. Parallel with: P1a and E1; **Y1 builds in parallel but
merges after Y0e**, because `tests/test_durable.py` has a second step (8.1). Surface: none. Tests: the
write-gate ratchet of `tests/test_durable.py`: Y0e removes the six rows of the three writers it moves
(`hydra.write_daemon_config`, `runtime._write`, `runtime_worker._write`) and sets the counts of
`test_the_follow_up_table_is_counted` to 2 record rows, 24 keys and 26 call sites (the two `save_overlay` rows
stay until Y1 deletes the function); `tests/test_cli.py` (12 tests), two of which assert the `not_available`
answer through the CLI and are **rewritten by Y2 in W2** (8, 8.2: they assert a stub that Y2, Y4b and Y4e
replace). Its branch is checked with E1's `check_ownership.py` (section 8, rule 4). Acceptance: the full unit
suite green; the AST gate lists no record-bearing writer outside `durable` except the legacy `save_overlay`
(Y1 removes it, 8.2) and the artifact writes of 8.2.

**E1 (Hydra, M): negotiation, identity, error contract, `expect`, `rk`, and the seams.**
Goal: everything the other engine packages build on, with no behaviour change for protocol 2.
Files (8.1): `S/Session.java` (hello negotiation, `info(c)` rendering capabilities, limits and policy from
`Advertised`; the status header; **the `admit` call at `:248` passes the request** and **the call
sites of `ProjectEntry.info(client)` at `:265`, `:333`, `:427` pass the client**; the `case` dispatch
otherwise untouched), `S/Scheduler.java` (only signatures: `laneOf(cmd, req, v3)`, `admit(c, cmd, req, m, waitMs)`
and the `describe(boolean)` overload, all returning today's values), `S/ImportCommands.java` (the
`admit` call at `:112` only), `S/ProjectCommands.java` (the call sites of `ProjectEntry.info(client)` at
`:92` and `:395`), `S/ProjectEntry.java` (the `info(Client)` signature, same value),
`S/UpgradeCache.java` (`currentDbVersion()` moved out, `CURRENT_DB_VERSION` now `DbVersions.program()`),
`S/HydraInfo.java`, `S/HeadlessSession.java` (endpoint and `ready`: `protocolMin/Max`; `paths` set at
start; the generic `-set key=value` flag), `S/Client.java` (`protocol`, `v3()`: written once by the first
`hello`, 3.1), `S/SessionException.java` (all new codes, the `next` and `retryAfterMs` carriers, and the
one busy-details and the one `bad_request`-details helper, conditionals C12 and C13),
`S/Connection.java` (`error()` takes the client and emits `next` and `retryAfterMs` for v3, C10),
`S/Operations.java` (`expect` on signature, data_type, v3 only), `S/EditCommands.java` (`withLastEditor`
fields, `rk`, v3 only), `S/Journal.java` (`rk`); new `S/Identity.java` (paths, platform,
analysisIdentity, cached decompiler hash), `S/Advertised.java` (capability, limit and policy names
declared up front), `S/Settings.java`, `S/Preflight.java`, `S/Hooks.java` (the admission interface and the governor-statistics accessor, both inert), `S/Guarded.java` (a wrapper that restarts a daemon thread after a `Throwable`, unused until E9), `S/DbVersions.java` (`program()` and a
`dataTypes()` that returns `null`; D31, 3.1, 3.2, 3.5, 3.7); `examples/contract_tests.py` (the tests below);
`examples/check_ownership.py` (E1's **first commit**, section 8: the package ids read from the wave plan
table, which fixes `Y0e` and `Y4e`; the `<id>-` golden prefix; refusal of frozen files; the root documents of the
Hydralysis table resolved to the repository root).
Depends on: E0 and P1a (its `cc_e1.py` runs on P1a's loader and vendored 1.0.0 client). Parallel with: Y1, Y0e.
Surface: hello block (3.2), endpoint fields, `expect`/`rk` (3.4), `next`/`retryAfterMs`.
Tests: `examples/char_e1.py` new goldens (hello at protocol 3 with `paths`, `platform` and
`analysisIdentity` masked and `capabilities`, `limits` and `policy` compared as required subsets, 3.1; `expect` conflicts on signature and data_type
with the same key order as rename; `rk` replay with the reconstructed reply of 3.4);
`examples/contract_tests.py` (a protocol-2 hello is answered byte-identically to the committed shape;
endpoint `protocol:2` + `protocolMax:3`; a request for 9 is answered 3; absent 2; registering an unknown
capability, limit or policy name throws; the first `hello` fixes the protocol: a second `hello` asking 3 on
a protocol-2 connection answers 2, `"protocol":"3"` answers 2); `examples/cc_e1.py` (V6 first: the
vendored 1.0.0 client against the E1 engine connects and works, endpoint `protocol:2`; then G1 and the `rk`
half of G7 on the stock 1.0.0 client: a v2 `edit` with a wrong `expect` on `signature` and on `data_type`
succeeds, a v2 request with the same `rk` twice is applied twice); a seam test that `laneOf(cmd, req, v3)` and `describe(false)` return exactly today's
values for every command and that the `-set` flag reaches `Settings`.
Acceptance: seven old scenarios `identical` at protocol 2; the new goldens differ from nothing else;
`dbVersions.program` non-null and equal to the constant; after E1 alone no engine behaviour differs
at protocol 2.
**Revision 6.** E1 also builds the two seams the governor needs (`Hooks.Admission`, whose default allows, called before
`open_project`, `open_program`, `fork_project` and `import`; and `Guarded`), registers the new capability, limit and
setting names of 3.1, 3.13 and 3.7 (a typo still fails a test), and changes no behaviour: the v2 goldens stay identical.

**P1a (Hydra, S): client library protocol range and the protocol-2 compatibility harness.** Files:
`support/ghidra_session.py` (`PROTOCOL=3`, `PROTOCOL_MIN=2`, `check_compatible`, endpoint overlap,
`session.protocol`; the pass-through of a `config.json` `engine` object as `-set key=value`, 3.7), new
`examples/client_compat_tests.py` (with the loader for `cc_*.py`, 5.1), new
`examples/stock/ghidra_session_1_0_0.py` (the 1.0.0 client at `b6df709e1e`, vendored byte for byte, so
that the protocol-2 behaviour tests really are a protocol-2 client). Surface: client side of 3.1. Tests:
the 1.1.0 client against a fake protocol-2 server and against the real hydra.3 install (works at 2);
against the hydra.4 candidate (3); an engine that sends `protocolMax` below 2 is refused with both versions
named. P1a needs no engine of E1 to pass: the vendored 1.0.0 client against the E1 engine (V6) is the
first test of E1's `cc_e1.py`. Depends on: none; **lands first in W1**, because every `cc_*` file of
every later engine package (E1, E2, E3a, E3b, E4, E5) runs on its loader and its vendored client.
Acceptance: all pass; the 1.1.0 client works at 2 against hydra.3 and at 3 against the E1 engine.

**Y1 (Hydralysis, L): store v3, effects, bundles.**
Files: `workcopy.py` (v3 load/migrate/save **read with `require_seal=True`**, effects capture in
`edit`, `pending_of(store)` and the extended marker of 4.2 in `state_of` and `_prefix_matches`, the
`commits[]`/`archived[]` schema, `revert` with `has_dependents` and `cascade`, `has_overlays` and
`expected_state` through `durable.exists` so that the `.bak` fallback applies, 8.2),
`revisions.py` (effect and field vocabulary), `analysis.py` (new kinds, option validation; the legacy
`save_overlay` and its reader `load_overlays` are deleted, 8.2),
`scripts/RusticQuery.java` (`effects` output, `annotation_probe`, `verify_before` in `apply_overlays`, and
`state:null` to clear the `overlay_state` option, 4.6 step 5),
`query.py` (`status options.show=changes`), new `annotations.py` (bundles), new
`tests/test_store_v3.py`, `tests/test_bundles.py`, `tests/test_engine_integration.py` (existing: the
real-engine round trip is added, env-gated), and the existing tests that write or patch a store by hand,
**named in 8.1**: `tests/test_analysis.py` (the 15 `save_overlay` calls, with the retargeting of 8.2),
`tests/test_exporting.py`, `tests/test_crossbuild.py`, `tests/test_revisions.py` (the vocabulary),
`tests/test_query_script.py` (the RusticQuery structure guards that the new outputs must keep passing),
`tests/test_query.py` (`status show=changes`), and the second step of `tests/test_durable.py` (the two
`save_overlay` rows and the counts, after Y0e).
Depends on: Y0a, Z1 (in-wave order: Z1 merges first) and **Y0e** (in-wave order: `tests/test_durable.py`; Y1 merges after Y0e). Parallel with:
E1, P1a.
Surface: store v3 (4.2), bundle format (4.9), `changes`.
Tests: v2 to v3 migration is lossless and leaves `.v2.bak`; effects round trip for rename, comment,
signature, type, label, variable, struct; `before_unknown` handling; subject rebase tests unchanged;
bundle export then dry-run import on a fresh target reports hash, sha256 and base drift; the replay set
with a committed subset and a skipped record **below** a committed one (the skipped record is pending and
replayed, never taken for committed; the marker of a program built before the commit no longer matches).
`revert` of the earlier record of a chain is refused with `has_dependents`, `cascade` removes the chain, a
batch reverts whole (4.2); a hand-stripped seal on a v3 store is `store_corrupt`; with the main store file
deleted and the `.bak` intact, `has_overlays` and `expected_state` still see the overlays. Golden: a
RusticQuery `effects` output check on the committed MSVC fixtures. Fault: kill between engine apply and
store write (the marker heals it).
Acceptance: all existing rebase tests green; `verify_before` mismatch rolls the whole transaction back and
names the effect; the frozen tests that call `workcopy._apply(settings, engine, program, records, state, timeout)`
and `workcopy._replayable(settings, target, edit)` (the frozen client tests at lines 144-170 and the frozen
archive-import tests at lines 33-38) pass unchanged, so Y1 keeps those signatures.

### W2

**Z4 (Hydralysis, M): no-stock end-to-end proof and harness audit.**
Files (revision 8.2, A22): `skills/evidence/SKILL.md` and `skills/hooks/SKILL.md` (the front matter `name` equals the directory).
Goal: the "no stock Ghidra" criterion, proven rather than assumed (audit C2).
Files (8.1): new `tests/test_engine_nostock.py`, new `tools/audit_harness.py`, `docs/ci.md`,
`.github/workflows/tests.yml`, and the front matter of `skills/hydralysis/SKILL.md` and `skills/ghidra-project/SKILL.md`
(the two skill files of the `re-*` family outside the repository are recorded in Z4's report, not governed by 8.1).
Depends on: Z13a (the skill files). Parallel with: Y2, Z5, Z7.
Surface: none.
Tests: one sequential class that scrubs `os.environ` and `PATH` itself, then inspects (not ready), installs (a job),
inspects (ready), prepares, adopts, runs `ghidra_query` and a small `ghidra_run`, with a process audit and a canary
directory; the audit reads each harness configuration, launches the configured server, dumps `tools/list` and
greps the skill directories for the stock-install names. Acceptance: the class exits 0 in the CI engine job; the
audit exits 0.

**Z5 (Hydralysis, L): real-engine matrix for prepare, adopt and scripts.**
Files (revision 8.2, A16): `backends.py` (`ensure()` only).
Goal: cover fresh import and script migration on a real engine.
Files (8.1): new `tests/test_engine_prepare.py` (it also carries the tree-hash variant of the adopt test, so Z5 does not
edit the file Y1 and Y2 own), new `tests/test_engine_scripts.py`, new `docs/verification-prepare.md`.
Depends on: Y2 (the one-line edit of `targets.py` that derives `copied` and `imported` by observation is Y2's,
8.3). Parallel with: Z4, Z7.
Surface: none.
Tests: whoami plus the 8 MSVC fixtures as a gated test; concurrent prepare against `maxImports`; cancel mid-import
registers no program and no target; a killed worker; a local KotOR fresh prepare with seconds, count and first-query
time recorded; adopt with the tree hash before and after and no import, analyze, fork or writable `open_program`
in the daemon command log; a legacy 12.1.4 fixture; a staged `.java` run after daemon start; compile-error output;
a mutating script on a copy leaves the tree hash unchanged. Acceptance: exits 0; the KotOR run is local evidence
(counts and hashes only).

**Z7 (Hydralysis, M): 12.1.4 to 12.3 golden comparison.**
Files (revision 8.2, A19): new `tests/test_golden_classify.py`.
Goal: the owner's golden diff, explained and reported, never gated (owner decision).
Files (8.1): new `tools/golden_classify.py` (a new file, because the golden harness is shared and frozen), new
`docs/verification-golden.md`.
Depends on: none. Parallel with: Y2, Z4, Z5.
Surface: none.
Tests: re-capture with the options held equal (`maxBadData` pinned; the other option, dropping it from the options
hash, would edit a frozen file and is not chosen); classify the changed functions by cause; an accepted-difference
list; stock-12.1.4 baselines for the 8 fixtures; fresh against upgraded analysis mode; no game C text in the
repository. Acceptance: counts-only report committed; today 6,645 of 8,616 KotOR functions (77.124%) are identical
and the 98% gate of the old harness is **reported, not enforced**.

**E2 (Hydra, L): format, backup, gate, fork report.**
Files (revision 8.2, A13 and A14): `S/Session.java` (the `seal_project` and `prepare_upgrade` dispatch), `S/Access.java` (`Seals.requireNotSealed`), `S/Advertised.java` (the capability name `seal`), `S/OverlayCommands.java` (`markPromote`, `clearPromote`), `S/ForkSweeper.java` and `S/ForkIntent.java` (the process start-time check against pid reuse), `S/HeadlessSession.java` (the `DbVersions.dataTypes()` self-check), `examples/contract_tests.py`, and `examples/conc/` (the red-table base script only: the base is built as a disposable fork). The `dbVersions` assertions of the E1 characterization script and its goldens are recorded in the E1 W1 cell (A13).
Files (8.1): new `S/ProjectFormat.java`, `S/ProjectBackup.java` (with the canonical serializer of 3.4), `S/Seals.java` (`seal_project`, the seal registry, the `sealed` refusal, D38);
`S/UpgradeCache.java` (`readStored`, no behaviour change; the DB-version constant is already
`DbVersions`, E1), `S/ForkCommands.java` and `S/ProjectFork.java` (purpose, open, verify, cost, warnings,
sidecar fields `purpose` and `disposable`, one validation method also registered with `Preflight`),
`S/ProgramCommands.java` (`openWritable` gate, `upgradeBackup`), `S/EditCommands.java` (`save` comment
stamp), `S/ProjectCommands.java` (`openProject`) and `S/ProjectEntry.java` (`info(client)` adds `format` for
v3, the one conditional C6), `S/DbVersions.java` (`dataTypes()`: the data type database version read from
a database header, tested against 12.1.4 data or left `null`); new `format-matrix.json`, `examples/format_gate.py`, `examples/make_legacy_fixture.py`
(builds a small 12.1.4-format project from one of our own generated PEs with stock 12.1.4; the output
is committed under `examples/fixtures/legacy-12.1.4/`; it contains nothing derived from a game), `examples/vectors/canonical-manifest.json`,
`examples/dt_e2.py`, `examples/char_e2.py`, `examples/cc_e2.py`. **E2 does not edit `Session.java`**
(E1 placed the `ProjectEntry.info(client)` call sites) **and names no lane**: a backup reaches the `maint`
lane through E3a's command mapping, with no dependency between the two packages.
Depends on: E1, E2a (it edits `ForkCommands.java` and `ProjectFork.java` after E2a did) and E8 (and, for `cc_e2.py`, P1a). Parallel with: Y2 (E3a follows E2 on `S/HeadlessSession.java`, revision 8.2, A13).
Surface: `format`, `fork_project` fields and manifest, gate, `backup_required` (3.4).
Tests: characterization `format_fork` (format on a current-format fixture; a backup fork; sidecar and
manifest masked, key order checked); `daemon_tests` `upgrade_gate` (needs `--legacy-project`: canonical
`upgrade:true` without `backup` gives `backup_required`; stale, unverified, foreign-revision, wrong self-hash
or wrong-size backup is refused; a good one opens; a fork and the upgrade cache are exempt, and so is a
fork whose sidecar has no `disposable` field (a hydra.2/3 fork); a generation or a project with a missing,
unparseable or `disposable:false` sidecar is canonical (non-disposable for the gate, D12; not sealed by that alone, D38); source tree hash unchanged on read-only paths),
`format_readonly` (tree hash before and after), `backup_fault` (kill the daemon mid-backup: no folder with a
verifying manifest, retry succeeds; corrupt one byte: client re-hash refuses; engine gate still passes by
design, which the test documents; a failed `verify` leaves no project in the destination and no manifest,
3.4), `fork_report` (NTFS asserts `method:"copy"` and a warning; **on the Dev Drive (ReFS) it also asserts that
a freshly forked candidate has the same `Revision.of` as its source**, the property that the step 4 gate
of 4.6, `backup.source.revision == Revision.of(candidate)`, relies on and that the NTFS check of the
second review did not cover), `manifest_canonical` (the vector of 3.4,
a non-ASCII path and U+2028 written by the engine and verified by Python and the reverse),
`cc_e2.py` (G7 `purpose`/`open` ignored for v2, G8 and V1: v2 `conflict` with `reason:"backup_required"`,
V7 the sidecar fields). `format_gate.py` fails when `ProgramDB.DB_VERSION`, `DataTypeManagerDB.DB_VERSION`,
`DataTypeArchiveDB.DB_VERSION`, `ProgramUserDataDB.DB_VERSION` or `SlaFormat.FORMAT_VERSION` differ from
`format-matrix.json` (values on the sync branch: 33, 3, 5, 1, 4).
Acceptance: as the tests; old goldens identical at protocol 2; the data-type DB read is either tested
against the fixture or reported `null`.
**Revision 6.** E2 adds: `seal_project` and the `sealed` refusal of every writable path (V8, `cc_e2` `sealed_refusal`); `fork_project
purpose:"view"` (a disposable fork whose sidecar names the owner agent, the lineage and the base generation) with the
admission hook; `prepare_upgrade`, a job that finishes the master's 15 to 16.5 s upgrade-cache build under a single-flight
lock before the first view is forked; the sidecar field `promote:"in-progress"` until a `promote_overlay` is acknowledged;
and `backup_min_independent` 1 by default (the second root is configured, OD9). Test: a writable open of a pristine sealed
project is refused with its tree hash unchanged (red on hydra.3: `~index.bak` changed, `~journal.bak` deleted).
**Revision 7 (B1).** E2 defines the sealed predicate of D38 from the registry and from `state:"complete"` on a `generation` or
`backup` sidecar (never from `disposable:false`), writes `state:"candidate"` for a `generation` fork and `complete` only when
`seal_project` or a verified backup says so, and makes `seal_project` refuse a project that is open writable. Test
`candidate_then_seal` (`dt_e2` and `cc_e2`, red on a build whose predicate is `disposable:false`, where the first writable
open is refused): `fork_project purpose:"generation"` gives a sidecar with `disposable:false` and `state:"candidate"`; a
writable open with `upgrade:true` and the backup of the gate succeeds and an edit saves; `seal_project` records the seal;
the same writable open, `analyze`, `save` and an owner script are then refused (`sealed` for v3, `conflict` with
`details.reason:"sealed"` for v2), a read-only open works, and the tree hash after the refusals equals the hash at the
seal; a sidecar with `disposable:false` and no `state` is non-disposable (an upgrade without a backup is refused) but not
sealed (a writable open is allowed). **`seal_union` (K1u, D66, planted violation X11):** after `seal_project`, the sidecar is
edited back to `candidate`, then deleted, then torn: each time a writable open, `save` and `analyze` are still refused while the
registry record or `SEALED.json` stands, and with the registry record also removed `SEALED.json` alone still seals; `unseal`
removes all three; a `SEALED.json` copied from another project is ignored when its `manifestSha256` does not match.

**E3a (Hydra, L): lanes, fair key, queue info, import wait, validate-before-wait.**
Files (revision 8.2, A12): `examples/client_compat_tests.py` and `examples/stock/ghidra_session_1_0_0.py` (the grant only; no edit is planned).
Files (8.1): `S/Scheduler.java` (the bodies behind E1's signatures: MAINT, fair key, per-key cap, queue info,
ETA, history, the `Preflight` call), `S/ImportCommands.java` (remaining wait; the `ImportGate.enter` call at `:100` passes the client),
**`S/ImportGate.java`** (`enter` takes the `Client`, its `Entry` keeps it, and `queueInfo(e)` adds
`estimateScope:"load"` for a v3 entry; the `queue` object of an import wait is v2 behaviour and
stays, 3.5), `S/Requests.java` (the generic `Preflight` checks, registered under `*`), `S/Connection.java` (`respond`: the `queue` header),
`S/RequestMonitor.java` (carriers for the queue information, the **lane** and the **lane note** the
decision produced: E4 only copies them into the `script` reply), `S/HeadlessSession.java` (the new `maxLong` and `maintSlots`
defaults of D40 at `:133-134` and the usage text at `:78-79`; found in revision 8: the default lives there and not in `Scheduler`),
`examples/dt_e3a.py`,
`examples/char_e3a.py`, `examples/cc_e3a.py`. **E3a does not edit `Session.java`.** Every v3 effect is
gated on `Client.v3()` (3.1, 5.1).
Depends on: E1 (and P1a for `cc_e3a.py`) and, from revision 8.2 (A13), E2, because both edit `S/HeadlessSession.java` (E2 first); the order is the declared sequence of 8.1. Parallel with: Y2.
Surface: `lane`, `maint`, `queue`, `busy` details (3.5).
Tests: `lane_starvation` now passes (p99 bound recorded from the E0 baseline, not assumed), `maint_lane`
(`fork_project`/`save` start while long is saturated, on a v3 connection), `fair_key` (two labels on one
connection share; the cap holds only while another key waits), `queue_info` (position, ETA null without
history, `estimate:true`), `import_wait`, `preflight_wait` (a bad request fails at once when the lane is
full and keeps its old error order when it is not), `per_key_cap_conserving` (maint with 4 slots and two
keys that each run one request and queue another: both queued requests run, no slot idles, 3.5). Characterization: `status.scheduler` v3 shape new
golden. `cc_e3a` (the stock 1.0.0 client, hydra.3 behaviour recorded first): `v2_lane_unchanged` (G2),
`v2_queue_order` (G3), `v2_no_preflight` (G4), `v2_progress_keys` (G5: the exact key set of every
progress event during a slot wait and an import wait: the import wait still carries `queue` and gains no
`estimateScope`), `import_wait` and `import_wait_explicit` on a v2 connection (V2, both directions).
Acceptance: old goldens identical at protocol 2; golden decompile diff identical (gate 9.1, run here).
**Revision 6.** The defaults of D40 (`maintSlots` 4, `maxLong` `max(8, CPUs)`); the per-key running cap for v2 too (V9, test
`v2_running_cap`); `RequestMonitor.addCancelHook` as E3a's first commit (so E3b needs no edit of the same method); the
`Ticket.yieldSlot` and `reacquire` API, inert until E3c wires it behind `yieldSlots` (D39); the A lane test (`lanetest`) is the
acceptance: a 7th client's script, save and fork in 1 s or less with six long scripts running (10.2-10.5 s before). `cc_e3a` `v2_lane_defaults` (V9, D62): the `status.scheduler.long.slots` of a v2
connection equals `max(8, CPUs)`; the v2 goldens mask `slots` (E0 amendment A1) and E3a edits none.

**Y2 (Hydralysis, L): lineage, commit, revert, backups on hydra.2/3, shared base.**
Files (revision 8.2, A17): `tests/test_store_v3.py` (the fixture mentions `_start_saver`).
Files: new `lineage.py`, `commits.py`, `backups.py`; `targets.py` (stable key, `CURRENT.log` resolve),
`workcopy.py` (shared base key, `pending`, `stale`, `_directory`, clearing a stale `overlay_state` on a
fresh generation base), `overlayjobs.py` (kind `commit`), `exporting.py` (header, resume refusal), `query.py`
(`stop`, `status options.show=lineage`), `api.py` (**the handler registry** that replaces the Y0d stubs, `api.HANDLER_MODULES`: it
imports the handler modules of the later packages lazily and answers `not_available` for a module that does not exist yet; 8, 8.2),
**`tests/test_contracts.py` (`NotAvailableCarriers`, `:111-157`) and `tests/test_cli.py` (its two stub tests): each of those
tests is rewritten to patch `api.HANDLER_MODULES` with a module that never exists, so that Y4b and Y4e need no edit (8, 8.2)**, `tests/fakehydra.py` (fork purposes), new `tests/test_lineage.py`, `tests/test_commit.py`, `tests/test_backups.py`, `tests/vectors/canonical-manifest.json`
(a copy of E2's vector, asserted byte-identical at the release gate 9.8), additions to
`tests/test_engine_integration.py`, `tests/test_exporting.py` (header, resume refusal), `tests/test_overlayjobs.py`
(kind `commit`) and `tests/test_query.py` (`stop`, `show=lineage`). `backups.py` registers `backend action=backups` (`op=list|verify`) and `commits.py` registers the
`job` `options` filters (`kind`, `cid`), so that no later package edits `api.py`. **Revision 6 adds** (8.1): `hydra.py` (the launch configuration: `maxLong` and `maxQuick` from the expected number of agents, D54), new `integrity.py` and `tests/test_integrity.py` (the header-magic check and quarantine of every Hydralysis-owned fork before it is opened; D42, D44), `_start_saver` and `workcopy_saver.py` are deleted (D61: the background saver, its state keys, the `saved` flag of `status` and `overlay_save_debounce_s`), `README.md` (the sentence "The working copy is saved in the background after edits pause (`overlay_save_debounce_s`)" and the per-target lock sentence of the Concurrency policy, both false after this package; plus a "Changes in 0.5.0" note, 5.2), `locks.py` (a typed `LockBusy(ValueError)` with `what`, `path`, `waited_s` and `retry_after_ms`, so the per-view lock's bound becomes the structured `busy`; `LaneLock` unchanged), new `tests/test_locks.py`, `config.example.json` (`overlay_save_debounce_s` out; `generationKeep` and `viewIdleDeleteS` in) and `tests/test_durable.py` (the allow-list row of `_start_saver` leaves with the function; its stale-entry assertion would fail otherwise), `tests/test_concurrency.py` (the `_sync` and single-base tests that Z1 marked as known issues now pass), and the capability names `views`, `publish`, `environment` and `evidenceBundle` in `api.HANDLER_MODULES`.
Depends on: Y1, Z1, Z13a (`README.md`, which it edits after Z13a), Y0a (the `AppendLog` it builds the logs on, as streamed by the W0 follow-up `2bf90c7`), Y0b (`tests/fakehydra.py`), Y0d (`api.py`) and Y0e (`tests/test_cli.py`, whose stub tests it rewrites). Parallel with: E2, E3a.
Surface: 4.4-4.7.
Tests: **the rewritten stub tests of `tests/test_contracts.py` and `tests/test_cli.py` pass with Y2's own handlers
registered and would pass unchanged when Y4b and Y4e register theirs (they patch the registry with a module that
never exists and register none of them)**; key stability across a generation flip (the overlay store is found); commit preconditions;
`dry_run` has zero side effects (tree hash); a commit on a KotOR-sized fixture produces a verified
generation and an untouched master; revert; one-way confirmation required when format unknown; torn and
gapped `CURRENT.log`; `tampered` detection; **subset and skip commits** (4.2: dependency closure,
`selection_not_closed`, skip propagation, a skipped record below a committed one stays pending and is
replayed by the next sync and taken by the next commit, revert of a commit makes its ids pending again;
`revert_chain`: commit c1, commit c2, `commit_revert` c2 then c1, the records of both are pending again in
`seq` order (c1's rehydrated from its archive) and the pointer is back at generation 0; `subset_missing_type`:
a subset commit of a signature without the struct it uses ends `ABORTED` with the effect named and nothing
published, or the test fails and the closure is extended (4.2); a `batch` split by `only` is refused or
completed by the closure);
**archival** (the previous commit's records leave `edits[]`, the caps then bound the live records);
the **reference snapshot** (a commit while edits continue compares against the `upTo` texts, and a
function touched by an outside record is `excluded`); the generation's sidecar rewrite on hydra.2/3 and
that a fork of the generation carries no `overlay_state`. Fault matrix: every point of 4.6, including
`publish_torn` followed by a successful new commit, `intent_torn` and the subset variants, **and the
two-process torn-tail test of 4.1 on `CURRENT.log`** (a long-lived process appends again after a second
process was killed mid-line), with oracle O1-O6, fresh roots. Golden: **commit round trip** (after-commit touched functions against the
reference snapshot; its own comparison, never mixed with the hydra.3/hydra.4 diff).
Acceptance: all O1-O6 hold at every fault point; two simultaneous commits give one `commit_busy`.
**Revision 6.** The shared base per `(lineage, generation, engine release)` with a cross-process single-flight lock and a completion
marker; one writer connection per view with a reference-counted reset and a per-view lock replacing `.sync.lock` (D44); the
launch configuration; `integrity.py`; the candidate verification (K2, K3) before the `CURRENT.log` append; `adopt` produces
generation 0 with the upgrade-cache build finished. Test: 12 processes building views at once finish near fork + open +
replay (a prediction, measured by Z2), `base_upgrade` is absent for the second to Nth view, and the 4-thread and 12-thread
tests of Z1 pass (red before: `no_project`).
**Revision 7.** B1: on hydra.2/3 the job rewrites the new fork's sidecar to `state:"candidate"` and, after the manifest and the
verification (the manifest hashes the sidecar without `state`), to `state:"complete"` (4.6 step 7b); test
`candidate_writable_until_seal` in `tests/test_commit.py` on the fake daemon (the fake implements the sealed predicate of
D38: the candidate opens and saves before 7b, a writable open is refused with `sealed` after it, red against the rev6
predicate). B5 (D61): test `test_view_lifecycle`: no module or call starts a second writer of a fork (`workcopy_saver` and
`_start_saver` are absent, the state has no `saved_at`, `status` has no `saved` key); closing a view's program with
its discard option keeps the folder and a reopen replays what the marker shows it lost (the eviction policy itself is Y5's, W4); `LockBusy` reaches the caller
as the structured `busy` after `SYNC_LOCK_S`; `tests/test_locks.py` covers `LockBusy` and the non-blocking `LaneLock`. B3: the
`OPTION_BAGS` lines of `ghidra_query` and `ghidra_run` list `options.as`, and the retention command `backups options.op=remove`
(OD8) is a dry run unless `confirm:true` and refuses generation 0, the head, a revert target and a live view's base.

### W3

**Z2 (Hydralysis, M): measurement harness.**
Goal: replace single-run figures by recorded medians (report-only), and measure the two numbers revision 6 leaves
open: the named-view cost with the shared base (9.16) and the publish latency (SP7).
Files (8.1): new `benchmarks/mcp_latency.py`, `benchmarks/concurrency_bench.py`, `benchmarks/named_view_cost.py`,
`benchmarks/bench_cold_start.py`, `benchmarks/bench_install.py`, `benchmarks/budgets.json`, `tests/test_output_size.py`
(rule 3 freezes the existing benchmark files, so these are new files with their own rows).
Depends on: Y2 (the shared base it measures), Y1. Parallel with: Y3, Z3, Z6, Z8.
Surface: none.
Tests: the harness spawns the real stdio MCP server against a pinned target, discards warm-up, N of at least 30
warm calls, and records median, p95 and maximum with the engine release, machine, program SHA-256, file system
and the **foreign load**; the concurrency bench prints serial and concurrent times, the speed-up and the lane
`everQueued` for the native and the `ghidra_query` paths separately; `named_view_cost` runs at least 5 times at
1, 4 and 12 simultaneous new views, shared base against rebuilt base, with each phase (`fork`, `base_upgrade`,
`open`, `replay`) on NTFS and ReFS; a publish run at 1, 4 and 12 publishers; a **replay run** of 1, 100, 1,000 and 4,096 pending records onto a fresh base, taken as the cost of the first call after an idle eviction (the per-call threshold of 5 s decides the keep-warm rule and the lowered store cap of D61). Acceptance: each script exits 0 and
writes JSON under `_logs/<stream>/`; budgets are three times the recorded median and report-only; owner machine
only, never hosted CI for time.

**Z3 (Hydralysis, M): environment, config and an early doctor slice.**
Files (revision 8.2, A15): `api.py` (the `backend status` branch only; the statement below that Z3 does not edit `api.py` was proved wrong, 8.6) and `tests/test_durable.py` (two FOLLOW_UP rows).
Goal: every harness launch reports the same root, engine and configuration; no surprise JVM from `backend status`.
Files (8.1): new `environment.py`, new `tests/test_environment.py`, `config.py`, `paths.py`, `mcp.py` (the launch
banner in the MCP `initialize` metadata and on stderr). **Z3 does not edit `cli.py` or `api.py`** (8.3): the
initial command is `python -m hydralysis.environment init`, and the `environment` handler registers through Y2's
`api.HANDLER_MODULES`.
Depends on: Y2 (the registry), Y0c (`mcp.py`). Parallel with: Y3, Z2, Z6, Z8.
Surface: `backend action=status` with `start=False`.
Tests: the same root and configuration from any working directory with a scrubbed environment; a process-level
server from a foreign directory; `backend status` with no daemon spawns nothing; a banner with root, source,
configuration source, engine release and file system; a warning on a system-drive root and on a non-COW volume;
8 server processes, one root, exactly one `java.exe`. Acceptance: exits 0; `backend --action doctor` leaves the
`java.exe` list unchanged.

**Z6 (Hydralysis, M): corpus export parity and resume.**
Goal: a full export that provably equals the corpus.
Files (8.1): `exporting.py` (the snapshot at export start, after Y2's header edit), `export_worker.py`, new
`tests/test_engine_export.py`, `tools/verify_corpus.py`, and the resume-refusal assertion of the existing exporting
test file (the package that makes a frozen assertion false owns it, rule of section 8).
Depends on: Y2. Parallel with: Y3, Z2, Z3, Z8.
Surface: none.
Tests: the expected count is read from the engine (8,616 internal functions on KotOR, 60 thunks included; the 350
non-internal of the 8,966 are excluded) with a `written+failed==expected` field separate from `all_succeeded`;
per-row cost measured before any refactor; a kill at 50% and a resume equals an uninterrupted run; cancel latency;
cancel while paused; the KotOR run pinned by SHA-256. Acceptance: fixture-scale export in CI; the KotOR run is the
local tier.

**Z8 (Hydralysis, M): surface parity tests.**
Goal: move tool-mapping rows from "to verify" to tested.
Files (8.1): `tests/fixtures/verify_fixtures.py` (new check groups `listing`, `callgraph`, `namemap`; the
file is a harness, extended not replaced), new `tests/test_parity_surface.py`.
Depends on: none. Parallel with: Y3, Z2, Z3, Z6.
Surface: none.
Tests: listing, call graph, name to address and read-memory against the linker-map ground truth of the MSVC
fixtures (x86 and x64); documented gaps for segments, namespaces, classes and Ghidra-memory reads. Acceptance: the
harness exits 0 for those groups.

**E3b (Hydra, L): cancel-aware waits, bounded release, abandoned holders, `applied`.**
Files (8.1): new `S/Waits.java` (the single timed `tryLock` and the registration state machine of 3.5);
`S/RequestMonitor.java` (the wait registration and the `cancel()` override), `S/Caller.java` (monitor in
the thread local), `S/Access.java`, `S/ProgramEntry.java` (waiters, `abandoned`), `S/OverlayCommands.java`
(lock site only), `S/Connection.java` (`run`: grace, `shutdownNow`, disconnect regardless), `S/Session.java`
(`disconnect`, optional orphan TTL in `reap`), `S/ProjectCommands.java` (`leaveProject`),
`S/ProgramCommands.java` (`releaseUse` for owners and writers, with the bounded wait; `closeEntry`; **the plain-reader fast path of 3.5 is E3c's**, D63); `examples/dt_e3b.py`, `examples/cc_e3b.py`; and, revision 8.3 (A24), `examples/daemon_tests.py` (the function `t_shared_stress` only).
Out of scope, stated: the untimed overlay-lifecycle `lock()` calls of `OverlayCommands.java` (3.5, 6).
Depends on: E3a, **E2** (it edits `ProgramCommands.java` and `ProjectCommands.java` after E2 did) and P1a
(`cc_e3b.py`). Parallel with: Y3.
Surface: `cancelled.details.applied`, `busy.reason`, `abandonedRequests`, `lock_queue_full`.
Tests: `cancel_queued` (slot wait and lock wait answer `cancelled` within 1 s), `dead_client_lock_wait`
(kill a client blocked in `wait=3600000`: released within `cleanupGraceS + abandonWaitS + 2 s` for a
cooperative script), `abandoned_holder` (a deliberately non-cooperative script: `abandonedRequests`,
`busy{reason:abandoned}`, the program is not disposed, `health` lists it, nothing waits 10 minutes),
`lock_queue_full`, `applied_flag`, **`owner_leave_bounded` (D63a: an owner or writer of an open program is killed while another client reads it; the exclusive leave waits at most `cleanupGraceS + abandonWaitS` and the readers wait no longer; it must fail on hydra.3, where the leave waits 600 s)**, and the three tests of 3.5: **`writer_vs_steady_readers`** (an
exclusive request against steady shared readers acquires within a bounded time and keeps its FIFO
position; run first against a slice-polling build, where it must fail), **`cancel_while_waiting`**
(including 200 cancels raced against the release, no leaked lock and no stray interrupt) and
`deadline_in_lock_wait`. `cc_e3b` (the stock 1.0.0 client): `dead_client_lock_wait` (V3),
`abandoned_holder` (V4: `busy` with the existing keys), `cancel_while_waiting` (V5), `owner_leave_bounded` (V3: a 1.0.0
client that owns a program is killed while another client reads it). Characterization
unchanged at protocol 2.
Acceptance: the ownership-bits question (3.5) is decided in review and recorded; golden diff identical.
**Revision 6.** E3b's first commit takes the `makeWritable` wait out of `synchronized (s.registry)` in `openProject`
(`ProjectCommands.java:70-77`), the cheap half of BP8; E3c replaces the registry. E3b also: re-checks `client.leaving` after a
lock is acquired so a dead client's queued write is never applied (BP11); dispatches read-class commands of a v3 connection in
parallel unless the request says `ordered` (BP15); bounds the per-connection outbound queue and disconnects a client that stalls
its reply for `writeStallMs` (BP23, test `stalled_socket` first); and removes the 600 s `CLEANUP_WAIT_MS` waits for owners
and writers (readers are E3c's).

**Y3 (Hydralysis, M): rebase, publish, merge.** Files: new `views.py`; `workcopy.py`, `query.py`,
`tests/test_views.py`, additions to `tests/test_query.py`. Depends on: Y2. Surface: 4.7-4.8. Tests: stale-after-commit; rebase outcomes
clean, converged, conflict, and "already in the master" decided from the generation manifests' `store.ids`
(a record published from another view matches by `merged_from`); publish idempotent through `published_through`; `stale_view` refusal with
`next`. Acceptance: no conflict outcome is silently resolved.
**Revision 6.** Y3 also builds the publish queue of 4.10: sealed `pending` changesets, the leader on `publish.lock`, the FIFO
drain with `publishBatchMax` 1, the verification of the candidate before the `CURRENT.log` append, the per-changeset result,
exactly-once through the manifest's ids, and the polling job (`publish_pending{position, etaMs}`). Tests: a publish storm
with 24 publishers and kills of the leader and of the daemon (K12, K16), merge-order independence, no reader or view
waits (K13). No latency figure is stated (SP7). The publish queue is the only path by which a view's edits reach a saved generation; there is no background saver (D61).

### W4

**E3c (Hydra, L): the non-blocking core.**
Goal: no reader of any program waits for another client's leave, a project command or a registry monitor; the
readers of a sealed generation meet no lock another client can hold (NB1-NB6, 3.10, D37, D39, D57).
Files (8.1): `S/Session.java` (the join of a program under analysis answers `analyzing` at once, the registry
replaced by the state machine, `reap` disposes by refcount), `S/Access.java` (a project pin instead of the
whole-command project lock; the project lock covers structure changes only), `S/ProgramEntry.java` (the user
count as a refcount, deferred and non-blocking disposal of the last user), `S/ProgramCommands.java` (the plain-reader leave, built once here from the rev5 fast path of 3.5 (D63b): every client that is neither owner, writer nor overlay holder, at any user count, and `close_program`), `S/ProjectCommands.java` (`open_project`,
`refresh` as a repoint, `leaveProject` without a wait under a monitor), `S/ProjectEntry.java` (the state machine
fields) and new `S/ProjectRegistry.java` (a `ConcurrentHashMap` from project key to a slot with the states
`OPENING`, `OPEN`, `CLOSING`; single-flight opens; nothing waits for a lock inside it), `examples/dt_e3c.py`,
`examples/char_e3c.py`, `examples/cc_e3c.py`. The per-request waiter caps for every v3 request (D39) and the optional
`Ticket.yieldSlot` wiring behind `yieldSlots` (default off) are here too. Revision 8.3 (A25): `S/Waits.java` (the overload `Waits.lock(ReentrantLock, long, AtomicInteger)`) and `support/ghidra_session.py` (the race-free Toolhelp snapshot).
Depends on: E3b (and, through it, E3a and E2), P1a (`cc_e3c.py`), X0, and from revision 8.3 (A25) P1b, because it edits `support/ghidra_session.py` after P1b did (the declared sequence of 8.1). Parallel with: E4, Y5.
Surface: `busy` `details.reason` `analyzing` and `lock_queue_full` for all v3 requests (3.13); V10 (5.1).
Tests: B's `s1` (a, b, c), `s5`, `s7`, `s13` rerun with the red values recorded in 3.10 (BP3, BP7, BP8, BP9); a test
that enumerates the 17 rows of `lock_matrix.json` and fails if a row has no decision in 3.10; a refcount leak test
(users return to zero after 200 cancels raced against release, no stray interrupt, the daemon log has no
`ClosedByInterruptException`); **`reader_leave_no_freeze`** (the three scenarios of 3.5: a clean close, a FIN and the end of an abandoned request each leave
the next join and the next script of a joined entry answered within their `wait`; it must fail on hydra.3),
`last_user_leave_disposes` and `reader_leave_all` on a protocol-2 and a protocol-3
connection, and `cc_e3c` `reader_leave` (a 1.0.0 client closes its connection while another client's read runs); a deadlock stress of `yieldSlots` (SP9) before it may be switched on.
Acceptance: 9.13; the v2 goldens identical; the golden decompile diff identical (9.1).

**Y5 (Hydralysis, L): per-agent default views.**
Files (revision 8.2, A18): `api.py` (`ghidra_run` `options.as`), `userscripts.py` (`run(who=)`), `tests/support.py`, `tests/test_commit.py`, `tests/test_integrity.py` and `tests/test_store_v3.py` (fixtures).
Goal: every agent edits only in its own view, readers read the sealed master, and views are evicted safely (D43,
4.10). This replaces the deferred Y5 of revision 5: its preconditions are now packages (Y3 soaked in the chaos PR
lane, the stable agent id, the eviction, Z2's per-phase cost).
Files (8.1): `workcopy.py` (lazy creation at the first edit, routing, eviction hooks), `query.py` (the default view,
`options.as` and the fallback `<client name>@<boot id>`, `scope:"master"`, `follow:"head"`, the structured `busy` to
`next` mapping), `views.py` (the view records of 4.10), new `viewgov.py` (LRU, idle time, `max_views`, the keep-warm rule of D61, the atomic
pin-or-evict step of 3.11), `tests/test_views.py` (additions), new `tests/test_viewgov.py`, `README.md` (the sentence "Clients share the default view"), `skills/hydralysis/SKILL.md` and `skills/ghidra-project/SKILL.md` (one paragraph each: pass a distinct `options.as` for each editing sub-agent, D59).
Depends on: Y3, Y2, Z2, Z3 (revision 8.2, A18: both edit `api.py`), Z4 (the skill files). Parallel with: E3c, E4, P1b.
Surface: 4.10; `ghidra_query action=status options.show=views`.
Tests: K11 with 12 real agents (separate processes, `options.as`) on 3 projects: no unpublished tag visible to
another agent; 24 agents: no `no_project` error, no shared mutable state; a kill of an agent process rebuilds its view
from the store (K15); an evicted view is rebuilt and answers the same (K8); eviction never closes a view with a running
request; the shared view keeps its mandatory `expect_revision`. **Revision 7 (D59, K11p) - `subagents_one_process`:** one real stdio MCP
server process (the stdio transport harness of the MCP transport tests over the fake daemon, one `initialize` whose `clientInfo` name
is `claude-code`) and two threads that stand for two sub-agents P and Q, each sending `tools/call` of `ghidra_query`. (1)
Neither passes `options.as`: both get the id `claude-code@<boot id>`; `status show=views` lists **one** view; P's unpublished
rename is visible to Q's read (asserted: this is the documented behaviour of a shared identity, not a failure), and a Q edit
that carries a stale `expect_revision` is rebased subject-aware or refused naming P, never applied over P's (the K16 model: no
lost update). (2) P passes `options.as:"P"` and Q `options.as:"Q"`: two views; Q never sees P's tag until P publishes (K11);
`status show=views` lists both. (3) The `options` bags of `ghidra_query` and `ghidra_run` accept `as`, `backend help` lists
it, the catalog hash and the advertised size are unchanged (no schema change), and the two skill files carry the sentence (a
grep gate). (4) A native tool call (no `options` bag) from either sub-agent reads the master and never a view. The test can
fail: against a build that derives the id from `clientInfo` alone, (2) fails; against one that ignores `as`, (2) fails; against
one that silently shares a view while promising isolation, a documentation check of (1) fails. Eviction closes a view only with
no running request, loses no record (the store holds them) and a reopened view replays them (D61). `keep_warm_view` (a view with at least `viewKeepWarmRecords` pending records is not closed by idle time, only by LRU pressure) and `restart_adopts_orphaned_view` (revision 8): process 1 (default id) edits and is killed; process 2 (new boot id, same `clientInfo` name) reports the orphan in `adoptable` on its first call, reads the master until it adopts, `options.as:"<old id>"` re-attaches and sees the edits, a live lease refuses with `view_in_use`, and with `HYDRALYSIS_AGENT_ID` set process 2 gets the same id without adopting. Acceptance: 9.16
reported; 9.17 PR lane against hydra.3.

**E4 (Hydra, M): script isolation.** Files: `S/ScriptCommands.java` (`isolation`, `scriptSha256`,
`attemptedChanges` measured before the rollback, `basedOn`, and the `lane` and `laneNote` **copied from the
request monitor**, where E3a stored the decision; E4 does not decide a lane; the `script` validation
method registered with `Preflight`), `S/OverlayCommands.java` (`loadOverlay` extracted), new
`S/PrivateInstance.java`; `examples/dt_e4.py`, `examples/char_e4.py`, `examples/cc_e4.py`.
Depends on: E3b (and, through it, E3a, E2) and P1a (`cc_e4.py`). Parallel with: E3c, P1b.
Surface: 3.4 `script`, 3.6.
Tests: a mutating user script with a concurrent decompile reader in each mode (shared: attempted and
rolled back; exclusive and private: readers never see it); the master file hash and revision unchanged;
RusticQuery read actions report `attemptedChanges:false`; `script_changed`; `unsavedIgnored` when the
program holds unsaved edits; **the private open cost on KotOR is measured and written to the test
timings**; the `Program.lock` spike result recorded either way. `cc_e4`: a v2 `script` with `isolation`,
`lane` and a wrong `scriptSha256` runs as today (G7). Golden decompile diff identical.
Acceptance: `shared` unchanged for protocol 2.
**Revision 6.** Overlays are opened from the stored file with a timed wait, so opening a new overlay during an exclusive hold
of the base no longer fails `busy` (BP24); a user script never runs `shared` (D47); `scriptMaxS`, CPU and allocated-bytes
sampling and the quarantine of a script that ignores cancel (`health.leakedWorkers`, the owner's long cap drops to 1) are
here. Parallel with: E3c, P1b (not E5, which moved to W5). **Revision 8:** E4's `PrivateInstance` stays read-only on the stored file; the writable disposable clone that E7's worker uses is E7's (D64).

**P1b (Hydra, M): launcher.** Files: `support/ghidra_session.py` (deadline, `LaunchError`, registry,
`DuplicateDaemonError`, `Daemon.health()`, `Daemon.attach()`, the caller-job detection and the breakaway-then-WMI spawn of D65, the JVM flag of D60, the `maxLong` comment), `examples/dt_p1b.py`. Depends on: P1a.
Tests: `launch_errors` (no JDK, JDK 21 against 25, heap above free RAM, lock held, early exit: each a code
and details), `duplicate_daemon` (a second state dir with `singleton:"per-install"` raises; the default
warns), `call_deadline` (a hung call cancels and raises `deadline_exceeded`, the connection survives),
N concurrent launchers start exactly one daemon per root. Fresh roots only. The deadline exists only in
the library that ships with hydra.4 (3.8); against a hydra.2/3 engine Hydralysis uses the client-side
watchdog of 7.6 (Y4a).
**Revision 8 (D60, D65, replaces the revision 7 paragraph).** P1b owns **no** Job Object. It adds the caller-job detection,
the breakaway-then-WMI spawn with its reported outcome (`caller_in_job`, `spawn`, `survival`, `warnings[]`) and the JVM flag
`--enable-native-access=ALL-UNNAMED`, and updates the `maxLong` default comment of the launcher (`ghidra_session.py:425-426`),
which follows E3a's new default (D40). Tests `daemon_survives_launcher_exit`, **both variants, each with an expected result**:
(A) the launcher runs in a kill-on-close job **with** breakaway rights: `spawn:"breakaway"`, `survival:"independent"`, the
daemon answers `health` after the launcher's job is closed; (B) the launcher runs in a kill-on-close job **without**
breakaway rights: breakaway fails with WinError 5, `spawn:"wmi"`, `survival:"independent"`, the daemon answers `health` after
the job is closed; (C) negative control: with the WMI route disabled in the test, B ends `spawn:"stayed"`,
`survival:"bound_to_harness"`, the warning `daemon_dies_with_harness` is present and the daemon is dead after the job is
closed (the test fails if the daemon survives, which proves that the job and not luck decides); (D) a launcher in no job:
`spawn:"detached"`. The daemon's own job is E9's (3.11); SP3 tests both halves.

### W5

**E5 (Hydra, M): health and watchdog.** Files: `S/Session.java` (`isInline`, `case health`, starting the
watchdog), new `S/Health.java`, `S/Watchdog.java`, `S/Scheduler.java` (`describe` with `tryLock` for v3,
lane stats), `S/HeadlessSession.java` (parse `testHooks`); `examples/dt_e5.py`, `examples/cc_e5.py`.
Depends on: E3b (lane stats), E3c (it edits `Session.java` after E3c did) and P1a (`cc_e5.py`). Parallel with: Z13b, Z15 (E6 runs after it).
Surface: `health` (3.4), `debug_stall` behind the launch property.
Tests: `health` answers while a long request runs; a daemon suspended from outside (`NtSuspendProcess`)
is seen by the Python probe as a live pid with no answer; with the hook, `tick.ageMs` grows and
`schedulerLockOk` is false while `ping` still answers; a v3 `status` no longer blocks on a held
scheduler lock (`cc_e5`: the same held lock makes a v2 `status` block as on hydra.3, G6);
`hello.platform.testHooks` true and `health.state:"degraded"` with the hook on.
Acceptance: the hook cannot be enabled from `config.json` or a request.
**Revision 6.** `health` also reports `waits.foreignBlocked`, `governor{...}`, `leakedWorkers` and `repairs[]` (3.13), read through
E1's `Hooks`; E9 (same wave) starts the governor after E5 starts the watchdog in `HeadlessSession.java`. `Health` also takes a contributor list
(a name-to-supplier registry that the classes it reports on fill, such as `ScriptWorker` and `ProcessJob`), so E7 and E9 add their
figures without editing `Health.java` (D60, D64). E5 moved from W4
to W5 because E3c owns `Session.java` in W4 (D56).

**E9 (Hydra, L): the resource governor.**
Goal: overload is refused with a structured `busy`, never an out-of-memory; one client cannot take the daemon down
(3.11, D46).
Files (8.1): new `S/Governor.java` (admission: heap after GC, the watermarks, `maxViews`, the per-client cap, the
disk estimate; the `degraded` state), new `S/Budgets.java` (the `Settings` keys and the learned `estHeap`), new
`S/DecompilerGate.java` (the fair semaphore), new `S/ProcessJob.java` (the daemon's own Job Object, D60), `S/ProgramEntry.java` and `S/Overlay.java` (the gate at
`borrowDecompiler`, the crash circuit breaker, the negative cache), `S/HeadlessSession.java` (starts the process job as the first statement of `launch`, then the governor
**after** E5 starts the watchdog), `examples/dt_e9.py`, `examples/cc_e9.py`, `examples/char_e9.py` (the golden
`characterization/v3/e9-limits.json`). Revision 8.5 (8.9): also `S/Session.java` (A33), `S/Health.java` (A34),
`S/Advertised.java` (A35), `S/QueryCommands.java` (A36) and new `S/Guarded.java` (A37).
Depends on: E5, E3c (it edits `ProgramEntry.java` after E3c), E1 (the seams `Hooks.Admission` and `Guarded`), P1b (the `--enable-native-access` flag in the JVM arguments, which E9 does not own) and X0.
Parallel with: Z13b, Z15 (E6 and E7 run after it).
Surface: `busy` `details.reason` `capacity`, `decompiler_failed`, `runaway_quarantined`; `limits`; `health.governor` (3.13).
Tests: `-Xmx256m` with 24 views ends in structured `busy`, 0 `OutOfMemoryError`, the reaper alive (red on hydra.3);
`-Xmx512m` with 24 views runs; a 100-view probe is refused at `maxViews`; kill -9 of a native decompiler during a
12-client load fails one request and the next works; a hang and a timeout; a daemon kill leaves no orphan
decompiler or worker (the decompilers are **suspended** before the daemon is killed, and a no-job control with `ProcessJob` disabled must show the survivors, so the test is red without the job, D48; the planted violation X9 is the same suspended process), and the daemon's `health.processJob` is `own:true` (D60; SP3); a runaway script is quarantined and counted; SP4 (dispose and recreate a
`DecompInterface`). Acceptance: 9.14; no daemon thread dies in any lap; heap after GC below the hard watermark.

**E7 (Hydra, L): a killable script worker.**
Goal: an untrusted `ghidra_run` script that ignores cancel is killed at its timeout and releases its slot and its owner's long
cap (D47). A **gated hydra.4 package** (revision 7, D64, OD12): a deaf script that holds a slot and a lock is a measured
blocking point, so the claim "a deaf script is killed" is made only when the E7 items of 9.14 pass, and hydra.4 is not tagged before they do.
Files (8.1): `S/ScriptCommands.java` (the routing of a script not pinned by `scriptSha256` to a worker), new
`S/ScriptWorker.java` (a pooled child JVM that opens a **private, writable, disposable clone of the saved view** (D64), speaks over a pipe, is
killed on cancel, timeout, heap breach or client disconnect and exits when its parent dies, and whose clone is deleted after every run), `examples/dt_e7.py`. **E7 does
not edit `Session.java`, `Health.java`, `HeadlessSession.java` or a seam file**: the worker count reaches `health` through E5's
contributor list, kill on disconnect rides E3a's `RequestMonitor.addCancelHook` and E3b's dead-client path, and the worker
inherits the daemon's own Job Object (E9, D60).
Depends on: E3a, E3b, E4 (it edits `ScriptCommands.java` after E4), E5 (the `Health` contributor list), E9 (the process job
and the budgets) and SP10. Parallel with: Z13b, Z15 (E6 and R1 run after it).
Surface: `isolation:"worker"`; the refusal `conflict` with `details.reason:"unsaved"`; the worker count in `health`.
Tests: a deaf script (it ignores cancel and interrupt) is gone at its timeout and the owner's long cap is released
(red on hydra.3 and on the E4 build, where it ran to its end 22 s after cancel); a daemon kill leaves no worker (K7); a
worker killed by hand fails one request and the next works; the start-up and RAM cost from SP10 are recorded and
the gate is not passed above the budget they set. **The 9.14 test is specified for an EDITED view** (revision 8, D64): apply an edit to a view and leave it unsaved; run a deaf script with `isolation:"worker"` that prints the edited name and then ignores cancel; assert (1) the engine refuses it without the owner's save (`unsaved`), (2) after the owner's save the script **sees the edit** (a stale read, the unedited name, fails the test), (3) `attemptedChanges` of a mutating run is measured on the clone and the view is byte-for-byte unchanged afterwards, (4) the deaf script is killed at its timeout, its slot and the owner's long cap are released, the clone is deleted, and (5) the save is counted (one, within the per-view lock bound). A variant on an unedited view must not save. Acceptance: the E7 items of 9.14; RusticQuery stays in process.

**Z13b (Hydralysis, M): documentation, surfaces and numbers.**
Goal: the tool mapping, the verification table and the numbers come from the ledger.
Files (8.1): `README.md` (the "Evidence and limits" section), `THIRD_PARTY.md`, `docs/tool-mapping.md`, new
`docs/data/tool-surfaces.json`, `docs/verification.md` (a dated table of owner-reported third-party figures, each
labelled "not reproduced"), new `tools/count_surfaces.py`, new `tests/test_tool_mapping.py`, `docs/data/claims.json`,
`tests/test_claims.py`.
Depends on: Z13a, Z4, Y2, Y5 (the `README.md` sentences they rewrote). Parallel with: E9, E6, Z15.
Surface: none.
Tests: the doc table equals `api.TOOL_NAMES`; no row says "to verify" once declared complete; the catalog size in
the documents is generated from `tool_table()`; the 8-outstanding-per-lane MCP cap is documented. Acceptance:
the tests exit 0; `tools/count_surfaces.py` writes the three counts.

**Z15 (Hydra, M): fork maintenance and policy.**
Files (revision 8.2, A11): new `/.github/scripts/upstream-sync-report.sh`, `/.github/scripts/test-upstream-sync-report.sh`, `/.github/scripts/check-archive-notices.sh` and `/.github/scripts/test-check-archive-notices.sh`.
Goal: the fork keeps its upstream merges safe, and its guard knows the patched core files.
Files (8.1): `/.github/CONTRIBUTING.md`, `/.github/SECURITY.md`, new `/.github/workflows/upstream-sync.yml`, new
`/.github/hydra-touched-files.txt` (the patched core classes: the three of hydra.2 and 3 plus the two E8 adds).
Depends on: E8. Parallel with: E9, E6, Z13b.
Surface: none.
Tests: a scheduled upstream-sync workflow (merge, `buildHeadless`, the three suites, the golden diff, a pull request with
the shortlog and a file-overlap report); a guard that fails when a patched core file changes upstream; a
supported-versions table and a fix-time statement; the real release archives contain LICENSE, NOTICE and
NOTICE-HYDRA. Acceptance: the workflow's dry run passes; the root documents say "Merge, never rebase". R1 keeps
the README and CHANGELOG.

**S2 (site, S): the claims that a passed gate flips.**
Goal: the site claims exactly what the gates proved, in the same change as each release (D52).
Files (8.1): the same files as S1 (the version constants among them are edited by R1's bump script and owned here).
Depends on: S1, R1, Z13b. Parallel with: none (it runs after R1).
Surface: none.
Tests: the site build fails if its copy of the ledger differs from its source; the grep gate of 9.19. Acceptance: a
claim changes wording only when its flipping test changed from red to green (8.3).

**E6 (Hydra, M): the soak and chaos gate runner.** Files: new `examples/soak_tests.py`, new `examples/chaos_tests.py`. Depends on: E2, E3a, E3b, E3c, E4, E5, E7, E9, X0. R1
follows it in W5.
12 client processes with distinct labels over mixed work (quick decompiles, quick scripts, long sleeps,
fork and save, cancels), seeded client kills. Pass criteria: no lost, duplicated or reordered
acknowledged edit against the clients' own logs; every queue empty and no program owner left after the
clients exit; quick-lane p99 under the bound recorded by E0 on hydra.3; no `abandoned` holder after
cooperative scripts; **a backup (`fork_project purpose:"backup"`) started while the long lane is
saturated runs in the `maint` lane** (the combined check of E2 and E3a, which share no code). PR lane
about 2 minutes; nightly longer.
**Revision 6 replaces the rev5 criteria above by gate 9.17**: the PR lane (4 agents x 2 projects, 10 minutes), the nightly lane (16 x
4, 2 hours) and the release run (24 x 6, at least 4 hours), the fault classes with minimum hit counts, the oracle K1-K17 and
`waits.foreignBlocked` (D49, D50). E0's recorded failing latency is not a bound. The counted kill batches of 9.15 run on X0's
library; E6 only schedules them.

**R1 (both, M): hydra.4 release preparation.**
Files: Hydra: `S/HydraInfo.java` (version), `/CHANGELOG.md`, `/NOTICE-HYDRA` (the verified list of patched core files), `/README.md` and `README.md` (a protocol 3 section pointing here;
the new limits and the config keys of 3.7; the "Protocols" matrix), `ARCHITECTURE.md` (rows for the new
classes), `certification.manifest` (its own release entries; every package appends its own files, 8), the
release workflow (a dry run); Hydralysis: new `tools/bump_hydra.py` and `tests/test_bump_hydra.py`. The **release notes** carry the items
of 5.2 (D4 `minClient` unchanged, the pin refusal of Hydralysis 0.4.x, V1 to V11 by name) and the full v3 hello
golden. `tools/bump_hydra.py` generates `RELEASE`, `PROTOCOL` and `ASSETS` (with SHA-256 and sizes) in `hydra.py`, the
`fakehydra` constants and the one pin sentence of `README.md`, `THIRD_PARTY.md` and `docs/upstream-setup.md`,
and **edits no other file** (5; `tests/test_bump_hydra.py` asserts the edit set); **R1 is its only owner**,
Y4a runs it. **No tag, no push, no release by this stream**; the tag is an
owner action. Until then Hydralysis tests run against the candidate install with `hydra_allow_unpinned`.
Depends on: every engine package, **including E6 and E7** (R1 runs after E6 within W5), E8, R0.
**Revision 6.** `tools/bump_hydra.py` also writes the site's release and protocol constants (the files of S1; S2 owns the edit,
as Y4a owns the Hydralysis pins); R1 states the headless-only sentence in the release notes and the guarantees of 6.1 that
hold in hydra.4, and no claim a gate has not passed (D52).

### W6

**Z9 (Hydralysis, L): evidence v2 and bundles.**
Goal: content-addressed evidence with coverage and limitation objects, and bundles that two exports compare equal
(audit C1-25, C1-42, C2-25 to C2-28). Runtime evidence and coverage come before memory write (owner decision).
Files (8.1): `evidence.py` (in place, legacy rows backfilled), new `evidence_bundle.py` (its own `__main__`; **Z9 does not edit `cli.py` or `api.py`**; the `evidenceBundle` handler registers through Y2's `api.HANDLER_MODULES`, 8.2),
new `tests/test_evidence_model.py`, `tests/test_evidence_bundle.py`, `tests/test_evidence_parity.py`,
`docs/upstream-runtime.md` (the correction of its line 64).
Depends on: Y1 (view, sequence and generation provenance), Y2. Parallel with: Y4a, Z10, Z14.
Surface: none.
Tests: an `evidence_id` stable across key order and sessions that rejects a flipped byte; a coverage and
limitation catalog stored with each row; bundle export, verify, compare and import; parity cases loaded from the
reference checkout; no game payload bytes. Acceptance: the three test files exit 0; two independent bundle exports
compare equal modulo volatile fields.

**Z10 (Hydralysis, L): runtime evidence on the existing fixtures, capture, snapshot, export-name hooks.**
Files (revision 8.2, A21): new `runtime_actions.py`, `runtime_agents.py`, `runtime_capture.py`, `runtime_events.py`, `runtime_exports.py` and `runtime_snapshot.py` (the split of the worker).
Goal: audit C1-24, C1-41, C2-17 to C2-21, C2-24; fixture-first.
Files (8.1): `runtime.py` and `runtime_worker.py` (after Y0e; the 805-line worker is split into agent templates,
event log, action handlers and lifecycle before features are added), the existing fixture harness `tests/fixtures/verify_fixtures.py`
(new checks `break_continue`, `export_hook`, `capture`, `snapshot`; `mcp_typed_read` gains the view-revision
assertion), `tests/fixtures/flow_fixture.c` (an exported function for the export-name test),
`tests/fixtures/build_fixtures.py` (the runtime fixture source folded into `BUILDS`), `tests/fixtures/runtime_fixture.c`,
the fakes under `tests/fakefrida/`, new `tests/test_runtime_capture.py` and `tests/test_runtime_snapshot.py`.
Depends on: Y0e, Z8, Z9. Parallel with: Y4a, Z14.
Surface: none.
Tests: for each new action a fake-Frida unit test (every pull request); hook by module export name verified
against the file's export table; a durable append-only event log with sequence and hash chain, counters independent
of recorded events; `runtime snapshot` and `runtime compare` with volatile masks; the real-process side is the
fixture harness on the owner machine (MSVC and Frida; not CI). Acceptance: the two new test files and the runtime
tests exit 0 in CI (fake); the harness checks exit 0 on the owner machine; no CI claim for the real side before a run
shows it.

**Z14 (Hydralysis, M): Hydralysis release.**
Goal: audit C1-34 and the policy half of C1-49; carries the "Changes in 0.5.0" note of 5.2 into `CHANGELOG.md`.
Files (8.1): new `CHANGELOG.md`, new `.github/workflows/release.yml`, new `docs/versioning.md` (in the Hydralysis
repository).
Depends on: R1 (`bump_hydra.py`), Y4a (the pin), Z13b. Parallel with: Z9, Z10.
Surface: none.
Tests: a workflow dry run (`workflow_dispatch`) builds the sdist and wheel, runs the unit and engine jobs and attaches the
artifacts with SHA256SUMS; a version policy (which version pins which engine, what 0.x means, how to roll back
a pin); release notes carry the limits (Windows x64, ReFS-only copy-on-write, the one-way upgrade, a restart once).
Acceptance: in a fresh environment the installed wheel reports the tag version and `backend inspect` reports ready.
No tag by this stream.

**Y4a (Hydralysis, L): engine adoption and supervisor.** Files: `hydra.py` (capabilities, pin, `Supervisor`,
deadlines: P1b's on hydra.4, the abandon helper of 7.6 on hydra.2/3 with its pool of entries, the registry of
two budgets, the leave gate and `abandoned_cap`), `query.py` (lane hint, shorter waits, `wait` below the
deadline on **every call of the attempt** on hydra.2/3, one entry acquired per attempt in `_ask`,
`forget(entry)`, and `QueryRunner.stop` over the entries with the report of 7.6; 7.6), `tests/fakehydra.py`
(the v3 fake: queue info, `next`, health; **the E2 surface that Y4d's tests need: `format` in project info,
`backup_required` on the upgrade gate, `fork_project purpose:"backup"` writing an engine-style manifest with
`writer:"engine"`**; and a connection-scoped project and program context that is **opt-in**, default off, so
that no frozen test changes), new `tests/test_deadline.py` and `tests/test_supervisor.py`, additions to
`tests/test_query.py` (and the `:285-296` release literals derived from the fake's constant), and
`tests/test_backends.py` (the release literals `:21` and `:101` derived from `hydra.RELEASE`). It **runs** R1's
`tools/bump_hydra.py` to produce the pin bump and owns **exactly the files the script edits** (5): `hydra.py`,
`tests/fakehydra.py` and the three pin statements of `README.md`, `THIRD_PARTY.md` and `docs/upstream-setup.md`
(8.1 has a W6 cell for each); it does not own the script. Depends on: R1, Y0b, **Y2** (`tests/fakehydra.py`) and
**Y1, Y2, Y3, Y5** (`query.py`) and **Z13b** (`README.md`, `THIRD_PARTY.md`); **Y4b and Y4d merge after it** (8).
Tests: the
deadline helper of 7.6 (abandon without a FIN, a gated close, never an early `close()`) against the fake and the real hydra.3 (the
cases L, S, C of 7.6, the abandoned-connection budgets, the leave gate, the pool entry with `replacement_context`,
`wait_below_deadline` and `leave_gate_no_freeze`: the list in 7.6); 7.2 policy against the fake and
the real engine (a suspended daemon is restarted within budget; `lost_on_restart` recorded; a slow daemon
with non-recoverable unsaved edits is not restarted); degrade matrix 7.5 against hydra.3.
**Revision 6.** The supervisor's auto-restart is gated on `journal.durable` and waits for process exit (D55); read tools send `parallel`
by default; the structured `busy` reasons of 3.13 map to a ready `next`; the doctor (Y4b) reports `repairs[]`, unfinished candidates
and the engine's integrity-cut status. Y4a depends on Y5 because it edits `query.py` after Y5.

**Y4b (Hydralysis, M): doctor.** Files: new `doctor.py` (it registers `backend action=doctor` with the
handler registry that Y2 built and does not touch the dispatcher file, 8.2), `tests/test_doctor.py`. Depends on: P1b, E5, Y2 (the registry) and **Y4a** (the abandoned-connection registry in `hydra.py`, 7.6,
which the doctor lists: in-wave order, Y4b merges after Y4a). The doctor reports leftover `*.tmp` files and
the abandoned connections of both budgets (7.6).
Tests: zero daemon spawns and zero engine calls when no daemon exists; cites `hello.paths/platform/
analysisIdentity`; one finding per section of 7.1.

**Y4d (Hydralysis, M): engine backup and format adoption.** Files: `commits.py`, `backups.py`,
`lineage.py`, and their tests `tests/test_commit.py`, `tests/test_lineage.py`, `tests/test_backups.py`. Depends on: E2, Y2 and **Y4a** (in-wave order: its tests run on the fake daemon that Y4a extends with the E2 surface, 8.2). Switch backups to `purpose:"backup"` (`writer:"engine"`), use
`format` for the confirmation, pass `backup:` to the candidate open, and adopt legacy backups (4.5: verify, then `seal_project`). Tests: a Python-written backup is
accepted by the engine gate and the reverse; fault matrix re-run; `legacy_backup_adoption`: a backup made on hydra.2/3 is listed `sealed:false`, adopted by `op=verify`, then refused a writable open; a flipped byte makes it `legacy_unverified` and unusable as a source.

**Y4e (Hydralysis, S): `ghidra_run` modes.** Files: `userscripts.py`, new `tests/test_userscripts.py`
(the existing structure-guard test of the RusticQuery script is Y1's in W1, 8.1).
Depends on: E4, E7 (the worker route), Y5 (revision 8.2, A18: `userscripts.py` `run(who=)`), Y2 (the handler registry: it registers the `ghidra_run` `options` handler from
`userscripts.py` and does not touch the dispatcher file). Tests: `private` only on a clean working copy, `exclusive`
otherwise, and on hydra.4 `worker` on a view after the owner's bounded save under the per-view lock (D64); the reply shows `attemptedChanges`, `isolation`, `basedOn`; a script on an edited view sees the edit, and the save happens once and only when `info.changed`.

### W7

**Z11 (Hydralysis, M): runtime scenario end to end.**
Goal: audit C2-29 and the KotOR halves of C2-17 to C2-19; fixture-first.
Files (8.1): new `tools/scenarios/kotor_vfs_lookup.py`, new `tests/test_runtime_scenario_fixture.py` (the fake-Frida
mirror, CI), and the `scenario` check of the fixture harness `tests/fixtures/verify_fixtures.py` (the game-free
analogue on `flow_fixture.exe`; manual).
Depends on: Z9, Z10; the owner's decision on a live game run (profile copy only). Parallel with: Z12.
Surface: none.
Tests: the 12-step scenario of the old toolchain (verify sites, spawn paused from a profile copy, observe, export
hooks, capture, resume, typed read, snapshot, writers, detach, evidence add, bundle export); the install tree hash
unchanged. Acceptance: the pass sequence equals the recorded one, zero silent drops or an explicit limitation, the
second bundle compares with zero non-volatile deltas.

**Z12 (Hydralysis, M, gated): runtime memory write and watchpoints, fixture-only.**
Files (revision 8.2, A20): new `runtime_memory.py` and `tests/fakememory.py`.
Goal: audit C2-20 (write), C2-22, C2-23; only after the owner's decisions and only on fixtures.
Files (8.1): `runtime.py`, `runtime_worker.py`, new `tools/watch_conformance.py`, new `tests/test_runtime_watch.py`,
`tests/test_runtime_write.py`, `tests/fixtures/flow_fixture.c` and `tests/fixtures/build_fixtures.py` (a watch case).
Depends on: Z10. Parallel with: Z11.
Surface: none.
Tests: compare-and-swap write with a required reason, an executable-range guard and an undo log that reports
DIVERGED; a watch state machine to verified-clear, a tainted session on a failed disarm, a per-architecture
conformance stamp; an x86 and x64 teardown matrix with debug-register readback and a 100-iteration race loop (the
target exits 0, never `0x80000004`). Acceptance: the conformance tool exits 0 for both architectures. Not built
without the decisions; carries a process-fault risk and is never marketed before a fixture proof.

### W8

Hydra hydra.5 packages. Each is conditional: it starts only when its spike (9.20) says go.

**E10 (Hydra, M): overlay-backed views for direct clients.**
Goal: a cheaper per-agent view where the spike says it is cheaper than a fork.
Files (8.1): `S/Overlay.java`, `S/OverlayCommands.java` (an overlay opened from the stored file with a durable
journal), `examples/dt_e10.py`.
Depends on: E4, E9, SP2. Parallel with: E11, E12.
Surface: none new.
Tests: first-edit time, heap and disk against a fork view on KotOR and on the large program (SP2); RusticQuery
`apply_overlays` on an overlay equals the fork-based working copy. Acceptance: go only if both measures win.

**E11 (Hydra, M): read replicas of a hot program.**
Goal: DB-bound reads of one program scale beyond the 1.4x to 1.8x of one `Program` instance.
Files (8.1): new `S/ReplicaPool.java`, `S/ProgramEntry.java`, `examples/dt_e11.py`.
Depends on: E9, SP1, SP8. Parallel with: E10, E12.
Surface: none new; replicas are internal.
Tests: B's `s12_instances` and `t3_scaling` rerun: `functions` x N toward the 4.1x measured on private instances; a read
of a replica while the stored file is saved by another instance (SP1). Acceptance: go or no-go recorded.

**E12 (Hydra, M): power-loss durability.**
Goal: the only package that may allow a power-loss claim (6.1).
Files (8.1): `/Ghidra/Framework/DB/src/main/java/db/buffers/LocalManagedBufferFile.java` (the version file, its header
and the directory entry flushed), `examples/dt_e12.py`.
Depends on: E8. Parallel with: E10, E11.
Surface: none.
Tests: a simulated power-loss matrix (a virtual machine or a crash simulator; a process kill keeps the OS page
cache and proves nothing here). Acceptance: only after it passes may a document say anything about power loss.

---

## 9. Release gates

hydra.4 is not tagged by this stream; these are the conditions under which the owner may tag it. Every
gate is a command with a **verified exit code** and a log under `D:/Projects/Hydra/_logs/<stream>/`.
Fresh state roots; the live daemons (18220, 17936) are never touched; no game-derived data enters any repo.

| # | Gate | Pass condition |
|---|---|---|
| 9.1 | **Golden decompile diff**, hydra.3 against the hydra.4 candidate | `tools/golden.py capture` then `diff` on fresh **copies** of KotOR (program pinned by SHA-256, function count read from the engine, not hard-coded: the 8616 seen on 2026-10-27 is an observation) on **both** paths, `production` (RusticQuery, the path agents use) and `explicit`; plus the **8 public MSVC fixture programs, 4 x86 and 4 x64** (`flow`, `vcall`, `diff1` and `diff2` for each architecture; `D:/Projects/Hydra/_golden/sets/fixtures.json` lists exactly these eight, and an earlier report of "6 x86 and 4 x64" is wrong), profile `fixtures`. Their function counts are read from the engine like KotOR's: the set file totals 4,497 functions while `docs/golden-harness.md:143` says 3,959, a difference this gate does not depend on and does not resolve. Identical on all (hydra.3 against itself is deterministic: 8616 identical). Source tree hash before and after each capture equal. Run after E1 (the seams must change nothing), after E3a, after E4, and at release. Any difference blocks. The hydra.2-to-hydra.3 difference (one x64 `strncmp` function per fixture, GP-7212) is **not** in this comparison. |
| 9.2 | **Commit round trip** (separate comparison, never mixed with 9.1) | After a commit on the KotOR copy, the touched functions of the new generation decompile identically to the working copy; 25 untouched functions identical to the previous generation. |
| 9.3 | **Characterization** | the seven scenarios `identical` at `--protocol 2` (the scheduler `slots` are masked since E0's amendment A1, D62, and asserted by `cc_e3a` `v2_lane_defaults`); the v3 run is always made with `--require-v3` (without it an engine that serves no v3 is a SKIP with exit 0, which E0's review found and which a gate must not accept); every v3 scenario golden recorded, reviewed as a diff of additions, committed; the full v3 hello golden recorded by R1 (3.1) |
| 9.4 | **Engine suites** | `session_smoke.py`, `contract_tests.py`, `daemon_tests.py` (all, with `--legacy-project`, so `legacy_overlay` and the older-format half of `upgrade_cache` run: the sync stream skipped them), `client_compat_tests.py` (with every `cc_*.py`: the protocol-2 behaviour tests of 5.1, run by the stock 1.0.0 client), `format_gate.py`; plus the fork tests on a ReFS volume |
| 9.5 | **Soak, 12 clients** (superseded by 9.17 in revision 6) | the PR lane of `soak_tests.py` green as part of 9.17 |
| 9.6 | **Upgrade and backup round trip** on the legacy fixture | backup (engine) then gate refusal without it, success with it, on a fork; commit to a new generation; restore the backup alongside; the restored tree hash equals the original; the one-way format step is asserted by `format_gate.py` (9.7), not shown in a stock Ghidra GUI (headless only, D36); source tree hash unchanged throughout |
| 9.7 | **DB-version check** | `format_gate.py` exit 0: the constants (`ProgramDB` 33, `DataTypeManagerDB` 3, `DataTypeArchiveDB` 5, `ProgramUserDataDB` 1, `SlaFormat` 4 on the sync branch) equal `format-matrix.json`; `hello.analysisIdentity.dbVersions` equal them at runtime and are not `-1`. A changed constant without a matrix entry and release note fails the merge, and also fails any future upstream sync |
| 9.8 | **Compatibility** | a raw protocol-2 transcript against hydra.4; the 1.1.0 client against hydra.3 (real install) and a fake protocol-2 server; Hydralysis 0.5.x test suite against hydra.3 (degraded set) and hydra.4; `bump_hydra.py` output verified against the zip SHA-256 and its edit set equal to the list of 5; the two copies of `canonical-manifest.json` (engine and Hydralysis) are byte-identical and both languages verify the other's manifest (3.4) |
| 9.9 | **Fault matrices** | Hydralysis commit points (4.6) with oracle O1-O6; engine `backup_fault`; Y0a torn and zero-length files; all green |
| 9.10 | **Measurements recorded before any constant is fixed** | fsync latency per volume (F: Dev Drive on USB NVMe, C:, D:, E: HDD); store write cost at 1, 4, 16 writers, **including `write_json` of job and progress records, which now does a read, a `.bak` write and a main write (two fsyncs, two replaces: about 16 ms per 600-byte record on D: in Y0a's review, unmeasured on F:, C: and E:) and is rewritten often by export workers**; backup hash throughput; clone against copy on KotOR (122 MB) with the 1.5 GB program as a stress case only; private-instance open cost on KotOR; quick-lane p99 with the long lane saturated, before and after; the per-phase named-view cost. `quickScriptMaxS`, grace times, ETA budgets, `SYNC_LOCK_S`, copy limits and the private default derive from these |
| 9.11 | **Hygiene** | every commit authored and committed as `KelpHect <kellhect@gmail.com>` (checked with `git log --format='%an <%ae> | %cn <%ce>'`); `certification.manifest` lists every new file and `buildHeadless` passes the IP check; docs state every limit of section 6; `examples/check_ownership.py` passes for every package branch (8.1) |
| 9.12 | **Verification gate: red before green, and an oracle that can fail** (D48) | X0's self-test flags every planted violation X1-X5, X7-X11 and tolerates X6; the red table recorded on hydra-3-candidate and `hydra-session-after` reproduces each recorded defect within its range (BP3 refusals 2.5-12.0 s; BP7 all 9 probes; BP8 9,421 ms; BP9 6 of 6; BP10 10.2-10.5 s; BP11 write applied by a dead client; BP14 94 of 114 polls; the version-file poison 12 of 363 and 7 of 95; fork 12 of 162 (its 4 `.rep` without `.gpr` were not reproduced in review, D41); Hydralysis `no_project` with 4 threads); a package's test is accepted as evidence only if it was red on the old build and is green on the new one; a row that does not reproduce is reported, not tuned away. Exit 0 verified |
| 9.13 | **Non-blocking gate (NB, G-NB)** on the hydra.4 build | B's `s1` (three variants), `s2`, `s4`, `s5`, `s7`, `s11`, `s13` and A's `lanetest` re-run: `waits.foreignBlocked` is 0 for reads of a sealed generation and for view operations (K13); zero refused probes in the variants that refused before; another project's `open_project` during a writable wait in 100 ms or less (9,421 ms before); a 7th client's script, save and fork in 1 s or less with six long scripts running (10.2-10.5 s before); reader throughput under four view writers at least 0.9x the no-writer baseline (shared-mode writers: 0.27x); a dead client's queued write never applied; cancel and disconnect release a lock wait within `cleanupGraceS + abandonWaitS + 1 s`; E3c's enumeration of the 17 `lock_matrix.json` rows has a decision for every row; `s1` (a, b, c) and `reader_leave_no_freeze` are E3c's gate (D63b) and `owner_leave_bounded` is E3b's (D63a); DB-bound reads at 8 clients scale at least 3x **only if E11 is built**. Latency thresholds come from a quiet-machine run (foreign load recorded below 25% CPU), are reproduced twice before they fail, and are report-only on a loaded machine |
| 9.14 | **Resource gate (G-RES)** | 24 views at `-Xmx256m` end in structured `busy` with 0 `OutOfMemoryError` and a live reaper; 24 views at `-Xmx512m` run; a 100-view probe is refused at `maxViews`; decompiler kill -9, hang and timeout leave other requests unaffected and the next request working; a daemon kill leaves no orphan decompiler or worker, tested with **suspended** decompilers and a no-job control that must show survivors (K7, SP3(b), D60), and the launch outcome of both harness-job variants is as SP3(a) expects (D65); a runaway or deaf script is quarantined and counted, **and a deaf script that ignores cancel and interrupt is killed at its timeout by E7, **on a view with unsaved edits** (the owner saves once, the script sees the edit, a stale read fails the test), its slot and the owner's long cap released, with the worker's start-up and RAM cost recorded (SP10, D64); until these E7 items pass the documents say "bounded and quarantined", not "killed"**; throughput not below the A baselines (9.18) |
| 9.15 | **Crash gate (G-CRASH)**, counted | with trigger-timed kills (the method of C, X0's library): at least 400 save kills (200 NTFS, 200 ReFS) with 0 unopenable and 0 unrepaired; at least 300 `fork_project` kills with 0 blocked retries, 0 `.rep` without `.gpr`, 0 leftovers after the sweep; at least 200 publish and `promote_overlay` kills; at least 50 daemon kills with 8 clients; every kill followed by K1-K17; Wilson bounds reported, wording "below 0.75% at 95%" after 0 of 400; the canonical hash unchanged. Single-run results of rev5 are replaced by counted ones |
| 9.16 | **View-cost gate (G-VIEW)** | Z2's `named_view_cost`: the median of at least 5 runs of the first-edit time at 1, 4 and 12 simultaneous new views, shared base against rebuilt base, NTFS and ReFS, foreign load recorded; the 0.3 to 0.55 s prediction is quoted nowhere until this gate reports; the result decides the spare-view pool (not in the first cut) and `publishBatchMax` (with SP7) |
| 9.17 | **Chaos and soak gate (G-SOAK)** (replaces 9.5) | harness E6 on X0's library with a ground-truth ledger the harness itself flushes. Workload per agent: reads (decompile, `functions`, xrefs, Hydralysis queries), edits in its view, publish, rebase, analysis in a candidate, deaf and runaway scripts, bulk opens. Faults (each class must fire a minimum count or the run cannot pass): kill -9 of random clients, of the daemon (wait for exit) at random and trigger-timed, of a native decompiler, of a publish leader mid-build; suspend of the daemon and of a client; a client that stops reading its socket; a handle holder during saves; an out-of-memory probe that tries 100 views. **PR lane**: 4 agents x 2 projects, 10 min. **Nightly**: 16 agents x 4 projects, 2 h, at least 150 kills. **Release**: three consecutive green nightly runs on NTFS plus one on ReFS (a fixture under 10 GB on F:, cleaned up), plus **one** run of 24 agents x 6 projects (a KotOR copy, the fixture, imported executables) for at least 4 hours. Pass: zero oracle violations, `waits.foreignBlocked` 0, no unexplained `busy`, no leak. All daemons use fresh state roots under `D:/Projects/Hydra/_logs/<stream>/` and are stopped at the end |
| 9.18 | **Compatibility and performance (G-COMPAT, G-PERF)** | the seven v2 goldens identical; every row of 5.1 (V1-V11, G1-G8) has its `cc_` test; the 12.1.4-against-12.3 decompile difference (77.124% of 8,616 identical on KotOR; Z7 measured that `maxBadData` 4 does not explain it, 8.6) is **reported, never gated** (owner); an interleaved A/B (A's method) of hydra.3 against hydra.4 at 12 agents: median throughput not below 0.9x and CPU-seconds per function (0.031 to 0.041) within 10% |
| 9.19 | **Claims gate (G-CLAIMS)** | `tests/test_claims.py` passes against `docs/data/claims.json`; no sentence of the 25 claims of 8.3 is stronger than the status of its flipping test; the site build fails when its copy of the ledger differs from its source; the banned phrases of D52 are absent from the engine README, the module README, the CHANGELOG, the Hydralysis README and skills and the site (a grep gate) |
| 9.20 | **Spikes gate (G-SPIKE)** (revision 7: the number that "9.20" cited without defining) | every spike that gates a package of the release has its script and its output file under `D:/Projects/Hydra/_logs/<stream>/`, run on a quiet machine with the foreign load recorded, and a recorded go or no-go. **Which spikes gate which release:** hydra.4 needs SP3 (E9's process job and P1b's launch sequence), SP4 (E9 crash isolation), SP5 (E8), SP6 (E2a) and SP10 (E7), and SP7 before any publish latency figure is quoted; SP1, SP2 and SP8 (E10, E11) gate hydra.5 and SP9 gates `yieldSlots` only if it is to be switched on, so none of them waits for or blocks the hydra.4 tag. A package that depends on a spike does not start before its spike has run; a failed spike stops its package and falls back to the decision named in the table, never to a weaker claim |

**Spikes (revision 6; gate 9.20).** A constant or a package that rests on an unmeasured Ghidra or Windows behaviour waits for its
spike; a failed spike stops the dependent package and falls back to the decision named, never to a weaker claim. Each spike is
a script and an output file under `D:/Projects/Hydra/_logs/<stream>/`, run on a quiet machine with the foreign load recorded.

| # | Question | Decides |
|---|---|---|
| SP1 | Is a read-only open of the stored file safe, on Windows, while another instance saves a new version of the same program? | E11; whether readers of a program under analysis can be served from the stored file; otherwise D37 stands |
| SP2 | Heap, disk and first-edit time of an overlay-backed view against a fork view, on KotOR and on the 1.5 GB program | E10; `estHeap` and `maxViews` defaults |
| SP3 | **Containment and survival of the daemon (D60, D65).** (a) *Survival*, both variants, with the real launcher and the real daemon: the launcher runs in a kill-on-close job (i) with breakaway rights: expected `spawn:"breakaway"` and a daemon that answers `health` after the job is closed; (ii) without breakaway rights: expected breakaway WinError 5, `spawn:"wmi"` and a daemon that answers `health` after the job is closed (an environment-free start: the WMI route is checked with the real configuration); negative control: with the WMI route disabled (ii) must end `bound_to_harness` with the daemon dead, and a launcher-owned kill-on-close job (the revision 6 design) must kill the daemon. (b) *Containment*: the daemon with its own job spawns 12 native decompilers that are then **suspended** (`NtSuspendProcess`) or hung, so that they cannot exit on their own when the pipe closes; `TerminateProcess` of the daemon; none survives within 5 s. **No-job control, which must show survivors** (the same run with `ProcessJob` disabled leaves the 12 suspended decompilers alive; a test whose control shows no survivors proves nothing and fails the spike); also with busy decompilers, which exit on a closed pipe with or without the job. Java-spawned `decompile.exe` inheriting the job was measured 4 of 4 (`review-rev7/exp_jvm_job.json`) | E9 `ProcessJob`, P1b's launch sequence; GR9 and "survives the harness" are not claimed before it passes |
| SP4 | Can an in-process `DecompInterface` be disposed and recreated after its native process was killed? | E9 crash isolation |
| SP5 | Does flushing before the rename keep Ghidra's version chain and index, and is the second flush idempotent; save time before and after | E8 |
| SP6 | Does the fork publish survive a handle holder (antivirus, indexer) on NTFS and ReFS, with retry and backoff? | E2a |
| SP7 | Publish latency at 1, 4 and 12 publishers (fork + replay + save + verify) | `publishBatchMax`, the bound of 4.10 |
| SP8 | DB-bound read scaling and heap with K read-only instances of one stored file | E11 go or no-go |
| SP9 | A stress test of `Ticket.yieldSlot` with a reserved re-entry slot: no deadlock, and `s5` improves | `yieldSlots` may leave off |
| SP10 | Script worker JVM start-up time and RAM | E7 (hydra.4, D64): the hydra.4 tag waits for it |

## 10. Open owner decisions

Only the choices that are genuinely the owner's. Each has the default this design assumes if no answer
comes, and what it blocks.

OD8 to OD14 were answered on 2026-10-28 with "use your defaults"; they are marked **decided (owner delegated defaults)** below and in every place that cites them.

| # | Decision | Default | Blocks |
|---|---|---|---|
| OD1 | **Backup policy.** DECIDED (revision 6): a second independent copy by default (`backup_min_independent` 1); the second root is configured, OD9; the 50 GB ask-first rule stays. A same-volume clone does not survive loss of the volume. | decided | Y2 config defaults, Y4d |
| OD2 | **Generation mode against the Ghidra GUI.** REMOVED (revision 6): there is no GUI and none is planned (D36). | removed | |
| OD3 | **Daemon singleton and the two live daemons** (18220 `default` at `F:\dev-cache\hydra-state`, 17936 `rusticre` at `F:\dev-cache\rusticre-latest`): consolidate into one root and enforce `singleton:"per-install"`? Changing the instance id or state dir starts a second daemon, so a Hydralysis rename of `INSTANCE` must wait. | Warn only; no consolidation by this stream | P1b default policy |
| OD4 | **Supervisor default.** CHANGED (revision 6, D55): auto-restart only once a durable journal exists, waiting for the process to exit, within the 3-per-10-minutes budget, refusing while non-recoverable unsaved edits exist | on, gated by `journal.durable` | Y4a default |
| OD5 | **Tag and publish hydra.4 and pin Hydralysis to it** (and the visibility of the private Hydralysis repo). This stream creates no tag, release, push or PR. | Not done | R1 follow-up, Y4a |
| OD6 | **Legacy window.** hydra.4 and hydra.5 serve protocol 2; refuse it from hydra.6? | Review at hydra.5 | none now |
| OD7 | **Per-agent default views and the agent identity.** DECIDED (revision 6, D43, D45): views are the default; `options.as` with the fallback `<client name>@<boot id>` (one rule, D59); any holder of the confirmation may publish through the queue; an optional `publish_policy` can name one integrator identity | decided | Y5 |
| OD8 | **Retention of generations and views.** **Decided (owner delegated defaults, revision 7):** keep the last 3 generations and evict idle views after 24 h, both configurable (`generationKeep` 3, `viewIdleDeleteS` 86400, 3.7). D28 stands: nothing deletes a backup, a generation or a candidate automatically; the doctor lists every generation beyond the newest 3 (never generation 0, the head, a revert target or a live view's base) and `backend action=backups options.op=remove` deletes one only with `confirm:true`. A view's fork folder is a disposable cache (D43), so deleting it after 24 h idle loses nothing (the store holds the records); admission still refuses at `diskReserve`, and the 50 GB ask-first rule stays | decided (owner delegated defaults) | Y2, Y4b, Y5 |
| OD9 | **The second backup root** (OD1 is decided: a second independent copy by default). **Decided (owner delegated defaults, revision 7):** `E:\dev-cold\hydralysis-backups`, configured in `config.json`; the engine hard-codes no path | decided (owner delegated defaults) | Y2 defaults, Y4d |
| OD10 | **Name of the integrity cut.** **Decided (owner delegated defaults, revision 7):** there is no separate interim integrity release. E8 and E2a land in W1 and ship in hydra.4; the tag names stay `12.3-hydra.<n>` (D1, D35, 5.3) | decided (owner delegated defaults) | the hydra.4 release |
| OD11 | **Labels** of the Hydralysis releases. **Decided (owner delegated defaults, revision 7):** Hydralysis 0.5.0 "qualified" is the client only, on the hydra.3 pin; 0.6.0 pins hydra.4 (5.3) | decided (owner delegated defaults) | R1, Y4a |
| OD12 | Pull E7 (the killable script worker) into hydra.4. **Decided (owner delegated defaults, revision 7):** yes, as a gated package in W5 (D64): deaf scripts that hold a slot and a lock are a measured blocking point. The claim waits for its gate (9.14) | decided (owner delegated defaults) | E7 |
| OD13 | A small quota volume (a VHD, may need administrator rights) for ENOSPC tests. **Decided (owner delegated defaults, revision 7):** no quota volume; disk-full is tested through the fault-injection seam (Hydralysis: a patched write raising `ENOSPC`; engine: `diskReserve` above the free space, 3.12), and a real ENOSPC inside a Ghidra save is neither tested nor claimed | decided (owner delegated defaults) | 9.15 disk lane |
| OD14 | **Site and engine wording pass first.** R0 and S1 land in W0, before any engine package. **Decided (owner delegated defaults, revision 7):** yes; S1's wording edits are prepared on a local branch of `F:/Projects/hydra-engine-site` and are **not deployed**; deploying hydrare.dev stays an owner action | decided (owner delegated defaults) | S1, S2 |

Decided here rather than asked (veto by saying so): `minClient` stays 1.0.0 (D4; it is also a required
line of the release notes, 5.2); `save` is in the maint lane for v3 connections (D16, 5.1); no inference of the quick lane (D16); commit and publish ride `type_edit` kinds (D25); no
automatic deletion (D28). Revision 7 records OD8 to OD14 as decided from the owner's delegation of defaults. Revision 6 decided from the owner's list: per-agent views required, the second backup by default, runtime evidence and coverage before memory write, fixture-first runtime proof, the 12.1.4-against-12.3 diff reported and never gated, auto-restart only after the journal exists, no daemon-root consolidation, ReFS warn only, Hydralysis 0.5.0 qualified, work on D:.

---

## Appendix A: code facts and where they were read

Branch `feat/session-extract` @ `b6df709e1e` (Hydra) and `feat/hydralysis-0.5` @ `d0466bc` (Hydralysis).

| Fact | Where |
|---|---|
| Inline commands are `ping`, `cancel`, `status`; a **repeat** `hello` is not inline (the first `hello` of a connection is answered synchronously by `Connection.authenticate`, `Connection.java:187-205`); admit happens before the command runs | `Session.java:219-221`, `:223-250` |
| `Session.info()` builds both hello and the status header; `PROTOCOL_VERSION = 2`; `CLEANUP_WAIT_MS = 600_000` | `Session.java:319-337`, `:51-52` |
| `disconnect` cancels, then `leaveProject(c, p, true, CLEANUP_WAIT_MS)` | `Session.java:109-129` |
| `reap` uses non-blocking `tryLock` on the project and program | `Session.java:167-214` |
| `laneOf(String cmd)`: `script`, `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay` are LONG; the queue is keyed by `c.id`; `m.waiting(lane + " slot")` has no queue info; `describe()` takes `lock.lock()`; release is round-robin by client; the slot wait polls its own condition in 100 ms steps and checks cancel | `Scheduler.java:59-69`, `:84`, `:152`, `:155`, `:285-290`, `:266-277`, `:157-183` |
| `Scheduler.admit(c, cmd, m, waitMs)` has two callers: `Session.execute` (not for `import`) and `ImportCommands`; `ImportGate.enter(kind, who, clientId, project, what, bytes, m, waitMs)` receives only `c.id` (`ImportGate.java:165`, called at `ImportCommands.java:100`); the import wait already puts `queue` in progress events (`ImportGate.java:188-194`) and `status.requests[].queue` (`RequestMonitor.java:111`) in protocol 2; `Scheduler.describe()` takes no argument (`Scheduler.java:285`) | `Scheduler.java:138`, `Session.java:248`, `ImportCommands.java:100`, `:112`, `ImportGate.java:165`, `:188-194`, `RequestMonitor.java:111`, `Scheduler.java:285` |
| `Connection.run`: cancel, `awaitTermination(1, HOURS)` twice, then `session.disconnect`; `Caller.enter` in `respond`; `annotate` adds `stale`/`refreshed` | `Connection.java:93-108`, `:211-250` |
| Lock waits are one timed `tryLock(wait)` and ignore cancel; the three locks are **fair** `ReentrantReadWriteLock`s | `Access.java:105-109`, `ProgramEntry.java:191-196`, `OverlayCommands.java:142`; `ProgramEntry.java:115`, `ProjectEntry.java:43`, `Overlay.java:54` |
| `RequestMonitor.cancel()` is `TaskMonitorAdapter.cancel()` (public, overridable); the deadline timer calls it; `Session.cancel` and `Connection.run` call it | `TaskMonitorAdapter.java:123`, `RequestMonitor.java:118-121`, `Session.java:393,409`, `Connection.java:95-97` |
| `Caller.enter(Client, Identity)` stores no monitor; `scope()` exists | `Caller.java:41-50`, `:86-90` |
| `RequestMonitor.waiting(what, queueInfo)` exists and feeds progress events | `RequestMonitor.java:93-101`, `:191-193` |
| `expect` is wired for rename, label, comment; `signature` and `data_type` compute `oldSig`/`oldType` without comparing | `Operations.java:48-60`, `:157`, `:186`, `:229-271` |
| `withLastEditor` maps `name` and `comment` only; `Journal.fieldOf` returns the op name for the rest; a journal entry is a copy of the per-op result plus `seq`, `at`, `client`, `name`, `harness`, `cmd` | `EditCommands.java:49-70`, `:76-88`, `Journal.java:103-125` |
| Contained scripts: outer transaction always rolled back; `modBefore` read; `changed:false` by construction when contained; `exclusive` flag | `ScriptCommands.java:92`, `:172-196` |
| `loadOverlay` uses `getReadOnlyDomainObject` / `openReady` | `OverlayCommands.java:277-314` |
| `olderFormat` reads `DB Version` and `Language Version` without opening the program, swallows errors to `null`; `currentDbVersion()` is **private static**, returns `-1` on failure, feeds `CURRENT_DB_VERSION` | `UpgradeCache.java:986-1042`, `:1056-1065`, `:107` |
| `openWritable`: `getDomainObject(e, upgrade, false, m)` | `ProgramCommands.java:408-439` |
| `fork_project`: temp folder then move; `Revision` before and after (a changed source removes the copy); sidecar (`kind ghidra-session-fork`, no `disposable`; a failed write only warns); `writable` defaults to true; success reply has no file-system fields; refusal `cost` has them | `ForkCommands.java:54-277`, `:205-214`, `:246-257`, `:82`, `ProjectFork.java:92-179` |
| `ProjectFork.clones`: Windows and ReFS only | `ProjectFork.java:138-141` |
| `Revision.of`: size and mtime for files above `HASH_LIMIT` (1 MiB); excludes `projectState` | `Revision.java:51-80`, `UpgradeCache.java:98` |
| Import: unlimited gate wait, then `admit` and `lockProject` with the default 10 s | `ImportCommands.java:77-114`, `Requests.java:30-44` |
| Endpoint file and `ready` carry `protocol`; hydra.2 client sends `protocol` in hello and checks equality on hello and endpoint | `HeadlessSession.java:187`, `:356`; `ghidra_session.py:850-852`, `:105-125`, `:1000` |
| `Daemon.connect(start=...)`, `jvm_alive` (instance lock), `LaunchError`, `sock.settimeout(None)` | `ghidra_session.py:1004`, `:969-979`, `:89`, `:845` |
| README rules: additions need no protocol change; protocol "must be equal"; 12.1.4 program DB 32 and data type DB 2 against 33 and 3 (README line numbers are at the design branch tip, +2 after `README.md:538`) | `README.md:988-992`, `:973`, `:1003-1004` |
| `target_key = sha256(resolved gpr + program)`; overlay store, working dir and view key derive from it | `targets.py:114-117`, `workcopy.py:36-47`, `:105-106` |
| `_save_store` and `write_json`: write then replace, no fsync | `workcopy.py:72-80`, `backends.py:50-54` |
| `edit()` stores inside `.sync.lock` before returning; `_prefix_matches` heals a marker ahead of the store | `workcopy.py:543-554`, `:341-349` |
| `_base` keyed by master revision and engine release | `workcopy.py:290-328` |
| `Engine.call` retries every command once after `closed`; `EngineError` keeps only some detail keys | `hydra.py:268-287`, `:51-63` |
| `RusticQuery`: `apply_overlays`, `overlay_state` marker; no `effects`, `verify_before`, `annotation_probe`; 17 `checkCancelled` sites | `RusticQuery.java:2300-2345`, `:126`.. |
| Every query is a `script` call with `timeout = timeout_s + 5` and a 180 s wait | `query.py:76-91`, `:29` |
| `TOOL_WORKERS = 4`, `MAX_OUTSTANDING = 8`, `listChanged: False` | `mcp.py:22-23`, `:45` |
| `ghidra_query` has an `options` bag; `ghidra_run` has `view` but no `options`; `backend` and `job` have none | `api.py:61-137` |
| `tools/golden.py` and `docs/golden-harness.md` exist; no `tools/bump_hydra.py` | Hydralysis tree |
| The 317 characterization steps record replies only (no progress events, older-format projects or lock timing); none carries `expect` on `signature`/`data_type`; `hydraVersion` is masked | `examples/characterization/*.json`, `characterization_tests.py` docstring |
| Gson 2.13.2 with `disableHtmlEscaping()` still writes U+2028/U+2029 as `\u2028`/`\u2029`, control characters as lower-case `\u00xx`, and keeps insertion order (run against the jar in the hydra-3 candidate install) | `Ghidra/Framework/Generic/lib/gson-2.13.2.jar` |
| Hydralysis depends on `pefile` and `capstone` only; the 8 fixture programs of the golden set | `pyproject.toml:9-12`; `D:/Projects/Hydra/_golden/sets/fixtures.json` |
| `Engine.module()` loads the session library from the engine install; connections are keyed by role; the 1.0.0 `send`/`wait` are thread-safe and `SocketSession` waits with `settimeout(None)` | `hydra.py:229-233`, `:227` at d0466bc (`:315-321`, `:313` at 589432e); `ghidra_session.py:681-682`, `:732-738`, `:845` |
| `SocketSession.close()` closes `_w` and `_r` before `sock.shutdown`; `wait()` holds `_read_lock` (`:748`) inside `_r.readline()` (`:753`): `close()` from a second thread hangs and sends nothing (experiment, 7.6); the hydra.2 library and the one in the hydra-3 candidate differ only in `HYDRA_RELEASE` | `ghidra_session.py:740-776`, `:866-874`; `D:/Projects/Hydra/_logs/spec-rev3/exp1_client_matrix.py` |
| `Connection.run` on EOF or reset: `leaving`, cancel every running monitor (observed: `cancelled` false to true), `awaitTermination(1, HOURS)`, no socket close and no unregister until the request threads end (observed on a real hydra.3 daemon) | `Connection.java:93-108`; `D:/Projects/Hydra/_logs/spec-rev3/exp2_engine.py`, `exp2_summary.txt` |
| A connection is a **client**: the project and the program a call uses belong to it. `Access.projectFor` refuses a project the client has not joined (`no_project: this client has not joined project p1; send open_project`); a script's `program` key must be one the client opened (`no_program`); `open_project` and `open_program` add the client to the `users` set of the project and the program (a `LinkedHashSet`, no limit); `Session.reap` leaves a program with users open; a clean close, a FIN of an idle connection and the end of a request after a FIN remove the entry, an abandoned connection that sent no FIN and is never closed does not (measured: `users` `[2, 14]` to `[2]`; `[2, 16]` stays) | `Access.java:82-85`, `ProjectCommands.java:83-84`, `ProgramCommands.java:236-237`, `ProgramEntry.java:148`, `Session.java:171-173`; `D:/Projects/Hydra/_logs/spec-rev4/exp5_pool_entry.py`, `exp5_small_out.txt`, `exp5_kotor_out.txt` |
| `ProgramCommands.releaseUse` takes the program's **exclusive** lock for every leave (`close_program`, `leaveProject`, `Session.disconnect`); the program lock is a fair `ReentrantReadWriteLock`, so a queued exclusive makes every new shared acquirer wait behind a running reader: a new entry's `open_program` and an already-joined entry's script fail `busy` after their `wait` (measured on hydra-3-candidate and the refactor build; absent when the leaving entry was never closed, and with the fast path of 3.5 compiled over the same engine) | `ProgramCommands.java:461-472`, `:480`, `ProjectCommands.java:286-327`, `ProgramEntry.java:115`, `:191-196`; `D:/Projects/Hydra/_logs/spec-rev5/exp/` (`exp11_rerun.py`, `exp12_rerun.py`, `exp13_leave_rules.py`, `exp14_last_user.py`, `exp15_busy_first_script.py`, `exp16_first_script.py`, `exp16c_cold_script.py`, with their `*_out.txt`) |
| The pinned release literal `12.3-hydra.<n>` is in `hydra.py` (`RELEASE`), `tests/fakehydra.py:28`, `tests/test_backends.py:21` and `:101`, `tests/test_query.py:285-296`, `README.md:50`, `THIRD_PARTY.md:16` and `docs/upstream-setup.md:24`, and as history in `docs/golden-harness.md` and `docs/verification-*.md`; `hydra.py` builds the message `test_backends.py:101` asserts from `RELEASE` | `git grep` at `8e696e2`; `hydra.py:30`, `:216-217` (`:29`, `:190-191` at `589432e`) |
| `tests/test_contracts.py:111-157` and Y0e's `tests/test_cli.py` assert `not_available` for `doctor`, `backups`, `ghidra_run` `options` and `job` `options` through the real dispatcher | `tests/test_contracts.py`, `tests/test_cli.py`; `api.py:426`, `:504-526` at `f46788b` |
| `Engine` (`hydra.py:209` at d0466bc, `:295` at 589432e) is one connection per process and root, shared by every thread; `_keys` is a module dict keyed `(engine.key, gpr, program, writable)`; `forget(engine)` drops one engine's rows; `QueryRunner._ask` retries once after `no_program`, `not_found`, `no_project`, `closed` | `hydra.py:209`, `:227`, `:268` and `:295`, `:313`, `:385`; `query.py:33`, `:49`, `:70`, `:184-210` (same at both bases) |
| On hydra.3 a request with `wait=3000` for a program held by another client is answered `busy` at 3.0 s and leaves nothing registered; `shutdown(SHUT_WR)` ends every request in flight on the connection (B cancelled 0.02 s after the FIN, A, which ignores cancel, went on for 12.1 s) | `D:/Projects/Hydra/_logs/spec-rev4/exp6_wait_and_collateral.py`, `exp6_out.txt` |
| Overlays have no journal; the overlay lifecycle takes untimed `lock()` calls | `OverlayCommands.java:228, 238, 251, 319, 352, 404`; no `journal` in `OverlayCommands.java` or `Overlay.java` |
| `AppendLog` at Hydralysis `589432e` read whole logs through `localio.read_bytes` (32 MiB budget; streamed since `2bf90c7`); the write gate freezes 41 (file, function, kind) keys outside `durable.py` (43 call sites): 11 non-record keys, 8 record-bearing and 22 artifact keys | `durable.py` (`AppendLog`), `localio.py:18`, `tests/test_durable.py` (`FOLLOW_UP`, `NOT_A_RECORD`) |
| hydra.3 candidate: `decompile.exe` sha256 starts `4f4680aa1c22`; gate PASS, KotOR 8616/8616 identical to hydra-2 | `t2_impl_gate.json` (stream report) |
| Revision 6: `LocalManagedBufferFile.saveCompleted` renames the pre-save file to `db.N+1.gbf` (`renameFile`) and only then calls `setReadOnly()`; `LocalManagedBufferFile.setReadOnly` calls `super.setReadOnly` (`:375`) whose `flush()` writes the header and syncs (`LocalBufferFile.java:822-825`, `flush` `:768`, `raf.getFD().sync()` `:785`) | `LocalManagedBufferFile.java:677-710` (`:696`, `:709`), `:360-375`; `LocalBufferFile.java:502`, `:768-790`, `:822-825` |
| Revision 6: `ProjectFork.copy` stages into `.<name>.fork-<hex>.tmp`, moves `.rep` then `.gpr`; the sidecar is written afterwards and a failure only warns | `ProjectFork.java:155-185`, `ForkCommands.java:246-257` |
| Revision 6: `openProject` calls `makeWritable` (which waits for the project lock) inside `synchronized (s.registry)`; the same monitor guards `leaveProject` and `reap` | `ProjectCommands.java:70-77`, `:104`, `:309`; `Session.java:177` |
| Revision 6: the decompiler pool is per program entry or overlay (`borrowDecompiler`, a new `DecompInterface` per borrow when none is free), with no bound across clients | `Decompilers.java:15-28`, `ProgramEntry.java:45`, `:287`, `:299`, `Overlay.java:47`, `:89` |
| Revision 6: `Connection` has one single-thread worker per connection; `run` waits `awaitTermination(1, HOURS)` for it and the parallel pool | `Connection.java:63`, `:99-102` |
| Revision 6: measurement streams A, B, C, D | `D:/Projects/Hydra/_logs/measA/`, `lockmap/`, `crash-C/`, `claims-audit/` |
| Revision 7: `workcopy._start_saver` spawns `hydralysis.workcopy_saver` (one process per target on `.saver.lock`), which reopens the fork writable with `upgrade` and `refresh`, saves with `wait=600000` after a 600 s debounce and takes `.sync.lock` for 120 s; `tests/test_durable.py` has an allow-list row for `_start_saver` and asserts that no entry is stale | `workcopy.py:421-437`, `workcopy_saver.py:23-69` at `627b5b5`; `tests/test_durable.py:1027`, `:1127` at `8e696e2` |
| Revision 7: `locks.locked` raises a bare `ValueError("<what> is busy ...")` when its timeout ends; `LaneLock.acquire` is a non-blocking OS lock | `locks.py:79-92`, `:20-50` at `627b5b5` |
| Revision 7: the launcher starts the daemon with `DETACHED_PROCESS` and `CREATE_NEW_PROCESS_GROUP` and, when the caller's job allows it, `CREATE_BREAKAWAY_FROM_JOB` | `ghidra_session.py:1058-1062` at `b6df709e1e` |
| Revision 7: six v2 goldens carry `status.scheduler.quick.slots` and `long.slots` (20 occurrences); `slots` is not in `VOLATILE` | `examples/characterization/{clients,fork_refresh,import_script,overlays,readonly,session}.json`, `characterization_tests.py:150-169` at `f47ff15934` |
| Revision 7: the `options` bags of `ghidra_query`, `ghidra_run`, `backend`, `job` and `runtime` are free-form objects documented by `OPTION_BAGS`; one `clientInfo` is read per connection and labels every engine request | `api.py:72-82`, `:114`, `:157-181`; `mcp.py:57`; `hydra.py:312` at `627b5b5` |
| Revision 7: fork times and sizes of measurement A | `measA/out/forkcost-ntfs.json` (`seq`, `conc`), `forkcost-refs.json`, `hlm-b.json`, `hlm-d.json` |
| Revision 8: `_spawn` swallows the `OSError` of `CREATE_BREAKAWAY_FROM_JOB` and falls back to staying in the caller's job; nested job assignment always succeeds, so a daemon in the harness's kill-on-close job dies with it | `ghidra_session.py:1058-1065` at `b6df709e1e`; `review-rev7/job_nobreak.json`, `job_breakok.json`, `job_wmi.json` |
| Revision 8: Java-spawned `decompile.exe` inherit the JVM's job (4 of 4); a busy decompiler exits when its pipe closes with or without a job; a suspended one survives without the job and dies when the job handle closes | `review-rev7/exp_jvm_job.json`, `exp_jvm_job_control_busy.json`, `exp_jvm_job_control_hung.json`, `exp_jvm_job_withjob_hung.json` |
| Revision 8: the process enters through `SessionMain.main`, which calls `GhidraLauncher.launch` with `HeadlessSession` as the class; `HeadlessSession.launch` is an instance method; no `--enable-native-access` exists in the launcher; the lane defaults are at `HeadlessSession.java:133-134` and the usage text at `:78-79`; the launcher comment is `ghidra_session.py:425-426` | `SessionMain.java:42-50`, `HeadlessSession.java:78-79`, `:97`, `:133-134`, `ghidra_session.py:425-426`, `:583` at `b6df709e1e` |
| Revision 8: Hydralysis `README.md:104` says the working copy is saved in the background after edits pause (`overlay_save_debounce_s`) and that clients share the default view | `README.md:104` at `627b5b5` |
| Revision 8: save cost on KotOR (NTFS) | `measA/out/forkcost-ntfs.json`: `save_solo.save_ms` 128, `save_12_concurrent` 324 to 779 ms |
| Revision 7: the review experiments (fork race, fork kills, Job Object ownership) | `D:/Projects/Hydra/_logs/review-rev6/exp1_fork_race.json`, `exp2_fork_kill.json`, `exp7_jobobject.json` |

## Appendix B: what the source designs got wrong or left out

Found by reading the code; each is handled in the section named.

1. **The target key is derived from the project path** (D11): a generation pointer flip orphans the
   overlay store. Design A said it had not enumerated `targets[].gpr` consumers; B and C missed it.
2. **`Engine.call` retries mutating commands** (4.3), which A rated harmless and B/C patched with a key everywhere.
3. **Dead-client release is not only `Connection.run`**: `leaveProject` and `releaseUse` wait 600 s (3.5).
4. **`olderFormat` returns "current" on any error** and the DB-version constant can be `-1` (3.4).
5. **`Revision.of` is metadata for large files**, so "revision equals" is not an integrity check (D13).
6. **`private` isolation cannot see unsaved shared edits**, which Hydralysis working copies hold (D20, 7.4).
7. **`RusticQuery` has no `effects`, `verify_before` or `annotation_probe`**: A's commit relied on them as if present (4.2, Y1 sized L).
8. **A replayed commit would be applied twice** unless the replay set excludes the committed records, and a scalar watermark is not enough once a commit can take a subset or skip a drifted record: commit state is a committed-id set (D32, 4.2).
9. **`laneOf` is static and cmd-only**; the `save`-if-fast heuristic of A needs state the lane decision does not have (D16, D17).
10. **A WAL under the program write lock** (B) protects an edit path Hydralysis does not use (D5).
11. **README's own versioning rule** says additions need no protocol change; none of the designs reconciled it (D2).
12. **The stock client refuses an endpoint of protocol 3**; "old clients keep working" needed `protocol:2` plus a maximum (D3), and RusticRE 0.4.x still refuses by pin (5).
13. **`tools/bump_hydra.py` does not exist**; the designs assumed it (R1).
14. **The generation sidecar hole**: "no sidecar means canonical" exempts every generation from the second on (D12).
15. **Test files would collide**: every package wanted `daemon_tests.py` (D30).

16. **(Revision 6) The three revision-6 drafts left gaps the judges and the code found.** Draft A's directory-rename fork publish cannot cover a
    destination folder that already exists (`ProjectFork.java:155-159`), and its engine `view_*` family and four-lane scheduler are not needed (D41, D43, D40).
    Draft B's repair-on-open renamed a version file on **read-only** opens, which would break the master-unchanged guarantee and could race a second
    daemon's in-flight save (D42), and its XL core rewrite rested on spikes that had not run (D37). Draft C's reorder of locks before slots lets a lock holder
    wait for a saturated lane (D39), and its `mutant=` switches put test branches into the release jar (D48). All three described the save-time defect
    imprecisely or not at all: it is an ordering bug (rename before the header flush), not a missing temporary name (D42).
17. **(Revision 6) The rev5 text itself:** "`_base` is built once per master revision" is false in the code (D44); "bounded waits satisfy 'locks do not block'"
    is false by measurement (D37); the README, the CHANGELOG and the site disagreed on eleven claims (D52).

## Revision history

**Revision 8.1 (amendments of the W1 coordinator: seven ownership and wording items, A2 to A8).** Docs only; no engine or client code is edited in this commit except `examples/check_ownership.py` (A2). One commit on `docs/spec-rev8-1` (worktree `D:/Projects/Hydra/wt/hspec`, from `57b7714be2`, the tip of `feat/w1-hydra`). Input: the coordinator's findings while integrating W0 and W1, the package branches `feat/w0-x0`, `docs/w0-r0`, `feat/w1-e8` and `feat/w1-e2a`, and the build files `gradle/support/ip.gradle` and `gradle/hydra/headless.gradle`.

**Revision 8.1: where each item landed.**

| Item | Verified against the revision 8 text and the tree | Disposition | Where it landed |
|---|---|---|---|
| A2 the id pattern of `check_ownership.py` | **Right.** On the revision 8 spec the script stopped with exit 2 (`wave plan W0: the package id(s) X0 are not parsed by PKG`); it read two of the three package columns of the wave plan, counted `E5 **then** E9` as two owners and had no site table | **Fixed in the script**, with 12 new self-test checks (24 to 36), after the first run on the package branches also fixed the root paths and the directory rows | E0 (amendment A2), `examples/check_ownership.py`, section 8 rule 4 and bullet, 8.5 |
| A3 E8 and `LocalDatabaseItem.java` | **Right.** `LocalDatabaseItem` wraps a `PrivateDatabase` when the file system is not versioned (its own class comment), so `VersionedDatabase` alone does not reach it | **Fixed.** New row, Files text, NOTICE row and Z15 guard wording (sixth patched core file) | 8.1, E8, 8.5 |
| A4 E2a and `Advertised.java` | **Right.** E2a enables `forkAtomic`; E1 registers names up front; the two are in W1 | **Declared as a sequence** E1 then E2a on that file only; E2a depends on E1; 23 in-wave dependencies, three file sequences | 8.1, E2a, wave plan, section 8 in-wave bullet, 8.5 |
| A5 `src/routes/embed/how-it-works.tsx` | **Right.** The file exists in the site repository; it renders the HowItWorks panel for the README recording and its notes say that analysis runs alongside questions "without slowing them" (claim C3 of 8.3) | S1 owns it in W0, S2 in W5 | 8.1 site table, S1, 8.5 |
| A6 crash-C forks | Instruction of the coordinator, recorded as given (the `crash-C` directory was not recounted in this revision); the 12 of 363 kills of 3.12 are kills of a scenario, a different count | Text corrected to nine; 3.12 is unchanged | X0 Tests |
| A7 `--client` | **Right.** Commit `c37b0e73b4` edits E0's file in W1 | Recorded as an E0 amendment | E0 (amendment A7) |
| A8 R0 grep gate; X0 manifest | **Partly.** R0 had a test promise and no test file. The premise on the manifest is wrong in its words (the IP scan does read `examples/`) and right in its conclusion (headered sources need no line) | Gate assigned to Z13a and S1; the manifest paragraph states what the build does | R0, Z13a, X0, section 8 manifest bullet, 8.5 |

**Proof output (revision 8.1)** (`D:/Projects/Hydra/_logs/spec-rev8/prove_disjoint_rev8.py`, unchanged, with the same default inventories as revision 8; output `D:/Projects/Hydra/_logs/spec-rev8-1/prove_disjoint_rev8_on_rev8_1_out.txt`; exit 0): *52 package ids identical in the wave plan table and the proof's plan; 123 matrix rows and 344 owner cells; 52 package blocks; files edited by the text but granted by no row or rule: none; three declared `then` sequences (`S/Advertised.java` E1 then E2a, `S/HeadlessSession.java` E5 then E9, `tests/test_durable.py` Y0e then Y1), each with the later package depending on the earlier one in the same wave; `LocalDatabaseItem.java` exists in the tree and is E8's; dependency cycles: none; RESULT: 0 violations.* Four plants on this text each exit 1: E2a without its dependency on E1 (`SEQUENCE-WITHOUT-DEPENDENCY`), E8's Files text without `LocalDatabaseItem.java` (`MATRIX-FILE-NOT-IN-TEXT`), S2's cell of `how-it-works.tsx` removed (`TEXT-FILE-NOT-IN-MATRIX`), and the `then` cell of `Advertised.java` reduced to E1 (`EDITED-BY-TEXT-NOT-GRANTED`). `table_check.py` (53 tables, 0 rows with a wrong cell count, 4 literal-pipe rows as before) and `consistency_rev8.py` (consistent) pass. `examples/check_ownership.py` on this text: 123 rows, 52 packages, 0 violations; `--selftest` 36 checks, 0 failures. **Package branches checked with the fixed script** (`D:/Projects/Hydra/_logs/spec-rev8-1/branch_checks.txt`, base `feat/w1-hydra` unless stated): X0 (`feat/w0-x0`) 36 changed files, 0 outside its rows; R0 (`docs/w0-r0`) 3, 0; E8 (`feat/w1-e8`) 6, 0 (including `LocalDatabaseItem.java`); P1a (`f47ff15934..fa7079b4b2`) 3, 0; E1 (`fa7079b4b2..b5f651e201`) 28, 0; E2a (`feat/w1-e2a`, its working tree) 8, 1: `examples/contract_tests.py` is E1's row, so E2a must not edit it (its `Advertised.java` change is covered by A4). Whole `feat/w1-hydra` read as one package shows the coordinator's own edits (this file, `characterization_tests.py` by A7, and P1a's files).

**Revision 8 (answers the independent review of revision 7: five blocking items and nine others).** Docs only; no code in any repository this stream owns; one commit on `design/protocol-3-rev8` (worktree `D:/Projects/Hydra/wt/hydra-design8`, from `0fc3730d88`, the tip of `design/protocol-3-rev7`). Input: `D:/Projects/Hydra/_logs/review-rev7/` (Job Object experiments with stand-ins and with a JVM, 14 mutation plants of the proof, the proof run). Every item was verified against the text of revision 7 first. Added: D65, D66, section 2.3, K1u, X11, and the unbackticked-name check of the proof. No claim of "never corrupts" or "never blocks" was added.

**Revision 8: where each item landed.**

| Item | Verified against the revision 7 text | Disposition | Where it landed |
|---|---|---|---|
| **1** a daemon-owned job does not make the daemon outlive its harness when the harness is in a kill-on-close job without breakaway rights | **Right.** D60, the P1b test, SP3(a) and GR9 promised survival from the daemon-owned job; nested assignment always succeeds, so "if the assignment fails" was dead code; `_spawn` swallows the breakaway `OSError` (`ghidra_session.py:1058-1065`) | **Fixed.** Containment (D60) and survival (D65) are separate. P1b detects the caller's job, tries breakaway, then spawns out of the job through WMI `Win32_Process.Create`, then stays with `daemon_dies_with_harness`; the outcome is a launch field (`caller_in_job`, `spawn`, `survival`) and a warning; the claim is limited to `survival:"independent"`; the P1b test and SP3(a) list both variants with expected results and a negative control | D65, D60, 3.8, 3.11, P1b, SP3(a), GR9, 7.1 (doctor), Appendix A |
| **2** the containment tests pass without any job | **Right.** `exp_jvm_job_control_busy.json`: busy decompilers die with the JVM without a job | **Fixed.** SP3(b), K7, GR9, the E9 test and X9 use suspended or hung decompilers and a no-job control that must show survivors (red without `ProcessJob`, D48); Java-spawned `decompile.exe` inherit the job, 4 of 4 | SP3(b), K7, X9 (3.12), GR9, E9, D60, Appendix A |
| **3** E7 clones the saved view and nothing saves a view fork any more | **Right.** D61 deleted the saver and kept the worker on the "saved view"; after the first edit the clone is stale and `attemptedChanges` cannot be measured | **Fixed.** D61's contingency is promoted: the owner saves the fork once, under the per-view lock, before a worker or private clone when the view has unsaved edits (bounded, in the lane `save` has); the engine refuses a worker on unsaved edits; the worker uses a private writable disposable clone; the 9.14 E7 test is specified for an **edited** view and a stale read fails it | D64, D61, D20, D47, 3.6, 7.4, E7, E4, Y4e |
| **4** E3a changes the `maxLong` default, which lives in `HeadlessSession.java`, without a cell; the proof reads only backticked names | **Right.** `HeadlessSession.java:133-134`, usage `:78-79`; the launcher comment `ghidra_session.py:425-426` | **Fixed.** E3a has a W2 cell and names the file; the owners are E1, E3a, then E5 and E9, one per wave, the chain checked by the proof; P1b owns the launcher comment. The proof reads unbackticked names in `Files` paragraphs and `.properties`-like names, and checks that a file naming a changed default has a row | 8.1, E3a, P1b, 8.4, the proof (`prove_disjoint_rev8.py`) |
| **5** Hydralysis `README.md:104` becomes false when Y2 removes the saver; the `saved` key disappears without a note | **Right.** The sentence and `overlay_save_debounce_s` are in `README.md:104` at `627b5b5`; the same sentence also says "Clients share the default view", which D43 makes false (found while fixing it, given to Y5) | **Fixed.** Y2 owns the README sentences (W2) and the "Changes in 0.5.0" note; Y5 owns the default-view sentence (W4); 5.2 has the 0.5.0 note; Z14 carries it into `CHANGELOG.md`; the saver scan covers `README.md`, `docs` and `skills` (no `docs` or `skills` file carries it) | 8.1 (`README.md` split from `THIRD_PARTY.md`), Y2, Y5, Z13b, Z14, 5.2 |
| 6 `test_view_lifecycle` asserts an eviction that Y5 builds in W4 | Right | Reworded to "close with discard, keep the folder, reopen replays" | Y2 |
| 7 candidate verification: 4.10 and K3 open the candidate writable, 4.6 verifies a read-only clone; "never reuses" against `resume_verified` | Right | Verification runs on a disposable clone, the candidate is never reopened, and the step 7 hash is the hash 7b seals; "never reuses" is the default, `resume_verified:true` publishes a sealed candidate after a re-hash | 4.6 (step 7, faults), 4.10 (step 4), K3, K1 |
| 8 "boot id" undefined; a harness restart strands pending edits | Right | Boot id defined (16 random hex digits per server start); view records carry agent name, boot id, pid and lease; adopt and resume rule (`adoptable`, `options.as` re-attach, `view_in_use`, `HYDRALYSIS_AGENT_ID`, `view_rebuilt`); test `restart_adopts_orphaned_view` | D59, 4.10, Y5 |
| 9 "first act of `HeadlessSession.main`"; the FFM flag has no owner; the orphan sweep is too wide | Right. The process enters through `SessionMain.main` and `GhidraLauncher`; `HeadlessSession.launch` is an instance method (`:97`); no `--enable-native-access` exists | `ProcessJob` starts as the first statement of `HeadlessSession.launch`; P1b owns `--enable-native-access=ALL-UNNAMED` (E9 depends on P1b); the sweep kills only a parentless `decompile` under this install's `Ghidra/Features/Decompiler/os/` | D60, E9, P1b, 8.1 |
| 10 gates and ordering: 9.20 waits for spikes of hydra.5 work; D64 against SP10; E7 "Parallel with: E6"; the in-wave list | Right on all four (E5 had the same "Parallel with: E6" error and is fixed too) | 9.20 and 5.3 state which spikes gate which release (hydra.4: SP3-SP7, SP10; hydra.5 or optional: SP1, SP2, SP8, SP9); "hydra.4 is not tagged" until the E7 gate passes, one statement everywhere; E7 and E5 no longer claim to be parallel with E6; the in-wave bullet lists all 22 dependencies the proof prints | 9.20, 5.3, SP table, D64, E5, E7, section 8 |
| 11 backups made on hydra.2/3 are never sealed on hydra.4 | Right | Backup sidecar fields defined (`purpose:"backup"`, `disposable:false`, `state:"complete"`, `SEALED.json`); legacy backups are listed `sealed:false` and adopted by `op=verify` (re-hash, then `seal_project`) or labelled `legacy_unverified` and refused as a source; test `legacy_backup_adoption` | 4.5, Y4d |
| 12 stale `.sync.lock` in PREPARE and FINALIZED; no lock order for marking other views stale | Right | The committing view's lock; FINALIZED takes the record lock of one other view at a time, never an edit lock; `.sync.lock` only as a citation of the code of `627b5b5` | 4.6 (preconditions, steps 1 and 9), 4.2 |
| 13 replay of a full store is unmeasured and every idle return pays it | Right | Z2 measures 1, 100, 1,000 and 4,096 records; the per-call threshold is 5 s; the fallback is keep-warm (`viewKeepWarmRecords`) and a lower store cap, not a save at eviction | D61, Z2, 3.7, 3.11, Y5 |
| 14 the sealed predicate depends on one sidecar field and a per-`stateDir` registry | Right | Three records (registry, sidecar, `SEALED.json`) and their union (D66); the client treats every `CURRENT.log` generation as sealed and reconciles; GR1 says "accident guard"; K1u, planted violation X11 and `dt_e2` `seal_union` | D66, D38, 3.13, V8, K1, GR1, E2, X0 |

**Where I differ from the review or the instruction, and what stands.** (1) Item 3 asked for the save "in the long lane"; `save` runs in the maint lane for a v3 connection (G2) and in the long lane on hydra.2/3, so the text says "the lane that `save` has". (2) Item 14 asked for the seal record in the generation manifest (`CURRENT.log`); the engine cannot read `CURRENT.log` (D12), so the third record is the marker file `SEALED.json` in the project folder, which the engine can read; `CURRENT.log` stays the client's witness. (3) Item 1: `review-rev7/job_wmi.json` records that the spawn went through WMI from inside the job; the survival after the harness exit is the review's observation, not a field of that file, and SP3(a) repeats it with the real launcher and daemon; the WMI route also inherits no environment, which the text now handles. (4) The review's two plants `no_locks_row` and `no_saver_row` replace large regions; they exit 1 with over a hundred violations and prove little, so rev8 adds targeted plants for the same rows (below).

**Proof output (revision 8)** (`D:/Projects/Hydra/_logs/spec-rev8/prove_disjoint_rev8.py`, the revision 7 script plus the checks of 8.4, with the same default inventories: Hydra `f47ff15934`, Hydralysis `d0466bc`, `589432e`, `f46788b`, `8e696e2` and `627b5b5`; output `prove_disjoint_rev8_out.txt`; exit 0): *52 package ids identical in the wave plan table and the proof's plan; 120 matrix rows and 341 owner cells; 52 package blocks; files edited by the text (backticked or not) but granted by no row or rule: none; the two declared `then` sequences are unchanged; `S/HeadlessSession.java` is owned by E1 (W1), E3a (W2), then E5 and E9 (W5) with each later owner depending on the earlier; the three Hydra files that name `maxLong` or `maintSlots` (`README.md`, `HeadlessSession.java`, `ghidra_session.py`) are matrix files; the saver-pattern scan (now over `README.md`, `docs` and `skills` too) finds the files of revision 7 plus `README.md`, all Y2's in W2; the 22 in-wave dependencies are the ones listed in section 8; dependency cycles: none; RESULT: 0 violations.* Plants: `plants_rev8.py` re-applies the 16 plant files of the review of revision 7 to this text: 9 still have their original text and all 9 exit 1 (`plants_rev8_out.txt`); `plants_rev8b.py` runs 13 targeted plants (the seven rewritten ones, unbackticked and backticked `S/SessionMain.java` and `support/launch.properties` in E9, E3a's HeadlessSession cell removed, Y2's and Y5's README cells removed, E7 moved to W8, gate 9.20 renamed, Y2's dependency on Z13a removed) and every one exits 1 (`plants_rev8b_out.txt`). The same script on the **revision 7 text** exits 1 (the saver sentence in the README and E3a's missing `HeadlessSession.java` cell), `prove_disjoint_rev8_on_rev7_out.txt`. The table-structure check (51 tables, every row has its header's cell count, code spans respected; 4 rows hold a literal `|` in a code span, as in revision 7) and the identifier check (`consistency_rev8.py`: D1 to D66, GR1 to GR11, K1 to K17 and K1u, BP1 to BP25, SP1 to SP10, V1 to V11, G1 to G8, OD1 to OD14, X1 to X11, gates 9.1 to 9.20 and the 52 package blocks each defined once, the contents links resolve, the stale statements of revision 7 are absent) both pass: `table_check_rev8.txt`, `consistency_rev8.txt`.

**Plants re-run.** `plants_rev8.py` re-applies the reviewer's plant mutations to the revision 8 text: 9 of the 16 plant files still have their original text and all 9 exit 1; the 7 whose text was rewritten in revision 8 (`e3a_edits_golden`, `e7_health`, `e9_launchprops`, `e9_sessionmain_backtick`, `e9_sessionmain_plain`, `p1b_job`, `y2_edits_readme`) are recreated on the revision 8 text by `plants_rev8b.py` together with plants for the new checks (the unbackticked `S/SessionMain.java` in E9 now exits 1, where the revision 7 script exited 0).

**Revision 7 (answers the adversarial review of revision 6: six blocking defects and a list of nits; and records the owner's delegated defaults OD8 to OD14).** Docs only; no code in any repository this stream owns; one commit on `design/protocol-3-rev7` (worktree `D:/Projects/Hydra/wt/hydra-design7`, from `1ab4859f08`, the tip of `design/protocol-3-rev6`). Inputs: the review `D:/Projects/Hydra/_logs/review-rev6/` (seven experiments on the real daemon, an ownership check, a consistency check) and the owner's delegation of OD8 to OD14 ("use your defaults"). Every finding was verified against the text of revision 6 before anything was changed; where the review was only partly right the table says so and what stands. The edit scripts are in `D:/Projects/Hydra/_logs/spec-rev7/edit-scripts/`. Added: decisions D59 to D64, section 2.2, section 8.4, gate 9.20, V11, BP25, K11p. No claim of "never corrupts" or "never blocks" was added anywhere; every claim is still limited to a named test (6.1).

**Revision 7: where each finding landed.**

| Finding | Verified against the revision 6 text | Disposition | Where it landed |
|---|---|---|---|
| **B1** D38 defines "sealed" as sidecar `disposable:false`, `fork_project purpose:"generation"` writes `disposable:false`, and 4.6 step 4 and 4.10 step 3 open that candidate writable to replay and save | **Right.** D38, V8 and 3.4 said it; 4.6 step 4 and 4.10 step 3 needed the writable open; the two cannot both hold | **Fixed.** Sealed is an explicit record (`seal_project`, or `state:"complete"` on a `generation` or `backup` sidecar) and never `disposable:false` alone; a candidate is `state:"candidate"`, writable by its publisher until verified; `seal_project` is the commit point of the candidate's *immutability*, while the publish commit point stays the `CURRENT.log` append (D10) | D38, D12, D41, D43 unchanged, 3.4 (`purpose`, sidecar), 3.13 (`seal_project`), 4.6 (step 4, new step 7b, `MANIFEST` hashes the sidecar without `state`, recovery row, fault point `after_seal`), 4.10 (steps 3 and 4), V8, K3, K6, GR1, E2 (`candidate_then_seal`, red when the predicate is `disposable:false`), E2a, Y2 (`candidate_writable_until_seal`) |
| **B2** P1b, 3.8 and 3.11 start the daemon inside a launcher-owned kill-on-close Job Object; the shared daemon then dies when the launching harness exits | **Right.** 3.8, 3.11, D46, P1b, SP3, K7 and GR9 said so. `review-rev6/exp7_jobobject.json` (Python stand-ins): launcher-owned job, `daemon_alive_after_launcher_exit` false; daemon-owned job, true, and the grandchild dies with the daemon | **Fixed.** The daemon creates its own Job Object and assigns itself (E9, `S/ProcessJob.java`); the launcher owns none; SP3 tests ownership (launcher exits, daemon alive; `TerminateProcess` of the daemon, children dead; negative control) | D60, D46, 3.8, 3.11, P1b (`daemon_survives_launcher_exit`), E9, SP3, K7, GR9 (not claimed before SP3 passes), 9.14, 8.1, 8.4. The experiment used Python stand-ins, so SP3 repeats it with the JVM and the real decompilers |
| **B3** GR5 "no agent sees another agent's unpublished edit" is false by default when sub-agents share one MCP server process; 4.10 and 4.11 disagree about the fallback | **Right.** 4.10: per-process default view; 4.11: falls back to the shared view with mandatory `expect_revision`; D43 and GR5 promised isolation. The fallback id is one id per process (`mcp.py:57`, `hydra.py:312`) | **Fixed.** One rule (D59): the agent id is `options.as` or the process default; callers that share an id share a view and are covered by `expect_revision`, not isolation. GR5 restated for distinct ids and processes; a "Not guaranteed" entry; K11p and Y5 `subagents_one_process` show both behaviours and that `options.as` separates sub-agents | D59, D43, D36, 4.10 (Identity), 4.11, 6.1 (GR5, Not guaranteed), K11, Y5, 7.7 (`options.as`; no schema change, no epoch), 7.8, OD7, 8.1 (Y2 `OPTION_BAGS`, Y5 skills). No per-call identity can be derived from MCP (one `clientInfo` per connection); a tool without an `options` bag takes no identity and reads the master, which is a decision, not a measurement |
| **B4** seven v2 goldens record `status.scheduler.quick.slots` and `long.slots` unmasked while E3a changes the lane defaults and the goldens are E0's in W0 only | **Right on the substance, one correction.** `slots` is not in `VOLATILE`; it occurs 20 times, but in **six** goldens (`clients` 2, `fork_refresh` 2, `import_script` 4, `overlays` 2, `readonly` 4, `session` 6); `edits.json` has none | **Fixed by masking.** E0 amendment A1 (W0) masks `slots` under `scheduler` and re-records the six goldens once (only the 20 lines change); `cc_e3a` `v2_lane_defaults` asserts the number; every other v2 behaviour E3a changes is listed in V9 and is invisible to the goldens; E3a owns no golden, so the proof is unchanged | D62, D40, E0 (A1), E3a, V9, 8.1 (goldens row), 8.4, 9.3, Appendix A; the proof lists the goldens and requires the amendment text |
| **B5** `workcopy_saver.py` and `locks.py` have no ownership row; D44/Y2 replace the per-target `.sync.lock` | **Right.** `workcopy.py:421-437` spawns the saver (one process per target, reopens the fork writable with `upgrade` and `refresh`, `save` with `wait=600000`, `.sync.lock` for 120 s); `tests/test_durable.py:1127` also asserts that no allow-list entry is stale, a second hidden dependency of the deletion | **Fixed by deletion.** The saver is deleted and folded into the per-view lifecycle (a view fork is a cache, persistence is the publish queue); Y2 owns `workcopy_saver.py` (deleted), `locks.py` (`LockBusy`), `tests/test_locks.py`, `config.example.json` and the `tests/test_durable.py` allow-list row. Contingency if Z2 shows a full-store replay above 30 s: the owner's process may save at eviction under the view's lock, never a second process | D61, D44, BP25, 4.10, Y2, Y3, Y5, Z2 (replay run), 8.1 (six rows and cells), 8.4, Appendix A; the proof's symbol-deletion check and a saver-pattern scan |
| **B6** the package that removes the plain-reader leave stall is attributed inconsistently (6.2 "until E3b's fast path", BP3, V3/V10, W3/W4 texts) | **Right.** Four different statements | **Fixed.** (a) owner and legacy leave and the 600 s waits: **E3b, W3, hydra.4**, bounded and attributed, not removed; (b) plain-reader leave at any user count: **E3c, W4, hydra.4**, built once from the rev5 fast path. V3 is the dead-client release only, V10 the plain-reader leave | D63, D19, 2.1, 3.5, 3.9 (residual row), 3.10 (BP3), 5.1 (V3, V10), 6.1 (GR6), 6.2, 7.6, 8.1, 8.3 (C5), 9.13, E3b (`owner_leave_bounded`), E3c (`reader_leave_no_freeze`, `reader_leave`) |
| Nit: count of changed rev5 decisions (line 16 "nine") against 2.1 and the report | **Right.** 2.1 has 19 rows: 12 reverse or change a position, 5 preserved, 2 decided | **Fixed.** "twelve" with the breakdown | header, 2.1 (counting paragraph), the rev6 history row |
| Nit: `9.20` is a dangling reference | **Right.** Cited in W8 and the history, no row | **Fixed.** Gate 9.20 (spikes) defined; hydra.4 gates are 9.1-9.4 and 9.7-9.20; the proof checks every cited gate | 9, 5.3, the spikes table |
| Nit: K13 hard-codes "p99 at most 5 ms" against D49 | **Right** | **Fixed.** The p99 is recorded; its threshold is fixed from a quiet-machine run, reproduced twice, report-only on a loaded machine | K13 (3.12) |
| Nit: the table of contents misses new sections | **Right** | **Fixed.** Contents lists 2.1, 2.2, 3.9-3.13, 4.10, 4.11, 5.3, 6.1, 7.8, 8.1-8.4 | Contents |
| Nit: 3.9 fork-time citation and per-view size | **Right.** `forkcost-ntfs.json`: single fork 214 ms (`seq[0]`), 121-222 ms for 12 in sequence, 364-1,184 ms (median 751.5) for 12 at once (`conc[2]`); 127.7 MB is the engine path, 243-346 MB per view is Hydralysis' old path (`hlm-d`, `hlm-b`) | **Fixed.** Each figure carries its file, key and path | 3.9 (Write path) |
| Nit: D41, a concurrent publisher without an idempotency key | **Right.** `exp1_fork_race.json`: six forks to one destination, one success, five bare `failed` | **Fixed.** `conflict` with `fork_in_progress` or `exists`; with the same `rk` the loser returns the winner's result; declared V11 with `cc_e2a` `fork_race_conflict` | D41, 5.1 (V11), E2a |
| Nit: "Y4b/Y4d/Z14 merge after Y4a" in the proof's sequence form | **Partly.** The sequence form exists only for a file two packages both edit in one wave; Y4a shares no file with these three | **Stated as prose.** An in-wave dependency named in each `Depends on:` and printed by the proof; E7's order after E9, E5 and E4 is the same kind | section 8 (new bullet), wave plan W6, 8.1 closing paragraph, 8.4 |
| Nit: the 4-of-162 fork-publish kill figure | **Right.** `exp2_fork_kill.json`: 14 trigger-timed kills, 2 absent, 12 complete, no `.rep` without `.gpr` | **Fixed.** Cited as C's figure, "not reproduced in review" | D41, GR10, 9.12, E2a |

**Where the review was not right, or only partly right, and what stands.** (1) B4 said seven goldens; six carry the numbers (the rest of the finding stands). (2) B2's experiment used Python stand-ins for the daemon and the decompiler and Windows job semantics for nesting were not tested with the JVM; the decision stands on SP3, which is why GR9 is not claimed before SP3 passes. (3) The review could not reproduce the fork-publish kill figures of C (0 of 14), which proves nothing about the 162-kill batch; the order change of E2a is kept because of the code order, and the 300-kill batch of 9.15 decides. (4) The owner's instruction for B1 said that `seal_project` is the commit point; it is the commit point of the candidate's *immutability* only, because the single commit point of a publish is the `CURRENT.log` append (D10) and two commit points would make recovery ambiguous.

**Owner-delegated defaults, all marked "decided (owner delegated defaults)" in section 10.**

| Item | Decision | Where it landed |
|---|---|---|
| Owner decision OD8 | keep the last 3 generations, evict idle views after 24 h, both configurable | section 10, 3.7 (`generationKeep`, `viewIdleDeleteS`), 3.11 (eviction row), 7.7 (`options.op=remove`), 4.10, Y2 and Y5 text; D28 unchanged (no automatic deletion of a generation) |
| Owner decision OD9 | second backup root `E:\dev-cold\hydralysis-backups` | section 10 (unchanged value, marked decided) |
| Owner decision OD10 | no separate interim integrity release; E8 and E2a land in W1 and ship in hydra.4; tag names `12.3-hydra.<n>` | D1, D35, 2.1, 2.2, 5.3 (the integrity row is gone), GR2, GR10, W1 note, section 10 |
| Owner decision OD11 | 0.5.0 "qualified" is the client only on the hydra.3 pin; 0.6.0 pins hydra.4 | 5.3, section 10 |
| Owner decision OD12 | E7 moves into hydra.4 as a gated package | D64, D47, D56, D35, 3.6, 3.11, 3.12, BP13, 5.3, 6.1, 6.2, wave plan (W5), 8.1, E7 block (W5), E6 and R1 dependencies, 9.14, SP10, section 10; the wording stays "bounded and quarantined" until its gate passes |
| Owner decision OD13 | no quota volume; disk-full through the fault-injection seam | 3.12 (disk-full row), X0, section 10 |
| Owner decision OD14 | S1 edits prepared on a local branch of `F:/Projects/hydra-engine-site`, not deployed; deploying hydrare.dev stays an owner action | S1 block, section 10 |

**Proof output (revision 7)** (`D:/Projects/Hydra/_logs/spec-rev7/prove_disjoint_rev7.py`, the revision 6 script plus the checks of 8.4, with the same default inventories as revision 6: Hydra `f47ff15934`, Hydralysis `d0466bc`, `589432e`, `f46788b`, `8e696e2` and `627b5b5`; output `prove_disjoint_rev7_out.txt`; exit 0): *52 package ids identical in the wave plan table and the proof's plan (E7 in W5); 119 matrix rows and 338 owner cells; 52 package blocks; files edited by the text but granted by no row or rule: none; the two declared `then` sequences are unchanged (`S/HeadlessSession.java`, E5 then E9; `tests/test_durable.py`, Y0e then Y1); `_start_saver` is deleted by Y2 and both existing tests that mention it (`tests/test_durable.py`, `tests/test_query.py`) carry a Y2 cell in W2; the saver-pattern scan finds seven files and all are Y2's in W2; the six goldens with an unmasked `slots` are E0 rows in W0, E0's text records the amendment A1 and no E3a cell names a golden; P1b's cell has no Job Object and `S/ProcessJob.java` is a bold E9 row in W5; every gate cited is defined (9.1 to 9.20); the in-wave dependencies printed include E7 after E5 and E9, E6 and R1 after E7, and Y4b, Y4d and Z14 after Y4a; dependency cycles: none; 123 matrix files exist or are marked created (98 created); RESULT: 0 violations.* Negative controls: the same script on the **revision 6 text** exits 1 (14 violations: E7 in W8, the P1b Job Object sentence, the saver files without a Y2 cell, `S/ProcessJob.java` missing, gate 9.20 cited and undefined), `prove_disjoint_rev7_on_rev6_out.txt`; two planted failures on the revision 7 text each exit 1 (Y2's W2 cell of `tests/test_durable.py` removed: three violations; the Job Object put back into P1b's cell: `P1B-OWNS-A-JOB-OBJECT`), `plant1_out.txt` and `plant2_out.txt`. The table-structure check (`table_check.py`: every row of the 49 tables has its header's cell count, code spans respected; 4 rows hold a literal `|` inside a code span, the same rows as in revision 6 minus the one that revision 7 rewrote) and the identifier check (`consistency_rev7.py`: D1 to D64, GR1 to GR11, K1 to K17, BP1 to BP25, SP1 to SP10, V1 to V11, G1 to G8, OD1 to OD14, gates 9.1 to 9.20 and the 52 package blocks each defined once, the 58 links of the contents resolve) both pass: `table_check_rev7.txt`, `consistency_rev7.txt`.

**Revision 6 (the multi-agent, never-corrupt, non-blocking objective; headless only).** Docs only; no code in any repository this stream owns; one commit on `design/protocol-3-rev6` (worktree `D:/Projects/Hydra/wt/hydra-design6`, from `f03963af91`). Inputs: the owner's objective of 2026-10-27 (several harnesses on several projects at once, no corruption, locks must not block other clients, no GUI, the two old daemons are dead); four measurement streams run on the real daemon (A capacity `_logs/measA`, B lock map `_logs/lockmap`, C crash `_logs/crash-C`, D claims `_logs/claims-audit`); three competing drafts (A isolation first, B engine concurrency, C verification first); three judges (correctness, implementation risk and code fit, agent ergonomics and truthful claims); the PR #6 traceability audit (`rre-trace` `627b5b5`, Z1-Z15 and its eight ownership conflicts). The synthesis took Draft A's structure as the base (a verified candidate becomes head only by one `CURRENT.log` append; views are disposable caches; a complete list of residual serialisation points), Draft C's sealed generation as the read path and its falsifiability machinery (without its test switches in the jar), and Draft B's source-level fix of the version-file ordering, its deterministic `waits.foreignBlocked` gate and its release-to-claim table. **Code checked while writing:** the version-file ordering (`LocalManagedBufferFile.java:696` renames the pre-save file before `:709` `setReadOnly()` writes the header, `LocalBufferFile.java:822-825`, `:768-790`), the fork publish order (`ProjectFork.java:155-185`, `ForkCommands.java:246-257`), the registry monitor (`ProjectCommands.java:70-77`), the lock sites (`Access.java:105-109`, `ProgramEntry.java:191-196`, `OverlayCommands.java:139-143`), the decompiler pool (`ProgramEntry.java:287-299`, `Overlay.java:89`), and every `File.java:line` citation of the new text by a script against `b6df709e1e`. Site line citations were read in `F:/Projects/hydra-engine-site/src`. No daemon was started; none was touched.

| Item | Disposition | Where | Note |
|---|---|---|---|
| Owner: per-agent views required, not deferred | applied; reverses D26 | D43, D44, D45, 4.10, Y5 (W4) | Y5 moves from W7 to W4 and becomes a real package; its preconditions are gates |
| Owner: a second independent backup by default | applied | OD1 decided, OD9, E2 | `backup_min_independent` 1; the second root is configured, the engine hard-codes none |
| Owner: runtime evidence and coverage first, memory write and watchpoints later and fixture-only | applied | D53, Z9-Z12, waves W6-W7 | Z12 stays gated |
| Owner: 12.1.4-against-12.3 decompile diff reported, never gated | applied | Z7, 9.18 | 77.124% of 8,616 identical; `maxBadData` pinned or at 4 gives the same figure (8.6) |
| Owner: supervisor auto-restart only once a durable journal exists | applied | D55, 7.2, Y4a | `journal.durable` |
| Owner: no daemon-root consolidation; ReFS warn only; Hydralysis 0.5.0 shipped qualified; work on D: | applied | OD3 unchanged, D35, 5.3 | 0.5.0 is client-only on the hydra.2/3 pin |
| Owner: headless only, no GUI | applied | D36, 4.7, 6.2, 9.6, OD2 removed, R0/S1/Z13a | the GUI rows of 4.7, the stock-Ghidra clause of 9.6 and the GUI limit are gone; U14 lists the sentences to change |
| Owner: locks must not block other clients; multiple projects at once | applied as contracts NB and ISO, honestly bounded | D37, D39, D57, 3.9, 3.10, GR6 | 24 blocking points each have a decision and a red test; the residual list is complete; open (legacy) projects, protocol 2 and the shared view keep their locks and carry no claim |
| Judge 1, adopt 1: Draft A's structure as the base | adopted | D45, 3.9, 4.10 | verified candidate, one `CURRENT.log` append, disk queue with a non-blocking leader lock, disposable views, residual list |
| Judge 1, adopt 2: B's F1a, flush and sync before `renameFile`, shipped early | adopted | D42, E8, 5.3 | confirmed in source; the integrity cut is protocol-neutral |
| Judge 1, adopt 3 / judge 3, adopt 1: `waits.foreignBlocked` and `waited{}` attribution as the primary non-blocking gate | adopted | D49, K13, 9.13, 3.13 | `waited` appears from 250 ms only |
| Judge 1, adopt 4 / judge 2, adopt 6: planted violations, red before green, deterministic crash points, a 50 ms watcher, the model fold | adopted | D48, X0, K2, K16, 9.12 | the shipped-jar `mutant=` switches are replaced by compiling the old class back over the new engine through `Ghidra/patch/`; crash points are trigger-timed external kills |
| Judge 1, adopt 5: exactly-once publish through the manifest's ids | adopted | D45, 4.10 step 5, K12 | |
| Judge 1, adopt 6: quarantine never writes a read-only or sealed tree | adopted | D42, `corrupt_newest` | B's F1b as written is rejected |
| Judge 1, adopt 7: waiters never hold a slot, and never hold a lock while waiting for a slot | **partly adopted, with the conflict resolved explicitly** | D39, BP9, SP9 | C's locks-before-slots is rejected; slot-first stays (deadlock-free), bounded by waiter caps for every v3 request; A's slot-yield is built behind `yieldSlots` (off) only if SP9 shows no deadlock. The residual (up to the cap of waiters hold slots) is stated in 3.10 |
| Judge 1, adopt 8: atomic fork publish with a recognisable half state, idempotent retry, a sweeper that only removes what the engine made | adopted | D41, E2a, K6 | `.gpr` last (A's single rename cannot cover an existing destination folder) |
| Judge 1, adopt 9 / judge 2, adopt 2: engine refusal of a writable open of a sealed or non-disposable project | adopted | D38, E2, V8 | one predicate; a project with no marker is not sealed, so legacy use is unchanged |
| Judge 1, adopt 10 / judge 2, adopt 3: refcount leave, no wait inside the registry monitor, interruptible waits, `leaving` re-check | adopted | BP3, BP8, BP11, E3b, E3c, V10 | un-nesting is E3b's first commit |
| Judge 1, adopt 11 / judge 2, adopt 4: spikes before the unmeasured assumptions, failing back to the sealed path | adopted | 9.20 (SP1-SP10), D37 | |
| Judge 1, adopt 12: rule-of-three wording, process-crash scope, per-release availability, a not-guaranteed list | adopted | 6.1, D50, D58 | |
| Judge 1, adopt 13: structured `busy` before heap or native memory runs out, Throwable-safe threads, eviction by an atomic compare against a pin count | adopted | 3.11, E9 | |
| Judge 2, adopt 5: the Hydralysis-only work as its own client release on the hydra.3 pin | adopted | D35, 5.3 | Hydralysis 0.5.0 qualified |
| Judge 2, adopt 7: seams for the governor only | adopted | E1 (`Hooks`, `Guarded`), D46 | |
| Judge 2, adopt 8: one owner per file per wave, the site row, the wording pass at W0 | adopted | 8.1, 8.3, R0, S1, Z13a | the proof of this table is below |
| Judge 3, adopt 2-14: one claims ledger, the W0 wording pass, the release-to-claim table, one error contract, the `maxLong` interim, the residual list in health and docs, red-before-green, ranges and bounds, visible limits, a stable `options.as`, the corruption fix early, a non-blocking publish, the ownership resolutions | adopted | D52, D54, D43, D35, 5.3, 3.13, 3.9, 3.11, 8.3 | |
| Judge 1, reject 1: B's quarantine on a read-only open | rejected | D42 | |
| Judge 1, reject 2 / judge 2, reject 5: C's locks before slots | rejected | D39 | |
| Judge 1, reject 3: bounded waits as the answer to "locks must not block" | rejected | D37, 3.10 | bounded waits stay for the legacy paths only |
| Judge 1, reject 4 / judge 2, reject 7: random-time kills or one 8-hour all-or-nothing run as the proof | rejected | D50, 9.15, 9.17 | counted trigger-timed batches, a nightly lane and one release run |
| Judge 1, reject 5 / judge 3, reject 5: claims ("never corrupts", "any number", "never blocks") before the gates | rejected | D52, 6.1 | |
| Judge 1, reject 6: optimistic parallel builds | rejected | D45 | |
| Judge 1, reject 7 / judge 3, reject 9: ReFS as protection; the PR #6 fork figure | rejected | 6.1, D52 | 3 of 80 trigger-timed ReFS kills still poisoned a version file |
| Judge 1, reject 8: per-view base rebuilds | rejected | D44 | |
| Judge 1, reject 9: in-process stopping of a deaf script | rejected | D47 | |
| Judge 1, reject 10 / judge 2, adopt 9: any GUI feature or mention | rejected | D36 | |
| Judge 2, reject 1-2: B's N1 as one XL package; replica pools, immutable snapshots and a snapshot-only read semantic in hydra.4 | rejected; E3c is bounded and the rest is conditional | D37, D51, E11 | |
| Judge 2, reject 3-4: Draft A's engine `view_*` family, four lanes, FFM nested limits, decompiler negative cache | rejected, **except one conflict resolved**: judge 1 praised crash isolation, judge 2 rejected the negative cache; the minimal form (3 failures per minute on one function, a 10-minute negative cache, E9) stays, so a client cannot drive a crash loop | D43, D40, D46 | FFM limits and the fourth lane are not built |
| Judge 2, reject 6: `mutant=` and `crashAt=` hooks; the E8 ".part" scheme | rejected | D48, D42 | the file is already a temporary pre-save file |
| Judge 2, reject 8-9: E7/E10/E11 on the hydra.4 critical path; stacking E8, E2, E3a, E3c in one wave; `Session.java` with four owners and no gate | rejected / answered | D56, D47 | E8 and E2a are W1, E2 and E3a W2, E3c W4; `Session.java` has four owners over W1-W5, each wave gated by the characterization diff and its red-table rows |
| Judge 3, reject 1, 4: always-on reply fields; silent staleness | rejected | D51 | |
| Judge 3, reject 2: a pid-based agent id | rejected | D43 | |
| Judge 3, reject 6, 7, 8, 10: loaded-machine latency thresholds; extra lane taxonomy; deferring all truth to the XL refactor; spare pools, group commit and replica pools in the first cut | rejected | D49, D40, D35, D45 | |
| The audit's 8 ownership conflicts and 2 conditionals | resolved | 8.3 | table "The eight conflicts" |
| The audit's Z1-Z15 | integrated | 8, 8.1, 8.3, D53 | Z2 moved from W4 to W3; Z13 and S are split by wave (a, b) |
| Claims audit: 11 contradicted, 14 unsupported or stale claims | wording, ledger, owner, flip tests | D52, 8.3, 9.19 | 25 claims with replacement text and flipping package |
| Rev5 decisions reversed or changed | marked in place and listed | 2.1 | D26 reversed; D19, D16, D17, D20, D12, D1 changed; D5, D22, D28 preserved; OD1, OD2, OD4, OD7 decided or removed; gate 9.5 replaced, 9.6 stock clause removed (counted in revision 7: twelve positions, not nine) |
| The two old daemons | not touched | | this stream started no daemon and touched none |

**Proof output** (`D:/Projects/Hydra/_logs/spec-rev6/prove_disjoint_rev6.py`, run on this file with the default inventories: Hydra `f47ff15934`, Hydralysis `d0466bc`, `589432e`, `f46788b`, `8e696e2` and `627b5b5`; output `prove_disjoint_rev6_out.txt`; exit 0): *52 package ids identical in the wave plan table and the proof's plan (the pattern sees Y0e, Y4e, X0, E2a, E3c, Z13a, S2); 116 matrix rows, 330 (repo, wave, file) owner cells in a Hydra, a Hydralysis and a Site table; 52 package blocks; files edited by the text but granted by no row or rule: none; files owned by more than one package in one wave: none besides the two declared `then` sequences (`S/HeadlessSession.java`, E5 then E9; `tests/test_durable.py`, Y0e then Y1); every package's Files text equals its matrix files (the union of its `Files` paragraphs; S2 by the stated waiver "the same files as S1"); 57 existing test, example, tool and benchmark files: 29 with a row, 0 by rule, 28 frozen; dependency cycles: none; no package depends on a later wave; a later owner of a file that does not depend on the earlier one: none; frozen tests asserting a stub answer: `tests/test_cli.py` and `tests/test_contracts.py`, both owned in W2 by Y2; frozen tests asserting a catalog epoch: only `tests/test_contracts.py`, no later package changes it; frozen tests asserting a value a revision-6 package changes (`SYNC_LOCK_S`, `.sync.lock`, the default identity, `maxLong`/`maxQuick`, and in the Hydra examples a default lane size or the cleanup wait): none; pinned `12.3-hydra.<n>` literals in the Hydralysis tree: all in the bump list, the Y4a rewrite list or the historical list (the audit report `docs/pr6-traceability.md` is now historical); the site's five files with the release literal all have S1 and S2 cells; 120 matrix files exist, 96 are created and all 96 are marked created; the Ghidra-core and root paths exist in the tree they name; RESULT: 0 violations.* The same script on the **revision 5 text** exits 1 (25 violations: the plan has 24 ids, no row for the revision 6 packages, no site table), `prove_disjoint_rev6_on_rev5_out.txt`; four **planted** failures on the revision 6 text each exit 1 (a deleted row of E9's three files: six violations; Y2's W2 cell of `tests/test_contracts.py` removed: `FROZEN-TEST-ASSERTS-A-STUB-NO-OWNER`; `S/Access.java` given to E4 in W4: three violations; E9 named beside E5 in the W5 cell of `S/Scheduler.java` without a sequence: `EXTRA-NAME-IN-CELL`), `prove_disjoint_rev6_plants_out.txt`. Counts: 52 packages in 9 waves (W0 to W8), 116 matrix rows, 330 owner cells, 2 declared in-wave sequences, 13 reply-shape conditionals, 6 behaviour gates, 8 G rows, 10 V rows (V8 to V10 new), 58 decisions (D35 to D58 new, 10 rev5 rows marked), 14 owner decisions (OD8 to OD14 new), 8 gates added (9.12 to 9.19) and 10 spikes.


**Revision 5 (answers the fourth independent review: three blocking items and nine nits, and four items folded in from the W0 package reviews).** Docs only; no code in any repository this stream owns; one commit on `design/protocol-3`.
The review's verdict was that revision 4 was not clean: two frozen tests that no row could edit would break
when later packages made their assertions false (BLOCKING 1 and 2), and a pool entry's leave stalls every other
reader of its program (BLOCKING 3). Every claim below was checked against the code or by experiment before
the text was written. New experiments, on the real hydra-3-candidate daemon, the refactor build
(`hydra-session-after`, same behaviour) and one experimental engine copy (`hydra-spec-rev5-patched`: the refactor
build with one class replaced through `Ghidra/patch/`; not a package), Python 3.15.0, fresh state roots under
`D:/Projects/Hydra/_logs/spec-rev5/exp/`: `exp11_rerun.py` and `exp12_rerun.py` (the reviewer's scripts, re-run
first), `exp13_leave_rules.py` (scenarios A to E, run on both engines), `exp14_last_user.py`,
`exp15_busy_first_script.py`, `exp16_first_script.py`, `exp16c_cold_script.py`, with their `*_out.txt`; the
experimental patch is `D:/Projects/Hydra/_logs/spec-rev5/patch/src/ProgramCommands.java`; the proof is
`D:/Projects/Hydra/_logs/spec-rev5/prove_disjoint_rev5.py` with `prove_disjoint_rev5_out.txt` (and
`prove_disjoint_rev5_on_rev4_out.txt`). No live daemon was touched. **Rejected: none.** Two of the reviewer's
statements are **refined**, not rejected: (1) BLOCKING 3 says every shared acquirer "is refused busy until the
running read ends": a waiter is refused only when its own `wait` is shorter than what remains of the running read
(it otherwise just waits, longer); (2) "today's single shared connection never leaves, so this is new with the
pool": the stall is the same in kind for any client that leaves (another agent's process, a harness exit,
Hydralysis's own `close_program` in `stop`), the pool makes it frequent. Revision 5 also **found** three things the review
did not name (rows F1 to F3).

| Item | Disposition | Where | Note |
|---|---|---|---|
| BLOCKING 1: `tests/test_contracts.py` (frozen after W0) asserts the Y0d stubs forever; Y2, Y4b, Y4e break it, no row may edit it | fixed | 8 (new bullet and the `api.py` bullet), 8.1, 8.2, 7.7, Y2, Y0e, wave plan | `tests/test_contracts.py` gets a **W2 cell for Y2**, and **Y2 rewrites the four stub tests** (`NotAvailableCarriers`, `:111-157`: doctor and backups; `ghidra_run` options; job options) to patch `api.HANDLER_MODULES` (the seam Y2 builds, named in the spec: `{"backups", "doctor", "jobOptions", "scriptIsolation"}` to handler module paths, read at call time) with a module that never exists, so the dispatcher's own `not_available` path stays asserted whichever handler modules exist and **Y4b and Y4e edit neither file**; the option-validation test (`:132-138`) and the non-stub assertions inside the four (plain calls, `:142-143`, `:158-161`) are unchanged. **The generalised detector** (`prove_disjoint_rev5.py`): every frozen test file that contains the literal `not_available` at the Hydralysis revisions is listed and must have a W2 cell for Y2 whose text names the registry and the file. On the **revision 4 text** it exits 1 with 12 violations: *`tests/test_cli.py  revs ['8e696e2']; cells {'W1': ['Y0e']} -> VIOLATION`* and *`tests/test_contracts.py  revs ['589432e', '8e696e2', 'f46788b']; cells {'W0': ['Y0d']} -> VIOLATION`* (and ten pinned-literal violations, BLOCKING 2); on the **revision 5 text** exit 0: *`tests/test_cli.py ... cells {'W1': ['Y0e'], 'W2': ['Y2']} -> OK`*, *`tests/test_contracts.py ... cells {'W0': ['Y0d'], 'W2': ['Y2']} -> OK`* |
| F1 (found by the detector): Y0e's own `tests/test_cli.py` (committed in `8e696e2`) asserts `not_available` twice, through the CLI | fixed with BLOCKING 1 | 8, 8.1 (a W2 cell for Y2 on `tests/test_cli.py`), 8.2, Y0e, Y2 | the reviewer named only `tests/test_contracts.py`; the same class had just been created by Y0e (`test_doctor_and_backups_pass_the_not_available_answer_through_without_side_effects` and `test_the_call_command_reaches_doctor_too`); Y2 rewrites both in W2 |
| BLOCKING 2: Y4a "owns the files the script edits" and names none; `tests/test_backends.py` (frozen) hard-codes the pinned release | fixed | 5, 8, 8.1, 8.2, Y4a, R1, 9.8 | the files `tools/bump_hydra.py` edits are **listed**: `hydra.py` (`RELEASE`, `PROTOCOL`, `ASSETS`), `tests/fakehydra.py`, and the one pin sentence of each of `README.md`, `THIRD_PARTY.md` and `docs/upstream-setup.md` (found by the scan; the review named only the first two), each with a W6 cell for Y4a; the history documents (`docs/golden-harness.md`, `docs/verification-*.md`) are listed as untouched. **Decided: derive, not edit per bump**: Y4a (W6 cell added for `tests/test_backends.py`) rewrites `test_backends.py:21` and `:101` to read `hydra.RELEASE` and `test_query.py:285-296` to read the fake's constant, once, so that no bump edits a test; `tests/test_bump_hydra.py` asserts that the script edits only the listed files. **The pinned-literal scan** (`12.3-hydra.<n>` over the whole tree at the four Hydralysis revisions) requires each hit to be in the bump list, the Y4a rewrite list (with Y4a's text saying it derives from `hydra.RELEASE`) or the historical list: revision 4 text, 10 violations; revision 5 text, 0, with the output *`hydra.py -> OK: edited by bump_hydra.py, a W6 cell of Y4a`*, *`tests/test_backends.py -> OK: Y4a rewrites it to derive the release`*, *`docs/golden-harness.md -> OK: historical, not edited`* |
| BLOCKING 3: an entry that joined a program and leaves queues `releaseUse`'s exclusive lock; every new shared acquirer waits behind it (7.6, 'users and the cap', `replacement_context`, step 5, `QueryRunner.stop`, 6) | fixed, **by experiment**, in two layers | 3.5 (new paragraph), D19, D33, 5.1 V3, 6, 7.2, 7.5, 7.6 (deadline bullet, unit of the pool, read-only bullet, `users` bullet, new 'Leaving a program', steps 1, 4, 5, 6, P1b/E3b paragraph, tests), 3.8, E3b, Y4a, Appendix A | **Reproduced first** (hydra-3-candidate, fresh roots): `exp11_rerun`: control without a leave: join 3 ms, script 36.4 ms; `clean_close`: *`Y (after X left) join busy after 1509.5 ms`*; `fin`: *`join busy after 1509.1 ms`*; `abandon_no_fin`: *`join ok 4 ms`, `Y script ok 35.5`*; `exp12_rerun`: *`joined-entry script busy 1509.3 shared 1`*, *`joined-entry functions busy 1507.4 shared 1`*, *`after holder ended 37.0`*. **Engine layer (E3b, hydra.4, all protocols, declared with V3):** a plain reader's leave (neither owner nor shared writer, no overlay, **not the last user**) takes no exclusive lock; check and removal are one step under `synchronized (e.users)`, so the last user always takes today's path. **Measured** with that one change compiled over the same engine (`exp13` on `hydra-spec-rev5-patched`): scenario A *`probe new-entry join: ok 3 ms`, `joined entry: script ok 44 ms`*; C (FIN, rev. 4 mechanism) *`ok 3 ms`, `ok 42 ms`*; E *`ok 3 ms`, `script ok 189 ms`* (unpatched: busy after 1,509, 1,510 and 1,511 ms); `exp14` gives identical `users` lists and dispose behaviour on both engines (six entries closed concurrently, five rounds; the sole user; a second user). Tests in E3b: `reader_leave_no_freeze` (must fail on hydra.3), `last_user_leave_disposes`, `cc_e3b` `reader_leave`. **Client layer (hydra.2/3, where the engine cannot change): rules L1 to L3**: no FIN or early close on an entry that joined a program while a request runs on it (**the half-close of revision 3 is withdrawn**: a FIN adds nothing `cancel` had not done, its one distinct effect is the leave at the end of the request), a **leave gate** (a joined entry is closed only when this process has no read in flight on a program it joined; the abandoned worker closes its session itself after the engine's answer, through the gate), at most 8 entries waiting in the closing list, and the four live entries are never closed for being idle. Measured on the unpatched engine: C (rev. 4) *`join busy after 1510 ms`*, D (no FIN, gated) *`join ok 4 ms`, `script ok 43 ms`, deferred close 0.1 ms*, E (no FIN, close at once) *`join busy after 1511 ms`*, B (idle entry kept, closed after the read) *`ok 3 ms`, `ok 41 ms`, close 0.3 ms*. `replacement_context` is now **deterministic** (polls with bounds, no fixed sleeps, five numbered assertions, including the deferred close during another read); new tests `leave_gate_no_freeze`, the gate tests against the fake, `wait_below_deadline` extended to the opens; the `users` arithmetic is 1 + 4 + 8 + 8 = **21**; section 6 states the limit (another process's leave and `close_program` from anyone still stall, bounded and visible); `QueryRunner.stop` is specified (N7). **Rejected alternative:** never leaving at all (keeping every entry open for the process lifetime) is the rule for idle entries only; the abandoned and retiring entries must eventually close, which is what the gate is for |
| N1: the unit of the pool is the attempt, not the call; does `deadline_s` cover all three | fixed | 7.6 ('The unit of the pool is the attempt', steps 1, 2, 4), D33, 7.5, Y4a | verified (`query.py:54`, `:58`, `:90`): one `_ask` attempt is `open_project` + `open_program` + `script`; **`deadline_s` is the deadline of the attempt**, one clock from the acquire, every call takes what is left; `_ask`'s second attempt starts a new clock (up to two deadlines and two graces, about 130 s, the existing retry rule); test: a fake whose `open_program` and script take 40 s each gives `deadline_exceeded` at 60 s plus the grace, not at 120 s |
| N2: the two opens send `wait=BUSY_WAIT_MS` and are deadline-bound too | fixed, **by experiment** | 7.6 (the unit paragraph, 'A lock wait needs no abandon', `wait_below_deadline`), Y4a | verified (`query.py:29`, `:54`, `:58`): both opens now send `wait = min(25 s, remaining / 2)` on hydra.2/3; measured on the real engine that both opens honour a short `wait` (*busy after 1509 ms*, `exp13` A, `exp11_rerun`); `wait_below_deadline` covers them |
| N3: the health probe is "one pool entry per call" (7.5) or its own connection (7.2, 7.6) | fixed | 7.5, 7.2 | **one wording**: the probe has its own connection, outside the entries; it joins nothing, so its close takes no program lock and needs no gate |
| N4: cost numbers are from a quiet daemon; the first script on a replacement entry while another script runs | fixed, **by experiment** | 7.6 ('Quiet and busy') | said; busy figures added: join unchanged (3.1 and 1.3 ms with an 8 s script running, `exp15`); **the slow first script is not per entry**: it is the first-ever run of a script file while another instance still runs, 1,813, 2,157 and 1,626 ms (`exp15`), 2,130 ms (`exp16c`) for the first new entry and 37.7 ms for the next one; with the script warm, 46.6 ms against 42.1 ms quiet (`exp16`); the reviewer's 325 ms and 1.70 s and the 1.55 s KotOR outlier are consistent with it, not diagnosed |
| N5: Y4d's tests need fake-engine support (`format`, `backup_required`, `purpose:"backup"`, `writer:"engine"`) but `tests/fakehydra.py` is Y4a's; a connection-scoped fake may break frozen tests | fixed | 8.2, 8.1, Y4a, Y4d, wave plan | **assigned to Y4a** (the file is Y4a's in W6): it adds the E2 surface, and the connection scope is **opt-in** (`connection_scoped`, default off), so every frozen test keeps the single-context fake; Y1 keeps the signatures that frozen tests call (`workcopy._apply`, `workcopy._replayable`, `tests/test_client.py:144-170`, `tests/test_archive_import.py:33-38`; its acceptance runs them unchanged); Y4d depends on Y4a |
| N6: E1 widens `check_ownership.py`'s regex | verified, extended | 8 (rule 4), 8.2, E1 | already an E1 task (first commit); confirmed with the shipped checker patched to `[a-e]`; extended with the Hydralysis root documents (`README.md`, `THIRD_PARTY.md`, `docs/...` resolve under `src/hydralysis/` today), which the new rows need; Y0e's branch passes the matrix with the widened pattern (`8e696e2`: six files, 0 violations) |
| N7: `QueryRunner.stop` after the pool: what do `released` and `failed` contain | fixed | 7.6 (`users` bullet), Y4a, tests | specified: wait for the gate (at most the grace), `close_program` on the shared connection and on every entry that joined the target, never a connection close; `released` lists each daemon program key once, `failed` has `{program, entry, error}` per failed close, `ok` is `not failed`, one additive key `entries: {closed, deferred}` |
| N8: wording 'by one Hydralysis process; the engine has no cap' | fixed | 7.6 (`users` bullet), 6 | said: 21 per program for one process, and the engine has no cap (twelve entries listed fourteen ids), other processes add theirs |
| N9: Y4a-before-Y4b/Y4d order for `tests/fakehydra.py` | fixed | wave plan, 8.1 text, Y4d | **declared**: Y4b and Y4d merge after Y4a; Y4d's `Depends on` names Y4a; the proof prints Y4d after Y4a as an in-wave order |
| (a) 8.1 needs a row for the v2 goldens under E0 (`check_ownership --package E0` exits 1 on `fork_refresh.json`, `overlays.json`) | fixed | 8.1 (new Hydra row), 8 (rule 3), 8.2, E0 | a row lists the seven goldens for E0 (W0); rule 3 no longer calls them frozen forever; the documented reason: the total size of the copied project varies with the host address (`FILE_ID = hex(host IPv4) + hex(port) + nanoTime`, stored 3 times per program, `FileIDFactory.java:33-54`; 27-character ids against 24 changed the total by 18 bytes), so `bytes` is masked in dicts that also have `mode`, 14 lines changed; `check_ownership.check_changes` for E0 over the six files of E0's three commits: revision 4 text, 2 violations (the two goldens); revision 5 text, 0 |
| (b) E0's `import_wait` test text says `max(importsMs) >= 19000` | fixed | E0 | now: slowest import within 19000..23000 ms (`SLOWEST_IMPORT_MAX_MS = 23000`) and spread within 8000..12000 ms, as committed in `f47ff15934` (`dt_baseline.py:55-58`), with the evidence keys; the failure paths were not exercised on a real failing observation (said) |
| (c) Y0a / 4.1 wording: the every-acquisition tail check | fixed | 4.1 item 3 (writers, tests), 6, Appendix A | `589432e`'s `_clean_tail` already repaired a no-LF tail; the rule is **new only for LF-terminated damage**; the discriminating scenario is another process leaving an LF-terminated invalid line (it fails with `LineageCorrupt: invalid line at byte 17 followed by a valid line` on `589432e`, passes on `b0b947b`); the no-LF case is a contract guard |
| (d) committed Y0a to Y0d code differs from the spec | fixed (spec follows the code) | 7.6 (`EngineError`, Pools), 7.7, 8.2, Y0b, Y0c, Y0d, D25 | `EngineError`: lists 5 plus `more`, **`next` and `retryAfterMs` uncapped**, the lists inside `queue` capped at 64 with `more["queue.waiting"]` (`33cb5ee`, `5018367`); catalog **epoch 2** (epoch 1 never left the branch; the address text keeps only the refusal clause, 8,172 bytes against 8,192, the long form costs 104 more); `MAX_OUTSTANDING` per lane with the busy hint as text **and** `structuredContent.retryAfterMs` (`49d5bb6`) |
| F2 (found): the catalog is reported in four places, not two | fixed | 7.7, 8.2, Y0d | `backend` `status`, `help` and `inspect` and the MCP `initialize` `_meta` (`1584f6e`; `test_inspect_and_the_mcp_initialize_reply_report_the_catalog_too`); the spec said 'nowhere else' |
| F3 (found): three of Y0e's revision 4 tasks had already landed in the W0 follow-ups | fixed (spec follows the code) | 4.1, 6, 8.1, 8.2, Y0e, wave plan, header | the streamed `AppendLog` reads, the every-acquisition check and the two-process tests (`2bf90c7`, `b0b947b`), the `EngineError` `next` exemption (`33cb5ee`, `5018367`) and the `test_client.py` guard (`33cb5ee`) were done before Y0e; Y0e (`8e696e2`) verified them; the Y0e cells for `durable.py`, `tests/test_client.py` and `tests/test_runtime.py` are removed (the last row with it), section 6's 32 MiB limit is replaced by what remains for Y2 (strictness of `last()`, rotation); `write_json` is `write_sealed` in the code |

Also while re-reading the whole file: the Contents, D1 to D34 (no new decision number: D19, D25 and D33 are amended),
the packages, the wave plan, 8.1 and the cross-references of 7.6 were checked against each other. **Proof output**
(`prove_disjoint_rev5.py`, exit 0): *24 ids identical; 69 matrix rows, 165 (repo, wave, file) owner cells; 24 package
blocks; files edited by the text but granted by no row or rule: none; Y1 deletes `save_overlay` and
`load_overlays`, both granted to Y1; declared sequences: 1 (`tests/test_durable.py`, Y0e then Y1); 57 existing
test, example, tool and benchmark files: 28 with a row, 0 by rule, 29 frozen (the seven v2 goldens now have a row);
dependency cycles: none; in-wave order: E1 after P1a, R1 after E6, Y1 after Y0e, Y4b and Y4d after Y4a; a later
owner not depending on an earlier one: none; frozen tests asserting a stub: `tests/test_cli.py` and
`tests/test_contracts.py`, both OK; pinned release literals: 10 files, all OK; catalog epoch asserted by `tests/test_contracts.py` only, and no later package changes it, OK; RESULT: 0 violations.* The same
script on the revision 4 text exits 1 with 12 violations. Counts: 24 packages, 69 matrix rows, 165 owner cells,
1 declared in-wave sequence, 13 reply-shape conditionals, 6 behaviour gates, 8 G rows, 7 V rows and 34 decisions
unchanged.

**Revision 4 (answers the third independent review: two blocking items and eleven nits).** Docs only; no
code; one commit on `design/protocol-3`. The review's verdict was that revision 3's three original
blockers were closed and that two new gaps were open: a fresh per-call connection loses the engine-side
project and program context (BLOCKING A), and Y1 and Y0e share test files that have no cell (BLOCKING B).
Every claim below was checked against the code or by experiment before the text was written; the
experiments are new and recorded in `D:/Projects/Hydra/_logs/spec-rev4/` (`exp5_pool_entry.py` with
`exp5_small_out.txt` and `exp5_kotor_out.txt`, `exp6_wait_and_collateral.py` with `exp6_out.txt`, and
`prove_disjoint_rev4.py` with `prove_disjoint_rev4_out.txt`), on the real hydra-3-candidate daemon and its
1.0.0 library, Python 3.15.0, fresh state roots; no live daemon was touched. **Rejected: none.** One
item is fixed with a correction of the reviewer's wording (N8), and two of the reviewer's citations were
corrected rather than copied (N2: the `wait=` call is `query.py:90-91` at both bases, not `:84`/`:90`;
BLOCKING B: `tests/test_analysis.py` has 15 `save_overlay` calls plus the import, 16 lines).

| Item | Disposition | Where | Note |
|---|---|---|---|
| BLOCKING A: a fresh per-call connection has no project or program | fixed, **by experiment** | 7.6 (new: scope, "A lock wait needs no abandon", "The pool entry", steps 1 and 5, tests), 7.2, 7.5, D33, 6, Appendix A, Y4a | The reviewer's result reproduced on the real hydra.3, for a 3-function fixture and the 122 MB KotOR copy: `script program=key` works on the connection that opened it and fails on a fresh one with `no_project: this client has not joined project p1; send open_project`; `functions` fails with `no_program`; `open_project` alone is not enough (`no_program: p1:/alpha.exe is not open for this client`). **Specified**: a pool **entry** is a connection plus the context it joined (its key is the root, the role and a serial that is never reused); `QueryRunner._ask` acquires one entry per attempt and the existing `open_program` path re-establishes the context by a `_keys` cache miss; invariants I1 (serial never reused), I2 (`forget(entry)` on retirement), I3 (a retry takes another entry); `sync_scripts` and `write_daemon_config` stay per process. **Cost, measured** (10 cold entries per fixture): connect and `hello` 3.3 ms, `open_project` 1.9 ms, `open_program` 0.7 ms (medians; about 6 ms; about 27 ms if the three worst coincided), the same for both fixtures; the first-ever open of a program is 1.36 s (small) and 1.95 s (KotOR) and is paid once per program and daemon, not per entry; one KotOR entry of ten took 1.55 s for its first script (cause not investigated). **`users`**: every entry is one more `users` element; measured `[2]`, `[2, 14]`, back to `[2]` 1 s after a clean close or a FIN of an idle entry, `[2, 16]` stays for an entry abandoned with **no** FIN, a cooperative script that got the FIN left within 1.5 s, twelve entries at once listed fourteen ids with no refusal and all left when closed. The half-close of step 4 always sends the FIN, so the leak is bounded by the cap: at most 1 + 4 + 8 = 13 `users` entries per program per process, each gone when its request ends; `leaveProject`/`releaseUse` keep the 600 s waits (D19) until E3b (owners and writers) and E3c (plain readers). **Read-only**: reads already open read-only, and the two opens are the least a script with `program=<key>` needs, so there is no cheaper join. Y4a tests: `replacement_context` (a replacement re-establishes its context, the other connections are untouched, no `no_project`, the experiment quoted as a test and dropped from the design if its premise stops holding) |
| BLOCKING B: Y1 deletes `save_overlay`, `tests/test_durable.py` freezes it, `tests/test_analysis.py` calls it | fixed | 8 (the declared sequence, the four ownership rules), 8.1 (matrix: 65 rows), 8.2, Y0e, Y1, wave plan W1 | **One decision**: the ratchet table is Y0e's in W1 (its six rows for the writers it moves, and the three count assertions); the two `save_overlay` rows and the counts are the **second step of W1, after Y0e**, in Y1's commit that deletes the function, because removing the rows without the function (or the function without the rows) fails the gate itself, which is why the reviewer's second option (Y0e deletes the rows, Y1 the function) was not taken. After Y0e the table has 2 record rows, 24 keys and 26 call sites; after Y1, 0, 22 and 24. It is the only declared sequence, written as two rows for one file so that E0's `check_ownership.py` (which unions the rows of a path and allows one package per cell) needs no special case; Y1 declares the dependency on Y0e and merges after it. `tests/test_analysis.py` (the 15 calls and the import), `tests/test_exporting.py` (`:94-98` hand-appends to a store), `tests/test_crossbuild.py`, `tests/test_revisions.py`, `tests/test_query_script.py` and `tests/test_query.py` are in Y1's W1 cell; `tests/test_runtime.py` is Y0e's (the sealed `_write`). `load_overlays`, whose only caller was `save_overlay`, goes with it. Found on the way: `tests/test_query_script.py` is a structure guard of `RusticQuery.java` (Y1's file), not a Y4e test: Y4e's tests are a new `tests/test_userscripts.py`; `tests/test_engine_integration.py` exists already (Y1 and Y2 add to it) |
| BLOCKING B, the class: every test and example file has an owner (reviewer's N5) | fixed | 8, 8.1, 8.2, E1, E2, Y0e, Y1, Y2, Y3, Y4a, Y4b, Y4d, Y4e, R1, `prove_disjoint_rev4.py` | **Four rules a script checks** (a row; `dt_`, `char_`, `cc_` files and goldens `v3/<id>-<scenario>.json` carry the owner's id; everything else is frozen; the branch check refuses frozen files). New rows: eight existing test files (`test_analysis`, `test_exporting`, `test_crossbuild`, `test_revisions`, `test_query_script`, `test_engine_integration`, `test_overlayjobs`, `test_runtime`) and thirteen new files (`test_store_v3`, `test_bundles`, `test_lineage`, `test_commit`, `test_backups`, `test_views`, `test_doctor`, `test_userscripts`, `test_deadline`, `test_supervisor`, `test_bump_hydra`, `test_cli`, `tests/vectors/canonical-manifest.json`), `examples/fixtures/legacy-12.1.4/` for E2, and the second `check_ownership.py` row for E1; the Y0c `mcp.py` and Y0d `api.py`/`workflow_help.py` rows already had their Files text, which the script confirms. **The script** (`prove_disjoint_rev4.py`, a copy of the revision 3 proof) now also lists the files that appear in no row but are edited by some package's text, the files two packages of one wave cite, the existing files that are frozen, and **every existing test that mentions a symbol a Hydralysis package deletes**, which is the check that would have caught this blocker. Output on this file, exit 0: *24 ids, identical (the pattern sees Y0e and Y4e); 65 matrix rows, 155 (repo, wave, file) cells; 24 package blocks; files edited by the text but granted by no row or rule: none; Y1 deletes `save_overlay` (mentioned in `tests/test_analysis.py`, `tests/test_durable.py`) and `load_overlays` (`tests/test_analysis.py`), both granted to Y1; declared sequences: 1 (`tests/test_durable.py`, Y0e then Y1); 54 existing test, example, tool and benchmark files: 18 with a row, 0 by rule, 36 frozen (listed by the script); dependency cycles: none; a later owner not depending on an earlier one: none; RESULT: 0 violations*. The same script on the revision 3 text exits 1 with 15 violations (the unowned new test files, `tests/test_engine_integration.py` and `tests/test_query_script.py` cited by packages with no row, and `tests/test_analysis.py` and `tests/test_durable.py` mentioning `save_overlay` with no owner): `prove_disjoint_rev4_on_rev3_out.txt` |
| N1 the cap of 8 is shared with the supervisor probe | fixed | 7.6 step 5, 7.2 | the probe has **its own budget of 3** abandoned connections (the three misses that make a wedge) and is exempt from the 8 of user calls; the cap answers with a new Hydralysis code `abandoned_cap` (details and `next`), never `daemon_unhealthy`, which stays the restart-budget code; `ping` is inline (`Session.java:219-221`) so it cannot be stuck in a lock wait; test: with the budget full a probe is still sent |
| N2 `wait=` below `deadline_s` on hydra.2/3 | fixed, **by experiment** | 7.6 ("A lock wait needs no abandon"), 7.6 Waits rule | on hydra.2/3 a quick-lane read sends `wait = min(25 s, deadline_s / 2)`; measured on the real hydra.3: a read for a held program with `wait=3000` was answered `busy` at 3.0 s with the holder's details, nothing left registered, the connection usable. Stated limits: `wait` applies in full to each timed wait of a request (slot, project lock, program lock), and it does not bound a running script, so abandonment stays for the running cases S and C. Test `wait_below_deadline` |
| N3 the half-close cancels every request on the connection | fixed, **by experiment** | 7.6 step 1, tests | measured (and the reviewer's X1/X2): with a non-cooperative A and a cooperative B on one connection, `cancel` for A and the FIN ended B at once (0.02 s after the FIN) while A went on for 12.1 s; the one-call-per-entry rule is now an **invariant** that Y4a's code and tests enforce (a second `send` on a checked-out entry raises; the shared `Engine` connection is never half-closed); 'no other call is affected' is rewritten |
| N4 '41 write sites' | fixed | D14, 8.2, Appendix A | counted again from `tests/test_durable.py` at `589432e`: 41 `(file, function, kind)` **keys** (11 + 8 + 22), **43 call sites** (`COUNTS`: `hydra.install Path.rename` and `crossbuild.run open(w)` have two each); the 8 record-bearing keys are 8 sites, the 22 artifact keys are 24 sites; Revision 3's own history row keeps its original wording |
| N5 test files with no owner | fixed | see BLOCKING B, the class | |
| N6 Y4b depends on Y4a's registry | fixed | Y4b, wave plan W6, 7.6 | declared (`Depends on` and "Y4a, then Y4b" in the wave plan); the proof prints it as an in-wave order |
| N7 append inside the writer-lock hold; lock kind | fixed | 4.1 item 3 | the whole of acquisition, check, repair and the `fsync`ed append is one hold (`durable.py:451-457`, `:531-547` at 589432e); `.commit.lock` and the `.lock` of `backups.log` are OS locks (`locks.py:1`, `:39-41`: `msvcrt.locking` or `fcntl.flock`, released at process death), never an `O_EXCL` file with stale-lock reclaim; a reader that sees an in-flight line reports a transient `torn_tail`, benign |
| N8 coverage after deleting `save_overlay` | **fixed with a correction** | 8.2 (new paragraph), Y1 | the reviewer asked that the cap and validation assertions be kept against `workcopy._save_store`; reading the code showed that `_save_store` enforces only the **byte cap** (`write_sealed(max_bytes=...)`), the count cap and duplicate-id rule live in `load_store` (`workcopy.py:62-69`) and `edit` (`:545-546`), the build check in `load_store` (`:59-60`), the path and address rules in `_overlay_path` and `_edit`; each of the nine affected tests is retargeted to the function that has the rule, and **two** assertions that exist only in `save_overlay` (same id twice is one record; a changed edit under an existing id is refused: production `edit()` mints a new id every time, `:539`) are dropped on purpose and recorded |
| N9 'differ only in `HYDRA_RELEASE`' | fixed | 7.6 | re-run: plain `diff` of `hydra-2/client/.../ghidra_session.py` (LF) and `hydra-3-candidate/.../ghidra_session.py` (CRLF) prints 2,734 lines; `diff --strip-trailing-cr` prints one line, `HYDRA_RELEASE` `"12.3-hydra.2"` against `"dev"` (`:77`); the text says "modulo line endings" |
| N10 `hydra.py` citation base | fixed | header, 7.6, Appendix A | the header says which commit each citation uses (`d0466bc`, or `@589432e`, a descendant); both sets of `hydra.py` lines were read (`Engine` :209 / :295, key :227 / :313, `module()` :229 / :315, `_connect` :232 / :318, `call` :268 / :385, `EngineError` :51 / :102) and 7.6 and Appendix A give both; the `query.py` lines are identical at both |
| N11 `check_ownership.py` cannot see `Y0e`/`Y4e` | recorded as an **E1 task** (no code edited) | 8 (rule 4), 8.1 (new E1 cell), 8.2, E1 | confirmed on the E0 branch: `PKG = re.compile(r"\b[EPYR]\d+[a-d]?\b")` (`examples/check_ownership.py:57`, `:145`); E1's first commit reads the ids from the wave plan table, accepts the golden prefix and refuses frozen files; Y0e's branch is checked with E1's copy until E1 merges; the proof script checks the same property in the spec (it parses the plan table with a pattern that includes `e`) |

Also while re-reading the whole file: the Contents, D1 to D34 (no new decision number: the pool entry is part
of D33), the packages, the wave plan, 8.1 and the cross-references of 7.6 were checked against each other;
counts: 24 packages, 65 matrix rows, 155 owner cells, 1 declared in-wave sequence, 13 reply-shape
conditionals and 34 decisions unchanged.

**Revision 3 (answers the second independent review of revision 2 and the reviews of the W0 packages).**
Docs only; no code; one commit on `design/protocol-3`. B1, B2 and B3 below are the three blocking items of
the second review, N1 to N17 its seventeen nits (numbered in the order the review listed them), W the
findings of the W0 package reviews (Y0a to Y0d, E0) that belong to the design. Every change was checked
against the code or by experiment before the text was written. Experiments (new in this revision):
`D:/Projects/Hydra/_logs/spec-rev3/exp1_client_matrix.py`, `exp2_engine.py`, `exp3_lifecycle.py` with their
recorded output (7.6); the disjointness proof was re-run with `prove_disjoint_rev3.py` (output
`prove_disjoint_rev3_out.txt`). **Rejected: none.** Two items are fixed in part and have an owner for the
rest, both marked below (N9, N17).

| Item | Disposition | Where | Note |
|---|---|---|---|
| B1 deadline fallback on hydra.2/3 | fixed, **by experiment** | 7.6 (new sub-section), 3.8, 7.2, 7.5, D33, 3.5, 6, Appendix A, Y4a | `session.close()` hangs on the real 1.0.0 `SocketSession` (Python 3.14.7 and 3.15.0): it closes the makefiles before `shutdown`; the reviewer was right. `shutdown(SHUT_WR)` returns at once and delivers the FIN (the reviewer's `close_test2` is right that it does not wake the reader, but the FIN does reach the server). Chosen: half-close and abandon (worker thread owns `wait`, `cancel`, `SHUT_WR`, never `close()`, cap 8). On a real hydra.3 daemon the request goes on until it ends by itself (cooperative: released in 0.1 s; lock wait and non-cooperative script: until the holder or script ends); an abandoned-without-FIN connection leaks the engine-side client for good. The client never relies on an EOF coming back. P1b/E3b change this on hydra.4. N8 of revision 2 is superseded by this row |
| B2 `ImportGate.java` ownership and premise | fixed | 3.1 (C4, C5), 3.5, 5.1 G5, 8.1, W2 plan, E3a, Appendix A | `ImportGate.java` added to E3a's files and to the 8.1 matrix (W2, E3a); `ImportGate.enter` receives only `c.id` (`ImportGate.java:165`), so E3a gives it the `Client`; premise corrected: an import wait already carries `queue` in v2 progress events and `status.requests[].queue` (`ImportGate.java:188-194`, `RequestMonitor.java:111`); only the slot-wait `queue` key and `estimateScope` are new; `v2_progress_keys` kept and extended. Disjointness re-proved with `prove_disjoint_rev3.py`: 50 matrix rows, 123 (repo, wave, file) cells, no cell with two packages, no file with two owners in one wave, no dependency cycle |
| B3 torn-tail repair trigger | fixed | 4.1 item 3, 4.4, D10, recovery table of 4.6, Y0e, Y2 | the trigger is every acquisition of the writer lock, with the cheap check (ends in LF and size equals the last valid end); the two-process test (A appends and stays alive, B killed mid-line, A appends again: a repair record, no `lineage_corrupt`) is in 4.1, Y0e and the Y2 fault matrix |
| N1 untimed overlay locks | fixed | 3.5, 6 | listed as out of scope (`OverlayCommands.java:228, 238, 251, 319, 352, 404`); the claim now says the three request-bound timed waits are what E3b converts |
| N2 V2 "can only gain" | fixed | 3.5, 5.1 V2, E3a | both directions declared (no `wait`: success where it failed; explicit numeric `wait` spent in the gate: failure where it could succeed); tests `import_wait`, `import_wait_explicit` |
| N3 G6 cites | fixed | 5.1 G6 | cites 3.4; `describe(boolean)` is added by E1, it does not exist today (`Scheduler.java:285`) |
| N4 `O` label collision | fixed | 10, 4.7, 5 | owner decisions renamed **OD1 to OD7**; the commit-fault oracles keep **O1 to O6** (so "O2/O5" in the Revision 2 rows means the oracles) |
| N5 3.1 list incomplete; "fourteen" | fixed | 3.1, 3.3, 5.1, D2 | the table is one row per conditional, **C1 to C13: the count is thirteen** (the reviewer's 13 reproduced; "fourteen" was wrong), now including `bad_request` `details.field`/`allowed[]`, `cancelled` `details.phase`, `lock_queue_full`, `rk_expired`; keys with no conditional of their own are named; D2's threshold (twenty) is checked against 13 |
| N6 hello golden per wave; `DbVersions` | fixed | 3.1, 3.2, 8.1, E1, E2 | `capabilities`, `limits`, `policy` compared as required subsets, `paths`/`platform`/`analysisIdentity` masked, `platform.testHooks` asserted only by E5's tests; `Advertised` declares limit and policy names too; `DbVersions.java` has an E1 (W1) and an E2 (W2) cell |
| N7 revert leaves a stale `before` | fixed | 4.2, Y1 | `revert` refused with `has_dependents`; `cascade:true` reverts the chain; a batch always goes whole; recomputing the chain rejected |
| N8 `commit_revert` after archival | fixed | 4.2, 4.6, Y2 | rehydrated from the sealed archive in the same atomic store write, or `store_full` / `archive_unreadable`; test `revert_chain` |
| N9 subset commit and semantic dependencies | **fixed in part** | 4.2, 6, Y2 | the invariant is stated as per coarse subject, a `batch` is selected whole, and `subset_missing_type` must show fail-closed (ABORTED); whether closure needs type references is **decided by that test's result, owner Y2**, not guessed here |
| N10 undeclared dependencies | fixed | 8, every package's "Depends on", wave plan | Y2 (Y0b, Y0d, Y0e), E3b (E2), Y4a (Y2, Y1, Y3), Y4b (Y2), Y4e (Y2), E4 (E2) and P1a before E1 and every later `cc_*` file; the V6 test moved to `cc_e1`; R1 after E6 and E1 after P1a are declared in-wave sequences ("then" in the wave plan; the proof prints them) |
| N11 `rk` on `apply_overlay` | fixed | D15, 3.4 | dropped: overlays have no journal; `rk` is on `edit`, `rename`, `comment` |
| N12 26 ms figure | fixed | 3.6 | two README rows: 26 ms / +3 MB on 174 functions (`README.md:410`), 116 ms / +54 MB on 243,855 (`README.md:409`) |
| N13 work-conserving cap | fixed | 3.5, E3a | the cap holds a key back only while another key waits that is itself under its cap; test `per_key_cap_conserving` |
| N14 "This file is the design" | fixed | 8, R1 | it names `PROTOCOL-3.md`; R1's text has a `Files:` label and says every package appends to `certification.manifest` |
| N15 `Client.protocol` | fixed | 3.1, Appendix A, E1 | the first `hello` fixes the protocol (it is handled synchronously in `Connection.authenticate`); a repeat `hello` is answered with the connection's own protocol; a non-integer `protocol` is treated as absent |
| N16 `Y4c`; E0 "six tests" | fixed | wave plan, E0 | no Y4c exists, said; E0's wording follows the E0 convention (a premise that does not hold is dropped); on hydra.3 all six were CONFIRMED (`_logs/E0/baseline1.log`, `baseline2.log`) |
| N17 citation hygiene | **accepted, no renumbering** | header | README citations stay at the design-branch tip (the header already says so); revision 3 adds that the cited phrase is quoted where it helps and that the other evidence is cited by path |
| W `cli.py` unowned | fixed | 7.1, 8.1, 8.2, Y0e | Y0e, W1 |
| W `api.py` stubs need owners | fixed | 8, 8.1, 8.2, D34, Y2, Y4b, Y4e | one handler registry built by Y2 (W2); no other package edits `api.py` |
| W `has_overlays`/`expected_state` bypass the `.bak` | fixed | 8.2, 8.1, Y1 | Y1 (W1), `durable.exists`; test |
| W record-bearing writers outside `durable`; "~52 sites" | fixed | D14, 8.2, 4.1 item 4 | counted from the AST gate at `589432e`: 41 sites outside `durable.py` (11 non-record, 8 record-bearing in 4 writers, 22 artifacts); owner table in 8.2 (Y1, Y0e) |
| W Y0a edited unowned test files | fixed | 8, 8.1 | `tests/test_address_maps.py` and `tests/test_query.py` are Y0a's explicitly, with the rule that a format change owns the tests that hand-write it |
| W `MAX_OUTSTANDING` | decided | 7.6, Y0c, 8.2 | per lane (8 and 8, total up to 16) |
| W where `catalog` is reported | decided | 7.7, Y0d, 8.2 | `backend action=status` and `backend help` only; the hash covers the tool table only |
| W `AppendLog` 32 MiB budget | fixed | 4.1 item 3, 6, 8.2, Y0e | streamed reads and a tail window; owner Y0e (W1); the interim limit is recorded in section 6 |
| W v3 store read with `require_seal=True` | fixed | 8.2, Y1 | Y1 (W1) |
| W lone surrogate in a seal | decided | 3.4 | tolerated in seals and bundles (Python-only), refused in manifests |
| W `EngineError` cap on `next`; `unittest.main()` guard; `write_daemon_config`, `runtime` writers | fixed | 7.6, 8.1, 8.2, Y0e | Y0e (W1); `config.json` goes through `atomic_write` without a seal (the engine's launcher reads it) |
| W Y0b retry decisions (`close_project` and others, lost-reply behaviour) | recorded | 4.3 | recorded as decided; no behaviour change |
| W E0 review (`import_wait` signature, `--require-v3`, 8.1 rows) | fixed | E0, 9.3, 8.1 | `max(importsMs) >= 19000`; gate 9.3 always passes `--require-v3`; `dt_baseline.py` and `characterization/v3/` are in the matrix |
| W Y0a write cost | recorded | 9.10 | about 16 ms per record on D:, added to the gate-9.10 measurements |

Also while re-reading the whole file: the Contents, D1 to D34, G1 to G8, V1 to V7, C1 to C13, the packages (now
including Y0e), the waves and 8.1 were cross-checked (counts: 34 decisions, 13 reply-shape conditionals, 6
behaviour gates, 8 G rows, 7 V rows); the `OD` labels and the oracles no longer collide; the 8.1 matrix, the
wave plan and the packages' `Files` lists agree (the proof script's remaining differences are test files, which
are owned by name).

**Revision 2 (answers the independent review).** Docs only; no code. Every claim changed here was checked
against the code named in the text before the text was changed. Nothing in the review was rejected; where
the fix differs from the reviewer's first suggestion the table says so.

| Item | Disposition | Where | Note |
|---|---|---|---|
| B1 AppendLog torn tail | fixed | 4.1 item 3, 4.4, 4.6 (recovery table, `publish_torn`), D10 | writer-side repair under the lock (preserve fragment, truncate, record), readers ignore a torn tail, `publish_torn` then a successful new commit, per-offset cut test |
| B2 commit watermark | fixed | 4.2, 4.6 steps 1, 5, 7, 9, 4.7, 4.9, D32, O2/O5, Y1/Y2 tests, App. B8 | scalar `committed_through` replaced by a committed-id set (`commits[].ids`); exact subset and skip semantics (record is the unit, dependency closure, skip propagation, drift pre-pass); the marker carries `base` and `committed_sha256` |
| B3 compatibility claims | fixed | 3.1, 5.1, 5.2, D2, D16, D18, 1, matrix | one table of every v2-visible change: eight gated on v3 (G1-G8: `expect`, lane move, fair key and cap, validate-before-wait, progress `queue`, `describe` `tryLock`, new request fields, gate refusal code), seven declared visible (V1-V7) with a reason and a v2 behaviour test (`cc_*.py`, stock 1.0.0 client). The gate's v2 refusal reuses the existing `conflict` code. Counts corrected: nine reply-shape rows, fourteen conditionals, six behaviour gates; fallback threshold stated for the reply-shape count (twenty) |
| B4 ownership | fixed | 8, 8.1, wave plan, E0-E6, R1, Y*, D17, D31, 3.2, 3.7 | seams first: E1 makes the two signature changes and call sites (`Session.java:248`, `ImportCommands.java:112`), the `project` hook and four registries (`Advertised`, `Settings`, `Preflight`, `DbVersions`); `currentDbVersion()` moves to `DbVersions` (E1); E2 and E3a share no file; `laneNote` is decided by E3a and copied by E4; `Preflight` validators register per package; `bump_hydra.py` is R1's; E2 names no lane (combined check in E6) instead of a stub; matrix per file and wave plus `check_ownership.py` |
| B5 lock-wait fairness | fixed | 3.5, E3b, E0 | slices rejected (AQS re-enqueues at the tail on every timeout; untimed `tryLock` barges); one timed `tryLock` and cancel by interrupting the registered thread, with the state machine that keeps the interrupt inside the wait; tests `writer_vs_steady_readers` (also run against a polling build, must fail), `cancel_while_waiting`, `deadline_in_lock_wait` |
| N1 Journal citations | fixed | 3.4, App. A | `fieldOf` `Journal.java:117-125`, `lastAt` `:103-114`, file is 127 lines |
| N2 README line shift | fixed | header convention, D2, 3.4, 4.6, App. A | 986-990 to 988-992, 1001-1002 to 1003-1004, 1009-1012 to 1011-1014; also `:971` to `:973`, which the review did not name; convention: Java and Python at the named commits, README at the design branch tip |
| N3 `retryAfterMs` | fixed | 3.1, 3.3 | one location, `error.retryAfterMs`, never in `details` |
| N4 failed backup verify | fixed | 3.4 | one rule: the engine removes its copy as it already does for a changed source, writes no manifest, answers `failed` with `details.verify`; the Hydralysis writer never writes the manifest |
| N5 CRC | fixed | 4.1 | CRC-32, `zlib.crc32` (Hydralysis depends on `pefile` and `capstone` only); every `CRC32C` mention removed |
| N6 `selfSha256` | fixed | 3.4 | pinned canonical form for both writers; verified that Gson (even with `disableHtmlEscaping`) escapes U+2028/U+2029 and does not sort keys, so the engine uses a small canonical serializer; test with non-ASCII paths from both writers and a fixed vector |
| N7 backup fork `writable` | fixed | 4.5 | `writable:false` on hydra.2/3 (`ForkCommands.java:82` defaults to true) |
| N8 deadlines on hydra.2/3 | fixed | 3.8, 7.2, 7.5, 7.6, P1b, Y4a | P1b is hydra.4-only; a client-side watchdog (timer, `cancel`, then close a dedicated connection) needs only 1.0.0's `send`/`wait`/`close` |
| N9 capability registry | fixed | 3.1, D31, E1 | `Advertised`; per-wave golden growth handled by subset comparison and a full golden at R1 |
| N10 overlaps | fixed | 8, 8.1 | `laneNote`, E2/E3a, `preflight`, `bump_hydra.py` each resolved (see B4) |
| N11 D12 | fixed | D12, 4.6 step 4, E2 | decided from the sidecar alone (`kind` and not `disposable:false`); Hydralysis rewrites the sidecar of a generation it makes on hydra.2/3 before the manifest hash |
| N12 compaction | fixed | 4.2, 6 | committed records archived (never deleted) at the next `FINALIZED`; the latest commit's records stay for revert; the pending cap is listed as a limit |
| N13 stale `overlay_state` | fixed | 4.6 step 5, 4.7, Y1, Y2 | commit clears the option in the candidate (`state:null`), the marker's `base` and `committed_sha256` make a leftover mismatch, a fork of a generation clears a non-empty one |
| N14 step 7 reference | fixed | 4.6 steps 1, 7 | reference texts captured at `upTo` under `.sync.lock`; functions touched by outside records are `excluded` |
| N15 `rk` replay | fixed | 3.4 | the journal stores the per-op result, not the reply; the replay reply is reconstructed and said to be so |
| N16 quick hint | fixed | 3.4, 6 | trust-based; a non-cooperative quick script keeps its slot past its timeout |
| N17 D4 visible | fixed | 5.2, R1, section 10 | required release-notes line |
| N18 cumulative backups | fixed | 4.5 | confirmation text and doctor state the cumulative size; `backup_root_warn_gb` |
| N19 fixture count | fixed | 9.1 | 8 programs, 4 x86 and 4 x64, from `_golden/sets/fixtures.json`; the set totals 4,497 functions against 3,959 in `docs/golden-harness.md:143` (not reconciled, not relied on) |

Also corrected while re-reading: two stale cross references (`private` is 3.6, the backup schema is under
3.4), the claim that each package edits a "status table" of this file (there is none), and the
`Session.java` ownership sentence of the first revision (D17, 8).

**Revision 1.** The first version of this file (one commit on `design/protocol-3`).
