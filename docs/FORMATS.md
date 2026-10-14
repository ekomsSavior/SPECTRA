# Portable evidence formats

All formats are documented data, without a paid service dependency. Source implementations are in `src/project.js`, `src/experiments.js`, `src/compare.js` and `src/harness.js`. UI rendering treats sample and imported text as data.

## Investigation: spectra-project-v2

A standard ZIP using stored members, CRC32 and UTF-8 names. `manifest.json` contains the schema, original SHA-256/name, notes/bookmarks, code annotations, native assumptions, settings, recovered rows/hints, harness selections, decompilation, decoder selection and debugger controls/checkpoints. Optional `sample.bin` must match the original hash. `layers/0.bin`…`layers/7.bin` carry recovered bytes, each with its own SHA-256 and transform chain. `dependencies/N.bin` contains optional managed dependency bytes. `comparison.bin` is an optional second version with a separate hash.

Limits: 128 MiB ZIP, 16 MiB manifest, 64 MiB sample, 8 recovery layers / 16 MiB total, 32 dependencies / 64 MiB including the sample, 32 MiB second binary, 10,000 code annotations, 4,000 recovery rows, 8 named checkpoints. Import validates all bytes and UI evidence before replacing current state. Unknown members, duplicate paths, traversal names, CRC/hash mismatch and excessive nesting/counts are rejected. Ordinary third-party ZIP compression is not accepted for investigation bundles; firmware extraction has its own bounded compressed parser.

Original sample omission does not omit recovered data or dependencies. Check bundles before sharing; they can contain your sample, keys entered in harness recipes, recovered secrets, notes and experiment edits. Browser full save includes the original bytes. Analysis itself sends none of this to the host.

Legacy `spectra-project-v1` notes exports remain readable. They do not contain complete workspace bytes or emulator state. Incomplete legacy exports are not presented as complete investigations.

Comparison records/listings are reproducible derived evidence. A saved second binary is re-analyzed on import; a saved firmware offset is re-inspected. No guest/native instructions run for either action. Derived functions may differ after an engine upgrade; original files/hashes remain the reference.

## Experiment: spectra-replay-v1

Fields include schema, original SHA-256, engine fingerprint, initialization options, bounded actions, summary and digest. Actions are attempted step counts and analyst register/memory edits, in order. The fingerprint includes interpreter integration, parser/decoder and emulator assets. Different builds or sample hashes refuse replay. An imported summary must match its digest, but is still labeled imported evidence until actual replay succeeds.

Restoration initializes a fresh emulator and replays actions in cancellable batches. It checks final registers, all mapped 4 KiB page hashes/permissions, tracked frames, edits, terminal state, and applicable Windows model state including virtual files and handle positions. x86 verification includes extended CPU registers; hardware verification covers the supported integer-register profile, whose FP/SIMD/system operations are rejected. It does not serialize native WASM pointers or claim OS-process restoration. MIPS operation counts and executed instruction counts differ because delay pairs are atomic.

Memory comparison is page-level, not an exact changed-byte count. Traces are bounded tails. Cancellation or a mismatch keeps the previous emulator. Nothing restores or runs automatically on project import; use Restore by replay.

## Other reports

`spectra-comparison-v1` identifies both hashes, metadata, string/import additions/removals, decoded function matches, basis/confidence, unmatched functions and ambiguous groups. Exact decoded-byte equality is not whole-function or behavioral proof when boundaries/decoding are partial.

`spectra-harness/1` selection.json identifies the original assembly SHA-256/MVID and chosen tokens/signatures. invocation.json carries the selected call, JSON arguments, constructor and setup sequence. Downloaded code has a dry-run default; explicit execution invokes real target code outside the browser. Templates and limitations are shipped with each ZIP.

## Recipes and batch evidence (0.9)

`spectra-lab-v1` is bounded recipe data: native harness ABI/arguments, named buffers, mappings, registers, explicit hooks, ARM MMIO sequences, virtual files and Linux argv/env/stdin. `spectra-recipe-export-v1` wraps it in a sample SHA-256 and CPU initialization options; UI import checks the current sample and does not execute. Recipe editor values are saved in project settings.

`spectra-batch-v1` identifies the sample, engine fingerprint, initialized CPU options, budget, per-case recipe, stop reason, output buffers, return register and observed coverage. Batches cap at 16 cases and 8 MiB report data. Project imports validate its shape and sample binding; stored reports remain unverified evidence. No auto-execution follows import. Replay summaries now include lab mappings, model events, coverage, buffer state, MMIO read indices/writes, Linux file bytes/FD positions/heap/output and the recipe, alongside CPU and mapped page digests. See EXPERIMENT-LAB.md for full semantics and limits.

Optional `codeSetup.budget` records cumulative `instructions` (1–1,000,000) and `decodedBytes` (16–16,777,216). Older projects without it use the default 60,000 / 4 MiB. Import validates these bounds. Code results and live traversal queues are recomputed locally; annotations and selected addresses remain part of the investigation. Code JSON exports additionally include `limits`, `continuation` (pending count, canContinue, ceiling) and `coverage` (decodedBytes, executableBytes). Finished queued traversal is not a claim of complete binary coverage.

## v0.15 optional evidence fields

Project-v2 optionally includes up to two `traceFiles` (validated spectra-trace-v1 observations), hash/version-bound `lessonProgress`, `provenance` and `mappingRecord` (each at most 512 KiB). Older projects remain accepted. Imported lesson checks are labeled historical; trace import never initializes an emulator. See EVIDENCE-WORKFLOWS.md for envelope checksums, selected bundle schema and limits.
