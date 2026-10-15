# Portable evidence workflows — SPECTRA 0.16

All four workflows run locally in the browser. No sample upload is introduced. They extend the existing debugger, projects, File structure and Training ground. The new beginner/intermediate books are not included in this release.

## Persistent recordings (v2)

Debugger lab → **Persistent recording** retains ordered observations beyond the live 200-row preview. Initialize a compatible setup, choose a byte/instruction budget, and press Start recording **before** Step or Run. Stop recording flushes it to local IndexedDB. Browse 100 rows at a time, search all stored records, or compare two saved runs using bounded event alignment. Reload preserves committed segments. A recording left open by tab loss must be explicitly sealed as interrupted before export; its missing tail is not reconstructed.

The recorder captures the initial mapped pages and original image provenance, successful map/unmap/protect operations, model events, instruction observations, analyst edits and stops. Mapping at selected event reconstructs allocation/protection state at that sequence; Original bytes requires the same sample hash and an unambiguous file-backed address. Unmapped then reallocated pages do not inherit old image provenance. Changes to bytes, relocations, and arbitrary historical registers/memory are not reconstructed by this ledger.

Budgets: 2/8/32/64 MiB selectable; up to 100,000 instructions and 250,000 records. The writer reserves footer headroom under the 64 MiB file-member limit. A budget hit pauses interactive execution and exposes a gap. It keeps admitted history rather than evicting early rows. Per-instruction observation/write limits remain those of the debugger; faulting operations and MIPS branch/delay pairs keep their existing semantics. This is full **observation retention within a budget**, not lossless machine state or time travel.

**Export recording** prepares a completed `.ndjson` file. Use the explicit **Save completed file** link to save it through the browser, then confirm it exists in your downloads/Files. Preparation alone is not a download confirmation. Import recording validates incrementally into temporary storage and discards failed imports. It never initializes an emulator. Two opened recordings can be included under the trace selection in a project/evidence bundle.

Imported x64dbg v1 `.trace32/.trace64` and Chrome trace-event JSON are inert observations. The x64dbg adapter accepts uncompressed version 1, preserves thread IDs, opcode bytes, pre-instruction dump changes and memory observations. Unchanged memory is labeled “read or same-value write (unknown).” Chrome JSON is limited to 8 MiB and preserves file order instead of inventing instruction order. Neither adapter establishes the executable SHA-256 or enables byte navigation/replay. See [recording format and adapter contracts](RECORDINGS.md).

Alignment uses event keys with 24-record lookahead, 2,000 result rows and 4 MiB of result data. Repeated keys and uncertain pairs stay ambiguous. A matching key or payload is not semantic equivalence. Larger comparisons report truncation.

## Legacy bounded trace snapshots (v1)

1. Initialize a compatible debugger setup and explicitly step/run the benign exercise or your reviewed routine.
2. Pause. In Debugger lab → Portable traces, optionally include supplied inputs/analyst edits, then Capture paused trace.
3. Search retained addresses, instructions, API/syscall events or recorded values. Select a row to inspect its exact recorded changes.
4. Download selected trace. Open trace file later, with or without its original sample. Import parses data only.
5. With the matching sample open, recorded loader origins map a selected address to original file bytes. Assembly navigation additionally requires that address already decoded in this investigation. Neither link displays historical memory.
6. A second slot enables comparison. A third import/capture replaces the selected slot. Comparison reports sample/engine mismatch, first different retained ordinal, final register differences and changes in events/mappings/stop metadata. It is not path alignment or semantic equivalence.

### Format and limits

A `.trace.json` is a `spectra-trace-envelope-v1` object containing `sha256` and `payload`. The checksum is SHA-256 over UTF-8 `JSON.stringify(payload)` in serialized property order. Cosmetic outer whitespace is irrelevant; changing payload values/order requires recomputing its checksum. This detects corruption, not authorship or trustworthiness.

Payload schema `spectra-trace-v1` records sample name/SHA-256/size, engine identity/hash, CPU, ABI when supplied by a harness, environment, stop reason/status/PC, final registers, instructions, event channels, final mappings, optional loader origins and optional inputs. `scope` is `bounded-observation`; `replayable` is false. It is distinct from the existing verified replay checkpoint format.

- Payload at most 4 MiB; envelope at most 4 MiB + 256 bytes. JSON depth 24 / 250,000 values. Prototype-related keys are rejected.
- Latest 200 instruction records. Each carries its step, address, mnemonic/operands, observed register changes and at most 32 clipped write observations (up to 256 bytes per range). Faulting operations can be partial. This is not a complete memory log.
- Up to 500 Windows model events and 256 experiment model events. Counts and omitted records remain explicit. No missing history is reconstructed from guesses.
- Model event step is the pre-operation count; instruction step is the completed/partial attempt count. Order within each channel is retained. Sorting by step in the viewer does not assert a total execution order across tied channels.
- At most 4,096 final mappings/origins. Origins are validated against sample size and unsigned 64-bit extents. Mapping lifecycle is **not** recorded.
- Final registers and mappings describe the end of capture, not every historical position. ABI can be null when no explicit function harness supplied one.
- Inputs and analyst edits are opt-in. Traces can still contain secrets in register/memory/API evidence. Excluding inputs is not redaction.

Imported traces are visibly unverified observations even with a valid checksum. They never construct or drive an emulator. Project-v2 can preserve two trace payloads.

## Selective evidence bundles

Notebook → Selective evidence bundle separates nine selections: findings; original sample; recovered artifacts; dependencies; comparison binary; analysis results/settings; debugger experiments; portable traces; lesson progress. Only findings are selected by default. Findings include notes, bookmarks, address annotations and parent provenance. Analysis includes type/signature hypotheses, code mapping/depth, reconstructed source and detection reports. Experiments include debugger settings/recipes, controls, checkpoints and batch results. Harness-runner recipes and unrelated UI searches are not copied by this exporter.

Prepare inventory creates an immutable snapshot of selected sources, backed by Blobs/local files. Review its selection flags, member paths, lengths and hashes. Download prepared bundle writes that snapshot incrementally; Save completed file then requests the browser download. Selection changes disable download until preparation is repeated; later investigation edits require preparing again to include them.

`*.evidence.zip` contains `evidence-manifest.json` (`spectra-evidence-v1`) and the existing project-v2 members under `project/`. Every member has a byte length and SHA-256 in the outer manifest. The manifest's sample identity must agree with the project. Missing, duplicated, tampered or unlisted files fail validation. A manifest with an unknown evidence schema is shown for inspection, with restoration disabled.

Cancel preparation / export aborts the active operation. A truncated ZIP without its final directory is rejected as incomplete. Browser-private staging files use `.partial` names. Discard prepared files / clear old export leftovers removes current prepared links and abandoned staging files older than 24 hours, while retaining recordings/investigations.

Opening a bundle reviews its inventory first. The separately labeled replacement action restores the selected project. Without bundled original bytes, the matching sample must already be open. Restore may recompute static analysis and load metadata engines, as existing project restore does; no sample instructions run. Replay requires a separate explicit action.

Existing caps remain: 129 MiB ZIP input, 16 MiB project metadata, 64 MiB original, 8 recovered layers / 16 MiB total, at most 32 dependencies / 64 MiB including the primary image, and 32 MiB comparison bytes, additionally bounded by archive limits. ZIP writing, CRC/SHA hashing and file-member verification use 64 KiB chunks. The exporter prefers browser-private file storage, with a bounded 16 MiB fallback where no streaming destination exists. Original source buffers, prepared Blobs, metadata and restoration allocations still consume memory; this is not a constant-total-memory claim. Whole-workspace project/library saves remain the older in-memory ZIP path. Maximum-sized exports on phones have not been established. Use the smallest relevant selections and export before leaving a heavy tab.

Selecting a category can include sensitive content within it. Notes can quote bytes; traces can contain decoded strings; captured layers include their provenance; experimental recipes can contain private values. Category selection does not inspect or sanitize secrets inside selected data. The manifest shows included files, not a secret-scanning verdict.

## Address mapping help

File structure offers three explicit sources:

- **Declared file headers:** PE headers/sections, ELF PT_LOAD spans (including PN_XNUM extended numbering), or thin Mach-O segments (32/64 bit, either byte order, including SG_HIGHVM). Relocatable objects require an explicit map; universal Mach-O requires selecting a slice first. PE extent is max(VirtualSize, SizeOfRawData). ELF p_filesz distinguishes original bytes from p_memsz zero-fill.
- **Captured debugger mappings:** loader regions and allocated pages from the latest available session snapshot. Rebasing/load bias is recorded. File-backed original bytes can differ from relocated or modified memory.
- **Current raw disassembly range:** the analyst's reviewed offset, byte length and base VA. It does not invent a loader.

Input may be decimal or `0x` hex: file offset, VA, or PE-only RVA. BigInt arithmetic preserves unsigned 64-bit values. Results are file-backed, zero-fill, allocated, file-only or unmapped. Ambiguous overlaps return all precise candidates; page residency does not override loader byte provenance. There is no fabricated file offset for stack/scratch/BSS. Export captures both the ledger and query result as `spectra-mapping-v1` data, also retained by the analysis export selection.

Relocatable ELF needs an analyst mapping; extended ELF program-header numbering is currently rejected with an explanation. This converter does not expand any execution engine's supported addresses or CPU modes. Firmware child investigations preserve container/member coordinates and parent hash. Compressed or decoded layers have no assumed linear parent offset conversion.

## Resumable teaching exercises

The existing native-reference, decoder and hardware exercises gain versioned checklists. Windows virtual-file and Linux virtual-stdin/stdout exercises expose existing benign model demos through Training ground too. They are not a new malware collection or the unpublished manuals' practice pack.

Each lesson has three evidence checks and an exact built-in fixture SHA-256, kind, CPU and version. A confirmation dialog protects the current sample when opening an exercise. Loading/preparing does not itself run sample instructions. Checks inspect analysis results, observed instructions, model events, return registers or newly captured recovered output. Pasting a correct-looking answer is not enough. Recovered strings imported from a project do not count as a newly observed capture.

Check my evidence records narrow milestones. Read the evidence text: successful output under a model is not proof of identical real-system behavior. Historical milestones persist after later experiments; their recorded timestamp matters. Save lesson workspace uses the existing local IndexedDB investigation slot. Resume saved workspace recovers it after a reload. Project ZIPs and selected lesson progress in evidence bundles are portable alternatives. Browser storage is evictable.

Import validates fixture hash/version before replacing the investigation. Saved checks show “saved evidence; not reverified this session.” The debugger checkpoint is restored as inert data; restoring by replay remains deliberate. Checks may be refreshed after gathering current-session evidence. No score claims the user has mastered interpretation.

## Scope and next foundation

This release is not time travel. Reverse stepping needs budgeted history/checkpoint coverage, a deterministic event log (including partial failures, edits, hooks, map changes, file state and MMIO consumption), cancellation and state-digest verification. The portable format deliberately says what it lacks so research can build on reliable observations rather than treating truncated traces as complete recordings.


## Expanded lesson routes (v2)

Each of the five existing fixtures now has six stages: identity, its two investigation-specific observations, an address-mapping result, an analyst-written evidence note, and a prepared findings inventory. Missing checks explain the required evidence and offer a named navigation button. Notes are checked for presence, not correctness. New mapping/note milestones require a current observation/edit; restoring saved text alone does not turn it into fresh evidence. Old v1 three-stage progress migrates to six stages with previous marks labeled historical. Save after Check my evidence; prepare the bundle again if you want that latest progress inside it.

Automated checks and desktop browser walkthroughs cover persistence, provenance and restoration. Physical iPad/iPhone Safari, VoiceOver and modest-device peak-memory validation are still pending. [Safari acceptance route](SAFARI-ACCEPTANCE.md). The separately drafted beginner/intermediate manuals remain unpublished.
