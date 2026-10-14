# Portable evidence workflows — SPECTRA 0.15

All four workflows run locally in the browser. No sample upload is introduced. They extend the existing debugger, projects, File structure and Training ground. The new beginner/intermediate books are not included in this release.

## Portable traces

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

Prepare inventory creates one immutable in-memory snapshot. Review its selection flags, member paths, lengths and hashes. Download returns that prepared snapshot. Selection changes disable download until preparation is repeated; later investigation edits require preparing again to include them.

`*.evidence.zip` contains `evidence-manifest.json` (`spectra-evidence-v1`) and the existing project-v2 members under `project/`. Every member has a byte length and SHA-256 in the outer manifest. The manifest's sample identity must agree with the project. Missing, duplicated, tampered or unlisted files fail validation. A manifest with an unknown evidence schema is shown for inspection, with restoration disabled.

Opening a bundle reviews its inventory first. The separately labeled replacement action restores the selected project. Without bundled original bytes, the matching sample must already be open. Restore may recompute static analysis and load metadata engines, as existing project restore does; no sample instructions run. Replay requires a separate explicit action.

Existing caps remain: 129 MiB ZIP input, 16 MiB project metadata, 64 MiB original, 8 recovered layers / 16 MiB total, at most 32 dependencies / 64 MiB including the primary image, and 32 MiB comparison bytes, additionally bounded by archive limits. This first release assembles ZIPs in memory. It does not claim constant-memory streaming or guarantee maximum-sized exports on a phone. Use the smallest relevant selections and export before leaving a heavy tab.

Selecting a category can include sensitive content within it. Notes can quote bytes; traces can contain decoded strings; captured layers include their provenance; experimental recipes can contain private values. Category selection does not inspect or sanitize secrets inside selected data. The manifest shows included files, not a secret-scanning verdict.

## Address mapping help

File structure offers three explicit sources:

- **Declared file headers:** PE headers/sections or ELF PT_LOAD spans. PE extent is max(VirtualSize, SizeOfRawData). ELF p_filesz distinguishes original bytes from p_memsz zero-fill.
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
