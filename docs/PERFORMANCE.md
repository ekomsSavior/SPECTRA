# Budgets and performance checks

The release criterion is bounded work, cancellation, lazy heavy engines, honest partial results and basic workflows that do not need a large VM image. Measurements here describe the test host, not a claim of testing every low-end laptop.

- Original file: 64 MiB. Basic analysis worker: 30 seconds. Strings are bounded and long previews labeled clipped.
- Disassembly: 60,000 instructions, 4 MiB decoded bytes, bounded graph walk, 45-second worker timeout. Results mark truncation. Only the current table page is rendered.
- Native decompilation: 32 MiB input, 60-second worker limit; on-demand function. .NET main image: 16 MiB; up to 32 local deps, each 16 MiB, 64 MiB total. Browse large managed assemblies before decompiling individual methods.
- Hardware emulators are separate bundles (~0.54–2.57 MiB each) loaded only for the chosen family. Ghidra loads small language catalogs once and selected processor/ABI files on demand. Engines use disposable workers; Reset/Cancel terminates them.
- Emulator memory: 16 MiB guest mappings, 100,000 attempted operations/session, 10,000 instructions or 4 seconds/run; control returns between batches of at most 32. Eight checkpoints, 200 analyst edits, 128 breakpoints, 32 watchpoints. Replay: 60-second worker deadline. x86 extended register and memory digest checks cost more than a simple Step.
- Recovery: 4 MiB transform input, 8 MiB output, 8 layers / 16 MiB total, 4,000 rows, 30-second workers. Firmware: 64 MiB expanded container, 16 MiB regular member, 2,000 entries, 30 seconds. Links are never followed; nested extraction is manual.
- Binary comparison: 32 MiB each file, first 2,000 recovered functions, 60-second worker. Tables show a bounded subset; exported report retains all computed matches. Side-by-side reconstruction loads sequentially with separate cancellable workers.
- Workspace: 128 MiB bundle, 16 MiB metadata, depth/count checks. Explicit local save/restore is intentional; large ZIP CRC/hash validation may briefly use the main thread. Autosave is opt-in/debounced and waits for a paused experiment; browser disk quotas/eviction are outside the app's control.

Run `python3 scripts/test.py` for functional checks. `python3 scripts/measure.py` records startup analysis/disassembly wall time and process peak RSS on the current machine, plus shipped asset sizes. Capture before/after results for changes, and use browser QA on an actual modest machine before claiming a hardware performance target. Do not trade away parser budgets or uncertainty labels to improve a benchmark.

- Advanced lab: recipe JSON 256 KiB, 16 mapped regions / 1 MiB added guest memory, 16 buffers / 32 KiB, 32 hooks, 32 MMIO records (256 read values each), 256 retained model events. Coverage: 8,192 locations/transitions each. Batch: 16 fresh cases, 10,000 instructions each, 30-second cooperative deadline (40-second worker termination fallback), 512 KiB combined input recipes, 8 MiB report. CPU/memory quotas remain in force. Linux file data: 512 KiB aggregate, 64 KiB each; combined stdout/stderr 64 KiB. These caps are implementation limits, not laptop performance claims.
