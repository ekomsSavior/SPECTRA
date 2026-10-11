# Browser access and System lab

The public application needs a browser, not a companion, account, second computer or paid API. The same investigation tools are offered on narrow screens. Device memory and browser support still constrain which jobs can finish. Physical Safari/iPad/iPhone testing is not represented by a desktop Chromium viewport test.

## System lab implementation

The dedicated worker restores the pinned DiE/v86 Linux baseline: i686 Linux 4.19.172, 128 MiB guest RAM, v86 commit f7011b0fc46c980f44834d490d4d444b65bec0b5. This is a real small Linux guest restored from a clean booted state, not a new cold-boot image and not the routine debugger's Linux syscall model. The runtime downloads about 20 MiB on first use. BIOS, state and WASM bytes are checked against the existing pinned manifest.

No sample is imported or executed on Start. Copy open sample places bytes at a generated `/mnt/input-N.bin` path. Console commands are explicit analyst actions; filenames never become shell commands. There is no emulated guest NIC or network relay. The guest cannot browse the analyst's host filesystem; the only file bridge is the bounded in-memory 9p tree and explicit input/output controls.

Guest filesystem mutations are bounded before resizing: 8 MiB per shared file, 16 MiB total backing buffers, 256 allocated inodes, bounded lock metadata. Exceeding a bound terminates the worker. Only regular files reached through real directories can be captured; links/device entries are excluded. The browser does not interpret console output as HTML. A console burst above 64 KiB per flush stops the worker. Visible output retains 64 KiB; the export retains 1 MiB with a truncation flag.

Pause retains RAM and files. Stop/discard terminates the worker. A hidden page or each five-minute run window pauses the guest. Startup has a 60-second deadline. One in-memory checkpoint stores actual emulator state, including guest RAM and 9p file bytes. Save/restore pause the guest and require explicit Resume. The checkpoint is temporary, is bounded to 180 MiB, and is not part of project ZIPs or the IndexedDB investigation library. Typical checkpoint memory is roughly 150 MiB in addition to the running guest. Closing/reloading the tab or opening another sample discards it.

Captured guest files can enter Recovery lab with SHA-256, guest path, baseline identity and session provenance. Capture and sample changes are guarded by the investigation storage epoch. Projects preserve captured recovery bytes; a separate JSON session-log export preserves commands and retained output. Guest claims remain untrusted evidence.

## What this environment does not imply

The baseline is not Windows, x86-64 or ARM Linux; importing a binary does not supply missing architecture support, loaders or libraries. It is not full-process GDB-style debugging. The existing routine debugger remains available for its supported architectures, stepping and breakpoints. A browser VM is not a claim of universal compatibility or a proof that unknown software cannot exhaust a tab. The host/browser may still evict it under memory pressure.

Additional QEMU-Wasm CPU/board configurations are isolated research prototypes. Their results must be recorded by exact engine, image, memory profile and browser. They are not silently substituted for this baseline, and a kernel startup log is not a successful shell or a working device model.

## Other browser access changes

- Investigation library: IndexedDB v2 migrates the existing `workspace` store and adds `projects`/`revisions`. Saves are atomic. Each project binds to the sample SHA-256, retains eight revisions, and belongs to an optional collection. The library caps at 32 projects and 512 MiB including Trash. Permanent removal is available only in Trash after an explicit UI confirmation. Portable exports remain necessary when site storage is evicted.
- Experiment forms: inputs become the same bounded data-only recipe used by the debugger. All edits pass the existing recipe validator. JSON remains available, and existing hook effects survive form edits.
- Code workspace: history retains 128 local navigation positions. The paired C pane requires matching sample hash and function entry. The graph draws at most 64 blocks and only resolved internal edges; the detailed list remains available. Type controls pass actual supported declarations to Ghidra.
- Firmware: SquashFS 4.0 little-endian gzip/XZ/Zstandard; 64 MiB input/regular-output budget, 16 MiB per file, 2,000 entries, 32 directory levels, 8 MiB metadata cache, 30-second worker deadline. Files remain inert buffers. Inventory positions identify inode metadata for SquashFS, not a fictitious contiguous location for decompressed file data. Unsupported formats/codecs stop.

## Reproducing checks

Run `npm ci --prefix tests --ignore-scripts`, then `python3 scripts/test.py`. Generated harness runtime checks additionally use `SPECTRA_DOTNET=/path/to/dotnet`. System tests exercise the shipping worker and real Linux guest; storage tests use pinned fake-indexeddb only in tests. Browser QA must additionally check a true page reload, a narrow viewport, file-picker input, real workers, and no page-wide horizontal overflow. Report physical device results separately.

Firmware codec sources and a portable build command are in `vendor/firmware`; rebuilding uses Emscripten 3.1.56. The application build itself uses included pinned runtime assets and does not need the compiler.
