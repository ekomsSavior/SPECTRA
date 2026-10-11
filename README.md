# SPECTRA 0.9 — Church of Malware

A free browser reverse-engineering workbench. Open a binary, follow the evidence, keep the investigation. Optional explanations use the same tools and evidence as the professional workspace.

- Live: https://spectra.churchofmalware.org/
- Source: https://git.churchofmalware.org/ek0mssavi0r/SPECTRA
- No account, paid tier, sample uploads, paid API, or telemetry in the analysis app. Engines are served by the Church. Cloudflare receives normal delivery metadata; sample analysis stays local.
- Black, gray and white; Creepster wordmark. Teaching defaults off.

## Investigate

ASCII and ASCII-range UTF-16 strings, SHA-256, byte offsets, hex, entropy, filters, local decoders, notes and bookmarks. PE and ELF parsers expose headers, sections, mapped addresses, imports, exports, symbols, relocation slots and supported unwind function starts.

Capstone disassembly supports x86/x64, ARM/Thumb, AArch64, RISC-V 32/64 with compressed instructions, and MIPS32/64. Follow strings into references, calls, functions, assembly, reconstructed code, and a prepared debugger experiment. Function starts and references retain their evidence; candidates are labeled. Rename functions and attach comments, variable/type hypotheses and code bookmarks.

Native C reconstruction uses the real Ghidra decompiler through Pyre's WASM bridge. Select architecture, instruction/data order, ABI, raw range and load address. Supplied C function prototypes and type declarations are parsed by Ghidra and affect reconstruction. They are analyst assumptions, not recovered truth. Variable notes do not silently rewrite engine types. .NET C# reconstruction and metadata/IL evidence use ILSpy. Local managed dependencies are resolved by exact assembly identity without executing or uploading them.

Recovery supports Base64/hex candidates, bounded single-byte XOR hunts, x86 stack strings, supplied-key XOR/RC4/AES transforms and bounded gzip/DEFLATE expansion. Recovered byte layers have hashes and provenance and can be analyzed again. Encrypted text still needs its actual key; this is not a general executable unpacker.

## Detect

The real Detect It Easy 3.21 engine and matching database run in an on-demand browser worker. Compiler/language, packer/protector and obfuscation fingerprints keep their raw evidence; heuristic labels stay visible. No installs or sample uploads. About 20 MiB initially; 16 MiB sample limit and 180-second cancellation boundary. Reports export and survive saved investigations. See [detection and source notes](docs/DETECTION.md).

## Experiment

The browser debugger uses Unicorn WASM. Initialize never executes a sample instruction. Step, step over/out, conditional register breakpoints, memory read/write watchpoints, register edits, patches, memory capture and traces are bounded and inspectable. Save up to eight experiments; restore replays recorded attempts and analyst edits in a fresh emulator, verifies its state, then swaps sessions. Compare registers, mapped-page digests, permissions and Windows-model events/files.

x86/x64 can run bare routines or a bounded Windows PE model with rebasing, imports, TLS initialization, 56 modeled APIs, API traces and virtual files. Unknown APIs and unsupported operations stop; no guest networking is supplied. It is not a complete Windows OS or CLR debugger.

ARM/Thumb/AArch64, RV32/RV64+C and MIPS32/64 integer routines have separate lazy-loaded engines. CPU defaults are documented in [hardware notes](docs/HARDWARE.md). System instructions, FP/SIMD and unmodeled operations stop before execution. ARM/Thumb transitions use live CPU mode. MIPS branch/delay pairs step atomically; slot breakpoints pause before the pair, and conditions see pre-pair registers. A synthetic mapped return boundary is explicit. Analyst-defined ARM MMIO responses are available; no full board, peripherals, RTOS or firmware boot is emulated.

SPECTRA 0.9 adds native integer/pointer function harnesses for System V/Windows x64, x86 cdecl/stdcall, ARM/Thumb AAPCS32 and AArch64 AAPCS64; before/after input buffers; saved data-only environment recipes; explicit address/API hooks; mapped captured memory; and virtual file fixtures. ARM register sequences and captured MMIO writes expose supplied hardware behavior. A focused Linux model supports little-endian static ELF64 ET_EXEC on x64 and AArch64, argc/argv/env/auxv, BSS and a small explicit syscall set. It does not supply a Linux kernel or general libc/runtime compatibility.

Coverage records observed instruction locations/transitions, including labeled modeled boundaries. Batches run up to 16 independent recipes and compare return values, buffers and observed paths. Complete reports save with investigations. Three benign demos provide ready-to-run function, Linux and ARM experiments. See [the experiment reference](docs/EXPERIMENT-LAB.md) for all controls, schemas, modeled syscalls, reproducibility limits and examples.

An **optional experimental Linux/GDB companion** serves its own authenticated loopback browser UI. It provides real native process debugging on the analyst's machine, with explicit pairing and launch. It is not a sandbox; use an isolated lab. Public SPECTRA never connects to it. Windows/.NET, remote attach and hardware adapters are not included. See [companion instructions](companion/README.md).

## Keep and compare

Notebook exports a versioned ZIP with notes, annotations, settings, recovery bytes/provenance, selected harness methods, dependencies, reconstructed source and replay checkpoints. Include original bytes or require the matching local sample on import. Full local workspace save/resume uses IndexedDB; autosave is opt-in. Browser storage can be cleared or evicted, so export work you need to keep. Saved comparisons retain the second binary and recompute evidence on resume. Firmware listings are re-derived from the saved offset. Source bytes are hash-checked before the current investigation is replaced. Import does not run sample instructions. See [export formats](docs/FORMATS.md).

Binary diff compares strings, imports and decoded functions. Exact decoded-byte matches are distinguished from symbol/shape candidates. Ambiguous and unmatched functions remain visible. Open matched functions in side-by-side assembly or reconstruct each side on demand. Partial decoding and clipped string previews are reported; these results do not prove behavioral equivalence.

Firmware files inspects ZIP (stored/deflated), USTAR/PAX, newc/crc CPIO and gzip wrappers. Regular files stay byte buffers; links/devices remain metadata. Opening a child records the parent's hash, path and container offset. SquashFS is detected but not extracted in this release. Nested extraction is manual and bounded.

For thick clients, select methods/classes and generate a downloadable .NET harness with pinned sample identity, explicit entry/constructor/setup recipes, argument conversion and optional local proxy hooks. Modern .NET harness execution is tested with benign fixtures. The .NET Framework 4.8 AnyCPU/x86/x64 template is compile-tested; **Windows execution has not been validated**. Local dependencies are analyzable, but the downloaded runner still needs the target's real runtime/native dependencies and environment. Original binaries are not included automatically.

## Learn and contribute

Training ground includes an 18-chapter searchable field guide covering every section and its controls, workflows, FAQs, and a glossary. Download the standalone HTML book or print it to PDF; the guide ships in the offline release too. Its Links area points to Church Git and MalwareBazaar. The guide content lives in `src/guide-content.mjs` and is rendered from that single source into both the reader and `guide.html`.

Training ground has a compiled benign C/ELF exercise, an XOR-loop memory experiment and hardware addition/delay-slot exercises. Source, exact fixtures, hints, walkthroughs and evidence checks are included. Optional contextual explanations follow the selected finding or instruction. Nothing forces experienced users through a tutorial.

See [contributing](CONTRIBUTING.md), [budgets and performance](docs/PERFORMANCE.md), [engine builds](docs/BUILDING-ENGINES.md) and [roadmap](ROADMAP.md). Original Church code is MIT licensed; third-party engines retain their licenses. The combined debugger distribution includes GPL-2.0 Unicorn with matching source. See [license scope](NOTICE.md) and the generated third-party notices.

## Build and run offline

Use Node.js 20+ (verified with 24.19) and Python 3. No npm installation is needed for the app:

```bash
node build.mjs
python3 scripts/package-source.py
python3 scripts/serve.py --port 4173
```

Open `http://127.0.0.1:4173/`. Keep the **whole dist directory**, including `engines/v09`; a saved HTML file alone does not contain the decompilers or hardware engines. All runtime assets are included locally; no CDN or API is needed. The localhost server applies the production CSP. The source ZIP includes all browser runtime assets. To publish the large DiE runtime source archive too, collect the pinned inputs documented in docs/DETECTION.md and run `python3 scripts/package-detection-source.py /path/to/source-inputs` after package-source.py. Training ground also offers a complete offline ZIP download, assembled from verified static parts to fit the host asset limit. A complete offline ZIP can be made with `python3 scripts/package-offline.py`. Engine rebuilds need the documented upstream toolchains, not for ordinary app builds.

```bash
python3 scripts/test.py
# Optional generated-harness integration test, with a suitable installed SDK:
SPECTRA_DOTNET=/path/to/dotnet node tests/harness.test.mjs
# Optional real local debugger test; runs only its compiled benign fixture:
python3 companion/test_companion.py
```

The optional Framework build may restore locked NuGet packages. Browser tests should cover both first-use lazy engine loads and a real document reload before claiming save/resume works.

## Hosting

SPECTRA does not audit or harden the user's network or analysis machine. Static parsing, decompilation and emulation are incomplete models; inspect warnings and preserve uncertainty. Full-process Windows/.NET execution, whole-file unpacking, advanced type recovery, SquashFS extraction and further hardware profiles remain areas for continued research.
