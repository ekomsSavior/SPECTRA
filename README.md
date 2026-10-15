# SPECTRA

**Reverse engineering in your browser. Free, open source, and built for the community.**

[Open SPECTRA](https://spectra.churchofmalware.org/) · [Read the field guide](https://spectra.churchofmalware.org/guide.html) · [Church Git](https://git.churchofmalware.org/ek0mssavi0r/SPECTRA) · [GitHub](https://github.com/ekomsSavior/SPECTRA)

SPECTRA is the [Church of Malware](https://churchofmalware.org/)'s reverse-engineering workbench. Inspect a binary, follow its strings into code, reconstruct functions, test a routine, and keep the evidence together in one workspace. Use it for malware analysis, software research, firmware inspection, patch comparison, or your first look inside a compiled program.

The tools are for everyone. No account, paid tier, or paid API is required. Beginners get the same workbench as experienced researchers, with optional explanations and hands-on exercises to help them find their way.

**Your samples stay in your browser.** Parsing, disassembly, decompilation, detection, and emulation run locally. The analysis app does not upload samples or include telemetry. The Church serves the engine assets; Cloudflare receives normal website delivery metadata. A complete offline release is available too.

## Start with a question. Follow the evidence.

1. **Open a file**, or head to **Training ground** and choose a benign exercise with source and a walkthrough.
2. **Get your bearings.** Check the format, architecture, imports, strings, and detection results. Pick something worth investigating.
3. **Follow it into code.** Move through references, callers, disassembly, and reconstructed source. Name what you understand and annotate what you still need to prove.
4. **Test a theory.** Prepare a compatible debugger setup, supply the inputs a routine needs, and inspect its registers, memory, and execution trace.
5. **Keep your work.** Save an investigation, compare another build, or export selected evidence for someone else to examine.

**Teaching defaults off. Click “Explain as I go” at the top of the workspace to turn it on.** Explanations follow the selected finding or instruction; all tools remain available either way.

## The workbench

### Inspect and identify

| Section | What you can do |
| --- | --- |
| **Strings** | Extract ASCII and wide-string candidates, filter findings, inspect offsets, and bookmark leads. SHA-256 and entropy give you a starting picture of the file. |
| **File structure** | Examine PE and ELF headers, sections, imports, exports, symbols, and supported relocation/unwind records. Convert file offsets, RVAs, and virtual addresses with an exact 64-bit mapping ledger, including thin Mach-O mappings and captured debugger regions. |
| **Hex explorer** | Inspect the bytes behind a finding and check what a parser, decoder, or code view is telling you. |
| **Detect** | Run the real **Detect It Easy** engine and signature database locally to identify compiler/language, packer, protector, and obfuscation fingerprints. Keep the report and its evidence with the investigation. |
| **Firmware files** | Inspect and extract supported ZIP, TAR, CPIO, gzip, and SquashFS containers. Follow extracted files into their own investigations with parent hashes and provenance preserved. |

Mapping results distinguish file-backed bytes, zero-fill, allocated memory, and ambiguous overlaps. Extracting a compressed child does not invent a linear offset back into its parent. Detection results are leads to investigate, not a verdict about a file's behavior.

### Follow code and reconstruct meaning

**Disassembly, Functions, and Cross-references** connect strings, addresses, calls, and code. Capstone supports x86/x64, ARM/Thumb, AArch64, RISC-V 32/64 with compressed instructions, and MIPS32/64. Explore control-flow graphs, follow callers, and keep assembly beside reconstructed C.

Analysis can continue in bounded passes without throwing away completed work. Supported indirect-call and switch-table patterns retain their evidence; unresolved targets remain visible. Function recognition combines declared names, import thunks, and a curated exact-signature library, with local signature-pack import/export.

**Decompile** brings two established engines into the browser:

- **Ghidra**, through Pyre's WebAssembly bridge, reconstructs native C. Choose the architecture, ABI, byte order, load address, and raw range when needed. Validated function signatures and type declarations feed back into reconstruction and callers.
- **ILSpy** reconstructs managed C# and exposes metadata and IL. Add local dependencies resolved by full assembly identity, without loading or executing their code.

Function names, comments, bookmarks, structure layouts, and type hypotheses stay with the investigation. Corrections mark affected native output stale so it can be regenerated. Reconstructed source and analyst-supplied types remain interpretations to check against the bytes.

**Recovery lab and Decoder lab** help examine hidden data: Base64/hex candidates, bounded XOR hunts, x86 stack strings, supplied-key XOR/RC4/AES transforms, and gzip/DEFLATE expansion. Recovered layers retain their hashes and provenance and can be analyzed again. These are focused recovery tools; encrypted data still needs the appropriate key, and arbitrary packed executables are not automatically unpacked.

### Experiment in Debugger lab

The **Unicorn WebAssembly debugger** keeps stepping, breakpoints, registers, memory, and traces in the same workspace as your static analysis. Setup is inferred from the sample and checked before initialization. Initializing a session does not execute sample instructions.

- Step into, over, or out; use conditional register breakpoints and memory read/write watchpoints.
- Edit registers, patch emulated memory, capture buffers, and inspect API/syscall events and virtual files.
- Build native function harnesses with integer/pointer arguments, input buffers, and explicit calling conventions.
- Supply data-only environment recipes, captured memory, API responses, virtual files, and supported ARM MMIO responses.
- Compare bounded experiment batches, observed coverage, return values, and before/after buffers.
- Save checkpoints and verify forward replay in a fresh emulator before restoring an experiment.

Supported environments include a bounded **Windows x86/x64 PE model** with relocations, imports, TLS handling, and modeled APIs; **static Linux ELF** setups for x86, x64, ARM/Thumb, and AArch64; and bare integer-routine profiles for supported ARM, RISC-V, and MIPS modes. ARM/Thumb static PIE has a dedicated supported path.

These environments model selected OS/API behavior. They do not supply a complete Windows/Linux system, a CLR debugger, or every dependency a program expects. Preflight identifies missing support; unsupported operations stop explicitly. Guest networking is not provided. See [debugger environments](docs/BROWSER-LAB.md), [experiment controls](docs/EXPERIMENT-LAB.md), and [hardware support](docs/HARDWARE.md) for the exact profiles.

For managed-client research, SPECTRA also generates **downloadable .NET harnesses** from selected methods/classes, with explicit constructor/setup recipes and arguments. The generated runner runs in the analyst's own environment, outside the browser, and needs the target's runtime and dependencies. Modern .NET has benign execution tests; the .NET Framework template is compile-tested, with Windows execution validation still outstanding.

### Preserve, compare, and share evidence

**Notebook and the Investigation library** preserve notes, annotations, settings, recovered layers, decompiled output, and experiments. Keep named investigations and revisions locally, or export portable projects. Autosave is optional; export work you need to keep because browser storage can be cleared or evicted.

**Persistent recordings** retain ordered instruction observations, model events, edits, stops, and mapping changes within an explicit budget. Browse and search saved segments, compare runs with event alignment, and import/export checksummed NDJSON. Documented x64dbg and Chrome trace-event adapters bring external observations into the workbench. Imported evidence remains labeled unverified; trace import does not run a sample or create a replay checkpoint. Recordings are not time-travel debugging.

**Selective evidence bundles** let you choose findings, samples, recovered files, dependencies, analysis, experiments, traces, and lesson progress separately. Review a prepared inventory with per-file sizes and SHA-256 hashes before exporting. ZIP writing is incremental, with cancellation and incomplete-file checks. Choosing categories is not automatic redaction of their contents.

**Binary diff** compares strings, imports, and decoded functions between builds. Inspect matched functions in paired assembly or decompile either side. Exact byte matches stay distinct from uncertain symbol/shape matches; a match alone does not prove equivalent behavior.

The [evidence workflow reference](docs/EVIDENCE-WORKFLOWS.md), [recording contracts](docs/RECORDINGS.md), and [project formats](docs/FORMATS.md) document what is retained, how restoration works, and where the limits are.

## Learn by doing

**Training ground** includes benign native, Windows, Linux, decoder, and hardware exercises with source, fixtures, hints, walkthroughs, and resumable evidence checklists. Each route ties progress to the exact exercise and distinguishes newly observed evidence from imported history.

The built-in **18-chapter field guide** covers the workbench's sections, controls, workflows, FAQs, and terminology. Read it in place, download the standalone book, or print it to PDF. It also ships in the offline release.

The interface supports narrow layouts, touch navigation, and keyboard controls. Larger engines and recordings still need memory; a small screen does not mean a small workload. Physical iPad/iPhone Safari and assistive-technology validation remain ongoing. See the [device test route](docs/SAFARI-ACCEPTANCE.md) and [performance budgets](docs/PERFORMANCE.md).

## Run locally or offline

The hosted workbench needs no installation. For offline use, **Training ground → Download complete offline release** includes the app and its browser engines.

To build from source, use **Node.js 20+** and **Python 3**. No npm installation is needed for the app build:

```bash
node build.mjs
python3 scripts/package-source.py
python3 scripts/serve.py --port 4173
```

Open [localhost:4173](http://127.0.0.1:4173/). Keep the **whole `dist` directory**, including its versioned `engines` directory. A saved HTML file alone does not contain the analysis engines. Runtime assets are served locally without a CDN or analysis API, and the supplied server applies the production content security policy.

To assemble a complete offline ZIP:

```bash
python3 scripts/package-offline.py
```

Engine rebuilds use additional upstream toolchains; ordinary app builds use the included runtime assets. See [engine builds](docs/BUILDING-ENGINES.md) and [Detect It Easy source packaging](docs/DETECTION.md) for those workflows.

## Build with us

SPECTRA belongs to the Church of Malware community. Useful bug reports, small reproducible binaries, lessons, architecture tests, accessibility feedback, and code contributions all help make the workbench better.

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Share a benign reproducer and the research question you were trying to answer; keep live malware and private samples out of public issues.

For source changes, install the test dependencies and run the regression suite:

```bash
npm ci --prefix tests --ignore-scripts
python3 scripts/test.py
```

Optional generated-harness integration checks use an installed .NET SDK:

```bash
SPECTRA_DOTNET=/path/to/dotnet node tests/harness.test.mjs
```

[Roadmap](ROADMAP.md) · [Analysis depth](docs/ANALYSIS-DEPTH.md) · [Release notes and verification](docs/releases/) · [Experimental local debugger companion](companion/README.md)

## Open source, with credit where it's due

SPECTRA builds on Ghidra/Pyre, ILSpy, Capstone, Unicorn, Detect It Easy, and the work of their contributors. Original Church code and lessons are **MIT licensed**. Third-party components retain their own licenses; the combined debugger distribution includes GPL-2.0 Unicorn and matching source. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), and the distribution's third-party notices for scope and attribution.

**Church of Malware — Hackers helping hackers.**
