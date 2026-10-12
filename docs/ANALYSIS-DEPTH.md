# Deeper static analysis (0.11)

SPECTRA keeps machine-decoded evidence, file-value candidates and analyst hypotheses separate. These features never execute a sample. Try **Disassembly → Load analysis demo**; source and build instructions are in fixtures/analysis-depth.

## Indirect targets

The decoder now tracks admitted constant and address-building sequences within a basic block. x86/x64 supports full-register MOV/LEA and simple ADD/SUB/XOR, pointer loads, register calls/jumps and fixed-address memory transfers. AArch64 supports ADR/ADRP, unshifted ADD/SUB, MOV and simple LDR/BLR/BR sequences. Calls, branches, entry points, discontinuities and unrecognized instructions discard facts. This is deliberately conservative local analysis, not whole-program dataflow or general virtual-call recovery.

A register constant targeting executable bytes can extend code discovery. Import loads retain the slot name and contributing instruction addresses. A file-backed pointer is a candidate: its runtime contents are unverified. Writable pointer slots do not drive automatic traversal. Unknown, partial-register and unsupported patterns remain unresolved. Hardware families without this automatic tracking can still use explicit target hypotheses.

In **Indirect targets & switch tables**, choose a decoded transfer using **Use selected instruction**, enter a candidate target VA and a note, then **Save indirect target**. It must map to executable bytes. Removing a hypothesis reruns analysis from the original bytes. It is not an emulator hook or a Ghidra control-flow override.

## Switch tables

Automatic recovery supports unsigned CMP + JA/JAE guards followed by an x86 absolute indexed pointer jump, or an x64 PIC LEA / MOVSXD / ADD / JMP sequence. A 32-bit range check cannot bound a 64-bit index unless the admitted sequence explicitly zero-extends it. Alternate entries, calls, changed indices, invalid targets and unsupported layouts are rejected. Entries overlapping an already decoded instruction are rejected.

For a known layout on other architectures, enter the dispatch VA, table VA, count, width (1/2/4/8), absolute or signed-relative encoding, relative base VA, and first case label. Every entry must fit file-backed mappings and point to aligned executable bytes. The entry values, file offsets, targets, case labels and source of the interpretation appear in the table report and code JSON. No instruction-scaling or PC-bias is guessed; supply only a matching representation. A computed first-case label is an analyst label, not a proven source switch value.

At most 32 automatic tables and 32 analyst layouts are retained, each with 256 entries. Each analysis request expands at most four indirect-discovery rounds. Disassembly starts with 60,000 instructions / 4 MiB decoded and can explicitly continue toward 1,000,000 instructions / 16 MiB, with 45 seconds per request. Pending direct work is retained at budget boundaries; indirect hypotheses are expanded only after that direct frontier is exhausted. Function comparisons retain their separate default bounded pass. Candidate branch edges join the graph and function traversal; they are labeled separately from direct instructions. Duplicate case destinations remain separate evidence. Static contents do not prove runtime reachability.

## Library-function evidence

Functions shows three kinds of evidence:
- Standard-library names present in binary symbols. Symbols can be misleading.
- Small forwarding thunks through named import slots, including admitted register-load sequences. This identifies the import relationship, not the final runtime implementation.
- Exact complete contiguous function byte matches. Thirty source-built x86/x64 GCC reference candidates ship for strlen, strcmp, memcmp, memcpy and memset. They are Church reference implementations, not a comprehensive vendor-libc/FLIRT database. Compiler changes, relocation changes, padding gaps and incomplete recovery can prevent a match.

Ambiguous names for the same bytes remain separate. **Use this name** records an analyst rename and the supporting evidence in Notebook. It does not silently replace names or declare a file benign. Maximum4096 findings are retained; the UI shows the first500.

**Export selected function signature** captures the selected complete contiguous16–4096byte function and its sample hash/address as provenance. Choose a reviewed C identifier. **Import signature pack** reads local JSON with schema spectra-signatures-v1 and signatures containing name, mode, endian, exact hexadecimal bytes and source. Modes match the decoder (arm64, not aarch64). No scripts or wildcard patterns run. Limit512 entries/256KiB signature bytes/1MiB import file. Imported signatures live with the investigation. All supported decoder families can use exact packs; the bundled reference corpus covers x86/x64 only. Rebuild it with python3 scripts/build-signatures.py and the documented GCC flags.

## Structure workspace

Under Decompile, select the intended architecture, mapping and ABI first. Open **Structure workspace** and enter a name, total size and ordered fields. Each field has byte offset, a fixed-width integer or char type, name and array count. Fields must be non-overlapping and naturally aligned. Gaps and trailing bytes become explicit uint8_t padding. Limit32 structures,64fields each,64KiB structure size,4096elements/field. The generated declaration is visible.

Save the structure. In a function prototype, use the registered name, for example `uint32_t read_count(Record *record);`. Ghidra's parser registers the name from `struct Record { ... };`; its prototype parser expects `Record *`, rather than `struct Record *`. Decompile to validate the signature and see actual engine output. A rejected declaration does not overwrite the saved function assumptions.

**Read fields from file** uses a file offset and selected data byte order. It shows exact integer values (including full64bit values), at most16values/array. Pointers are not followed. This preview is a supplied layout applied to bytes; it is not automatic structure recovery. Packed layouts, bitfields, nested types and C++ classes are outside this form; the separate declaration parser accepts only its supported C subset and can reject unsupported declarations.

## Corrections and reproducibility

Successful engine-applied signatures are saved by function VA and full Ghidra language/compiler ID. All saved signatures and shared declarations for that language are passed to later native reconstruction, including callers and the current sample's side of Binary diff. Signatures outside the selected mappings are omitted with a warning. Other architectures/ABIs and the comparison's second binary do not inherit them. Maximum128signatures and32distinct type declarations per reconstruction. Type dependency order follows saved declarations; unresolved or conflicting types produce an engine error instead of guessed output.

Renames follow code links, functions, references and newly reconstructed calls. Notebook's signature/variable notes remain notes until the user chooses **Use signature in Ghidra** and successfully decompiles. Changes mark an existing native reconstruction stale, disable copying/exporting it as current source, and require recomputation in the paired pane. Comparison output is marked for refresh. Names are not patched into old C text.

Full project exports and named library revisions retain hypotheses, imported signatures, structures, saved native assumptions and their revision. Import restores data and reruns static analysis; it never runs the sample. Older projects default to empty new collections. Debugger replay is tied to an engine fingerprint; this analysis update changes that fingerprint, so old replay records may require recreating an experiment with the current engine.
