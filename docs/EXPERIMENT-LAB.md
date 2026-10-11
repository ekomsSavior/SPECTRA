# Experiment lab — SPECTRA 0.9

The lab asks a small, useful question: **with these bytes and these inputs, what changes?** Everything here runs in a disposable browser worker. Guest code cannot open a host file, connect to a server, launch a process or boot an OS. A model is still a model: keep its assumptions with the evidence.

## First run

Open **Debugger lab → Load function + batch demo**. Initialization maps bytes and supplies arguments; it executes no instructions. The demo computes `left ? left + right : right`. Run / continue returns 5 for 2 and 3. Run cases tries zero, two and seven in separate emulators and returns 3, 5 and 10. The two nonzero cases share a path; the zero case takes another. The interactive session is unchanged by the batch.

Use **Load ARM register demo** to read an analyst-supplied 41 from address `0x20000000`, increment it, and capture a write of 42. Use **Load Linux demo** to read virtual stdin and echo it to virtual stdout; select x86, x64, ARM, Thumb or AArch64 first. These demos replace the current sample. Source/bytes are in `src/lab-ui.js`, `src/linux.js` and `tests/advanced-lab.test.cjs`.

## 1. Native function inputs

Select an actual function through Disassembly / Functions → debugger, or set the start VA yourself. Choose Bare routine, or Windows model when you need its PE mapping/import environment. Enable **Call the selected entry as a native function**, choose the ABI and supply an argument array. Initialize again after editing setup.

| ABI | CPU | Register arguments | Remaining arguments | Return |
|---|---|---|---|---|
| sysv64 | x64 | RDI RSI RDX RCX R8 R9 | RSP+8 onwards | RAX |
| win64 | x64 | RCX RDX R8 R9 | RSP+40 onwards, after return address and 32-byte shadow space | RAX |
| cdecl | x86 | none | ESP+4 onwards | EAX |
| stdcall | x86 | none | ESP+4 onwards; hooks pop argument words | EAX |
| aapcs32 | ARM / Thumb | R0–R3 | SP onwards | R0 |
| aapcs64 | AArch64 | X0–X7 | SP onwards | X0 |

Only **one unsigned machine word per integer/pointer** is supported. Use strings for exact values, especially above JavaScript's safe integer range. To represent a signed input, supply its correctly sized two's-complement bit pattern. This does not infer sign extension, floating-point, aggregates, multiword values, varargs, member-function `this` rules or hidden result pointers. Check the caller and the actual signature. RISC-V/MIPS still use explicit register/stack setup; this new ABI form does not claim support for them.

The synthetic x64 entry stack is 8 mod 16; ARM32 uses 8-byte and AArch64 16-byte alignment. Stack and scratch are 64 KiB each at `0x70000000` and `0x60000000`. x86 returns to zero; hardware returns to the explicit `0x50000000` boundary. The Windows function harness skips TLS callback execution and process/DLL entry calls, while retaining mapped PE data, initialized TLS data and modeled imports. A routine depending on those skipped callbacks needs additional supplied state.

In **Arguments**, enter:

```json
[{"buffer":"input"},"3"]
```

In **Input / output buffers**, enter:

```json
[{"name":"input","hex":"41424300","size":32}]
```

Unfilled bytes are zero. The first automatic buffer begins at scratch+4096; subsequent buffers are 16-byte aligned. An explicit `address` must lie in existing writable, non-executable memory outside the ABI/startup stack. Buffers cannot overlap each other. `{ "buffer":"input", "offset":1 }` points inside it. Results display before/after bytes and the return register. A return register shown before a clean return is intermediate state, not a valid function result.

## 2. Saved environment recipes and hooks

The advanced recipe editor accepts **data, never executable scripts**. Function and buffer fields have dedicated controls in the UI; the exported recipe combines them under `harness` and `buffers`. Other keys are `schema`, `label`, `regions`, `registers`, `hooks`, `mmio`, `files`, `argv`, `env`, and `stdin`. Unknown keys are rejected.

```json
{
  "label":"Known config and a fixed clock",
  "files":[{"path":"C:\\config.txt","hex":"746573740a"}],
  "hooks":[{
    "api":"kernel32.dll!GetTickCount",
    "abi":"win64","argc":0,"result":"1234",
    "label":"Clock value supplied by analyst"
  }]
}
```

Windows paths normalize slash direction and case. Linux paths are absolute virtual names; `..` is rejected. These are byte buffers, not files on your machine. Config, fixtures and API outputs are observations you supply; SPECTRA does not discover a real user's configuration or credentials.

Hooks identify **one** mapped executable `address` or Windows `DLL!API` (case-insensitive, with `.dll`). An exact address hook takes precedence over a named API hook if both target the same boundary. Supply the matching ABI and `argc`. A hook reads those arguments, writes optional outputs, supplies `result`, and returns to the caller without executing the target body. Each event says the target was skipped. This is useful for isolating a parser or supplying a recorded service response; it is not evidence of the actual API implementation.

An output write uses the value of a pointer argument plus an offset:

```json
{"hooks":[{"address":"0x1010","abi":"sysv64","argc":1,
 "result":"4","writes":[{"argument":0,"offset":0,"hex":"44415441"}],
 "label":"Four recorded output bytes"}]}
```

Outputs need writable, non-executable mapped data. Invalid return targets or output ranges stop. Hook writes trigger watchpoints. Hooks do not automatically allocate objects, follow pointers, synthesize structs, call a server or implement DLL code. Unmatched/unknown APIs still stop. General `registers` are applied after the ABI setup, so a register override can deliberately replace an argument.

Map captured memory in page-sized regions:

```json
{"regions":[{"address":"0x20000000","size":4096,"permissions":"RW",
 "hex":"41424300","name":"Captured RAM at this address"}]}
```

Regions must be page aligned, cannot overlap existing memory, and allow R/RW/RX/RWX permissions. Code writes during execution still stop, including writes into a recipe's executable region. Initial recipe bytes and explicit session patches are analyst edits; they are not recovered bytes from the sample.

**Export recipe** writes the sample hash, CPU/environment setup and recipe. **Import recipe** requires the same sample and loads data only. The full investigation preserves the editors, recipe, checkpoints and batch report. Imports do not run anything until you choose an execution action. Reset uses the last initialized configuration; Initialize uses the current editors.

## 3. Focused Linux userspace

Choose **Linux static ELF model** for little-endian **ELF32/ELF64 ET_EXEC on x86, x64, ARM/Thumb EABI5 or AArch64**. ARM starts in user mode; the Thumb entry bit is preserved. Startup stack words match the CPU pointer width. The model loads PT_LOAD segments, zeros BSS, merges page permissions, and builds argc/argv/env and a small auxiliary vector. Program headers must be present in a load segment. Entry must be in executable file bytes; startup begins at that entry. Dynamic/PIE/interpreter/TLS images are rejected. Most normal distribution binaries expect much more than this profile; start with small static syscall-only programs.

`argv` and `env` are string arrays; env entries use NAME=value. Empty argv defaults to `["sample"]`. `stdin` is hex. UID/GID 1000, PID 1337, 4 KiB pages and deterministic AT_RANDOM bytes `01..10` are explicit model values. There is no randomness source, clock, shell, dynamic linker, threads, signals, scheduler, `/proc`, kernel or live networking. Unsupported syscalls stop before supplying a result.

| Syscall | x64 / AArch64 number | Supported behavior |
|---|---|---|
| read | 0 / 63 | Virtual stdin/files, current descriptor position, bounded output buffer |
| write | 1 / 64 | Captured stdout/stderr or writable virtual file; raw bytes retained |
| open | 2 / — | x64 virtual absolute path |
| openat | 257 / 56 | AT_FDCWD only; absolute virtual path |
| close | 3 / 57 | Close virtual descriptor |
| lseek | 8 / 62 | SET/CUR/END within the virtual 64 KiB range |
| mmap | 9 / 222 | Anonymous private, address=0, fd=-1, offset=0; up to 1 MiB |
| mprotect | 10 / 226 | Entire modeled mmap allocation only |
| munmap | 11 / 215 | Entire modeled mmap allocation only |
| brk | 12 / 214 | Synthetic heap range 0x41000000–0x41100000; shrinking retains mappings |
| getpid | 39 / 172 | Explicit synthetic PID 1337 |
| exit, exit_group | 60,231 / 93,94 | Record low-byte exit code and stop this session |

Open flags are RDONLY/WRONLY/RDWR, optional CREAT/TRUNC/CLOEXEC; permissions/ownership are not modeled. Unknown flags stop. File data is capped at 64 KiB/file, 512 KiB total, 64 file records and 64 descriptors. I/O is capped at 64 KiB/call; combined stdout/stderr at 64 KiB. The report retains separate stdout/stderr hex and combined emission-order hex; displayed text can contain decoding replacements for non-UTF-8 bytes. Closing stdout/stderr and later writing must yield EBADF, like other closed descriptors. No FD duplication or pipes are modeled.

The complete architecture-specific syscall map is exported as `SpectraLinux.ABI` / `CALLS` in `src/linux.js`; `tests/runtime.test.cjs` exercises all five profiles. Added process queries include UID/GID/EUID/EGID, PPID/TID, synthetic uname, getcwd, access/readlink on virtual regular files and bounded readv/writev. ELF32 uses mmap2 with zero offset; legacy mmap argument-block entry is unsupported. ARM OABI SVC immediates and nonzero AArch64 SVC immediates stop explicitly.

A modeled syscall is one observed boundary, not an emulated kernel instruction trace. x64 records RCX/R11 syscall clobbers. The experiment logs arguments, results and model notes. Virtual files can go to Recovery lab. Supply only relevant data; secrets placed in recipes can be included in project/report exports.

## 4. ARM hardware experiments

Use a bare ARM, Thumb or AArch64 routine. Map captured RAM and supply general registers or function arguments. Add `mmio` records for **exact aligned 1, 2 or 4-byte accesses**:

```json
{"mmio":[{"address":"0x20000000","width":4,"values":["0","1"],
 "onExhaustion":"stop","write":"capture","label":"Ready bit capture"}]}
```

A read consumes the next value. The default stops when values run out; explicit `hold` repeats the last value. Captured writes are logged; they do not alter a future read sequence or trigger peripheral side effects. Accesses to another register in the same page, an unexpected width, or forbidden writes stop. A stopped CPU operation can be partial; it is excluded from observed coverage. Events keep the supplied/read/written value, address and width.

Register pages cannot overlap existing mappings. No interrupts, timers, DMA, bus timing, reset sequence or complete peripheral/board model is created. Memory captures must match the target's load address and byte order. MMIO recipes cannot be combined with the Linux process profile. Replays check sequence positions, captured writes, maps, CPU/memory state and coverage.

## 5. Coverage and batches

Observed coverage tracks up to 8,192 executed instruction locations and 8,192 observed transitions with hit counts. Explicit modeled hooks and syscalls are included as boundaries and labeled in trace/events. Partial or failed operations are excluded. It is **not whole-binary coverage**, not a proof that an unvisited branch is unreachable, and not a function/basic-block coverage percentage. MIPS delay-slot locations are counted with the atomic branch/slot operation; its transition connects the branch to the resulting PC.

The UI shows the first 256 locations and 100 transitions; reports retain the bounded collection. Clicking a location reads its current interactive-session bytes. If inspecting a batch case, those bytes can differ from that case: batch output is evidence, not a live restored emulator.

Cases are JSON objects. `arguments` replaces function arguments. `buffers`, `regions`, `hooks`, `mmio`, `files`, `argv`, `env` and `stdin` replace that base collection/value. `registers` merges by name. Every case starts with fresh memory, files, CPU and model state from the last initialized CPU setup, plus the current recipe/case overrides. Interactive edits, watchpoints and breakpoints are not inherited. This isolates inputs while preserving the interactive session.

```json
[{"label":"empty","arguments":["0","3"]},
 {"label":"nonzero","arguments":["7","3"]}]
```

Limits: 1–16 cases, 1–10,000 instructions per case, 30 seconds per batch, 512 KiB combined recipe input and 8 MiB saved report. Pause cancels the batch; cancelled/incomplete batches do not replace the previous complete report. Setup errors remain visible and later cases continue. Compare return values, changed buffers and added/missing observed locations against the first case whose setup succeeded. A faulting baseline is still a faulting baseline; review the stop reasons. Export the report or save it in an investigation. Imported reports are recorded evidence, not a cryptographic proof that someone ran them.

## Reproducibility and remaining limits

Replay fingerprints include the new Linux/recipe code. A checkpoint from an older emulator build cannot replay in this build; its original offline release is the correct environment for that experiment. The new recipes are portable data but still depend on their sample bytes and chosen CPU. A full OS/board environment remains future work.

The regression fixtures cover ABI registers/stack spill and alignment, hooks and output writes, virtual files, Linux startup/read/write/exit/memory calls, ARM MMIO and failures, replay, batch isolation/cancellation and project validation. They establish these small supported behaviors, not compatibility with every compiled program.

Primary ABI references: [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), [Arm AAPCS32](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst), [Arm AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst), [AMD64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI). Linux interface reference: [Linux syscall tables](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/syscall.tbl). SPECTRA implements the limited subset above, not those complete specifications.
