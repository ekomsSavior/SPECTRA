# Hardware workflows

Native reconstruction uses Ghidra processor/ABI specifications; instruction decoding uses Capstone; routine experiments use Unicorn. These are distinct engines. Support in one does not imply support in the others.

| Family | Decompiler | Routine emulator default |
|---|---|---|
| ARM32 / Thumb | LE/BE32 ARMv8, Thumb, Cortex profiles; default/Windows/APCS as provided | Cortex-A15 LE or ARM1176 BE32; live ARM↔Thumb transitions |
| AArch64 | LE or BE data, v8A; LE instructions in both | Cortex-A72 |
| RISC-V | RV32/RV64 with C; ilp32d/lp64d compiler profiles | SiFive U34/U54 integer subset, LE |
| MIPS | MIPS32/64 LE/BE default profiles | 74KF / R4000 integer subset; branch/delay pairs |

Raw inputs require file offset, length, load address and architecture. Ghidra entries must be aligned (2 bytes for Thumb/RISC-V, 4 for ARM/AArch64/MIPS). Thumb's state bit is not part of the byte address. Choose its profile explicitly for mixed-mode functions. Automatic whole-image disassembly does not resolve every mixed ARM/Thumb transition; treat that limitation as part of its evidence. The emulator follows live CPSR.T for tested BX/BLX interworking.

Unsupported profiles stop clearly: ARM BE8, MIPS16/microMIPS/R6/n32 and RV32E. RISC-V ELF ABI flags that differ from the double-float compiler profile require explicit analyst acceptance for decompilation. The native function form supplies single-word integer/pointer AAPCS32/AAPCS64 arguments; RISC-V/MIPS use explicit register/stack state. Hardware FP/SIMD/system and privilege operations are outside its admitted instruction set. CPU-model selection is not exposed by this Unicorn wrapper.

MIPS return delay slots execute together with the branch. SPECTRA preflights both and stops before an unsupported slot. A slot breakpoint stops before the pair; conditional slot breakpoints read pre-pair registers. Both instructions count against the instruction budget. Branch-likely annul/compact modes and nested delay-slot control flow are not admitted. The trace displays both instructions and the combined after-state.

Mapping is bounded to 16 MiB including stack/scratch and a synthetic RX return page at 0x50000000. Stack/scratch are 64 KiB at 0x70000000/0x60000000. General registers begin at zero; SP and return-link state are explicit synthetic inputs. ARM/Thumb/AArch64 have optional exact-width MMIO response sequences and captured writes. AArch64 also has a separate small static Linux ELF profile. Neither supplies a device, interrupt-controller, kernel, firmware boot or network model. See EXPERIMENT-LAB.md. Unknown execution stops. Memory faults may leave partial state.

Tests include 27 genuine Ghidra reconstruction fixtures, type-driven field reconstruction, 14 architecture/endian/compressed emulator cases with verified replay, system-instruction stops, MIPS slot preflight/breakpoints/budgets and ARM interworking. See fixtures/hardware-functions.json and tests/hardware*. These small proofs do not establish broad coverage of every extension, calling convention or chip.
