# Browser debugger environments

The standalone System lab was removed in v0.12. Its unshipped research source remains under `research/system-lab/`. There is no separate shell or guest import step in the supported workflow.

The main file is mapped by Debugger lab's selected loader. Initial setup is inferred from binary headers, then validated before Initialize. Initialization does not run instructions. PE x86/x64 use the existing Windows model. Little-endian static ELF ET_EXEC uses Linux models for x86, x64, ARM/Thumb EABI5 and AArch64. Bare routines retain the existing hardware profiles and explicit analyst harnesses.

Preflight reports loader failures, missing ELF interpreter/shared-library requirements, unsupported TLS/PIE and Windows import coverage. Windows APIs supplied by a recipe are assumptions, not native library implementations. Loading data through virtual files does not provide a dynamic linker or CLR.

The Linux startup stack contains ABI-width argc, argv, environment and auxv. PT_LOAD bytes, permissions and zeroed BSS are preserved. Modeled syscalls use architecture-specific numbers, registers and signed return values. No live networking or host filesystem access is provided. Undefined syscalls halt at the instruction. OS identity and startup random bytes are synthetic and deterministic.

Session memory, API/syscall traces, stepping, breakpoints, watchpoints, output, virtual-file capture and verified replay all use the same debugger session. New experiments are checked with benign fixtures, not user malware execution. Whole-OS boot remains research until it can serve this workflow.

ABI references: [Linux ARM syscall table](https://github.com/torvalds/linux/blob/v6.12/arch/arm/tools/syscall.tbl), [Linux x86 syscall tables](https://github.com/torvalds/linux/tree/v6.12/arch/x86/entry/syscalls), and [generic syscall ABI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h).
