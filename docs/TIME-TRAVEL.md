# Routine history in Debugger lab

Routine history is an opt-in, session-local timeline for x86/x64 **bare routines**. It retains a verified boundary after each instruction attempt or analyst register/memory edit. Earlier boundaries are reconstructed by forward replay from the original initialization, then checked against their recorded digest. The engine does not execute instructions backward.

## A first experiment

1. Open Debugger lab and load the benign decoding demo. Initialize the session; no instructions run yet.
2. In **Time travel · routine history**, choose **512 actions** and **Start history** before stepping or editing.
3. Use the regular Step, Step over/out, or Run controls. A run may pause at its time budget; continue as needed. The decoding demo ends after 221 instructions.
4. Choose **Step backward**, or enter a retained **Boundary** and choose **Inspect boundary**. Boundary zero is the initialized state. An instruction attempt that stops without completing an instruction still gets its own boundary; edits also count as actions.
5. The badge says **HISTORICAL · READ ONLY**. The existing register, assembly, memory, trace and model panels show the verified reconstructed state. Memory navigation and capture are available. Execution and edits are locked.
6. **Step forward in history** inspects the next retained boundary. **Return to latest** restores the untouched live experiment. It does not replay or undo the live session.
7. Set address/conditional breakpoints or memory watchpoints, then choose **Reverse to breakpoint / access**. This searches earlier retained observations and reconstructs the boundary *before* the matching operation. It can use a watchpoint added after capture. Repeated instruction addresses are searched in timeline order, not address order.
8. Save a checkpoint or export an investigation if you want to preserve a selected state. The existing explicit replay workflow can reconstruct that checkpoint later. **The timeline itself is not saved by projects or trace files.**

## Verification and state ownership

Each admitted boundary has a digest over the existing experiment verifier's supported registers (including x86 vector/FPU and descriptor state), all mapped-page hashes and permissions, call tracking, analyst edits, attempt/instruction counters, terminal state and the explicit recipe/model snapshot. CPU writes, address-hook outputs, buffers and model events therefore contribute to verification, even when the ordinary 200-row trace preview is clipped.

A seek creates a fresh emulator using the same in-memory sample, setup and engine. It checks the initialized state, replays retained actions and checks the destination digest. Only a matching candidate becomes the historical view. Divergence or cancellation discards the candidate and returns to the intact latest live session. At most one live emulator and one replay candidate/view are retained by this workflow.

A recorded digest verifies agreement with this local experiment. It is not proof that the environment matches a real machine or that a binary is safe. Imported portable traces remain unverified observations and cannot be used as executable histories.

## Deliberate limits

- x86/x64 bare-routine profile only. Windows/Linux process history, ARM/Thumb/AArch64, RISC-V and MIPS history are not admitted yet. Existing stepping and checkpoint controls still work for those profiles.
- Start immediately after initialization, before any steps or edits. Recipe initialization is included in boundary zero.
- At most **2 MiB mapped memory**, **2,048 actions** and **4 MiB serialized timeline metadata**. These are admission budgets, not total browser memory measurements. Engine memory, source bytes, the live session and a replay candidate are additional.
- A budget hit pauses **before the next action**. Older boundaries are not evicted. Discard the timeline explicitly to continue without it, or reset to begin another experiment.
- Each seek replays from the initial state. Periodic executable checkpoints, persistence, timeline import, branch editing, process/model expansion and faster long histories remain follow-up work.
- Reverse access search retains up to 128 read/write observations per action. If that list is clipped, the result reports uncertainty; absence of a retained match cannot establish that an access never occurred.
- A backward action includes an analyst edit or an attempted instruction, not necessarily one completed instruction. Partial fault states remain partial and are verified as such.
- Persistent recording and routine history are separate capture modes. Stop/discard the current mode before starting the other. Separate batch runs or checkpoint restoration also require discarding the active timeline.

Historical memory captures and session reports carry a history-view marker. Exporting a checkpoint from a historical view preserves that selected state, not the later live state or the entire timeline. Browser reload/tab loss discards this first timeline implementation; export needed evidence before leaving.
