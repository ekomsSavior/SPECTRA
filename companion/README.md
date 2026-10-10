# SPECTRA local debugger companion — experimental Linux release

Run this on your own isolated research machine. It uses your installed GDB to execute real native code. It is not a sandbox and does not impose limits on the target's CPU, files or network access. The public SPECTRA page never connects to it.

Requires Python 3.10+ and GDB. Tested on Linux with Python 3.12 and GDB 15.1. Windows, managed/.NET debugging, remote attach, OpenOCD and native dependency provisioning are not included.

```bash
python3 companion.py --target /absolute/path/to/your/lab-program
```

Open the printed `http://127.0.0.1:PORT/` in your browser. Paste the pairing token from that terminal. Check the displayed target filename and SHA-256. **Load symbols** parses the image without execution. **Launch real process** requires the checkbox and runs until main; the loader and constructors can execute first. The UI provides instruction step/over/out, continue/pause, breakpoints, registers, stack, threads and bounded memory reads.

End debugger & target shuts down that GDB session. Ctrl-C stops the companion. Closing the tab alone does not terminate a running target. Tokens stay in page/process memory and are never put in URLs or localStorage.

The server exposes exactly two static UI files and one authenticated API on loopback. Exact Host/Origin checks, per-process bearer pairing, bounded commands and a separate target-output PTY protect the control channel. They do not protect the host from the target. Use your lab's containment. Hash checks before load/launch detect ordinary replacement, but they do not eliminate a same-user file-change race while GDB opens a path. Forked descendants and forced debugger failure require external process containment.

```bash
python3 test_companion.py
```

Tests compile and debug only the included benign C fixture. The API/parser tests require local sockets and permission for GDB to trace its own child. Review the command contract below before adapting this companion.

## Command contract

Each request is a JSON object with `op` plus only its documented fields. Extra fields and unknown operations are rejected.

| op | Fields | Behavior |
| --- | --- | --- |
| status | optional `after` event sequence | State, capability list, bounded events and truncation flag |
| load | none | Parse the configured image without running it |
| launch | none | Run real native code and stop at main; constructors may run first |
| step | none | One machine instruction |
| next | none | Step over one machine instruction; honors breakpoints inside calls |
| finish | none | Execute until the current function returns |
| pause | none | Interrupt a running inferior |
| continue | none | Resume a stopped inferior |
| stack | none | At most 32 frames |
| registers | optional array `indices` | At most 64 register values, with names; defaults to first 32 |
| memory | `address`, `length` | Read 1–4,096 bytes; address must be a literal `0x...` integer |
| breakpoint | `address` | Add a breakpoint at a literal address |
| breakpoint_delete | integer `id` | Delete one breakpoint |
| threads | none | Inspect GDB's thread list |
| quit | none | Exit GDB and terminate its launched target; server can then be stopped |

Step, next, finish, pause and continue are asynchronous. A successful command acknowledgement does not mean the process is stopped. Use the sequenced running/stopped events and session state. Stopped inspection operations refuse to run while the process is executing.

The endpoint returns 400 for invalid input/state, 401 for a missing/bad token, 403 for an invalid Host/Origin, 409 for an explicit GDB error, and 504 when a GDB command times out and the session is closed.

## GDB control channel

The process is launched through an argv array with `--nx --nh --interpreter=mi2`. Auto-load scripts and debuginfod are disabled before loading any image. Shell startup is disabled, and raw-value printing avoids invoking pretty printers. MI commands are selected by server code; numeric arguments are validated before interpolation and the configured image path is C-string quoted byte by byte.

The MI parser supports command tokens, result/async/stream records, nested tuples, value lists, result lists with repeated item names, standard C escapes, octal UTF-8 byte sequences and quoted commas. It rejects malformed/deep/oversized records instead of comma-splitting debugger output. Commands wait for their matching numeric token; asynchronous events are handled independently.

**Inferior output uses a separate PTY.** A target printing `999^exit` or `*running,...` cannot impersonate MI messages. Its bytes are retained as bounded `target-output` events only. The fixture exercises that case explicitly.

Limits include 16 KiB HTTP requests, 8 concurrent HTTP handlers, 1 MiB MI records/responses, 32 parser nesting levels, 10,000 parser nodes, 128 retained events, 16 KiB per retained event, 2 KiB target-output chunks, an 8-second command wait, and a 64 MiB selected executable limit. The event ring can discard old output and reports that fact. These limits do not sandbox the native target or bound its own memory/CPU/network use.

## Run and verify

From the workspace root:

```bash
python3 test_companion.py
```

Tests need loopback sockets and permission for GDB to trace its own benign child. The Codex restricted sandbox did not permit sockets; the successful run used the approved local-only escalation. No external network connection is needed.

For a manual session after the test compiles its fixture:

```bash
python3 companion.py \
  --target 'lab target "quoted"; literal/benign-client'
```

Use the printed local endpoint/token from your own terminal. For example, send `{"op":"load"}` and then `{"op":"launch"}` as separate authenticated requests. Launch is actual native execution. Ctrl-C shuts the daemon down and closes its debugger.

## Executed verification

`test-output.txt` records 11 passing test groups:

1. Wrong/missing/null Origin, bad token, hostile Host/Host alias, duplicate Host, unsupported method/path, duplicate JSON fields, content type and size are rejected.
2. Loading leaves the benign constructor marker absent; `.gdbinit` and target `-gdb.py` auto-load sentinels also remain absent. Raw console/evaluate, alternate paths and injected arguments are rejected without issuing MI commands.
3. Explicit launch creates the constructor marker, stops at main, returns real stack/register/thread state and reads the expected `0x11223344` variable. MI-looking target output cannot alter debugger state.
4. Expression strings, newline injection, boolean/oversized lengths, address overflow, invalid register indices and breakpoint injection are rejected. An unmapped memory read is surfaced as a GDB error.
5. Instruction step and next change the real PC, an address breakpoint stops inside the helper, deletion succeeds, and finish returns to main.
6. Pause interrupts the actual running loop, memory shows the helper's update to `0x1122334b`, and continue reports the fixture's normal exit.
7. A second launch is quit while running; both GDB and that specific inferior have exited afterward.
8–11. C-string round-trip including Unicode/control characters, nested result lists, stream/async parsing, and malformed/deep-record rejection.

The initial lifecycle test placed a breakpoint after next had already stepped over its only call. That test setup was corrected; the final run is green. There was no application regression or deployed change.

## Scope and provenance

The code, UI and tests are included in the Church's SPECTRA source release. No arbitrary expression, debugger console, HTTP-supplied target path or launch arguments are accepted. API permissions and size limits are deliberately narrow. Additional targets/platforms should include separate lifecycle and browser tests before being claimed as supported.

Primary protocol references: https://www.sourceware.org/gdb/download/onlinedocs/gdb.html/GDB_002fMI-Output-Syntax.html and https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html .
