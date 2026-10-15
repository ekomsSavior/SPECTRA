# Recording v2 and external adapters

This document describes SPECTRA 0.16. Every import is data, unverified and non-replayable. A checksum proves that serialized bytes agree with the accompanying digest; it does not prove who captured them, that events happened, or that the sample was identified correctly.

## Native NDJSON transport

UTF-8, one JSON object and LF per line. The first line has `type: "header"`, `schema: "spectra-recording-v2"`, `replayable: false`, `origin`, sample name/byte length/SHA-256, engine identity (or null), CPU, environment, creation time, start step and explicit budgets. Local headers may contain initial registers/options. Producer inputs can contain sensitive data.

Each subsequent observation is `{type:"record", seq, step, kind, data}`. `seq` starts at zero and increases by one across storage segments. Steps cannot regress. Event `kind` is instruction, windows, lab, mapping, register-edit, memory-edit, stop, external or gap. Mapping snapshots contain page extents and optional original loader spans, image base and load bias. Map, unmap and protect contain exact unsigned address/size strings. File-backed origin bounds must fit the declared sample. These are reported provenance, not independent verification.

The final object has `type:"complete"`, record count, SHA-256, source status, `completeHistory`, gaps and `observationsOnly:true`. SHA-256 covers the exact preceding UTF-8 lines including LF, not the footer. Reformatting those lines requires recomputing the digest. A missing footer, trailing content, malformed JSON, unsafe prototype key, noncontiguous sequence, regressing step, checksum mismatch or exceeded limit rejects the import and removes staging records.

Limits: 64 MiB nominal recording budget with 128 KiB reserved footer headroom, 250,000 records, 100,000 instruction operations, 128 KiB encoded line, JSON depth 20 and 30,000 values per record. Persistent segments are normally flushed around 64–128 KiB (up to 256 KiB for a boundary record); debugger batches also flush after at most 32 instructions. Segment data and its index are committed atomically. Interrupted metadata retains status `recording` until an analyst seals it as incomplete. A missing segment fails inspection. Browser eviction can remove the database: there is no off-device backup unless the analyst exports it.

`completeHistory` only states that the producer reported no retention gap from step zero. Per-instruction clipped writes, unsupported CPU/OS behavior, partial faults and model limitations remain. Imports cannot become verified replay checkpoints.

## x64dbg adapter

Supported: binary `TRAC`, JSON header version 1, `arch: x86|x64`, uncompressed stream; normal instruction block type 0 and high-bit extension blocks retained as bounded opaque metadata/hashes. Unknown mandatory block types, compression, reserved flags, truncation and oversize inputs fail. No x64dbg DLL or sample code is loaded.

Register indices use the documented x86/x64 `REGDUMP` layout (instruction pointer index 8/16). Relative changed-index encodings are expanded exactly; pointer values remain hexadecimal strings, including addresses above JavaScript's safe integer range. Recorded state is pre-instruction. Memory flags distinguish changed values from unchanged values; unchanged may be a read **or a same-value write**, so the adapter never claims the distinction is known. Thread IDs and opcode bytes are retained. The file hash identifies the trace file; producer metadata is preserved separately and is not substituted for an executable SHA-256.

Primary references: [x64dbg trace-file specification](https://help.x64dbg.com/en/latest/developers/tracefile.html), [upstream REGDUMP declarations](https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h), [trace writer](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/TraceRecord.cpp). Future producer versions require explicit adapter changes and fixtures.

## Chrome trace-event adapter

Accepts a trace-event array or an object with a `traceEvents` array, up to 8 MiB and 100,000 events. It preserves bounded producer events, phases, timestamps, process/thread IDs, arguments and file order. It does not sort timestamps into an invented global execution order, map events to native instructions, or infer runtime memory. JSON parsing for this adapter is bounded but is not streaming. Native NDJSON and binary x64dbg imports are incremental.

Primary references: [Chromium trace-event format](https://chromium.googlesource.com/catapult/+/HEAD/docs/trace-event-format.md), [Perfetto format overview](https://perfetto.dev/docs/getting-started/other-formats).

## Evidence ZIP transport

Stored ZIP entries, UTF-8 names, final central directory, exact local/central size and CRC agreement, SHA-256 for every inventory member. Maximum 512 members, 64 MiB/member, 128 MiB expanded payload and 129 MiB input. Traversal paths, duplicate/overlapping members, symlinks, encrypted members, data descriptors, ZIP64 and compressed input members are rejected. This intentionally narrow format avoids executing or extracting arbitrary archive contents onto a host filesystem.

The archive is assembled with bounded 64 KiB working chunks and written to a local destination. The immutable source snapshot and any restoration buffers are additional memory/storage. Browser download completion is outside the web page's control: a prepared Save completed file link is not proof that Safari/Files has saved the file.
