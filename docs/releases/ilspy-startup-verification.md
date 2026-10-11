# ILSpy startup recovery — SPECTRA 0.12.1

A reported .NET executable successfully produced a managed type tree and 73,715 characters of reconstructed C# on the live v0.12 site before this hotfix. The original intermittent startup failure was not reproduced. Its cause remains unconfirmed; this release improves diagnosis and recovery rather than claiming a verified fix to that unknown cause.

The managed worker previously imported the runtime before its error boundary existed. Runtime imports now happen inside that boundary. Import failures and asynchronous startup failures reach the interface with their available details. Analysis failures and loading timeouts are labeled separately. Retry ILSpy recreates the worker and preserves the file, local dependencies and requested metadata/type/method operation. Cancel or a new sample invalidates old worker responses.

The app and downloadable archives use a new v0121 asset path so an immutable cached worker or archive cannot substitute the previous release. Native and debugger engine binaries remain unchanged.

## Validation

- 8 managed-worker regression tests: import failure, asynchronous startup rejection, late runtime failure, malformed/oversized input and token validation, bounded diagnostics, absent entry point, oversized output, successful retry with real ILSpy metadata and C#.
- Existing 7 managed, 8 dependency, 3 Ghidra and 9 delivery-policy checks passed.
- Browser test under the production content security policy: deliberately return HTTP 503 for the managed entry module, observe a named startup error, retry the retained file successfully, then reconstruct C#.
- Browser Ghidra demo still reconstructs its native loop after switching engines.
- User-provided malware was inspected only as local data. No target code executed; sample bytes and reconstructed malware source are not included in this repository or release archives.

Unresolved framework dependencies can reduce the quality of recovered types and expressions. They are distinct from engine startup errors. Matching local dependencies remain optional and are read as metadata only.
