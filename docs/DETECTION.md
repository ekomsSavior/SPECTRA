# Local detection with DiE

SPECTRA 0.8 runs the real Detect It Easy 3.21 console scanner and its matching 2,047-file database in a v86 worker. This is the pinned browser release 1.2.0 from xoreaxlmbdx/die-in-browser, not a claim to contain today's newest DiE signatures. The database extracted from the VM matches the official DiE 3.21 source archive byte-for-byte under the recorded sorted-path hash. Runtime asset hashes and upstream versions are in vendor/die/manifest.json.

Open a sample and choose Detect → Scan with DiE. Nothing needs to be installed. The runtime downloads from the Church on demand; files stay in the browser. Networking, keyboard, mouse and audio adapters are disabled in the analysis VM. The sample is written under a fixed inert filename and passed only to diec. No sample path or content becomes a shell command. This is static inspection; the program being inspected is not launched.

Heuristics default on; deeper embedded-file scanning is optional. The initial runtime download is about 20 MiB. Each scan starts a fresh worker and VM; the guest has 128 MiB of RAM, with additional browser/WASM overhead. Maximum sample size is 16 MiB, serial output 2 MiB, findings 2,000 and total wall time 180 seconds including downloads. Cancel, replacement of the sample and completion discard the worker. Timeout or parser errors do not produce a successful report. Browsers may pause background work; keep the tab visible while scanning. This does not change the workbench's separate 64 MiB inspection limit.

Findings retain DiE's category, name, version, details, file region and raw output. Heuristic results remain explicitly labeled. A match is identification evidence, not a malware verdict or proof that the named protector is active. A language/compiler label does not prove the original source language. No match does not prove absence of packing or obfuscation. Explanations are optional. Findings and raw JSON can be exported, and saved investigations bind reports to the sample SHA-256. Imported display rows are regenerated from the raw report.

## Verification

The benign ManagedTraining.dll is recognized as MSIL/C# and .NET Core without an obfuscator claim. fixtures/benign-upx.elf is tests/fixtures/benign.elf packed with upstream UPX 5.2.1 (`upx --no-progress benign-upx.elf`); its original C source and build information remain in tests/fixtures. Only static scanning occurs in these tests. UPX is recognized by the actual scanner. The unchanged managed fixture took about 45 seconds in the preview browser on the development laptop. This is not a low-end-device performance guarantee.

Run `node tests/detection.test.cjs` for actual worker/engine scans, output validation and cancellation checks. `node tests/project.test.cjs` checks sample binding and saved raw evidence. Browser QA additionally checks live rendering and document-reload persistence.

## Source and licensing

DiE is MIT; v86 is BSD-2-Clause; its Linux guest and supporting libraries retain their own GPL/LGPL and other terms. The browser integration is MIT. No ExeInfoPE or dnSpyEx code is bundled by this feature. See vendor/die/LICENSES.txt and NOTICE.md.

The normal app source ZIP includes the SPECTRA adapter and pinned runtime assets. The separate **DiE runtime source + build recipes** download at `/detection-source.zip` includes the official complete DiE source, v86 and SeaBIOS source, pinned browser build files, Buildroot configuration, Linux, libc, Qt, other runtime sources, Alpine source recipes/patches and hash inventories. It is large because it contains the guest operating-system and library sources; ordinary users do not need it to scan files. Both archives are streamed from fixed static parts to keep host and browser memory bounded. They remain available without an account.

The guest build follows the included upstream Dockerfile and nodejs_state.js. Use the included DiE 3.21 source instead of resolving a moving branch; v86 commit f7011b0fc46c980f44834d490d4d444b65bec0b5, Buildroot 2025.11 and Linux 4.19.172 are pinned. The Alpine 3.22 recipes are pinned at 3eb59d73169cd4f90317120e15f4bd640cb29dd6; all ten runtime source archives were checked against their APKBUILD SHA-512 values. Preserve the included patches/configuration and collect legal-info after a rebuild. The release reuses upstream prebuilt bytes; these materials identify the corresponding code and build recipes, not a claim that changing a toolchain reproduces identical VM snapshots. Rebuilds must update hashes, rerun fixtures, and use a new immutable engine asset path.
