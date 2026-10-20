# Android APK and DEX analysis

Open an APK or standard `.dex`, then choose **Decompile → dex2jar + Vineflower**. The Android workbench runs in a dedicated browser worker. Package members and class bytes remain local data; no uploaded class is loaded into a JVM or Android runtime.

## A useful first pass

1. **Read APK / DEX.** Review the number of DEX files, classes and members. Standard root names (`classes.dex`, `classes2.dex`, and later numbered files) are indexed independently. Duplicate class identities remain visible with their DEX filenames.
2. Expand **Manifest, resources & package files**, select `AndroidManifest.xml`, and choose **Decode XML / resource table**. Read package identity, components, intent filters and permission declarations. A permission is a capability request, not evidence that the program used it.
3. Select `resources.arsc` to inspect resource IDs, type/key names, scalar values, bags and variants. Numeric references stay numeric; raw configuration bytes identify variants. This is an evidence inventory, not an apktool-style rebuilt project. XML under `res/` can also be decoded.
4. Search by package/class name. Choose a class and **Decompile**. SPECTRA translates its DEX to JVM class bytes with dex2jar, then reconstructs Java with Vineflower. Kotlin applications use this same DEX path; the output is Java, not recovered original Kotlin.
5. Choose a method and **Inspect method bytes**. Read its descriptor, DEX hash, code offset and instruction length. The preview shows up to 256 bytes. These are Dalvik instructions; native ARM/x86 disassembly is not an appropriate interpretation of them.
6. Expand **Source references** to follow engine-reported references to classes or methods with an unambiguous definition in this package. These links are symbolic source relationships, not a claim that a source line corresponds one-to-one with a DEX instruction.
7. **Export source** saves the selected class as `.java`. **Export evidence** retains the package hash, DEX hash/name, class selection, metadata, source tokens, engine identity and warnings. **Export inventory** records package members and class identities. The currently reconstructed class also survives workspace/project exports and the selected analysis group of an evidence bundle.

**Open DEX in Hex explorer** creates a child investigation at the selected method's instruction offset. **Open child investigation** can open a native `lib/<abi>/*.so` in the ordinary Ghidra workflow. These actions replace the active sample after confirmation; save the current investigation first. The child retains its parent hash/member name and its own hash. Compression does not create an invented linear offset into the parent APK.

## Try the teaching route

**Training ground → Load the Android exercise** starts a six-stage, hash-bound route. **Android demo** in Decompile opens the same benign fixture directly.

The fixture is intentionally unsigned and not installable. Its declared INTERNET permission teaches the difference between metadata and behavior; its code makes no network calls. It contains:

- `classes.dex`: `Training`, with arithmetic, a loop, a switch, exception handling, strings and a byte-array XOR transform.
- `classes2.dex`: `SecondDex`, whose `total` method calls `Training.sum` across the DEX boundary.
- Binary `AndroidManifest.xml`, a small resource table and a native x86-64 addition library.

Read the manifest, reconstruct `SecondDex`, follow its reference to `Training.sum`, and inspect a method's bytes. Write an evidence-backed note in Notebook, then prepare a findings inventory. Return to Training ground and **Check my evidence**. Save the lesson workspace or export a project to resume later. Imported milestones remain historical; imported Java or resource text alone does not count as a new observation.

Fixture sources and rebuild commands are in [fixtures/android](../fixtures/android/README.md).

## Limits and interpretation

| Input / operation | Bound |
| --- | --- |
| APK or other top-level input | 64 MiB |
| Archive inventory | 20,000 entries; at most 256 MiB declared expanded size |
| Selected member extraction | 32 MiB; CRC and actual output size checked |
| DEX files | 32 files; 32 MiB each; 64 MiB combined |
| Classes | 50,000 combined; 100 shown per class-search page |
| Member metadata display | First 2,000 methods/fields per class |
| Supporting class conversion | 64 classes and 16 MiB translated bytes per reconstruction |
| Reconstructed source | 2 MiB per class |
| Resource table results | 20,000 entries; at most 4,096 values per bag |
| Worker operation | 60 seconds; startup up to 120 seconds |

Limits bound work and output; they do not measure total browser memory. Large applications may exceed them on a modest device. Cancel terminates the worker. The original file stays open and a later operation starts a fresh worker.

Supported standard DEX versions are **035 and 037–040**. Compact/optimized DEX, DEX 041 containers, split-set merging and dynamically decrypted or downloaded classes need separate support. A resource-only split can still be inspected. Embedded or renamed DEX files can be opened explicitly as child investigations; they are not silently treated as standard root classes.

Neither Android framework JARs nor external dependencies are bundled. Missing or ambiguous class metadata is reported. This can affect types, casts, inheritance and recovered expressions. Obfuscation and difficult control flow can cause errors or incomplete source. A class that cannot translate fails explicitly; successful decompilation is not a proof of semantic equivalence.

APK signatures and publisher authenticity are **not verified**. CRC and DEX Adler-32 checks are integrity diagnostics, not trust decisions. Resource decoding does not apply framework defaults, overlays or device configuration selection; compact resource entries are labeled unsupported. No install/rebuild/signing, Android process emulation, ART debugging, dynamic loading, or network interaction is provided.

## Engine and format sources

- [dex2jar](https://github.com/pxb1988/dex2jar), pinned to `b5bda4fb4935ae8b3869b422454ae3b3896c7bc1`, Apache-2.0.
- [Vineflower browser port](https://github.com/katana-project/vf), `0.6.4-1.12.0`, MIT bridge and Apache-2.0 engine.
- [TeaVM](https://github.com/konsoletyper/teavm), `0.15.0-dev-6`, Apache-2.0; ASM `9.5`, BSD.
- [AOSP DEX format](https://source.android.com/docs/core/runtime/dex-format) and [Android resource structures](https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/include/androidfw/ResourceTypes.h).

Runtime hashes are in `vendor/android/manifest.json`. The port and rebuild instructions are in [android-source](../android-source/README.md). All required browser runtime assets ship locally and in the offline release.
