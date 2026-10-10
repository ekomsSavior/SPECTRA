# Engine build material

Normal SPECTRA builds use pinned local assets and require no engine rebuild. Hash inventories are in vendor. All shipping transformations and original integration sources are included. This documents the actual toolchain, without claiming reproducible hashes across different compilers/hosts.

## Ghidra / Pyre native WASM

`native-source/src` is the modified Pyre bridge; `native-source/third_party/ghidra-decompiler` is its pinned standalone Ghidra source. The added C exports are `spectra_set_prototype` and `spectra_add_type`. Original source is archived under upstream/pyre-835d7dd-source.tar.gz, with Pyre's MIT and Ghidra Apache notices. SPECTRA used Emscripten 3.1.56 commit 57b21b8fdcbe3ebb523178b79465254668eab408 from Microsoft.NET.Runtime.Emscripten.3.1.56.Sdk.linux-x64 10.0.12 and its matching Node pack, with a writable local cache and zlib 1.2.13. zlib source is archived too.

Activate that toolchain so `emcc`/`em++` work, then:

```bash
bash native-source/build.sh
cp native-source/dist/pyre_decompiler.mjs vendor/ghidra/
cp native-source/dist/pyre_decompiler.wasm vendor/ghidra/
```

The script uses -Os, C++17, exception support, exported memory/file APIs, and USE_ZLIB. A toolchain may download its port unless you prime EM_PORTS with the included matching zlib source. Review the exports and regenerate hashes/tests after any compiler or source change. Never silently replace the ABI of a published engine path.

Hardware specs are from Ghidra 12.0.3 commit 09f14c92d3da6e5d5f6b7dea115409719db3cce1. To rebuild with a C++17 compiler, Python3 and zlib development library:

```bash
tar -xzf upstream/hardware-spec-source.tar.gz -C native-source
python3 native-source/build_sleigh.py
python3 native-source/compile_specs.py
python3 native-source/prepare_profiles.py
```

The curated result lands in native-source/bundle. Copy its `specs` files into vendor/ghidra/specs after reviewing the profile manifest against vendor/ghidra/profiles.json. That shipped catalog combines these hardware profiles with the pinned x86 profiles. Small .ldefs catalogs for all five families are registered before creating Ghidra's first architecture; expensive .sla/.pspec/.cspec assets are fetched only for the chosen profile. Ghidra freezes its language catalog on first use.

## Managed WASM and harnesses

`managed-source/Spectra.Managed.csproj` pins ILSpy 11.1.0.9782. The release used .NET SDK 10.0.401, wasm-tools workload and browser runtime 10.0.12:

```bash
dotnet publish managed-source/Spectra.Managed.csproj -c Release -o managed-publish
```

Copy `managed-publish/wwwroot/_framework` to vendor/managed/_framework, removing stale hashes and redundant .gz/.br/.map outputs. Keep `vendor/managed/main.mjs`, which is the host wrapper. Generate a new manifest, run managed/dependency/harness checks and inspect worker loading in the browser. NuGet/workload installation needs network access; ordinary app builds do not. The source-to-runtime export is metadata analysis only; no target Assembly.Load occurs in the browser engine.

Harness source lives in harness-source and harness-source/net48. Modern fixtures execute only after --execute; Framework 4.8 builds use locked packages and Windows execution remains unverified. Include that limitation with generated projects.

## Unicorn and Capstone

The unmodified prebuilt engines come from pinned @alexaltea/unicorn-js 2.1.4 and @alexaltea/capstone-js 5.0.9 packages. Matching Unicorn source is archived in upstream/unicorn-matching-source.tar.gz, including engine submodule files and wrapper build scripts. Extract, activate an Emscripten/Python/CMake/C++ environment, and follow its BUILDING/build.py instructions (`python3 build.py x86`, `arm`, `aarch64`, `mips`, `riscv`). Preserve original patches and GPL notices. A successful source build is not evidence that arbitrary different toolchains reproduce the prebuilt package's hash.

The wrapper's Capstone detail offsets differ from the compiled native layout. SPECTRA reads only known instruction fields and asks the native group API, with additional tested RISC-V control-flow and hardware opcode checks. Do not reuse unverified structure offsets for operands/register metadata.
