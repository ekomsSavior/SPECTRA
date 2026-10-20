# Browser DEX translation bridge

SPECTRA uses dex2jar's `DexFileReader` and `Dex2Asm` as static parsers/translators, compiled to JavaScript through TeaVM. It does not instantiate sample classes. Vineflower's separate browser port reconstructs Java from the generated class bytes.

The bridge overrides ASM's reflective superclass lookup with an explicit error. `COMPUTE_MAXS` is used, not reflective frame computation. There is no fallback that loads application classes or fabricates their inheritance. DEX reader and translation errors remain errors.

## Rebuild the DEX bridge

Requires JDK 21 and network access to obtain Gradle/TeaVM/ASM build dependencies. Ordinary SPECTRA users need none of these.

From this directory:

```bash
tar -xzf ../upstream/dex2jar-b5bda4f.tar.gz
./gradlew generateJavaScript --no-daemon
cp build/generated/teavm/js/spectra-dex.js ../vendor/android/dex.mjs
```

`JAVA_HOME` must identify a full JDK, including `javac`. The source archive is the pristine dex2jar commit recorded in `vendor/android/manifest.json`. This directory's own Java bridge is original SPECTRA code under the project MIT license. Upstream dex2jar remains Apache-2.0.

The pinned Vineflower browser runtime is `vf.runtime.js` from the npm package `@run-slicer/vf@0.6.4-1.12.0`, stored here as `vendor/android/vf.mjs`. The package integrity, upstream commit and runtime SHA-256 are recorded in the manifest. The matching bridge source is `upstream/vineflower-browser-97ce2aa.tar.gz`; follow its Gradle build to regenerate that engine. Its code retains MIT/Apache-2.0 licensing. SPECTRA uses the JavaScript backend to avoid requiring Wasm GC on older/mobile browsers.

After replacing either engine, update the runtime manifest, run `node build.mjs` from the app root, and run the Android parser, engine and worker tests. The benign fixtures include loops, switches, exception handling, object fields, Unicode and cross-DEX calls. Review reconstruction warnings and compare against the fixture sources; a successful engine startup alone is insufficient.

The browser adapter is `src/engines/android-session.mjs`; worker lifetime/bounds are in `src/engines/android-worker.mjs` and `src/android-ui.js`. Manifest/resource and metadata parsers are in `src/android.js`. ZIP indexing/extraction is in `src/archive.js`.
