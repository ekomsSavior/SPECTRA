# Android training fixtures

These are original, benign Church fixtures under SPECTRA's MIT license. `AndroidTraining.apk` is an APK-shaped archive for static analysis, intentionally unsigned and not installable. No source here performs file, network, device or process I/O.

`Training.java` exercises constructors/fields, addition, loops, sparse switch cases, an arithmetic exception handler, branch-selected strings, XOR over byte arrays, modified UTF-8 including NUL and a supplementary character. `SecondDex.java` calls `Training.sum` across a DEX-file boundary. `native.c` provides a separate native-library handoff.

The XML/table generator follows AOSP's documented layouts. The declared INTERNET permission is a teaching example: it does not establish any actual traffic. The native library is a Linux x86-64 shared object with a simple C ABI, included for static Ghidra inspection; it is not an Android JNI integration test.

## Rebuild

Use JDK 21, R8/D8 `8.3.37`, a C compiler and Python 3. Run from this directory with `R8_JAR` pointing to the downloaded official R8 JAR:

```bash
mkdir -p build/main build/second build/dex-main build/dex-second
javac --release 8 -g -d build/main source/org/church/spectra/Training.java
java -cp "$R8_JAR" com.android.tools.r8.D8 --min-api 26 --output build/dex-main build/main/org/church/spectra/Training.class
javac --release 8 -g -cp build/main -d build/second secondary/org/church/spectra/SecondDex.java
java -cp "$R8_JAR" com.android.tools.r8.D8 --min-api 26 --output build/dex-second build/second/org/church/spectra/SecondDex.class
cp build/dex-main/classes.dex classes.dex
cp build/dex-second/classes.dex classes2.dex
cc -shared -fPIC -O0 -g -Wl,--build-id=none native.c -o libtraining.so
python3 package-fixture.py
```

The archive has fixed entry timestamps. Native compiler version, paths and debug metadata can change its hash; rebuild the application afterward so its lesson identity matches the exact included fixture. A changed fixture intentionally does not inherit the old fixture's lesson progress.
