import org.teavm.gradle.api.JSModuleType
plugins { java; id("org.teavm") version "0.15.0-dev-6" }
repositories { mavenCentral(); maven("https://teavm.org/maven/repository") }
dependencies { implementation("org.ow2.asm:asm-tree:9.5"); implementation("org.ow2.asm:asm-util:9.5"); implementation("org.ow2.asm:asm-commons:9.5") }
java.toolchain { languageVersion = JavaLanguageVersion.of(21) }
sourceSets.main { java.srcDirs("dex2jar/dex-reader-api/src/main/java", "dex2jar/dex-reader/src/main/java", "dex2jar/dex-ir/src/main/java", "dex2jar/dex-translator/src/main/java", "dex2jar/d2j-base-cmd/src/main/java") }
teavm { js { mainClass = "org.church.spectra.Main"; moduleType = JSModuleType.ES2015; obfuscated = false } }
