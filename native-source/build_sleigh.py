from pathlib import Path
import re, subprocess, concurrent.futures

root=Path(__file__).resolve().parent
src=root/'third_party/ghidra-decompiler'
build=root/'sleigh-build'; build.mkdir(exist_ok=True)
cmake=(src/'CMakeLists.txt').read_text()
groups={g:re.findall(r'\$\{DECOMP_SRC_DIR\}/([\w.]+)',re.search(r'set\('+g+r'\s+(.*?)\)',cmake,re.S).group(1)) for g in ['BASE_SOURCES','SLGH_SOURCES','SLEIGHC_SOURCES']}
def compile_file(n):
    out=build/(n+'.o')
    if not out.exists(): subprocess.run(['g++','-std=c++17','-O2','-DNDEBUG','-w','-c',str(src/n),'-I'+str(src),'-o',str(out)],check=True)
    return str(out)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(compile_file,[n for v in groups.values() for n in v]))
for g in ['BASE_SOURCES','SLGH_SOURCES']:
    subprocess.run(['ar','rcs',str(build/(g+'.a')),*[str(build/(n+'.o')) for n in groups[g]]],check=True)
subprocess.run(['g++',*[str(build/(n+'.o')) for n in groups['SLEIGHC_SOURCES']],str(build/'SLGH_SOURCES.a'),str(build/'BASE_SOURCES.a'),'-lz','-o',str(build/'sleighc')],check=True)
print(build/'sleighc')
