from pathlib import Path
import subprocess, concurrent.futures, shutil, json, hashlib
root=Path(__file__).resolve().parent
selected={
    'ARM':['ARM8_le','ARM8_be','ARM7_le','ARM7_be'],
    'AARCH64':['AARCH64','AARCH64BE'],
    'RISCV':['riscv.lp64d','riscv.ilp32d'],
    'MIPS':['mips32le','mips32be','mips64le','mips64be'],
}
def compile_spec(job):
    arch,base=job
    src=root/'ghidra-source'/arch/'data'/'languages'
    dest=root/'specs'/arch/'data'/'languages';dest.mkdir(parents=True,exist_ok=True)
    log=root/(base+'.build.log')
    with log.open('w') as f: subprocess.run([str(root/'sleigh-build'/'sleighc'),str(src/(base+'.slaspec')),str(dest/(base+'.sla'))],stdout=f,stderr=subprocess.STDOUT,check=True)
    return arch,base
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    for arch,base in pool.map(compile_spec,[(a,b) for a,v in selected.items() for b in v]): print(arch,base,flush=True)
for arch in selected:
    src=root/'ghidra-source'/arch/'data'/'languages';dest=root/'specs'/arch/'data'/'languages'
    for p in src.iterdir():
        if p.suffix in ['.ldefs','.cspec','.pspec']: shutil.copy2(p,dest/p.name)
manifest={'ghidraCommit':'09f14c92d3da6e5d5f6b7dea115409719db3cce1','compilerSourcePyreCommit':'835d7dd871304966165339d8cc7ae2deb0d00789','files':[]}
for p in sorted((root/'specs').rglob('*')):
    if p.is_file():
        b=p.read_bytes();manifest['files'].append({'path':str(p.relative_to(root/'specs')),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
(root/'spec-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('total',len(manifest['files']),sum(x['bytes'] for x in manifest['files']))
