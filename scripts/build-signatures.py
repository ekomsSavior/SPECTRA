#!/usr/bin/env python3
"""Build exact, source-auditable reference candidates using the local GCC."""
from pathlib import Path
import subprocess,json,tempfile,hashlib
root=Path(__file__).resolve().parents[1]
source=root/'fixtures/library-reference/reference.c'
version=subprocess.check_output(['gcc','--version'],text=True).splitlines()[0]
entries=[]
with tempfile.TemporaryDirectory(prefix='spectra-signatures-') as tmp:
 for bits,mode in [(32,'x86'),(64,'x64')]:
  for optimization in ['-O1','-O2','-Os']:
   obj=Path(tmp)/'reference.o'
   flags=[f'-m{bits}',optimization,'-ffreestanding','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector','-fcf-protection=none','-fno-pic','-ffunction-sections','-c']
   subprocess.run(['gcc',*flags,str(source),'-o',str(obj)],check=True)
   for name in ['strlen','strcmp','memcmp','memcpy','memset']:
    out=Path(tmp)/'function.bin'
    subprocess.run(['objcopy','-O','binary','--only-section=.text.'+name,str(obj),str(out)],check=True)
    data=out.read_bytes()
    # Standalone reference functions must have no relocations.
    relocs=subprocess.check_output(['objdump','-r','-j','.text.'+name,str(obj)],text=True)
    if 'R_' in relocs:raise RuntimeError('Reference unexpectedly has relocations')
    if len(data)<16:continue
    item={'name':name,'mode':mode,'endian':'little','bytes':data.hex(),'source':f'Church MIT reference.c; {version}; {" ".join(flags)}; exact bytes, candidate semantics only'}
    if not any(x['mode']==mode and x['name']==name and x['bytes']==item['bytes'] for x in entries):entries.append(item)
pack={'schema':'spectra-signatures-v1','sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'note':'Exact Church reference implementation candidates; not a comprehensive libc signature database. Match does not prove library provenance. Import your own reviewed signatures for other builds.','signatures':entries}
(root/'fixtures/library-reference/signatures.json').write_text(json.dumps(pack,indent=2)+'\n')
print(len(entries),'reference signatures built')
