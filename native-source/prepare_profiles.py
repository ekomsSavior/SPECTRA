from pathlib import Path
import xml.etree.ElementTree as ET
import json,hashlib,shutil
root=Path(__file__).resolve().parent
specs=root/'specs'; curated=root/'bundle'/'specs'
selections={
 'ARM':['ARM:LE:32:v8','ARM:BE:32:v8','ARM:LE:32:v8T','ARM:BE:32:v8T','ARM:LE:32:Cortex','ARM:BE:32:Cortex'],
 'AARCH64':['AARCH64:LE:64:v8A','AARCH64:BE:64:v8A'],
 'RISCV':['RISCV:LE:32:default','RISCV:LE:64:default'],
 'MIPS':['MIPS:LE:32:default','MIPS:BE:32:default','MIPS:LE:64:default','MIPS:BE:64:default'],
}
profiles={};files=set()
for arch,ids in selections.items():
 folder=specs/arch/'data'/'languages'
 ldef=next(p for p in folder.glob('*.ldefs') if p.stem.lower()==('riscv' if arch=='RISCV' else arch.lower()))
 tree=ET.parse(ldef)
 for language in tree.getroot().findall('language'):
  lang=language.attrib['id']
  if lang not in ids:continue
  for compiler in language.findall('compiler'):
   if compiler.attrib['id'] not in ['default','gcc','windows','apcs']:continue
   names=[ldef.name,language.attrib['slafile'],language.attrib['processorspec'],compiler.attrib['spec']]
   paths=[str(Path(arch)/'data'/'languages'/name) for name in sorted(set(names))]
   profile=lang+':'+compiler.attrib['id']
   profiles[profile]={'directory':str(Path(arch)/'data'/'languages'),'files':paths,'instructionAlignment':2 if arch=='RISCV' or ':v8T' in lang or ':Cortex' in lang else 4,'bytes':sum((specs/p).stat().st_size for p in paths)}
   files.update(paths)
for name in sorted(files):
 dest=curated/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(specs/name,dest)
manifest={'specSource':{'project':'Ghidra','tag':'Ghidra_12.0.3_build','commit':'09f14c92d3da6e5d5f6b7dea115409719db3cce1'},'compilerSource':{'project':'Pyre vendored Ghidra SLEIGH compiler','commit':'835d7dd871304966165339d8cc7ae2deb0d00789'},'profiles':profiles,'files':[]}
for name in sorted(files):
 data=(specs/name).read_bytes();manifest['files'].append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
(root/'bundle'/'hardware-specs.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(len(profiles),'profiles',len(files),'files',sum(f['bytes'] for f in manifest['files']),'bytes')
