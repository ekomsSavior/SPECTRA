#!/usr/bin/env python3
from pathlib import Path
import zipfile
root=Path(__file__).resolve().parents[1];out=root/'dist/debugger-source.zip';out.parent.mkdir(exist_ok=True)
def include(p):
 parts=p.relative_to(root).parts
 return p.is_file() and parts[0] not in ['dist','work','releases','.git','.wrangler'] and not any(x in ['bin','obj','build','cache','ports','__pycache__'] or x.startswith('lab target ') for x in parts) and p.name!='release-verification.json'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p in sorted(root.rglob('*')):
  if include(p):z.write(p,'spectra/'+str(p.relative_to(root)))
 z.writestr('BUILDING.txt','SPECTRA 0.7 corresponding source\nSee spectra/README.md, NOTICE.md, docs/BUILDING-ENGINES.md and upstream/ archives.\nnode build.mjs builds the local app from included pinned assets.\nUnicorn wrapper/engine corresponding source and build scripts are included in spectra/upstream/unicorn-matching-source.tar.gz.\nModified Pyre/Ghidra source and matching hardware specifications are included.\n')
with zipfile.ZipFile(out) as z:assert z.testzip() is None
print(f'{out.name}: {out.stat().st_size} bytes')
