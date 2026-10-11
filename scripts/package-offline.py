#!/usr/bin/env python3
from pathlib import Path
import zipfile
root=Path(__file__).resolve().parents[1];out=root/'releases/spectra-v0.8-guide-offline.zip';out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p in sorted((root/'dist').rglob('*')):
  if p.is_file() and not p.name.startswith('offline-part-') and p.name!='offline-manifest.json' and not p.name.startswith('die-source-part-'):z.write(p,'spectra-offline/dist/'+str(p.relative_to(root/'dist')))
 z.write(root/'scripts/serve.py','spectra-offline/scripts/serve.py');z.write(root/'LICENSE','spectra-offline/LICENSE');z.write(root/'NOTICE.md','spectra-offline/NOTICE.md')
 z.writestr('spectra-offline/START.txt','Run python3 scripts/serve.py --port 4173, then open http://127.0.0.1:4173/ . Keep the whole dist folder. All analysis assets are local. The optional native debugger companion runs separately on your own isolated lab machine. App source is available from the localhost /debugger-source.zip endpoint. The larger DiE operating-system source archive remains at https://spectra.churchofmalware.org/detection-source.zip.\n')
print(f'{out.name}: {out.stat().st_size} bytes')
# Static-host asset limits: split the download, reassemble and verify in-browser.
import hashlib,json
folder=root/'dist/engines/v08guide3/downloads';folder.mkdir(parents=True,exist_ok=True)
for old in folder.glob('offline-part-*.bin'):old.unlink()
parts=[]
with out.open('rb') as f:
 index=0
 while True:
  data=f.read(16*1024*1024)
  if not data:break
  name=f'offline-part-{index:02}.bin';(folder/name).write_bytes(data);parts.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});index+=1
(folder/'offline-manifest.json').write_text(json.dumps({'version':'0.8','name':out.name,'bytes':out.stat().st_size,'parts':parts},indent=2)+'\n')
paths=sorted('/'+str(p.relative_to(root/'dist')) for p in (root/'dist/engines').rglob('*') if p.is_file())
(root/'asset-paths.mjs').write_text('// Generated release assets.\nexport const ENGINE_PATHS=new Set('+json.dumps(paths,indent=2)+');\n')
