#!/usr/bin/env python3
"""Split an existing release ZIP into static assets; emit fixed stream manifests."""
from pathlib import Path
import argparse,hashlib,json
root=Path(__file__).resolve().parents[1]
def package(source,route,prefix):
 folder=root/'dist/engines/v014/downloads';folder.mkdir(parents=True,exist_ok=True)
 for p in folder.glob(prefix+'-part-*.bin'):p.unlink()
 parts=[];whole=hashlib.sha256();size=0
 with source.open('rb') as f:
  while data:=f.read(16*1024*1024):
   name=f'{prefix}-part-{len(parts):02}.bin';(folder/name).write_bytes(data);whole.update(data);size+=len(data)
   parts.append({'path':'/engines/v014/downloads/'+name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 if len(parts)>40:raise ValueError('Archive exceeds the streaming request budget')
 manifest={'name':source.name,'bytes':size,'sha256':whole.hexdigest(),'parts':parts}
 p=root/'dist/download-archives.json';all=json.loads(p.read_text()) if p.exists() else {};all[route]=manifest;p.write_text(json.dumps(all,indent=2)+'\n')
 (root/'archive-manifests.mjs').write_text('// Generated release manifests.\nexport const ARCHIVES='+json.dumps(all,indent=2)+';\n')
 paths=sorted('/'+str(p.relative_to(root/'dist')) for p in (root/'dist/engines').rglob('*') if p.is_file());(root/'asset-paths.mjs').write_text('// Generated release assets.\nexport const ENGINE_PATHS=new Set('+json.dumps(paths,indent=2)+');\n')
 print(source.name,size,'bytes',len(parts),'parts');return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('route',choices=['/debugger-source.zip','/detection-source.zip']);p.add_argument('prefix',choices=['source','die-source']);a=p.parse_args();package(a.source,a.route,a.prefix)
