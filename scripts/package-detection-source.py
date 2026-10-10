#!/usr/bin/env python3
"""Package the collected pinned source inputs; never downloads or executes them."""
from pathlib import Path
import argparse,zipfile,importlib.util,json,hashlib
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('inputs',type=Path);a=p.parse_args()
if not (a.inputs/'die_sourcecode_3.21.tar.gz').exists():raise SystemExit('Supply the complete pinned source input directory described in docs/DETECTION.md.')
out=root/'releases/spectra-v0.8-detection-source.zip';out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out,'w',zipfile.ZIP_STORED) as z:
 for f in sorted(a.inputs.rglob('*')):
  if f.is_file() and '.git' not in f.parts:z.write(f,'spectra-detection-source/'+str(f.relative_to(a.inputs)))
 z.write(root/'docs/DETECTION.md','spectra-detection-source/BUILDING.md')
 z.write(root/'vendor/die/manifest.json','spectra-detection-source/runtime-manifest.json')
 z.write(root/'vendor/die/LICENSES.txt','spectra-detection-source/LICENSES.txt')
 z.write(root/'src/engines/detection-worker.js','spectra-detection-source/spectra-worker.js')
with zipfile.ZipFile(out) as z:assert z.testzip() is None
spec=importlib.util.spec_from_file_location('downloads',root/'scripts/package-downloads.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);mod.package(out,'/detection-source.zip','die-source')
