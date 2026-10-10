#!/usr/bin/env python3
from pathlib import Path
import subprocess,json,platform
root=Path(__file__).resolve().parents[1]
script=r'''const fs=require('fs'),core=require('./src/engine.js');require('./src/binary.js');const code=require('./src/code.js');(async()=>{const start=performance.now(),bytes=core.demo(),meta=core.analyze(bytes.buffer),analysisMs=performance.now()-start,cs=await require('./vendor/capstone/dist/capstone.js')({wasmBinary:fs.readFileSync('vendor/capstone/dist/capstone.wasm')}),cstart=performance.now(),r=code.analyze(cs,bytes,meta);console.log(JSON.stringify({scenario:'bundled benign demo; cold process, decoder initialized',sampleBytes:bytes.length,analysisMs,disassemblyMs:performance.now()-cstart,instructions:r.instructions.length,processPeakRssKiB:process.resourceUsage().maxRSS,node:process.version}));})();'''
r=subprocess.run(['node','-e',script],cwd=root,text=True,capture_output=True,check=True)
report={'system':platform.system()+' '+platform.machine(),'measurement':json.loads(r.stdout),'assets':{str(p.relative_to(root/'dist')):p.stat().st_size for p in (root/'dist').rglob('*') if p.is_file() and (p.name=='index.html' or p.name.startswith('unicorn_'))},'note':'Host reference measurement, not a low-end laptop certification or browser peak-memory measurement.'}
(root/'docs/performance-reference.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
