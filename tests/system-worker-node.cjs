const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{parentPort}=require('node:worker_threads');
const root=path.resolve(__dirname,'../vendor/die');
globalThis.importScripts=(...names)=>{for(const name of names){if(name==='./libv86.js')globalThis.V86=require(path.join(root,'libv86.js')).V86;else if(name==='./system.js')globalThis.SpectraSystem=require('../research/system-lab/system.js');else throw Error('Unexpected script');}};
globalThis.fetch=async url=>{const name=String(url).replace(/^\.\//,'');if(!/^[\w.-]+$/.test(name))throw Error('Unexpected engine request');const b=fs.readFileSync(path.join(root,name));return {ok:true,json:async()=>JSON.parse(b),arrayBuffer:async()=>Uint8Array.from(b).buffer};};
globalThis.postMessage=m=>parentPort.postMessage(m);globalThis.close=()=>setImmediate(()=>process.exit(0));globalThis.onmessage=null;globalThis.onunhandledrejection=null;
process.on('unhandledRejection',reason=>globalThis.onunhandledrejection({preventDefault(){},reason}));
vm.runInThisContext(fs.readFileSync(path.resolve(__dirname,'../research/system-lab/system-worker.js'),'utf8'));
parentPort.on('message',data=>globalThis.onmessage({data}));
