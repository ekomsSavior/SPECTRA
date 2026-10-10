// Run the actual shipping worker in a separate Node worker for fixture checks.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {parentPort,workerData}=require('node:worker_threads');
const root=path.resolve(__dirname,'../vendor/die');
globalThis.importScripts=()=>{globalThis.V86=require(path.join(root,'libv86.js')).V86;};
globalThis.fetch=async url=>{const name=String(url).replace(/^\.\//,'');if(!/^[\w.-]+$/.test(name))throw Error('Unexpected engine request');const b=fs.readFileSync(path.join(root,name));return {ok:true,json:async()=>JSON.parse(b),arrayBuffer:async()=>Uint8Array.from(b).buffer};};
globalThis.postMessage=m=>parentPort.postMessage(m);globalThis.close=()=>setImmediate(()=>process.exit(0));globalThis.onmessage=null;
vm.runInThisContext(fs.readFileSync(path.resolve(__dirname,'../src/engines/detection-worker.js'),'utf8'));
globalThis.onmessage({data:workerData});
