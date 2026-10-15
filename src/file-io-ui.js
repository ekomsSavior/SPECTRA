// File destinations stay local. A completion message is emitted only after close succeeds.
const fileIO={prepared:new Map()};
async function clearPreparedExport(slot){const old=fileIO.prepared.get(slot);if(!old)return;fileIO.prepared.delete(slot);URL.revokeObjectURL(old.url);old.box.remove();await old.discard();}
function offerPreparedExport(file,name,target,slot){
 const url=URL.createObjectURL(file),box=document.createElement('div'),link=document.createElement('a'),discard=document.createElement('button');
 box.className='toolbar';link.className='button';link.href=url;link.download=name;link.textContent='Save completed file: '+name;discard.className='button';discard.textContent='Discard prepared file';discard.onclick=()=>clearPreparedExport(slot);
 box.append(link,discard);$(target).after(box);fileIO.prepared.set(slot,{url,box,discard:file.discard||(()=>{})});return box;
}
async function localSink(name,{choose=false,maxBytes=129*1024*1024}={}){
 if(choose&&!navigator.storage?.getDirectory&&typeof showSaveFilePicker==='function'){const handle=await showSaveFilePicker({suggestedName:name});return {sink:await handle.createWritable(),finish:async()=>{},discard:async()=>{},mode:'direct file stream'};}
 if(navigator.storage?.getDirectory){const root=await navigator.storage.getDirectory(),dir=await root.getDirectoryHandle('spectra-exports',{create:true}),key=crypto.randomUUID()+'.partial',handle=await dir.getFileHandle(key,{create:true}),sink=await handle.createWritable();return {sink,async finish(){return handle.getFile();},async discard(){await dir.removeEntry(key).catch(()=>{});},mode:'temporary local file stream'};}
 const cap=Math.min(maxBytes,16*1024*1024),parts=[];let total=0,finished=false;return {sink:{async write(b){if((total+=b.length)>cap)throw Error('This browser has no streaming file destination. Fallback export cap: 16 MiB. Reduce the selected evidence or recording budget.');parts.push(b.slice());},async close(){finished=true;},async abort(){parts.length=0;}},async finish(){if(!finished)throw Error('Export incomplete.');return new Blob(parts);},async discard(){parts.length=0;},mode:'bounded memory fallback (16 MiB cap)'};
}
async function stagedFile(source,name,{signal,maxBytes=129*1024*1024,onProgress}={}){const target=await localSink(name,{maxBytes});try{await SpectraStream.write(source,target.sink,{signal,maxBytes,onProgress});const file=await target.finish();return {file,discard:target.discard,mode:target.mode};}catch(e){await target.discard();throw e;}}
async function exportStream(source,name,{signal,onProgress,maxBytes=129*1024*1024,target='evidence-status'}={}){
 await clearPreparedExport(target);const destination=await localSink(name,{choose:true,maxBytes});const started=performance.now(),heapStart=performance.memory?.usedJSHeapSize;let heapPeak=heapStart??null;
 try{const result=await SpectraStream.write(source,destination.sink,{signal,maxBytes,onProgress:p=>{if(performance.memory)heapPeak=Math.max(heapPeak??0,performance.memory.usedJSHeapSize);onProgress?.({...p,mode:destination.mode});}}),file=await destination.finish();
 if(file){offerPreparedExport(file,name,target,target);fileIO.prepared.get(target).discard=destination.discard;}
 return {...result,saveRequired:!!file,mode:destination.mode,elapsedMs:Math.round(performance.now()-started),jsHeapStart:heapStart??null,jsHeapPeak:heapPeak,memoryNote:'JS heap is not total device memory; Blob, browser, WASM, and OS allocations are excluded.'};
 }catch(e){await destination.discard();throw e;}
}

$('export-clear').onclick=async()=>{try{for(const slot of [...fileIO.prepared.keys()])await clearPreparedExport(slot);if(navigator.storage?.getDirectory){const dir=await(await navigator.storage.getDirectory()).getDirectoryHandle('spectra-exports',{create:true});let count=0;for await(const [name,handle]of dir.entries()){if(++count>2048)break;if(handle.kind==='file'&&/^[a-f0-9-]+\.partial$/.test(name)){const file=await handle.getFile();if(Date.now()-file.lastModified>24*60*60*1000)await dir.removeEntry(name);}}}$('evidence-status').textContent='Prepared files discarded. Export leftovers older than 24 hours cleared; recordings and investigations were kept.';}catch(e){$('evidence-status').textContent='Could not clear temporary export files: '+e.message;}};
