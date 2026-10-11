/* Portable replay contains validated actions, never native CPU-context pointers. */
(function(root){
'use strict';
const VERSION='spectra-replay-v1',ENGINE='__DEBUG_ENGINE_ID__';
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const sha=async b=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',b)));
function stable(v){if(typeof v==='bigint')return v.toString();if(v instanceof Map)return [...v].map(([k,x])=>[stable(k),stable(x)]);if(v instanceof Uint8Array)return hex(v);if(Array.isArray(v))return v.map(stable);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]));return v;}
const canonical=v=>JSON.stringify(stable(v));
function validate(c,sample,engine=ENGINE){
 if(!c||c.schema!==VERSION||c.sha256!==sample||c.engine!==engine)throw Error('Checkpoint needs the same sample SHA-256 and emulator build.');
 if(!/^[0-9a-f]{64}$/.test(c.sha256)||!/^[0-9a-f]{64}$/.test(c.digest)||!c.options||!Array.isArray(c.actions)||c.actions.length>601)throw Error('Invalid checkpoint document.');
 if(c.label!==undefined&&(typeof c.label!=='string'||c.label.length>100))throw Error('Invalid checkpoint label.');
 let attempts=0,edits=0,total=0;
 for(const a of c.actions){
  if(a.kind==='steps'){if(!Number.isSafeInteger(a.count)||a.count<1)throw Error('Invalid replay step count.');attempts+=a.count;}
  else if(a.kind==='register'){edits++;if(typeof a.name!=='string'||a.name.length>8||!(/^(?:0x[0-9a-f]{1,16}|\d{1,20})$/i).test(a.value))throw Error('Invalid replay register edit.');}
  else if(a.kind==='patch'){edits++;if(!Number.isSafeInteger(a.address)||a.address<0||!Array.isArray(a.bytes)||a.bytes.length<1||a.bytes.length>4096||a.bytes.some(x=>!Number.isInteger(x)||x<0||x>255))throw Error('Invalid replay memory edit.');total+=a.bytes.length;}
  else throw Error('Unknown replay action.');
 }
 if(attempts>100001||edits>200||total>819200)throw Error('Checkpoint exceeds the experiment budget.');
 return c;
}
async function validateEvidence(c,sample,engine=ENGINE){
 validate(c,sample,engine);const s=c.summary;if(!s||typeof s!=='object'||!Number.isSafeInteger(s.steps)||s.steps<0||s.steps>100000||!Number.isSafeInteger(s.attempts)||s.attempts<0||s.attempts>100001||!s.registers||typeof s.registers!=='object'||Object.keys(s.registers).length>100||!Array.isArray(s.memory)||s.memory.length>4096)throw Error('Invalid checkpoint summary.');
 let last=-1;for(const r of s.memory){if(!Number.isSafeInteger(r.address)||r.address<=last||!Number.isInteger(r.size)||r.size<1||r.size>4096||!Number.isInteger(r.permissions)||r.permissions<0||r.permissions>7||!/^[0-9a-f]{64}$/.test(r.sha256))throw Error('Invalid checkpoint memory summary.');last=r.address;}
 if(await sha(new TextEncoder().encode(canonical(s)))!==c.digest)throw Error('Checkpoint summary does not match its recorded digest.');return c;
}
function registers(s){
 if(s.verificationRegisters)return s.verificationRegisters();
 const out={...s.regs()},read=(n,size)=>{const id=s.uc['X86_REG_'+n];if(id===undefined)throw Error('Verification register unavailable: '+n);return s.e.reg_read(id,size);};
 // Native widths from pinned Unicorn qemu/target/i386/unicorn.c; never guess buffer sizes.
 for(let i=0;i<(s.mode==='x64'?32:8);i++){const n=(s.mode==='x64'?'ZMM':'YMM')+i;out[n]=hex(read(n,s.mode==='x64'?64:32));}
 for(let i=0;i<8;i++)out['FP'+i]=hex(read('FP'+i,10));
 for(const n of ['FPSW','FPCW','FPTAG','FCS','FDS','FOP','CS','DS','ES','FS','GS','SS'])out[n]=hex(read(n,2));
 for(const n of ['FIP','FDP'])out[n]=hex(read(n,8));out.MXCSR=hex(read('MXCSR',4));out.FS_BASE=hex(read('FS_BASE',s.mode==='x64'?8:4));if(s.mode==='x64')out.GS_BASE=hex(read('GS_BASE',8));
 for(const n of ['GDTR','IDTR','LDTR','TR']){const b=read(n,24),v=new DataView(b.buffer,b.byteOffset,b.byteLength);out[n]={base:v.getBigUint64(8,true).toString(),limit:v.getUint32(16,true)};if(n==='LDTR'||n==='TR'){out[n].selector=v.getUint16(0,true);out[n].flags=v.getUint32(20,true);}}
 return out;
}
async function inspect(s){
 const memory=[];
 for(const r of s.e.mem_regions().sort((a,b)=>a.begin<b.begin?-1:1)){
  const start=Number(r.begin),end=Number(r.end)+1;
  for(let at=start;at<end;at+=4096){const size=Math.min(4096,end-at);memory.push({address:at,size,permissions:r.perms,sha256:await sha(s.e.mem_read(at,size))});}
 }
 let windows=null;
 if(s.windows){const w=s.windows;windows={};for(const n of ['info','extra','memoryBytes','lookup','modules','allocations','nextHeap','heapHandle','lastError','clock','tlsValues','nextHandle','fileBytes','output','exitCode','filename','command','entries','phase','eventCount','events'])windows[n]=stable(w[n]);
  windows.api=[...w.api].map(([at,a])=>[at,{library:a.library,name:a.name,definition:a.definition}]);
  windows.files=await Promise.all([...w.files].map(async([path,f])=>({path,size:f.bytes.length,sha256:await sha(f.bytes)})));
  windows.handles=[...w.handles].map(([handle,h])=>({handle,path:h.file.path,position:h.position,access:h.access}));
 }
 const summary={registers:registers(s),memory,windows,...(s.lab?{lab:s.lab.snapshot()}:{}),steps:s.steps,attempts:s.attempts,frames:s.frames,edits:s.edits,terminal:s.stopped?{status:s.status,reason:s.reason}:null};
 return {summary:stable(summary),digest:await sha(new TextEncoder().encode(canonical(summary)))};
}
async function capture(s,sha256,options,engine=ENGINE){const end=await inspect(s);return {schema:VERSION,engine,sha256,options:JSON.parse(JSON.stringify(options)),actions:JSON.parse(JSON.stringify(s.journal)),...end};}
function action(s,a){if(a.kind==='register')s.editRegister(a.name,a.value);else if(a.kind==='patch')s.patch(a.address,Uint8Array.from(a.bytes));else throw Error('Expected an edit.');}
async function replay(c,s,progress=async()=>{}){
 let n=0;for(const a of c.actions){if(a.kind==='steps'){for(let i=0;i<a.count;i++){if(s.stopped)throw Error('Replay stopped before the recorded actions ended.');s.step();if(++n%32===0)await progress(n);}}else action(s,a);}
 const end=await inspect(s);if(end.digest!==c.digest)throw Error('Replay verification failed. The previous session has been kept.');
 if(!s.stopped){s.status='paused';s.reason='Checkpoint replay verified. Ready for your next experiment.';}return end;
}
function compare(a,b){
 if(a.sha256!==b.sha256||a.engine!==b.engine)throw Error('Compare checkpoints from the same sample and emulator build.');
 const x=a.summary,y=b.summary,changes=[];
 for(const k of new Set([...Object.keys(x.registers),...Object.keys(y.registers)]))if(canonical(x.registers[k])!==canonical(y.registers[k]))changes.push({register:k,before:x.registers[k],after:y.registers[k]});
 const ma=new Map(x.memory.map(r=>[r.address,r])),mb=new Map(y.memory.map(r=>[r.address,r])),pages=[];
 for(const at of new Set([...ma.keys(),...mb.keys()]))if(canonical(ma.get(at))!==canonical(mb.get(at)))pages.push({address:at,before:ma.get(at)||null,after:mb.get(at)||null});
 return {fromSteps:x.steps,toSteps:y.steps,registers:changes,memoryPages:pages,labChanged:canonical(x.lab)!==canonical(y.lab),beforeLab:x.lab||null,afterLab:y.lab||null,windowsChanged:canonical(x.windows)!==canonical(y.windows),beforeFiles:x.windows?.files||[],afterFiles:y.windows?.files||[],beforeEvents:x.windows?.events||[],afterEvents:y.windows?.events||[],note:'Memory differences are 4 KiB pages, including mapping/permission changes. API traces retain the latest 500 events.'};
}
root.SpectraExperiments={VERSION,ENGINE,sha,stable,canonical,validate,validateEvidence,inspect,capture,replay,compare};if(typeof module!=='undefined')module.exports=root.SpectraExperiments;
})(globalThis);
