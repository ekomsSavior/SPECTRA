'use strict';
importScripts('./libv86.js','./system.js');
let vm=null,started=false,ready=false,checkpoint=null,serial='',flushTimer=null,queue=Promise.resolve(),imports=0,outputBudget=0,stopped=false;
const send=m=>postMessage(m),status=text=>send({type:'status',text}),terminalDecoder=new TextDecoder();
const terminalInput=text=>vm.serial0_send(Array.from(new TextEncoder().encode(text),b=>String.fromCharCode(b)).join(''));
function flush(){clearTimeout(flushTimer);flushTimer=null;if(serial){send({type:'serial',text:terminalDecoder.decode(Uint8Array.from(serial,c=>c.charCodeAt(0)),{stream:true})});serial='';}outputBudget=0;}
function die(error){if(stopped)return;stopped=true;try{vm?.destroy();}catch{}flush();send({type:'error',error:String(error?.message||error).slice(0,1000)});close();}
onunhandledrejection=e=>{e.preventDefault();die(e.reason);};
async function asset(name,spec){const r=await fetch('./'+name);if(!r.ok)throw Error('Linux engine download failed ('+r.status+').');const b=await r.arrayBuffer();if(b.byteLength!==spec.bytes)throw Error('Linux engine size mismatch.');const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),v=>v.toString(16).padStart(2,'0')).join('');if(hash!==spec.sha256)throw Error('Linux engine hash mismatch.');return b;}
async function start(){
 if(started)throw Error('This guest is already initialized.');started=true;status('Loading the local Linux baseline · about 20 MiB on first use…');
 const m=await fetch('./manifest.json').then(r=>{if(!r.ok)throw Error('Linux manifest unavailable.');return r.json();});
 const [bios,state,wasm]=await Promise.all(['seabios.bin','v86state.bin.zst','v86.wasm'].map(n=>asset(n,m.assets[n])));
 vm=new V86({memory_size:128*1024*1024,autostart:false,filesystem:{},net_device:false,disable_keyboard:true,disable_mouse:true,disable_speaker:true,bios:{buffer:bios},initial_state:{buffer:state},wasm_fn:async env=>(await WebAssembly.instantiate(wasm,env)).instance.exports});
 vm.add_listener('serial0-output-byte',b=>{if(stopped)return;serial+=String.fromCharCode(b);if(++outputBudget>65536)return die(Error('Guest console flood stopped. Reset the guest to continue.'));if(!flushTimer)flushTimer=setTimeout(flush,60);});
 vm.add_listener('emulator-loaded',async()=>{try{SpectraSystem.guardFS(vm.fs9p);ready=true;await vm.run();vm.serial0_send("stty -echo; PS1='spectra# '; export PS1; cd /tmp; printf '\\nSPECTRA Linux lab - i686 / 128 MiB / guest network disabled\\n'; uname -a\n");send({type:'ready',baseline:m.assets['v86state.bin.zst'].sha256});}catch(e){die(e);}});
}
async function action(m){
 if(m.type==='start')return start();
 if(!ready)throw Error('Start Linux and wait for the guest to be ready.');
 if(m.type==='input'){if(typeof m.text!=='string'||m.text.length>4096)throw Error('Console input limit: 4,096 characters.');terminalInput(m.text);}
 else if(m.type==='pause'){await vm.stop();send({type:'paused'});}
 else if(m.type==='resume'){await vm.run();send({type:'running'});}
 else if(m.type==='snapshot'){await vm.stop();const next=await vm.save_state();SpectraSystem.size(next.byteLength,SpectraSystem.STATE);checkpoint=next;send({type:'snapshot',bytes:next.byteLength});}
 else if(m.type==='restore'){if(!checkpoint)throw Error('Save a checkpoint first.');await vm.stop();await vm.restore_state(checkpoint);send({type:'restored'});}
 else if(m.type==='import'){if(!(m.buffer instanceof ArrayBuffer)||!m.buffer.byteLength)throw Error('Choose a nonempty file.');SpectraSystem.size(m.buffer.byteLength);const name='input-'+(++imports)+'.bin';await vm.create_file(name,new Uint8Array(m.buffer));send({type:'imported',path:'/mnt/'+name,bytes:m.buffer.byteLength});}
 else if(m.type==='files')send({type:'files',files:SpectraSystem.files(vm.fs9p)});
 else if(m.type==='read'){SpectraSystem.regular(vm.fs9p,m.path);const b=await vm.read_file(m.path);SpectraSystem.size(b.byteLength);send({type:'file',path:m.path,buffer:b.slice().buffer});}
 else throw Error('Unknown system lab action.');
}
onmessage=e=>{const m=e.data;queue=queue.then(()=>action(m)).catch(e=>{if(!ready)die(e);else send({type:'action-error',error:String(e.message||e).slice(0,1000),running:vm?.is_running()});});};
