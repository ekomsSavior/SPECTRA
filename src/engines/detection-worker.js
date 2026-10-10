'use strict';
// Only trusted, fixed scanner commands enter this VM. Samples are data files.
importScripts('./libv86.js');
let started=false,vm=null;
const MAX_FILE=16*1024*1024,MAX_OUTPUT=2*1024*1024;
const status=text=>postMessage({type:'status',text});
const fail=e=>{try{vm?.destroy();}catch{}postMessage({type:'error',error:String(e.message||e).slice(0,1000)});close();};
async function asset(name,spec){
 const r=await fetch('./'+name);if(!r.ok)throw Error('Detection engine download failed ('+r.status+').');
 const b=await r.arrayBuffer();if(b.byteLength!==spec.bytes)throw Error('Detection engine size mismatch.');
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),x=>x.toString(16).padStart(2,'0')).join('');
 if(hash!==spec.sha256)throw Error('Detection engine hash mismatch.');return b;
}
onmessage=async e=>{
 if(started)return;started=true;const {buffer,heuristics,deep}=e.data||{};
 try{
  if(!(buffer instanceof ArrayBuffer)||buffer.byteLength<1||buffer.byteLength>MAX_FILE)throw Error('DiE scan limit: 1 byte to 16 MiB.');
  if(typeof heuristics!=='boolean'||typeof deep!=='boolean')throw Error('Invalid detection options.');
  status('Loading DiE 3.21 · about 20 MiB on first use…');
  const m=await fetch('./manifest.json').then(r=>{if(!r.ok)throw Error('Detection manifest unavailable.');return r.json();});
  const [bios,state,wasm]=await Promise.all(['seabios.bin','v86state.bin.zst','v86.wasm'].map(n=>asset(n,m.assets[n])));
  status('Starting the local scanner…');
  let phase='ready',output='';
  vm=new V86({memory_size:128*1024*1024,autostart:true,filesystem:{},net_device:false,disable_keyboard:true,disable_mouse:true,disable_speaker:true,bios:{buffer:bios},initial_state:{buffer:state},wasm_fn:async env=>(await WebAssembly.instantiate(wasm,env)).instance.exports});
  vm.add_listener('serial0-output-byte',byte=>{
   try{
    output+=String.fromCharCode(byte);if(output.length>MAX_OUTPUT)throw Error('DiE output exceeded 2 MiB.');
    if(phase==='ready'&&output.includes('\nSPECTRA_SCAN_READY\r\n')){phase='scan';output='';status('Scanning locally. Heuristics can take a minute or two…');vm.serial0_send('cd /die_build && ./run_diec.sh -bj'+(heuristics?'u':'')+(deep?'d':'')+' /mnt/sample.bin; rc=$?; printf "\\nSPECTRA_SCAN_DONE:%s\\n" "$rc"\n');}
    else if(phase==='scan'){
     const match=output.match(/\r?\nSPECTRA_SCAN_DONE:(\d+)\r?\n/);if(!match)return;phase='done';
     if(match[1]!=='0')throw Error('DiE scanner exited with status '+match[1]+'.');
     const raw=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(output.slice(0,match.index),c=>c.charCodeAt(0))).trim();JSON.parse(raw);
     postMessage({type:'result',raw,engine:{name:m.engine,version:m.version,browserRelease:m.browserRelease,stateSha256:m.assets['v86state.bin.zst'].sha256},options:{heuristics,deep}});vm.destroy();close();
    }
   }catch(err){fail(err);}
  });
  vm.add_listener('emulator-loaded',async()=>{try{await vm.create_file('sample.bin',new Uint8Array(buffer));vm.serial0_send("stty -echo; PS1=''; printf '\\nSPECTRA_SCAN_READY\\n'\n");}catch(err){fail(err);}});
 }catch(err){fail(err);}
};
