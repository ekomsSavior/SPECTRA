/* Conservative x86 constant tracing: no branches, calls, or unknown instructions executed. */
(function(root){
'use strict';
function recover(code){
 if(!code||!['x86','x64'].includes(code.mode))return {rows:[],note:'Stack recovery currently covers x86/x64 constant writes. Run supported code analysis first.'};
 const stackReg=code.mode==='x64'?'rsp':'esp',frameReg=code.mode==='x64'?'rbp':'ebp';
 const rows=[],seen=new Set(),jumpTargets=new Set((code.references||[]).filter(r=>r.kind==='branch').map(r=>r.to)),functionStarts=new Set((code.functions||[]).map(f=>f.address));
 let memory=new Map(),registers=new Map(),sp=0,bp=null,previous=null,steps=0,blocks=0,stopped=0,limited=false;
 const family=reg=>{const r=reg.toLowerCase();if(/^(?:r(?:ax|bx|cx|dx|si|di|8|9|1[0-5]))$/.test(r))return {name:r,width:64};if(/^(?:e(?:ax|bx|cx|dx|si|di))$/.test(r))return {name:'r'+r.slice(1),width:32};if(/^r(?:8|9|1[0-5])d$/.test(r))return {name:r.slice(0,-1),width:32};return null;};
 const imm=s=>/^-?(?:0x[0-9a-f]+|\d+)$/i.test(s)?(s.startsWith('-')?-BigInt(s.slice(1)):BigInt(s)):null;
 function read(s){const n=imm(s);if(n!==null)return {value:n,sources:[]};const reg=family(s),v=reg&&registers.get(reg.name);return v?{value:BigInt.asUintN(reg.width,v.value),sources:v.sources}:null;}
 function mem(s){const m=s.match(/^(byte|word|dword|qword) ptr \[(rsp|rbp|esp|ebp)(?: ([+-]) (0x[0-9a-f]+|\d+))?\]$/i);if(!m||![stackReg,frameReg].includes(m[2]))return null;const base=m[2]===frameReg?bp:sp;if(base===null)return null;const address=base+(m[3]==='-'?-1:1)*Number(m[4]||0),width=({byte:1,word:2,dword:4,qword:8})[m[1]];return Number.isSafeInteger(address)&&Math.abs(address)<=65536?{address,width}:null;}
 function flush(){if(!memory.size)return;const positions=[...memory.keys()].sort((a,b)=>a-b);for(let start=0;start<positions.length;){let end=start+1;while(end<positions.length&&positions[end]===positions[end-1]+1)end++;const cells=positions.slice(start,end).map(p=>memory.get(p)),bytes=Uint8Array.from(cells,c=>c.byte);for(const s of root.SpectraCore.extract(bytes,6,100).strings){if(s.encoding==='UTF-16BE')continue;const relevant=cells.slice(s.offset,s.offset+s.byteLength),sources=[...new Set(relevant.flatMap(c=>c.sources))].sort((a,b)=>a-b),origin=relevant[0];if(!sources.length)continue;const key=sources.join(',')+':'+s.text;if(seen.has(key))continue;if(rows.length>=2000){limited=true;return;}seen.add(key);rows.push({id:rows.length,method:'stack',text:s.text,encoding:s.encoding,sourceOffset:origin.offset,sourceLength:0,codeAddresses:sources,functionAddress:origin.functionAddress,stackOffset:positions[start]+s.offset,confidence:'constant-trace candidate',evidence:'Known constants written to adjacent stack bytes in one straight-line block. Reachability and later use are unverified.',tags:root.SpectraCore.tagsFor(s.text)});}start=end;}}
 function reset(){flush();memory=new Map();registers=new Map();sp=0;bp=null;steps=0;blocks++;}
 function write(m,v,i){if(!v){for(let n=0;n<m.width;n++)memory.delete(m.address+n);return;}if(memory.size+m.width>4096){reset();limited=true;return;}const sources=[...new Set([...v.sources,i.address])].slice(-128);for(let n=0;n<m.width;n++)memory.set(m.address+n,{byte:Number((BigInt.asUintN(m.width*8,v.value)>>BigInt(n*8))&255n),sources,offset:i.offset,functionAddress:i.functionAddress});}
 function readMem(m){let value=0n,sources=[];for(let n=0;n<m.width;n++){const c=memory.get(m.address+n);if(!c)return null;value|=BigInt(c.byte)<<BigInt(n*8);sources.push(...c.sources);}return {value,sources};}
 for(const i of (code.instructions||[]).slice(0,60000)){
  if(!previous||previous.address+previous.size!==i.address||previous.call||previous.jump||previous.stop||jumpTargets.has(i.address)||functionStarts.has(i.address)||steps>=256)reset();steps++;previous=i;
  if(i.call||i.jump||i.ret||i.stop){reset();continue;}
  const operands=i.operands.split(',').map(s=>s.trim()),[dst,src]=operands,mn=i.mnemonic;
  if(['nop','endbr64','endbr32','cmp','test'].includes(mn))continue;
  if(['push','pop'].includes(mn)){if(/^(?:ax|bx|cx|dx|si|di|sp|bp|r(?:8|9|1[0-5])w)$/.test(dst)||/^word ptr /.test(dst)){reset();stopped++;continue;}const width=code.mode==='x64'?8:4;if(mn==='push'){sp-=width;write({address:sp,width},read(dst),i);}else{const reg=family(dst);if(reg)registers.delete(reg.name);if(dst===frameReg)bp=null;else if(!reg){reset();stopped++;continue;}for(let n=0;n<width;n++)memory.delete(sp+n);sp+=width;}continue;}
  if(mn==='mov'&&dst===frameReg&&src===stackReg){bp=sp;continue;}
  if(['add','sub'].includes(mn)&&dst===stackReg&&imm(src)!==null){const amount=Number(imm(src));if(Math.abs(amount)>65536){reset();stopped++;continue;}sp+=(mn==='sub'?-amount:amount);continue;}
  const reg=family(dst),target=mem(dst);
  if(['mov','movabs'].includes(mn)){const value=read(src);if(reg){if(value)registers.set(reg.name,{value:BigInt.asUintN(reg.width,value.value),sources:[...value.sources,i.address].slice(-128)});else registers.delete(reg.name);continue;}if(target){if([...Array(target.width)].some((_,n)=>memory.has(target.address+n)))flush();write(target,value,i);continue;}}
  if(mn==='lea'&&reg){registers.delete(reg.name);continue;}
  if(['xor','add','sub','and','or','shl','shr','not'].includes(mn)&&(reg||target)){
   const left=reg?read(dst):readMem(target),right=mn==='not'?{value:0n,sources:[]}:read(src);let value;
   if(mn==='xor'&&dst===src&&reg)value=0n;
   else if(left&&right){const a=left.value,b=right.value,width=reg?reg.width:target.width*8;switch(mn){case 'xor':value=a^b;break;case 'add':value=a+b;break;case 'sub':value=a-b;break;case 'and':value=a&b;break;case 'or':value=a|b;break;case 'not':value=~a;break;case 'shl':value=a<<(b&BigInt(width===64?63:31));break;case 'shr':value=BigInt.asUintN(width,a)>>(b&BigInt(width===64?63:31));break;}}
   const result=value===undefined?null:{value,sources:[...(left?.sources||[]),...(right?.sources||[]),i.address].slice(-128)};
   if(reg){if(result)registers.set(reg.name,{...result,value:BigInt.asUintN(reg.width,result.value)});else registers.delete(reg.name);}else{flush();write(target,result,i);}continue;
  }
  // A missed write or stack adjustment must not leave stale bytes in the trace.
  reset();stopped++;
 }
 flush();return {rows,limited,blocks,stopped,note:'x86/x64 constant trace only. Resets at control-flow boundaries and unsupported instructions; no loops or API calls are emulated. Unsupported paths can hide strings.'};
}
root.SpectraStack={recover};if(typeof module!=='undefined')module.exports=root.SpectraStack;
})(globalThis);
