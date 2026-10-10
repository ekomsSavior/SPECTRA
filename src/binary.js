/* File-backed address maps. Virtual addresses are never used as file offsets. */
(function(root){
'use strict';
function toOffset(r,va){for(const s of r.mappings||[])if(va>=s.address&&va-s.address<s.size)return s.offset+va-s.address;return null;}
function toVA(r,off){for(const s of r.mappings||[])if(off>=s.offset&&off-s.offset<s.size)return s.address+off-s.offset;return null;}
function enrich(r,b){
 const v=new DataView(b.buffer,b.byteOffset,b.byteLength), fits=(o,n=1)=>Number.isSafeInteger(o)&&Number.isSafeInteger(n)&&o>=0&&n>=0&&o<=b.length-n;
 let le=true;const u16=o=>v.getUint16(o,le),u32=o=>v.getUint32(o,le),u64=o=>{const n=v.getBigUint64(o,le);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('Address exceeds the supported exact integer range');return Number(n);};
 const str=(o,end=b.length)=>{let s='';for(let i=o;fits(i)&&i<end&&i<o+2048&&b[i];i++)s+=String.fromCharCode(b[i]);return s;};
 const warn=s=>{if(!r.warnings.includes(s))r.warnings.push(s);};
 r.mappings=[];r.symbols=[];r.seeds=[];r.endian='little';
 try{
 if(r.format.startsWith('PE')){
  for(const s of r.sections){s.address=r.imageBase+s.rva;const size=Math.max(0,Math.min(s.size,b.length-s.offset));if(size)r.mappings.push({...s,size});}
  const pe=u32(0x3c),opt=pe+24,wide=r.bits===64,dd=opt+(wide?112:96),optEnd=opt+u16(pe+20),nd=u32(opt+(wide?108:92));
  const dir=i=>nd>i&&dd+(i+1)*8<=optEnd?{va:r.imageBase+u32(dd+i*8),size:u32(dd+i*8+4)}:null;
  const imp=dir(1),base=imp?toOffset(r,imp.va):null;let index=0;
  if(base!==null)for(let d=0;d<Math.min(512,Math.floor(imp.size/20));d++){const o=base+d*20;if(!fits(o,20))break;const first=u32(o+16),name=u32(o+12),original=u32(o);if(!first&&!name&&!original)break;const thunk=toOffset(r,r.imageBase+(original||first));if(thunk===null)continue;for(let j=0;j<8192&&index<r.imports.length;j++){const t=thunk+j*(wide?8:4);if(!fits(t,wide?8:4)||(wide?v.getBigUint64(t,true)===0n:u32(t)===0))break;r.imports[index++].address=r.imageBase+first+j*(wide?8:4);}}
  const exp=dir(0),eo=exp?toOffset(r,exp.va):null;
  if(eo!==null&&fits(eo,40)){const count=Math.min(u32(eo+20),30000),nc=Math.min(u32(eo+24),30000),fn=toOffset(r,r.imageBase+u32(eo+28)),names=toOffset(r,r.imageBase+u32(eo+32)),ords=toOffset(r,r.imageBase+u32(eo+36)),labels=new Map();for(let i=0;i<nc&&names!==null&&ords!==null&&fits(names+i*4,4)&&fits(ords+i*2,2);i++){const no=toOffset(r,r.imageBase+u32(names+i*4));if(no!==null)labels.set(u16(ords+i*2),str(no));}for(let i=0;i<count&&fn!==null&&fits(fn+i*4,4);i++){const rv=u32(fn+i*4),address=r.imageBase+rv;if(!rv||address>=exp.va&&address<exp.va+exp.size)continue;r.symbols.push({name:labels.get(i)||'export_'+(u32(eo+16)+i),address,size:0,type:'function',source:'PE export'});}}
  const runtime=dir(3),ro=runtime?toOffset(r,runtime.va):null;
  if(r.architecture==='x86-64'&&ro!==null)for(let i=0;i<Math.min(30000,Math.floor(runtime.size/12));i++){const o=ro+i*12;if(!fits(o,12))break;const address=r.imageBase+u32(o),end=r.imageBase+u32(o+4);if(end>address&&toOffset(r,address)!==null)r.seeds.push({address,size:end-address,name:'sub_'+address.toString(16),source:'PE unwind table'});}
 }else if(r.format==='ELF'){
  r.warnings=r.warnings.filter(s=>!s.startsWith('This release identifies ELF'));
  if(![1,2].includes(b[4])||![1,2].includes(b[5]))throw Error('Invalid ELF class or byte order');
  le=b[5]===1;r.endian=le?'little':'big';const wide=b[4]===2,header=wide?64:52,word=wide?u64:u32;
  if(!fits(0,header))throw Error('Truncated ELF header');
  const machine=u16(18);r.bits=wide?64:32;r.architecture=({3:'x86',62:'x86-64',40:'ARM',183:'ARM64',8:'MIPS',20:'PowerPC',21:'PowerPC64',243:'RISC-V'})[machine]||'Machine '+machine;r.elfType=u16(16);r.elfFlags=u32(wide?48:36);r.entry=word(24);r.imageBase=0;
  if(r.architecture==='ARM'&&(r.entry&1)){r.architecture='ARM Thumb';r.entryThumb=true;r.entry--;}
  const ph=word(wide?32:28),sh=word(wide?40:32),phent=u16(wide?54:42),shent=u16(wide?58:46);let phnum=u16(wide?56:44),shnum=u16(wide?60:48),namesIndex=u16(wide?62:50);
  if(sh&&shent>=(wide?64:40)&&fits(sh,shent)){if(!shnum)shnum=word(sh+(wide?32:20));if(namesIndex===65535)namesIndex=u32(sh+(wide?40:24));if(phnum===65535)phnum=u32(sh+(wide?44:28));}
  if(shnum>4096||phnum>1024)warn('ELF table limit reached; structure may be incomplete.');
  if(phnum&&phent<(wide?56:32))throw Error('Invalid ELF program header size');
  for(let i=0;i<Math.min(phnum,1024);i++){const o=ph+i*phent;if(!fits(o,phent)){warn('Truncated ELF program headers.');break;}if(u32(o)!==1)continue;const offset=word(o+(wide?8:4)),address=word(o+(wide?16:8)),size=word(o+(wide?32:16)),flags=u32(o+(wide?4:24)),permissions=(flags&4?'R':'-')+(flags&2?'W':'-')+(flags&1?'X':'-');if(!fits(offset,size)){warn('ELF load segment extends beyond file bytes.');continue;}r.mappings.push({name:'LOAD '+i,offset,address,size,permissions});}
  if(shnum&&shent<(wide?64:40))throw Error('Invalid ELF section header size');
  const sections=[];
  for(let i=0;i<Math.min(shnum,4096);i++){const o=sh+i*shent;if(!fits(o,shent)){warn('Truncated ELF section table.');break;}const type=u32(o+4),flags=word(o+8),address=word(o+(wide?16:12)),offset=word(o+(wide?24:16)),rawSize=word(o+(wide?32:20)),size=type===8?0:rawSize,s={index:i,nameIndex:u32(o),type,flags,address,rva:address,offset,size,virtualSize:rawSize,link:u32(o+(wide?40:24)),entrySize:word(o+(wide?56:36)),permissions:(flags&2?'R':'-')+(flags&1?'W':'-')+(flags&4?'X':'-'),entropy:0};if(size&&!fits(offset,size)){warn('ELF section extends beyond file bytes.');s.size=0;}sections.push(s);}
  const ns=sections[namesIndex];for(const s of sections){s.name=ns&&s.nameIndex<ns.size?str(ns.offset+s.nameIndex,ns.offset+ns.size):'section_'+s.index;s.entropy=root.SpectraCore.entropy(b.subarray(s.offset,s.offset+s.size));}
  r.sections=sections.filter(s=>s.index>0);
  if(!r.mappings.length&&r.elfType!==1)r.mappings=sections.filter(s=>s.size&&(s.flags&2)).map(s=>({...s}));
  // Relocatable ELF has no unique linked VA map. Do not invent one.
  if(r.elfType===1)warn('Relocatable ELF: choose a raw code range to disassemble; linked addresses are not available.');
  if(!r.sections.length)r.sections=r.mappings.map(s=>({...s,rva:s.address,entropy:root.SpectraCore.entropy(b.subarray(s.offset,s.offset+s.size))}));
  const symtabs=new Map();let total=0;
  for(const s of sections.filter(s=>s.type===2||s.type===11)){const strings=sections[s.link],entry=wide?24:16;if(s.entrySize<entry||!strings)continue;const symbols=[];for(let i=0;i<Math.floor(s.size/s.entrySize)&&total<60000;i++,total++){const o=s.offset+i*s.entrySize,nameIndex=u32(o),info=b[o+(wide?4:12)],section=u16(o+(wide?6:14)),address=word(o+(wide?8:4)),size=word(o+(wide?16:8)),name=nameIndex<strings.size?str(strings.offset+nameIndex,strings.offset+strings.size):'';const symbol={name,thumb:r.architecture.startsWith('ARM')&&r.bits===32&&!!(address%2),address:r.architecture.startsWith('ARM')&&r.bits===32?address-address%2:address,size,type:(info&15)===2?'function':'symbol',source:s.name,section};symbols.push(symbol);if(name&&section&&r.elfType!==1)r.symbols.push(symbol);if(name&&!section)r.imports.push({name,library:'ELF dynamic / undefined',offset:o,tags:root.SpectraCore.tagsFor(name),symbolIndex:i});}symtabs.set(s.index,symbols);}
  if(total>=60000)warn('ELF symbol limit reached (60,000).');
  let relocationCount=0;for(const s of sections.filter(s=>s.type===4||s.type===9)){const syms=symtabs.get(s.link),min=wide?(s.type===4?24:16):(s.type===4?12:8);if(!syms||s.entrySize<min)continue;for(let i=0;i<Math.floor(s.size/s.entrySize)&&relocationCount++<60000;i++){const o=s.offset+i*s.entrySize,address=word(o),symbolIndex=wide?Number(v.getBigUint64(o+8,le)>>32n):u32(o+4)>>>8,symbol=syms[symbolIndex];if(symbol&&!symbol.section&&symbol.name&&toOffset(r,address)!==null)r.imports.push({name:symbol.name,library:s.name,address,offset:o,tags:root.SpectraCore.tagsFor(symbol.name)});}}
  if(relocationCount>=60000)warn('ELF relocation limit reached (60,000).');
 }
 if(r.entry!==null&&toOffset(r,r.entry)!==null)r.seeds.push({address:r.entry,name:'entry',size:0,source:'entry point',thumb:!!r.entryThumb});
 for(const s of r.symbols)if(s.type==='function'&&toOffset(r,s.address)!==null)r.seeds.push(s);
 }catch(e){warn('Deeper header inspection stopped: '+e.message+'. Available bytes are still inspectable.');}
 r.mappings=r.mappings.filter(s=>{const valid=Number.isSafeInteger(s.address)&&Number.isSafeInteger(s.address+s.size)&&fits(s.offset,s.size);if(!valid)warn('Address mapping exceeds supported bounds and was skipped.');return valid;});
 return r;
}
const api={enrich,toOffset,toVA};root.SpectraBinary=api;if(typeof module!=='undefined')module.exports=api;
})(globalThis);
