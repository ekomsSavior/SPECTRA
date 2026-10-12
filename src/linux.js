/* Bounded Linux userspace model: static ELF32/64 ET_EXEC and bounded ARM static PIE, no kernel or host I/O. */
(function(root){
'use strict';
const P=4096,STACK=0x70000000,SCRATCH=0x60000000,AREA=65536;
const check=(v,m)=>{if(!v)throw Error(m);},up=n=>Math.ceil(n/P)*P;
// Syscall IDs follow Linux v6.12 arch/{arm,x86}/ syscall tables and asm-generic/unistd.h.
const ABI={
 x64:{word:8,number:'RAX',result:'RAX',args:['RDI','RSI','RDX','R10','R8','R9'],machine:'x86_64',calls:[60,231,0,1,2,257,3,8,9,11,10,12,39,102,104,107,108,110,186,63,79,21,89,19,20]},
 aarch64:{word:8,number:'X8',result:'X0',args:['X0','X1','X2','X3','X4','X5'],machine:'aarch64',calls:[93,94,63,64,-1,56,57,62,222,215,226,214,172,174,176,175,177,173,178,160,17,-1,-1,65,66]},
 x86:{word:4,number:'EAX',result:'EAX',args:['EBX','ECX','EDX','ESI','EDI','EBP'],machine:'i686',calls:[1,252,3,4,5,295,6,19,192,91,125,45,20,199,200,201,202,64,224,122,183,33,85,145,146]},
 arm:{word:4,number:'R7',result:'R0',args:['R0','R1','R2','R3','R4','R5'],machine:'armv7l',calls:[1,248,3,4,5,322,6,19,192,91,125,45,20,199,200,201,202,64,224,122,183,33,85,145,146]}
};ABI.thumb=ABI.arm;
const CALLS=['exit','exit_group','read','write','open','openat','close','lseek','mmap','munmap','mprotect','brk','getpid','getuid','getgid','geteuid','getegid','getppid','gettid','uname','getcwd','access','readlink','readv','writev'];
const PIE_BASE=0x10000000;
function inspect(bytes){
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),fits=(a,n)=>Number.isSafeInteger(a)&&a>=0&&n>=0&&a<=bytes.length-n;
 check(fits(0,16)&&bytes[0]===127&&bytes[1]===69&&bytes[2]===76&&bytes[3]===70&&[1,2].includes(bytes[4])&&[1,2].includes(bytes[5])&&bytes[6]===1,'Not a supported ELF header.');
 const wide=bytes[4]===2,le=bytes[5]===1,word=wide?8:4;check(fits(0,wide?64:52),'Truncated ELF header.');
 const u16=a=>v.getUint16(a,le),u32=a=>v.getUint32(a,le),ptr=a=>{check(fits(a,word),'Truncated ELF value.');const n=wide?Number(v.getBigUint64(a,le)):u32(a);check(Number.isSafeInteger(n),'ELF address exceeds exact range.');return n;};
 const type=u16(16),machine=u16(18),entry=ptr(24),mode=machine===62&&wide?'x64':machine===183&&wide?'aarch64':machine===3&&!wide?'x86':machine===40&&!wide?(entry%2?'thumb':'arm'):null;
 const ph=ptr(wide?32:28),ent=u16(wide?54:42),count=u16(wide?56:44),segments=[],issues=[],needed=[];
 check(ent===(wide?56:32)&&count>0&&count<=128&&fits(ph,ent*count),'Invalid ELF program header table.');
 for(let j=0;j<count;j++){const at=ph+j*ent;segments.push({type:u32(at),flags:u32(at+(wide?4:24)),offset:ptr(at+(wide?8:4)),address:ptr(at+(wide?16:8)),fileSize:ptr(at+(wide?32:16)),size:ptr(at+(wide?40:20)),align:ptr(at+(wide?48:28)),index:j});}
 const string=(at,limit)=>{check(fits(at,limit)&&limit<=4096,'Invalid ELF dependency string.');const n=bytes.subarray(at,at+limit).indexOf(0);check(n>=0,'Unterminated ELF dependency string.');return new TextDecoder().decode(bytes.subarray(at,at+n));};
 let interpreter=null;const interp=segments.find(r=>r.type===3);if(interp)interpreter=string(interp.offset,interp.fileSize);
 const dynamicSegments=segments.filter(r=>r.type===2);check(dynamicSegments.length<=1,'Multiple ELF dynamic tables are unsupported.');const dynamic=dynamicSegments[0],entries=[];if(dynamic){check(fits(dynamic.offset,dynamic.fileSize)&&dynamic.fileSize<=65536&&dynamic.fileSize%(word*2)===0,'Invalid ELF dynamic table.');let ended=false;for(let at=dynamic.offset;at+word*2<=dynamic.offset+dynamic.fileSize;at+=word*2){const tag=ptr(at),value=ptr(at+word);if(!tag){ended=true;break;}entries.push({tag,value});}check(ended,'Unterminated ELF dynamic table.');const table=entries.find(e=>e.tag===5),size=entries.find(e=>e.tag===10);for(const e of entries.filter(e=>e.tag===1)){check(needed.length<128&&table&&size&&e.value<size.value,'Invalid ELF dependency table.');const address=table.value+e.value,r=segments.find(r=>r.type===1&&address>=r.address&&address<r.address+r.fileSize);check(r,'ELF dependency string is not file-backed.');needed.push(string(r.offset+address-r.address,Math.min(4096,size.value-e.value,r.fileSize-(address-r.address))));}}
 if(![0,3].includes(bytes[7]))issues.push('ELF OS ABI '+bytes[7]+' is not supported by the Linux model.');
 if(!mode)issues.push('No Linux process profile for ELF machine '+machine+' / '+word*8+' bits.');
 if(!le)issues.push('Linux process loading currently requires little endian. Use a bare routine for a supported big-endian CPU.');
 const armPie=type===3&&machine===40&&!wide&&le;
 if(type!==2&&!armPie)issues.push('This Linux loader supports static ET_EXEC and little-endian ARM32/Thumb static PIE only.');
 if(machine===40&&!wide&&(u32(36)>>>24)!==5)issues.push('ARM Linux process loading requires EABI5; legacy OABI is not modeled.');
 if(interpreter)issues.push('Missing dynamic interpreter: '+interpreter+'. Loading a dependency as a virtual file does not supply a linker.');
 if(needed.length)issues.push('Missing shared libraries: '+needed.join(', ')+'. Native dependency linking is not modeled.');
 if(dynamic&&!armPie)issues.push('Dynamic ELF linking/relocations are not modeled for this executable profile.');
 if(segments.some(r=>r.type===7))issues.push('ELF thread-local storage (PT_TLS) is not initialized by this profile.');
 const info={type,armPie,mode,machine,word,entry,start:machine===40?entry-entry%2:entry,entries,dynamic,relocations:[],endian:le?'little':'big',ph,ent,count,segments,interpreter,needed,issues};
 if(armPie)try{info.relocations=armRelocations(bytes,info);}catch(e){issues.push(e.message);}
 return info;
}
// Only local REL relative relocations are admitted. No symbol resolver or native DLLs.
function armRelocations(bytes,info){
 const {segments,entries,dynamic}=info,v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),loads=segments.filter(r=>r.type===1),tags=new Map();
 for(const r of loads)check(r.size>=r.fileSize&&r.offset<=bytes.length-r.fileSize&&r.address+r.size<=0x100000000,'Invalid ARM PIE load segment.');
 const file=(va,n)=>{const r=loads.find(r=>va>=r.address&&n<=r.fileSize-(va-r.address));check(r,'ARM PIE table is not entirely file-backed.');return r.offset+va-r.address;};
 if(dynamic)check(file(dynamic.address,dynamic.fileSize)===dynamic.offset,'Dynamic table address does not match its file mapping.');
 for(const e of entries){if(e.tag===1)continue;check(!tags.has(e.tag),'Duplicate ELF dynamic tag '+e.tag+'.');tags.set(e.tag,e.value);}
 for(const tag of [7,8,9,35,36,37,2,20,23])check(!tags.get(tag),'ARM PIE supports DT_REL relative relocations only; RELA, RELR and PLT tables need another loader.');
 check(!tags.has(22)&&!((tags.get(30)||0)&4),'ARM PIE text relocations are unsupported.');
 const size=tags.get(18)||0,address=tags.get(17),entrySize=tags.get(19);
 check(size%8===0&&size<=8192*8,'ARM PIE REL table limit: 8,192 complete records.');
 check(entrySize===undefined&&!size||entrySize===8,'ARM PIE DT_RELENT must be 8.');
 check(!size||address!==undefined,'ARM PIE is missing DT_REL.');
 if(!size){check(!tags.get(0x6ffffffa),'RELCOUNT exceeds the empty relocation table.');return [];}
 const at=file(address,size),out=[],targets=new Set(),count=tags.get(0x6ffffffa)||0;check(count<=size/8,'RELCOUNT exceeds the relocation table.');
 for(let j=0;j<size/8;j++){
  const target=v.getUint32(at+j*8,true),id=v.getUint32(at+j*8+4,true),type=id&255,symbol=id>>>8;
  if(j<count)check(type===23&&symbol===0,'RELCOUNT includes a non-relative relocation.');
  if(type===0)continue;
  check(type===23&&symbol===0,'Unsupported ARM relocation '+type+' / symbol '+symbol+'. Only R_ARM_RELATIVE with no symbol is supported.');
  const r=loads.find(r=>target>=r.address&&4<=r.size-(target-r.address));
  check(r&&(r.flags&2)&&!(r.flags&1)&&target%4===0,'ARM relocation target must be aligned writable non-executable image data.');
  check(!targets.has(target),'Duplicate ARM relocation target.');targets.add(target);
  check(target+4<=address||target>=address+size,'ARM relocation may not rewrite its own table.');
  if(dynamic)check(target+4<=dynamic.address||target>=dynamic.address+dynamic.fileSize,'ARM relocation may not rewrite the dynamic table.');
  let addend=0;for(let k=0;k<4;k++)if(target-r.address+k<r.fileSize)addend+=(bytes[r.offset+target-r.address+k]||0)*2**(8*k);
  out.push({target,type:23,addend});
 }
 return out;
}
function loadBias(info,value){
 if(!info.armPie){check(value===undefined||value===0,'Custom Linux load bias is supported only for ARM static PIE.');return 0;}
 const bias=value===undefined?PIE_BASE:Number(value),align=Math.max(P,...info.segments.filter(r=>r.type===1).map(r=>r.align||1));
 check(Number.isSafeInteger(bias)&&bias>=P&&bias<0x40000000&&bias%align===0,'ARM PIE load bias must respect segment alignment, be nonzero, and stay below 0x40000000.');return bias;
}
function prepare(bytes,meta,options){
 check(!options.raw,'Linux process mode requires a complete static ELF image.');const info=inspect(bytes),{mode,word,ph,ent,count}=info;
 const bias=loadBias(info,options.loadBase),entry=info.entry+bias,requested=options.start===undefined?info.start+bias:Number(options.start),start=info.machine===40?requested-requested%2:requested,owner=options.linuxRelocations||'program';
 check(['program','loader'].includes(owner),'Unknown Linux relocation owner.');
 check(owner==='program'||info.armPie,'Loader-owned relocations require ARM static PIE.');
 check(!info.issues.length,info.issues.join(' '));check(mode===options.mode,'CPU mismatch: this ELF needs '+mode+', selected '+options.mode+'.');
 check(!options.endian||['auto','little'].includes(options.endian),'Linux model requires little endian.');
 check(owner==='loader'?start!==info.start+bias&&start!==entry:[info.start+bias,entry].includes(start),owner==='loader'?'Loader-owned relocations require an alternate entry; do not rerun self-relocating startup.':'Linux startup begins at the relocated ELF entry. Use an alternate entry only with explicit loader-owned relocations.');
 const regions=[],pages=new Map(),hardware=['arm','thumb','aarch64'].includes(mode),reserve=AREA*2+(hardware?P:0);
 for(const r of info.segments){if(r.type!==1)continue;const {flags,offset,fileSize,size,align}=r,address=r.address+bias;
  check(size>=fileSize&&offset<=bytes.length-fileSize&&address>=P&&Number.isSafeInteger(address+size)&&address+size<=(word===4?0x100000000:0x800000000000),'Invalid ELF load segment.');if(!size)continue;
  check(size<=16*1024*1024&&(!align||align===1||(Number.isInteger(Math.log2(align))&&address%align===offset%align)),'Invalid ELF segment size/alignment.');check(!(flags&~7),'Unsupported ELF segment flags.');
  for(const [a,n] of [[STACK,AREA],[SCRATCH,AREA],[0x50000000,AREA],[0x40000000,0x02000000]])check(address+size<=a||address>=a+n,'ELF overlaps reserved session memory.');
  check(!regions.some(r=>address<r.address+r.size&&address+size>r.address),'Overlapping ELF segments are unsupported.');
  const perms=(flags&4?1:0)|(flags&2?2:0)|(flags&1?4:0);regions.push({name:'PT_LOAD '+r.index,address,offset,size,fileSize,permissions:(perms&1?'R':'-')+(perms&2?'W':'-')+(perms&4?'X':'-')});
  for(let a=Math.floor(address/P)*P;a<up(address+size);a+=P){if(!pages.has(a))check((pages.size+1)*P+reserve<=16*1024*1024,'Linux image exceeds 16 MiB mapped-memory budget.');pages.set(a,(pages.get(a)||0)|perms);}
 }
 check(!['arm','thumb','aarch64'].includes(mode)||start%(mode==='thumb'?2:4)===0,'ELF entry is misaligned for the CPU instruction mode.');
 check(regions.length&&regions.some(r=>r.permissions.includes('X')&&start>=r.address&&start<r.address+r.fileSize),'ELF entry is not in executable file bytes.');
 const mapped=[];for(const [address,perms]of [...pages].sort((a,b)=>a[0]-b[0])){const last=mapped.at(-1);if(last&&last.address+last.size===address&&last.perms===perms)last.size+=P;else mapped.push({address,size:P,perms});}
 const pr=regions.find(r=>ph>=r.offset&&ph+ent*count<=r.offset+r.fileSize);check(pr,'Program headers must be present in a load segment for Linux startup.');
 return {environment:'linux',mode,start,endian:'little',regions,mapped,memoryBytes:pages.size*P+reserve,stack:STACK,scratch:SCRATCH,areaSize:AREA,returnBoundary:hardware?0x50000000:0,linux:{word,entry,linkedEntry:info.entry,pie:info.armPie,bias,relocationOwner:owner,relocations:info.relocations.map(r=>({...r,address:r.target+bias,value:(r.addend+bias)>>>0})),phdr:pr.address+ph-pr.offset,phnum:count,phent:ent},scope:(info.armPie?'Static PIE ':'Static ')+mode+' Linux userspace model. Supported syscalls only; no kernel, dependency linker, PT_TLS layout, threads, signals or live network.'};
}
function relocate(session){
 const l=session.plan.linux;if(!l||l.relocationOwner!=='loader')return;
 for(const r of l.relocations){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,r.value,true);session.e.mem_write(r.address,b);}
}
class Environment{
 constructor(s,recipe){
  this.s=s;this.lab=s.lab;this.tls=0;this.clearTid=0;if(['arm','thumb'].includes(s.mode))s.writeReg('CPSR',(s.readReg('CPSR')&32n)|16n);this.files=new Map(recipe.files.map(f=>{check(f.path.startsWith('/')&&!f.path.split('/').some(x=>x==='..'),'Linux virtual files need absolute paths without ..');return [f.path,{path:f.path,bytes:root.SpectraLab.bytes(f.hex)}];}));this.fds=new Map();this.closedOutput=[];this.nextFd=3;this.output='';this.stdout=[];this.stderr=[];this.outputBytes=[];this.exitCode=null;this.heap=0x40000000;this.brk=0x41000000;this.brkEnd=this.brk;this.allocations=[];
  const input={path:'<stdin>',bytes:root.SpectraLab.bytes(recipe.stdin||'')};this.fds.set(0,{file:input,position:0,flags:0});
  let top=STACK+AREA;const putText=t=>{const b=new TextEncoder().encode(t+'\0');top-=b.length;check(top>STACK+8192,'Linux startup strings exceed stack budget.');s.e.mem_write(top,b);return top;};
  const argv=(recipe.argv.length?recipe.argv:['sample']).map(putText),env=recipe.env.map(putText),exec=argv[0];top-=16;const random=top;s.e.mem_write(random,Uint8Array.from({length:16},(_,i)=>i+1));
  const l=s.plan.linux,word=l.word,aux=[3,l.phdr,4,l.phent,5,l.phnum,6,P,7,0,9,l.entry,11,1000,12,1000,13,1000,14,1000,16,(['arm','thumb'].includes(s.mode)?0x8000:0),23,0,25,random,31,exec,0,0];
  const words=[argv.length,...argv,0,...env,0,...aux],sp=Math.floor((top-words.length*word)/16)*16;check(sp>=STACK,'Linux startup stack overflow.');
  words.forEach((n,i)=>this.lab.put(sp+i*word,BigInt(n),word));s.writeReg(s.sp,BigInt(sp));this.lab.event('linux-loader',{bias:l.bias,entry:l.entry,relocationOwner:l.relocationOwner,relativeRelocations:l.relocations.length,applied:l.relocationOwner==='loader'?l.relocations.length:0});this.lab.event('linux-startup',{argv:recipe.argv.length?recipe.argv:['sample'],env:recipe.env,random:'deterministic 01..10 bytes; analyst model',scope:s.plan.scope});
 }
 handlesTls(i){
  if(!['arm','thumb'].includes(this.s.mode)||!i||i.mnemonic!=='mrc'||this.s.liveThumb()&&(this.s.readReg('CPSR')&0x0600fc00n))return false;
  // Narrow TPIDRURO read only. No general privileged coprocessor emulation.
  return /^p15, #?0, (r(?:[0-9]|1[0-2])|sb|sl|fp|ip|lr), c13, c0, #?3$/.test(i.operands);
 }
 readTls(i){
  const match=i.operands.match(/^p15, #?0, (r(?:[0-9]|1[0-2])|sb|sl|fp|ip|lr), c13, c0, #?3$/);check(match,'Unsupported TLS instruction.');
  const reg=({sb:'R9',sl:'R10',fp:'R11',ip:'R12'})[match[1]]||match[1].toUpperCase();this.s.writeReg(reg,BigInt(this.tls));this.s.writeReg(this.s.ip,BigInt(i.address+i.size));this.lab.event('linux-tls-read',{address:i.address,register:reg,value:this.tls,behavior:'modeled single-thread TPIDRURO'});
 }
 fixedMap(address,size,perms){
  check(address>=P&&address%P===0&&address+size<=0x50000000,'MAP_FIXED requires page-aligned memory below the session boundary.');
  const overlaps=this.s.e.mem_regions().filter(r=>address<=Number(r.end)&&address+size>Number(r.begin));
  if(overlaps.length){
   const old=this.lab.extra.find(r=>r.name==='Linux brk'&&address>=r.address&&address+size<=r.address+r.size);
   check(old&&overlaps.every(r=>Number(r.begin)>=old.address&&Number(r.end)<old.address+old.size),'MAP_FIXED may replace only a contained brk range; image, stack and other mappings are protected.');
   this.s.e.mem_unmap(address,size);this.lab.extra=this.lab.extra.filter(r=>r!==old);
   if(old.address<address)this.lab.extra.push({...old,size:address-old.address});
   if(address+size<old.address+old.size)this.lab.extra.push({...old,address:address+size,size:old.address+old.size-address-size});
  }
  this.lab.map(address,size,perms,'Linux mmap');this.allocations.push({address,size,perms});return address;
 }
 protect(address,size,perms){
  check(Number.isSafeInteger(address)&&address%P===0&&Number.isSafeInteger(size)&&size>0&&size<=16*1024*1024&&address+size<=(this.s.word===4?0x100000000:0x800000000000)&&[0,1,2,3,4,5,6,7].includes(perms),'Invalid mprotect range or permissions.');
  const image=this.s.plan.mapped,alloc=this.allocations.find(r=>r.address===address&&r.size===size);
  if(alloc){this.s.e.mem_protect(address,size,perms);alloc.perms=perms;this.lab.extra.find(x=>x.address===address).perms=perms;return;}
  let cursor=address;for(const r of [...image].sort((a,b)=>a.address-b.address)){if(r.address>cursor)break;if(r.address<=cursor&&r.address+r.size>cursor)cursor=Math.min(address+size,r.address+r.size);if(cursor===address+size)break;}
  check(cursor===address+size,'mprotect supports image pages or one complete mmap allocation only.');
  const split=[];for(const r of image){const lo=Math.max(address,r.address),hi=Math.min(address+size,r.address+r.size);if(lo>=hi){split.push(r);continue;}if(r.address<lo)split.push({...r,size:lo-r.address});split.push({...r,address:lo,size:hi-lo,perms});if(hi<r.address+r.size)split.push({...r,address:hi,size:r.address+r.size-hi});}
  check(split.length<=4096,'mprotect mapping limit reached.');this.s.e.mem_protect(address,size,perms);this.s.plan.mapped=split;
 }
 path(at){let text='';for(let i=0;i<4096;i++){const b=this.lab.read(at+i,1)[0];if(!b){check(text.startsWith('/')&&!text.split('/').some(x=>x==='..'),'Only absolute virtual paths without .. are supported.');return text;}text+=String.fromCharCode(b);}throw Error('Virtual pathname exceeds 4096 bytes.');}
 snapshot(){return {tls:this.tls,clearTid:this.clearTid,output:this.output,closedOutput:this.closedOutput,stdoutHex:root.SpectraLab.hexBytes(this.stdout),stderrHex:root.SpectraLab.hexBytes(this.stderr),outputHex:root.SpectraLab.hexBytes(this.outputBytes),exitCode:this.exitCode,brk:this.brk,brkEnd:this.brkEnd,nextFd:this.nextFd,heap:this.heap,allocations:this.allocations,files:[...this.files].map(([path,f])=>({path,hex:root.SpectraLab.hexBytes(f.bytes)})),fds:[...this.fds].map(([fd,h])=>({fd,path:h.file.path,position:h.position,flags:h.flags})),stdin:root.SpectraLab.hexBytes(this.fds.get(0)?.file.bytes||[])};}
 syscall(i){
  const s=this.s,abi=ABI[s.mode],number=Number(s.readReg(abi.number)),call=(['arm','thumb'].includes(s.mode)?({983045:'set_tls',983046:'get_tls',256:'set_tid_address',403:'clock_gettime64'})[number]:null)||CALLS[abi.calls.indexOf(number)],a=abi.args.map(n=>s.readReg(n)),n=a.map(x=>Number(BigInt.asIntN(abi.word*8,x))),id=(x,y)=>call===CALLS[ABI.x64.calls.indexOf(x)];let result=0n,detail='';
  try{
  if(['arm','thumb','aarch64'].includes(s.mode))check(/^#?(?:0x)?0$/.test(i.operands.trim()),'Only svc #0 is modeled; ARM OABI calls are unsupported.');
  const count=k=>{check(Number.isSafeInteger(n[k])&&n[k]>=0&&n[k]<=65536,'Syscall byte count cap: 65,536.');return n[k];},err=e=>{result=BigInt(-e);};
  if(id(60,93)||id(231,94)){if(this.clearTid)this.lab.write(this.clearTid,new Uint8Array(4),'linux-clear-tid');this.exitCode=Number(a[0]&255n);detail='modeled process exit; no host process affected';}
  else if(call==='set_tls'){const at=Number(a[0]);check(at===0||s.region(at,1,1),'set_tls needs a readable modeled thread-pointer address or zero.');this.tls=at;detail='Single emulated thread pointer; no PT_TLS layout or threads created.';}
  else if(call==='get_tls'){result=BigInt(this.tls);detail='Single emulated thread pointer.';}
  else if(call==='set_tid_address'){const at=Number(a[0]);check(at===0||s.region(at,4,2)&&!s.region(at,4,4),'set_tid_address needs writable modeled data or zero.');this.clearTid=at;result=1337n;detail='Recorded clear-child-tid address for the single modeled thread.';}
  else if(id(0,63)){
   const h=this.fds.get(n[0]);if(!h||h.flags===1)err(9);else{const size=count(2),b=h.file.bytes.slice(h.position,h.position+size);this.lab.write(n[1],b,'linux-read');h.position+=b.length;result=BigInt(b.length);detail=h.file.path;}
  }else if(id(1,64)){
   const std=[1,2].includes(n[0]),h=this.fds.get(n[0]);
   if(std?this.closedOutput.includes(n[0]):!h||h.flags===0)err(9);
   else{const size=count(2),b=this.lab.read(n[1],size);
    if(std){check(this.outputBytes.length+b.length<=65536,'Linux output cap reached.');this.outputBytes.push(...b);(n[0]===1?this.stdout:this.stderr).push(...b);this.output=new TextDecoder().decode(Uint8Array.from(this.outputBytes));result=BigInt(size);detail=n[0]===1?'stdout':'stderr';}
    else{const length=Math.max(h.file.bytes.length,h.position+b.length);check(length<=65536,'Virtual file limit: 64 KiB.');check([...this.files.values()].reduce((v,f)=>v+f.bytes.length,0)-h.file.bytes.length+length<=524288,'Virtual filesystem cap: 512 KiB.');const out=new Uint8Array(length);out.set(h.file.bytes);out.set(b,h.position);h.file.bytes=out;h.position+=b.length;result=BigInt(b.length);detail=h.file.path;}
   }
  }else if(call==='open'||call==='openat'){
   const old=call==='open',index=old?0:1,path=this.path(n[index]),flags=n[index+1];check(old||n[0]===-100,'openat supports AT_FDCWD only.');const largeFile=['arm','thumb'].includes(s.mode)?0x20000:0;check(Number.isInteger(flags)&&flags>=0&&flags<=0x7fffffff&&!(flags&~(3|64|512|524288|largeFile))&&(flags&3)!==3,'Unsupported open flags.');
   let file=this.files.get(path);if(!file&&!(flags&64))err(2);else{check(this.files.size<64||file,'Virtual file count limit.');check(this.fds.size<64,'Virtual descriptor limit.');check(!(flags&512)||(flags&3)!==0,'Read-only truncation unsupported.');if(!file){file={path,bytes:new Uint8Array()};this.files.set(path,file);}if(flags&512){check((flags&3)!==0,'Read-only truncation unsupported.');file.bytes=new Uint8Array();}check(this.fds.size<64,'Virtual descriptor limit.');const fd=this.nextFd++;this.fds.set(fd,{file,flags:flags&3,position:0});result=BigInt(fd);detail=path;}
  }else if(id(3,57)){if([1,2].includes(n[0])&&!this.closedOutput.includes(n[0]))this.closedOutput.push(n[0]);else if(!this.fds.delete(n[0]))err(9);}
  else if(id(8,62)){const h=this.fds.get(n[0]);if(!h)err(9);else{check([0,1,2].includes(n[2])&&Number.isSafeInteger(n[1]),'Unsupported lseek.');const at=(n[2]===0?0:n[2]===1?h.position:h.file.bytes.length)+n[1];if(at<0||at>65536)err(22);else{h.position=at;result=BigInt(at);}}}
  else if(id(9,222)){
   check((n[3]===34&&n[0]===0||n[3]===50)&&n[4]===-1&&n[5]===0,'mmap supports anonymous private memory: no hint, or a bounded MAP_FIXED range.');check(n[1]>0&&n[1]<=1048576&&[0,1,2,3,4,5,6,7].includes(n[2]),'Invalid mmap length/protection.');
   const size=up(n[1]);if(n[3]===50){result=BigInt(this.fixedMap(Number(a[0]),size,n[2]));detail='Anonymous fixed mapping; only contained brk pages may be replaced.';}else{const address=this.heap;this.lab.map(address,size,n[2],'Linux mmap');this.allocations.push({address,size,perms:n[2]});this.heap+=size+P;result=BigInt(address);}
  }else if(id(10,226)){this.protect(n[0],up(n[1]),n[2]);detail='Permissions changed on modeled memory.';}else if(id(11,215)){
   const size=up(n[1]),r=this.allocations.find(r=>r.address===n[0]&&r.size===size);check(r&&n[1]>0,'Only complete mmap allocations can be unmapped/protected.');
   s.e.mem_unmap(r.address,r.size);this.lab.extra=this.lab.extra.filter(x=>x.address!==r.address);this.allocations=this.allocations.filter(x=>x!==r);
  }else if(id(12,214)){
   if(n[0]){if(n[0]<0x41000000||n[0]>0x41100000)result=BigInt(this.brk);else{const end=up(n[0]);if(end>this.brkEnd){this.lab.map(this.brkEnd,end-this.brkEnd,3,'Linux brk');this.brkEnd=end;const parts=this.lab.extra.filter(x=>x.name==='Linux brk').sort((a,b)=>a.address-b.address);if(parts.length>1){const merged=[];for(const part of parts){const last=merged.at(-1);if(last&&last.address+last.size===part.address&&last.perms===part.perms)last.size+=part.size;else merged.push({...part});}this.lab.extra=[...this.lab.extra.filter(x=>x.name!=='Linux brk'),...merged];}}this.brk=n[0];}}result=BigInt(this.brk);
  }else if(['getpid','gettid'].includes(call))result=1337n;
  else if(call==='getppid')result=1n;
  else if(['getuid','getgid','geteuid','getegid'].includes(call)||abi.word===4&&[24,47,49,50].includes(number))result=1000n;
  else if(call==='uname'){const b=new Uint8Array(390);['Linux','spectra','6.12.0-model','#1 SPECTRA modeled userspace',abi.machine,'(none)'].forEach((t,k)=>b.set(new TextEncoder().encode(t).slice(0,64),k*65));this.lab.write(n[0],b,'linux-uname');detail='Synthetic identity; no kernel is booted.';}
  else if(call==='getcwd'){if(n[1]<2)err(34);else{this.lab.write(n[0],Uint8Array.of(47,0),'linux-getcwd');result=2n;detail='Virtual current directory /';}}
  else if(call==='access'){const path=this.path(n[0]);check(n[1]>=0&&!(n[1]&~7),'Invalid access mode.');if(!this.files.has(path))err(2);else if(n[1]&1)err(13);detail=path+' (virtual regular data file)';}
  else if(call==='readlink'){const path=this.path(n[0]);if(!this.files.has(path))err(2);else err(22);detail='Virtual files are regular files, not symbolic links.';}
  else if(call==='readv'||call==='writev'){
   check(n[2]>=0&&n[2]<=64,'Vector I/O limit: 64 entries.');const vec=[];let total=0;for(let k=0;k<n[2];k++){const at=n[1]+k*abi.word*2,address=Number(this.lab.ptr(at,abi.word)),size=Number(this.lab.ptr(at+abi.word,abi.word));check(Number.isSafeInteger(address)&&Number.isSafeInteger(size)&&size>=0&&(total+=size)<=65536,'Vector I/O cap: 65,536 bytes.');vec.push({address,size});}
   const h=this.fds.get(n[0]),std=[1,2].includes(n[0]);if(call==='readv'){
    if(!h||h.flags===1)err(9);else for(const v of vec){const b=h.file.bytes.slice(h.position,h.position+v.size);this.lab.write(v.address,b,'linux-readv');h.position+=b.length;result+=BigInt(b.length);if(b.length<v.size)break;}
   }else if(std?this.closedOutput.includes(n[0]):!h||h.flags===0)err(9);
   else{const b=new Uint8Array(total);let pos=0;for(const v of vec){b.set(this.lab.read(v.address,v.size),pos);pos+=v.size;}
    if(std){check(this.outputBytes.length+total<=65536,'Linux output cap reached.');this.outputBytes.push(...b);(n[0]===1?this.stdout:this.stderr).push(...b);this.output=new TextDecoder().decode(Uint8Array.from(this.outputBytes));}
    else{const length=Math.max(h.file.bytes.length,h.position+total);check(length<=65536&&[...this.files.values()].reduce((v,f)=>v+f.bytes.length,0)-h.file.bytes.length+length<=524288,'Virtual file capacity exceeded.');const out=new Uint8Array(length);out.set(h.file.bytes);out.set(b,h.position);h.file.bytes=out;h.position+=total;}result=BigInt(total);
   }detail=call+'; virtual I/O only';
  }
  else throw Error('No Linux model for syscall '+number+'. No result was supplied.');
  if(s.mode==='x64'){s.writeReg('RCX',BigInt(i.address+i.size));s.writeReg('R11',s.readReg('EFLAGS'));}
  s.writeReg(abi.result,BigInt.asUintN(abi.word*8,result));s.writeReg(s.ip,BigInt(i.address+i.size));
  this.lab.event('linux-syscall',{number,name:call||'identity32',arguments:a.map(String),result:result.toString(),detail,behavior:'modeled; virtual I/O only'});
  if(this.exitCode!==null)s.halt('exited','Modeled Linux process exited with status '+this.exitCode+'.');
  }catch(e){this.lab.event('linux-syscall-unsupported',{number,name:call||'unknown',arguments:a.map(String),address:i.address,reason:e.message});throw Error((call?call+' (syscall '+number+'): ':'')+e.message);}
 }
}
function demo(mode='x64'){
 check(ABI[mode],'No Linux demo for this CPU.');
 // read(0, scratch, 32); write(1, scratch, result); exit(0).
 const code=mode==='x64'?Uint8Array.from('31c031ffbe00000060ba200000000f054889c2b801000000bf010000000f05b83c00000031ff0f05'.match(/../g),h=>parseInt(h,16)):new Uint8Array(52);
 if(mode==='aarch64'){const v=new DataView(code.buffer);[0xd2800000,0xd2ac0001,0xd2800402,0xd28007e8,0xd4000001,0xaa0003e2,0xd2800020,0xd2800808,0xd4000001,0xd2800000,0xd2800ba8,0xd4000001,0xd503201f].forEach((w,i)=>v.setUint32(i*4,w,true));}
 if(['arm','thumb','x86'].includes(mode)){
  const hex=mode==='x86'?'b80300000031dbb900000060ba20000000cd8089c2b804000000bb01000000cd80b80100000031dbcd80':mode==='arm'?'0000a0e30612a0e32020a0e30370a0e3000000ef0020a0e10100a0e30470a0e3000000ef0000a0e30170a0e3000000ef':'0020062109072022032700df02460120042700df0020012700df';
  const code=Uint8Array.from(hex.match(/../g),h=>parseInt(h,16)),b=new Uint8Array(256+code.length),v=new DataView(b.buffer);b.set([127,69,76,70,1,1,1]);v.setUint16(16,2,true);v.setUint16(18,mode==='x86'?3:40,true);v.setUint32(20,1,true);v.setUint32(24,0x400100+(mode==='thumb'?1:0),true);v.setUint32(28,52,true);v.setUint32(36,mode==='x86'?0:0x05000000,true);v.setUint16(40,52,true);v.setUint16(42,32,true);v.setUint16(44,1,true);v.setUint32(52,1,true);v.setUint32(60,0x400000,true);v.setUint32(68,b.length,true);v.setUint32(72,b.length+64,true);v.setUint32(76,5,true);v.setUint32(80,4096,true);b.set(code,256);return b;
 }
 const b=new Uint8Array(256+code.length),v=new DataView(b.buffer);b.set([127,69,76,70,2,1,1]);v.setUint16(16,2,true);v.setUint16(18,mode==='x64'?62:183,true);v.setUint32(20,1,true);v.setBigUint64(24,0x400100n,true);v.setBigUint64(32,64n,true);v.setUint16(52,64,true);v.setUint16(54,56,true);v.setUint16(56,1,true);v.setUint32(64,1,true);v.setUint32(68,5,true);v.setBigUint64(80,0x400000n,true);v.setBigUint64(96,BigInt(b.length),true);v.setBigUint64(104,BigInt(b.length),true);v.setBigUint64(112,4096n,true);b.set(code,256);return b;
}
root.SpectraLinux={prepare,inspect,loadBias,relocate,Environment,demo,ABI,CALLS,PIE_BASE};if(typeof module!=='undefined')module.exports=root.SpectraLinux;
})(globalThis);
