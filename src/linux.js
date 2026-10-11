/* Bounded Linux userspace model: ELF64 ET_EXEC, x86-64/AArch64, no kernel or host I/O. */
(function(root){
'use strict';
const P=4096,STACK=0x70000000,SCRATCH=0x60000000,AREA=65536;
const check=(v,m)=>{if(!v)throw Error(m);},up=n=>Math.ceil(n/P)*P;
function prepare(bytes,meta,options){
 check(!options.raw,'Linux process mode requires a complete static ELF image.');
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),fits=(a,n)=>Number.isSafeInteger(a)&&a>=0&&n>=0&&a<=bytes.length-n;
 check(fits(0,64)&&bytes[0]===127&&bytes[1]===69&&bytes[2]===76&&bytes[3]===70&&bytes[4]===2&&bytes[5]===1&&bytes[6]===1,'Linux model needs a little-endian ELF64 image.');
 const u64=a=>{check(fits(a,8),'Truncated ELF header.');const n=Number(v.getBigUint64(a,true));check(Number.isSafeInteger(n),'ELF address exceeds exact range.');return n;};
 const machine=v.getUint16(18,true),mode=machine===62?'x64':machine===183?'aarch64':null;
 check(mode&&mode===options.mode,'Linux model supports matching x64 or AArch64 ELF images.');
 check(!options.endian||['auto','little'].includes(options.endian),'Linux model requires little endian.');
 check(v.getUint16(16,true)===2,'Linux model currently requires static ET_EXEC, not PIE/shared objects.');
 const entry=u64(24),ph=u64(32),ent=v.getUint16(54,true),count=v.getUint16(56,true);
 check(ent===56&&count>0&&count<=128&&fits(ph,ent*count),'Invalid ELF program header table.');
 check(options.start===undefined||Number(options.start)===entry,'Linux startup begins at the ELF entry. Use a function harness for another address.');
 const regions=[],pages=new Map();let endImage=0;
 for(let j=0;j<count;j++){
  const at=ph+j*ent,type=v.getUint32(at,true);check(![2,3,7].includes(type),'Dynamic linking, interpreters and TLS are outside this Linux profile.');if(type!==1)continue;
  const flags=v.getUint32(at+4,true),offset=u64(at+8),address=u64(at+16),fileSize=u64(at+32),size=u64(at+40),align=u64(at+48);
  check(size>=fileSize&&fits(offset,fileSize)&&address>=P&&Number.isSafeInteger(address+size)&&address+size<0x800000000000,'Invalid ELF load segment.');if(!size)continue;
  check(size<=16*1024*1024&&(!align||align===1||(Number.isInteger(Math.log2(align))&&address%align===offset%align)),'Invalid ELF segment size/alignment.');
  check(!(flags&~7),'Unsupported ELF segment flags.');
  for(const a of [STACK,SCRATCH,0x50000000])check(address+size<=a||address>=a+AREA,'ELF overlaps reserved session memory.');
  check(!regions.some(r=>address<r.address+r.size&&address+size>r.address),'Overlapping ELF segments are unsupported.');
  const perms=(flags&4?1:0)|(flags&2?2:0)|(flags&1?4:0);
  regions.push({name:'PT_LOAD '+j,address,offset,size,fileSize,permissions:(perms&1?'R':'-')+(perms&2?'W':'-')+(perms&4?'X':'-')});
  for(let a=Math.floor(address/P)*P;a<up(address+size);a+=P){if(!pages.has(a))check((pages.size+1)*P+AREA*2+(mode==='aarch64'?P:0)<=16*1024*1024,'Linux image exceeds 16 MiB mapped-memory budget.');pages.set(a,(pages.get(a)||0)|perms);}endImage=Math.max(endImage,address+size);
 }
 check(regions.length&&regions.some(r=>r.permissions.includes('X')&&entry>=r.address&&entry<r.address+r.fileSize),'ELF entry is not in executable file bytes.');
 const memoryBytes=pages.size*P+AREA*2+(mode==='aarch64'?P:0);check(memoryBytes<=16*1024*1024,'Linux image exceeds 16 MiB mapped-memory budget.');
 const mapped=[];for(const [address,perms]of [...pages].sort((a,b)=>a[0]-b[0])){const last=mapped.at(-1);if(last&&last.address+last.size===address&&last.perms===perms)last.size+=P;else mapped.push({address,size:P,perms});}
 const pr=regions.find(r=>ph>=r.offset&&ph+ent*count<=r.offset+r.fileSize);
 check(pr,'Program headers must be present in a load segment for Linux startup.');
 return {environment:'linux',mode,start:entry,endian:'little',regions,mapped,memoryBytes,stack:STACK,scratch:SCRATCH,areaSize:AREA,returnBoundary:mode==='aarch64'?0x50000000:0,linux:{phdr:pr.address+ph-pr.offset,phnum:count,phent:ent},scope:'Static ELF64 Linux userspace model. Supported syscalls only; no kernel, dynamic linker, threads, signals or live network.'};
}
class Environment{
 constructor(s,recipe){
  this.s=s;this.lab=s.lab;this.files=new Map(recipe.files.map(f=>{check(f.path.startsWith('/')&&!f.path.split('/').some(x=>x==='..'),'Linux virtual files need absolute paths without ..');return [f.path,{path:f.path,bytes:root.SpectraLab.bytes(f.hex)}];}));this.fds=new Map();this.closedOutput=[];this.nextFd=3;this.output='';this.stdout=[];this.stderr=[];this.outputBytes=[];this.exitCode=null;this.heap=0x40000000;this.brk=0x41000000;this.brkEnd=this.brk;this.allocations=[];
  const input={path:'<stdin>',bytes:root.SpectraLab.bytes(recipe.stdin||'')};this.fds.set(0,{file:input,position:0,flags:0});
  let top=STACK+AREA;const putText=t=>{const b=new TextEncoder().encode(t+'\0');top-=b.length;check(top>STACK+8192,'Linux startup strings exceed stack budget.');s.e.mem_write(top,b);return top;};
  const argv=(recipe.argv.length?recipe.argv:['sample']).map(putText),env=recipe.env.map(putText),exec=argv[0];top-=16;const random=top;s.e.mem_write(random,Uint8Array.from({length:16},(_,i)=>i+1));
  const l=s.plan.linux,aux=[3,l.phdr,4,l.phent,5,l.phnum,6,P,7,0,9,s.plan.start,11,1000,12,1000,13,1000,14,1000,23,0,25,random,31,exec,0,0];
  const words=[argv.length,...argv,0,...env,0,...aux],sp=Math.floor((top-words.length*8)/16)*16;check(sp>=STACK,'Linux startup stack overflow.');
  words.forEach((n,i)=>this.lab.put(sp+i*8,BigInt(n),8));s.writeReg(s.sp,BigInt(sp));this.lab.event('linux-startup',{argv:recipe.argv.length?recipe.argv:['sample'],env:recipe.env,random:'deterministic 01..10 bytes; analyst model',scope:s.plan.scope});
 }
 path(at){let text='';for(let i=0;i<4096;i++){const b=this.lab.read(at+i,1)[0];if(!b){check(text.startsWith('/')&&!text.split('/').some(x=>x==='..'),'Only absolute virtual paths without .. are supported.');return text;}text+=String.fromCharCode(b);}throw Error('Virtual pathname exceeds 4096 bytes.');}
 snapshot(){return {output:this.output,closedOutput:this.closedOutput,stdoutHex:root.SpectraLab.hexBytes(this.stdout),stderrHex:root.SpectraLab.hexBytes(this.stderr),outputHex:root.SpectraLab.hexBytes(this.outputBytes),exitCode:this.exitCode,brk:this.brk,brkEnd:this.brkEnd,nextFd:this.nextFd,heap:this.heap,allocations:this.allocations,files:[...this.files].map(([path,f])=>({path,hex:root.SpectraLab.hexBytes(f.bytes)})),fds:[...this.fds].map(([fd,h])=>({fd,path:h.file.path,position:h.position,flags:h.flags})),stdin:root.SpectraLab.hexBytes(this.fds.get(0)?.file.bytes||[])};}
 syscall(i){
  const s=this.s,arm=s.mode==='aarch64',number=Number(s.readReg(arm?'X8':'RAX')),names=arm?['X0','X1','X2','X3','X4','X5']:['RDI','RSI','RDX','R10','R8','R9'],a=names.map(n=>s.readReg(n)),n=a.map(x=>Number(BigInt.asIntN(64,x))),id=(x,y)=>number===(arm?y:x);let result=0n,detail='';
  const count=k=>{check(Number.isSafeInteger(n[k])&&n[k]>=0&&n[k]<=65536,'Syscall byte count cap: 65,536.');return n[k];},err=e=>{result=BigInt(-e);};
  if(id(60,93)||id(231,94)){this.exitCode=Number(a[0]&255n);detail='modeled process exit';}
  else if(id(0,63)){
   const h=this.fds.get(n[0]);if(!h||h.flags===1)err(9);else{const size=count(2),b=h.file.bytes.slice(h.position,h.position+size);this.lab.write(n[1],b,'linux-read');h.position+=b.length;result=BigInt(b.length);detail=h.file.path;}
  }else if(id(1,64)){
   const std=[1,2].includes(n[0]),h=this.fds.get(n[0]);
   if(std?this.closedOutput.includes(n[0]):!h||h.flags===0)err(9);
   else{const size=count(2),b=this.lab.read(n[1],size);
    if(std){check(this.outputBytes.length+b.length<=65536,'Linux output cap reached.');this.outputBytes.push(...b);(n[0]===1?this.stdout:this.stderr).push(...b);this.output=new TextDecoder().decode(Uint8Array.from(this.outputBytes));result=BigInt(size);detail=n[0]===1?'stdout':'stderr';}
    else{const length=Math.max(h.file.bytes.length,h.position+b.length);check(length<=65536,'Virtual file limit: 64 KiB.');check([...this.files.values()].reduce((v,f)=>v+f.bytes.length,0)-h.file.bytes.length+length<=524288,'Virtual filesystem cap: 512 KiB.');const out=new Uint8Array(length);out.set(h.file.bytes);out.set(b,h.position);h.file.bytes=out;h.position+=b.length;result=BigInt(b.length);detail=h.file.path;}
   }
  }else if(!arm&&number===2||id(257,56)){
   const old=!arm&&number===2,index=old?0:1,path=this.path(n[index]),flags=n[index+1];check(old||n[0]===-100,'openat supports AT_FDCWD only.');check(Number.isInteger(flags)&&flags>=0&&flags<524868&&!(flags&~(3|64|512|524288))&&(flags&3)!==3,'Unsupported open flags.');
   let file=this.files.get(path);if(!file&&!(flags&64))err(2);else{check(this.files.size<64||file,'Virtual file count limit.');check(this.fds.size<64,'Virtual descriptor limit.');check(!(flags&512)||(flags&3)!==0,'Read-only truncation unsupported.');if(!file){file={path,bytes:new Uint8Array()};this.files.set(path,file);}if(flags&512){check((flags&3)!==0,'Read-only truncation unsupported.');file.bytes=new Uint8Array();}check(this.fds.size<64,'Virtual descriptor limit.');const fd=this.nextFd++;this.fds.set(fd,{file,flags:flags&3,position:0});result=BigInt(fd);detail=path;}
  }else if(id(3,57)){if([1,2].includes(n[0])&&!this.closedOutput.includes(n[0]))this.closedOutput.push(n[0]);else if(!this.fds.delete(n[0]))err(9);}
  else if(id(8,62)){const h=this.fds.get(n[0]);if(!h)err(9);else{check([0,1,2].includes(n[2])&&Number.isSafeInteger(n[1]),'Unsupported lseek.');const at=(n[2]===0?0:n[2]===1?h.position:h.file.bytes.length)+n[1];if(at<0||at>65536)err(22);else{h.position=at;result=BigInt(at);}}}
  else if(id(9,222)){
   check(n[0]===0&&n[3]===34&&n[4]===-1&&n[5]===0,'mmap supports anonymous private mappings with no address hint.');check(n[1]>0&&n[1]<=1048576&&[0,1,2,3,4,5,6,7].includes(n[2]),'Invalid mmap length/protection.');
   const size=up(n[1]),address=this.heap;this.lab.map(address,size,n[2],'Linux mmap');this.allocations.push({address,size,perms:n[2]});this.heap+=size+P;result=BigInt(address);
  }else if(id(11,215)||id(10,226)){
   const size=up(n[1]),r=this.allocations.find(r=>r.address===n[0]&&r.size===size);check(r&&n[1]>0,'Only complete mmap allocations can be unmapped/protected.');
   if(id(11,215)){s.e.mem_unmap(r.address,r.size);this.lab.extra=this.lab.extra.filter(x=>x.address!==r.address);this.allocations=this.allocations.filter(x=>x!==r);}
   else{check([0,1,2,3,4,5,6,7].includes(n[2]),'Unsupported protection bits.');s.e.mem_protect(r.address,r.size,n[2]);r.perms=n[2];this.lab.extra.find(x=>x.address===r.address).perms=n[2];}
  }else if(id(12,214)){
   if(n[0]){if(n[0]<0x41000000||n[0]>0x41100000)result=BigInt(this.brk);else{const end=up(n[0]);if(end>this.brkEnd){this.lab.map(this.brkEnd,end-this.brkEnd,3,'Linux brk');this.brkEnd=end;const parts=this.lab.extra.filter(x=>x.name==='Linux brk').sort((a,b)=>a.address-b.address);if(parts.length>1){parts[0].size=end-parts[0].address;this.lab.extra=this.lab.extra.filter(x=>x.name!=='Linux brk'||x===parts[0]);}}this.brk=n[0];}}result=BigInt(this.brk);
  }else if(id(39,172))result=1337n;
  else throw Error('No Linux model for syscall '+number+'. No result was supplied.');
  if(!arm){s.writeReg('RCX',BigInt(i.address+i.size));s.writeReg('R11',s.readReg('EFLAGS'));}
  s.writeReg(arm?'X0':'RAX',BigInt.asUintN(64,result));s.writeReg(s.ip,BigInt(i.address+i.size));
  this.lab.event('linux-syscall',{number,arguments:a.map(String),result:result.toString(),detail,behavior:'modeled; virtual I/O only'});
  if(this.exitCode!==null)s.halt('exited','Modeled Linux process exited with status '+this.exitCode+'.');
 }
}
function demo(mode='x64'){
 check(['x64','aarch64'].includes(mode),'Linux demo supports x64 or AArch64.');
 // read(0, scratch, 32); write(1, scratch, result); exit(0).
 const code=mode==='x64'?Uint8Array.from('31c031ffbe00000060ba200000000f054889c2b801000000bf010000000f05b83c00000031ff0f05'.match(/../g),h=>parseInt(h,16)):new Uint8Array(52);
 if(mode==='aarch64'){const v=new DataView(code.buffer);[0xd2800000,0xd2ac0001,0xd2800402,0xd28007e8,0xd4000001,0xaa0003e2,0xd2800020,0xd2800808,0xd4000001,0xd2800000,0xd2800ba8,0xd4000001,0xd503201f].forEach((w,i)=>v.setUint32(i*4,w,true));}
 const b=new Uint8Array(256+code.length),v=new DataView(b.buffer);b.set([127,69,76,70,2,1,1]);v.setUint16(16,2,true);v.setUint16(18,mode==='x64'?62:183,true);v.setUint32(20,1,true);v.setBigUint64(24,0x400100n,true);v.setBigUint64(32,64n,true);v.setUint16(52,64,true);v.setUint16(54,56,true);v.setUint16(56,1,true);v.setUint32(64,1,true);v.setUint32(68,5,true);v.setBigUint64(80,0x400000n,true);v.setBigUint64(96,BigInt(b.length),true);v.setBigUint64(104,BigInt(b.length),true);v.setBigUint64(112,4096n,true);b.set(code,256);return b;
}
root.SpectraLinux={prepare,Environment,demo};if(typeof module!=='undefined')module.exports=root.SpectraLinux;
})(globalThis);
