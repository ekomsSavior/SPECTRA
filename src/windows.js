// Browser-local Windows model. No host DLLs, files, sockets, or processes.
(function(root){
'use strict';
const PAGE=4096,AREA=65536,ENV=0x71000000,STUB=0x72000000,MAX=16*1024*1024;
const down=n=>Math.floor(n/PAGE)*PAGE,up=n=>Math.ceil(n/PAGE)*PAGE,hx=n=>'0x'+BigInt(n).toString(16).toUpperCase();
function check(ok,text){if(!ok)throw Error(text);}
function prepare(bytes,options={}){
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),fits=(o,n)=>Number.isSafeInteger(o)&&Number.isSafeInteger(n)&&o>=0&&n>=0&&o<=bytes.length-n;
 const u16=o=>{check(fits(o,2),'Truncated PE field.');return v.getUint16(o,true);},u32=o=>{check(fits(o,4),'Truncated PE field.');return v.getUint32(o,true);},u64=o=>{check(fits(o,8),'Truncated PE field.');const n=Number(v.getBigUint64(o,true));check(Number.isSafeInteger(n),'PE address exceeds exact range.');return n;};
 check(u16(0)===0x5a4d,'Windows mode requires a PE file.');const pe=u32(0x3c);check(u32(pe)===0x4550,'Invalid PE signature.');
 const machine=u16(pe+4),wide=machine===0x8664;check(wide||machine===0x14c,'Windows emulation supports native x86/x64 PE files.');
 check(!options.mode||options.mode===(wide?'x64':'x86'),'CPU mismatch: this PE requires '+(wide?'x64':'x86')+'.');
 const word=wide?8:4,opt=pe+24,optSize=u16(pe+20),count=u16(pe+6);
 check(count>0&&count<=96&&fits(opt,optSize)&&optSize>=(wide?112:96),'Invalid optional header or section count.');
 check(u16(opt)===(wide?0x20b:0x10b),'PE machine and optional header disagree.');
 const preferred=wide?u64(opt+24):u32(opt+28),base=options.loadBase===undefined?preferred:Number(options.loadBase),imageSize=u32(opt+56),headers=u32(opt+60),entryRva=u32(opt+16),alignment=u32(opt+32);
 check(Number.isSafeInteger(base)&&base>=PAGE&&base%AREA===0,'Image base needs nonzero 64 KiB alignment.');
 check(imageSize>0&&imageSize<=MAX-4*AREA&&headers>0&&headers<=imageSize&&fits(0,headers),'Invalid PE image/header size or memory budget.');
 check(alignment>0&&imageSize%alignment===0,'Invalid section alignment.');
 check(base+imageSize<=(wide?0x800000000000:0x100000000),'Image exceeds CPU address range.');
 for(const a of [0x60000000,0x70000000,ENV,STUB])check(base+imageSize<=a||base>=a+AREA,'Image overlaps reserved session memory.');
 const regions=[{name:'PE headers',address:base,offset:0,size:headers,fileSize:headers,permissions:'R--'}],pages=new Map();
 const add=(a,size,p)=>{for(let n=down(a);n<up(a+size);n+=PAGE)pages.set(n,(pages.get(n)||0)|p);};add(base,headers,1);
 for(let i=0;i<count;i++){const o=opt+optSize+i*40;check(fits(o,40),'Truncated section table.');let name='';for(let j=0;j<8&&bytes[o+j];j++)name+=String.fromCharCode(bytes[o+j]);
  const raw=u32(o+16),size=Math.max(u32(o+8),raw),rva=u32(o+12),offset=u32(o+20),flags=u32(o+36);if(!size)continue;
  check(rva>=headers&&rva+size<=imageSize&&(!raw||fits(offset,raw)),'Section '+name+' exceeds file/image bounds.');
  check(!regions.some(r=>base+rva<r.address+r.size&&base+rva+size>r.address),'Overlapping PE sections are ambiguous.');
  const p=(flags&0x40000000?1:0)|(flags&0x80000000?2:0)|(flags&0x20000000?4:0);
  regions.push({name,address:base+rva,offset,size,fileSize:raw,permissions:(p&1?'R':'-')+(p&2?'W':'-')+(p&4?'X':'-')});add(base+rva,size,p);
 }
 const mapped=[];for(const [at,perms]of [...pages].sort((a,b)=>a[0]-b[0])){const last=mapped.at(-1);if(last&&last.address+last.size===at&&last.perms===perms)last.size+=PAGE;else mapped.push({address:at,size:PAGE,perms});}
 const memoryBytes=mapped.reduce((n,r)=>n+r.size,0)+4*AREA;check(memoryBytes<=MAX,'Process exceeds the 16 MiB mapping budget.');
 const offset=(rva,n=1)=>{const r=regions.find(r=>rva>=r.address-base&&rva+n<=r.address-base+r.fileSize);check(r,'PE directory is not wholly backed by file bytes.');return r.offset+rva-r.address+base;};
 const dd=opt+(wide?112:96),dirs=Math.min(16,u32(opt+(wide?108:92))),dir=i=>{if(i>=dirs||dd+8*(i+1)>opt+optSize)return null;const rva=u32(dd+8*i),size=u32(dd+8*i+4);return rva&&size?{rva,size}:null;};
 const str=rva=>{let s='';for(let i=0;i<1024;i++){const b=bytes[offset(rva+i)];if(!b)return s;s+=String.fromCharCode(b);}throw Error('Unterminated PE name.');};
 check(!dir(14),'This PE contains managed .NET code. Use .NET decompilation; the Windows CPU model has no CLR.');
 const imports=[],imp=dir(1);if(imp){let terminated=false;for(let i=0;i<Math.min(512,Math.floor(imp.size/20));i++){const o=offset(imp.rva+i*20,20),original=u32(o),name=u32(o+12),first=u32(o+16);if(!original&&!name&&!first){terminated=true;break;}check(name&&first,'Malformed import descriptor.');const library=str(name);let ended=false;
  for(let j=0;j<4096;j++){const at=offset((original||first)+j*word,word),value=wide?v.getBigUint64(at,true):BigInt(u32(at));if(!value){ended=true;break;}check(imports.length<4000,'Import cap: 4,000 slots.');offset(first+j*word,word);
   const ordinal=!!(value&(wide?0x8000000000000000n:0x80000000n));imports.push({library,name:ordinal?'#'+Number(value&65535n):str(Number(value)+2),address:base+first+j*word,ordinal});
  }check(ended,'Truncated or oversized import thunk list.');
 }check(terminated,'Truncated or oversized import descriptors.');}
 const delta=base-preferred,relocations=[],rel=dir(5);if(delta){check(rel&&!(u16(pe+22)&1),'Image has no usable base relocations.');for(let cursor=0;cursor<rel.size;){const o=offset(rel.rva+cursor,8),page=u32(o),size=u32(o+4);check(size>=8&&size%2===0&&cursor+size<=rel.size,'Invalid relocation block.');
  for(let j=8;j<size;j+=2){const e=u16(offset(rel.rva+cursor+j,2)),type=e>>>12,rva=page+(e&4095);if(!type)continue;check(type===(wide?10:3),'Unsupported relocation type '+type+'.');check(regions.some(r=>base+rva>=r.address&&base+rva+word<=r.address+r.size),'Relocation outside mapped image.');relocations.push({address:base+rva,width:word});check(relocations.length<=100000,'Relocation cap exceeded.');}cursor+=size;
 }}
 let tls=null;const td=dir(9);if(td){const o=offset(td.rva,wide?40:24),read=wide?u64:u32,a=read(o),b=read(o+word),index=read(o+word*2),callbacks=read(o+word*3),zero=u32(o+word*4);check(b>=a&&b-a+zero<=8192,'TLS data exceeds the 8 KiB model limit.');const list=[];if(callbacks){let ended=false;for(let i=0;i<33;i++){const p=read(offset(callbacks-preferred+i*word,word));if(!p){ended=true;break;}list.push(base+p-preferred);}check(ended&&list.length<=32,'TLS callback cap exceeded.');}check(mapped.some(r=>(r.perms&2)&&base+index-preferred>=r.address&&base+index-preferred+4<=r.address+r.size),'TLS index is outside writable memory.');tls={sourceOffset:b>a?offset(a-preferred,b-a):0,size:b-a,zero,index:base+index-preferred,callbacks:list};}
 let start=options.start===undefined?base+entryRva:Number(options.start);if(delta&&start>=preferred&&start<preferred+imageSize)start+=delta;
 const executable=a=>mapped.some(r=>(r.perms&4)&&a>=r.address&&a<r.address+r.size);check(Number.isSafeInteger(start)&&executable(start),'Start is outside executable PE memory.');for(const a of tls?.callbacks||[])check(executable(a),'TLS callback is outside executable memory.');
 return {environment:'windows',mode:wide?'x64':'x86',start,regions,mapped,memoryBytes,stack:0x70000000,scratch:0x60000000,areaSize:AREA,windows:{base,preferred,imageSize,entry:base+entryRva,dll:!!(u16(pe+22)&0x2000),delta,imports,relocations,tls,warnings:['Single-threaded Windows user-mode model; unsupported calls stop.','No kernel, real DLL code, SEH unwinding, child processes, or live I/O. Loader module lists are empty; manual DLL/export walking is not modeled.',...(dir(13)?['Delay-import descriptors are not resolved.']:[])]}};
}
const APIS={
 VirtualAlloc:[4,'allocate'],VirtualFree:[3,'free'],VirtualProtect:[4,'protect'],GetProcessHeap:[0,'heap'],HeapAlloc:[3,'heapAlloc'],HeapFree:[3,'heapFree'],HeapReAlloc:[4,'realloc'],
 GetLastError:[0,'error'],SetLastError:[1,'setError'],GetCurrentProcess:[0,'process'],GetCurrentProcessId:[0,'pid'],GetCurrentThreadId:[0,'tid'],
 ExitProcess:[1,'exit'],TerminateProcess:[2,'terminate'],GetTickCount:[0,'ticks'],GetTickCount64:[0,'ticks'],Sleep:[1,'sleep'],IsDebuggerPresent:[0,'debugger'],
 GetModuleHandleA:[1,'moduleA'],GetModuleHandleW:[1,'moduleW'],LoadLibraryA:[1,'loadA'],LoadLibraryW:[1,'loadW'],GetProcAddress:[2,'proc'],
 GetCommandLineA:[0,'commandA'],GetCommandLineW:[0,'commandW'],GetModuleFileNameA:[3,'filenameA'],GetModuleFileNameW:[3,'filenameW'],
 lstrlenA:[1,'lengthA'],lstrlenW:[1,'lengthW'],lstrcpyA:[2,'copyA'],lstrcpyW:[2,'copyW'],RtlMoveMemory:[3,'move'],RtlCopyMemory:[3,'move'],RtlZeroMemory:[2,'zero'],RtlFillMemory:[3,'fill'],
 memcpy:[3,'move','cdecl'],memmove:[3,'move','cdecl'],memset:[3,'memset','cdecl'],strlen:[1,'lengthA','cdecl'],wcslen:[1,'lengthW','cdecl'],malloc:[1,'malloc','cdecl'],calloc:[2,'calloc','cdecl'],free:[1,'crtFree','cdecl'],
 OutputDebugStringA:[1,'outputA'],OutputDebugStringW:[1,'outputW'],TlsAlloc:[0,'tlsAlloc'],TlsFree:[1,'tlsFree'],TlsSetValue:[2,'tlsSet'],TlsGetValue:[1,'tlsGet'],
 CreateFileA:[7,'fileA'],CreateFileW:[7,'fileW'],ReadFile:[5,'readFile'],WriteFile:[5,'writeFile'],GetFileSize:[2,'fileSize'],SetFilePointer:[4,'filePointer'],CloseHandle:[1,'close']
};
const DLLS=new Set(['kernel32.dll','kernelbase.dll','ntdll.dll','msvcrt.dll','ucrtbase.dll','vcruntime140.dll']);
const apiSupport=(library,name)=>{const lib=canon(library);return !!((DLLS.has(lib)||lib.startsWith('api-ms-win-'))&&Object.hasOwn(APIS,name)&&(!CRT.has(name)||['msvcrt.dll','ucrtbase.dll','vcruntime140.dll'].includes(lib)||lib.startsWith('api-ms-win-crt-')));};
const CRT=new Set(['memcpy','memmove','memset','strlen','wcslen','malloc','calloc','free']);
const canon=s=>{const n=String(s).replace(/^.*[\\/]/,'').toLowerCase();return n.includes('.')?n:n+'.dll';};
class Environment{
 constructor(s,bytes,options={}){
  this.s=s;s.windows=this;this.loading=true;this.info=s.plan.windows;this.word=s.word;this.wide=s.mode==='x64';this.extra=[];this.memoryBytes=s.plan.memoryBytes-2*AREA;this.events=[];this.eventCount=0;this.api=new Map();this.lookup=new Map();this.modules=new Map();this.allocations=new Map();this.nextHeap=0x30000000;this.heapHandle=ENV+0x100;this.lastError=0;this.clock=1000;this.tlsValues=new Map(this.info.tls?[[0,BigInt(ENV+0x5000)]]:[]);this.files=new Map();this.handles=new Map();this.nextHandle=256;this.fileBytes=0;this.output='';this.exitCode=null;
  this.map(ENV,AREA,3,'Process environment');this.map(STUB,AREA,5,'API traps');this.s.e.mem_write(STUB,new Uint8Array(AREA).fill(0xcc));
  for(const r of this.info.relocations)this.put(r.address,BigInt.asUintN(r.width*8,this.ptr(r.address,r.width)+BigInt(this.info.delta)),r.width);
  this.filename='C:\\spectra\\'+String(options.filename||'sample.exe').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,100);this.command='"'+this.filename+'"';
  this.string(ENV+0x3000,this.command,false);this.string(ENV+0x3400,this.command,true);this.string(ENV+0x3800,this.filename,false);this.string(ENV+0x3c00,this.filename,true);
  for(const lib of ['kernel32.dll','kernelbase.dll','ntdll.dll','msvcrt.dll',...this.info.imports.map(i=>i.library)])this.module(lib,true);
  for(const i of this.info.imports)this.put(i.address,BigInt(this.trap(i.library,i.name)));
  this.processData();
  this.entries=[];if(s.plan.start===this.info.entry)for(const a of this.info.tls?.callbacks||[])this.entries.push({address:a,args:[this.info.base,1,0],phase:'TLS callback'});
  this.entries.push({address:s.plan.start,args:this.info.dll&&s.plan.start===this.info.entry?[this.info.base,1,0]:[],phase:this.info.dll?'DLL entry':'EXE entry'});
  if(this.info.tls){const t=this.info.tls;this.put(t.index,0n,4);this.put(ENV+0x4800,BigInt(ENV+0x5000));if(t.size)this.write(ENV+0x5000,bytes.slice(t.sourceOffset,t.sourceOffset+t.size));}
  this.enterNext();this.loading=false;this.note('loader','Mapped image, bound '+this.info.imports.length+' imports, applied '+this.info.relocations.length+' relocations.','modeled');
 }
 map(address,size,perms,name){
  check(Number.isSafeInteger(address)&&address>=PAGE&&address%PAGE===0&&size>0&&size%PAGE===0,'Invalid memory mapping.');check(Number.isSafeInteger(address+size)&&address+size<=(this.wide?0x800000000000:0x100000000),'Allocation exceeds CPU address range.');
  const all=this.s.e.mem_regions().map(r=>({address:Number(r.begin),size:Number(r.end)-Number(r.begin)+1}));
  check(all.reduce((n,r)=>n+r.size,0)+size<=MAX,'16 MiB mapped-memory budget reached.');
  check(!all.some(r=>address<r.address+r.size&&address+size>r.address),'Allocation overlaps mapped memory.');
  this.s.e.mem_map(address,size,perms);this.s.e.mem_write(address,new Uint8Array(size));this.extra.push({address,size,perms,name});this.memoryBytes+=size;
 }
 ptr(at,width=this.word){const b=this.read(Number(at),width),d=new DataView(b.buffer,b.byteOffset,b.byteLength);return width===8?d.getBigUint64(0,true):BigInt(d.getUint32(0,true));}
 put(at,value,width=this.word){const b=new Uint8Array(width),d=new DataView(b.buffer);if(width===8)d.setBigUint64(0,BigInt.asUintN(64,BigInt(value)),true);else d.setUint32(0,Number(BigInt.asUintN(32,BigInt(value))),true);this.write(at,b);}
 write(at,bytes){if(!bytes.length)return;check(Number.isSafeInteger(Number(at))&&this.s.region(Number(at),bytes.length,this.loading?0:2),'Write outside writable session memory.');this.s.e.mem_write(Number(at),bytes);this.s.noteAccess('write',Number(at),bytes.length,'modeled-api');}
 read(at,size){check(Number.isSafeInteger(size)&&size>=0&&size<=1048576,'API read limit: 1 MiB.');if(!size)return new Uint8Array();check(Number.isSafeInteger(Number(at))&&this.s.region(Number(at),size,this.loading?0:1),'Read outside readable session memory.');const bytes=Uint8Array.from(this.s.e.mem_read(Number(at),size));this.s.noteAccess('read',Number(at),size,'modeled-api');return bytes;}
 text(at,wide=false){check(at,'Null string pointer.');let text='';for(let i=0;i<32768;i++){const b=this.read(Number(at)+i*(wide?2:1),wide?2:1),c=wide?b[0]|b[1]<<8:b[0];if(!c)return text;text+=String.fromCharCode(c);}throw Error('String exceeds the 32,768-character limit.');}
 string(at,text,wide){const b=new Uint8Array((text.length+1)*(wide?2:1));for(let i=0;i<text.length;i++){b[i*(wide?2:1)]=text.charCodeAt(i)&255;if(wide)b[i*2+1]=text.charCodeAt(i)>>>8;}this.write(at,b);}
 note(api,detail,behavior='modeled',extra={}){this.eventCount++;this.events.push({id:this.eventCount,step:this.s.steps,api,detail,behavior,...extra});if(this.events.length>500)this.events.shift();}
 module(name,create=false){const key=canon(name);if(this.modules.has(key))return this.modules.get(key);if(!create)return 0;check(this.modules.size<64,'Module cap: 64.');const h=ENV+0x8000+this.modules.size*0x100;this.modules.set(key,h);return h;}
 trap(library,name){const lib=canon(library),key=lib+'!'+name;if(this.lookup.has(key))return this.lookup.get(key);check(this.api.size<4000,'API trap cap: 4,000.');
  const address=STUB+this.api.size*16,def=apiSupport(lib,name)?APIS[name]:null;
  const valid=def&&(!CRT.has(name)||['msvcrt.dll','ucrtbase.dll','vcruntime140.dll'].includes(lib)||lib.startsWith('api-ms-win-crt-'));
  this.api.set(address,{address,library:lib,name,definition:valid?def:null});this.lookup.set(key,address);return address;
 }
 processData(){
  const peb=ENV+0x1000,ldr=ENV+0x2000,params=ENV+0x2800;
  this.put(ENV+(this.wide?0x30:0x18),BigInt(ENV));this.put(ENV+(this.wide?0x60:0x30),BigInt(peb));this.put(ENV+(this.wide?8:4),0x70010000n);this.put(ENV+(this.wide?0x10:8),0x70000000n);this.put(ENV+(this.wide?0x58:0x2c),BigInt(ENV+0x4800));
  this.put(peb+(this.wide?0x10:8),BigInt(this.info.base));this.put(peb+(this.wide?0x18:0xc),BigInt(ldr));this.put(peb+(this.wide?0x20:0x10),BigInt(params));this.put(peb+(this.wide?0x30:0x18),BigInt(this.heapHandle));
  for(const o of this.wide?[0x10,0x20,0x30]:[0xc,0x14,0x1c]){this.put(ldr+o,BigInt(ldr+o));this.put(ldr+o+this.word,BigInt(ldr+o));}
  const unicode=(at,text,ptr)=>{const b=new Uint8Array(this.wide?16:8),d=new DataView(b.buffer);d.setUint16(0,text.length*2,true);d.setUint16(2,(text.length+1)*2,true);if(this.wide)d.setBigUint64(8,BigInt(ptr),true);else d.setUint32(4,ptr,true);this.write(at,b);};
  unicode(params+(this.wide?0x60:0x38),this.filename,ENV+0x3c00);unicode(params+(this.wide?0x70:0x40),this.command,ENV+0x3400);
  if(this.wide)this.s.e.reg_write_i64(this.s.uc.X86_REG_GS_BASE,BigInt(ENV));
  else{const gdt=ENV+0xf000,b=new Uint8Array(8),d=new DataView(b.buffer);d.setUint16(0,65535,true);d.setUint16(2,ENV&65535,true);b[4]=ENV>>>16&255;b[5]=0xf3;b[6]=0xcf;b[7]=ENV>>>24;this.write(gdt+24,b);const flat=b.slice();flat[2]=flat[3]=flat[4]=flat[7]=0;flat[5]=0x93;this.write(gdt+16,flat);flat[5]=0x9b;this.write(gdt+8,flat);const gdtr=new Uint8Array(24),g=new DataView(gdtr.buffer);g.setBigUint64(8,BigInt(gdt),true);g.setUint32(16,0x100,true);this.s.e.reg_write(this.s.uc.X86_REG_GDTR,gdtr);for(const [name,value]of [['CS',8],['SS',16],['DS',16],['ES',16],['FS',0x1b]])this.s.e.reg_write_i32(this.s.uc['X86_REG_'+name],value);}
 }
 enterNext(){const e=this.entries.shift();if(!e){this.phase='returned';return false;}this.phase=e.phase;const sp=0x70010000-0x108;this.s.writeReg(this.s.sp,BigInt(sp));this.put(sp,0n);if(this.wide)e.args.forEach((n,i)=>this.s.writeReg(['RCX','RDX','R8','R9'][i],BigInt(n)));else e.args.forEach((n,i)=>this.put(sp+4+i*4,BigInt(n),4));this.s.writeReg(this.s.ip,BigInt(e.address));this.s.status='ready';this.s.reason=e.phase+' ready. Step or Run to begin.';return true;}
 allocate(size,perms=3,requested=0){check(Number.isSafeInteger(size)&&size>0&&size<=4*1024*1024,'Allocation limit: 1 byte–4 MiB.');check(!requested||requested%AREA===0,'Requested allocation address needs 64 KiB alignment.');const length=up(size),at=requested||this.nextHeap;this.map(at,length,perms,'Allocation');this.allocations.set(at,{address:at,size:length,requested:size,perms});if(!requested)this.nextHeap=up(at+length+PAGE);return at;}
 release(at){const r=this.allocations.get(at);if(!r)return false;this.s.e.mem_unmap(at,r.size);this.extra=this.extra.filter(p=>p.address<at||p.address>=at+r.size);this.allocations.delete(at);this.memoryBytes-=r.size;return true;}
 protection(p){check([1,2,4,8,16,32,64,128].includes(p),'Unsupported protection flags.');return ({1:0,2:1,4:3,8:3,16:4,32:5,64:7,128:7})[p];}
 args(count){const sp=Number(this.s.readReg(this.s.sp));return Array.from({length:count},(_,i)=>this.wide&&i<4?this.s.readReg(['RCX','RDX','R8','R9'][i]):this.ptr(sp+(this.wide?0x28+(i-4)*8:4+i*4)));}
 invoke(trap){
  const s=this.s,def=trap.definition,at=s.pc(),before=s.regs();if(!def){this.note(trap.library+'!'+trap.name,'No model; stopped before supplying a result.','unsupported');return s.halt('unsupported','No API model for '+trap.library+'!'+trap.name+'.');}
  const [count,handler,convention]=def;let a=[],result=0n,detail='',behavior='modeled',exit=false;const unsigned=x=>BigInt.asUintN(this.word*8,BigInt(x)),fail=e=>{this.lastError=e;return 0n;};
  try{
   a=this.args(count);const n=a.map(x=>Number(x===unsigned(-1)?-1n:x)),sp=Number(s.readReg(s.sp)),ret=this.ptr(sp);check(n.every(Number.isSafeInteger),'API argument exceeds supported exact range.');
   switch(handler){
    case'allocate':check(n[2]===0x3000||n[2]===0x1000,'VirtualAlloc supports committed allocations, not reservation-only regions.');result=BigInt(this.allocate(n[1],this.protection(n[3]),n[0]));detail='Zero-filled emulated pages.';break;
    case'free':check(n[1]===0&&n[2]===0x8000,'VirtualFree supports MEM_RELEASE with zero size.');result=this.release(n[0])?1n:fail(487);break;
    case'protect':{check(n[0]>=0&&n[1]>0&&n[1]<=4*1024*1024,'Invalid protection range.');const start=down(n[0]),size=up(n[0]+n[1])-start,r=s.region(start,size);check(r&&s.region(n[3],4,2),'Invalid mapping or protection output pointer.');const list=s.plan.mapped.includes(r)?s.plan.mapped:this.extra,pos=list.indexOf(r);check(pos>=0,'Synthetic stack/scratch protection cannot be changed.');const perms=this.protection(n[2]),old=({0:1,1:2,3:4,4:16,5:32,7:64})[r.perms]||1,parts=[];if(start>r.address)parts.push({...r,size:start-r.address});parts.push({...r,address:start,size,perms});if(start+size<r.address+r.size)parts.push({...r,address:start+size,size:r.address+r.size-start-size});this.put(n[3],BigInt(old),4);s.e.mem_protect(start,size,perms);list.splice(pos,1,...parts);result=1n;break;}
    case'heap':result=BigInt(this.heapHandle);break;
    case'heapAlloc':check(n[0]===this.heapHandle&&(n[1]===0||n[1]===8),'Unknown heap or unsupported flags.');result=BigInt(this.allocate(Math.max(1,n[2])));detail='Synthetic heap; fresh pages start at zero.';break;
    case'heapFree':check(n[0]===this.heapHandle&&n[1]===0,'Unknown heap or unsupported flags.');result=this.release(n[2])?1n:0n;break;
    case'realloc':{check(n[0]===this.heapHandle&&(n[1]===0||n[1]===8),'Unknown heap or in-place-only realloc.');const old=this.allocations.get(n[2]);check(old,'Unknown allocation.');const b=this.read(n[2],Math.min(old.requested,n[3])),p=this.allocate(Math.max(1,n[3]));this.write(p,b);this.release(n[2]);result=BigInt(p);break;}
    case'malloc':result=BigInt(this.allocate(Math.max(1,n[0])));break;
    case'calloc':check(Number.isSafeInteger(n[0]*n[1]),'calloc size overflow.');result=BigInt(this.allocate(Math.max(1,n[0]*n[1])));break;
    case'crtFree':if(n[0])check(this.release(n[0]),'Unknown free pointer.');break;
    case'error':result=BigInt(this.lastError);break;
    case'setError':this.lastError=Number(a[0]&0xffffffffn);break;
    case'process':result=unsigned(-1);break;
    case'pid':result=1337n;behavior='synthetic';break;
    case'tid':result=1n;behavior='synthetic';break;
    case'exit':this.exitCode=Number(a[0]&0xffffffffn);exit=true;break;
    case'terminate':check(a[0]===unsigned(-1),'Only the modeled current process can be terminated.');this.exitCode=Number(a[1]&0xffffffffn);exit=true;result=1n;break;
    case'ticks':result=BigInt(this.clock);if(trap.name==='GetTickCount')result&=0xffffffffn;behavior='synthetic';detail='Deterministic session clock.';break;
    case'sleep':check(n[0]>=0&&n[0]<=86400000,'Sleep exceeds one-day model limit.');this.clock+=n[0];behavior='synthetic';detail='Advanced model time; no host wait.';break;
    case'debugger':result=BigInt(s.read(ENV+0x1002,1)[0]);behavior='synthetic';detail='Modeled PEB BeingDebugged byte; initially zero.';break;
    case'moduleA':case'moduleW':case'loadA':case'loadW':{if(!a[0]&&handler.startsWith('module'))result=BigInt(this.info.base);else{const name=this.text(n[0],handler.endsWith('W')),key=canon(name);result=BigInt(this.module(name,handler.startsWith('load')&&(DLLS.has(key)||key.startsWith('api-ms-win-'))));if(!result)this.lastError=126;detail=name+' (API model handle, no DLL code).';}behavior='synthetic';break;}
    case'proc':{const mod=[...this.modules].find(([,h])=>h===n[0]);if(!mod){result=fail(126);break;}const name=n[1]<=65535?'#'+n[1]:this.text(n[1]);result=BigInt(this.trap(mod[0],name));detail=name+' (trap; unimplemented calls stop when invoked).';behavior='synthetic';break;}
    case'commandA':result=BigInt(ENV+0x3000);behavior='synthetic';break;
    case'commandW':result=BigInt(ENV+0x3400);behavior='synthetic';break;
    case'filenameA':case'filenameW':{check(!n[0]||n[0]===this.info.base,'Only main-module filename is modeled.');check(n[2]>=0&&n[2]<=32768,'Filename buffer size exceeds model bounds.');if(!n[2]){result=fail(122);break;}const text=this.filename.slice(0,Math.max(0,n[2]-1));this.string(n[1],text,handler.endsWith('W'));result=BigInt(text.length);if(text.length<this.filename.length){this.lastError=122;result=BigInt(n[2]);}behavior='synthetic';break;}
    case'lengthA':case'lengthW':result=BigInt(this.text(n[0],handler.endsWith('W')).length);break;
    case'copyA':case'copyW':this.string(n[0],this.text(n[1],handler.endsWith('W')),handler.endsWith('W'));result=a[0];break;
    case'move':this.write(n[0],this.read(n[1],n[2]));result=a[0];break;
    case'zero':check(n[1]>=0&&n[1]<=1048576,'API copy cap: 1 MiB.');this.write(n[0],new Uint8Array(n[1]));break;
    case'fill':case'memset':{const size=handler==='fill'?n[1]:n[2],value=handler==='fill'?n[2]:n[1];check(size>=0&&size<=1048576,'API copy cap: 1 MiB.');this.write(n[0],new Uint8Array(size).fill(value&255));result=a[0];break;}
    case'outputA':case'outputW':detail=this.text(n[0],handler.endsWith('W'));this.output=(this.output+detail+'\n').slice(-65536);break;
    case'tlsAlloc':{let i=0;while(this.tlsValues.has(i))i++;check(i<64,'TLS slot cap: 64.');this.tlsValues.set(i,0n);result=BigInt(i);break;}
    case'tlsFree':result=this.tlsValues.delete(n[0])?1n:0n;break;
    case'tlsSet':if(!this.tlsValues.has(n[0]))result=fail(87);else{this.tlsValues.set(n[0],a[1]);result=1n;}break;
    case'tlsGet':if(!this.tlsValues.has(n[0]))result=fail(87);else{result=this.tlsValues.get(n[0]);this.lastError=0;}break;
    case'fileA':case'fileW':{check(!(n[5]&0x40000000),'Overlapped file I/O is unsupported.');const path=this.text(n[0],handler==='fileW').replaceAll('/','\\').toLowerCase();check(path.length<=1024,'Virtual path too long.');let file=this.files.get(path);const disposition=n[4];check([1,2,3,4,5].includes(disposition),'Unknown file disposition.');if((disposition===1&&file)||([3,5].includes(disposition)&&!file)){this.lastError=file?80:2;result=unsigned(-1);break;}check(this.handles.size<256,'Virtual handle cap: 256.');check(this.files.size<64||file,'Virtual file cap: 64.');if(!file){file={path,bytes:new Uint8Array()};this.files.set(path,file);}if([2,5].includes(disposition)){this.fileBytes-=file.bytes.length;file.bytes=new Uint8Array();}check(this.handles.size<256,'Virtual handle cap: 256.');const h=this.nextHandle++;this.handles.set(h,{file,position:0,access:n[1]});result=BigInt(h);detail=path;behavior='virtual filesystem';break;}
    case'readFile':case'writeFile':{check(!a[4],'Overlapped I/O is unsupported.');const h=this.handles.get(n[0]);check(h,'Unknown virtual file handle.');check(n[2]>=0&&n[2]<=1048576,'File I/O cap: 1 MiB/call.');check(!n[3]||s.region(n[3],4,2),'Invalid byte-count output pointer.');if(handler==='readFile'){check(h.access&0x80000000,'File was not opened for reading.');const b=h.file.bytes.slice(h.position,h.position+n[2]);this.write(n[1],b);h.position+=b.length;if(n[3])this.put(n[3],BigInt(b.length),4);}else{check(h.access&0x40000000,'File was not opened for writing.');const b=this.read(n[1],n[2]),size=Math.max(h.file.bytes.length,h.position+b.length),total=this.fileBytes-h.file.bytes.length+size;check(size<=4*1024*1024&&total<=8*1024*1024,'Virtual file storage cap exceeded.');const next=new Uint8Array(size);next.set(h.file.bytes);next.set(b,h.position);this.fileBytes=total;h.file.bytes=next;h.position+=b.length;if(n[3])this.put(n[3],BigInt(b.length),4);}result=1n;detail=h.file.path;behavior='virtual filesystem';break;}
    case'fileSize':{const h=this.handles.get(n[0]);check(h,'Unknown virtual handle.');result=BigInt(h.file.bytes.length);if(n[1])this.put(n[1],0n,4);behavior='virtual filesystem';break;}
    case'filePointer':{const h=this.handles.get(n[0]);check(h&&!n[2]&&n[3]<=2,'Unknown handle, 64-bit seek, or invalid seek mode.');const p=(n[3]===0?0:n[3]===1?h.position:h.file.bytes.length)+Number(BigInt.asIntN(32,a[1]));check(p>=0&&p<=4*1024*1024,'Seek outside virtual file bounds.');h.position=p;result=BigInt(p);behavior='virtual filesystem';break;}
    case'close':result=this.handles.delete(n[0])?1n:fail(6);break;
    default:throw Error('API handler missing.');
   }
   if(!this.wide&&trap.name==='GetTickCount64')s.writeReg('EDX',BigInt.asUintN(32,result>>32n));result=unsigned(result);s.writeReg(this.wide?'RAX':'EAX',result);
   if(exit){s.halt('exited','Modeled Windows process exited with code '+this.exitCode+'.');this.phase='exited';}
   else{s.writeReg(s.sp,BigInt(sp+this.word+(!this.wide&&convention!=='cdecl'?count*4:0)));s.writeReg(s.ip,ret);s.status='stepped';s.reason='Modeled '+trap.name+'.';}
   this.note(trap.library+'!'+trap.name,detail,behavior,{arguments:a.map(hx),result:hx(result)});
  }catch(error){this.note(trap.library+'!'+trap.name,error.message,'unsupported',{arguments:a.map(hx)});s.halt('unsupported',trap.name+': '+error.message+' State may be partial.');}
  s.steps++;const after=s.regs();s.trace.push({step:s.steps,address:at,mnemonic:'API',operands:trap.library+'!'+trap.name,changes:Object.fromEntries(s.names.filter(n=>before[n]!==after[n]).map(n=>[n,{before:before[n],after:after[n]}])),writes:[],partial:s.stopped&&!exit,api:true});if(s.trace.length>200)s.trace.shift();s.breakAt=null;return !s.stopped;
 }
 snapshot(){return {phase:this.phase,imageBase:this.info.base,entry:this.info.entry,peb:ENV+0x1000,teb:ENV,memoryBytes:this.memoryBytes,modules:[...this.modules].map(([name,handle])=>({name,handle})),allocations:[...this.allocations.values()],events:this.events,eventCount:this.eventCount,lastError:this.lastError,clock:this.clock,exitCode:this.exitCode,files:[...this.files.values()].map(f=>({path:f.path,size:f.bytes.length})),output:this.output,warnings:this.info.warnings};}
}
function demo(mode='x64'){
 const wide=mode==='x64',base=wide?0x140000000:0x400000,b=new Uint8Array(0x800),v=new DataView(b.buffer),w16=(o,n)=>v.setUint16(o,n,true),w32=(o,n)=>v.setUint32(o,n,true),ptr=(o,n)=>wide?v.setBigUint64(o,BigInt(n),true):w32(o,n),text=(o,s)=>b.set(new TextEncoder().encode(s+'\0'),o);
 w16(0,0x5a4d);w32(0x3c,0x80);w32(0x80,0x4550);w16(0x84,wide?0x8664:0x14c);w16(0x86,3);const opt=0x98,os=wide?240:224;w16(0x94,os);w16(0x96,0x22);w16(opt,wide?0x20b:0x10b);w32(opt+16,0x1000);if(wide)ptr(opt+24,base);else w32(opt+28,base);w32(opt+32,4096);w32(opt+36,512);w32(opt+56,0x4000);w32(opt+60,512);w16(opt+68,3);w32(opt+(wide?108:92),16);
 const dd=opt+(wide?112:96);w32(dd+8,0x2000);w32(dd+12,40);
 const section=(i,name,rva,rawOffset,rawSize,virtualSize,flags)=>{const o=opt+os+i*40;text(o,name);w32(o+8,virtualSize);w32(o+12,rva);w32(o+16,rawSize);w32(o+20,rawOffset);w32(o+36,flags);};
 section(0,'.text',0x1000,0x200,0x200,0x200,0x60000020);section(1,'.data',0x2000,0x400,0x400,0x1000,0xc0000040);section(2,'.bss',0x3000,0,0,0x1000,0xc0000080);
 w32(0x400,0x2040);w32(0x40c,0x20c0);w32(0x410,0x2080);text(0x4c0,'kernel32.dll');text(0x500,'SPECTRA: hello from the Windows model');text(0x700,'C:\\spectra-demo.txt');
 const names=['OutputDebugStringA','GetTickCount','Sleep','ExitProcess','CreateFileA','WriteFile'],rvas=[0x2140,0x2170,0x2190,0x21b0,0x21d0,0x21f0];names.forEach((name,i)=>{ptr(0x440+i*(wide?8:4),rvas[i]);ptr(0x480+i*(wide?8:4),rvas[i]);text(0x400+rvas[i]-0x2000+2,name);});
 const code=[],emit=(...a)=>code.push(...a),u32=n=>[n&255,n>>>8&255,n>>>16&255,n>>>24&255],call=i=>{if(wide){const displacement=0x2080+i*8-(0x1000+code.length+6);emit(0xff,0x15,...u32(displacement));}else emit(0xff,0x15,...u32(base+0x2080+i*4));};
 if(wide){emit(0x48,0x83,0xec,0x48);emit(0x48,0x8d,0x0d,...u32(0x2100-(0x1000+code.length+7)));}else emit(0x68,...u32(base+0x2100));call(0);call(1);if(wide)emit(0xb9,25,0,0,0);else emit(0x6a,25);call(2);
 if(wide){emit(0x48,0x8d,0x0d,...u32(0x2300-(0x1000+code.length+7)),0xba,0,0,0,0xc0,0x45,0x31,0xc0,0x45,0x31,0xc9,0x48,0xc7,0x44,0x24,0x20,2,0,0,0,0x48,0xc7,0x44,0x24,0x28,0,0,0,0,0x48,0xc7,0x44,0x24,0x30,0,0,0,0);call(4);emit(0x48,0x89,0xc1);emit(0x48,0x8d,0x15,...u32(0x2100-(0x1000+code.length+7)),0x41,0xb8,37,0,0,0,0x41,0xb9,0,0,0,0x60,0x48,0xc7,0x44,0x24,0x20,0,0,0,0);call(5);}
 else{emit(0x6a,0,0x6a,0,0x6a,2,0x6a,0,0x6a,0,0x68,0,0,0,0xc0,0x68,...u32(base+0x2300));call(4);emit(0x6a,0,0x68,0,0,0,0x60,0x6a,37,0x68,...u32(base+0x2100),0x50);call(5);}
 if(wide)emit(0x31,0xc9);else emit(0x6a,0);call(3);emit(0xcc);b.set(code,0x200);return b;
}

root.SpectraWindows={prepare,Environment,APIS,apiSupport,apiKey:(library,name)=>canon(library)+'!'+name,ENV,STUB,demo};if(typeof module!=='undefined')module.exports=root.SpectraWindows;
})(globalThis);
