/* SPECTRA local CPU sessions. Guest code only runs in Unicorn's WASM memory.
   Optional bounded Windows model; no host calls, networking, or native launch. */
(function(root){
'use strict';
const PAGE=4096,MAX_MEMORY=16*1024*1024,MAX_STEPS=100000,STACK=0x70000000,SCRATCH=0x60000000,AREA=65536;
const hex=n=>'0x'+BigInt(n).toString(16).toUpperCase();
function address(value){if(typeof value==='string'&&!/^(?:0x[0-9a-f]+|\d+)$/i.test(value.trim()))throw Error('Use a decimal address or hex with 0x.');const n=Number(value);if(!Number.isSafeInteger(n)||n<0)throw Error('Address exceeds the supported exact range.');return n;}
function prepare(bytes,meta,options={}){
 if(options.environment==='linux')return root.SpectraLinux.prepare(bytes,meta,options);
 if(options.environment&&!['routine','windows'].includes(options.environment))throw Error('Unknown execution environment.');
 if(options.environment==='windows'){if(options.raw)throw Error('Windows mode needs a complete PE image, not a raw range.');return root.SpectraWindows.prepare(bytes,options);}
 const mode=options.mode||({'x86':'x86','x86-64':'x64'})[meta.architecture];
 if(!['x86','x64'].includes(mode))throw Error('Debugger lab currently supports x86 and x64. Choose a raw range for other file formats.');
 const valid=(n)=>Number.isSafeInteger(n)&&n>=0,maxAddress=mode==='x86'?0x100000000:0x800000000000;
 let regions;
 if(options.raw){const {offset,size,base}=options.raw;if(![offset,size,base].every(valid)||!size||offset>bytes.length-size)throw Error('Raw range is outside the file.');regions=[{name:'Selected raw bytes',address:base,offset,size,permissions:'RWX'}];}
 else regions=(meta.mappings||[]).filter(m=>m.size>0).map(m=>({name:m.name,address:m.address,offset:m.offset,size:m.size,permissions:m.permissions}));
 if(!regions.length||regions.length>256)throw Error('Need 1–256 file-backed mappings. Choose a smaller raw range.');
 const sorted=[...regions].sort((a,b)=>a.address-b.address);for(let i=1;i<sorted.length;i++)if(sorted[i].address<sorted[i-1].address+sorted[i-1].size)throw Error('Overlapping file-backed mappings are ambiguous. Choose a raw range.');
 const pages=new Map();let total=0;
 for(const r of regions){
  if(![r.address,r.offset,r.size].every(valid)||r.address+r.size>maxAddress||r.offset>bytes.length-r.size)throw Error('Invalid or unsupported memory mapping.');
  if(r.address<PAGE||r.address<STACK+AREA&&r.address+r.size>STACK||r.address<SCRATCH+AREA&&r.address+r.size>SCRATCH)throw Error('File mapping overlaps the session stack, scratch space, or null page. Choose a raw base.');
  const start=Math.floor(r.address/PAGE)*PAGE,end=Math.ceil((r.address+r.size)/PAGE)*PAGE;
  if(end-start>MAX_MEMORY)throw Error('Session exceeds the 16 MiB mapped-memory limit. Choose a smaller raw range.');
  const perms=(r.permissions.includes('R')?1:0)|(r.permissions.includes('W')?2:0)|(r.permissions.includes('X')?4:0);
  for(let p=start;p<end;p+=PAGE){if(!pages.has(p))total+=PAGE;pages.set(p,(pages.get(p)||0)|perms);}
 }
 if(total+AREA*2>MAX_MEMORY)throw Error('Session exceeds the 16 MiB mapped-memory limit. Choose a smaller raw range.');
 const start=address(options.start??meta.entry??regions.find(r=>r.permissions.includes('X'))?.address);
 if(!regions.some(r=>r.permissions.includes('X')&&start>=r.address&&start<r.address+r.size))throw Error('Start address must be inside the selected executable bytes.');
 const mapped=[];for(const [at,perms]of [...pages].sort((a,b)=>a[0]-b[0])){const last=mapped[mapped.length-1];if(last&&last.address+last.size===at&&last.perms===perms)last.size+=PAGE;else mapped.push({address:at,size:PAGE,perms});}
 return {mode,start,regions,mapped,memoryBytes:total+AREA*2,stack:STACK,scratch:SCRATCH,areaSize:AREA};
}
class Session{
 constructor(uc,cs,bytes,meta,options={}){
  this.uc=uc;this.cs=cs;this.plan=prepare(bytes,meta,options);this.mode=this.plan.mode;this.steps=0;this.trace=[];this.edits=[];this.status='ready';this.reason='Session ready. Nothing has stepped yet.';this.breakAt=null;this.stopped=false;
  this.journal=[];this.attempts=0;this.frames=[];this.watchpoints=[];this.hits=[];this.executing=false;
  this.names=this.mode==='x64'?['RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','R8','R9','R10','R11','R12','R13','R14','R15','RIP','EFLAGS']:['EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP','EFLAGS'];
  this.ip=this.mode==='x64'?'RIP':'EIP';this.sp=this.mode==='x64'?'RSP':'ESP';this.word=this.mode==='x64'?8:4;
  this.e=new uc.Unicorn(uc.ARCH_X86,this.mode==='x64'?uc.MODE_64:uc.MODE_32);
  try{
   for(const m of this.plan.mapped){this.e.mem_map(m.address,m.size,m.perms);this.e.mem_write(m.address,new Uint8Array(m.size));}
   for(const r of this.plan.regions)this.e.mem_write(r.address,bytes.subarray(r.offset,r.offset+(r.fileSize??r.size)));
   this.e.mem_map(STACK,AREA,3);this.e.mem_map(SCRATCH,AREA,3);this.e.mem_write(STACK,new Uint8Array(AREA));this.e.mem_write(SCRATCH,new Uint8Array(AREA));
   for(const n of this.names)this.writeReg(n,n==='EFLAGS'?2n:0n);
   this.writeReg(this.sp,BigInt(STACK+AREA-0x108));this.writeReg(this.ip,BigInt(this.plan.start));
   this.d=new cs.Capstone(cs.ARCH_X86,this.mode==='x64'?cs.MODE_64:cs.MODE_32);this.d.option(cs.OPT_DETAIL,cs.OPT_ON);
   // Use the stable native instruction layout (see code.js).
   cs.Instruction=function(p){this.address=cs.getValue(p+8,'i64');this.size=cs.getValue(p+16,'i16');this.bytes=[];for(let j=0;j<this.size;j++)this.bytes.push(cs.getValue(p+18+j,'i8')&255);this.mnemonic=cs.UTF8ToString(p+42);this.op_str=cs.UTF8ToString(p+74);};
   if(this.plan.environment==='windows')new root.SpectraWindows.Environment(this,bytes,options);
   this.hook=this.e.hook_add(uc.HOOK_MEM_WRITE,(_e,_type,at,size)=>{
    this.noteAccess('write',Number(at),size,'cpu');
    if(!this.pending)return;
    this.writeEvents++;
    if(this.writeEvents>1024){this.writeLimit=true;this.e.emu_stop();return;}
    const a=Number(at);if(!Number.isSafeInteger(a)||size>256)return;
    if([...this.plan.mapped,...(this.windows?.extra||[]),...(this.lab?.extra||[])].some(r=>(r.perms&4)&&a<r.address+r.size&&a+size>r.address)){this.execWrite=true;this.e.emu_stop();}
    if(!this.region(a,size,2)){this.badWrite=true;this.e.emu_stop();return;}
    if(this.pending.length<32){let before;try{before=Array.from(this.e.mem_read(a,size));}catch{before=[];}this.pending.push({address:a,size,before});}
   });
   this.readHook=this.e.hook_add(uc.HOOK_MEM_READ_AFTER,(_e,_type,at,size)=>this.noteAccess('read',Number(at),size,'cpu'));
  }catch(err){this.close();throw err;}
 }
 close(){for(const name of ['hook','readHook'])if(this[name]){this.e.hook_del(this[name]);this[name]=null;}if(this.d){this.d.close();this.d=null;}if(this.e){this.e.close();this.e=null;}}
 readReg(name){const id=this.uc['X86_REG_'+name];return this.mode==='x64'&&name!=='EFLAGS'?BigInt.asUintN(64,this.e.reg_read_i64(id)):BigInt(this.e.reg_read_i32(id)>>>0);}
 writeReg(name,value){const id=this.uc['X86_REG_'+name];if(this.mode==='x64'&&name!=='EFLAGS')this.e.reg_write_i64(id,BigInt.asIntN(64,value));else this.e.reg_write_i32(id,Number(BigInt.asIntN(32,value)));}
 regs(){return Object.fromEntries(this.names.map(n=>[n,hex(this.readReg(n))]));}
 pc(){return address(this.readReg(this.ip));}
 region(at,size=1,permission=0){return [...this.plan.mapped,...(this.windows?.extra||[]),{address:STACK,size:AREA,perms:3},{address:SCRATCH,size:AREA,perms:3}].find(r=>at>=r.address&&size<=r.size-(at-r.address)&&(r.perms&permission)===permission);}
 read(at,size){at=address(at);if(!Number.isSafeInteger(size)||size<1||size>65536||!this.region(at,size))throw Error('Read needs 1–65,536 bytes inside one mapped region.');return Uint8Array.from(this.e.mem_read(at,size));}
 decode(at){
  const api=this.windows?.api.get(at);if(api)return {address:at,size:16,bytes:[],mnemonic:'API',operands:api.library+'!'+api.name,privileged:false};
  const region=this.region(at,1,4);if(!region)return null;let row=null;
  this.d.disasm_iter(this.e.mem_read(at,Math.min(15,region.address+region.size-at)),at,(i,p)=>{row={address:at,size:i.size,bytes:i.bytes,mnemonic:i.mnemonic,operands:i.op_str,privileged:this.d.insn_group(p,this.cs.GRP_PRIVILEGE)};return false;});return row;
 }
 halt(status,reason){this.status=status;this.reason=reason;this.stopped=!['paused','breakpoint','watchpoint','target','ready','stepped','budget'].includes(status);return false;}
 step(){
  if(this.stopped)return false;
  this.attempts++;const last=this.journal.at(-1);if(last?.kind==='steps')last.count++;else this.journal.push({kind:'steps',count:1});
  if(this.attempts>100000)return this.halt('limit','Session reached 100,000 attempted steps. Reset for a fresh experiment.');
  let instruction,sp,phase=this.windows?.phase;try{instruction=this.decode(this.pc());sp=this.readReg(this.sp);}catch{}
  this.hits=[];this.hitsTruncated=false;this.executing=true;let ok;try{ok=this._step();}finally{this.executing=false;}
  let pc;try{pc=this.pc();}catch{return ok;}const now=this.readReg(this.sp),op=instruction?.mnemonic.split(' ').pop();
  if(phase!==this.windows?.phase)this.frames=[];
  else if(ok&&op==='call'&&now<sp)this.frames.push({returnAddress:instruction.address+instruction.size,stack:hex(sp)});
  else if((op==='ret'||op==='API')&&this.frames.length){const frame=this.frames.at(-1);if(pc===frame.returnAddress&&now>=BigInt(frame.stack))this.frames.pop();else if(op==='ret')this.frames=[];}
  if(this.hits.length&&!this.stopped)return this.halt('watchpoint','Watchpoint hit after '+(op==='API'?'the modeled API':'the instruction')+'. Inspect the completed access below.');
  return ok;
 }
 noteAccess(kind,at,size,source){
  if(!this.executing||!Number.isSafeInteger(at)||!Number.isSafeInteger(size)||size<1)return;
  for(const w of this.watchpoints)if(w.access.includes(kind)&&at<w.address+w.size&&at+size>w.address){if(this.hits.length<32)this.hits.push({kind,address:at,size,source,watchAddress:w.address});else this.hitsTruncated=true;}
 }
 setWatchpoints(points=[]){
  if(!Array.isArray(points)||points.length>32)throw Error('Use at most 32 watchpoints.');
  this.watchpoints=points.map(w=>{const at=address(w.address),size=Number(w.size);if(!Number.isSafeInteger(size)||size<1||size>65536||!Number.isSafeInteger(at+size)||!['read','write','read/write'].includes(w.access))throw Error('Watchpoint needs read/write access and a range of 1–65,536 bytes.');return {address:at,size,access:w.access};});
 }
 breakpoint(p){
  const at=address(typeof p==='object'?p.address:p),c=typeof p==='object'?p.condition:null;
  if(!c)return {address:at};
  if(!this.names.includes(c.register)||!['==','!=','<','<=','>','>='].includes(c.operator)||!/^(?:0x[0-9a-f]+|\d+)$/i.test(String(c.value)))throw Error('Invalid register breakpoint condition.');
  const value=BigInt(c.value),bits=this.mode==='x64'&&c.register!=='EFLAGS'?64:32;if(value>=(1n<<BigInt(bits)))throw Error('Condition value does not fit the register.');
  return {address:at,condition:{register:c.register,operator:c.operator,value:value.toString()}};
 }
 conditionMatches(c){if(!c)return true;const a=this.readReg(c.register),b=BigInt(c.value);return {'==':a===b,'!=':a!==b,'<':a<b,'<=':a<=b,'>':a>b,'>=':a>=b}[c.operator];}
 runTarget(kind){
  if(kind==='out'){const f=this.frames.at(-1);if(!f)throw Error('No observed caller. Step into a call first, or set your own return breakpoint.');return {...f};}
  const i=this.decode(this.pc());return i?.mnemonic==='call'?{returnAddress:i.address+i.size,stack:hex(this.readReg(this.sp))}:null;
 }
 _step(){
  if(this.stopped)return false;
  if(this.steps>=MAX_STEPS)return this.halt('limit','Session reached 100,000 instructions. Reset to start a fresh session.');
  let pc,i;try{pc=this.pc();if(pc===0){if(this.windows?.enterNext())pc=this.pc();else return this.halt('returned','Returned to the session boundary.');}const api=this.windows?.api.get(pc);if(api)return this.windows.invoke(api);i=this.decode(pc);}catch(err){return this.halt('fault',String(err.message||err));}
  if(!i)return this.halt('fault','No supported executable instruction at '+hex(pc)+'. Unmapped calls and OS imports are not supplied.');
  const op=i.mnemonic.split(' ').pop();
  if(i.privileged||/^(?:syscall|sysenter|sysexit|sysretq?|int|int1|int3|into|iret.*|in|ins[bwd]?|out|outs[bwd]?|hlt|ud2|vmcall|vmmcall|rdmsr|wrmsr|cpuid|rdtsc|rdtscp|rdrand|rdseed|retf.*)$/.test(op))return this.halt('unsupported','Stopped before '+i.mnemonic+'. OS, device, privileged, and environment-dependent operations are not emulated here.');
  const before=this.regs();this.pending=[];this.writeEvents=0;this.writeLimit=false;this.execWrite=false;this.badWrite=false;let fault='';
  try{this.e.emu_start(BigInt(pc),op==='ret'?0n:BigInt(pc+i.size),0,1);}catch(err){fault=String(err.message||err).slice(0,600);}
  const writes=this.pending.map(w=>{let after=[];try{after=Array.from(this.e.mem_read(w.address,w.size));}catch{}return {...w,after};});this.pending=null;
  const after=this.regs(),changes=Object.fromEntries(this.names.filter(n=>before[n]!==after[n]).map(n=>[n,{before:before[n],after:after[n]}]));
  this.steps++;this.trace.push({...i,step:this.steps,changes,writes,writesTruncated:this.writeEvents>32,partial:!!fault||this.writeLimit||this.execWrite||this.badWrite});if(this.trace.length>200)this.trace.shift();
  this.breakAt=null;
  if(this.badWrite)return this.halt('fault','Stopped on an unmapped or non-writable memory write. No missing memory was supplied; state may be partial.');
  if(this.execWrite)return this.halt('unsupported','Stopped on a write into executable memory. Self-modifying code is outside this first debugger release; inspect state before continuing.');
  if(this.writeLimit)return this.halt('limit','Stopped during a large memory operation (1,024 writes in one step). State may be partial.');
  if(fault)return this.halt('fault',fault+' No missing memory or API behavior was invented; state may be partial.');
  try{if(this.pc()===0){if(this.windows?.enterNext())return true;return this.halt('returned','Returned to the session boundary.');}}catch{return this.halt('fault','Instruction pointer left the supported exact address range.');}
  this.status='stepped';this.reason='Stepped '+i.mnemonic+'.';return true;
 }
 advance(count,breakpoints=[],skipCurrent=false,target=null){
  if(!Number.isSafeInteger(count)||count<1||count>10000)throw Error('Run budget must be 1–10,000 instructions.');
  if(!Array.isArray(breakpoints)||breakpoints.length>128)throw Error('Use at most 128 breakpoints.');
  const points=breakpoints.map(p=>this.breakpoint(p));let n=0;
  while(n<count&&!this.stopped){const pc=this.pc();if(target&&pc===target.returnAddress&&this.readReg(this.sp)>=BigInt(target.stack)){this.halt('target','Reached the observed return boundary.');break;}if(points.some(p=>p.address===pc&&this.conditionMatches(p.condition))&&!(skipCurrent&&n===0)){this.breakAt=pc;this.halt('breakpoint','Breakpoint at '+hex(pc)+'.');break;}if(!this.step()){n++;break;}n++;}
  if(!this.stopped&&!['breakpoint','watchpoint'].includes(this.status)&&target&&this.pc()===target.returnAddress&&this.readReg(this.sp)>=BigInt(target.stack))this.halt('target','Reached the observed return boundary.');
  if(!this.stopped&&!['breakpoint','watchpoint','target'].includes(this.status)){this.status='budget';this.reason='Paused after '+n+' instructions.';}
  return n;
 }
 editRegister(name,value){
  if(!this.names.includes(name))throw Error('Choose a general register, IP, SP, or flags.');
  const raw=String(value).trim();if(!/^(?:0x[0-9a-f]+|\d+)$/i.test(raw))throw Error('Register value must be unsigned decimal or hex with 0x.');
  const v=BigInt(raw),bits=this.mode==='x64'&&name!=='EFLAGS'?64:32;if(v>=(1n<<BigInt(bits)))throw Error('Value does not fit this register.');
  if(name===this.ip){address(v);if(!this.region(Number(v),1,4))throw Error('Instruction pointer must be in executable session memory.');}
  if(this.edits.length>=200)throw Error('Edit log is full. Reset for a fresh session.');
  const before=hex(this.readReg(name));this.writeReg(name,v);this.edits.push({step:this.steps,register:name,before,after:hex(v)});this.journal.push({kind:'register',name,value:hex(v)});if(name===this.ip||name===this.sp)this.frames=[];this.stopped=false;this.breakAt=null;this.status='paused';this.reason='Register updated. This is an analyst-supplied value.';
 }
 patch(at,bytes){
  at=address(at);if(!(bytes instanceof Uint8Array)||!bytes.length||bytes.length>4096||!this.region(at,bytes.length))throw Error('Patch needs 1–4,096 bytes inside one mapped region.');
  if(this.edits.length>=200)throw Error('Edit log is full. Reset for a fresh session.');
  const before=Array.from(this.read(at,bytes.length));this.e.mem_write(at,bytes);this.edits.push({step:this.steps,address:at,before,after:Array.from(bytes)});this.journal.push({kind:'patch',address:at,bytes:Array.from(bytes)});this.status='paused';this.reason='Session memory patched. The original file is unchanged.';this.stopped=false;this.breakAt=null;
 }
 snapshot(memoryAddress){
  let pc;try{pc=this.pc();}catch{pc=null;}
  const assembly=[];let at=pc;for(let n=0;n<16&&at!==null;n++){try{const i=this.decode(at);if(!i)break;assembly.push(i);at+=i.size;}catch{break;}}
  let memory=null;if(memoryAddress!==undefined){try{const a=address(memoryAddress),r=this.region(a);if(r)memory={address:a,bytes:Array.from(this.read(a,Math.min(256,r.address+r.size-a)))};}catch{}}
  const flags=Number(this.readReg('EFLAGS'));
  return {mode:this.mode,pc,attempts:this.attempts,frames:this.frames,watchpoints:this.watchpoints,hits:this.hits,hitsTruncated:this.hitsTruncated,registers:this.regs(),flags:Object.fromEntries([[0,'CF'],[2,'PF'],[4,'AF'],[6,'ZF'],[7,'SF'],[8,'TF'],[9,'IF'],[10,'DF'],[11,'OF']].map(([b,n])=>[n,(flags>>>b)&1])),steps:this.steps,status:this.status,reason:this.reason,stopped:this.stopped,assembly,trace:this.trace,edits:this.edits,memory,plan:this.plan,windows:this.windows?.snapshot(),mappings:[...this.plan.mapped,...(this.windows?.extra||[]),{address:STACK,size:AREA,perms:3,name:'Stack'},{address:SCRATCH,size:AREA,perms:3,name:'Scratch'}]};
 }
}
function demo(){const text=new TextEncoder().encode('https://decoded.example/config\u0000'),b=new Uint8Array(34+text.length);b.set([0x48,0x8d,0x35,27,0,0,0,0xbf,0,0,0,0x60,0xb9,text.length,0,0,0,0x8a,6,0x34,0x5a,0x88,7,0x48,0xff,0xc6,0x48,0xff,0xc7,0xff,0xc9,0x75,0xf0,0xc3]);b.set(text.map(n=>n^0x5a),34);return b;}
root.SpectraDebug={demo,prepare,Session,address,hex,MAX_MEMORY,MAX_STEPS,STACK,SCRATCH,AREA};if(typeof module!=='undefined')module.exports=root.SpectraDebug;
})(globalThis);
