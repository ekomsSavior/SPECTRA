/* Analyst-defined experiments. Recipes are bounded data, never evaluated scripts. */
(function(root){
'use strict';
const D=root.SpectraDebug,P=4096,SCHEMA='spectra-lab-v1',MAX_TEXT=262144;
const check=(v,m)=>{if(!v)throw Error(m);},hexBytes=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
function bytes(h){check(typeof h==='string'&&h.length<=131072&&/^(?:[0-9a-f]{2})*$/i.test(h),'Use an even number of hex digits, at most 64 KiB.');return Uint8Array.from(h.match(/../g)||[],x=>parseInt(x,16));}
function num(v,max=Number.MAX_SAFE_INTEGER){const n=D.address(v);check(n<=max,'Number exceeds the allowed range.');return n;}
function value(v,bits=64){check(typeof v==='string'||typeof v==='number'&&Number.isSafeInteger(v),'Use an integer or a decimal/0x string.');check(String(v).length<=20&&/^(?:0x[0-9a-f]+|\d+)$/i.test(String(v)),'Use unsigned decimal or 0x hexadecimal.');const n=BigInt(v);check(n<(1n<<BigInt(bits)),'Integer does not fit the selected ABI.');return n;}
function list(x,max){check(Array.isArray(x)&&x.length<=max,'Recipe collection exceeds its limit.');return x;}
function text(x,max){check(typeof x==='string'&&x.length<=max&&!x.includes('\0'),'Invalid or oversized recipe text.');return x;}
function exact(o,keys){check(o&&typeof o==='object'&&!Array.isArray(o),'Expected a recipe object.');for(const k of Object.keys(o))check(keys.includes(k),'Unknown recipe field: '+k);return o;}
function validate(input={}){
 check(JSON.stringify(input).length<=MAX_TEXT,'Recipe cap: 256 KiB.');exact(input,['schema','label','harness','regions','buffers','registers','hooks','mmio','files','argv','env','stdin']);
 const r=structuredClone(input);r.schema=r.schema||SCHEMA;check(r.schema===SCHEMA,'Unsupported lab recipe schema.');r.label=text(r.label||'Untitled experiment',100);
 r.regions=list(r.regions||[],16).map(x=>{exact(x,['address','size','permissions','hex','name']);const q={address:num(x.address),size:num(x.size,1048576),permissions:x.permissions||'RW',hex:x.hex||'',name:text(x.name||'Analyst region',80)};check(q.address>=P&&q.address%P===0&&q.size>0&&q.size%P===0&&['R','RW','RX','RWX'].includes(q.permissions),'Regions need page-aligned addresses/sizes and R, RW, RX or RWX permissions.');check(bytes(q.hex).length<=q.size,'Initial region bytes exceed its size.');return q;});check(r.regions.reduce((n,x)=>n+x.size,0)<=1048576,'Recipe region budget: 1 MiB.');
 const ids=new Set();let total=0;r.buffers=list(r.buffers||[],16).map(x=>{exact(x,['name','hex','size','address']);const name=text(x.name,40);check(/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)&&!ids.has(name),'Buffer names must be unique identifiers.');ids.add(name);const hex=x.hex||'',b=bytes(hex),size=x.size===undefined?Math.max(b.length,1):num(x.size,4096);check(size>0&&b.length<=size,'Buffer size must contain its initial bytes, up to 4096.');total+=size;return {name,hex,size,...(x.address===undefined?{}:{address:num(x.address)})};});check(total<=32768,'Buffer budget: 32 KiB.');
 const arg=x=>{if(x&&typeof x==='object'){exact(x,['buffer','offset']);check(ids.has(x.buffer),'Unknown argument buffer.');const offset=num(x.offset||0,4096),b=r.buffers.find(b=>b.name===x.buffer);check(offset<b.size,'Argument offset outside buffer.');return {buffer:x.buffer,offset};}return value(x).toString();};
 if(r.harness){exact(r.harness,['abi','arguments']);text(r.harness.abi,20);r.harness={abi:r.harness.abi,arguments:list(r.harness.arguments||[],16).map(arg)};}
 r.registers=r.registers||{};exact(r.registers,Object.keys(r.registers));check(Object.keys(r.registers).length<=32,'Register setup limit: 32.');for(const [k,v]of Object.entries(r.registers)){check(/^[A-Z][A-Z0-9]{0,7}$/.test(k),'Invalid register name.');r.registers[k]=value(v).toString();}
 r.hooks=list(r.hooks||[],32).map(x=>{exact(x,['address','api','abi','argc','result','writes','label']);check((x.address!==undefined)!==(x.api!==undefined),'Hook needs one address or DLL!API name.');const h={...x,abi:text(x.abi,20),argc:num(x.argc||0,16),result:arg(x.result??'0'),label:text(x.label||'Analyst response',100)};if(x.address!==undefined)h.address=num(x.address);else{h.api=text(x.api,180);check(/^[^!]+![^!]+$/.test(h.api),'Use DLL!API, including the DLL extension.');}h.writes=list(x.writes||[],8).map(w=>{exact(w,['argument','offset','hex']);const q={argument:num(w.argument,15),offset:num(w.offset||0,65536),hex:w.hex||''};check(q.argument<h.argc,'Hook write argument is outside argc.');check(bytes(q.hex).length<=4096,'Hook write cap: 4096 bytes.');return q;});return h;});
 const hookIds=r.hooks.map(h=>h.address!==undefined?'address:'+h.address:'api:'+h.api.toLowerCase());check(new Set(hookIds).size===hookIds.length,'Duplicate hooks are ambiguous.');
 r.mmio=list(r.mmio||[],32).map(x=>{exact(x,['address','width','values','onExhaustion','write','label']);const q={address:num(x.address),width:num(x.width,4),values:list(x.values||[],256).map(v=>value(v,(x.width||4)*8).toString()),onExhaustion:x.onExhaustion||'stop',write:x.write||'stop',label:text(x.label||'Modeled register',80)};check([1,2,4].includes(q.width)&&q.address>=P&&q.address%q.width===0&&['stop','hold'].includes(q.onExhaustion)&&['stop','capture'].includes(q.write),'Invalid MMIO register definition.');return q;});for(let i=0;i<r.mmio.length;i++)for(let j=0;j<i;j++)check(r.mmio[i].address>=r.mmio[j].address+r.mmio[j].width||r.mmio[i].address+r.mmio[i].width<=r.mmio[j].address,'Overlapping MMIO registers.');
 total=0;r.files=list(r.files||[],32).map(x=>{exact(x,['path','hex']);const path=text(x.path,512),hex=x.hex||'';total+=bytes(hex).length;return {path,hex};});check(total<=131072&&new Set(r.files.map(f=>f.path)).size===r.files.length,'Virtual files must be unique, within a 128 KiB input budget.');
 r.argv=list(r.argv||[],32).map(x=>text(x,1024));r.env=list(r.env||[],32).map(x=>{text(x,1024);check(/^[^=]+=.*/.test(x),'Environment entries need NAME=value.');return x;});r.stdin=r.stdin||'';bytes(r.stdin);return r;
}
function abi(s,name){
 const all={sysv64:{mode:['x64'],args:['RDI','RSI','RDX','RCX','R8','R9'],ret:'RAX',word:8,stack:8},win64:{mode:['x64'],args:['RCX','RDX','R8','R9'],ret:'RAX',word:8,stack:40},cdecl:{mode:['x86'],args:[],ret:'EAX',word:4,stack:4},stdcall:{mode:['x86'],args:[],ret:'EAX',word:4,stack:4,clean:true},aapcs32:{mode:['arm','thumb'],args:['R0','R1','R2','R3'],ret:'R0',word:4,stack:0,link:'LR'},aapcs64:{mode:['aarch64'],args:Array.from({length:8},(_,i)=>'X'+i),ret:'X0',word:8,stack:0,link:'LR'}};
 const a=all[name];check(a&&a.mode.includes(s.mode),'ABI '+name+' does not match '+s.mode+'. Integer/pointer arguments only.');return a;
}
class Lab{
 constructor(s,recipe){this.s=s;this.recipe=validate(recipe);this.extra=[];this.buffers=[];this.events=[];this.eventCount=0;this.coverage=new Map();this.edges=new Map();this.coverageTruncated=false;this.mmio=this.recipe.mmio.map(x=>({...x,index:0,writes:[]}));this.mmioPages=new Set();this.lastError=null;this.hooks=[];this.resultRegister=({x64:'RAX',x86:'EAX',arm:'R0',thumb:'R0',aarch64:'X0',riscv32:'A0',riscv64:'A0',mips32:'V0',mips64:'V0'})[s.mode];}
 event(kind,data){this.events.push({id:++this.eventCount,step:this.s.steps,kind,...data});if(this.events.length>256)this.events.shift();}
 map(address,size,perms,name){const s=this.s,regions=s.e.mem_regions();check(Number.isSafeInteger(address+size)&&address>=P&&address%P===0&&size>0&&size%P===0&&address+size<=(s.word===4?0x100000000:0x800000000000),'Invalid experiment mapping.');check(!regions.some(r=>address<=Number(r.end)&&address+size>Number(r.begin)),'Experiment mapping overlaps existing memory.');check(regions.reduce((n,r)=>n+Number(r.end)-Number(r.begin)+1,0)+size<=D.MAX_MEMORY,'16 MiB total memory budget reached.');s.e.mem_map(address,size,perms);s.e.mem_write(address,new Uint8Array(size));this.extra.push({address,size,perms,name});}
 read(at,size){check(Number.isSafeInteger(at)&&Number.isInteger(size)&&size>=0&&size<=65536,'Invalid modeled read.');if(!size)return new Uint8Array();check(this.s.region(at,size,1),'Modeled read outside readable memory.');this.s.noteAccess('read',at,size,'lab');return Uint8Array.from(this.s.e.mem_read(at,size));}
 write(at,b,source='analyst-hook'){if(!b.length)return;check(this.s.region(at,b.length,2)&&!this.s.region(at,b.length,4),'Modeled writes require non-executable writable memory.');this.s.e.mem_write(at,b);this.s.noteAccess('write',at,b.length,source);}
 put(at,n,width){const b=new Uint8Array(width),big=this.s.plan.endian==='big';for(let i=0;i<width;i++)b[big?width-1-i:i]=Number(n>>BigInt(8*i)&255n);this.s.e.mem_write(at,b);}
 ptr(at,width){const b=this.read(at,width),big=this.s.plan.endian==='big';let n=0n;for(let i=0;i<width;i++)n|=BigInt(b[big?width-1-i:i])<<BigInt(i*8);return n;}
 resolve(x,bits=this.s.word*8){if(x&&typeof x==='object'){const b=this.buffers.find(b=>b.name===x.buffer);check(b,'Unknown buffer reference.');return value(b.address+(x.offset||0),bits);}return value(x,bits);}
 args(a,count){const s=this.s,sp=num(s.readReg(s.sp));return Array.from({length:count},(_,i)=>i<a.args.length?s.readReg(a.args[i]):this.ptr(sp+a.stack+(i-a.args.length)*a.word,a.word));}
 setup(){
  const s=this.s,r=this.recipe;
  for(const x of r.regions){const perms=(x.permissions.includes('R')?1:0)|(x.permissions.includes('W')?2:0)|(x.permissions.includes('X')?4:0);this.map(x.address,x.size,perms,x.name);s.e.mem_write(x.address,bytes(x.hex));}
  let cursor=D.SCRATCH+4096;
  for(const b of r.buffers){const address=b.address??cursor;check(address+b.size<=D.STACK||address>=D.STACK+D.AREA,'Named buffers cannot overlap the startup/ABI stack; use scratch or an analyst mapping.');check(s.region(address,b.size,2)&&!s.region(address,b.size,4),'Input buffer needs non-executable writable memory.');check(!this.buffers.some(x=>address<x.address+x.size&&address+b.size>x.address),'Input buffers overlap.');const initial=new Uint8Array(b.size);initial.set(bytes(b.hex));s.e.mem_write(address,initial);this.buffers.push({...b,address,before:hexBytes(initial)});if(b.address===undefined)cursor=Math.ceil((address+b.size)/16)*16;}
  if(s.plan.environment==='linux'){check(!r.harness,'Linux startup and a function harness are separate entry modes.');s.linux=new root.SpectraLinux.Environment(s,r);}
  else{check(!r.argv.length&&!r.env.length&&!r.stdin,'argv, env and stdin belong to the Linux process profile.');if(r.files.length){check(s.windows,'Virtual files need a Windows or Linux process profile.');for(const f of r.files){const path=f.path.replaceAll('/','\\').toLowerCase();check(!s.windows.files.has(path),'Duplicate normalized Windows path.');const data=bytes(f.hex);s.windows.files.set(path,{path,bytes:data});s.windows.fileBytes+=data.length;}}}
  if(r.harness){
   const a=abi(s,r.harness.abi);this.resultRegister=a.ret;const top=D.STACK+D.AREA-1024,sp=a.link?top:top-a.word,ret=s.plan.returnBoundary||0;
   s.writeReg(s.sp,BigInt(sp));if(a.link)s.writeReg(a.link,BigInt(ret));else this.put(sp,BigInt(ret),a.word);
   r.harness.arguments.forEach((x,i)=>{const n=this.resolve(x,a.word*8);if(i<a.args.length)s.writeReg(a.args[i],n);else this.put(sp+a.stack+(i-a.args.length)*a.word,n,a.word);});
   if(s.windows){s.windows.entries=[];s.windows.phase='Analyst function harness';s.writeReg(s.ip,BigInt(s.plan.start));}
   this.event('function-input',{abi:r.harness.abi,arguments:r.harness.arguments.map(x=>this.resolve(x,a.word*8).toString()),note:'Integer/pointer arguments only. Floats, aggregates and variadic ABI rules are unsupported.'});
  }
  for(const [n,v]of Object.entries(r.registers)){check(s.names.includes(n)&&![s.ip,s.sp,'ZERO','CPSR','NZCV','EFLAGS'].includes(n),'Recipe register must be a general argument/data register.');s.writeReg(n,value(v,s.word*8));}
  for(const h of r.hooks){abi(s,h.abi);if(h.api)check(s.windows,'DLL!API hooks need the Windows process profile.');else check(s.region(h.address,1,4),'Address hook must target mapped executable memory.');}
  if(this.mmio.length){check(['arm','thumb','aarch64'].includes(s.mode)&&s.plan.environment!=='linux','MMIO recipes are for bare ARM/Thumb/AArch64 routines.');for(const x of this.mmio)this.mmioPages.add(Math.floor(x.address/P)*P);for(const page of this.mmioPages)this.map(page,P,3,'Analyst MMIO responses');
   const read=s.e.hook_add(s.uc.HOOK_MEM_READ,(_e,_t,address,size)=>this.access('read',Number(address),size));
   const write=s.e.hook_add(s.uc.HOOK_MEM_WRITE,(_e,_t,address,size,v)=>this.access('write',Number(address),size,v));this.hooks.push(read,write);
  }
 }
 access(kind,address,size,v){
  if(!this.s.executing||![...this.mmioPages].some(p=>address<p+P&&address+size>p))return;
  try{const m=this.mmio.find(m=>m.address===address&&m.width===size);check(m,'No exact MMIO response for this address/access width.');
   if(kind==='read'){check(m.values.length&&(m.index<m.values.length||m.onExhaustion==='hold'),'MMIO response sequence exhausted.');const val=m.values[Math.min(m.index,m.values.length-1)];this.put(address,BigInt(val),size);m.index++;this.event('mmio-read',{address,width:size,value:val,label:m.label,behavior:'analyst-supplied'});}
   else{check(m.write==='capture','MMIO writes are not permitted by this recipe.');const val=BigInt.asUintN(size*8,BigInt(v)).toString();m.writes.push(val);if(m.writes.length>256)m.writes.shift();this.event('mmio-write',{address,width:size,value:val,label:m.label,behavior:'captured; no peripheral side effects'});}
  }catch(e){this.lastError=e.message;this.s.e.emu_stop();}
 }
 modeled(i,callback){
  const s=this.s,before=s.regs();s.attempts++;const last=s.journal.at(-1);if(last?.kind==='steps')last.count++;else s.journal.push({kind:'steps',count:1});
  if(s.attempts>100000||s.steps>=100000)return s.halt('limit','Experiment instruction budget reached.');s.hits=[];s.hitsTruncated=false;s.breakAt=null;s.executing=true;
  try{callback();}catch(e){this.event('model-stop',{address:i.address,reason:e.message});return s.halt('unsupported',e.message+' State may be partial. Review the explicit recipe before reinitializing.');}finally{s.executing=false;}
  s.steps++;const after=s.regs();s.trace.push({...i,step:s.steps,changes:Object.fromEntries(s.names.filter(n=>before[n]!==after[n]).map(n=>[n,{before:before[n],after:after[n]}])),writes:[],modeled:true});if(s.trace.length>200)s.trace.shift();
  if(s.stopped)return false;if(s.pc()===(s.plan.returnBoundary||0))return s.halt('returned','Returned to the experiment boundary.');if(s.hits.length)return s.halt('watchpoint','Watchpoint after the modeled operation.');s.status='stepped';s.reason='Completed explicit '+i.mnemonic+' model.';return true;
 }
 invoke(h){const s=this.s,a=abi(s,h.abi),args=this.args(a,h.argc),sp=num(s.readReg(s.sp)),target=a.link?s.readReg(a.link):this.ptr(sp,a.word),ret=this.resolve(h.result,a.word*8),writes=h.writes.map(w=>({address:num(args[w.argument])+w.offset,bytes:bytes(w.hex)}));
  const pc=num(target),normalized=(s.mode==='arm'||s.mode==='thumb')?pc-pc%2:pc;
  check(normalized===(s.plan.returnBoundary||0)||s.region(normalized,1,4),'Hook return target is not executable memory.');for(const w of writes)check(s.region(w.address,w.bytes.length,2)&&!s.region(w.address,w.bytes.length,4),'Hook output is not writable data.');
  for(const w of writes)this.write(w.address,w.bytes);s.writeReg(a.ret,ret);if(!a.link)s.writeReg(s.sp,BigInt(sp+a.word+(a.clean?h.argc*a.word:0)));
  if(['arm','thumb'].includes(s.mode))s.writeReg('CPSR',(s.readReg('CPSR')&~32n)|(pc&1?32n:0n));s.writeReg(s.ip,BigInt(normalized));if(s.frames.at(-1)?.returnAddress===normalized)s.frames.pop();
  this.event('hook',{address:h.address,api:h.api,label:h.label,arguments:args.map(String),result:ret.toString(),writes:writes.map(w=>({address:w.address,hex:hexBytes(w.bytes)})),behavior:'analyst-supplied; target function skipped'});
 }
 record(at,beforeSteps){const s=this.s;if(s.steps===beforeSteps||s.trace.at(-1)?.partial)return;const entries=[at,...(s.trace.at(-1)?.delaySlot?[s.trace.at(-1).delaySlot.address]:[])];for(const pc of entries){if(this.coverage.size<8192||this.coverage.has(pc))this.coverage.set(pc,(this.coverage.get(pc)||0)+1);else this.coverageTruncated=true;}const key=at+'>'+s.pc();if(this.edges.size<8192||this.edges.has(key))this.edges.set(key,(this.edges.get(key)||0)+1);else this.coverageTruncated=true;}
 step(original){const s=this.s;if(s.stopped)return false;const at=s.pc(),steps=s.steps;let result;
  try{const api=s.windows?.api.get(at),h=this.recipe.hooks.find(h=>h.address===at)||this.recipe.hooks.find(h=>api&&h.api?.toLowerCase()===(api.library+'!'+api.name).toLowerCase());
   if(h)result=this.modeled({address:at,size:0,bytes:[],mnemonic:'HOOK',operands:h.api||h.label},()=>this.invoke(h));
   else{const i=s.decode(at);if(s.linux&&i&&(s.mode==='x64'&&i.mnemonic==='syscall'||s.mode==='aarch64'&&i.mnemonic==='svc'))result=this.modeled(i,()=>s.linux.syscall(i));else result=original();}
   if(this.lastError){s.halt('unsupported',this.lastError+' The last CPU operation may be partial.');if(s.trace.at(-1))s.trace.at(-1).partial=true;result=false;this.lastError=null;}
   this.record(at,steps);return result;
  }catch(e){return s.halt('fault','Experiment stopped: '+e.message);}
 }
 snapshot(){const s=this.s;return {label:this.recipe.label,recipe:this.recipe,mappings:this.extra,eventCount:this.eventCount,events:this.events,coverage:[...this.coverage].map(([address,hits])=>({address,hits})),edges:[...this.edges].map(([edge,hits])=>({edge,hits})),coverageTruncated:this.coverageTruncated,returnRegister:this.resultRegister,returnValue:D.hex(s.readReg(this.resultRegister)),buffers:this.buffers.map(b=>({name:b.name,address:b.address,size:b.size,before:b.before,after:hexBytes(s.e.mem_read(b.address,b.size))})),mmio:this.mmio,linux:s.linux?.snapshot()||null};}
}
function attach(s,recipe){
 const lab=new Lab(s,recipe);s.lab=lab;const region=s.region.bind(s),snapshot=s.snapshot.bind(s),step=s.step.bind(s),close=s.close.bind(s);
 s.region=(at,size=1,permission=0)=>lab.extra.find(r=>at>=r.address&&size<=r.size-(at-r.address)&&(r.perms&permission)===permission)||region(at,size,permission);
 s.step=()=>lab.step(step);s.snapshot=at=>{const out=snapshot(at);out.lab=lab.snapshot();out.mappings.push(...lab.extra);return out;};
 s.close=()=>{for(const h of lab.hooks)s.e?.hook_del(h);lab.hooks=[];close();};
 try{lab.setup();}catch(e){s.close();throw e;}return s;
}
function create(uc,cs,bytes,meta,options){const recipe=validate(options.recipe||{});if(options.environment==='linux')root.SpectraLinux.prepare(bytes,meta,options);const C=root.SpectraHardware.profiles[options.mode]?root.SpectraHardware.Session:D.Session;return attach(new C(uc,cs,bytes,meta,options),recipe);}
async function batch(make,cases,budget=1000,progress=async()=>{}){
 list(cases,16);check(cases.length&&Number.isInteger(budget)&&budget>=1&&budget<=10000,'Batch needs 1–16 cases and a 1–10,000 instruction budget.');const results=[];
 check(JSON.stringify(cases).length<=524288,'Combined batch recipe cap: 512 KiB.');for(let index=0;index<cases.length;index++){const recipe=validate(cases[index]);let s;try{s=make(recipe);}catch(e){results.push({label:recipe.label,status:'setup-error',reason:String(e.message).slice(0,1000),steps:0,recipe,lab:null});await progress(index+1,0);continue;}try{let attempted=0;while(!s.stopped&&s.steps<budget&&attempted<budget){const cost=s.operation?.().cost||1;if(s.steps+cost>budget)break;s.step();if(++attempted%32===0)await progress(index,attempted);}if(!s.stopped)s.halt('budget','Batch case reached its instruction budget.');results.push({label:recipe.label,status:s.status,reason:s.reason,steps:s.steps,recipe,lab:s.lab.snapshot()});}finally{s?.close();}await progress(index+1,0);}
 const baseline=new Set(results.find(r=>r.lab)?.lab.coverage.map(x=>x.address)||[]);for(const r of results){const set=new Set((r.lab?.coverage||[]).map(x=>x.address));r.coverageDifference={added:[...set].filter(x=>!baseline.has(x)),missing:[...baseline].filter(x=>!set.has(x))};r.changedBuffers=(r.lab?.buffers||[]).map(b=>({name:b.name,changed:b.before!==b.after,after:b.after}));}return results;
}
function validateBatch(b,sample){
 check(b&&b.schema==='spectra-batch-v1'&&b.sha256===sample&&/^[0-9a-f]{64}$/.test(b.engine),'Batch report requires its original sample hash and engine ID.');
 check(JSON.stringify(b).length<=8*1024*1024,'Batch report cap: 8 MiB.');list(b.results,16);check(b.results.length>0&&Number.isInteger(b.budget)&&b.budget>=1&&b.budget<=10000,'Invalid batch report budget.');
 for(const r of b.results){text(r.label,100);text(r.status,40);text(r.reason,2000);check(Number.isInteger(r.steps)&&r.steps>=0&&r.steps<=10000,'Invalid batch step count.');validate(r.recipe);if(r.lab){const l=r.lab;text(l.label,100);text(l.returnRegister,8);check(/^0x[0-9a-f]{1,16}$/i.test(l.returnValue),'Invalid return value.');check(Number.isSafeInteger(l.eventCount)&&l.eventCount>=0&&l.eventCount<=1000000,'Invalid event count.');list(l.coverage,8192).forEach(c=>{num(c.address);check(Number.isInteger(c.hits)&&c.hits>0&&c.hits<=10000,'Invalid coverage hit count.');});list(l.edges,8192).forEach(c=>{check(/^\d+>\d+$/.test(c.edge)&&c.edge.length<=40,'Invalid observed transition.');c.edge.split('>').forEach(a=>num(a));check(Number.isInteger(c.hits)&&c.hits>0&&c.hits<=10000,'Invalid transition count.');});list(l.events,256);list(l.buffers,16).forEach(x=>{text(x.name,40);num(x.address);check(Number.isInteger(x.size)&&x.size>=1&&x.size<=4096&&bytes(x.before).length===x.size&&bytes(x.after).length===x.size,'Invalid result buffer.');});if(l.linux){text(l.linux.output,131072);check(l.linux.exitCode===null||Number.isInteger(l.linux.exitCode)&&l.linux.exitCode>=0&&l.linux.exitCode<=255,'Invalid exit code.');list(l.linux.files,64).forEach(f=>{text(f.path,4096);bytes(f.hex);});}}
  for(const k of ['added','missing'])list(r.coverageDifference?.[k]||[],8192).forEach(a=>num(a));list(r.changedBuffers||[],16).forEach(x=>{text(x.name,40);bytes(x.after);});
 }return b;
}
root.SpectraLab={SCHEMA,MAX_TEXT,validate,validateBatch,abi,Lab,attach,create,batch,bytes,hexBytes};if(typeof module!=='undefined')module.exports=root.SpectraLab;
})(globalThis);
