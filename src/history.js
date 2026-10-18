/* Verified, session-local historical views. Trace imports never enter this module. */
(function(root){
'use strict';
const X=root.SpectraExperiments||(typeof require==='function'?require('./experiments.js'):null);
const MAX_MAPPED=2*1024*1024,MAX_ACTIONS=2048,MAX_BYTES=4*1024*1024,RESERVE=65536;
const copy=v=>JSON.parse(JSON.stringify(v)),check=(v,m)=>{if(!v)throw Error(m);};
function eligibility(s,options={}){
 if(!s)return 'Initialize a session first.';
 if(!['x86','x64'].includes(s.mode)||(options.environment||'routine')!=='routine'||s.windows||s.linux)return 'History currently supports x86/x64 bare routines. Process and hardware profiles keep their existing checkpoint controls.';
 if(s.journal.length||s.attempts||s.steps)return 'Start history immediately after initialization, before stepping or editing. Reset the session to start a new timeline.';
 const bytes=s.e.mem_regions().reduce((n,r)=>n+Number(r.end)-Number(r.begin)+1,0);
 if(bytes>MAX_MAPPED)return 'History admits at most 2 MiB of mapped memory. Choose a smaller raw routine.';
 return '';
}
function execute(s,a){
 if(a.kind==='step'){check(!s.stopped,'The recorded action tries to step a stopped session.');s.step();}
 else if(a.kind==='register')s.editRegister(a.name,a.value);
 else if(a.kind==='patch')s.patch(a.address,Uint8Array.from(a.bytes));
 else throw Error('Unknown history action.');
}
function differences(a,b){
 const registers=[];for(const k of new Set([...Object.keys(a.registers),...Object.keys(b.registers)]))if(X.canonical(a.registers[k])!==X.canonical(b.registers[k]))registers.push({name:k,before:a.registers[k],after:b.registers[k]});
 const before=new Map(a.memory.map(p=>[p.address,p])),after=new Map(b.memory.map(p=>[p.address,p])),pages=[];
 for(const address of new Set([...before.keys(),...after.keys()]))if(X.canonical(before.get(address))!==X.canonical(after.get(address)))pages.push({address,before:before.get(address)||null,after:after.get(address)||null});
 return {registers,pages,modelChanged:X.canonical(a.lab)!==X.canonical(b.lab),fromSteps:a.steps,toSteps:b.steps};
}
class Timeline{
 static async start(session,options,make,budget=512){
  check(Number.isInteger(budget)&&budget>=1&&budget<=MAX_ACTIONS,'History budget must be 1–2,048 actions.');
  const reason=eligibility(session,options);check(!reason,reason);
  const h=new Timeline(session,make,budget),initial=await X.inspect(session);
  h.last=initial;h.entries.push({index:0,digest:initial.digest,pc:session.pc(),steps:0,kind:'initial',status:session.status,reason:session.reason});h.bytes=JSON.stringify(h.entries[0]).length;return h;
 }
 constructor(session,make,budget){this.live=session;this.make=make;this.budget=budget;this.entries=[];this.bytes=0;this.cursor=0;this.view=null;this.full=false;this.failed='';this.diff=null;this.generation=0;}
 get current(){return this.view||this.live;}
 get historical(){return this.cursor<this.entries.length-1;}
 info(){return {cursor:this.cursor,total:this.entries.length-1,budget:this.budget,bytes:this.bytes,maxBytes:MAX_BYTES,historical:this.historical,full:this.full,failed:this.failed,entry:this.entries[this.cursor],diff:this.diff};}
 perform(action){
  check(!this.pending,'A history action is already being verified.');
  const task=this._perform(action);this.pending=task;return task.finally(()=>{if(this.pending===task)this.pending=null;});
 }
 async _perform(action){
  check(!this.historical,'Historical state is read-only. Return to latest before running or editing.');check(!this.failed,this.failed);
  if(this.entries.length-1>=this.budget||this.bytes+RESERVE>MAX_BYTES){this.full=true;return false;}
  check(action&&['step','register','patch'].includes(action.kind),'Unknown history action.');
  if(action.kind==='step')check(!this.live.stopped,'The session has stopped; inspect its reason or supply a corrected state.');
  if(action.kind==='patch')check(Array.isArray(action.bytes)&&action.bytes.length<=4096,'History patch exceeds 4,096 bytes.');
  const s=this.live,registers=s.regs(),pc=s.pc(),accesses=[],original=s.noteAccess;let clipped=false;
  s.noteAccess=function(kind,address,size,source){if(this.executing){if(accesses.length<128)accesses.push({kind,address,size,source});else clipped=true;}return original.call(this,kind,address,size,source);};
  let error;try{execute(s,action);}catch(e){error=e;}finally{s.noteAccess=original;}
  // Invalid input leaves the prior timeline usable; any mutation after an exception closes admission.
  let end;try{end=await X.inspect(s);}catch(e){this.failed='History verification could not finish after the action. The latest state is inspectable, but reset before starting another timeline.';throw Error(this.failed,{cause:e});}
  if(error){if(end.digest!==this.last.digest)this.failed='An action failed after changing state. Reset before starting another history; the live state remains inspectable.';throw error;}
  const row={index:this.entries.length,kind:action.kind,action:copy(action),digest:end.digest,pc:s.pc(),beforePC:pc,beforeRegisters:registers,steps:s.steps,status:s.status,reason:s.reason,hits:copy(s.hits),hitsTruncated:!!s.hitsTruncated,accesses,accessesTruncated:clipped,partial:action.kind==='step'&&!!s.trace.at(-1)?.partial};
  const size=new TextEncoder().encode(JSON.stringify(row)).length;
  if(size>RESERVE){this.failed='History metadata exceeded its per-action limit. The latest action is not retained; reset to start another timeline.';throw Error(this.failed);}
  this.entries.push(row);this.cursor=row.index;this.bytes+=size;this.diff=differences(this.last.summary,end.summary);this.last=end;return true;
 }
 async advance(count,breakpoints=[],skip=false,target=null,progress=async()=>{}){
  check(Number.isInteger(count)&&count>=1&&count<=10000,'Invalid history run budget.');
  check(Array.isArray(breakpoints)&&breakpoints.length<=128,'Use at most 128 breakpoints.');
  const s=this.live,points=breakpoints.map(p=>s.breakpoint(p));let n=0;
  while(n<count&&!s.stopped){
   if(target&&s.pc()===target.returnAddress&&s.readReg(s.sp)>=BigInt(target.stack)){s.halt('target','Reached the observed return boundary.');break;}
   if(points.some(p=>p.address===s.pc()&&s.conditionMatches(p.condition))&&!(skip&&n===0)){s.breakAt=s.pc();s.halt('breakpoint','Breakpoint at 0x'+s.pc().toString(16)+'.');break;}
   if(!await this.perform({kind:'step'}))break;n++;if(await progress(n)===false)break;
   if(s.stopped||s.status==='watchpoint')break;
  }
  if(this.full&&!s.stopped)s.halt('budget','History budget reached before the next action. Inspect the retained timeline or discard it to continue.');
  else if(!s.stopped&&!['breakpoint','watchpoint','target'].includes(s.status)){if(target&&s.pc()===target.returnAddress&&s.readReg(s.sp)>=BigInt(target.stack))s.halt('target','Reached the observed return boundary.');else s.halt('budget','Paused after '+n+' verified history actions.');}
  return n;
 }
 returnLive(){this.generation++;this.view?.close();this.view=null;this.cursor=this.entries.length-1;this.diff=null;return this.live;}
 async seek(index,progress=async()=>{}){
  check(Number.isInteger(index)&&index>=0&&index<this.entries.length,'Choose a retained history boundary.');check(!this.failed,this.failed);
  if(index===this.entries.length-1)return this.returnLive();
  const prior=this.view?await X.inspect(this.view):this.last;
  // Keep one live emulator and one candidate at most. Failure/cancellation returns to the intact live session.
  this.returnLive();const generation=this.generation;let candidate=null;
  try{
   await progress(0);check(generation===this.generation,'History seek cancelled.');candidate=this.make();
   check((await X.inspect(candidate)).digest===this.entries[0].digest,'Initial history state diverged. The live experiment is unchanged.');
   for(let n=1;n<=index;n++){execute(candidate,this.entries[n].action);if(n%16===0){await progress(n);check(generation===this.generation,'History seek cancelled.');}}
   const end=await X.inspect(candidate);await progress(index);check(generation===this.generation,'History seek cancelled.');
   check(end.digest===this.entries[index].digest,'History verification failed. The live experiment is unchanged.');
   this.view=candidate;candidate=null;this.cursor=index;this.diff=differences(prior.summary,end.summary);
   this.view.hits=copy(this.entries[index].hits||[]);this.view.hitsTruncated=!!this.entries[index].hitsTruncated;this.view.status=this.entries[index].status;this.view.reason=this.entries[index].reason;return this.view;
  }finally{candidate?.close();}
 }
 reverseMatch(breakpoints=[],watchpoints=[]){
  check(Array.isArray(breakpoints)&&breakpoints.length<=128,'Use at most 128 breakpoints.');const points=breakpoints.map(p=>this.live.breakpoint(p));
  // Reuse the session's validation without changing its controls.
  const previous=this.live.watchpoints;try{this.live.setWatchpoints(watchpoints);watchpoints=copy(this.live.watchpoints);}finally{this.live.watchpoints=previous;}
  check(points.length||watchpoints.length,'Set an address/conditional breakpoint or memory watchpoint first.');
  let clipped=false;
  for(let n=this.cursor;n>0;n--){const row=this.entries[n],target=n-1;clipped ||= row.accessesTruncated;
   const hit=points.find(p=>p.address===row.beforePC&&(!p.condition||(()=>{const a=BigInt(row.beforeRegisters[p.condition.register]),b=BigInt(p.condition.value);return {'==':a===b,'!=':a!==b,'<':a<b,'<=':a<=b,'>':a>b,'>=':a>=b}[p.condition.operator];})()));
   const access=row.accesses.find(a=>watchpoints.some(w=>w.access.includes(a.kind)&&a.address<w.address+w.size&&a.address+a.size>w.address));
   if(hit||access)return {index:target,operation:n,kind:hit?'breakpoint':'watchpoint',clipped,access:access||null};
  }
  return {index:null,clipped};
 }
 close(){this.returnLive();this.entries=[];this.last=null;}
}
root.SpectraHistory={Timeline,eligibility,MAX_MAPPED,MAX_ACTIONS,MAX_BYTES,differences};if(typeof module!=='undefined')module.exports=root.SpectraHistory;
})(globalThis);
