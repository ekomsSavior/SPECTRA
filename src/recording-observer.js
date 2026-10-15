/* Attached after all environment models. Observes successful engine operations only. */
(function(root){
'use strict';
const R=root.SpectraRecording||(typeof require==='function'?require('./recording.js'):null),hex=n=>'0x'+BigInt(n).toString(16);
async function attach(session,info,store,budget){
 const snap=session.snapshot(),h={schema:R.SCHEMA,type:'header',replayable:false,origin:'spectra',sample:info.sample,engine:info.engine,cpu:snap.mode,environment:info.options.environment||'routine',createdAt:new Date().toISOString(),startStep:snap.steps,budget,initialRegisters:snap.registers,options:info.options};
 const writer=await R.Writer.create(store,JSON.parse(JSON.stringify(h))),undo=[];let detaching=false;
 const add=(kind,data)=>writer.add(kind,session.steps,data);
 function wrap(obj,name,fn){if(!obj||typeof obj[name]!=='function')return;const original=obj[name];Object.defineProperty(obj,name,{configurable:true,writable:true,value:function(...args){return fn.call(this,original,args);}});undo.push(()=>{obj[name]=original;});}
 const initial=()=>session.e.mem_regions().map(m=>({address:hex(m.begin),size:hex(BigInt(m.end)-BigInt(m.begin)+1n),perms:m.perms,name:'Mapped pages'}));
 add('mapping',{op:'snapshot',regions:initial(),origins:snap.plan?.regions||[],imageBase:snap.plan?.windows?.base??null,loadBias:snap.plan?.linux?.bias??snap.plan?.windows?.delta??0});
 for(const [method,op]of [['mem_map','map'],['mem_unmap','unmap'],['mem_protect','protect']])wrap(session.e,method,function(original,args){const result=original.apply(this,args);add('mapping',{op,address:hex(args[0]),size:hex(args[1]),perms:args[2]??null});return result;});
 for(const channel of ['windows','lab']){const events=session[channel]?.events;if(events)wrap(events,'push',function(original,args){const result=original.apply(this,args);for(const data of args)add(channel,data);return result;});}
 wrap(session,'step',function(original,args){if(writer.closed||writer.error){this.halt('budget','Recording stopped. Stop or restart the recorder before continuing execution.');return false;}const before=this.attempts,steps=this.steps;let result,error;try{result=original.apply(this,args);}catch(e){error=e;}if(this.steps!==steps){const row=this.trace.at(-1);if(row&&row.step>steps)add('instruction',row);}if(this.steps===steps||this.stopped||error)add('stop',{status:this.status,reason:error?String(error.message):this.reason,attempts:this.attempts,beforeAttempts:before,pc:this.pc()});if(error)throw error;return result;});
 for(const [method,kind]of [['editRegister','register-edit'],['patch','memory-edit']])wrap(session,method,function(original,args){const result=original.apply(this,args);add(kind,this.edits.at(-1)||{note:'Analyst edit applied'});return result;});
 await writer.flush(true);
 return {writer,async flush(){await writer.flush(true);},async finish(status='paused'){if(!detaching){detaching=true;undo.reverse().forEach(f=>f());}return writer.finish(status);},detach(){if(!detaching){detaching=true;undo.reverse().forEach(f=>f());}}};
}
root.SpectraRecordingObserver={attach};if(typeof module!=='undefined')module.exports=root.SpectraRecordingObserver;
})(globalThis);
