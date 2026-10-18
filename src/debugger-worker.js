/* Loaded only inside a dedicated, disposable worker. */
let session=null,running=false,runToken=0,memoryAddress=SpectraDebug.SCRATCH,source=null,recorder=null,history=null;
function publish(type='state',extra={}){postMessage({type,...extra,snapshot:session?{...(history?.current||session).snapshot(memoryAddress),historyView:history?.historical?{boundary:history.cursor,total:history.entries.length-1,digest:history.entries[history.cursor].digest,verifiedReplay:true}:null}:null,running,history:history?.info()||null,historyEligibility:session?SpectraHistory.eligibility(session,source?.options):'Initialize a session first.',recording:recorder?{id:recorder.writer.id,...recorder.writer.meta,error:recorder.writer.error?.message}:null});}
onmessage=async event=>{
 const m=event.data;
 try{
  if(m.action==='pause'){running=true;const pauseToken=++runToken;await history?.pending?.catch(()=>{});if(pauseToken!==runToken)return;if(history?.view)history.returnLive();else if(history)history.generation++;if(session&&!session.stopped){session.status='paused';session.reason='Paused by you.';}await recorder?.flush();running=false;publish();return;}
  if(running){publish('error',{error:'Pause the session before editing or reading another range.'});return;}
  if(m.action==='init'){history?.close();history=null;session?.close();session=null;
   if(recorder){await recorder.finish('interrupted');recorder=null;}
   const [uc,cs]=await Promise.all([MUnicorn(),MCapstone({wasmBinary:m.capstoneWasm})]);
   const bytes=new Uint8Array(m.buffer),sha256=await SpectraExperiments.sha(bytes);
   source={uc,cs,bytes,meta:m.meta,options:m.options,sha256,module:SpectraHardware.profiles[m.options.mode]?.module||'x86'};
   session=SpectraLab.create(uc,cs,bytes,m.meta,m.options);memoryAddress=SpectraDebug.SCRATCH;publish('state',{memoryAddress});return;
  }
  if(!session)throw Error('Initialize a session first.');
  if(m.action==='historyStart'){
   if(history)throw Error('Discard the current history before starting another.');if(recorder)throw Error('Stop Persistent recording before starting history.');
   const token=++runToken;running=true;const options=JSON.parse(JSON.stringify(source.options)),factory=()=>SpectraLab.create(source.uc,source.cs,source.bytes,source.meta,options);
   try{const next=await SpectraHistory.Timeline.start(session,options,factory,Number(m.budget));if(token!==runToken){next.close();return;}history=next;running=false;publish();}finally{if(token===runToken)running=false;}return;
  }
  if(m.action==='historyDiscard'){history?.close();history=null;publish();return;}
  if(m.action==='historyLive'){history?.returnLive();publish();return;}
  if(m.action==='historySeek'||m.action==='historyReverse'){
   if(!history)throw Error('Start a history first.');if(history.failed)throw Error(history.failed);let index=Number(m.index),match=null;
   if(m.action==='historyReverse'){match=history.reverseMatch(m.breakpoints||[],m.watchpoints||[]);if(match.index===null){publish('state',{historyNotice:match.clipped?'No retained match found; some access observations were clipped. Earlier matching accesses may be missing.':'No earlier match in the retained timeline.'});return;}index=match.index;}
   const token=++runToken;running=true;let lastPost=0;
   try{await history.seek(index,async n=>{if(token!==runToken)throw Error('History seek cancelled.');if(performance.now()-lastPost>200){publish('progress',{historyProgress:n});lastPost=performance.now();}await new Promise(resolve=>setTimeout(resolve,0));});if(token===runToken){running=false;publish('state',{historyNotice:match?'Verified boundary before '+match.kind+' at action '+match.operation+(match.clipped?'; access observations are clipped.':'.'):'Historical state verified. The live experiment is unchanged.'});}}catch(error){if(token===runToken)throw error;}finally{if(token===runToken)running=false;}return;
  }
  if(history?.historical&&['step','run','over','out','register','patch','restore','batch','recordStart'].includes(m.action))throw Error('Historical state is read-only. Return to latest before running or editing.');
  if(history&&['recordStart','restore','batch'].includes(m.action))throw Error('Discard history before a separate recording, checkpoint restore or batch. Save a checkpoint first if needed.');
  if(m.action==='recordStart'){if(recorder){await recorder.finish();recorder=null;}recorder=await SpectraRecordingObserver.attach(session,{sample:{name:m.name,sha256:source.sha256,bytes:source.bytes.length},engine:{sha256:SpectraExperiments.ENGINE},options:source.options},new SpectraRecording.Store(),m.recordBudget);publish();return;}
  if(m.action==='recordStop'){if(recorder){const id=recorder.writer.id,meta=await recorder.finish();recorder=null;publish('recorded',{recorded:{id,...meta}});}return;}
  if(m.watchpoints!==undefined)session.setWatchpoints(m.watchpoints);
  if(m.action==='batch'){
   if(recorder)throw Error('Stop the current recording before a separate batch experiment.');
   running=true;const token=++runToken,started=performance.now();let lastPost=0;
   try{const results=await SpectraLab.batch(recipe=>SpectraLab.create(source.uc,source.cs,source.bytes,source.meta,{...source.options,recipe}),m.cases,Number(m.budget),async(index,steps)=>{if(token!==runToken)throw Error('Batch cancelled.');if(performance.now()-started>30000)throw Error('Batch exceeded its 30-second limit. Reduce cases or instruction budget.');if(performance.now()-lastPost>200){publish('progress',{batchProgress:{index,steps,total:m.cases.length}});lastPost=performance.now();}await new Promise(r=>setTimeout(r,0));});
    if(token===runToken){running=false;const batch={schema:'spectra-batch-v1',sha256:source.sha256,engine:SpectraExperiments.ENGINE,options:source.options,budget:Number(m.budget),results};SpectraLab.validateBatch(batch,source.sha256);publish('batch',{batch});}
   }catch(error){if(token===runToken)throw error;}finally{if(token===runToken)running=false;}return;
  }
  if(m.action==='checkpoint'){
   running=true;const token=++runToken;
   try{const checkpoint=await SpectraExperiments.capture(history?.current||session,source.sha256,source.options);if(token===runToken){running=false;publish('checkpoint',{checkpoint});}}catch(error){if(token===runToken)throw error;}finally{if(token===runToken)running=false;}return;
  }
  if(m.action==='restore'){
   if(recorder){await recorder.finish();recorder=null;}
   const token=++runToken;running=true;let candidate=null,swapped=false,lastPost=0;
   try{
    const c=await SpectraExperiments.validateEvidence(m.checkpoint,source.sha256);if(token!==runToken)return;if((SpectraHardware.profiles[c.options.mode]?.module||'x86')!==source.module)throw Error('Initialize the checkpoint CPU family first.');candidate=SpectraLab.create(source.uc,source.cs,source.bytes,source.meta,c.options);
    await SpectraExperiments.replay(c,candidate,async count=>{if(token!==runToken)throw Error('Replay cancelled.');if(performance.now()-lastPost>200){publish('progress',{replayCount:count});lastPost=performance.now();}await new Promise(resolve=>setTimeout(resolve,0));});
    if(token!==runToken)throw Error('Replay cancelled.');candidate.setWatchpoints(m.watchpoints||[]);session.close();session=candidate;source.options=c.options;swapped=true;running=false;publish('restored',{options:c.options,digest:c.digest});
   }catch(error){if(token===runToken)throw error;}finally{if(!swapped)candidate?.close();if(token===runToken)running=false;}return;
  }
  if(m.action==='step'){const token=++runToken;running=true;try{if(history){if(!await history.perform({kind:'step'}))session.halt('budget','History budget reached before the next action. Inspect or discard the timeline.');}else session.step();await recorder?.flush();if(token===runToken){running=false;publish();}}catch(e){if(token===runToken)throw e;}finally{if(token===runToken)running=false;}return;}
  if(['run','over','out'].includes(m.action)){
   if(session.stopped)throw Error('This session stopped at an unsupported operation or fault. Reset or supply a corrected state before continuing.');
   const budget=Number(m.budget);if(!Number.isSafeInteger(budget)||budget<1||budget>10000)throw Error('Run budget must be 1–10,000 instructions.');
   const breakpoints=m.breakpoints||[];if(!Array.isArray(breakpoints)||breakpoints.length>128)throw Error('Use at most 128 breakpoints.');breakpoints.forEach(p=>session.breakpoint(p));
   const target=m.action==='run'?null:session.runTarget(m.action);if(m.action==='over'&&!target){const token=++runToken;running=true;try{if(history){if(!await history.perform({kind:'step'}))session.halt('budget','History budget reached before the next action. Inspect or discard the timeline.');}else session.step();await recorder?.flush();if(token===runToken){running=false;publish();}}catch(e){if(token===runToken)throw e;}finally{if(token===runToken)running=false;}return;}
   let remaining=budget,skip=session.status==='breakpoint'&&session.breakAt===session.pc(),lastPost=0;
   const token=++runToken,started=performance.now();running=true;
   const tick=async()=>{
    if(token!==runToken||!running)return;
    try{
     const n=history?await history.advance(Math.min(8,remaining),breakpoints,skip,target,async()=>{if(token!==runToken||!running)throw Error('History run cancelled.');await new Promise(r=>setTimeout(r,0));if(token!==runToken||!running)throw Error('History run cancelled.');return performance.now()-started<4000;}):session.advance(Math.min(32,remaining),breakpoints,skip,target);skip=false;remaining-=n;await recorder?.flush();if(token!==runToken||!running)return;
     if(session.stopped||history?.full||recorder?.writer.closed||['breakpoint','watchpoint','target'].includes(session.status)||remaining<=0||n===0||performance.now()-started>=4000){
      running=false;if(!session.stopped&&!['breakpoint','watchpoint','target'].includes(session.status)){session.status='budget';session.reason=history?.full?'History budget reached before the next action. Inspect or discard the timeline.':recorder?.writer.closed?'Recording budget reached. Stop or start a new recording before continuing.':(n===0?'Next atomic operation needs a larger remaining budget. ':'')+(target?'Return boundary not reached. ':'')+(remaining>0?'Paused at the 4-second run limit. Continue to keep tracing.':'Paused at the '+budget+'-instruction run budget.');}publish();return;
     }
     if(performance.now()-lastPost>150){publish('progress');lastPost=performance.now();}setTimeout(tick,0);
    }catch(err){if(token!==runToken)return;running=false;publish('error',{error:String(err.message||err)});}
   };tick();return;
  }
  if(m.action==='view'){memoryAddress=SpectraDebug.address(m.address);(history?.current||session).read(memoryAddress,1);publish('state',{memoryAddress});return;}
  if(m.action==='register'){const token=++runToken;running=true;try{if(history){if(!await history.perform({kind:'register',name:m.name,value:String(m.value)}))throw Error('History budget reached before the edit.');}else session.editRegister(m.name,m.value);await recorder?.flush();if(token===runToken){running=false;publish();}}catch(e){if(token===runToken)throw e;}finally{if(token===runToken)running=false;}return;}
  if(m.action==='patch'){const token=++runToken;running=true;try{if(history){if(!await history.perform({kind:'patch',address:m.address,bytes:Array.from(m.bytes)}))throw Error('History budget reached before the edit.');}else session.patch(m.address,new Uint8Array(m.bytes));await recorder?.flush();if(token===runToken){running=false;publish();}}catch(e){if(token===runToken)throw e;}finally{if(token===runToken)running=false;}return;}
  if(m.action==='capture'||m.action==='fileCapture'){
   const file=m.action==='fileCapture'?(session.windows?.files.get(m.path)||session.linux?.files.get(m.path)):null;if(m.action==='fileCapture'&&!file)throw Error('Virtual file unavailable.');
   const at=file?0:SpectraDebug.address(m.address),bytes=file?file.bytes.slice():(history?.current||session).read(at,Number(m.size));
   const token=++runToken;running=true;try{const sha=await SpectraExperiments.sha(bytes),result=SpectraCore.extract(bytes,4,2000);if(token===runToken){running=false;publish('capture',{capture:{bytes,address:at,path:file?.path,history:history?.historical?{boundary:history.cursor,digest:history.entries[history.cursor].digest,verifiedReplay:true}:null,sha256:sha,strings:result.strings,truncated:result.truncated,entropy:SpectraCore.entropy(bytes)}});}}catch(error){if(token===runToken)throw error;}finally{if(token===runToken)running=false;}
  }
 }catch(err){running=false;publish('error',{error:String(err.message||err).slice(0,1000)});}
};
