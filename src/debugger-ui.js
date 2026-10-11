const debugState={worker:null,url:null,timer:null,id:0,busy:false,active:false,snapshot:null,options:null,breakpoints:new Set(),conditions:[],watchpoints:[],checkpoints:[],resumable:null,pendingRestore:null,message:'Initialize a session, or try the decoding demo.'};
const debugNumber=id=>SpectraDebug.address($(id).value.trim());
const byteText=bytes=>Array.from(bytes,n=>n.toString(16).padStart(2,'0')).join(' ');
function endDebugger(message='Session ended. The last snapshot is still available.'){
 if(debugState.projectCheckpoint){debugState.projectCheckpoint.reject(Error(message));debugState.projectCheckpoint=null;}
 debugState.worker?.terminate();if(debugState.url)URL.revokeObjectURL(debugState.url);clearTimeout(debugState.timer);Object.assign(debugState,{worker:null,url:null,timer:null,busy:false,active:false,id:debugState.id+1,message});
}
function resetDebugger(){endDebugger('Initialize a session, or try the decoding demo.');debugState.snapshot=null;debugState.options=null;debugState.breakpoints.clear();debugState.conditions=[];debugState.watchpoints=[];debugState.checkpoints=[];debugState.resumable=null;debugState.pendingRestore=null;resetLab();renderDebugger();}
function setDebuggerDefaults(){if(!state.result)return;$('debug-environment').value='routine';$('debug-load-base').value='';$('debug-mode').value=({'x86':'x86','x86-64':'x64','ARM':state.result.entryThumb?'thumb':'arm','ARM64':'aarch64','RISC-V':state.result.bits===64?'riscv64':'riscv32','MIPS':state.result.bits===64?'mips64':'mips32'})[state.result.architecture]||'x64';$('debug-endian').value=state.result.endian||'little';$('debug-raw').checked=!state.result.mappings?.length;$('debug-start').value=hex(state.result.entry||0x100000);$('debug-offset').value='0x0';$('debug-size').value=hex(Math.min(state.bytes.length,65536));$('debug-base').value='0x100000';renderDebugger();}
function debuggerOptions(){return {recipe:labRecipe(),environment:$('debug-environment').value,filename:state.name,loadBase:$('debug-load-base').value.trim()?debugNumber('debug-load-base'):undefined,mode:$('debug-mode').value,endian:$('debug-endian').value,start:debugNumber('debug-start'),raw:$('debug-raw').checked?{offset:debugNumber('debug-offset'),size:debugNumber('debug-size'),base:debugNumber('debug-base')}:null};}
function armDebuggerTimeout(ms=8000){clearTimeout(debugState.timer);const id=debugState.id;debugState.timer=setTimeout(()=>{if(id!==debugState.id)return;endDebugger('Worker terminated at the time limit. Last snapshot may be incomplete; reset to start again.');renderDebugger();},ms);}
function sendDebug(action,extra={}){
 if(action==='pause'&&debugState.projectCheckpoint){debugState.projectCheckpoint.reject(Error('Workspace save cancelled while capturing the checkpoint.'));debugState.projectCheckpoint=null;}
 if(!debugState.worker||debugState.busy&&action!=='pause')return toast('Initialize a session and pause it before making changes.');
 if(['step','run','over','out','register','patch','restore'].includes(action))debugState.resumable=null;
 debugState.busy=true;debugState.message=action==='run'?'Running inside the emulator…':action==='pause'?'Pausing…':'Working on the session…';armDebuggerTimeout(action==='batch'?40000:action==='restore'?60000:action==='checkpoint'?20000:8000);debugState.worker.postMessage({action,watchpoints:debugState.watchpoints,...extra});renderDebugger();
}
async function initializeDebugger(options=null){
 if(state.busy||!state.result)return toast('Let file inspection finish first.');
 let o;try{o=options||debuggerOptions();(SpectraHardware.profiles[o.mode]?SpectraHardware:SpectraDebug).prepare(state.bytes,state.result,o);}catch(e){return toast(e.message);}
 endDebugger();debugState.resumable=null;debugState.snapshot=null;debugState.options=o;debugState.busy=true;debugState.message='Starting the local CPU emulator…';const id=debugState.id,job=state.job;
 try{
  const family=SpectraHardware.profiles[o.mode]?.module;let unicorn=$('unicorn-source').textContent;if(family){const r=await fetch(ENGINE_ROOT+'hardware/unicorn_'+family+'.js');if(!r.ok)throw Error('Hardware engine download failed.');unicorn=await r.text();if(id!==debugState.id||job!==state.job)return;}
  const source=['engine-source','capstone-source','windows-source','linux-source','debugger-source','native-plan-source','code-source','hardware-debugger-source','lab-source','experiments-source','debugger-worker-source'].map(n=>$(n).textContent).join('\n');
  debugState.url=URL.createObjectURL(new Blob([unicorn,source],{type:'text/javascript'}));debugState.worker=new Worker(debugState.url);
  debugState.worker.onmessage=e=>{
   if(id!==debugState.id||job!==state.job)return;
   const msg=e.data;if(msg.type==='restored')for(const c of debugState.checkpoints)if(c.digest===msg.digest)c.imported=false;if(msg.options)debugState.options=msg.options;if(msg.memoryAddress!==undefined)$('debug-memory-address').value=hex(msg.memoryAddress);if(msg.snapshot)debugState.snapshot=msg.snapshot;debugState.busy=!!msg.running;debugState.active=!!msg.snapshot;
   if(!debugState.busy)clearTimeout(debugState.timer);
   debugState.message=msg.error||msg.snapshot?.reason||'Session ready.';
   if(msg.error&&!msg.snapshot)endDebugger('Could not initialize: '+msg.error);
   if(msg.capture)acceptDebugCapture(msg.capture);
   if(msg.batch){labState.batch=msg.batch;labState.selected=-1;debugState.message='Batch complete. Each case started from fresh recipe state; the interactive session is unchanged.';}
   if(msg.batchProgress)debugState.message='Batch: '+msg.batchProgress.index+' / '+msg.batchProgress.total+' cases finished · '+msg.batchProgress.steps+' steps in the current case.';
   if(!msg.running&&!['progress','checkpoint'].includes(msg.type)&&!debugState.projectCheckpoint)scheduleWorkspace();
   if(msg.error&&debugState.projectCheckpoint){debugState.projectCheckpoint.reject(Error(msg.error));debugState.projectCheckpoint=null;}
   if(msg.checkpoint&&debugState.projectCheckpoint){debugState.projectCheckpoint.resolve(msg.checkpoint);debugState.projectCheckpoint=null;}
   else if(msg.checkpoint){scheduleWorkspace();debugState.checkpoints.push({...msg.checkpoint,label:debugState.checkpointLabel||'Experiment '+(debugState.checkpoints.length+1)});debugState.message='Checkpoint saved. Restore replays your recorded steps and edits inside the emulator.';}
   if(msg.replayCount!==undefined)debugState.message='Restoring experiment: '+fmt(msg.replayCount)+' recorded steps replayed…';
   if(debugState.pendingRestore&&msg.type==='state'&&!msg.error){const c=debugState.pendingRestore;debugState.pendingRestore=null;sendDebug('restore',{checkpoint:c});return;}
   renderDebugger();renderLearning();
  };
  debugState.worker.onerror=e=>{if(id!==debugState.id)return;endDebugger('Emulator stopped: '+(e.message||'worker error'));renderDebugger();};
  const capstoneWasm=Uint8Array.from(atob($('capstone-wasm').textContent.trim()),c=>c.charCodeAt(0));
  const {strings,blocks,...meta}=state.result,buffer=state.bytes.slice().buffer;
  debugState.worker.postMessage({action:'init',buffer,meta,options:o,capstoneWasm},[buffer,capstoneWasm.buffer]);armDebuggerTimeout(20000);
 }catch(e){endDebugger('Could not initialize: '+e.message);}
 renderDebugger();
}
function useCodeInDebugger(at){
 if(!codeState.data)return toast('Decode the selected code first.');
 $('debug-environment').value='routine';$('debug-mode').value=codeState.data.mode==='arm64'?'aarch64':codeState.data.mode;$('debug-endian').value=codeState.data.raw?.endian||state.result.endian||'little';$('debug-start').value=hex(at);$('debug-raw').checked=!!codeState.data.raw;
 if(codeState.data.raw){const r=codeState.data.raw;$('debug-offset').value=hex(r.offset);$('debug-size').value=hex(r.size);$('debug-base').value=hex(r.address);}
 changeView('debugger');toast('Start address selected. Initialize when ready; no instructions have run.');
}
function renderDebugger(){
 if(!$('debug-status'))return;
 const s=debugState.snapshot,ready=debugState.active&&!debugState.busy,canStep=ready&&!s?.stopped;
 renderWindowsSession(s,ready);renderExperiments(s,ready);renderLab(s,ready);
 $('debug-status').textContent=debugState.message+(s?.plan.scope?' '+s.plan.scope+(s.plan.cpu?' CPU: '+s.plan.cpu+'.':''):'');$('debug-count').textContent=(s?fmt(s.steps):'0')+' steps';
 for(const id of ['debug-step','debug-run','debug-over','debug-out'])$(id).disabled=!canStep;
 for(const id of ['debug-register-set','debug-memory-view','debug-scratch','debug-stack','debug-patch','debug-capture'])$(id).disabled=!ready;
 $('debug-break-add').disabled=debugState.busy;$('debug-break-address').disabled=debugState.busy;
 $('debug-pause').disabled=!debugState.active||!debugState.busy;$('debug-init').disabled=debugState.busy||state.busy;$('debug-reset').disabled=!debugState.options||state.busy;$('debug-end').disabled=!debugState.worker;$('debug-export').disabled=!s;
 $('debug-selected').disabled=!selectedFunction();$('debug-demo').disabled=state.busy;
 $('debug-assembly').innerHTML=(s?.assembly||[]).map((i,n)=>`<tr class="${!n?'selected':''}"><td><button class="text-button" data-debug-bp="${i.address}" aria-label="${debugState.breakpoints.has(i.address)?'Remove':'Set'} breakpoint ${hex(i.address)}">${debugState.breakpoints.has(i.address)?'●':'○'}</button></td><td>${hex(i.address)}${!n?' ←':''}</td><td class="instruction-bytes">${byteText(i.bytes)}</td><td><b>${esc(i.mnemonic)}</b> ${esc(i.operands)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">'+(s?'No instruction at the current pointer. Inspect the stop reason.':'Initialize to see live instruction bytes.')+'</td></tr>';
 $('debug-breakpoints').innerHTML=[...debugState.breakpoints].sort((a,b)=>a-b).map(a=>`<button class="chip" data-debug-bp="${a}" aria-label="Remove breakpoint ${hex(a)}">${hex(a)} ×</button>`).join('')||'<span class="muted tiny">No breakpoints set.</span>';
 document.querySelectorAll('[data-debug-bp]').forEach(b=>{b.disabled=debugState.busy;b.onclick=()=>{const a=Number(b.dataset.debugBp);if(debugState.breakpoints.has(a))debugState.breakpoints.delete(a);else if(debugState.breakpoints.size+debugState.conditions.length<128)debugState.breakpoints.add(a);else return toast('Limit: 128 breakpoints.');renderDebugger();scheduleWorkspace();};});
 const changes=s?.trace.at(-1)?.changes||{};
 $('debug-registers').innerHTML=Object.entries(s?.registers||{}).map(([name,v])=>`<div class="${changes[name]?'debug-changed':''}"><dt>${name}</dt><dd>${esc(v)}</dd></div>`).join('')||'<p class="empty">Registers appear after initialization.</p>';
 $('debug-flags').innerHTML=Object.entries(s?.flags||{}).map(([n,v])=>`<span class="pill ${v?'debug-flag-on':''}">${n} ${v}</span>`).join('');
 const previous=$('debug-register-name').value;$('debug-register-name').innerHTML=Object.keys(s?.registers||{}).filter(n=>!s?.readOnlyRegisters?.includes(n)).map(n=>`<option>${n}</option>`).join('');if(previous&&s?.registers[previous])$('debug-register-name').value=previous;
 const memory=s?.memory,lastWrites=s?.trace.at(-1)?.writes||[];let html='';
 if(memory){for(let n=0;n<memory.bytes.length;n+=16){const b=memory.bytes.slice(n,n+16),at=memory.address+n;html+=`<div class="debug-hex-row"><span>${hex(at)}</span><span>${b.map((v,j)=>`<i class="${lastWrites.some(w=>at+j>=w.address&&at+j<w.address+w.size)?'debug-changed':''}">${v.toString(16).padStart(2,'0')}</i>`).join(' ')}</span><span>${esc(b.map(v=>v>=32&&v<=126?String.fromCharCode(v):'·').join(''))}</span></div>`;}}
 $('debug-memory').innerHTML=html||'<div class="empty">Read a mapped address to inspect its bytes.</div>';
 $('debug-trace').innerHTML=[...(s?.trace||[])].reverse().map(i=>`<tr><td>${i.step}${i.partial?' · partial':''}</td><td><code>${hex(i.address)}</code><br><code>${esc(i.mnemonic+' '+i.operands+(i.delaySlot?' | delay slot: '+i.delaySlot.mnemonic+' '+i.delaySlot.operands:''))}</code></td><td>${Object.entries(i.changes).map(([n,v])=>`<div><b>${n}</b> ${esc(v.before)} → ${esc(v.after)}</div>`).join('')||'—'}</td><td>${i.writes.map(w=>`<div><code>${hex(w.address)}</code><br>${byteText(w.before)} → ${byteText(w.after)}</div>`).join('')||'—'}${i.writesTruncated?'<p>First 32 writes shown.</p>':''}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">Step once. Follow what changes.</td></tr>';
}
function acceptDebugCapture(capture){
 const s=debugState.snapshot,total=recoveryState.artifacts.reduce((n,a)=>n+a.bytes.length,0);
 if(!s||recoveryState.artifacts.length>=8||total+capture.bytes.length>16*1024*1024)return toast('Recovery layer limit reached. Clear its results first.');
 stopRecovery();recoveryState.pendingStack=false;
 const id='layer-'+recoveryState.nextArtifact++,chain=[{method:'emulation',sourceSha256:state.hash,mode:s.mode,start:s.plan.start,memoryAddress:capture.address,length:capture.bytes.length,virtualPath:capture.path,steps:s.steps,assumptions:s.windows?'Modeled Windows process. Review API events and unsupported behavior.':'Bare routine with zeroed registers, stack and scratch. See analyst edits.',windows:s.windows,lab:s.lab,environment:s.plan.environment||'routine',edits:s.edits}];
 const artifact={id,name:id+' · '+(capture.path?'virtual file':'emulated memory'),method:'emulation',bytes:capture.bytes,sha256:capture.sha256,strings:capture.strings,entropy:capture.entropy,sourceId:capture.path||'session memory',sourceOffset:capture.address,sourceLength:capture.bytes.length,chain,emulationTrace:s.trace};
 recoveryState.artifacts.push(artifact);const firstNew=recoveryState.rows.length;addRecoveryRows(capture.strings.map(r=>({...r,method:'emulation',sourceOffset:r.offset,sourceLength:r.byteLength,decodedOffset:r.offset,artifactId:id,confidence:'emulated state',evidence:(capture.path?'Captured from virtual file '+capture.path+' at file offset '+hex(r.offset):'Captured from emulated VA '+hex(capture.address+r.offset))+' after '+s.steps+' attempted steps. Depends on the supplied state; not proof of real-world execution.',tags:core.tagsFor(r.text)})),id);
 if(recoveryState.rows.length>firstNew)recoveryState.selected=firstNew;
 recoveryState.message='Captured '+human(capture.bytes.length)+' from '+(capture.path||hex(capture.address))+'. '+capture.strings.length+' strings found.';
 $('recovery-filter').value='all';$('recovery-search').value='';recoveryState.page=Math.floor(firstNew/100);renderRecovery();$('recovery-input').value=id;setRecoveryRange();changeView('recovery');toast('Emulated bytes are now a Recovery lab input.');
}
function exportDebug(){const s=debugState.snapshot;if(!s)return;download(baseName()+'.debugger.json',JSON.stringify({tool:'SPECTRA 0.9',sample:state.name,sha256:state.hash,createdAt:new Date().toISOString(),configuration:debugState.options,breakpoints:[...debugState.breakpoints],...s,note:'Emulated CPU with explicit supplied/model state, not a full operating system or board. Last 200 attempts only. Faults may leave partial state. Memory edits and register arguments are analyst-supplied.'},null,2));}
$('debug-init').onclick=()=>initializeDebugger();$('debug-reset').onclick=()=>initializeDebugger(debugState.options);$('debug-end').onclick=async()=>{if(debugState.active&&!debugState.busy){try{debugState.resumable=await checkpointForProject();endDebugger('Session ended. Its verified checkpoint is retained for workspace saving.');}catch(e){endDebugger('Session ended without a new checkpoint: '+e.message);}}else{debugState.resumable=null;endDebugger('Session ended immediately. Save a checkpoint before ending if you need to resume.');}renderDebugger();scheduleWorkspace();};
$('debug-step').onclick=()=>sendDebug('step');for(const action of ['run','over','out'])$('debug-'+action).onclick=()=>{try{sendDebug(action,{budget:debugNumber('debug-budget'),breakpoints:[...[...debugState.breakpoints].map(address=>({address})),...debugState.conditions]});}catch(e){toast(e.message);}};$('debug-pause').onclick=()=>sendDebug('pause');
$('debug-selected').onclick=()=>{const f=selectedFunction();if(f)useCodeInDebugger(f.address);};
$('debug-demo').onclick=async()=>{const job=state.job+1;await analyzeFile(new File([SpectraDebug.demo()],'spectra-decoding-loop.bin'),true);if(state.job!==job||state.busy||state.name!=='spectra-decoding-loop.bin')return;$('debug-environment').value='routine';$('debug-raw').checked=true;$('debug-mode').value='x64';$('debug-start').value='0x100000';$('debug-base').value='0x100000';$('debug-offset').value='0x0';$('debug-size').value=hex(state.bytes.length);$('debug-memory-address').value='0x60000000';$('debug-capture-size').value='64';changeView('debugger');initializeDebugger();};
$('debug-break-add').onclick=()=>{try{const n=debugNumber('debug-break-address');if(debugState.breakpoints.size+debugState.conditions.length>=128)return toast('Limit: 128 breakpoints.');debugState.breakpoints.add(n);renderDebugger();scheduleWorkspace();}catch(e){toast(e.message);}};
$('debug-register-set').onclick=()=>sendDebug('register',{name:$('debug-register-name').value,value:$('debug-register-value').value});
$('debug-memory-view').onclick=()=>{try{sendDebug('view',{address:debugNumber('debug-memory-address')});}catch(e){toast(e.message);}};
$('debug-scratch').onclick=()=>{$('debug-memory-address').value='0x60000000';sendDebug('view',{address:SpectraDebug.SCRATCH});};
$('debug-stack').onclick=()=>{const s=debugState.snapshot;if(!s)return;const sp=Number(s.registers.RSP??s.registers.ESP??s.registers.SP);$('debug-memory-address').value=hex(sp);sendDebug('view',{address:sp});};
$('debug-patch').onclick=()=>{try{const text=$('debug-patch-bytes').value.replace(/\s/g,'');if(!/^(?:[0-9a-f]{2})+$/i.test(text)||text.length>8192)throw Error('Use up to 4 KiB of hex byte pairs.');sendDebug('patch',{address:debugNumber('debug-patch-address'),bytes:Uint8Array.from(text.match(/../g),h=>parseInt(h,16))});}catch(e){toast(e.message);}};
$('debug-capture').onclick=()=>{try{sendDebug('capture',{address:debugNumber('debug-memory-address'),size:debugNumber('debug-capture-size')});}catch(e){toast(e.message);}};
$('debug-export').onclick=exportDebug;

function renderWindowsSession(s,ready){
 const w=s?.windows;$('debug-windows-panel').hidden=!w;if(!w)return;
 $('debug-windows-summary').textContent=w.phase+' · image '+hex(w.imageBase)+' · TEB '+hex(w.teb)+' · PEB '+hex(w.peb)+' · '+human(w.memoryBytes)+' mapped · '+w.eventCount+' events. '+w.warnings.join(' ');
 $('debug-map').innerHTML=s.mappings.map(r=>'<div class="mono">'+hex(r.address)+'–'+hex(r.address+r.size)+' · '+[(r.perms&1)?'R':'-',(r.perms&2)?'W':'-',(r.perms&4)?'X':'-'].join('')+' · '+esc(r.name||'Image')+'</div>').join('');
 $('debug-apis').innerHTML=[...w.events].reverse().map(e=>'<tr><td>'+e.step+'</td><td>'+esc(e.api)+'</td><td class="mono">'+esc((e.arguments||[]).join(', '))+' → '+esc(e.result??'—')+'</td><td>'+esc(e.behavior)+': '+esc(e.detail)+'</td></tr>').join('');
 $('debug-output').textContent=w.output||'No OutputDebugString calls yet.';
 $('debug-files').innerHTML=w.files.map((f,i)=>'<button class="button" data-virtual-file="'+i+'" '+(!ready||!f.size?'disabled':'')+'>'+esc(f.path)+' · '+human(f.size)+'</button>').join('')||'<p class="muted">No virtual files written.</p>';
 $('debug-files').querySelectorAll('[data-virtual-file]').forEach(b=>b.onclick=()=>sendDebug('fileCapture',{path:w.files[Number(b.dataset.virtualFile)].path}));
}
$('debug-windows-demo').onclick=async()=>{const job=state.job+1;await analyzeFile(new File([SpectraWindows.demo()],'spectra-windows-demo.exe'),true);if(state.job!==job||state.busy)return;$('debug-environment').value='windows';$('debug-raw').checked=false;changeView('debugger');initializeDebugger();};
$('debug-environment').onchange=()=>{if(['windows','linux'].includes($('debug-environment').value)){$('debug-raw').checked=false;$('debug-start').value=hex(state.result?.entry||0);}};

function renderExperiments(s,ready){
 $('debug-resume-workspace').hidden=!debugState.resumable;$('debug-resume-workspace').disabled=debugState.busy;
 $('debug-checkpoint').disabled=!ready||debugState.checkpoints.length>=8;
 $('debug-out').disabled=!ready||s?.stopped||!s?.frames?.length;
 for(const id of ['debug-condition-add','debug-watch-add'])$(id).disabled=debugState.busy;
 const options='<option value="">No condition</option>'+Object.keys(s?.registers||{}).map(n=>'<option>'+n+'</option>').join(''),reg=$('debug-condition-register').value;
 $('debug-condition-register').innerHTML=options;$('debug-condition-register').value=reg;
 $('debug-conditions').innerHTML=debugState.conditions.map((p,i)=>'<button class="chip" data-condition-remove="'+i+'">'+hex(p.address)+' · '+esc(p.condition.register+' '+p.condition.operator+' '+p.condition.value)+' ×</button>').join('');
 $('debug-watches').innerHTML=debugState.watchpoints.map((w,i)=>'<button class="chip" data-watch-remove="'+i+'">'+hex(w.address)+' + '+w.size+' · '+esc(w.access)+' ×</button>').join('');
 for(const [attr,list]of [['condition',debugState.conditions],['watch',debugState.watchpoints]])document.querySelectorAll('[data-'+attr+'-remove]').forEach(b=>{b.disabled=debugState.busy;b.onclick=()=>{list.splice(Number(b.dataset[attr+'Remove']),1);renderDebugger();scheduleWorkspace();};});
 $('debug-watch-hits').textContent=(s?.hits||[]).map(h=>h.source+' '+h.kind+' at '+hex(h.address)+' · '+h.size+' bytes').join('\n')+(s?.hitsTruncated?'\nFirst 32 hits shown.':'');
 $('debug-checkpoints').innerHTML=debugState.checkpoints.map((c,i)=>'<div class="padded"><b>'+esc(c.label)+'</b> · '+(c.imported?'Imported evidence; replay to verify · ':'')+fmt(c.summary.steps)+' steps <button class="button small" data-checkpoint-restore="'+i+'">Restore by replay</button> <button class="button small" data-checkpoint-export="'+i+'">Download</button> <button class="text-button" data-checkpoint-remove="'+i+'">Remove</button></div>').join('')||'<p class="padded muted">Save a baseline, change an input, and compare what happened.</p>';
 for(const action of ['restore','export','remove'])document.querySelectorAll('[data-checkpoint-'+action+']').forEach(b=>{b.disabled=debugState.busy;b.onclick=()=>{const i=Number(b.dataset['checkpoint'+action[0].toUpperCase()+action.slice(1)]),c=debugState.checkpoints[i];if(action==='export')download(baseName()+'.experiment.json',JSON.stringify(c));else if(action==='remove'){debugState.checkpoints.splice(i,1);renderDebugger();scheduleWorkspace();}else{try{SpectraExperiments.validate(c,state.hash);if(debugState.worker)sendDebug('restore',{checkpoint:c});else{debugState.pendingRestore=c;initializeDebugger(c.options);}}catch(e){toast(e.message);}}};});
 const choices=debugState.checkpoints.map((c,i)=>'<option value="'+i+'">'+esc(c.label)+'</option>').join('');
 for(const id of ['debug-compare-a','debug-compare-b']){const old=$(id).value;$(id).innerHTML=choices;if(old)$(id).value=old;}
 $('debug-compare').disabled=debugState.checkpoints.length<2;
}
$('debug-condition-add').onclick=()=>{try{if(debugState.conditions.length+debugState.breakpoints.size+debugState.conditions.length>=128)throw Error('Limit: 128 breakpoints total.');const register=$('debug-condition-register').value;if(!register)throw Error('Choose a register for the condition.');const condition={register,operator:$('debug-condition-op').value,value:$('debug-condition-value').value.trim()},s=debugState.snapshot;if(!s)throw Error('Initialize the debugger first.');const bits=s.registerBits?.[register]||(s.mode==='x64'&&register!=='EFLAGS'?64:32);if(!/^(?:0x[0-9a-f]+|\d+)$/i.test(condition.value)||BigInt(condition.value)>=(1n<<BigInt(bits)))throw Error('Value must fit the selected unsigned register.');debugState.conditions.push({address:debugNumber('debug-break-address'),condition});renderDebugger();scheduleWorkspace();}catch(e){toast(e.message);}};
$('debug-watch-add').onclick=()=>{try{const address=debugNumber('debug-watch-address'),size=debugNumber('debug-watch-size');if(size<1||size>65536||!Number.isSafeInteger(address+size)||debugState.watchpoints.length>=32)throw Error('Use up to 32 watchpoints, each 1–65,536 bytes.');debugState.watchpoints.push({address,size,access:$('debug-watch-access').value});renderDebugger();scheduleWorkspace();}catch(e){toast(e.message);}};
$('debug-checkpoint').onclick=()=>{debugState.checkpointLabel=$('debug-checkpoint-label').value.trim().slice(0,100);sendDebug('checkpoint');};
$('debug-checkpoint-import').onclick=()=>$('experiment-input').click();
$('experiment-input').onchange=async e=>{const f=e.target.files[0];e.target.value='';if(!f)return;try{if(f.size>8*1024*1024||debugState.checkpoints.length>=8)throw Error('Limit: 8 checkpoints, 8 MiB per document.');const c=await SpectraExperiments.validateEvidence(JSON.parse(await f.text()),state.hash);if(!c.summary?.registers||!Array.isArray(c.summary.memory))throw Error('Missing checkpoint summary.');debugState.checkpoints.push({...c,imported:true,label:(c.label||f.name).slice(0,100)});scheduleWorkspace();renderDebugger();toast('Checkpoint imported. Nothing has run. Choose Restore when ready.');}catch(err){toast(err.message);}};
$('debug-compare').onclick=()=>{try{const a=debugState.checkpoints[Number($('debug-compare-a').value)],b=debugState.checkpoints[Number($('debug-compare-b').value)],d=SpectraExperiments.compare(a,b);$('debug-comparison').textContent=a.label+' → '+b.label+'\n'+d.registers.map(r=>r.register+': '+JSON.stringify(r.before)+' → '+JSON.stringify(r.after)).join('\n')+'\n'+d.memoryPages.length+' changed memory pages\n'+d.memoryPages.slice(0,100).map(p=>hex(p.address)+': '+(!p.before?'mapped':!p.after?'unmapped':p.before.permissions!==p.after.permissions?'permissions changed':'bytes changed')).join('\n')+'\nRecipe / experiment model changed: '+d.labChanged+'\nWindows model changed: '+d.windowsChanged+'\nVirtual files before: '+JSON.stringify(d.beforeFiles)+'\nVirtual files after: '+JSON.stringify(d.afterFiles)+'\n'+d.note;download(baseName()+'.experiment-diff.json',JSON.stringify({sha256:state.hash,from:a.label,to:b.label,...d},null,2));}catch(e){toast(e.message);}};

$('debug-resume-workspace').onclick=()=>{try{const c=SpectraExperiments.validate(debugState.resumable,state.hash);if(debugState.worker)sendDebug('restore',{checkpoint:c});else{debugState.pendingRestore=c;initializeDebugger(c.options);}}catch(e){toast(e.message);}};
