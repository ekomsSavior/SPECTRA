const decompileState={worker:null,engine:null,ready:false,busy:false,timer:null,id:0,pending:null,result:null,types:[],base64:null,assembly:null,analysisWarnings:[],dependencies:[],harnessSelected:new Set(),harnessFocus:null,message:'Pick a function. The engine downloads on first use; the file never uploads.'};
const ENGINE_ROOT='./engines/v08/';
function stopDecompiler(message){decompileState.worker?.terminate();clearTimeout(decompileState.timer);Object.assign(decompileState,{worker:null,ready:false,busy:false,engine:null,pending:null,id:decompileState.id+1});if(message)decompileState.message=message;}
function resetDecompiler(){stopDecompiler();decompileState.restoreManaged=null;$('harness-recipe').value='';Object.assign(decompileState,{result:null,types:[],base64:null,assembly:null,analysisWarnings:[],dependencies:[],harnessSelected:new Set(),harnessFocus:null,message:'Pick a function. The engine downloads on first use; the file never uploads.'});renderDecompiler();}
function isManagedImage(){try{const b=state.bytes,v=new DataView(b.buffer,b.byteOffset,b.byteLength);if(v.getUint16(0,true)!==0x5a4d)return false;const opt=v.getUint32(0x3c,true)+24,wide=v.getUint16(opt,true)===0x20b;return v.getUint32(opt+(wide?112:96)+14*8,true)>0;}catch{return false;}}
function setDecompilerDefaults(){if(!state.result)return;$('decompile-engine').value=isManagedImage()?'managed':'native';$('decompile-address').value=hex(state.result.entry||0x100000);$('decompile-compiler').value='auto';$('decompile-architecture').value='auto';$('decompile-endian').value='auto';$('decompile-raw').checked=false;$('decompile-use-types').checked=false;$('decompile-prototype').value='';$('decompile-types-input').value='';$('decompile-size').value=hex(Math.min(state.bytes.length,65536));renderDecompiler();}
function useFunctionDecompiler(address){$('decompile-engine').value='native';$('decompile-address').value=hex(address);selectNativeAssumptions();changeView('decompile');toast('Function selected. Hit Decompile when ready.');}
function nativeOptions(){
 const entry=SpectraDebug.address($('decompile-address').value.trim()),codeRaw=codeState.data?.raw,mode=$('decompile-architecture').value;
 const raw=$('decompile-raw').checked?{offset:debugNumber('decompile-offset'),size:debugNumber('decompile-size'),address:debugNumber('decompile-base')}:codeRaw?{offset:codeRaw.offset,size:codeRaw.size,address:codeRaw.address}:null;
 const options={entry,mode:mode==='auto'&&codeRaw?({'arm64':'aarch64'})[codeState.data.mode]||codeState.data.mode:mode,endian:$('decompile-endian').value,raw,functions:codeState.data?.functions||state.result.seeds,compiler:$('decompile-compiler').value,acceptAbi:$('decompile-abi-accept').checked,name:investigation.annotations.get(entry)?.name||undefined};
 const plan=SpectraNative.plan(state.bytes,state.result,options),key=plan.language+'@'+entry;
 if($('decompile-use-types').checked){const declaration=$('decompile-prototype').value.trim(),type=$('decompile-types-input').value.trim();options.prototypes=declaration?[{address:entry,declaration}]:[];options.types=type?[type]:[];investigation.nativeAssumptions.set(key,{declaration,type});}else investigation.nativeAssumptions.delete(key);
 return options;
}
function selectNativeAssumptions(){try{const o={entry:debugNumber('decompile-address'),mode:$('decompile-architecture').value,endian:$('decompile-endian').value,compiler:$('decompile-compiler').value,acceptAbi:$('decompile-abi-accept').checked,raw:$('decompile-raw').checked?{offset:debugNumber('decompile-offset'),size:debugNumber('decompile-size'),address:debugNumber('decompile-base')}:null},p=SpectraNative.plan(state.bytes,state.result,o),a=investigation.nativeAssumptions.get(p.language+'@'+p.entry);$('decompile-use-types').checked=!!a;$('decompile-prototype').value=a?.declaration||'';$('decompile-types-input').value=a?.type||'';}catch{}}

function decompileTimer(ms){clearTimeout(decompileState.timer);decompileState.timer=setTimeout(()=>{stopDecompiler('Engine stopped at the time limit. Pick a smaller function/type and try again.');renderDecompiler();},ms);}
function sendDecompile(){const m=decompileState.pending;if(!m)return;decompileState.pending=null;decompileState.message=m.token===-1?'Reading managed metadata…':'Reconstructing code locally…';decompileTimer(60000);if(m.buffer)decompileState.worker.postMessage(m,[m.buffer]);else decompileState.worker.postMessage(m);renderDecompiler();}
function runDecompiler(token=0){
 if(state.busy||!state.result||decompileState.busy)return toast('Let the current job finish, or cancel it.');
 const engine=$('decompile-engine').value;let job;
 try{
  if(engine==='native'){if(isManagedImage())throw Error('This is a managed PE. Choose ILSpy for its C#.');const options=nativeOptions(),{strings,blocks,...meta}=state.result;SpectraNative.plan(state.bytes,meta,options);job={buffer:state.bytes.slice().buffer,meta,options};}
  else{if(state.bytes.length>16*1024*1024)throw Error('.NET input cap: 16 MiB.');if(!decompileState.base64){let text='';for(let i=0;i<state.bytes.length;i+=32768)text+=String.fromCharCode(...state.bytes.subarray(i,i+32768));decompileState.base64=btoa(text);}job={base64:decompileState.base64,token,dependencies:decompileState.dependencies.map(d=>({name:d.name,base64:d.base64}))};}
 }catch(e){return toast(e.message);}
 if(decompileState.engine!==engine)stopDecompiler();const id=++decompileState.id,sourceJob=state.job;decompileState.busy=true;decompileState.pending={id,...job};
 if(!decompileState.worker){
  decompileState.message='Loading '+(engine==='native'?'Ghidra + selected processor specs':'ILSpy + .NET runtime (~13 MiB)')+' from this site. Your sample stays local…';
  try{decompileState.worker=new Worker(ENGINE_ROOT+(engine==='native'?'native/worker.mjs?rev=1':'managed/worker.mjs'),{type:'module'});decompileState.engine=engine;
   decompileState.worker.onmessage=({data:m})=>{
    if(sourceJob!==state.job)return;
    if(m.ready){decompileState.ready=true;sendDecompile();return;}
    if(m.id!==undefined&&m.id!==decompileState.id)return;
    clearTimeout(decompileState.timer);decompileState.busy=false;
    if(m.error){stopDecompiler('Could not decompile: '+m.error);renderDecompiler();return;}
    if(m.result){const r=m.result;if(r.types){decompileState.types=SpectraHarness.enrich(r.types);decompileState.assembly=r.assembly;decompileState.analysisWarnings=r.analysisWarnings||[];}decompileState.result={...r,sha256:state.hash,sample:state.name,selection:engine==='native'?{entry:r.plan.entry}:{token:decompileState.lastToken},engineKind:engine,createdAt:new Date().toISOString()};decompileState.message=r.code?((engine==='native'?'Ghidra reconstructed C':'ILSpy reconstructed C#')+' · review the warnings below.'):'Metadata loaded. Pick a type or method to reconstruct its C#.';}
    const restored=decompileState.restoreManaged;if(restored&&m.result?.types){decompileState.result=restored.result;decompileState.restoreManaged=null;}renderDecompiler();if(restored&&m.result?.types)setSettings(restored.settings);renderLearning();scheduleWorkspace();
   };
   decompileState.worker.onerror=e=>{if(sourceJob!==state.job)return;stopDecompiler('Engine could not start: '+(e.message||'worker error')+'. Retry, or use the hosted page if you opened an offline HTML file.');renderDecompiler();};decompileTimer(120000);
  }catch(e){stopDecompiler(e.message);}
 }else sendDecompile();
 decompileState.lastToken=token;renderDecompiler();
}
function renderDecompiler(){
 if(!$('decompile-status'))return;const d=decompileState,managed=$('decompile-engine').value==='managed';
 $('decompile-dependencies-panel').hidden=!managed;$('decompile-dependency-list').textContent=d.dependencies.map(dep=>dep.name+' · '+human(dep.bytes.length)+' · '+dep.sha256).join('\n')||'No local dependencies selected.';
 $('decompile-status').textContent=d.message;$('decompile-run').disabled=d.busy||state.busy;$('decompile-tree').disabled=d.busy||state.busy;$('decompile-tree').hidden=!managed;$('decompile-cancel').hidden=!d.busy;$('decompile-engine').disabled=d.busy;
 $('decompile-address-wrap').hidden=managed;$('decompile-selected').hidden=managed;$('decompile-native-controls').hidden=managed;$('decompile-hardware-controls').hidden=managed;$('decompile-selected').disabled=!selectedFunction()||d.busy;
 for(const id of ['decompile-copy','decompile-export'])$(id).disabled=!d.result?.code;$('decompile-report').disabled=!d.result;
 const funcs=codeState.data?.functions||state.result?.seeds||[],value=$('decompile-functions').value;$('decompile-functions').innerHTML='<option value="">Entry / custom address</option>'+funcs.slice(0,2000).map(f=>'<option value="'+f.address+'">'+esc(f.name||'sub_'+f.address.toString(16))+' · '+hex(f.address)+'</option>').join('');$('decompile-functions').value=value;
 $('decompile-tree-panel').hidden=!managed||!d.types.length;renderManagedTree();renderHarness();
 $('decompile-output').textContent=d.result?.code||'The code will land here. Treat it as a reconstruction, then check the assembly.';
 $('decompile-output-title').textContent=d.result?.code?(d.result.engineKind==='managed'?'C# · '+(d.result.selection.token===0?'assembly':hex(d.result.selection.token)):'C · '+hex(d.result.plan.entry)):'Reconstructed source';
 $('decompile-warnings').textContent=d.result?[(d.result.engineKind==='managed'?'Reconstructed C#. Original comments and some names are gone. Missing dependencies can change type and expression recovery.':'Ghidra output depends on the selected start, mappings, calling convention, and inferred signatures.'),...(d.result.warnings||[]),...(d.result.analysisWarnings||[]),...(d.result.dependencies?.length?['Local dependencies: '+d.result.dependencies.map(x=>x.identity+' ['+(x.resolved?'resolved':'supplied, not referenced')+']').join('; ')]:[]),...(d.result.missingReferences?.length?['Unresolved dependencies: '+d.result.missingReferences.join('; ')]:[])].join(' '):'';
 $('decompile-imports').innerHTML='<table class="simple-table"><thead><tr><th>LIBRARY</th><th>IMPORT</th><th>SLOT VA</th></tr></thead><tbody>'+(state.result?.imports||[]).slice(0,1000).map(i=>'<tr><td>'+esc(i.library)+'</td><td>'+esc(i.name)+'</td><td>'+esc(i.address!==undefined?hex(i.address):'—')+'</td></tr>').join('')+'</tbody></table>';
}
$('decompile-engine').onchange=()=>{stopDecompiler();decompileState.result=null;decompileState.message='Choose a function, or browse managed types.';renderDecompiler();};
$('decompile-run').onclick=()=>runDecompiler(0);$('decompile-tree').onclick=()=>runDecompiler(-1);$('decompile-cancel').onclick=()=>{stopDecompiler('Cancelled. The engine worker was terminated.');renderDecompiler();};
$('decompile-selected').onclick=()=>{const f=selectedFunction();if(f)useFunctionDecompiler(f.address);};$('decompile-discover').onclick=()=>{startCode();};
$('decompile-functions').onchange=e=>{if(e.target.value){$('decompile-address').value=hex(Number(e.target.value));selectNativeAssumptions();}};$('decompile-search').oninput=renderDecompiler;
$('decompile-copy').onclick=()=>copy(decompileState.result.code);
$('decompile-export').onclick=()=>download(baseName()+(decompileState.result.engineKind==='managed'?'.cs':'.c'),decompileState.result.code,'text/plain');
$('decompile-report').onclick=()=>download(baseName()+'.decompilation.json',JSON.stringify({tool:'SPECTRA 0.7',...decompileState.result},null,2));
$('decompile-native-demo').onclick=async()=>{const job=state.job+1,b=SpectraWindows.demo();b.fill(0x90,512,1024);b.set([0x31,0xc0,0x85,0xc9,0x7e,6,1,0xc8,0xff,0xc9,0x75,0xfa,0xc3],512);await analyzeFile(new File([b],'spectra-native-loop.exe'),true);if(state.job===job)changeView('decompile');};
$('decompile-managed-demo').onclick=async()=>{const job=state.job;try{const r=await fetch(ENGINE_ROOT+'fixtures/ManagedTraining.dll');if(!r.ok)throw Error('Demo unavailable ('+r.status+').');const bytes=await r.arrayBuffer();if(state.job!==job)return;await analyzeFile(new File([bytes],'ManagedTraining.dll'),true);if(state.job===job+1)changeView('decompile');}catch(e){toast(e.message);}};

for(const id of ['decompile-address','decompile-architecture','decompile-compiler','decompile-endian'])$(id).onchange=selectNativeAssumptions;
$('decompile-hardware-demo').onclick=async()=>{let mode=$('decompile-architecture').value;if(!['arm','thumb','cortex','aarch64','riscv32','riscv64','mips32','mips64'].includes(mode))mode='arm';const samples={arm:'010080e01eff2fe1',thumb:'40187047',cortex:'40187047',aarch64:'0000018bc0035fd6',riscv32:'2e958280',riscv64:'2e958280',mips32:'211085000800e00301004224',mips64:'2d1085000800e00301004264'},bytes=Uint8Array.from(samples[mode].match(/../g),x=>parseInt(x,16));await analyzeFile(new File([bytes],'spectra-'+mode+'-add.bin'),true);$('decompile-engine').value='native';$('decompile-architecture').value=mode;$('decompile-endian').value='little';$('decompile-compiler').value='auto';$('decompile-raw').checked=true;$('decompile-offset').value='0x0';$('decompile-size').value=hex(bytes.length);$('decompile-base').value='0x1000';$('decompile-address').value='0x1000';changeView('decompile');toast('Benign addition function loaded. MIPS includes a +1 in the return delay slot.');};

function bytesBase64(bytes){let text='';for(let i=0;i<bytes.length;i+=32768)text+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(text);}
$('decompile-dependencies').onclick=()=>$('dependency-input').click();
$('decompile-dependencies-clear').onclick=()=>{stopDecompiler();decompileState.dependencies=[];decompileState.result=null;renderDecompiler();scheduleWorkspace();};
$('dependency-input').onchange=async e=>{const files=[...e.target.files];e.target.value='';const job=state.job;try{if(files.length+decompileState.dependencies.length>32)throw Error('Choose at most 32 local dependencies.');let total=state.bytes.length+decompileState.dependencies.reduce((n,d)=>n+d.bytes.length,0);for(const f of files){total+=f.size;if(f.size>16*1024*1024||total>64*1024*1024)throw Error('Limit: 16 MiB per dependency, 64 MiB including the main image.');}const added=[];for(const f of files){const bytes=new Uint8Array(await f.arrayBuffer());added.push({name:f.name.slice(0,240),bytes,base64:bytesBase64(bytes),sha256:await SpectraExperiments.sha(bytes)});}if(job!==state.job)return;stopDecompiler();decompileState.dependencies.push(...added);decompileState.result=null;decompileState.message='Dependencies loaded as bytes. Decompile to resolve exact assembly identities; none are executed.';renderDecompiler();scheduleWorkspace();}catch(err){toast(err.message);}};
