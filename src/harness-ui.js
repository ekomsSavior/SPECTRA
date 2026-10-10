function harnessInput(){return {types:decompileState.types,assembly:decompileState.assembly,sha256:state.hash,sample:state.name,selected:[...decompileState.harnessSelected],primaryToken:Number($('harness-entry').value),analysisWarnings:decompileState.analysisWarnings};}
function setHarnessSelection(tokens,add){const current=decompileState.harnessSelected,next=new Set(current);for(const token of tokens){if(add)next.add(token);else next.delete(token);}if(next.size>2000)return toast('Harness cap: 2,000 methods. Pick a smaller class or selection.');decompileState.harnessSelected=next;renderDecompiler();scheduleWorkspace();}
function renderManagedTree(){
 const d=decompileState,q=$('decompile-search').value.trim().toLowerCase(),category=$('decompile-category').value;
 const open=new Set([...$('decompile-types').querySelectorAll('details[open][data-type]')].map(el=>Number(el.dataset.type)));
 const matches=(t,m)=>(!q||(t.fullName||t.ns+'.'+t.name).toLowerCase().includes(q)||m.signature.toLowerCase().includes(q))&&(category==='all'||m.labels.some(l=>l.category===category));
 let nodes=0,shown=0,clipped=false;
 $('decompile-types').innerHTML=d.types.filter(t=>t.methods.some(m=>matches(t,m))).map(t=>{
  if(shown++>=500){clipped=true;return '';}
  return '<details data-type="'+t.token+'" '+(q||category!=='all'||open.has(t.token)?'open':'')+'><summary>'+esc(t.fullName||t.name)+(t.labels.length?' <span class="muted tiny">'+esc(t.labels.join(' · '))+'</span>':'')+'</summary><div class="managed-type-tools"><button class="text-button" data-managed-token="'+t.token+'">Decompile type</button><button class="text-button" data-select-type="'+t.token+'">Add class to harness</button></div>'+t.methods.filter(m=>matches(t,m)).map(m=>{
   if(++nodes>1500){clipped=true;return '';}
   return '<div class="managed-method"><label class="managed-pick"><input type="checkbox" data-harness-token="'+m.token+'" '+(d.harnessSelected.has(m.token)?'checked':'')+' aria-label="Select '+esc(t.fullName+'::'+m.name+' '+hex(m.token))+' for harness"/></label><div><button class="text-button mono" data-managed-token="'+m.token+'" title="'+esc(m.signature)+'">'+esc(m.name)+' · '+hex(m.token)+'</button><div class="method-tags">'+m.labels.map(l=>'<span class="signal-tag">'+esc(l.category)+'</span>').join('')+'<button class="text-button evidence-link" data-harness-focus="'+m.token+'" aria-label="Inspect clues for '+esc(m.name)+' '+hex(m.token)+'">Clues ↗</button></div></div></div>';
  }).join('')+'</details>';
 }).join('')+(clipped?'<p class="muted">Tree display capped at 500 types / 1,500 methods. Search or filter to narrow it.</p>':'');
 $('decompile-types').querySelectorAll('[data-managed-token]').forEach(b=>{b.disabled=d.busy;b.onclick=()=>{d.harnessFocus=Number(b.dataset.managedToken);runDecompiler(d.harnessFocus);};});
 $('decompile-types').querySelectorAll('[data-harness-token]').forEach(b=>{b.onchange=()=>setHarnessSelection([Number(b.dataset.harnessToken)],b.checked);});
 $('decompile-types').querySelectorAll('[data-select-type]').forEach(b=>{b.onclick=()=>setHarnessSelection(d.types.find(t=>t.token===Number(b.dataset.selectType)).methods.map(m=>m.token),true);});
 $('decompile-types').querySelectorAll('[data-harness-focus]').forEach(b=>{b.onclick=()=>{d.harnessFocus=Number(b.dataset.harnessFocus);renderHarness();$('harness-evidence').scrollIntoView({block:'nearest',behavior:'smooth'});};});
}
function renderHarness(){
 const d=decompileState,managed=$('decompile-engine').value==='managed';$('harness-panel').hidden=!managed;
 const methods=d.types.flatMap(t=>t.methods.map(m=>({t,m}))),selected=methods.filter(({m})=>d.harnessSelected.has(m.token));
 $('harness-count').textContent=selected.length+' selected';
 $('harness-assembly').disabled=!methods.length||d.busy;$('harness-clear').disabled=!selected.length;
 $('harness-download').disabled=!selected.length||!state.hash||d.busy;$('harness-manifest').disabled=$('harness-download').disabled;
 const entry=$('harness-entry').value;
 $('harness-entry').innerHTML=selected.filter(({m})=>!m.name.startsWith('.')).map(({t,m})=>'<option value="'+m.token+'">'+esc(t.fullName+'::'+m.name+' · '+hex(m.token))+'</option>').join('');
 if(selected.some(({m})=>String(m.token)===entry))$('harness-entry').value=entry;
 $('harness-entry').disabled=!selected.length;
 $('harness-download').disabled=$('harness-download').disabled||!selected.some(({m})=>!m.name.startsWith('.'));
 $('harness-summary').textContent=methods.length?'Assembly clues · '+SpectraHarness.CATEGORIES.map(c=>c+': '+methods.filter(({m})=>m.labels.some(l=>l.category===c)).length).join(' · '):'';
 $('harness-identity').textContent=d.assembly?d.assembly.name+' · '+d.assembly.targetFramework+' · '+d.assembly.machine+' / '+d.assembly.corFlags:'Browse .NET types, then tick methods or add a class to your harness.';
 $('harness-compatibility').textContent=d.assembly?.targetFramework.startsWith('.NETFramework')?'This is a .NET Framework client. Choose the experimental Framework 4.8 host and match its architecture. It is compile-tested; Windows execution still needs validation. UI/COM/startup behavior may need custom LabHooks.cs.':'Match the runner to the client’s runtime, OS and CPU. UI setup, login state, complex objects and native dependencies may need LabHooks.cs.';
 const focused=methods.find(({m})=>m.token===d.harnessFocus),type=d.types.find(t=>t.token===d.harnessFocus);
 const targets=focused?[focused]:type?type.methods.map(m=>({t:type,m})):[];
 if(!targets.length){$('harness-evidence').innerHTML='<p class="muted">Hit Clues beside a method. Labels point you toward crypto, auth, networking, serialization and file access. Each one keeps the evidence that triggered it.</p>';return;}
 const title=focused?focused.m.signature:type.fullName,rows=targets.flatMap(({t,m})=>m.labels.flatMap(l=>l.evidence.map(e=>({m,category:l.category,...e}))));
 $('harness-evidence').innerHTML='<h3>'+esc(title)+'</h3>'+(focused?'<p class="muted">'+esc(SpectraHarness.readiness(focused.m))+'</p>':'')+'<p class="muted tiny">IL calls/references are stronger clues than names or strings. Declared API names/scopes can be spoofed. These are leads, not proof the code runs.</p>'+(rows.length?'<div class="simple-scroll"><table class="simple-table"><thead><tr><th>LABEL</th><th>BASIS</th><th>LOCATION</th><th>EVIDENCE</th></tr></thead><tbody>'+rows.slice(0,150).map(e=>'<tr><td>'+esc(e.category)+'</td><td>'+esc(e.basis)+(e.stateMachine?'<br/><span class="muted">generated state machine</span>':'')+'</td><td>'+hex(e.sourceToken)+(e.offset!==undefined?'<br/>IL_'+e.offset.toString(16).padStart(4,'0'):'')+'</td><td>'+esc(e.opcode?e.opcode+' ':'')+esc(e.value)+(e.scope?'<br/><span class="muted tiny">Declared scope: '+esc(e.scope)+'</span>':'')+'</td></tr>').join('')+'</tbody></table></div>':'<p class="muted">No category clues in the scanned evidence. That does not rule out hidden or indirect behavior.</p>')+targets.flatMap(({m})=>m.warnings.map(w=>'<p class="muted tiny">'+esc(m.name+': '+w)+'</p>')).slice(0,30).join('')+(rows.length>150?'<p class="muted tiny">Showing 150 evidence rows. Export the manifest for this selection.</p>':'');
}
$('decompile-category').onchange=renderDecompiler;
$('harness-assembly').onclick=()=>setHarnessSelection(decompileState.types.flatMap(t=>t.methods.map(m=>m.token)),true);
$('harness-clear').onclick=()=>{decompileState.harnessSelected=new Set();renderDecompiler();scheduleWorkspace();};
$('harness-download').onclick=()=>{try{const files=SpectraHarness.projectFiles(harnessInput(),SPECTRA_HARNESS_TEMPLATES,$('harness-target').value,$('harness-platform').value,$('harness-recipe').value.trim()?JSON.parse($('harness-recipe').value):null);download(baseName()+'.spectra-harness.zip',SpectraHarness.zip(files),'application/zip');toast('Harness downloaded. Read README.txt; dotnet run previews without loading the client.');}catch(e){toast(e.message);}};
$('harness-manifest').onclick=()=>{try{download(baseName()+'.harness-selection.json',JSON.stringify(SpectraHarness.manifest(harnessInput()),null,2));}catch(e){toast(e.message);}};
