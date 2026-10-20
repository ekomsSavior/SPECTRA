const androidState={inventory:null,detail:null,resource:null,selected:0,page:0,queued:null,memberAction:null,observedInventory:null,observedManifest:null,observedSource:null,observedMethod:null};
function isAndroidInput(){return state.bytes.length>=4&&(String.fromCharCode(...state.bytes.subarray(0,4))==='dex\n'||/\.apk$/i.test(state.name));}
function resetAndroid(){Object.assign(androidState,{inventory:null,detail:null,resource:null,selected:0,page:0,queued:null,memberAction:null,observedInventory:null,observedManifest:null,observedSource:null,observedMethod:null});for(const id of ['android-search','android-file-search'])if($(id))$(id).value='';if($('android-bytes'))$('android-bytes').textContent='';}
function androidSelection(){return androidState.inventory?.classes[androidState.selected];}
function androidPost(action,extra={}){
 const d=decompileState,c=androidSelection();d.busy=true;d.message=action==='open'?'Reading Android package locally…':'Working on Android evidence…';decompileTimer(60000);
 const message={id:d.id,action,...(c?{dex:c.dex,index:c.index}:{}),...extra};
 if(action==='open'){message.buffer=state.bytes.slice().buffer;d.worker.postMessage(message,[message.buffer]);}else d.worker.postMessage(message);
 renderDecompiler();
}
function runAndroid(action,extra={}){
 const d=decompileState;if(state.busy||!state.result||d.busy)return toast('Let the current job finish, or cancel it.');
 if(['class','decompile','methodBytes'].includes(action)&&!androidSelection())return toast('Read the package and select a class first.');
 if(action==='decompile')d.result=null;
 if(d.engine!=='android')stopDecompiler();
 const id=++d.id,job=state.job;d.busy=true;androidState.queued={action,extra};
 if(d.worker&&d.ready){androidState.queued=null;androidPost(action,extra);return;}
 d.engine='android';d.message='Loading the local Android decompiler…';decompileTimer(120000);
 try{
  const worker=d.worker=new Worker(ENGINE_ROOT+'android/worker.mjs',{type:'module'});
  worker.onmessage=async({data:m})=>{
   if(state.job!==job||d.worker!==worker)return;
   if(m.ready){androidPost('open');return;}if(m.id!==d.id)return;
   if(m.progress){d.message=m.progress;renderDecompiler();return;}
   clearTimeout(d.timer);
   if(m.error){stopDecompiler('Android analysis stopped: '+m.error+' Your original file is still open.');renderDecompiler();return;}
   if(m.inventory){
    androidState.inventory=m.inventory;androidState.observedInventory=state.hash;d.ready=true;const queued=androidState.queued;androidState.queued=null;
    if(androidState.selected>=m.inventory.classes.length)androidState.selected=0;
    d.message='Android inventory ready. Select a class, then Decompile.';
    if(queued&&queued.action!=='open'){androidPost(queued.action,queued.extra);return;}
   }
   if(m.detail){androidState.detail=m.detail;$('android-bytes').textContent='';d.message='Class metadata loaded. Decompile it, or inspect a method’s DEX bytes.';}
   if(m.result){androidState.observedSource=state.hash;d.result={...m.result,sha256:state.hash,sample:state.name,createdAt:new Date().toISOString(),stale:false};androidState.detail=m.result.detail;d.message='Java reconstructed locally. Check the warnings and the method evidence.';scheduleWorkspace();}
   if(m.resource){androidState.resource=m.resource;if(m.resource.name==='AndroidManifest.xml')androidState.observedManifest=state.hash;d.message='Decoded '+m.resource.name+' locally.';}
   if(m.methodBytes){if(m.methodBytes.includes('DEX instruction range'))androidState.observedMethod=state.hash;$('android-bytes').textContent=m.methodBytes;d.message='DEX method bytes shown. They are not native CPU instructions.';}
   d.busy=false;renderDecompiler();
   if(m.member){const purpose=androidState.memberAction;androidState.memberAction=null;await androidMember(m.member,purpose);}
  };
  worker.onerror=e=>{if(d.worker===worker&&state.job===job)decompilerFailure(e.message||'Android worker error.',d.ready?'analysis':'startup');};
 }catch(e){decompilerFailure(e.message);}
 renderDecompiler();
}
function renderAndroid(){
 const a=androidState,d=decompileState,active=$('decompile-engine').value==='android';$('android-panel').hidden=!active;if(!active)return;
 const inv=a.inventory;
 for(const id of ['android-read','android-search','android-classes','android-method','android-file-search','android-files'])$(id).disabled=d.busy;
 for(const id of ['android-inventory','android-resource','android-member-open','android-member-save'])$(id).disabled=d.busy||!inv;
 $('android-resource-export').disabled=!a.resource||d.busy;
 $('android-method-bytes').disabled=!a.detail||d.busy;$('android-open-dex').disabled=!a.detail||d.busy;
 if(inv)$('android-summary').textContent=inv.dexes.length+' DEX files · '+fmt(inv.classes.length)+' classes · '+fmt(inv.files.length)+' package members. '+inv.warnings.join(' ');
 else $('android-summary').textContent='64 MiB input · up to 32 DEX files, 32 MiB each / 64 MiB combined · 50,000 classes · 60 seconds per job. No uploads.';
 const q=$('android-search').value.toLowerCase(),rows=(inv?.classes||[]).map((c,i)=>({...c,i})).filter(c=>!q||c.name.toLowerCase().includes(q)),pages=Math.max(1,Math.ceil(rows.length/100));a.page=Math.min(a.page,pages-1);
 $('android-classes').innerHTML=rows.slice(a.page*100,a.page*100+100).map(c=>'<option value="'+c.i+'">'+esc(c.name)+' · '+esc(inv.dexes[c.dex].file)+' · '+c.methods+' methods</option>').join('');$('android-classes').value=String(a.selected);
 $('android-page').textContent=rows.length?`${a.page+1} / ${pages} · ${fmt(rows.length)} matches`:'No classes found';$('android-prev').disabled=d.busy||a.page===0;$('android-next').disabled=d.busy||a.page>=pages-1;
 const detail=a.detail,method=$('android-method').value;
 $('android-detail').textContent=detail?[detail.name,'DEX: '+detail.file,'DEX SHA-256: '+detail.sha256,'Class definition: '+hex(detail.offset),'Superclass: '+(detail.superclass||'none'),'Declared source name: '+(detail.source||'absent'),detail.fields.length+' listed fields · '+detail.methods.length+' listed methods',...(detail.membersClipped?['Member display is limited to the first 2,000 fields/methods.']:[])].join('\n'):'Choose a class to inspect its definitions. Java reconstruction appears below.';
 $('android-method').innerHTML=detail?detail.methods.map((m,i)=>'<option value="'+i+'">'+esc(m.name+m.descriptor)+(m.codeOffset?' · DEX '+hex(m.instructionOffset):' · no code')+'</option>').join(''):'<option value="">Choose a class first</option>';
 if(detail?.methods[Number(method)])$('android-method').value=method;
 const fq=$('android-file-search').value.toLowerCase(),files=(inv?.files||[]).filter(f=>!fq||f.name.toLowerCase().includes(fq)),chosen=$('android-files').value;
 $('android-files').innerHTML=files.slice(0,200).map(f=>'<option value="'+esc(f.name)+'">'+esc(f.name)+' · '+human(f.length)+'</option>').join('');
 if(files.slice(0,200).some(f=>f.name===chosen))$('android-files').value=chosen;
 $('android-file-count').textContent=files.length>200?`${fmt(files.length)} matches; showing the first 200. Narrow the search.`:`${files.length} matching members.`;
 $('android-resource-output').textContent=a.resource?(a.resource.kind==='xml'?a.resource.text+'\n\n'+a.resource.warnings.join('\n'):JSON.stringify(a.resource,null,2)):'Choose the manifest, a resource XML, or resources.arsc.';
 const tokens=d.result?.engineKind==='android'?d.result.tokens||[]:[],links=[],seen=new Set(),targets=new Map();
 for(const [i,c]of (inv?.classes||[]).entries())targets.set(c.name,targets.has(c.name)?-1:i);
 for(const t of tokens){if(t.declaration||!['method','class','field'].includes(t.kind))continue;const key=t.className+'::'+t.name+t.descriptor;if(seen.has(key))continue;seen.add(key);const target=targets.get(t.className);if(target!==undefined&&target>=0)links.push({target,label:key});if(links.length>=100)break;}
 $('android-source-links').innerHTML=links.length?links.map(t=>'<button class="text-button" data-android-ref="'+t.target+'">'+esc(t.label)+'</button>').join(''):'No unambiguous in-package source references in the current reconstruction.';
 $('android-source-links').querySelectorAll('[data-android-ref]').forEach(b=>{b.disabled=d.busy;b.onclick=()=>selectAndroidClass(Number(b.dataset.androidRef),true);});
}
function selectAndroidClass(index,decompile=false){
 if(decompileState.busy)return;androidState.selected=index;androidState.detail=null;decompileState.result=null;const c=androidSelection();if(!c)return;
 if(decompile){$('android-search').value='';androidState.page=Math.floor(index/100);}
 runAndroid(decompile?'decompile':'class');
}
async function androidMember(member,purpose){
 const bytes=new Uint8Array(member.buffer),name=member.name.split('/').pop().replace(/[^a-z0-9._-]/gi,'_');
 if(purpose?.kind==='save'){download(name+'.extracted.bin',bytes,'application/octet-stream');return;}
 if(purpose?.kind!=='open')return;
 if(!bytes.length)return toast('This member is empty. Download it to preserve the evidence.');
 const sourceJob=state.job;const file=androidState.inventory?.files.find(f=>f.name===member.name),parent={kind:'container-member',sha256:state.hash,name:state.name,format:'APK / DEX',entry:member.name,entryOffset:file?.direct?0:file?.offset,offsetKind:file?.direct?'direct bytes':file?.method===0?'stored member bytes':'compressed member; no linear parent offset',size:bytes.length,childSha256:await SpectraExperiments.sha(bytes)};
 if(state.job!==sourceJob)return;await analyzeFile(new File([bytes],name));if(state.job!==sourceJob+1||state.hash!==parent.childSha256)return;
 investigation.provenance=parent;state.caseNotes='[Android package member]\n'+JSON.stringify(parent,null,2);persist();
 if(purpose.offset!==undefined){state.hexStart=Math.floor(purpose.offset/HEX_PAGE)*HEX_PAGE;changeView('hex');renderHex();}else changeView('decompile');
}
$('android-read').onclick=()=>runAndroid('open');
$('android-classes').onchange=e=>selectAndroidClass(Number(e.target.value));
$('android-search').oninput=()=>{androidState.page=0;renderAndroid();};
$('android-prev').onclick=()=>{androidState.page--;renderAndroid();};$('android-next').onclick=()=>{androidState.page++;renderAndroid();};
$('android-file-search').oninput=renderAndroid;
$('android-resource').onclick=()=>runAndroid('resource',{name:$('android-files').value});
$('android-resource-export').onclick=()=>{const r=androidState.resource;if(r)download(baseName()+'.android-resource.json',JSON.stringify({schema:'spectra-android-resource-v1',sampleSha256:state.hash,...r},null,2));};
$('android-inventory').onclick=()=>{if(androidState.inventory)download(baseName()+'.android-inventory.json',JSON.stringify({schema:'spectra-android-inventory-v1',sample:state.name,...androidState.inventory},null,2));};
$('android-method-bytes').onclick=()=>runAndroid('methodBytes',{method:Number($('android-method').value)});
$('android-open-dex').onclick=()=>{const detail=androidState.detail;if(!detail||!confirm('Open this DEX as a child investigation? Export or save your current investigation first if you need to keep it.'))return;androidState.memberAction={kind:'open',offset:detail.methods[Number($('android-method').value)]?.instructionOffset||detail.offset};runAndroid('extract',{name:detail.file});};
for(const [id,kind]of [['android-member-open','open'],['android-member-save','save']])$(id).onclick=()=>{if(kind==='open'&&!confirm('Open this member as a child investigation? Export or save your current investigation first if you need to keep it.'))return;androidState.memberAction={kind};runAndroid('extract',{name:$('android-files').value});};
$('decompile-android-demo').onclick=async()=>{const job=state.job;try{const response=await fetch(ENGINE_ROOT+'fixtures/AndroidTraining.apk');if(!response.ok)throw Error('Android demo unavailable ('+response.status+').');const bytes=await response.arrayBuffer();if(job!==state.job)return;await analyzeFile(new File([bytes],'AndroidTraining.apk'),true);if(state.job===job+1){$('decompile-engine').value='android';changeView('decompile');runAndroid('open');}}catch(e){toast(e.message);}};
