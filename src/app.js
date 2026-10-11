(() => {
  'use strict';
  const $=id=>document.getElementById(id), core=SpectraCore;
  const state={result:null,bytes:new Uint8Array(),name:'',hash:'',demo:false,selected:null,tag:'all',page:0,sort:1,filtered:[],view:'strings',hexStart:0,bookmarks:new Set(),notes:{},caseNotes:'',job:0,busy:false};
  const PAGE=100, HEX_PAGE=256, MAX_FILE=64*1024*1024;
  const titles={system:["Boot a little world.","A Linux shell, shared files, and checkpoints. All inside this browser.","System lab"],detect:['Check the fingerprints.','Toolchains, packers and protectors. Keep the evidence behind the label.','Detect'],lessons:['Get your hands dirty.','Small binaries. Real evidence. No experience required.','Training ground'],compare:["Follow the changes.","Put two versions beside each other. Check what actually changed.","Binary diff"],firmware:["Look inside.","Extract regular files and keep their container provenance.","Firmware files"],decompile:['See the bigger picture.','Reconstruct the logic. Check it against the bytes.','Decompile'],debugger:['Watch it happen.','Step through a routine. Keep track of what changes.','Debugger lab'],recovery:['Peel back a layer.','Decode bytes, trace stack writes, and keep the evidence.','Recovery lab'],code:['Read the code.','Follow calls, inspect branches, and check the bytes.','Disassembly'],functions:['Find the functions.','Entry points, symbols, direct calls, and inferred boundaries.','Functions'],references:['Follow the references.','Trace code to strings, imports, and other code.','Cross-references'],strings:['SPECTRA.','','Strings'],hex:['Under the surface.','Follow the evidence to the exact bytes that produced it.','Hex explorer'],structure:['Read the blueprint.','File identity, memory sections, and the libraries behind the behavior.','File structure'],decoder:['Make it readable.','Peel back a layer. Turn encoded text into something you can investigate.','Decoder lab'],notebook:['Connect the dots.','Keep the evidence, capture your thinking, and take the investigation with you.','Notebook']};
  const tagLabel={url:'URL',ip:'IP address',domain:'Domain',email:'Email',path:'File path',registry:'Registry',command:'Command',api:'API',base64:'Base64?'};
  const explanations={url:'Looks like a URL. Check its code references before calling it a callback address.',ip:'Looks like an IPv4 address. It could be a destination, a default, or leftover test data.',domain:'Looks like a domain. We have not looked it up or contacted it.',email:'Looks like an email address. Check the surrounding data for context.',path:'A file path or environment variable. Follow its references to see what might read or write there.',registry:'A registry path. The nearby code can tell you whether it gets read, changed, or just printed.',command:'Names a shell or system tool. That does not mean the sample runs it—follow the reference.',api:'An API name worth a look. Check the call and its arguments; normal software uses these too.',base64:'Could be Base64. Send it to the decoder and see what comes back.'};
  let worker=null, workerURL=null, toastTimer=null, searchTimer=null, noteTimer=null, pendingReject=null;
  const esc=s=>String(s!==null&&typeof s==='object'?'[invalid value]':s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const hex=(n,d=8)=>'0x'+Math.max(0,n).toString(16).toUpperCase().padStart(d,'0');
  const fmt=n=>Number(n).toLocaleString('en-US');
  const human=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KiB':(n/1048576).toFixed(1)+' MiB';
  const key=s=>s.encoding+':'+s.offset;
  const selected=()=>state.result?.strings[state.selected];
  function toast(message) { $('toast').textContent=message;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,3500); }
  function notice(message) {$('notice').textContent=message;$('notice').hidden=!message;}
  function copy(text) { if(navigator.clipboard) navigator.clipboard.writeText(text).then(()=>toast('Copied to clipboard.')).catch(()=>toast('Clipboard unavailable. Select the text and copy it manually.')); else toast('Clipboard unavailable. Select the text and copy it manually.'); }
  function download(name,content,type='application/json') { const u=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),2000); }
  const fullText=s=>new TextDecoder(s.encoding==='ASCII'?'utf-8':s.encoding.toLowerCase()).decode(state.bytes.subarray(s.offset,s.offset+s.byteLength));
  const baseName=()=>state.name.replace(/[^a-z0-9._-]/gi,'_').slice(0,90)||'sample';
  function resetWorker() { if(pendingReject){pendingReject(Error('Analysis replaced.'));pendingReject=null;} if(worker)worker.terminate();if(workerURL)URL.revokeObjectURL(workerURL);worker=null;workerURL=null; }
  async function analyzeFile(file,isDemo=false) {
    if(file.size>MAX_FILE){toast('This release supports files up to 64 MiB.');return;}
    if(!file.size){toast('That file is empty. Open a file containing at least one byte.');return;}
    persist(); const job=++state.job; resetWorker(); resetComparison(); resetFirmware(); freshInvestigation(); resetSystemForSample(); resetCode(); resetRecovery(); resetDetection(); resetDebugger(); resetDecompiler(); state.busy=true;
    $('analysis-status').textContent='Analyzing…';$('analysis-status').style.display='';
    $('file-name').textContent=file.name;$('file-size').textContent=human(file.size);$('file-format').textContent='Reading';$('file-arch').textContent='—';$('file-hash').textContent='Computing…';$('demo-label').hidden=!isDemo;
    notice('Analyzing locally. You can open another file to replace this job.');
    const start=performance.now();
    try {
      const buffer=await file.arrayBuffer();if(job!==state.job)return;
      const source=$('engine-source').textContent+`\nonmessage=async function(e){try{const result=SpectraCore.analyze(e.data.buffer);let hash='';if(globalThis.crypto&&crypto.subtle){const d=await crypto.subtle.digest('SHA-256',e.data.buffer);hash=Array.from(new Uint8Array(d),v=>v.toString(16).padStart(2,'0')).join('');}postMessage({result,hash});}catch(error){postMessage({error:error.message});}};`;
      workerURL=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));worker=new Worker(workerURL);
      const finish=new Promise((resolve,reject)=>{pendingReject=reject;worker.onmessage=e=>e.data.error?reject(Error(e.data.error)):resolve(e.data);worker.onerror=e=>reject(Error(e.message||'Analysis worker failed.'));});
      worker.postMessage({buffer});
      const timeout=setTimeout(()=>pendingReject?.(Error('Analysis exceeded the 30-second limit. Try a smaller file.')),30000);
      let data;try{data=await finish;}finally{clearTimeout(timeout);}
      if(job!==state.job)return;
      resetWorker();state.result=data.result;state.bytes=new Uint8Array(buffer);state.name=file.name;state.hash=data.hash;state.demo=isDemo;state.selected=null;state.tag='all';state.page=0;state.hexStart=0;state.busy=false;codeHistory.clear();
      $('search').value='';$('encoding').value='default';$('min-length').value='4';$('unique').checked=false;
      restoreLocal();renderOverview();setRecoveryRange();setDebuggerDefaults();setDecompilerDefaults();applyFilter();
      const first=state.filtered.find(s=>s.tags.includes('url'))||state.filtered[0];if(first)selectString(first.id);else renderInspector();
      $('timing').textContent='Analyzed in '+((performance.now()-start)/1000).toFixed(2)+'s · '+human(file.size);
      const warnings=[...data.result.warnings];if(data.result.truncated)warnings.push('String limit reached: first '+fmt(core.LIMIT)+' strings retained.');if(!data.hash)warnings.push('SHA-256 unavailable in this browser context; local notes cannot be keyed to this file.');
      notice(warnings.join(' '));renderView();
    }catch(e){if(job!==state.job)return;resetWorker();state.busy=false;notice('Could not analyze this file: '+e.message);$('analysis-status').textContent='Error';if(state.result)renderOverview();}
  }
  function loadDemo() {analyzeFile(new File([core.demo()],'northstar-training.bin',{type:'application/octet-stream'}),true);}
  function renderOverview() {
    const r=state.result;if(!r)return;
    $('file-name').textContent=state.name;$('file-size').textContent=human(r.size);$('file-format').textContent=r.format;$('file-arch').textContent=r.architecture;$('file-hash').textContent=state.hash||'Unavailable';$('file-hash').title=state.hash;$('demo-label').hidden=!state.demo;$('analysis-status').textContent='Analysis complete';
    const preferred=r.strings.filter(s=>s.encoding!=='UTF-16BE');
    $('stat-strings').textContent=fmt(preferred.length);$('nav-count').textContent=fmt(preferred.length);$('stat-indicators').textContent=fmt(preferred.filter(s=>s.tags.length).length);$('stat-entropy').textContent=r.entropy.toFixed(2);$('stat-sections').textContent=r.sections.length||'—';$('stat-imports').textContent='sections · '+r.imports.length+' imports';
    $('entropy-chart').innerHTML=r.blocks.map((b,i)=>{const x=b.entropy/8,v=Math.round(28+190*x);return `<button data-block="${i}" style="background:rgb(${v},${v},${v})" title="${hex(b.offset)} · ${b.entropy.toFixed(2)} bits/byte" aria-label="Inspect file offset ${hex(b.offset)}, entropy ${b.entropy.toFixed(2)}"></button>`;}).join('');
  }
  function applyFilter(resetPage=true) {
    if(!state.result)return;
    const q=$('search').value.toLowerCase(), encoding=$('encoding').value, min=Math.max(4,Math.min(1024,Number($('min-length').value)||4)),unique=$('unique').checked,seen=new Set();
    let rows=state.result.strings.filter(s=>{
      if(s.length<min)return false;
      if(encoding==='default'&&s.encoding==='UTF-16BE')return false;
      if(!['all','default'].includes(encoding)&&s.encoding!==encoding)return false;
      if(state.tag==='bookmarked'&&!state.bookmarks.has(key(s)))return false;
      if(state.tag==='indicator'&&!s.tags.length)return false;
      if(!['all','indicator','bookmarked'].includes(state.tag)&&!s.tags.includes(state.tag))return false;
      if(q&&!s.text.toLowerCase().includes(q)&&!hex(s.offset).toLowerCase().includes(q))return false;
      if(unique){const k=s.text;if(seen.has(k))return false;seen.add(k);}return true;
    });
    if(state.sort===-1)rows=rows.reverse();state.filtered=rows;if(resetPage)state.page=0;state.page=Math.min(state.page,Math.max(0,Math.ceil(rows.length/PAGE)-1));
    document.querySelectorAll('[data-tag]').forEach(b=>b.classList.toggle('active',b.dataset.tag===state.tag));
    $('visible-count').textContent=fmt(rows.length);$('result-summary').textContent=fmt(rows.length)+' results';renderRows();
  }
  function highlighted(text) {const q=$('search').value;if(!q)return esc(text);let out='',pos=0,i=0,n=0;const lower=text.toLowerCase(),find=q.toLowerCase();while((i=lower.indexOf(find,pos))!==-1&&n++<30){out+=esc(text.slice(pos,i))+'<mark>'+esc(text.slice(i,i+q.length))+'</mark>';pos=i+q.length;}return out+esc(text.slice(pos));}
  function renderRows() {
    const total=state.filtered.length,start=state.page*PAGE,rows=state.filtered.slice(start,start+PAGE);
    $('strings-body').innerHTML=rows.map(s=>`<tr data-id="${s.id}" tabindex="0" aria-selected="${s.id===state.selected}" class="${s.id===state.selected?'selected':''}"><td><button class="star ${state.bookmarks.has(key(s))?'saved':''}" data-star="${s.id}" aria-label="${state.bookmarks.has(key(s))?'Remove bookmark':'Bookmark string'}">${state.bookmarks.has(key(s))?'★':'☆'}</button></td><td>${hex(s.offset)}</td><td title="${esc(s.text)}">${highlighted(s.text)}</td><td>${s.tags.length?`<span class="signal-tag ${s.tags[0]}">${esc(tagLabel[s.tags[0]])}</span>`:'<span class="muted tiny">'+(s.encoding==='ASCII'?'—':'UTF-16')+'</span>'}</td></tr>`).join('');
    $('strings-empty').hidden=!!total;$('page-info').textContent=(total?start+1:0)+'–'+Math.min(start+PAGE,total)+' of '+fmt(total);$('page-number').textContent=(state.page+1)+' / '+Math.max(1,Math.ceil(total/PAGE));$('prev-page').disabled=!state.page;$('next-page').disabled=start+PAGE>=total;updateBookmarkCount();
  }
  function selectString(id) {if(!state.result?.strings[id])return;state.selected=id;renderRows();renderInspector();renderLearning();}
  function renderInspector() {
    const s=selected();if(!s){$('inspector-content').innerHTML='<div class="empty">Select a string to inspect its bytes, context, and signals.</div>';return;}
    const section=state.result.sections.find(v=>s.offset>=v.offset&&s.offset<v.offset+v.size),start=Math.max(0,s.offset-8),end=Math.min(state.bytes.length,s.offset+Math.min(s.byteLength,32)+8);
    let mini='';for(let i=start;i<end;i++)mini+=`<span class="${i>=s.offset&&i<s.offset+s.byteLength?'hl':''}">${state.bytes[i].toString(16).padStart(2,'0')} </span>`;
    $('inspector-content').innerHTML=`<div class="inspect-block"><div class="inspect-label">SELECTED STRING<button id="copy-selected" class="icon-button" aria-label="Copy selected string">⧉</button></div><pre class="string-value">${esc(s.text)}</pre><div class="inspect-tags">${s.tags.map(t=>`<span class="signal-tag ${t}">${esc(tagLabel[t])}</span>`).join('')||'<span class="signal-tag">Plain text</span>'}</div>${s.clipped?'<p class="inspect-explanation">Preview limited to 4,096 characters. Hex preserves all bytes.</p>':''}</div><div class="inspect-block"><div class="inspect-grid"><div><label>FILE OFFSET</label><code>${hex(s.offset)}</code></div><div><label>ENCODING</label><code>${esc(s.encoding)}</code></div><div><label>LENGTH</label><code>${fmt(s.length)} chars / ${fmt(s.byteLength)} B</code></div><div><label>SECTION</label><code>${esc(section?.name||'Unmapped')}</code></div></div>${explainEnabled?'<p class="inspect-explanation">'+esc(s.tags.length?explanations[s.tags[0]]:'Readable bytes. Follow their references to see where they fit.')+'</p>':''}</div><div class="inspect-block"><div class="inspect-label">BYTE CONTEXT<span>${hex(start)}</span></div><div class="minihex">${mini}</div><div class="inspect-actions"><button id="inspect-hex" class="button">⌗ View in hex</button><button id="inspect-refs" class="button">↗ Find code references</button><button id="inspect-decode" class="button">⇄ Decode</button></div></div><div class="inspect-block"><div class="inspect-label">ANALYST NOTE<button id="inspect-bookmark" class="text-button">${state.bookmarks.has(key(s))?'★ Saved':'☆ Save'}</button></div><textarea id="string-note" class="string-note" placeholder="Why does this matter?" aria-label="Note for selected string">${esc(state.notes[key(s)]||'')}</textarea><div class="note-hint">Notes save automatically on this device.</div></div>`;
    $('inspect-refs').onclick=()=>showStringRefs(s);$('copy-selected').onclick=()=>copy(fullText(s));$('inspect-hex').onclick=()=>goHex(s.offset);$('inspect-decode').onclick=()=>sendToDecoder(s);$('inspect-bookmark').onclick=()=>toggleBookmark(s.id);
    $('string-note').oninput=e=>{state.notes[key(s)]=e.target.value.slice(0,20000);schedulePersist();};
  }
  function toggleBookmark(id) {const s=state.result.strings[id],k=key(s);if(state.bookmarks.has(k))state.bookmarks.delete(k);else state.bookmarks.add(k);persist();applyFilter(false);renderInspector();if(state.view==='notebook')renderNotebook();trackNavigation();}
  function updateBookmarkCount() {$('bookmark-count').textContent=state.bookmarks.size;$('evidence-count').textContent=state.bookmarks.size;}
  function changeView(view) {
    if(!titles[view])view='strings';state.view=view;document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!=='view-'+view);document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
    const [title,subtitle,label]=titles[view];$('page-title').innerHTML=esc(title.slice(0,-1))+'<span>.</span>';$('page-title').classList.toggle('spectral-title',view==='strings');$('page-subtitle').textContent=subtitle;$('page-subtitle').hidden=!subtitle;$('breadcrumb-view').textContent=label;history.replaceState(null,'','#'+view);renderView();document.dispatchEvent(new Event('spectra-view'));if(view==='notebook')renderLibrary();trackNavigation();
  }
  function renderView(){if(state.view==='system')renderSystem();if(state.view==='detect')renderDetection();if(state.view==='decompile')renderDecompiler();if(state.view==='debugger')renderDebugger();if(state.view==='recovery')renderRecovery();if(state.view==='code')renderCode();if(state.view==='functions')renderFunctions();if(state.view==='references')renderReferences();renderLearning();if(state.view==='hex')renderHex();if(state.view==='structure')renderStructure();if(state.view==='notebook')renderNotebook();}
  function goHex(offset){state.hexStart=Math.max(0,Math.floor(offset/16)*16);changeView('hex');}
  function renderHex() {
    const bytes=state.bytes,s=selected();state.hexStart=Math.max(0,Math.min(state.hexStart,Math.max(0,Math.floor((bytes.length-1)/16)*16)));const end=Math.min(bytes.length,state.hexStart+HEX_PAGE);
    $('hex-offset').value=hex(state.hexStart);$('hex-selection').textContent=s?`${s.encoding} · ${hex(s.offset)} · ${s.byteLength} bytes · ${s.text.slice(0,160)}${s.text.length>160?'…':''}`:'Raw file bytes. Enter a hexadecimal (0x…) or decimal file offset.';
    let html='<div class="hex-row hex-head"><span class="hex-addr">OFFSET</span><span class="hex-bytes">'+Array.from({length:16},(_,i)=>'<span>'+i.toString(16).toUpperCase().padStart(2,'0')+'</span>').join('')+'</span><span>ASCII</span></div>';
    for(let i=state.hexStart;i<end;i+=16){let numbers='',ascii='';for(let j=0;j<16;j++){const at=i+j,b=bytes[at],cl=s&&at>=s.offset&&at<s.offset+s.byteLength?'hl':'';numbers+=`<span class="${cl}">${at<bytes.length?b.toString(16).padStart(2,'0'):'  '}</span>`;ascii+=`<span class="${cl}">${at<bytes.length?esc(b>=32&&b<=126?String.fromCharCode(b):'·'):' '}</span>`;}html+=`<div class="hex-row"><span class="hex-addr">${i.toString(16).toUpperCase().padStart(8,'0')}</span><span class="hex-bytes">${numbers}</span><span class="hex-ascii">${ascii}</span></div>`;}
    $('hex-content').innerHTML=html;$('hex-range').textContent=hex(state.hexStart)+' – '+hex(Math.max(0,end-1))+' / '+human(bytes.length);$('hex-prev').disabled=state.hexStart===0;$('hex-next').disabled=end>=bytes.length;
  }
  function renderStructure() {
    const r=state.result;if(!r){$('structure-content').innerHTML='<div class="panel empty">Open a file to inspect its structure.</div>';return;}
    $('structure-content').innerHTML=`<div class="structure-grid"><div class="panel"><div class="panel-heading"><h2>File identity</h2><span class="signal-tag">${esc(r.format)}</span></div><dl class="metadata"><dt>Architecture</dt><dd>${esc(r.architecture)}</dd><dt>Address width</dt><dd>${r.bits?r.bits+' bit':'Not identified'}</dd><dt>Entry point (VA)</dt><dd>${r.entry!==null?hex(r.entry):'Not available'}</dd><dt>Image base</dt><dd>${r.imageBase!==null?hex(r.imageBase):'Not available'}</dd><dt>File size</dt><dd>${fmt(r.size)} bytes</dd><dt>SHA-256</dt><dd>${esc(state.hash||'Unavailable')}</dd></dl></div><div class="panel"><div class="panel-heading"><h2>Sections <span class="pill">${r.sections.length}</span></h2><span class="tiny muted">Click a section to inspect bytes</span></div><div class="section-list">${r.sections.map((s,i)=>`<div class="section-row"><div><button data-section="${i}" class="section-name">${esc(s.name||'(unnamed)')} ↗</button><br><small>${esc(s.permissions)} · ${human(s.size)}</small></div><div><div class="section-meter"><span style="width:${s.entropy/8*100}%"></span></div><small>${s.entropy.toFixed(2)} bits / byte</small></div><div><small>FILE ${hex(s.offset)}<br>VA ${hex(s.address??s.rva)}</small></div></div>`).join('')||'<div class="empty">No mapped sections available.<br>Strings and hex work on any file type.</div>'}</div></div></div><div class="panel"><div class="panel-heading"><h2>Imported functions <span class="pill">${r.imports.length}</span></h2><span class="tiny muted">PE import slots / ELF undefined symbols and relocations</span></div><div class="simple-scroll">${r.imports.length?'<table class="simple-table"><thead><tr><th>LIBRARY</th><th>FUNCTION</th><th>TABLE OFFSET</th><th>SIGNAL</th></tr></thead><tbody>'+r.imports.map(i=>`<tr><td>${esc(i.library)}</td><td>${esc(i.name)}</td><td><button class="text-button" data-import-offset="${i.offset}">${hex(i.offset)}</button></td><td>${i.tags.includes('api')?'<span class="signal-tag api">API</span>':'—'}</td></tr>`).join('')+'</tbody></table>':'<div class="empty">No parsed imports found.<br>Dynamic resolution and packed import tables can hide these.</div>'}</div></div>`;
    document.querySelectorAll('[data-section]').forEach(b=>b.onclick=()=>goHex(r.sections[+b.dataset.section].offset));document.querySelectorAll('[data-import-offset]').forEach(b=>b.onclick=()=>goHex(+b.dataset.importOffset));
  }
  function sendToDecoder(s){$('decode-input').value=s.text;$('decode-output').value='';$('decode-mode').value=s.tags.includes('base64')?'base64':'url';$('xor-key-wrap').hidden=true;changeView('decoder');if(s.tags.includes('base64'))runDecode();}
  function runDecode(){try{$('decode-output').value=core.decode($('decode-input').value,$('decode-mode').value,$('xor-key').value);$('decode-message').textContent='Transform complete. Output is displayed as text and never executed.';$('decode-message').classList.remove('error');}catch(e){$('decode-output').value='';$('decode-message').textContent=e.message;$('decode-message').classList.add('error');}}
  function renderNotebook() {
    renderAnnotations();
    $('case-notes').value=state.caseNotes;updateBookmarkCount();const saved=state.result?.strings.filter(s=>state.bookmarks.has(key(s)))||[];
    $('evidence-list').innerHTML=saved.map(s=>`<button class="evidence-item" data-evidence="${s.id}"><small>★ ${hex(s.offset)} · ${esc(s.encoding)}</small><code>${esc(s.text)}</code>${state.notes[key(s)]?'<p>'+esc(state.notes[key(s)])+'</p>':''}</button>`).join('')||'<div class="empty">A trail worth keeping.<br>Star strings to collect evidence here.</div>';
    document.querySelectorAll('[data-evidence]').forEach(b=>b.onclick=()=>{const id=+b.dataset.evidence;resetFilters();$('encoding').value='all';applyFilter();state.page=Math.floor(state.filtered.findIndex(s=>s.id===id)/PAGE);selectString(id);changeView('strings');});
  }
  function storageKey(){return state.hash?'spectra:v1:'+state.hash:null;}
  function project(){return {schema:'spectra-project-v1',name:state.name,sha256:state.hash,createdAt:new Date().toISOString(),bookmarks:[...state.bookmarks],notes:state.notes,caseNotes:state.caseNotes,annotations:[...investigation.annotations.values()]};}
  function persist(){scheduleWorkspace();const k=storageKey();if(!k)return;try{localStorage.setItem(k,JSON.stringify(project()));$('notes-status').textContent='Saved on this device';}catch{$('notes-status').textContent='Storage unavailable — export to save';}}
  function schedulePersist(){clearTimeout(noteTimer);noteTimer=setTimeout(persist,350);}
  function validateProject(p){if(!p||p.schema!=='spectra-project-v1'||p.sha256!==state.hash||!state.hash)throw Error('This project belongs to a different file. Open the matching sample first.');if(!Array.isArray(p.bookmarks)||p.bookmarks.length>core.LIMIT||typeof p.notes!=='object'||p.notes===null||typeof p.caseNotes!=='string'||p.caseNotes.length>100000)throw Error('Invalid project document.');const valid=new Set(state.result.strings.map(key));const notes={};for(const [k,v]of Object.entries(p.notes)){if(valid.has(k)&&typeof v==='string')notes[k]=v.slice(0,20000);}return {bookmarks:new Set(p.bookmarks.filter(k=>typeof k==='string'&&valid.has(k))),notes,caseNotes:p.caseNotes};}
  function restoreLocal(){state.bookmarks=new Set();state.notes={};state.caseNotes='';const k=storageKey();if(!k)return;try{const raw=localStorage.getItem(k);if(raw){const p=JSON.parse(raw);Object.assign(state,validateProject(p));investigation.annotations=new Map(SpectraProject.annotations(p.annotations||[]).map(a=>[a.address,a]));applyAnnotations();}}catch{$('notes-status').textContent='Could not restore stored notes';}}
  function saveProject(){return saveInvestigation();}
  function exportReport(kind) {
    if(!state.result||state.busy){toast('Wait for analysis to finish.');return;}
    if(kind==='project'){saveProject();$('export-dialog').close();return;}
    const rows=state.filtered;
    if(kind==='json'){const {strings,blocks,...metadata}=state.result;download(baseName()+'.report.json',JSON.stringify({tool:'SPECTRA v0.11',createdAt:new Date().toISOString(),name:state.name,sha256:state.hash,syntheticDemo:state.demo,metadata,filters:{query:$('search').value,encoding:$('encoding').value,tag:state.tag,minLength:$('min-length').value,unique:$('unique').checked},strings:rows.map(s=>({...s,text:fullText(s),clipped:false})),investigation:project(),caveat:'Static text heuristics are not malware verdicts.'},null,2));}
    if(kind==='csv'){const cell=v=>'"'+String(v).replace(/^[=+@-]/,"'$&").replace(/"/g,'""')+'"';const lines=[['offset_hex','offset_decimal','encoding','length','byte_length','tags','text','note'],...rows.map(s=>[hex(s.offset),s.offset,s.encoding,s.length,s.byteLength,s.tags.join(';'),fullText(s),state.notes[key(s)]||''])];download(baseName()+'.strings.csv',lines.map(r=>r.map(cell).join(',')).join('\r\n'),'text/csv;charset=utf-8');}
    if(kind==='txt')download(baseName()+'.strings.txt',rows.map(s=>fullText(s)).join('\n'),'text/plain;charset=utf-8');
    $('export-dialog').close();toast('Exported '+fmt(rows.length)+' filtered strings.');
  }
  function resetFilters(){state.tag='all';$('search').value='';$('encoding').value='default';$('min-length').value=4;$('unique').checked=false;applyFilter();}
  /*__WORKBENCH__*/
  /*__RECOVERY_UI__*/
  /*__DEBUGGER_UI__*/
/*__LAB_UI__*/
/*__LAB_FORMS_UI__*/
  /*__DECOMPILER_UI__*/
/*__DETECTION_UI__*/
  /*__HARNESS_UI__*/
  /*__PROJECT_UI__*/
/*__KNOWLEDGE_UI__*/
/*__LIBRARY_UI__*/
/*__SYSTEM_UI__*/
  /*__COMPARE_UI__*/
  /*__FIRMWARE_UI__*/
/*__LESSONS_UI__*/
/*__GUIDE_UI__*/
/*__ACCESS_UI__*/
/*__NAVIGATION_UI__*/
  document.querySelector('.brand').onclick=e=>{e.preventDefault();changeView('strings');};
  document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>changeView(b.dataset.view));
  $('open-top').onclick=()=>$('file-input').click();$('file-input').onchange=e=>{if(e.target.files[0])analyzeFile(e.target.files[0]);e.target.value='';};$('demo-button').onclick=loadDemo;
  $('search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>applyFilter(),100);};for(const id of ['encoding','unique','min-length'])$(id).onchange=()=>applyFilter();
  $('tag-filters').onclick=e=>{const b=e.target.closest('[data-tag]');if(b){state.tag=b.dataset.tag;applyFilter();}};$('stat-indicator-button').onclick=()=>{state.tag='indicator';applyFilter();changeView('strings');};
  $('strings-body').onclick=e=>{const star=e.target.closest('[data-star]');if(star){toggleBookmark(+star.dataset.star);return;}const row=e.target.closest('[data-id]');if(row)selectString(+row.dataset.id);};
  $('strings-body').onkeydown=e=>{if(e.key==='Enter'&&e.target.matches('[data-id]'))selectString(+e.target.dataset.id);};
  $('prev-page').onclick=()=>{state.page--;renderRows();$('strings-body').parentElement.parentElement.scrollTop=0;};$('next-page').onclick=()=>{state.page++;renderRows();$('strings-body').parentElement.parentElement.scrollTop=0;};
  $('sort-offset').onclick=()=>{state.sort*=-1;$('sort-offset').textContent='OFFSET '+(state.sort===1?'↓':'↑');applyFilter();};$('clear-filters').onclick=resetFilters;
  $('copy-hash').onclick=()=>state.hash?copy(state.hash):toast('No hash is available yet.');$('entropy-chart').onclick=e=>{const b=e.target.closest('[data-block]');if(b)goHex(state.result.blocks[+b.dataset.block].offset);};
  $('hex-go').onclick=()=>{const raw=$('hex-offset').value.trim();if(!/^(?:0x[0-9a-f]+|\d+)$/i.test(raw))return toast('Use a decimal offset or hexadecimal prefixed with 0x.');const n=Number(raw);if(!Number.isSafeInteger(n)||n<0||n>=state.bytes.length)return toast('Offset is outside this file.');state.hexStart=Math.floor(n/16)*16;renderHex();};$('hex-offset').onkeydown=e=>{if(e.key==='Enter')$('hex-go').click();};$('hex-prev').onclick=()=>{state.hexStart=Math.max(0,state.hexStart-HEX_PAGE);renderHex();};$('hex-next').onclick=()=>{state.hexStart+=HEX_PAGE;renderHex();};
  $('decode-mode').onchange=()=>$('xor-key-wrap').hidden=$('decode-mode').value!=='xor';$('decode-run').onclick=runDecode;$('copy-decoded').onclick=()=>copy($('decode-output').value);
  $('case-notes').oninput=e=>{state.caseNotes=e.target.value.slice(0,100000);schedulePersist();};$('save-project').onclick=saveProject;$('load-project').onclick=()=>$('project-input').click();
  $('project-input').onchange=async e=>{const f=e.target.files[0];e.target.value='';if(!f)return;try{await restoreInvestigation(f);}catch(err){toast(err.message);}};
  $('export-button').onclick=()=>state.result&&!state.busy?$('export-dialog').showModal():toast('Wait for analysis to finish.');for(const kind of ['json','csv','txt','project'])$('export-'+kind).onclick=()=>exportReport(kind);
  $('help-button').onclick=()=>$('help-dialog').showModal();
  document.addEventListener('keydown',e=>{if(e.ctrlKey||e.metaKey||e.altKey||['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)||document.querySelector('dialog[open]'))return;if(e.key==='/'){e.preventDefault();changeView('strings');$('search').focus();}if(e.key.toLowerCase()==='o')$('file-input').click();if(e.key.toLowerCase()==='b'&&selected())toggleBookmark(state.selected);if(e.key.toLowerCase()==='h'&&selected())goHex(selected().offset);if(e.key==='?')$('help-dialog').showModal();});
  let dragDepth=0;document.addEventListener('dragenter',e=>{if(e.dataTransfer.types.includes('Files')){e.preventDefault();dragDepth++;$('drop-overlay').hidden=false;}});document.addEventListener('dragleave',e=>{e.preventDefault();dragDepth=Math.max(0,dragDepth-1);if(!dragDepth)$('drop-overlay').hidden=true;});document.addEventListener('dragover',e=>{e.preventDefault();e.dataTransfer.dropEffect='copy';});document.addEventListener('drop',e=>{e.preventDefault();dragDepth=0;$('drop-overlay').hidden=true;if(e.dataTransfer.files[0])analyzeFile(e.dataTransfer.files[0]);});
  window.addEventListener('beforeunload',persist);changeView(location.hash.slice(1)||'strings');loadDemo();
})();
