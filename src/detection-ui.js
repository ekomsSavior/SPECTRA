const detectionState={worker:null,timer:null,busy:false,run:0,report:null,message:'Open a file, then let DiE check its fingerprints.'};
function stopDetection(message){detectionState.worker?.terminate();detectionState.worker=null;clearTimeout(detectionState.timer);detectionState.timer=null;detectionState.busy=false;detectionState.run++;if(message)detectionState.message=message;}
function resetDetection(){stopDetection();detectionState.report=null;detectionState.message='Open a file, then let DiE check its fingerprints.';renderDetection();}
function startDetection(){
 if(state.busy||!state.result)return toast('Open a file and let inspection finish first.');
 if(state.bytes.length>16*1024*1024)return toast('DiE supports files up to 16 MiB in this browser release.');
 stopDetection();detectionState.report=null;detectionState.busy=true;detectionState.message='Preparing the scanner…';const run=detectionState.run,job=state.job,started=performance.now();
 try{
  const worker=new Worker(ENGINE_ROOT+'detection/worker.js');detectionState.worker=worker;
  worker.onmessage=e=>{if(run!==detectionState.run||job!==state.job)return;const m=e.data;
   if(m.type==='status')detectionState.message=m.text;
   if(m.type==='error')stopDetection('Stopped: '+m.error);
   if(m.type==='result'){try{const {rows}=SpectraDetection.normalize(m.raw);detectionState.report={schema:'spectra-detection-v1',sample:{name:state.name,sha256:state.hash,bytes:state.bytes.length},engine:m.engine,options:m.options,createdAt:new Date().toISOString(),elapsedMs:Math.round(performance.now()-started),rows,raw:m.raw};stopDetection('Finished in '+((performance.now()-started)/1000).toFixed(1)+' s · '+rows.length+' findings.');scheduleWorkspace();}catch(err){stopDetection('Report rejected: '+err.message);}}
   renderDetection();
  };
  worker.onerror=e=>{if(run===detectionState.run){stopDetection('Detection worker stopped: '+(e.message||'unknown error'));renderDetection();}};
  detectionState.timer=setTimeout(()=>{if(run===detectionState.run){stopDetection('Stopped at the 180-second limit. Try a smaller file or switch heuristics off. No complete report was produced.');renderDetection();}},180000);
  const buffer=state.bytes.slice().buffer;worker.postMessage({buffer,heuristics:$('detect-heuristics').checked,deep:$('detect-deep').checked},[buffer]);
 }catch(e){stopDetection(e.message);}renderDetection();
}
function renderDetection(){
 $('detect-status').textContent=detectionState.message;$('detect-run').disabled=detectionState.busy||state.busy||!state.result;$('detect-cancel').hidden=!detectionState.busy;$('detect-export').disabled=!detectionState.report;
 const report=detectionState.report,rows=report?.rows||[];$('detect-provenance').textContent=report?'DiE '+report.engine.version+' · '+report.sample.sha256+' · '+(report.options.heuristics?'heuristics on':'heuristics off')+(report.options.deep?' · deep scan':''):'';
 $('detect-results').innerHTML=rows.map(r=>`<article class="detection-finding"><div class="inline-controls"><span class="pill">${esc(r.type)}</span><span class="pill">${r.heuristic?'Heuristic':'Database detection'}</span></div><h3>${esc(r.name)}${r.version?' · '+esc(r.version):''}</h3>${r.info?'<p>'+esc(r.info)+'</p>':''}<small>${esc(r.format)} · ${esc(r.part)} · file offset ${esc(r.offset||'unknown')}</small><details><summary>What does this tell me?</summary><p>${esc(SpectraDetection.explanation(r.type))}</p><pre>${esc(r.display)}</pre></details></article>`).join('')||(report?'<p class="muted">No findings returned. That does not rule out packing, obfuscation or an unfamiliar toolchain.</p>':'<p class="muted">Compiler, language, packer, protector and other fingerprints will land here.</p>');
 $('detect-raw').textContent=report?.raw||'No report yet.';
}
$('detect-run').onclick=startDetection;$('detect-cancel').onclick=()=>{stopDetection('Scan cancelled. The local scanner was discarded.');renderDetection();};
$('detect-export').onclick=()=>{if(detectionState.report)download(baseName()+'.spectra-detection.json',JSON.stringify(detectionState.report,null,2));};
