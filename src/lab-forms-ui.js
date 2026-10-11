const formState={index:-1,old:null};
function formCollection(kind){if(kind==='arguments')return JSON.parse($('lab-arguments').value);if(kind==='buffers')return JSON.parse($('lab-buffers').value);const r=JSON.parse($('lab-recipe').value);return kind==='registers'?Object.entries(r.registers||{}).map(([name,value])=>({name,value})):r[kind]||[];}
function writeFormCollection(kind,rows){
 const r=JSON.parse($('lab-recipe').value),args=kind==='arguments'?rows:JSON.parse($('lab-arguments').value),buffers=kind==='buffers'?rows:JSON.parse($('lab-buffers').value);
 if(!['arguments','buffers'].includes(kind))r[kind]=kind==='registers'?Object.fromEntries(rows.map(r=>[r.name,r.value])):rows;
 SpectraLab.validate({...r,buffers,...($('lab-harness').checked?{harness:{abi:$('lab-abi').value,arguments:args}}:{})});
 if(kind==='arguments'&&!$('lab-harness').checked)SpectraLab.validate({harness:{abi:$('lab-abi').value,arguments:args}});
 $('lab-recipe').value=JSON.stringify(r,null,2);$('lab-arguments').value=JSON.stringify(args,null,2);$('lab-buffers').value=JSON.stringify(buffers,null,2);scheduleWorkspace();renderDebugger();
}
function renderInputForm(){const kind=$('input-kind').value,s=SpectraLabForms.specs[kind];formState.index=-1;formState.old=null;$('input-fields').innerHTML=(s.choice?'<label>Representation<select id="input-choice">'+s.choice.map((v,i)=>'<option value="'+i+'">'+esc(v)+'</option>').join('')+'</select></label>':'')+s.fields.map(([key,label,value])=>'<label>'+esc(label)+'<textarea data-input-field="'+key+'" rows="'+(['data','values'].includes(key)?3:1)+'" spellcheck="false" maxlength="65536">'+esc(value)+'</textarea></label>').join('');$('input-apply').textContent='Add '+s.title.toLowerCase();renderInputRows();}
function renderInputRows(){try{const kind=$('input-kind').value,rows=formCollection(kind);$('input-rows').innerHTML=rows.map((r,i)=>'<article class="input-row"><code>'+esc(JSON.stringify(r))+'</code><div class="inline-controls"><button class="button" data-input-edit="'+i+'">Edit '+(i+1)+'</button><button class="button" data-input-remove="'+i+'">Remove '+(i+1)+'</button></div></article>').join('')||'<p class="muted">No '+esc(SpectraLabForms.specs[kind].title.toLowerCase())+' entries yet.</p>';
 $('input-rows').querySelectorAll('[data-input-remove]').forEach(b=>b.onclick=()=>{try{const rows=formCollection(kind);rows.splice(Number(b.dataset.inputRemove),1);writeFormCollection(kind,rows);renderInputForm();$('input-status').textContent='Entry removed from the setup. Initialize to apply it.';}catch(e){$('input-status').textContent=e.message;}});
 $('input-rows').querySelectorAll('[data-input-edit]').forEach(b=>b.onclick=()=>{const r=formCollection(kind)[Number(b.dataset.inputEdit)];formState.index=Number(b.dataset.inputEdit);formState.old=r;const f={...r};let choice=0;
 if(kind==='arguments'){f.value=typeof r==='object'?r.buffer:String(r);f.offset=r.offset||0;choice=typeof r==='object'?1:0;}
 if(['buffers','files'].includes(kind)){f.data=r.hex;choice=1;}
 if(kind==='regions')f.data=r.hex;
 if(kind==='hooks'){f.target=r.api||r.address;choice=r.api?0:1;}
 if(kind==='mmio'){f.values=r.values.join('\n');choice=r.onExhaustion==='hold'?1:0;}
 if($('input-choice'))$('input-choice').value=choice;for(const el of $('input-fields').querySelectorAll('[data-input-field]'))el.value=f[el.dataset.inputField]??'';$('input-apply').textContent='Update entry '+(formState.index+1);$('input-fields').scrollIntoView({block:'center'});
 });
 }catch(e){$('input-rows').textContent='Advanced JSON needs correction: '+e.message;}}
$('input-kind').onchange=renderInputForm;$('input-reset').onclick=renderInputForm;
$('input-apply').onclick=()=>{try{const kind=$('input-kind').value,fields=Object.fromEntries([...$('input-fields').querySelectorAll('[data-input-field]')].map(el=>[el.dataset.inputField,el.value])),rows=formCollection(kind),r=SpectraLabForms.record(kind,fields,Number($('input-choice')?.value||0),formState.old);if(formState.index<0)rows.push(r);else rows[formState.index]=r;writeFormCollection(kind,rows);renderInputForm();$('input-status').textContent='Setup updated. Review it, then Initialize session. No instructions have run.';}catch(e){$('input-status').textContent=e.message;}};
$('input-builder').ontoggle=()=>{if($('input-builder').open)renderInputForm();};
for(const id of ['lab-arguments','lab-buffers','lab-recipe'])$(id).addEventListener('change',()=>{if($('input-builder').open)renderInputForm();});
