(function(root){
'use strict';
const specs={
 arguments:{title:'Function argument',fields:[['value','Integer value or buffer name','2'],['offset','Buffer offset (only for a pointer)','0']],choice:['integer','buffer pointer']},
 buffers:{title:'Input / output buffer',fields:[['name','Buffer name','input'],['size','Buffer size in bytes','32'],['data','Initial data','hello'],['address','Optional memory address','']],choice:['UTF-8 text','hex bytes']},
 files:{title:'Virtual file',fields:[['path','Path inside the model','/config.txt'],['data','File contents','hello\n']],choice:['UTF-8 text','hex bytes']},
 hooks:{title:'Supplied function response',fields:[['target','DLL!API or executable address','kernel32.dll!GetTickCount'],['abi','ABI: sysv64, win64, cdecl, stdcall, aapcs32, aapcs64','win64'],['argc','Number of arguments to record','0'],['result','Return value','1234'],['label','Why this response?','Recorded clock value']],choice:['Windows API','code address']},
 mmio:{title:'Hardware register responses',fields:[['address','Register address','0x20000000'],['width','Access width: 1, 2 or 4 bytes','4'],['values','Read values, one per line','0\n1'],['label','What is this register?','Recorded ready bit']],choice:['stop when values run out','hold final value']},
 regions:{title:'Captured memory region',fields:[['address','Page-aligned address','0x20000000'],['size','Page-aligned size','4096'],['permissions','Permissions: R, RW, RX or RWX','RW'],['data','Initial hex bytes','414200'],['name','Region name','Captured RAM']]},
 registers:{title:'Initial CPU register',fields:[['name','Register name','R0'],['value','Unsigned value','0x20000000']]}
};
const bytes=s=>Array.from(new TextEncoder().encode(s),b=>b.toString(16).padStart(2,'0')).join('');
function record(kind,f,choice=0,old={}){
 if(!specs[kind])throw Error('Unknown input kind.');
 const num=s=>{if(!/^(0x[0-9a-f]+|\d+)$/i.test(String(s).trim()))throw Error('Use decimal or 0x-prefixed hexadecimal numbers.');const n=Number(s);if(!Number.isSafeInteger(n))throw Error('This size or offset is too large.');return n;};
 const data=()=>choice===0?bytes(f.data||''):String(f.data||'').replace(/\s/g,'');
 if(kind==='arguments')return choice===0?String(f.value).trim():{buffer:String(f.value).trim(),offset:num(f.offset||'0')};
 const r=old&&typeof old==='object'?{...old}:{};
 if(kind==='buffers'){Object.assign(r,{name:f.name.trim(),size:num(f.size),hex:data()});delete r.address;if(f.address?.trim())r.address=num(f.address);}
 if(kind==='files')Object.assign(r,{path:f.path,hex:data()});
 if(kind==='hooks'){delete r.api;delete r.address;if(choice===0)r.api=f.target.trim();else r.address=num(f.target);Object.assign(r,{abi:f.abi.trim(),argc:num(f.argc),result:f.result.trim(),label:f.label});}
 if(kind==='mmio')Object.assign(r,{address:num(f.address),width:num(f.width),values:f.values.split(/[\s,]+/).filter(Boolean),label:f.label,onExhaustion:choice===0?'stop':'hold',write:r.write||'capture'});
 if(kind==='regions')Object.assign(r,{address:num(f.address),size:num(f.size),permissions:f.permissions.trim().toUpperCase(),hex:f.data.replace(/\s/g,''),name:f.name});
 if(kind==='registers'){if(!/^[A-Z][A-Z0-9]{0,12}$/.test(f.name.trim().toUpperCase()))throw Error('Use a CPU register name.');return {name:f.name.trim().toUpperCase(),value:f.value.trim()};}
 return r;
}
root.SpectraLabForms={specs,record,bytes};if(typeof module!=='undefined')module.exports=root.SpectraLabForms;
})(globalThis);
