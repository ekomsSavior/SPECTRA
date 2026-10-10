import PyreDecompiler from './pyre_decompiler.mjs';
import './native-plan.js';
const read=async name=>{const r=await fetch(new URL(name,import.meta.url));if(!r.ok)throw Error('Engine asset unavailable ('+r.status+'). Retry after a minute.');return new Uint8Array(await r.arrayBuffer());};
let mod,api,profiles,lastError='';const loaded=new Set(),directories=new Set();
async function init(){
 const [wasm,list]=await Promise.all([read('pyre_decompiler.wasm'),read('profiles.json')]);profiles=JSON.parse(new TextDecoder().decode(list)).profiles;
 mod=await PyreDecompiler({wasmBinary:wasm,print:()=>{},printErr:s=>{lastError=String(s).slice(0,2000);}});
 const bind=(n,r,a)=>mod.cwrap(n,r,a);api={dir:bind('pyre_add_spec_dir','number',['string']),create:bind('pyre_create','number',['string']),region:bind('pyre_add_region','number',['number','bigint','number','number']),symbol:bind('pyre_add_symbol','number',['number','bigint','string']),decompile:bind('pyre_decompile','number',['number','bigint','string']),free:bind('pyre_free_string',null,['number']),destroy:bind('pyre_destroy',null,['number']),prototype:bind('spectra_set_prototype','number',['number','bigint','string']),type:bind('spectra_add_type','number',['number','string'])};
 // Ghidra freezes its language catalog on first create. Load only the tiny ldefs
 // catalogs up front; SLA, processor and compiler specs still load per profile.
 const catalog=[...new Set(Object.values(profiles).flatMap(p=>p.files.filter(f=>f.endsWith('.ldefs'))))];
 const data=await Promise.all(catalog.map(f=>read('specs/'+f)));
 catalog.forEach((f,i)=>{mod.FS.mkdirTree('/spec/'+f.slice(0,f.lastIndexOf('/')));mod.FS.writeFile('/spec/'+f,data[i]);loaded.add(f);});
 for(const directory of new Set(Object.values(profiles).map(p=>p.directory))){if(api.dir('/spec/'+directory))throw Error('Processor catalog failed to load.');directories.add(directory);}
}
async function languageAssets(language){const profile=profiles[language];if(!profile)throw Error('This ISA/compiler combination is not in the tested profile bundle.');const missing=profile.files.filter(f=>!loaded.has(f)),values=await Promise.all(missing.map(f=>read('specs/'+f)));mod.FS.mkdirTree('/spec/'+profile.directory);missing.forEach((f,i)=>{mod.FS.writeFile('/spec/'+f,values[i]);loaded.add(f);});if(!directories.has(profile.directory)){if(api.dir('/spec/'+profile.directory))throw Error('Ghidra specifications failed to load.');directories.add(profile.directory);}return profile;}
const ready=init();ready.then(()=>postMessage({ready:true})).catch(e=>postMessage({error:String(e.message||e)}));
onmessage=async({data:m})=>{let h=0,p=0;try{await ready;const bytes=new Uint8Array(m.buffer),plan=SpectraNative.plan(bytes,m.meta,m.options),profile=await languageAssets(plan.language);h=api.create(plan.language);if(!h)throw Error('Ghidra could not initialize this language.');
 for(const r of plan.regions){const at=mod._malloc(r.size);if(!at)throw Error('Engine allocation failed.');try{mod.HEAPU8.set(bytes.subarray(r.offset,r.offset+r.size),at);if(api.region(h,BigInt(r.address),at,r.size))throw Error('Engine rejected a mapping.');}finally{mod._free(at);}}
 for(const s of plan.symbols)if(api.symbol(h,BigInt(s.address),s.name))throw Error('Engine rejected a function symbol.');
 if(!plan.symbols.some(s=>s.address===plan.entry)&&api.symbol(h,BigInt(plan.entry),plan.name))throw Error('Engine rejected selected function.');
 for(const t of plan.types){lastError='';if(api.type(h,t))throw Error('Type declaration rejected: '+(lastError||'Use one supported C declaration, such as struct Record { uint32_t count; };'));}
 for(const s of plan.prototypes){lastError='';if(api.prototype(h,BigInt(s.address),s.declaration))throw Error('Signature rejected: '+(lastError||'Use registered types such as uint32_t, int32_t, char*.'));}
 p=api.decompile(h,BigInt(plan.entry),plan.name);if(!p)throw Error('Ghidra returned no output.');const end=mod.HEAPU8.subarray(p,p+2000001).indexOf(0);if(end<0||end>2000000)throw Error('Output exceeds 2 MB. Select a smaller function.');const code=mod.UTF8ToString(p);if(code.length>2000000)throw Error('Output exceeds 2 million characters.');if(/^\s*\/\*\s*decompile error:/i.test(code))throw Error(code.slice(0,2000));
 postMessage({id:m.id,result:{code,engine:'Ghidra · SPECTRA/Pyre WASM bridge',plan,profileBytes:profile.bytes,warnings:['Reconstructed C, not original source. Inferred types and signatures need review.','Import-slot types are not propagated by this bridge. Check the Imports evidence below.',...plan.warnings,...(plan.prototypes.length||plan.types.length?['Analyst type/signature assumptions were applied to the engine. Clear them to compare the default inference.']:[])]}});
 }catch(e){postMessage({id:m.id,error:String(e.message||e).slice(0,3000)});}finally{if(p)api.free(p);if(h)api.destroy(h);}};
