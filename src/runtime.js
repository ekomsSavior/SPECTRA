/* Sample identity and debugger preflight. Never executes instructions or starts an engine. */
(function(root){
'use strict';
function identify(bytes,meta={}){
 const r={format:meta.format||'Raw',mode:({'x86':'x86','x86-64':'x64','ARM':meta.entryThumb?'thumb':'arm','ARM64':'aarch64','RISC-V':meta.bits===64?'riscv64':'riscv32','MIPS':meta.bits===64?'mips64':'mips32'})[meta.architecture]||null,endian:meta.endian||'little',start:meta.entry||0x100000,environment:'routine',issues:[],dependencies:[]};
 if(bytes.length>=4&&bytes[0]===127&&bytes[1]===69&&bytes[2]===76&&bytes[3]===70){r.format='ELF';r.environment='linux';try{const e=root.SpectraLinux.inspect(bytes);Object.assign(r,{mode:e.mode||r.mode,start:e.start,endian:e.endian,issues:e.issues,dependencies:[...(e.interpreter?[e.interpreter]:[]),...e.needed]});}catch(e){r.issues.push(e.message);}}
 else if(bytes.length>=2&&bytes[0]===77&&bytes[1]===90){r.format='PE';r.environment='windows';try{const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),at=v.getUint32(60,true);if(at>bytes.length-26||v.getUint32(at,true)!==0x4550)throw Error('Missing PE signature.');const machine=v.getUint16(at+4,true);const opt=at+24,wide=v.getUint16(opt,true)===0x20b,base=wide?Number(v.getBigUint64(opt+24,true)):v.getUint32(opt+28,true);r.start=base+v.getUint32(opt+16,true);if(!Number.isSafeInteger(r.start))throw Error('PE address exceeds exact range.');r.mode=({332:'x86',34404:'x64',452:'arm',43620:'aarch64'})[machine]||r.mode;if(![332,34404].includes(machine))r.issues.push('Windows process emulation is available for native x86/x64 PE only.');}catch(e){r.issues.push('Invalid PE header: '+e.message);}}
 return r;
}
function defaults(bytes,meta={}){const r=identify(bytes,meta);return {environment:r.environment,mode:r.mode||'x64',endian:r.endian,start:r.start,raw:r.environment==='routine'&&!meta.mappings?.length?{offset:0,size:Math.min(bytes.length,65536),base:0x100000}:null};}
function preflight(bytes,meta,options){
 const identity=identify(bytes,meta),blockers=[],warnings=[],imports=[];let plan=null;
 try{
  const recipe=root.SpectraLab.validate(options.recipe||{});
  if(options.environment==='linux')blockers.push(...identity.issues);
  if(options.environment==='routine'){warnings.push('Routine mode supplies mapped bytes and analyst state. It does not provide a process loader, OS services or native library code.');if(!options.raw&&identity.mode&&identity.mode!==options.mode)blockers.push('CPU mismatch: sample '+identity.mode+', selected '+options.mode+'. Choose its CPU or explicitly map a raw range.');}
  if(!blockers.length)plan=(root.SpectraHardware.profiles[options.mode]?root.SpectraHardware:root.SpectraDebug).prepare(bytes,meta,options);
  if(plan&&plan.mode!==options.mode)blockers.push('CPU mismatch: loader requires '+plan.mode+', selected '+options.mode+'.');
  if(plan&&['windows','linux'].includes(options.environment)&&options.endian==='big')blockers.push('This process model requires little endian.');
  if(options.environment==='linux'&&recipe.files.some(f=>!f.path.startsWith('/')||f.path.split('/').includes('..')))blockers.push('Linux virtual files require absolute paths without ..');
  if(options.environment==='linux'&&recipe.mmio.length)blockers.push('MMIO responses belong to bare hardware routines, not Linux process startup.');
  if(options.environment==='linux'&&recipe.harness)blockers.push('Disable the function harness for Linux entry-point startup, or choose Bare routine.');
  if(plan?.windows){for(const i of plan.windows.imports){const api=root.SpectraWindows.apiKey(i.library,i.name),hook=recipe.hooks.find(h=>h.api?.toLowerCase()===api.toLowerCase());imports.push({...i,support:hook?'analyst response':root.SpectraWindows.apiSupport(i.library,i.name)?'modeled':'missing'});}warnings.push(...plan.windows.warnings);const missing=imports.filter(i=>i.support==='missing');if(missing.length)warnings.push(missing.length+' import slots have no API model. You may initialize to inspect/step; execution stops if one is reached. Supply an explicit response only when you understand that call.');}
  if(plan?.linux&&['arm','thumb','aarch64'].includes(plan.mode))warnings.push('This CPU profile covers integer instructions; FP/SIMD and unsupported extensions stop explicitly.');
  if(plan?.linux)warnings.push(plan.scope,'argv/env/auxv and deterministic startup random bytes are supplied by the model. Libc compatibility is not implied; unsupported syscalls stop at the calling instruction.');
  if(!identity.mode)warnings.push('CPU could not be identified. Review the CPU, byte order and raw mapping yourself.');
 }catch(e){if(!blockers.includes(e.message))blockers.push(e.message);}
 return {identity,plan,blockers:[...new Set(blockers)],warnings,imports,ready:!!plan&&!blockers.length};
}
root.SpectraRuntime={identify,defaults,preflight};if(typeof module!=='undefined')module.exports=root.SpectraRuntime;
})(globalThis);
