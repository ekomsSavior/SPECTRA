// Validate virtual-address mappings before handing bytes to Ghidra.
(function(root){
'use strict';
function plan(bytes,meta,options={}){
 const num=n=>Number.isSafeInteger(n)&&n>=0;
 let mode=options.mode&&options.mode!=='auto'?options.mode:({'x86':'x86','x86-64':'x64','ARM':'arm','ARM Thumb':'thumb','ARM64':'aarch64','RISC-V':meta.bits===64?'riscv64':'riscv32','MIPS':meta.bits===64?'mips64':'mips32'})[meta.architecture];
 if(!['x86','x64','arm','thumb','cortex','aarch64','riscv32','riscv64','mips32','mips64'].includes(mode))throw Error('Choose a supported architecture and mapped or raw function range.');
 const selected=(meta.symbols||[]).find(s=>s.address===Number(options.entry??meta.entry));if((!options.mode||options.mode==='auto')&&['arm','thumb'].includes(mode)&&selected?.thumb)mode='thumb';
 const endian=options.endian&&options.endian!=='auto'?options.endian:meta.endian||'little';if(!['little','big'].includes(endian)||['x86','x64','riscv32','riscv64'].includes(mode)&&endian!=='little')throw Error('This architecture profile supports little endian only.');
 const bits=['x64','aarch64','riscv64','mips64'].includes(mode)?64:32,e=endian==='big'?'BE':'LE',x86=['x86','x64'].includes(mode),flags=meta.elfFlags||0,warnings=[];
 if(!options.raw){
  if(['arm','thumb','cortex'].includes(mode)&&(flags&0x800000))throw Error('ELF BE8 needs a separate instruction/data endian profile, which is not supplied here.');
  if(mode.startsWith('mips')&&(flags&0x06000020||(flags>>>28)>=9))throw Error('MIPS16, microMIPS, Release 6, and n32 need different ISA/ABI profiles. Use a supported ordinary MIPS range.');
  if(mode.startsWith('riscv')&&(flags&8))throw Error('RV32E needs a reduced-register ABI profile.');
  if(mode.startsWith('riscv')&&meta.format?.startsWith('ELF')&&(flags&6)!==4&&!options.acceptAbi)throw Error('Selected RISC-V compiler spec uses the double-float ABI. Review the ELF ABI mismatch and explicitly accept the selected spec, or choose a different input.');
 }
 let compiler=options.compiler||'auto';if(compiler==='auto')compiler=x86?(meta.format?.startsWith('ELF')?'gcc':'windows'):mode.startsWith('riscv')?'gcc':'default';
 if(x86&&!['windows','gcc'].includes(compiler)||!x86&&!mode.startsWith('riscv')&&!['default','windows','apcs'].includes(compiler)||mode.startsWith('riscv')&&compiler!=='gcc')throw Error('Calling convention is unavailable for this processor. Choose Automatic or a supported compiler.');
 const language=x86?'x86:LE:'+bits+':default:'+compiler:mode==='aarch64'?'AARCH64:'+e+':64:v8A:'+compiler:mode.startsWith('riscv')?'RISCV:LE:'+bits+':default:gcc':mode.startsWith('mips')?'MIPS:'+e+':'+bits+':default:'+compiler:'ARM:'+e+':32:'+(mode==='cortex'?'Cortex':mode==='thumb'?'v8T':'v8')+':'+compiler;
 if(!x86)warnings.push('Hardware decompilation uses the selected ISA, endian and compiler spec. Verify mixed ARM/Thumb calls, relocations and inferred prototypes. Debugger execution currently remains x86/x64.');
 if(mode.startsWith('riscv'))warnings.push('RISC-V ABI: ilp32d / lp64d. Soft/single-float prototypes are not supplied by this profile.');
 if(bytes.length>32*1024*1024)throw Error('Native decompilation input cap: 32 MiB.');
 const max=bits===32?0x100000000:0x800000000000,raw=options.raw;
 const regions=(raw?[{address:raw.address,offset:raw.offset,size:raw.size,permissions:'R-X',name:'Raw range'}]:meta.mappings||[]).filter(r=>r.size>0).map(r=>({address:r.address,offset:r.offset,size:r.size,name:String(r.name||'Mapping').slice(0,128)}));
 if(!regions.length||regions.length>256)throw Error('Need 1–256 file-backed mappings.');
 regions.sort((a,b)=>a.address-b.address);let total=0;
 for(let i=0;i<regions.length;i++){const r=regions[i];if(![r.address,r.offset,r.size].every(num)||r.address+r.size>max||r.offset>bytes.length-r.size)throw Error('Invalid file or virtual-address range.');if(i&&r.address<regions[i-1].address+regions[i-1].size)throw Error('Overlapping mappings are ambiguous.');total+=r.size;}
 if(total>32*1024*1024)throw Error('Mapped-byte cap: 32 MiB.');
 const entry=Number(options.entry??meta.entry),alignment=x86?1:['thumb','cortex','riscv32','riscv64'].includes(mode)?2:4;if(entry%alignment)throw Error('Function entry must align to '+alignment+' bytes. Thumb entries use the actual even byte address.');if(!num(entry)||!regions.some(r=>entry>=r.address&&entry<r.address+r.size))throw Error('Function entry must map to file bytes.');
 const symbols=[],seen=new Set(),name=s=>String(s||'function').replace(/[^a-zA-Z0-9_]/g,'_').slice(0,128).replace(/^[0-9]/,'_$&');
 for(const f of (options.functions||meta.seeds||[]).slice(0,2000)){if(!num(f.address)||seen.has(f.address)||!regions.some(r=>f.address>=r.address&&f.address<r.address+r.size))continue;seen.add(f.address);symbols.push({address:f.address,name:name(f.name||'sub_'+f.address.toString(16))});}
 const prototypes=(options.prototypes||[]).map(p=>{if(!num(p.address)||typeof p.declaration!=='string'||p.declaration.length>4096||!regions.some(r=>p.address>=r.address&&p.address<r.address+r.size))throw Error('Invalid signature address or declaration.');return {address:p.address,declaration:p.declaration};});
 const types=options.types||[];if(prototypes.length>128||!Array.isArray(types)||types.length>32||types.some(t=>typeof t!=='string'||t.length>16384))throw Error('Type/signature budget exceeded.');
 return {mode,endian,bits,entry,regions,symbols,language,types,prototypes,warnings,name:name(options.name||symbols.find(s=>s.address===entry)?.name||'sub_'+entry.toString(16))};
}
root.SpectraNative={plan};if(typeof module!=='undefined')module.exports=root.SpectraNative;
})(globalThis);
