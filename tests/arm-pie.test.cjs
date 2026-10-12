const {test,before}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
for(const p of ['engine','binary','code','windows','linux','native-plan','debugger','hardware-debugger','lab','experiments','runtime'])require('../src/'+p+'.js');
let uc,cs;before(async()=>{uc=await require('../vendor/unicorn/dist/unicorn_arm.js')();cs=await require('../vendor/capstone/dist/capstone.js')({wasmBinary:fs.readFileSync(__dirname+'/../vendor/capstone/dist/capstone.wasm')});});
function fixture(mode='arm',extra={}){const b=new Uint8Array(fs.readFileSync(__dirname+'/../fixtures/arm-pie/'+mode+'-static-pie.elf')),meta=SpectraCore.analyze(b.buffer),o={...SpectraRuntime.defaults(b,meta),...extra},make=()=>SpectraLab.create(uc,cs,b,meta,o);return {b,meta,o,make};}
for(const mode of ['arm','thumb'])for(const bias of [0x10000000,0x12000000])test(mode+' self-relocation at '+bias.toString(16)+' preserves entry, auxv, watchpoints and replay',async()=>{
 const f=fixture(mode,{loadBase:bias,start:bias+0x100}),p=SpectraRuntime.preflight(f.b,f.meta,f.o);assert.equal(p.ready,true,p.blockers.join(' '));assert.equal(p.plan.linux.relocations.length,1);const original=f.b.slice(),s=f.make();try{
  assert.equal(s.steps,0);assert.equal(s.pc(),bias+0x100);assert.equal(s.lab.ptr(bias+0x1000,4),0x1020n);assert.equal(s.read(bias+0x1400,16).every(x=>x===0),true);
  const sp=Number(s.readReg('SP'));assert.equal(s.lab.ptr(sp,4),1n);assert.equal(s.lab.ptr(sp+20,4),BigInt(bias+52));assert.equal(s.plan.linux.entry,bias+0x100+(mode==='thumb'?1:0));
  s.watchpoints=[{address:bias+0x1000,size:4,access:'write'}];s.advance(100);assert.equal(s.status,'watchpoint',s.reason);assert.equal(s.lab.ptr(bias+0x1000,4),BigInt(bias+0x1020));assert.equal(s.trace.at(-1).writes[0].after[3],bias>>>24);
  const checkpoint=await SpectraExperiments.capture(s,await SpectraExperiments.sha(f.b),f.o),copy=f.make();try{await SpectraExperiments.replay(checkpoint,copy);assert.equal(copy.lab.ptr(bias+0x1000,4),BigInt(bias+0x1020));}finally{copy.close();}
  s.watchpoints=[];s.advance(100);assert.equal(s.status,'exited',s.reason);assert.equal(s.linux.output,'pie\n');assert.deepEqual(f.b,original);
 }finally{s.close();}
});
for(const mode of ['arm','thumb'])test(mode+' loader-owned relocation and alternate entry, never rerun startup',()=>{
 const f=fixture(mode,{linuxRelocations:'loader',start:0x10000180}),s=f.make();try{assert.equal(s.steps,0);assert.equal(s.lab.ptr(0x10001000,4),0x10001020n);assert.equal(s.lab.events[0].applied,1);s.advance(100);assert.equal(s.status,'exited',s.reason);assert.equal(s.linux.output,'pie\n');}finally{s.close();}
 assert.throws(()=>SpectraLinux.prepare(f.b,f.meta,{...f.o,start:0x10000100}),/alternate entry/);
});
test('relative relocation validation rejects unsupported kinds, bad tables, targets and duplicate records',()=>{
 const mutations=[v=>v.setUint32(0x204,2,true),v=>v.setUint32(0x204,0x117,true),v=>v.setUint32(0x200,0x100,true),v=>v.setUint32(0x200,0x1001,true),v=>v.setUint32(0x200,0x1600,true),v=>v.setUint32(0x1114,4,true),v=>v.setUint32(0x110c,9,true),v=>v.setUint32(0x1104,0x3ff,true),v=>v.setUint32(0x111c,99,true),v=>v.setUint32(0x1120,22,true),v=>{v.setUint32(0x110c,16,true);v.setUint32(0x208,0x1000,true);v.setUint32(0x20c,23,true);},v=>v.setUint32(52+64+8,0x1110,true)];
 for(const mutate of mutations){const f=fixture();mutate(new DataView(f.b.buffer));assert.equal(SpectraRuntime.preflight(f.b,f.meta,f.o).ready,false,String(mutate));}
});
test('load bias cannot overlap session memory, wrap addresses or violate segment alignment',()=>{
 const f=fixture();for(const loadBase of [0,1,0x10000001,0x40000000,0xfffff000,-4096,NaN])assert.throws(()=>SpectraLinux.prepare(f.b,f.meta,{...f.o,loadBase}));
 const b=f.b.slice();new DataView(b.buffer).setUint32(52+32+8,0xfffff000,true);assert.throws(()=>SpectraLinux.prepare(b,f.meta,f.o));
});
test('ARM ELF with dependency interpreter, shared library, TLS or RELA is blocked before initialization',()=>{
 const changes=[v=>v.setUint32(52+64,3,true),v=>{v.setUint32(0x1120,1,true);v.setUint32(0x1124,0,true);},v=>v.setUint32(52+64,7,true),v=>{v.setUint32(0x1120,7,true);v.setUint32(0x1124,0x200,true);}];for(const change of changes){const f=fixture();change(new DataView(f.b.buffer));assert.equal(SpectraRuntime.preflight(f.b,f.meta,f.o).ready,false);}
});
for(const mode of ['arm','thumb'])test(mode+' TLS syscalls and TPIDRURO read, clear-tid, image mprotect and replay',async()=>{
 const f=fixture(mode,{linuxRelocations:'loader',start:0x100001c0}),s=f.make(),at=f.o.start;function call(number,args=[]){s.editRegister('PC',String(at));s.editRegister('R7',String(number));args.forEach((n,i)=>s.editRegister('R'+i,String(n)));s.step();assert.equal(s.status,'stepped',s.reason);return s.readReg('R0');}
 try{assert.equal(call(0xf0005,[0x10001020]),0n);assert.equal(call(0xf0006),0x10001020n);s.step();assert.equal(s.status,'stepped',s.reason);assert.equal(s.readReg('R0'),0x10001020n);assert.equal(call(256,[0x10001040]),1337n);
  assert.equal(call(125,[0x10001000,4096,1]),0n);assert.equal(s.region(0x10001000,4,2),undefined);assert.ok(s.region(0x10001000,4,1));assert.equal(call(125,[0x10001000,4096,3]),0n);assert.ok(s.region(0x10001000,4,2));
  const c=await SpectraExperiments.capture(s,await SpectraExperiments.sha(f.b),f.o),copy=f.make();try{await SpectraExperiments.replay(c,copy);}finally{copy.close();}
  s.editRegister('PC',String(at));s.editRegister('R7','1');s.editRegister('R0','0');s.step();assert.equal(s.status,'exited');assert.equal(s.lab.ptr(0x10001040,4),0n);
 }finally{s.close();}
});
test('anonymous MAP_FIXED can create a brk guard without replacing the image or hiding protection gaps',async()=>{
 const f=fixture('arm',{linuxRelocations:'loader',start:0x100001c0}),s=f.make(),at=f.o.start;function call(number,args=[]){s.editRegister('PC',String(at));s.editRegister('R7',String(number));args.forEach((n,i)=>s.editRegister('R'+i,BigInt.asUintN(32,BigInt(n)).toString()));s.step();return s.readReg('R0');}
 try{assert.equal(call(45,[0x41003000]),0x41003000n);s.patch(0x41001000,Uint8Array.of(255));assert.equal(call(192,[0x41001000,4096,0,50,-1,0]),0x41001000n);assert.equal(s.status,'stepped',s.reason);assert.equal(s.region(0x41001000,1,1),undefined);assert.equal(call(45,[0x41004000]),0x41004000n);assert.equal(s.region(0x41001000,1,2),undefined);assert.ok(s.region(0x41002000,1,2));
  const c=await SpectraExperiments.capture(s,await SpectraExperiments.sha(f.b),f.o),copy=f.make();try{await SpectraExperiments.replay(c,copy);}finally{copy.close();}
  call(192,[0x10000000,4096,3,50,-1,0]);assert.equal(s.status,'unsupported');assert.match(s.reason,/protected/);assert.equal(s.read(0x10000000,4)[0],127);assert.equal(s.pc(),at);assert.equal(s.lab.events.at(-2).name,'mmap');assert.equal(s.lab.events.at(-2).arguments[0],String(0x10000000));
 }finally{s.close();}
});
test('PIE breakpoint stops before execution and HWCAP advertises only modeled TLS capability',()=>{
 const f=fixture(),s=f.make();try{s.advance(10,[{address:0x10000100}]);assert.equal(s.status,'breakpoint');assert.equal(s.steps,0);const sp=Number(s.readReg('SP'));let found=false;for(let at=sp+16;at<sp+200;at+=8){const tag=s.lab.ptr(at,4);if(tag===16n){assert.equal(s.lab.ptr(at+4,4),0x8000n);found=true;break;}if(tag===0n)break;}assert.ok(found);s.advance(1,[],true);assert.equal(s.steps,1);}finally{s.close();}
});
test('ARM conditional ADDLS to PC is ordinary control flow; MOVS to PC still stops before exception return',()=>{
 const f=fixture();f.b.set(Buffer.from('000050e300f18f900700a0e32a00a0e31eff2fe1','hex'),0x100);let s=f.make();try{s.step();assert.equal(s.step(),true,s.reason);assert.equal(s.pc(),0x1000010c);s.step();assert.equal(s.readReg('R0'),42n);}finally{s.close();}
 f.b.set(Buffer.from('0ef0b0e1','hex'),0x100);s=f.make();try{s.step();assert.equal(s.status,'unsupported');assert.equal(s.pc(),0x10000100);assert.equal(s.steps,0);}finally{s.close();}
});

for(const mode of ['arm','thumb'])test(mode+' O_LARGEFILE works with bounded virtual files; other unsupported flags still stop',()=>{
 const f=fixture(mode,{linuxRelocations:'loader',start:0x100001c0,recipe:{files:[{path:'/fixture',hex:'616263'}]}}),s=f.make();
 function open(path,flags){s.patch(0x10001080,new TextEncoder().encode(path+'\0'));s.editRegister('PC',String(f.o.start));s.editRegister('R0',String(0x10001080));s.editRegister('R1',String(flags));s.editRegister('R7','5');s.step();return s.readReg('R0');}
 try{assert.equal(open('/fixture',0x20000),3n);assert.equal(s.status,'stepped',s.reason);assert.equal(s.linux.fds.get(3).file.path,'/fixture');assert.equal(open('/missing',0x20000),0xfffffffen);assert.equal(s.status,'stepped',s.reason);open('/fixture',0x10000);assert.equal(s.status,'unsupported');assert.match(s.reason,/Unsupported open flags/);}finally{s.close();}
});
