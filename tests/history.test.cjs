const {test,before}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
for(const p of ['engine','binary','code','windows','linux','native-plan','debugger','hardware-debugger','lab','experiments'])require('../src/'+p+'.js');
const H=require('../src/history.js'),X=SpectraExperiments;let uc,cs;
before(async()=>{uc=await require('../vendor/unicorn/dist/unicorn_x86.js')();cs=await require('../vendor/capstone/dist/capstone.js')({wasmBinary:fs.readFileSync(require.resolve('../vendor/capstone/dist/capstone.wasm'))});});
function fixture(hex,mode='x64',recipe={}){const bytes=typeof hex==='string'?Buffer.from(hex,'hex'):hex,options={mode,environment:'routine',start:0x100000,raw:{offset:0,size:bytes.length,base:0x100000},recipe},make=()=>SpectraLab.create(uc,cs,bytes,{},options);return {bytes,options,make,s:make()};}
async function use(hex,fn,mode='x64',recipe={}){const f=fixture(hex,mode,recipe);let h;try{h=await H.Timeline.start(f.s,f.options,f.make,512);await fn(h,f);}finally{h?.close();f.s.close();}}
for(const mode of ['x86','x64'])test(mode+' historical writes, patches, register edits and forward reconstruction preserve live state',async()=>use('bf00000060c707414243448b0790c3',async(h,{s})=>{
 await h.perform({kind:'register',name:mode==='x64'?'RCX':'ECX',value:'42'});await h.perform({kind:'patch',address:0x60000010,bytes:[5,6]});await h.advance(20);const live=(await X.inspect(s)).digest,n=h.entries.length-1;
 assert.equal(s.read(0x60000000,4)[0],65);await h.seek(0);assert.equal(h.current.read(0x60000010,2)[0],0);assert.equal(h.current.readReg(mode==='x64'?'RCX':'ECX'),0n);
 await assert.rejects(h.perform({kind:'step'}),/read-only/);
 await h.seek(2);assert.equal(h.current.read(0x60000010,2)[0],5);assert.equal(h.current.read(0x60000000,4)[0],0);
 await h.seek(4);assert.equal(h.current.read(0x60000000,4)[0],65);assert.ok(h.diff.pages.length);assert.equal((await X.inspect(h.current)).digest,h.entries[4].digest);
 h.returnLive();assert.equal(h.cursor,n);assert.equal(h.current,s);assert.equal((await X.inspect(s)).digest,live);
},mode));
test('decoder complete history, reverse conditional breakpoint and retroactive read/write watchpoints',async()=>use(SpectraDebug.demo(),async(h,{s})=>{
 await h.advance(512);assert.equal(s.status,'returned');assert.equal(s.steps,221);assert.equal(h.entries.length,222);
 const hit=h.reverseMatch([], [{address:0x60000000,size:1,access:'write'}]);assert.equal(hit.kind,'watchpoint');await h.seek(hit.index);assert.equal(h.current.read(0x60000000,1)[0],0);await h.seek(hit.index+1);assert.equal(h.current.read(0x60000000,1)[0],104);
 h.returnLive();const b=h.reverseMatch([{address:0x100011,condition:{register:'RCX',operator:'==',value:'1'}}]);assert.ok(b.index>100);await h.seek(b.index);assert.equal(h.current.readReg('RCX'),1n);
 const no=h.reverseMatch([0x123456]);assert.equal(no.index,null);assert.equal(no.clipped,false);
}));
test('address hooks restore model events, output buffers and call frames',async()=>use('e801000000c3ccc3',async(h,{s})=>{
 await h.advance(20);assert.equal(s.readReg('RAX'),42n);const index=h.entries.findIndex(r=>r.kind==='step'&&r.beforePC===0x100006);assert.ok(index>0);
 await h.seek(index-1);assert.equal(h.current.readReg('RAX'),0n);assert.equal(h.current.lab.snapshot().buffers[0].after,'00000000');
 await h.seek(index);assert.equal(h.current.readReg('RAX'),42n);assert.equal(h.current.lab.snapshot().buffers[0].after,'deadbeef');assert.ok(h.current.lab.events.some(e=>e.kind==='hook'));
},'x64',{harness:{abi:'sysv64',arguments:[{buffer:'input'}]},buffers:[{name:'input',size:4}],hooks:[{address:0x100006,abi:'sysv64',argc:1,result:'42',writes:[{argument:0,hex:'deadbeef'}]}]}));
test('unsupported attempt and partial memory fault boundaries reconstruct honestly',async()=>{
 await use('0f05',async(h,{s})=>{await h.perform({kind:'step'});assert.equal(s.steps,0);assert.equal(s.attempts,1);assert.equal(s.status,'unsupported');await h.seek(0);assert.equal(h.current.stopped,false);h.returnLive();assert.equal(h.current.status,'unsupported');});
 await use('bfffffffffc70741424344',async(h,{s})=>{await h.advance(10);assert.equal(s.status,'fault');assert.ok(h.entries.at(-1).partial);const faultIndex=h.cursor;await h.perform({kind:'register',name:'RDI',value:'0x60000000'});await h.seek(faultIndex);assert.equal(h.current.status,'fault');assert.equal((await X.inspect(h.current)).digest,h.entries[faultIndex].digest);await h.seek(1);assert.equal(h.current.stopped,false);h.returnLive();assert.equal(h.current.status,'paused');});
});
test('divergence, invalid targets, cancellation and changed initial recipe keep live experiment intact',async()=>use('90909090c3',async(h,{s})=>{
 await h.advance(3);const digest=(await X.inspect(s)).digest;h.entries[1].digest='0'.repeat(64);await assert.rejects(h.seek(1),/verification failed/);assert.equal(h.current,s);assert.equal((await X.inspect(s)).digest,digest);
 await assert.rejects(h.seek(1e6),/retained/);await assert.rejects(h.seek(2,async n=>{if(n===2)h.returnLive();}),/cancelled/);assert.equal(h.current,s);
 const original=h.make;h.make=()=>{const x=original();x.writeReg('RAX',1n);return x;};await assert.rejects(h.seek(0),/Initial history state diverged/);assert.equal((await X.inspect(s)).digest,digest);
}));
test('history budgets stop before executing, and invalid edits do not destroy history',async()=>use('90ebfd',async(h,{s})=>{
 h.budget=2;await assert.rejects(h.perform({kind:'patch',address:0,bytes:[1]}),/Patch needs/);assert.equal(h.entries.length,1);assert.equal(h.failed,'');
 await h.advance(50);assert.equal(s.steps,2);assert.equal(h.full,true);assert.equal(h.entries.length,3);const digest=(await X.inspect(s)).digest;assert.equal(await h.perform({kind:'register',name:'RAX',value:'99'}),false);assert.equal((await X.inspect(s)).digest,digest);
 await h.seek(0);h.returnLive();h.budget=20;h.bytes=H.MAX_BYTES-1;await h.advance(10);assert.equal(s.steps,2);
}));
test('preflight rejects process, hardware, already-executed and oversized profiles',async()=>{
 const f=fixture('90c3');try{assert.match(H.eligibility(f.s,{environment:'linux'}),/bare routines/);f.s.step();assert.match(H.eligibility(f.s,f.options),/immediately/);}finally{f.s.close();}
 const g=fixture(new Uint8Array(2*1024*1024));try{assert.match(H.eligibility(g.s,g.options),/2 MiB/);}finally{g.s.close();}
 assert.match(H.eligibility({mode:'arm'},{}),/bare routines/);
});
test('watchpoints, over/out boundaries, and repeated register comparisons retain correct state',async()=>use('e801000000c3c3',async(h,{s})=>{
 const target=s.runTarget('over');await h.advance(2,[],false,target);assert.equal(s.status,'target');assert.equal(s.pc(),0x100005);await h.seek(1);assert.equal(h.current.frames.length,1);h.returnLive();assert.equal(s.frames.length,0);
}));
test('clipped access history reports uncertainty rather than claiming no access',async()=>use('b900010000bf00000060f3aac3',async(h,{s})=>{await h.advance(10);h.entries[1].accessesTruncated=true;const match=h.reverseMatch([],[{address:0x600000ff,size:1,access:'write'}]);assert.equal(match.index,null);assert.equal(match.clipped,true);}));
test('failed verification after mutation closes admission and leaves the live state inspectable',async()=>use('9090c3',async(h,{s})=>{const inspect=X.inspect;try{X.inspect=async()=>{throw Error('digest unavailable');};await assert.rejects(h.perform({kind:'step'}),/verification could not finish/);}finally{X.inspect=inspect;}assert.equal(s.steps,1);assert.equal(h.entries.length,1);assert.match(h.failed,/reset/);await assert.rejects(h.seek(0),/verification could not finish/);await assert.rejects(h.perform({kind:'step'}),/verification could not finish/);assert.equal(s.steps,1);}));
