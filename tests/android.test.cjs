const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
require('../src/experiments.js');
const A=require('../src/android.js'),Z=require('../src/archive.js'),P=require('../src/project.js');
const fixture=n=>new Uint8Array(fs.readFileSync(__dirname+'/../fixtures/android/'+n));
const change=(b,off,value)=>{b=b.slice();new DataView(b.buffer).setUint32(off,value,true);return b;};
test('DEX metadata retains methods, owners, signatures and exact instruction spans',()=>{
 const b=fixture('classes.dex'),r=A.dex(b),c=r.classes[0];assert.equal(r.version,'038');assert.equal(c.name,'org/church/spectra/Training');assert.equal(c.methods.length,8);assert.deepEqual(r.warnings,[]);
 const decode=c.methods.find(m=>m.name==='decode');assert.equal(decode.descriptor,'([BI)[B');assert.ok(decode.instructionOffset+decode.instructionBytes<=b.length);assert.ok(decode.registers>=decode.inputs);
});
test('DEX table, count, header, map and code offsets are bounded',()=>{
 assert.throws(()=>A.dex(new Uint8Array(32*1048576+1)),/budget/);const b=fixture('classes.dex');for(const [off,v] of [[32,b.length+1],[36,0],[40,0],[56,0xffffffff],[60,b.length],[52,b.length-2],[96,50001],[100,b.length]])assert.throws(()=>A.dex(change(b,off,v)));
 assert.throws(()=>A.dex(b.subarray(0,100)));const pos=A.dex(b).classes[0].methods[0].codeOffset;assert.throws(()=>A.dex(change(b,pos+12,0xffffffff)));
});
test('unsupported DEX container versions and compact DEX fail explicitly',()=>{
 const b=fixture('classes.dex');b[4]=48;b[5]=52;b[6]=49;assert.throws(()=>A.dex(b),/041/);b[0]=99;assert.throws(()=>A.dex(b),/Supported DEX/);
});
test('checksum mismatch stays visible without making an authenticity claim',()=>{
 const b=fixture('classes.dex');b[8]^=1;assert.match(A.dex(b).warnings.join(' '),/Adler-32/);
});
test('binary XML decodes manifest namespace, permission, boolean and resource reference',()=>{
 const r=A.xml(fixture('AndroidManifest.xml.bin'));assert.match(r.text,/xmlns:android=/);assert.match(r.text,/android.permission.INTERNET/);assert.match(r.text,/android:debuggable="false"/);assert.match(r.text,/@0x7f010000/);assert.equal(r.elements.length,3);
});
test('XML boundaries, string counts and chunk sizes reject corrupt input',()=>{
 const b=fixture('AndroidManifest.xml.bin');for(const [off,v]of [[4,0xffffffff],[12,0],[16,0xffffffff],[28,0xffffffff]])assert.throws(()=>A.xml(change(b,off,v)));
 assert.throws(()=>A.xml(b.subarray(0,b.length-1)));
});
test('plain XML is inert supplied text with no entity or network resolution',()=>{
 const text='<!DOCTYPE a SYSTEM "https://example.invalid/"><a>&xxe;</a>';const r=A.xml(new TextEncoder().encode(text));assert.equal(r.text,text);assert.match(r.warnings[0],/No external entities/);
});
test('resource table retains ID, type/key, value, configuration and byte offset',()=>{
 const r=A.resources(fixture('resources.arsc'));assert.equal(r.entries.length,1);assert.equal(r.entries[0].id,'0x7f010000');assert.equal(r.entries[0].name,'app_name');assert.equal(r.entries[0].value,'SPECTRA Android training');assert.equal(r.entries[0].config,'04000000');assert.equal(r.entries[0].offset,476);
});
test('resource table bounds and unknown layouts fail instead of guessing values',()=>{
 const b=fixture('resources.arsc');assert.throws(()=>A.resources(change(b,4,b.length-1)));assert.throws(()=>A.resources(change(b,480,99999)));assert.throws(()=>A.resources(change(b,436,0xffffffff)));
});
test('ZIP index does not inflate unused members; selected extraction validates CRC',async()=>{
 const b=fixture('AndroidTraining.apk'),index=Z.index(b);assert.equal(index.length,6);assert.equal(index[0].bytes,undefined);const f=index.find(f=>f.name==='classes.dex');assert.deepEqual(await Z.extract(b,f),fixture('classes.dex'));
 const bad=b.slice();bad[f.offset+2]^=1;await assert.rejects(Z.extract(bad,f));await assert.rejects(Z.extract(b,f,{maxEntry:1}));
});
test('ZIP directory refuses collisions, traversal, encryption, bombs and overlaps',()=>{
 const b=Z.zip([{name:'classes.dex',bytes:fixture('classes.dex')},{name:'classes2.dex',bytes:fixture('classes2.dex')}]);
 const v=new DataView(b.buffer),end=b.length-22,central=v.getUint32(end+16,true);
 assert.throws(()=>Z.index(change(b,central+24,0xffffffff)),/budget/);
 const enc=b.slice();new DataView(enc.buffer).setUint16(central+8,1,true);assert.throws(()=>Z.index(enc),/Encrypted/);
 assert.throws(()=>Z.zip([{name:'../classes.dex',bytes:new Uint8Array(1)}]),/path/);
 assert.throws(()=>Z.zip([{name:'x',bytes:new Uint8Array(1)},{name:'x',bytes:new Uint8Array(1)}]),/duplicate/);
 assert.throws(()=>Z.index(b,{maxEntries:1}),/limits/);
});
test('partial XML and resource corpus mutations terminate with bounded output or errors',()=>{
 for(const [name,fn]of [['AndroidManifest.xml.bin','xml'],['resources.arsc','resources']]){
  const b=fixture(name);for(let n=0;n<120;n++){const altered=b.slice(),at=(n*37)%b.length;altered[at]^=255;try{const r=A[fn](altered);assert.ok(JSON.stringify(r).length<2*1048576);}catch(e){assert.ok(e instanceof Error);}}
 }
});
test('Android source evidence round-trips through projects without starting an engine',async()=>{
 const sample=fixture('classes.dex'),hash=await globalThis.SpectraExperiments.sha(sample),m={schema:P.SCHEMA,name:'classes.dex',sha256:hash,bookmarks:[],notes:{},caseNotes:'',annotations:[],settings:{'decompile-engine':'android'},layers:[],checkpoints:[],harnessSelected:[],decompilation:{engineKind:'android',selection:{dexFile:'classes.dex',className:'org/church/spectra/Training'},sha256:hash,dexSha256:hash,code:'class Training {}',tokens:[],warnings:['Reconstructed Java.']}};
 const restored=await P.decode(await P.encode(m,sample,[]),'');assert.deepEqual(restored.manifest.decompilation,m.decompilation);
 m.decompilation.selection.className={toString:null};await assert.rejects(P.encode(m,sample,[]));m.decompilation.selection.className='Training';m.decompilation.tokens=[{start:100,length:1,kind:'class',name:'Training',className:'Training',descriptor:''}];await assert.rejects(P.encode(m,sample,[]),/token span/);
});
test('Android lesson requires newly observed manifest, source reference and method evidence',()=>{
 const L=require('../src/lessons.js'),hash='a'.repeat(64),p=L.start('android','dex',hash),decompilation={sha256:hash,engineKind:'android',selection:{className:'org/church/spectra/SecondDex'},tokens:[{kind:'method',className:'org/church/spectra/Training',name:'sum'}]};
 let r=L.evaluate(p,{hash,decompilation});assert.deepEqual(r.checks.slice(1),Array(5).fill(null));
 r=L.evaluate(p,{hash,decompilation,android:{observedInventory:hash,observedManifest:hash,observedSource:hash,observedMethod:hash}});assert.ok(r.checks.slice(0,4).every(Boolean));assert.equal(r.checks[4],null);assert.equal(L.diagnostics(r)[3].view,'decompile');
 r.checks.forEach(c=>{if(c)c.origin='imported';});assert.equal(L.diagnostics(L.evaluate(r,{hash}))[2].historical,true);assert.throws(()=>L.start('android','x64',hash));
});
