const {test,before}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');const core=require('../src/engine.js');require('../src/binary.js');const code=require('../src/code.js'),cmp=require('../src/compare.js');let cs;
before(async()=>{cs=await require('../vendor/capstone/dist/capstone.js')({wasmBinary:fs.readFileSync(__dirname+'/../vendor/capstone/dist/capstone.wasm')});});
const make=b=>{const bytes=Uint8Array.from(b),meta=core.analyze(bytes.buffer);return {name:'fixture',bytes,meta,code:code.analyze(cs,bytes,meta,{manual:{architecture:'x64',offset:0,size:bytes.length,address:4096,endian:'little'}})};};
test('real decoded function preserves exact match and changed constant uncertainty',async()=>{const a=make([0xb8,1,0,0,0,0xc3]),same=await cmp.compare(a,a),b=make([0xb8,2,0,0,0,0xc3]),changed=await cmp.compare(a,b);assert.equal(same.functions.matched[0].changed,false);assert.match(same.functions.matched[0].confidence,/exact/);assert.equal(changed.functions.matched[0].changed,true);assert.match(changed.functions.matched[0].confidence,/heuristic|candidate/);assert.notEqual(changed.before.sha256,changed.after.sha256);});
test('duplicate bytes and names do not force arbitrary function matches',()=>{const a=[1,2].map(address=>({address,name:'same',sha256:'a',shape:'a',instructionCount:2})),b=[3,4].map(address=>({address,name:'same',sha256:'a',shape:'a',instructionCount:2})),r=cmp.matches(a,b);assert.equal(r.matched.length,0);assert.equal(r.ambiguous.length,1);assert.equal(r.removed.length,2);});
test('removed strings/imports and additions retain evidence',async()=>{const a=make([0xc3]),b=make([0xc3]);a.meta.strings=[{text:'old',encoding:'ASCII',byteLength:3}];b.meta.strings=[{text:'new',encoding:'ASCII',byteLength:3}];a.meta.imports=[{library:'lib',name:'old'}];b.meta.imports=[{library:'lib',name:'new'}];const r=await cmp.compare(a,b);assert.equal(r.strings.removed[0].text,'old');assert.equal(r.imports.added[0].name,'new');});

test('raw comparison finds both CTF-style changes without decoding or function matches',async()=>{
 const before=new Uint8Array(256),after=new Uint8Array(256);
 before[0x10]=1;after[0x10]=2;before[0x48]=0x75;after[0x48]=0x74;
 const r=await cmp.compare({name:'before',bytes:before,meta:{}},{name:'after',bytes:after,meta:{}});
 assert.equal(r.functions.matched.length,0);assert.equal(r.rawBytes.total,2);
 assert.deepEqual(r.rawBytes.rows,[{offset:0x10,before:1,after:2,kind:'modified'},{offset:0x48,before:0x75,after:0x74,kind:'modified'}]);
});
test('raw counts distinguish empty, equal, appended and truncated files, including zero bytes',()=>{
 assert.equal(cmp.rawBytes(new Uint8Array(),new Uint8Array()).total,0);
 assert.equal(cmp.rawBytes(Uint8Array.of(0,255),Uint8Array.of(0,255)).total,0);
 const a=Uint8Array.of(0),b=Uint8Array.of(0,0,255),added=cmp.rawBytes(a,b),removed=cmp.rawBytes(b,a);
 assert.deepEqual([added.modified,added.added,added.removed],[0,2,0]);
 assert.deepEqual(added.rows.map(x=>[x.before,x.after]),[[null,0],[null,255]]);
 assert.deepEqual([removed.modified,removed.added,removed.removed],[0,0,2]);
 assert.deepEqual(removed.rows.map(x=>[x.before,x.after]),[[0,null],[255,null]]);
});
test('raw comparison explicitly uses same offsets rather than claiming insertion alignment',()=>{
 const r=cmp.rawBytes(Uint8Array.of(1,2,3),Uint8Array.of(1,99,2,3));
 assert.equal(r.mode,'same-file-offset');assert.equal(r.modified,2);assert.equal(r.added,1);
});
test('all byte differences remain pageable beyond the bounded JSON preview',()=>{
 const a=new Uint8Array(10000),b=new Uint8Array(10000);for(let i=0;i<10000;i+=2)b[i]=1;
 const r=cmp.rawBytes(a,b);assert.equal(r.total,5000);assert.equal(r.rows.length,4096);assert.equal(r.omitted,904);
 let start=0,offsets=[];do{const p=cmp.bytePage(a,b,start);assert.ok(p.rows.length<=64);offsets.push(...p.rows.map(x=>x.offset));start=p.nextOffset;}while(start!==null);
 assert.deepEqual(offsets,Array.from({length:5000},(_,i)=>i*2));
 assert.deepEqual(cmp.bytePage(a,b,9999),{rows:[],nextOffset:null});
 assert.equal(cmp.bytePage(a,b,125).rows[0].offset,126);
});
test('byte pager handles a last-offset change in a maximum-sized file and rejects invalid requests',()=>{
 const a=new Uint8Array(32*1024*1024),b=a.slice();b[b.length-1]=255;
 const r=cmp.rawBytes(a,b);assert.equal(r.total,1);assert.equal(r.rows[0].offset,b.length-1);
 for(const start of [-1,NaN,Infinity,0.5])assert.throws(()=>cmp.bytePage(a,b,start));
 for(const limit of [0,4097,1.5])assert.throws(()=>cmp.bytePage(a,b,0,limit));
});
