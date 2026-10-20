import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {AndroidSession} from '../dist/engines/v018/android/session.mjs';
import '../src/archive.js';
const Z=globalThis.SpectraArchive,fixture=n=>new Uint8Array(fs.readFileSync(new URL('../fixtures/android/'+n,import.meta.url)));
test('browser engines reconstruct Java control flow, fields and exceptions from real D8 bytecode',async()=>{
 const s=new AndroidSession(),inv=await s.open(fixture('AndroidTraining.apk'));assert.equal(inv.dexes.length,2);assert.equal(inv.classes.length,2);const r=await s.reconstruct(0,0);
 for(const pattern of [/class Training/,/switch \(/,/case 7:/,/for \(/,/catch \(ArithmeticException/,/this\.bias/,/\^/,/SPECTRA_FIXTURE_ONLY\.example/])assert.match(r.code,pattern);
 assert.ok(r.tokens.length>0);for(const t of r.tokens)assert.ok(t.start+t.length<=r.code.length);
 assert.equal(r.dexSha256,inv.dexes[0].sha256);assert.match(r.warnings.join(' '),/not verified/);
});
test('multidex source resolves available sibling class metadata and retains source references',async()=>{
 const s=new AndroidSession();await s.open(fixture('AndroidTraining.apk'));const r=await s.reconstruct(1,0);assert.match(r.code,/Training\.sum/);assert.ok(r.tokens.some(t=>t.kind==='method'&&t.className==='org/church/spectra/Training'&&t.name==='sum'));assert.match(r.selection.dexFile,/classes2/);
});
test('ambiguous multidex dependencies stay unverified instead of selecting the first class',async()=>{
 const s=new AndroidSession(),apk=Z.zip([{name:'classes.dex',bytes:fixture('classes.dex')},{name:'classes2.dex',bytes:fixture('classes.dex')},{name:'classes3.dex',bytes:fixture('classes2.dex')}]);const inv=await s.open(apk);assert.match(inv.warnings.join(' '),/duplicate class/);const r=await s.reconstruct(2,0);assert.match(r.warnings.join(' '),/Training \(ambiguous\)/);
});
test('manifest and table decoding preserve member hashes and inventory names',async()=>{
 const s=new AndroidSession();await s.open(fixture('AndroidTraining.apk'));const xml=await s.resource('AndroidManifest.xml'),table=await s.resource('resources.arsc');assert.match(xml.sha256,/^[a-f0-9]{64}$/);assert.equal(table.entries[0].value,'SPECTRA Android training');assert.equal((await s.extract('lib/x86_64/libtraining.so'))[0],127);
});
test('resource-only split is inspectable and reports absent DEX',async()=>{
 const s=new AndroidSession(),inv=await s.open(Z.zip([{name:'AndroidManifest.xml',bytes:fixture('AndroidManifest.xml.bin')}]));
 assert.equal(inv.classes.length,0);assert.match(inv.warnings.join(' '),/No root classes.dex/);await assert.rejects(s.reconstruct(0,0),/selection/);
});
test('invalid input, unknown selections, bad member CRC stop explicitly',async()=>{
 const s=new AndroidSession();await assert.rejects(s.open(new Uint8Array([1,2,3])));await assert.rejects(s.open(Z.zip([{name:'readme',bytes:new Uint8Array([1])}])));await s.open(fixture('classes.dex'));await assert.rejects(s.reconstruct(0,9999),/selection/);await assert.rejects(s.extract('../x'),/not found/);await assert.rejects(s.resource('classes.dex'),/Choose/);
 const apk=fixture('AndroidTraining.apk'),entry=Z.index(apk).find(f=>f.name==='classes.dex');apk[entry.offset+2]^=1;await assert.rejects(s.open(apk));
});
