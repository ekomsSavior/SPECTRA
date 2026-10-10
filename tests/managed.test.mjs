import fs from 'node:fs';import assert from 'node:assert/strict';import {decompile} from '../vendor/managed/main.mjs';
const b=fs.readFileSync(new URL('../fixtures/ManagedTraining.dll',import.meta.url)).toString('base64');
const tree=decompile(b,-1);assert.equal(tree.code,'');assert.ok(tree.types.some(t=>t.name==='Decoder'));
const type=tree.types.find(t=>t.name==='Decoder'),method=type.methods.find(m=>m.name==='Decode');assert.ok(method.rva>0);
const selected=decompile(b,method.token);assert.match(selected.code,/encoded\[i\] \^ key/);assert.ok(selected.missingReferences.length>0);
assert.match(decompile(b,type.token).code,/class Decoder/);assert.match(decompile(b,0).code,/foreach/);
assert.throws(()=>decompile('AAAA',0));assert.throws(()=>decompile(b,0x04000001),/Select an assembly/);
console.log('7 managed WASM checks passed: tree, method metadata, C#, missing references, type/assembly reconstruction, malformed input, token validation.');
