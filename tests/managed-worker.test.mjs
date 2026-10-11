import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {startManagedWorker} from '../src/engines/managed-worker.mjs';

function scope() {
 const messages=[],listeners=new Map();
 return {messages,postMessage:m=>messages.push(m),addEventListener:(name,fn)=>listeners.set(name,fn),reject:reason=>listeners.get('unhandledrejection')({reason,preventDefault(){}})};
}
test('a failed runtime import reports startup detail instead of a generic worker error',async()=>{
 const s=scope();await startManagedWorker(s,()=>Promise.reject(Error('Runtime module unavailable (503)')));
 assert.deepEqual(s.messages,[{engineError:'Runtime module unavailable (503)',phase:'startup'}]);assert.equal(s.onmessage,undefined);
});
test('an unhandled runtime startup rejection never releases the pending sample',async()=>{
 const s=scope();let release;const loading=startManagedWorker(s,()=>new Promise(resolve=>release=resolve));
 s.reject(Error('WebAssembly compilation blocked'));release({decompile:()=>{throw Error('must not run');}});await loading;
 assert.deepEqual(s.messages,[{engineError:'WebAssembly compilation blocked',phase:'startup'}]);assert.equal(s.onmessage,undefined);
});
test('a late runtime failure is labeled analysis and suppresses further jobs',async()=>{
 const s=scope();let calls=0;await startManagedWorker(s,async()=>({decompile:()=>{calls++;}}));
 s.reject(Error('runtime exited'));s.reject(Error('second failure'));s.onmessage({data:{id:1,base64:'AAAA'}});
 assert.equal(calls,0);assert.deepEqual(s.messages,[{ready:true},{engineError:'runtime exited',phase:'analysis'}]);
});
test('malformed job, size and token limits stop before ILSpy',async()=>{
 const s=scope();let calls=0;await startManagedWorker(s,async()=>({decompile:()=>{calls++;}}));
 for(const data of [null,{id:1,base64:42},{id:2,base64:'A'.repeat(22369625)},{id:3,base64:'AAAA',token:0x04000001}])s.onmessage({data});
 assert.equal(calls,0);assert.equal(s.messages.filter(m=>m.error).length,4);
});
test('sample errors remain job errors; startup diagnostics are bounded',async()=>{
 const s=scope();await startManagedWorker(s,async()=>({decompile:()=>{throw Error('Bad PE metadata');}}));s.onmessage({data:{id:9,base64:'AAAA'}});
 assert.deepEqual(s.messages.at(-1),{id:9,error:'Bad PE metadata'});
 const bad=scope();await startManagedWorker(bad,async()=>{throw Error('x'.repeat(9000));});assert.equal(bad.messages[0].engineError.length,3000);
});
test('missing engine export reports a startup failure',async()=>{
 const s=scope();await startManagedWorker(s,async()=>({}));assert.match(s.messages[0].engineError,/entry point/);assert.equal(s.messages[0].phase,'startup');
});
test('oversized reconstructed output is not delivered as a successful result',async()=>{
 const s=scope();await startManagedWorker(s,async()=>({decompile:()=>({code:'x'.repeat(2000001),types:[]})}));s.onmessage({data:{id:3,base64:'AAAA'}});
 assert.match(s.messages.at(-1).error,/Output limit/);assert.equal(s.messages.at(-1).result,undefined);
});
test('fresh worker retry reads real managed metadata and reconstructs C#',async()=>{
 const failed=scope();await startManagedWorker(failed,async()=>{throw Error('Temporary load failure');});
 const s=scope();await startManagedWorker(s,()=>import('../vendor/managed/main.mjs'));
 const base64=readFileSync(new URL('../fixtures/ManagedTraining.dll',import.meta.url)).toString('base64');
 s.onmessage({data:{id:11,base64,token:-1}});const tree=s.messages.at(-1);assert.equal(tree.id,11);assert.ok(tree.result.types.some(t=>t.name==='Decoder'));
 const method=tree.result.types.find(t=>t.name==='Decoder').methods.find(m=>m.name==='Decode');s.onmessage({data:{id:12,base64,token:method.token}});
 assert.equal(s.messages.at(-1).id,12);assert.match(s.messages.at(-1).result.code,/encoded\[i\] \^ key/);
});
