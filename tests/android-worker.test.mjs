import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Worker} from 'node:worker_threads';
import {once} from 'node:events';
import fs from 'node:fs';
const url=new URL('../dist/engines/v018/android/worker.mjs',import.meta.url).href;
const fixture=n=>new Uint8Array(fs.readFileSync(new URL('../fixtures/android/'+n,import.meta.url)));
async function host(){
 const w=new Worker(`const {parentPort,workerData}=require('node:worker_threads');globalThis.onmessage=null;globalThis.postMessage=(m,t)=>parentPort.postMessage(m,t);parentPort.on('message',m=>globalThis.onmessage({data:m}));import(workerData).catch(e=>{throw e;});`,{eval:true,workerData:url});
 const [ready]=await once(w,'message');assert.equal(ready.ready,true);
 const request=m=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>{w.terminate();reject(Error('Worker test deadline'));},15000),listener=r=>{if(r.id!==m.id||r.progress)return;clearTimeout(timer);w.off('message',listener);resolve(r);};w.on('message',listener);w.postMessage(m,m.buffer?[m.buffer]:[]);});
 return {w,request};
}
test('Android worker keeps successive class, bytes, resource and source requests connected',async()=>{
 const {w,request}=await host();try{
  const opened=await request({id:1,action:'open',buffer:fixture('AndroidTraining.apk').buffer});assert.equal(opened.inventory.classes.length,2);
  const detail=await request({id:2,action:'class',dex:1,index:0});assert.equal(detail.detail.name,'org/church/spectra/SecondDex');
  const code=await request({id:3,action:'decompile',dex:1,index:0});assert.match(code.result.code,/Training\.sum/);
  const bytes=await request({id:4,action:'methodBytes',dex:1,index:0,method:0});assert.match(bytes.methodBytes,/DEX instruction range/);
  const resource=await request({id:5,action:'resource',name:'AndroidManifest.xml'});assert.match(resource.resource.text,/uses-permission/);
 }finally{await w.terminate();}
});
test('transferred extracted DEX leaves worker analysis intact and malformed requests are errors',async()=>{
 const {w,request}=await host();try{
  await request({id:1,action:'open',buffer:fixture('classes.dex').buffer});
  const member=await request({id:2,action:'extract',name:'classes.dex'});assert.equal(member.member.buffer.byteLength,fixture('classes.dex').length);
  const source=await request({id:3,action:'decompile',dex:0,index:0});assert.match(source.result.code,/class Training/);
  const bad=await request({id:4,action:'methodBytes',dex:0,index:0,method:999});assert.match(bad.error,/invalid/);
 }finally{await w.terminate();}
});
test('terminating an Android job discards its worker and a fresh worker can analyze again',async()=>{
 const a=await host();a.w.postMessage({id:1,action:'open',buffer:fixture('AndroidTraining.apk').buffer});await a.w.terminate();
 const b=await host();try{const r=await b.request({id:1,action:'open',buffer:fixture('AndroidTraining.apk').buffer});assert.equal(r.inventory.classes.length,2);}finally{await b.w.terminate();}
});
