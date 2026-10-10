import {test} from 'node:test';
import assert from 'node:assert/strict';
import edge from '../edge.mjs';
import {readFileSync} from 'node:fs';
const config=JSON.parse(readFileSync(new URL('../wrangler.jsonc',import.meta.url)));
function fixture(){
  const maps=config.ratelimits.map(()=>new Map());let assets=0;
  const env={ASSETS:{fetch:async()=>{assets++;return new Response('SPECTRA',{headers:{'Content-Type':'text/html'}})}}};
  config.ratelimits.forEach((r,i)=>env[r.name]={limit:async({key})=>{const n=(maps[i].get(key)||0)+1;maps[i].set(key,n);return {success:n<=r.simple.limit};}});
  const call=(path='/',ip='192.0.2.1',options={})=>edge.fetch(new Request('https://spectra.churchofmalware.org'+path,{...options,headers:{'CF-Connecting-IP':ip,...options.headers}}),env);
  return {env,call,maps,assets:()=>assets};
}
test('static delivery retains security headers and never receives request bodies',async()=>{const f=fixture(),r=await f.call();assert.equal(r.status,200);assert.match(r.headers.get('Content-Security-Policy'),/connect-src 'self'/);assert.equal(r.headers.get('X-Frame-Options'),'DENY');assert.equal(await r.text(),'SPECTRA');const rejected=await f.call('/','192.0.2.1',{method:'POST',body:'sample'});assert.equal(rejected.status,405);assert.equal(f.assets(),1);});
test('burst limiter keys on edge IP across paths and query changes; unrelated IP remains usable',async()=>{const f=fixture();for(let i=0;i<30;i++)assert.equal((await f.call('/?q='+i)).status,200);const r=await f.call('/debugger-source.zip','192.0.2.1',{headers:{'X-Forwarded-For':'192.0.2.99'}});assert.equal(r.status,429);assert.equal(r.headers.get('Retry-After'),'10');assert.equal(r.headers.get('Cache-Control'),'no-store');assert.equal((await f.call('/','192.0.2.2')).status,200);assert.equal(f.assets(),31);});
test('minute limiter spans separate burst windows',async()=>{const f=fixture();for(let i=0;i<120;i++){if(i%30===0)f.maps[0].clear();assert.equal((await f.call()).status,200);}f.maps[0].clear();const r=await f.call();assert.equal(r.status,429);assert.equal(r.headers.get('Retry-After'),'60');assert.equal(f.assets(),120);});
test('missing edge identity, alternative hosts and limiter errors fail closed',async()=>{const f=fixture();for(const request of [new Request('https://spectra.churchofmalware.org/'),new Request('https://spectra.example.workers.dev/',{headers:{'CF-Connecting-IP':'192.0.2.1'}})])assert.equal((await edge.fetch(request,f.env)).status,403);f.env.SPECTRA_BURST.limit=async()=>{throw Error('unavailable');};assert.equal((await f.call()).status,503);assert.equal(f.assets(),0);});
test('unknown paths are small 404s and HEAD errors have no body',async()=>{const f=fixture();assert.equal((await f.call('/.env')).status,404);const r=await f.call('/missing','192.0.2.1',{method:'HEAD'});assert.equal(r.status,404);assert.equal(await r.text(),'');assert.equal(f.assets(),0);});
test('every asset request runs the guard and alternate public Worker URLs are disabled',()=>{assert.equal(config.assets.run_worker_first,true);assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);assert.deepEqual(config.routes,[{pattern:'spectra.churchofmalware.org',custom_domain:true}]);assert.notEqual(config.ratelimits[0].namespace_id,config.ratelimits[1].namespace_id);});

test('engine assets have separate bounded delivery without consuming the page quota',async()=>{const {ENGINE_PATHS}=await import('../asset-paths.mjs');const f=fixture(),path=[...ENGINE_PATHS][0];for(let i=0;i<100;i++)assert.equal((await f.call(path)).status,200);assert.equal((await f.call(path)).status,429);assert.equal((await f.call('/')).status,200);assert.equal((await f.call('/engines/v05/missing.js')).status,404);assert.equal((await f.call(path,'192.0.2.2')).headers.get('Cache-Control'),'public, max-age=31536000, immutable');assert.equal((await f.call(path,'192.0.2.2',{method:'POST',body:'not accepted'})).status,405);});
