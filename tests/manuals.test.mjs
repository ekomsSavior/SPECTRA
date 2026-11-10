import {test} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import edge from '../edge.mjs';
import {MANUAL_PATHS,MANUAL_CSP} from '../manual-paths.mjs';
const config=JSON.parse(readFileSync(new URL('../wrangler.jsonc',import.meta.url)));
const env={ASSETS:{fetch:async()=>new Response('book')}};
for(const {name} of config.ratelimits)env[name]={limit:async()=>({success:true})};
const call=(path,method='GET')=>edge.fetch(new Request('https://spectra.churchofmalware.org'+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1'}}),env);
test('published books, assets and practice files have exact guarded routes',async()=>{
 for(const route of MANUAL_PATHS){
  assert.equal((await call(route)).status,200,route);
  const actual=route==='/manuals'||route==='/manuals/'?'/manuals/index.html':route;
  assert.ok(existsSync(new URL('../dist'+actual,import.meta.url))||existsSync(new URL('../dist'+actual+'.html',import.meta.url)),route);
 }
 for(const route of ['/manuals/review-notes.html','/manuals/source-provenance.json','/manuals/missing.exe','/manuals/.env','/manuals/../README.md'])assert.equal((await call(route)).status,404);
 assert.equal((await call('/manuals/beginner','POST')).status,405);
});
test('book CSP permits local reading assets without expanding workbench policy',async()=>{
 const book=await call('/manuals/beginner');assert.equal(book.headers.get('Content-Security-Policy'),MANUAL_CSP);
 assert.match(MANUAL_CSP,/script-src 'self';/);assert.doesNotMatch(MANUAL_CSP,/wasm-unsafe-eval|connect-src/);
 const app=await call('/');assert.match(app.headers.get('Content-Security-Policy'),/img-src data:;/);
 for(const r of [book,app]){assert.equal(r.headers.get('X-Frame-Options'),'DENY');assert.equal(r.headers.get('Cache-Control'),'public, max-age=0, must-revalidate');}
});
test('both manuals precede the field guide in Training ground',()=>{
 const text=readFileSync(new URL('../src/index.html',import.meta.url),'utf8');
 const view=text.indexOf('id="view-lessons"'),guide=text.indexOf('class="panel guide-panel"',view);
 for(const file of ['manuals/beginner.html','manuals/intermediate.html','manuals/pdf/RE-for-beginners-with-SPECTRA.pdf','manuals/pdf/Intermediate-RE-with-SPECTRA.pdf','manuals/practice-pack.zip']){
 const pos=text.indexOf('href="'+file+'"',view);assert.ok(pos>view&&pos<guide,file);
 }
});
