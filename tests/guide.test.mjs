import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {chapters,guideEdition} from '../src/guide-content.mjs';
import {standaloneGuide} from '../src/guide-build.mjs';
const source=readFileSync(new URL('../src/index.html',import.meta.url),'utf8');
const built=readFileSync(new URL('../dist/index.html',import.meta.url),'utf8');
const standalone=readFileSync(new URL('../dist/guide.html',import.meta.url),'utf8');
const ids=new Set(chapters.map(c=>c.id));
test('guide preserves existing bookmarks and routes chapters only to real views',()=>{
 assert.equal(ids.size,chapters.length);
 for(const id of ['start','strings','code','decompile','debugger','functions','references','hex','structure','detect','recovery','decoder','compare','firmware','lessons','notebook','workflows','glossary'])assert.ok(ids.has(id),id);
 for(const c of chapters)if(c.view)assert.ok(source.includes('id="view-'+c.view+'"'),c.id+' view');
});
test('cross-chapter links resolve in the standalone and embedded readers',()=>{
 for(const c of chapters)for(const m of c.body.matchAll(/<a href="#guide-([^"]+)" data-guide-link="([^"]+)"/g)){
  assert.equal(m[1],m[2]); assert.ok(ids.has(m[1]),c.id+' -> '+m[1]);
  assert.ok(standalone.includes('id="guide-'+m[1]+'"'));
 }
 assert.ok(built.includes("a[data-guide-link]"));
 assert.ok(built.includes('showGuideChapter(link.dataset.guideLink,true)'));
});
test('the built standalone guide and embedded guide match the same source edition',()=>{
 assert.equal(standalone,standaloneGuide(),'Rebuild guide.html when refreshing the workbench');
 const match=built.match(/const SPECTRA_GUIDE=(.+);\n/);assert.ok(match);
 const embedded=JSON.parse(match[1]);assert.equal(embedded.edition,guideEdition);assert.deepEqual(embedded.chapters,chapters);
 assert.ok(built.includes('Read the field guide · '+chapters.length+' chapters'));
});
test('field reference has safe editorial markup and no embedded CTF answer keys',()=>{
 for(const c of chapters){
  assert.doesNotMatch(c.body,/<script\b|\bon\w+=|javascript:/i,c.id);
  assert.doesNotMatch(c.body,/SPECTRA\{[^}]+\}/,c.id+' must not include CTF flags');
  for(const m of c.body.matchAll(/<a\b[^>]*target="_blank"[^>]*>/g))assert.match(m[0],/rel="noopener noreferrer"/);
 }
});
