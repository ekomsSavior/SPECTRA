/* Compare evidence, retaining uncertain matches and incomplete decoding. */
(function(root){
'use strict';
const hash=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
const delta=(a,b,key)=>{const x=new Map(a.map(v=>[key(v),v])),y=new Map(b.map(v=>[key(v),v]));return {removed:[...x].filter(([k])=>!y.has(k)).map(([,v])=>v),added:[...y].filter(([k])=>!x.has(k)).map(([,v])=>v)};};
// Positional comparison: an insertion can shift every following byte. This
// reports evidence at equal file offsets, not a sequence alignment or code VA.
function bytePage(a,b,start=0,limit=64){
 if(!Number.isSafeInteger(start)||start<0||!Number.isSafeInteger(limit)||limit<1||limit>4096)throw Error('Invalid byte page.');
 const rows=[],end=Math.max(a.length,b.length);
 for(let offset=start;offset<end;offset++){
  const before=offset<a.length?a[offset]:null,after=offset<b.length?b[offset]:null;
  if(before===after)continue;
  if(rows.length===limit)return {rows,nextOffset:offset};
  rows.push({offset,before,after,kind:before===null?'added':after===null?'removed':'modified'});
 }
 return {rows,nextOffset:null};
}
function rawBytes(a,b){
 let modified=0;const common=Math.min(a.length,b.length);
 for(let offset=0;offset<common;offset++)if(a[offset]!==b[offset])modified++;
 const added=Math.max(0,b.length-a.length),removed=Math.max(0,a.length-b.length),total=modified+added+removed;
 const preview=bytePage(a,b,0,4096);
 return {mode:'same-file-offset',comparedOffsets:Math.max(a.length,b.length),modified,added,removed,total,rows:preview.rows,rowLimit:4096,omitted:Math.max(0,total-preview.rows.length),note:'Absolute file offsets; no insertion/deletion alignment. Added and removed mean bytes beyond the other file’s end. JSON includes the first 4096 differences; the table can page through every difference.'};
}
async function functions(code){const by=new Map((code?.instructions||[]).map(i=>[i.address,i]));return Promise.all((code?.functions||[]).slice(0,2000).map(async f=>{const instructions=f.instructionAddresses.map(a=>by.get(a)).filter(Boolean),raw=instructions.map(i=>(i.address-f.address)+':'+i.bytes.map(x=>x.toString(16).padStart(2,'0')).join('')).join('|'),shape=instructions.map(i=>i.mnemonic+' '+i.operands.replace(/(?:0x[\da-f]+|\b\d+\b)/gi,'#')).join('|');return {address:f.address,name:f.name,source:f.source,instructionCount:instructions.length,sha256:await hash(new TextEncoder().encode(raw)),shape:await hash(new TextEncoder().encode(shape)),assembly:instructions.map(i=>({address:i.address,mnemonic:i.mnemonic,operands:i.operands,bytes:i.bytes}))};}));}
function matches(before,after){const usedA=new Set(),usedB=new Set(),matched=[],ambiguous=[];
 const pass=(key,basis,confidence)=>{const a=new Map(),b=new Map();for(const [list,map,used]of [[before,a,usedA],[after,b,usedB]])for(const f of list){if(used.has(f.address))continue;const k=key(f);if(k)(map.get(k)||map.set(k,[]).get(k)).push(f);}for(const [k,x]of a){const y=b.get(k);if(!y)continue;if(x.length===1&&y.length===1){usedA.add(x[0].address);usedB.add(y[0].address);matched.push({before:x[0],after:y[0],basis,confidence,changed:x[0].sha256!==y[0].sha256});}else if(basis==='identical decoded bytes')ambiguous.push({basis,before:x.map(f=>f.address),after:y.map(f=>f.address)});}};
 pass(f=>f.instructionCount?f.sha256:null,'identical decoded bytes','exact bytes; not proof of behavioral equivalence');
 pass(f=>!/^sub_|^entry$|^range_/.test(f.name)&&!['direct call','executable range start','code-address candidate'].includes(f.source)?f.name:null,'matching symbol name','candidate; inspect both functions');
 pass(f=>f.instructionCount>1?f.shape:null,'same normalized instruction shape','heuristic; constants and addresses ignored');
 return {matched,ambiguous,removed:before.filter(f=>!usedA.has(f.address)),added:after.filter(f=>!usedB.has(f.address))};
}
async function compare(a,b){
 const af=await functions(a.code),bf=await functions(b.code),strings=delta(a.meta.strings||[],b.meta.strings||[],s=>s.encoding+':'+s.byteLength+':'+s.text),imports=delta(a.meta.imports||[],b.meta.imports||[],i=>i.library+'!'+i.name);
 return {schema:'spectra-comparison-v1',rawBytes:rawBytes(a.bytes,b.bytes),before:{name:a.name,sha256:await hash(a.bytes),format:a.meta.format,architecture:a.meta.architecture,size:a.bytes.length},after:{name:b.name,sha256:await hash(b.bytes),format:b.meta.format,architecture:b.meta.architecture,size:b.bytes.length},strings,imports,functions:matches(af,bf),warnings:[...(a.code?.warnings||[]),...(b.code?.warnings||[]),...(a.code?.truncated||b.code?.truncated?['Instruction limit reached. Function comparison is partial.']:[]),...(a.meta.truncated||b.meta.truncated?['String extraction was capped. String comparison is partial.']:[]),...((a.meta.strings||[]).some(s=>s.clipped)||(b.meta.strings||[]).some(s=>s.clipped)?['Long string previews are clipped. Changes after the preview may be missed; compare the original bytes.']:[]),'Function matching uses decoded instructions, metadata names, then a labeled shape heuristic. Ambiguous groups and unmatched functions remain visible.']};
}
root.SpectraCompare={compare,matches,functions,rawBytes,bytePage};if(typeof module!=='undefined')module.exports=root.SpectraCompare;
})(globalThis);
