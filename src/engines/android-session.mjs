import './archive.js';
import './android.js';
import * as dexBridge from './dex.mjs';
import {decompile} from './vf.mjs';

const A=globalThis.SpectraAndroid,Z=globalThis.SpectraArchive,MiB=1048576;
const sha=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
let loadedDexBytes=null;
export class AndroidSession {
 async open(bytes,progress=()=>{}){
  if(!(bytes instanceof Uint8Array)||bytes.length>A.LIMITS.input)throw Error('Android input limit: 64 MiB.');this.bytes=bytes;this.files=[];this.dexes=[];this.classes=[];this.byName=new Map();this.active=-1;
  this.warnings=[];this.hash=await sha(bytes);let dexBytes=0;
  if(A.kind(bytes)==='dex')this.files=[{name:'classes.dex',length:bytes.length,direct:true}];
  else if(A.kind(bytes)==='zip'){
   this.files=Z.index(bytes,{maxBytes:A.LIMITS.expanded,maxEntry:64*MiB,maxEntries:A.LIMITS.entries});
   if(!this.files.some(x=>x.name==='AndroidManifest.xml'||/^classes(?:[2-9]\d*)?\.dex$/.test(x.name)))throw Error('This ZIP has no Android manifest or root classes.dex. Open an APK or a standard DEX file.');
   this.warnings.push('APK signatures are not verified. Archive CRC checks detect damage, not publisher authenticity.');
  }else throw Error('Android analysis needs an APK/ZIP or standard DEX file.');
  const dexFiles=this.files.filter(x=>/^classes(?:[2-9]\d*)?\.dex$/.test(x.name));
  if(dexFiles.length>A.LIMITS.dexFiles)throw Error('APK contains more than 32 root DEX files.');
  for(const file of dexFiles){
   if(file.length>A.LIMITS.dex||(dexBytes+=file.length)>64*MiB)throw Error('DEX budget: 32 MiB per file, 64 MiB combined.');
   progress('Reading '+file.name+'…');const data=await this.extract(file.name),meta=A.dex(data),id=this.dexes.length,d={file:file.name,bytes:data,sha256:await sha(data),meta};
   this.dexes.push(d);this.warnings.push(...meta.warnings.map(w=>file.name+': '+w));
   for(const c of meta.classes){if(this.classes.length>=A.LIMITS.classes)throw Error('Combined class budget exceeded.');const row={dex:id,index:c.index,name:c.name,descriptor:c.descriptor,methods:c.methods.length};this.classes.push(row);if(!this.byName.has(c.name))this.byName.set(c.name,[]);this.byName.get(c.name).push(row);}
  }
  const duplicates=[...this.byName.values()].filter(x=>x.length>1).length;if(duplicates)this.warnings.push(duplicates+' duplicate class identities across DEX files. Select their DEX explicitly; ambiguous dependencies are not guessed.');
  if(!dexFiles.length)this.warnings.push('No root classes.dex found. This may be a resource/configuration split, or its code may be packed or stored elsewhere.');
  this.warnings.push('Static reconstruction only. No Android runtime or APK execution. Obfuscation, packing, missing platform classes and DEX-to-JVM translation can limit the recovered Java.');
  return {sha256:this.hash,classes:this.classes,files:this.files.map(({name,length,method,offset,compressed,direct})=>({name,length,method,offset,compressed,direct})),dexes:this.dexes.map(d=>({file:d.file,sha256:d.sha256,version:d.meta.version,counts:d.meta.counts})),warnings:this.warnings};
 }
 async extract(name){
  const f=this.files.find(f=>f.name===name);if(!f)throw Error('APK member not found.');
  return f.direct?this.bytes:Z.extract(this.bytes,f,{maxEntry:32*MiB});
 }
 detail(dex,index){
  const d=this.dexes[dex],c=d?.meta.classes[index];if(!c)throw Error('DEX class selection is invalid.');
  return {...c,dex,file:d.file,sha256:d.sha256,methods:c.methods.slice(0,2000),fields:c.fields.slice(0,2000),membersClipped:c.methods.length>2000||c.fields.length>2000};
 }
 async resource(name){
  const bytes=await this.extract(name),sha256=await sha(bytes);
  if(name==='resources.arsc')return {name,sha256,kind:'table',...A.resources(bytes)};
  if(name.endsWith('.xml'))return {name,sha256,kind:'xml',...A.xml(bytes)};
  throw Error('Choose AndroidManifest.xml, a resource XML, or resources.arsc.');
 }
 async reconstruct(dex,index,progress=()=>{}){
  const detail=this.detail(dex,index),cache=new Map(),errors=[],missing=new Set();let total=0,converted=0;
  const translate=row=>{
   const key=row.dex+':'+row.index;if(cache.has(key))return cache.get(key);
   if(++converted>64)throw Error('Dependency conversion budget: 64 classes per reconstruction.');
   const d=this.dexes[row.dex];if(loadedDexBytes!==d.bytes){dexBridge.open(d.bytes);loadedDexBytes=d.bytes;}
   const generated=dexBridge.translate(row.index),data=generated[row.name];
   if(!(data instanceof Uint8Array)||!data.length)throw Error('DEX translation produced no class bytes for '+row.name+'.');
   total+=data.length;if(total>16*MiB)throw Error('Translated class byte budget: 16 MiB.');
   cache.set(key,data);return data;
  };
  const selected={dex,index,name:detail.name};translate(selected);
  progress('Reconstructing '+detail.name+'…');
  const tokens=[];let tokenText='',tokensClipped=false;
  const collect=(kind,start,length,declaration,className,name,descriptor)=>{
   if(tokens.length>=20000){tokensClipped=true;return;}
   tokens.push({kind,start,length,declaration:!!declaration,className,name:name||'',descriptor:descriptor||''});
  };
  const result=await decompile([detail.name],{
   source:async name=>{
    if(name===detail.name)return translate(selected);
    const rows=this.byName.get(name);if(!rows?.length){missing.add(name);return null;}
    if(rows.length!==1){missing.add(name+' (ambiguous)');return null;}
    try{return translate(rows[0]);}catch(e){if(errors.length<100)errors.push(name+': '+String(e.message||e).slice(0,400));return null;}
   },
   options:{'banner':'// SPECTRA · dex2jar + Vineflower · reconstructed Java, not original source\n','max-time-per-method':'10','thread-count':'1'},
   tokenCollector:{start:text=>{tokenText=text;tokens.length=0;},visitClass:(s,l,d,c)=>collect('class',s,l,d,c),visitField:(s,l,d,c,n,t)=>collect('field',s,l,d,c,n,t),visitMethod:(s,l,d,c,n,t)=>collect('method',s,l,d,c,n,t),visitParameter:()=>{},visitLocal:()=>{},end:()=>{}},
   logger:{writeMessage:(level,message)=>{if((level==='warn'||level==='error')&&errors.length<100)errors.push(String(message).slice(0,1000));}}
  });
  const code=result[detail.name]||result[detail.name+'.java']||Object.values(result)[0];
  if(typeof code!=='string'||!code.length)throw Error('Vineflower returned no source for this class.');
  if(code.length>2*MiB)throw Error('Reconstructed source exceeds 2 MiB. Choose a smaller class.');
  const validTokens=tokenText===code?tokens.filter(t=>Number.isInteger(t.start)&&Number.isInteger(t.length)&&t.start>=0&&t.length>0&&t.start+t.length<=code.length):[];
  return {code,engineKind:'android',engine:'dex2jar b5bda4f / TeaVM 0.15.0-dev-6 → Vineflower 1.12.0 / browser port 0.6.4',selection:{dexFile:detail.file,className:detail.name},dexSha256:detail.sha256,detail,tokens:validTokens,
   warnings:[...this.warnings,...(missing.size?['Unavailable or ambiguous class metadata ('+missing.size+'): '+[...missing].slice(0,30).join(', ')+(missing.size>30?' …':'')]:[]),...errors,...(tokensClipped?['Source navigation token budget reached.']:[]),...(validTokens.length?[]:['No verified source token positions were returned for this class.'])]};
 }
}
