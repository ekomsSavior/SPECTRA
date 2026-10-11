/* Named browser investigations. Bundle bytes never leave this origin. */
(function(root){
'use strict';
const LIMIT=512*1024*1024,PROJECTS=32,REVISIONS=8;
const text=(s,n)=>String(s||'').trim().slice(0,n);
function metadata(input){
 const name=text(input.name,120),group=text(input.group,120),sample=text(input.sample,240);
 if(!name)throw Error('Give the investigation a name.');
 if(!/^[a-f0-9]{64}$/.test(input.sha256||''))throw Error('A sample hash is required.');
 return {name,group,sample,sha256:input.sha256};
}
function open(){return new Promise((resolve,reject)=>{let blocked=false;const r=indexedDB.open('spectra-investigations',2);r.onupgradeneeded=()=>{const d=r.result;for(const n of ['workspace','projects','revisions'])if(!d.objectStoreNames.contains(n))d.createObjectStore(n);};r.onerror=()=>reject(Error('Browser storage is unavailable. Export your investigation instead.'));r.onblocked=()=>{blocked=true;reject(Error('Close older SPECTRA tabs, then retry the storage upgrade.'));};r.onsuccess=()=>{if(blocked){r.result.close();return;}r.result.onversionchange=()=>r.result.close();resolve(r.result);};});}
async function transaction(names,mode,work){const db=await open();return new Promise((resolve,reject)=>{const tx=db.transaction(names,mode);let result,problem;tx.oncomplete=()=>{db.close();resolve(result);};tx.onabort=tx.onerror=()=>{db.close();reject(problem||Error('Storage operation failed. Your previous saved revisions remain intact; export the current investigation.'));};const fail=e=>{problem=e;tx.abort();};try{work(tx,v=>result=v,fail);}catch(e){fail(e);}});}
const request=(r,fn,fail)=>{r.onsuccess=()=>{try{fn(r.result);}catch(e){fail(e);}};};
async function list(){return transaction(['projects'],'readonly',(tx,done,fail)=>request(tx.objectStore('projects').getAll(),rows=>done(rows.sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt))),fail));}
async function save(input,bundle,id=null){
 const m=metadata(input),bytes=bundle instanceof Uint8Array?bundle:new Uint8Array(bundle);
 if(!bytes.length||bytes.length>129*1024*1024)throw Error('Investigation bundle must be between 1 byte and 129 MiB.');
 return transaction(['projects','revisions'],'readwrite',(tx,done,fail)=>{
  const ps=tx.objectStore('projects'),rs=tx.objectStore('revisions');
  request(ps.getAll(),projects=>{
   const previous=id?projects.find(p=>p.id===id):null;
   if(id&&!previous)throw Error('The selected investigation no longer exists. Refresh the library.');
   if(previous?.trashed)throw Error('Restore this investigation from Trash before saving a revision.');
   if(previous&&previous.sha256!==m.sha256)throw Error('This is a different binary. Save a new investigation under the same collection instead.');
   if(!previous&&projects.length>=PROJECTS)throw Error('Library cap: 32 investigations including Trash. Export unwanted projects, then delete them from Trash.');
   const key=previous?.id||crypto.randomUUID(),revision=crypto.randomUUID(),stamp=new Date().toISOString();
   const history=[{id:revision,savedAt:stamp,bytes:bytes.length},...(previous?.revisions||[])],removed=history.splice(REVISIONS);
   const total=projects.filter(p=>p.id!==key).reduce((n,p)=>n+p.revisions.reduce((n,r)=>n+r.bytes,0),0)+history.reduce((n,r)=>n+r.bytes,0);
   if(total>LIMIT)throw Error('Library byte budget reached (512 MiB). Export unwanted projects, then delete them from Trash. Browser storage may have a smaller quota.');
   const project={...m,id:key,createdAt:previous?.createdAt||stamp,updatedAt:stamp,trashed:false,revisions:history};
   rs.put({projectId:key,bundle:bytes},revision);for(const r of removed)rs.delete(r.id);ps.put(project,key);done(project);
  },fail);
 });
}
async function read(id,revision){return transaction(['projects','revisions'],'readonly',(tx,done,fail)=>request(tx.objectStore('projects').get(id),p=>{if(!p)throw Error('Investigation not found.');const r=p.revisions.find(r=>r.id===revision)||(!revision&&p.revisions[0]);if(!r)throw Error('Revision not found.');request(tx.objectStore('revisions').get(r.id),v=>{if(!v||v.projectId!==id)throw Error('Saved revision is missing.');done({...p,bundle:v.bundle,revision:r});},fail);},fail));}
async function trash(id,trashed){return transaction(['projects'],'readwrite',(tx,done,fail)=>{const s=tx.objectStore('projects');request(s.get(id),p=>{if(!p)throw Error('Investigation not found.');p.trashed=!!trashed;s.put(p,id);done(p);},fail);});}
async function purge(id){return transaction(['projects','revisions'],'readwrite',(tx,done,fail)=>{const ps=tx.objectStore('projects'),rs=tx.objectStore('revisions');request(ps.get(id),p=>{if(!p||!p.trashed)throw Error('Move the investigation to Trash before deleting it permanently.');for(const r of p.revisions)rs.delete(r.id);ps.delete(id);done(true);},fail);});}
async function estimate(){try{const e=await navigator.storage?.estimate();return e?{usage:e.usage,quota:e.quota}:null;}catch{return null;}}
root.SpectraLibrary={open,list,save,read,trash,purge,estimate,metadata,LIMIT,PROJECTS,REVISIONS};if(typeof module!=='undefined')module.exports=root.SpectraLibrary;
})(globalThis);
