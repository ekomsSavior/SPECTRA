/* Regular files remain inert byte buffers. No archive path is materialized. */
(function(root){
'use strict';
const MAX=64*1024*1024,ENTRY=16*1024*1024,COUNT=2000,decoder=new TextDecoder();
const string=b=>decoder.decode(b).replace(/\0.*$/s,'');
function path(s){s=s.replace(/^(?:\.\/)+/,'').replace(/\/$/,'');return root.SpectraArchive.name(s);}
function bounded(n,max=MAX){if(!Number.isSafeInteger(n)||n<0||n>max)throw Error('Container size or count exceeds the extraction budget.');return n;}
function oct(b){const s=string(b).trim();if(!/^[0-7]*$/.test(s))throw Error('GNU/base-256 or malformed TAR numbers are not supported.');return bounded(parseInt(s||'0',8));}
function tar(bytes){let at=0,entries=[],pax={},globalPax={},total=0;
 while(at+512<=bytes.length){const h=bytes.subarray(at,at+512);if(h.every(x=>x===0)){if(bytes.subarray(at).some(x=>x!==0))throw Error('Data follows the TAR terminator; concatenated archives need separate inspection.');return entries;}
  if(entries.length>=COUNT)throw Error('Container entry cap: 2,000.');let checksum=0;for(let i=0;i<512;i++)checksum+=i>=148&&i<156?32:h[i];if(checksum!==oct(h.subarray(148,156)))throw Error('TAR header checksum mismatch.');
  const type=String.fromCharCode(h[156]||48),prefix=string(h.subarray(345,500)),original=(prefix?prefix+'/':'')+string(h.subarray(0,100)),headerSize=oct(h.subarray(124,136));let size=headerSize,start=at+512;
  if(type==='x'||type==='g'){
   if(size>1024*1024||start+size>bytes.length)throw Error('PAX metadata limit exceeded.');const data=bytes.subarray(start,start+size),values={};let p=0;
   while(p<data.length){let space=p;while(space<data.length&&data[space]!==32)space++;const n=Number(string(data.subarray(p,space)));if(!Number.isSafeInteger(n)||n<space-p+3||p+n>data.length||data[p+n-1]!==10)throw Error('Malformed PAX record.');const line=decoder.decode(data.subarray(space+1,p+n-1)),eq=line.indexOf('=');if(eq<1)throw Error('Malformed PAX property.');const key=line.slice(0,eq),value=line.slice(eq+1);if(key.startsWith('GNU.sparse'))throw Error('Sparse TAR needs a separate parser.');values[key]=value;p+=n;}
   if(type==='g')globalPax={...globalPax,...values};else pax=values;at=start+Math.ceil(size/512)*512;continue;
  }
  const attrs={...globalPax,...pax};pax={};if(attrs.size!==undefined){if(!/^\d+$/.test(attrs.size))throw Error('Invalid PAX size.');size=bounded(Number(attrs.size));}const name=path(attrs.path||original);if(start+size>bytes.length)throw Error('TAR member extends beyond container bytes.');
  if(!['0','5','1','2','3','4','6'].includes(type))throw Error('Unsupported TAR extension or sparse member: '+type);
  const regular=type==='0';if(regular&&(size>ENTRY||(total+=size)>MAX))throw Error('Regular-file extraction budget exceeded.');entries.push({name,size,offset:start,kind:regular?'file':type==='5'?'directory':type==='2'?'symlink':type==='1'?'hardlink':'special',bytes:regular?bytes.slice(start,start+size):null});at=start+Math.ceil(size/512)*512;
 }
 throw Error('TAR is truncated or has no complete terminator.');
}
function cpio(bytes){let at=0,entries=[],total=0;const align=n=>Math.ceil(n/4)*4;
 while(at+110<=bytes.length){const h=bytes.subarray(at,at+110),magic=string(h.subarray(0,6));if(!['070701','070702'].includes(magic))throw Error('Expected newc/crc CPIO header.');const fields=[];for(let i=0;i<13;i++){const s=string(h.subarray(6+i*8,14+i*8));if(!/^[0-9a-f]{8}$/i.test(s))throw Error('Malformed CPIO field.');fields.push(parseInt(s,16));}
  const mode=fields[1],links=fields[4],size=bounded(fields[6]),namesize=bounded(fields[11],4096),check=fields[12],startName=at+110;if(!namesize||startName+namesize>bytes.length||bytes[startName+namesize-1]!==0)throw Error('Invalid CPIO name.');const raw=string(bytes.subarray(startName,startName+namesize-1)),start=align(startName+namesize);if(start+size>bytes.length)throw Error('CPIO member extends beyond container.');
  if(raw==='TRAILER!!!'){if(size||bytes.subarray(align(start+size)).some(x=>x!==0))throw Error('Concatenated CPIO streams need separate inspection.');return entries;}
  if(entries.length>=COUNT)throw Error('Container entry cap: 2,000.');if(magic==='070702'){let sum=0;for(const x of bytes.subarray(start,start+size))sum=(sum+x)>>>0;if(sum!==check)throw Error('CPIO member checksum mismatch.');}
  const type=mode&0xf000,regular=type===0x8000&&links<=1;if(regular&&(size>ENTRY||(total+=size)>MAX))throw Error('Regular-file extraction budget exceeded.');entries.push({name:path(raw),size,offset:start,kind:regular?'file':type===0x4000?'directory':type===0xa000?'symlink':type===0x8000?'hardlink':'special',bytes:regular?bytes.slice(start,start+size):null});at=align(start+size);
 }
 throw Error('CPIO is truncated or missing its trailer.');
}
async function gzip(bytes){const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip')).getReader(),chunks=[];let n=0;try{while(true){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>MAX)throw Error('Expanded container exceeds 64 MiB.');chunks.push(value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}const out=new Uint8Array(n);let at=0;for(const b of chunks){out.set(b,at);at+=b.length;}return out;}
async function inspect(bytes,offset=0,decode){bounded(bytes.length);bounded(offset,bytes.length);bytes=bytes.subarray(offset);let wrapper=null;if(bytes[0]===0x1f&&bytes[1]===0x8b){bytes=await gzip(bytes);wrapper='gzip';}
 let format,entries;const magic=string(bytes.subarray(0,6));
 if(bytes[0]===0x50&&bytes[1]===0x4b){format='ZIP';entries=(await root.SpectraArchive.unzip(bytes,{maxBytes:MAX,maxEntry:ENTRY,maxEntries:COUNT})).map(e=>({name:e.name,size:e.bytes.length,offset:e.offset,kind:e.name.endsWith('/')?'directory':'file',bytes:e.name.endsWith('/')?null:e.bytes,compression:e.method===8?'deflate':'stored'}));}
 else if(magic==='070701'||magic==='070702'){format='CPIO '+magic;entries=cpio(bytes);}
 else if(string(bytes.subarray(257,263)).startsWith('ustar')){format='USTAR/PAX';entries=tar(bytes);}
 else if(['hsqs','sqsh'].includes(string(bytes.subarray(0,4)))){const r=await root.SpectraSquashFS.inspect(bytes,decode);format='SquashFS 4.0 · '+r.codec;entries=r.entries.map(e=>({...e,offsetKind:'inode metadata block'}));}
 else throw Error('No supported container at this offset. Supported: ZIP, USTAR/PAX, newc/crc CPIO, SquashFS 4.0 (gzip / XZ / Zstandard), and gzip wrappers.');
 return {format,wrapper,containerOffset:offset,expandedSize:bytes.length,regularBytes:entries.reduce((n,e)=>n+(e.bytes?.length||0),0),entries,note:'Only regular files can be opened. Links and device entries stay metadata. Nested extraction is manual and uses the same byte/time limits.'};
}
root.SpectraFirmware={inspect,tar,cpio};if(typeof module!=='undefined')module.exports=root.SpectraFirmware;
})(globalThis);
