/* Bounded ZIP transport. Entries remain bytes; paths never become host paths. */
(function(root){
'use strict';
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true}),table=Uint32Array.from({length:256},(_,n)=>{for(let i=0;i<8;i++)n=n&1?0xedb88320^(n>>>1):n>>>1;return n>>>0;});
function crc(b){let n=0xffffffff;for(const v of b)n=table[(n^v)&255]^(n>>>8);return (n^0xffffffff)>>>0;}
function name(s){if(typeof s!=='string'||s.length>240||!s||/[\\\x00-\x1f:]/.test(s)||s.startsWith('/')||(s.endsWith('/')?s.slice(0,-1):s).split('/').some(x=>!x||x==='.'||x==='..'))throw Error('Unsafe or unsupported archive path.');return s;}
function zip(entries){
 if(!Array.isArray(entries)||entries.length>512)throw Error('Archive entry limit: 512.');const seen=new Set(),parts=[],central=[];let offset=0,total=0;
 for(const item of entries){const n=enc.encode(name(item.name)),bytes=typeof item.bytes==='string'?enc.encode(item.bytes):item.bytes;if(!(bytes instanceof Uint8Array)||seen.has(item.name))throw Error('Invalid or duplicate archive entry.');seen.add(item.name);total+=bytes.length;if(total>128*1024*1024)throw Error('Archive byte limit: 128 MiB.');const c=crc(bytes),h=new Uint8Array(30+n.length),v=new DataView(h.buffer);v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);v.setUint16(6,0x800,true);v.setUint32(14,c,true);v.setUint32(18,bytes.length,true);v.setUint32(22,bytes.length,true);v.setUint16(26,n.length,true);h.set(n,30);parts.push(h,bytes);
  const z=new Uint8Array(46+n.length),d=new DataView(z.buffer);d.setUint32(0,0x02014b50,true);d.setUint16(4,20,true);d.setUint16(6,20,true);d.setUint16(8,0x800,true);d.setUint32(16,c,true);d.setUint32(20,bytes.length,true);d.setUint32(24,bytes.length,true);d.setUint16(28,n.length,true);d.setUint32(42,offset,true);z.set(n,46);central.push(z);offset+=h.length+bytes.length;
 }
 const csize=central.reduce((n,b)=>n+b.length,0),end=new Uint8Array(22),v=new DataView(end.buffer);v.setUint32(0,0x06054b50,true);v.setUint16(8,entries.length,true);v.setUint16(10,entries.length,true);v.setUint32(12,csize,true);v.setUint32(16,offset,true);const out=new Uint8Array(offset+csize+22);let pos=0;for(const b of [...parts,...central,end]){out.set(b,pos);pos+=b.length;}return out;
}
function index(bytes,{maxBytes=128*1024*1024,maxEntry=64*1024*1024,maxEntries=512,storedOnly=false}={}){
 if(!(bytes instanceof Uint8Array)||bytes.length>maxBytes+1024*1024||bytes.length<22)throw Error('Archive size limit exceeded or ZIP is truncated.');
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),u16=o=>v.getUint16(o,true),u32=o=>v.getUint32(o,true);let e=-1;
 for(let o=bytes.length-22;o>=Math.max(0,bytes.length-65557);o--)if(u32(o)===0x06054b50&&o+22+u16(o+20)===bytes.length){e=o;break;}
 if(e<0||u16(e+4)||u16(e+6)||u16(e+8)!==u16(e+10))throw Error('Unsupported ZIP directory.');
 const count=u16(e+10),size=u32(e+12),start=u32(e+16);if(count>maxEntries||count===65535||start+size!==e)throw Error('Archive directory limits exceeded.');
 let at=start,total=0;const entries=[],seen=new Set(),spans=[];
 for(let i=0;i<count;i++){
  if(at+46>e||u32(at)!==0x02014b50)throw Error('Invalid ZIP entry.');
  const flags=u16(at+8),method=u16(at+10),checksum=u32(at+16),compressed=u32(at+20),length=u32(at+24),n=u16(at+28),extra=u16(at+30),comment=u16(at+32),local=u32(at+42),mode=u32(at+38)>>>16;
  if(at+46+n+extra+comment>e||u16(at+34)||flags&~0x808||![0,8].includes(method)||storedOnly&&method!==0||(mode&0xf000)===0xa000)throw Error('Encrypted, linked, or unsupported ZIP member.');
  const path=name(dec.decode(bytes.subarray(at+46,at+46+n)));if(seen.has(path))throw Error('Duplicate ZIP path.');seen.add(path);total+=length;if(length>maxEntry||total>maxBytes||compressed>maxBytes||method===0&&compressed!==length)throw Error('Expanded archive exceeds its byte budget.');
  if(local+30>start||u32(local)!==0x04034b50||u16(local+6)!==flags||u16(local+8)!==method)throw Error('ZIP local header mismatch.');
  const ln=u16(local+26),le=u16(local+28),data=local+30+ln+le;if(data>start||data+compressed>start||dec.decode(bytes.subarray(local+30,local+30+ln))!==path)throw Error('ZIP member is outside the data area.');
  if(!(flags&8)&&(u32(local+14)!==checksum||u32(local+18)!==compressed||u32(local+22)!==length))throw Error('ZIP size or checksum header mismatch.');
  spans.push([local,data+compressed]);entries.push({name:path,offset:data,compressed,length,method,checksum});at+=46+n+extra+comment;
 }
 if(at!==e)throw Error('Unexpected ZIP directory data.');spans.sort((a,b)=>a[0]-b[0]);for(let i=1;i<spans.length;i++)if(spans[i][0]<spans[i-1][1])throw Error('Overlapping ZIP entries.');
 return entries;
}
async function extract(bytes,item,{maxEntry=64*1024*1024}={}){
 if(!(bytes instanceof Uint8Array)||!item||!Number.isSafeInteger(item.offset)||!Number.isSafeInteger(item.compressed)||!Number.isSafeInteger(item.length)||item.offset<0||item.compressed<0||item.length<0||item.length>maxEntry||item.offset+item.compressed>bytes.length||![0,8].includes(item.method))throw Error('Invalid ZIP extraction span.');
 let b=bytes.subarray(item.offset,item.offset+item.compressed);
 if(item.method===8){const stream=new Blob([b]).stream().pipeThrough(new DecompressionStream('deflate-raw')),reader=stream.getReader(),chunks=[];let n=0;try{while(true){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>item.length||n>maxEntry)throw Error('ZIP output exceeds its declared size.');chunks.push(value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}b=new Uint8Array(n);let at=0;for(const c of chunks){b.set(c,at);at+=c.length;}}
 if(b.length!==item.length||crc(b)!==item.checksum)throw Error('ZIP member checksum or size mismatch.');return b.slice();
}
async function unzip(bytes,options={}){
 const entries=index(bytes,options),out=[];
 for(const item of entries)out.push({...item,bytes:await extract(bytes,item,options)});
 return out;
}
root.SpectraArchive={zip,unzip,index,extract,crc,name};if(typeof module!=='undefined')module.exports=root.SpectraArchive;
})(globalThis);
