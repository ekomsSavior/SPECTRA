/* Recovery transforms inspect data only. No native or emulated sample execution. */
(function(root){
'use strict';
const MAX_INPUT=4*1024*1024,MAX_OUTPUT=8*1024*1024,SCAN_LIMIT=256*1024,ROW_LIMIT=2000;
const printable=n=>n>=32&&n<=126;
function range(bytes,offset,size,limit=MAX_INPUT){if(![offset,size].every(Number.isSafeInteger)||offset<0||size<1||offset>bytes.length-size)throw Error('Choose a range inside the selected input.');if(size>limit)throw Error('This operation accepts at most '+(limit/1024)+' KiB at a time. Narrow the range.');return bytes.subarray(offset,offset+size);}
function hexBytes(s,label='Key',allowEmpty=false){const t=String(s||'').replace(/\s/g,'');if(!t&&allowEmpty)return new Uint8Array();if(!/^(?:[a-f0-9]{2})+$/i.test(t)||t.length>8192)throw Error(label+' must be complete hex byte pairs (at most 4,096 bytes).');return Uint8Array.from(t.match(/../g),x=>parseInt(x,16));}
function textBytes(s,method){if(method==='base64'){const t=s.replace(/\s/g,'');if(!/^[a-z0-9+/]*={0,2}$/i.test(t)||t.length%4===1)throw Error('This range is not standard Base64.');return Uint8Array.from(atob(t),x=>x.charCodeAt(0));}if(method==='hex'){const t=s.replace(/\s/g,'');if(!/^(?:[a-f0-9]{2})+$/i.test(t))throw Error('Hex input must contain complete byte pairs.');return Uint8Array.from(t.match(/../g),x=>parseInt(x,16));}throw Error('Unsupported text encoding.');}
function rc4(bytes,key){if(key.length>256)throw Error('RC4 keys are limited to 256 bytes.');const s=Uint8Array.from({length:256},(_,i)=>i);let j=0;for(let i=0;i<256;i++){j=(j+s[i]+key[i%key.length])&255;[s[i],s[j]]=[s[j],s[i]];}const out=new Uint8Array(bytes.length);let i=0;j=0;for(let n=0;n<bytes.length;n++){i=(i+1)&255;j=(j+s[i])&255;[s[i],s[j]]=[s[j],s[i]];out[n]=bytes[n]^s[(s[i]+s[j])&255];}return out;}
async function decompress(bytes,format,limit=MAX_OUTPUT){
 if(typeof DecompressionStream==='undefined')throw Error('This browser does not support local decompression.');
 const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format)).getReader(),chunks=[];let size=0;
 try{while(true){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>limit){await reader.cancel();throw Error('Expanded data exceeds the 8 MiB output limit.');}chunks.push(part.value);}}finally{reader.releaseLock();}
 const out=new Uint8Array(size);let p=0;for(const c of chunks){out.set(c,p);p+=c.length;}return out;
}
function summarize(bytes){const data=root.SpectraCore.extract(bytes,4,ROW_LIMIT);return {strings:data.strings,truncated:data.truncated,entropy:root.SpectraCore.entropy(bytes),size:bytes.length};}
async function transform(bytes,options){
 const input=range(bytes,options.offset,options.size),method=options.method;let out,params={};
 if(['gzip','deflate','deflate-raw'].includes(method)){try{out=await decompress(input,method);}catch(e){if(/limit|support/.test(e.message))throw e;throw Error('Decompression failed. Check the format and exact range; trailing bytes or a damaged stream can break it.');}}
 else if(['base64','hex'].includes(method)){out=textBytes(new TextDecoder('ascii').decode(input),method);}
 else if(['xor','rc4','aes-cbc','aes-gcm'].includes(method)){
  const key=hexBytes(options.key);params.keyBytes=key.length;
  if(method==='xor')out=input.map((b,i)=>b^key[i%key.length]);
  if(method==='rc4')out=rc4(input,key);
  if(method.startsWith('aes')){if(!root.crypto?.subtle)throw Error('AES needs Web Crypto in an HTTPS or localhost context.');if(![16,24,32].includes(key.length))throw Error('AES key must be 16, 24, or 32 bytes.');const iv=hexBytes(options.iv,'IV / nonce');if(method==='aes-cbc'&&iv.length!==16)throw Error('AES-CBC needs a 16-byte IV.');if(method==='aes-gcm'&&iv.length!==12)throw Error('This AES-GCM decoder expects a 12-byte nonce and a trailing 16-byte tag.');params.ivHex=options.iv.replace(/\s/g,'');const algorithm={name:method.toUpperCase(),iv};if(method==='aes-gcm'){algorithm.tagLength=128;algorithm.additionalData=hexBytes(options.aad,'Additional data',true);params.aadHex=options.aad||'';}try{const imported=await root.crypto.subtle.importKey('raw',key,algorithm.name,false,['decrypt']);out=new Uint8Array(await root.crypto.subtle.decrypt(algorithm,imported,input));}catch{throw Error('AES decryption failed. Check the key, IV, range, padding or authentication tag.');}}
 }else throw Error('Choose a supported transform.');
 if(out.length>MAX_OUTPUT)throw Error('Decoded data exceeds the 8 MiB output limit.');
 return {bytes:out,method,params,sourceOffset:options.offset,sourceLength:options.size,...summarize(out),note:'Transform completed. Readable output does not prove that the sample uses it.'};
}
function packingHints(bytes,meta){const hints=[];for(const s of meta?.sections||[]){if(/^UPX[012]$/i.test(s.name))hints.push({kind:'packer marker',offset:s.offset,text:s.name+' is a common UPX section name. Names can be copied or changed; this is a clue, not identification.'});if(s.size>=4096&&s.entropy>=7.2)hints.push({kind:'dense section',offset:s.offset,text:s.name+' has '+s.entropy.toFixed(2)+' bits/byte entropy. Compression, encryption, and dense data can all look like this.'});if(s.permissions?.includes('W')&&s.permissions?.includes('X'))hints.push({kind:'writable code',offset:s.offset,text:s.name+' is marked writable and executable. Worth checking, but not proof of packing.'});}return hints.slice(0,100);}
function scan(bytes,meta,options){
 const offset=options.offset,size=options.size,input=range(bytes,offset,size,SCAN_LIMIT),rows=[],hints=packingHints(bytes,meta),seen=new Set();let limited=false;
 function add(r){const k=r.method+':'+r.sourceOffset+':'+r.text;if(seen.has(k))return;if(rows.length>=ROW_LIMIT){limited=true;return;}seen.add(k);rows.push({...r,id:rows.length,tags:root.SpectraCore.tagsFor(r.text)});}
 const extracted=root.SpectraCore.extract(input,12,5000);
 for(const s of extracted.strings){if(s.encoding!=='ASCII'||s.clipped||s.text.length>8192)continue;const modes=[];if(/^(?:[0-9a-f]{2}){8,}$/i.test(s.text))modes.push('hex');if(s.text.length>=16&&s.text.length%4===0&&/^[a-z0-9+/]+={0,2}$/i.test(s.text))modes.push('base64');for(const method of modes){let decoded;try{decoded=textBytes(s.text,method);}catch{continue;}for(const t of root.SpectraCore.extract(decoded,6,50).strings){if(t.encoding==='UTF-16BE')continue;add({method,text:t.text,encoding:t.encoding,sourceOffset:offset+s.offset,sourceLength:s.byteLength,decodedOffset:t.offset,confidence:'decoded candidate',evidence:'Exact '+method+' transform; meaning and use still need checking.'});}}}
 // Indicator-led XOR search avoids producing thousands of random printable runs.
 // It derives a one-byte candidate key from each anchor, then verifies the full anchor.
 const anchors=['https://','http://','/bin/','/tmp/','/etc/','cmd.exe','powershell','HKEY_','User-Agent:'];
 for(let pos=0;pos<input.length;pos++){for(const anchor of anchors){if(pos+anchor.length>input.length)continue;const key=input[pos]^anchor.charCodeAt(0);if(!key)continue;let ok=true;for(let k=1;k<anchor.length;k++)if((input[pos+k]^key)!==anchor.charCodeAt(k)){ok=false;break;}if(!ok)continue;let end=pos;while(end<input.length&&end-pos<2048&&printable(input[end]^key))end++;if(end-pos<8)continue;const text=Array.from(input.subarray(pos,end),b=>String.fromCharCode(b^key)).join('');add({method:'xor',keyHex:key.toString(16).padStart(2,'0'),text,encoding:'ASCII',sourceOffset:offset+pos,sourceLength:end-pos,decodedOffset:0,confidence:'XOR candidate',evidence:'Single-byte XOR matched '+anchor+'. This is a lead, not a verified runtime decode.'});}}
 for(let i=0;i+2<input.length&&hints.length<120;i++){if(input[i]===0x1f&&input[i+1]===0x8b&&input[i+2]===8)hints.push({kind:'gzip header candidate',offset:offset+i,text:'Gzip header bytes. Select the exact stream in Decode bytes; embedded trailing data may need trimming.'});if(input[i]===0x78&&[0x01,0x5e,0x9c,0xda].includes(input[i+1]))hints.push({kind:'zlib header candidate',offset:offset+i,text:'Possible zlib header. The two-byte signature alone is not proof of compressed data.'});}
 return {rows,hints,offset,size,limited:limited||extracted.truncated||hints.length>=120,note:'Scanned '+size+' bytes. XOR hunt covers ASCII indicators with a single-byte key. Base64 and hex candidates are whole extracted strings. Other schemes can be missed.'};
}
const api={range,hexBytes,rc4,decompress,transform,scan,packingHints,MAX_INPUT,MAX_OUTPUT,SCAN_LIMIT,ROW_LIMIT};root.SpectraRecovery=api;if(typeof module!=='undefined')module.exports=api;
})(globalThis);
