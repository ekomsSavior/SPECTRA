/* Android input readers. Bytes are data, never loaded as executable classes.
 * Layout references: AOSP dex-format and androidfw/ResourceTypes.h. */
(function(root){
'use strict';
const MiB=1048576, utf8=new TextDecoder('utf-8',{fatal:true});
const LIMITS=Object.freeze({input:64*MiB,dex:32*MiB,entries:20000,expanded:256*MiB,dexFiles:32,classes:50000,strings:250000,methods:65536,resourceEntries:20000,text:2*MiB});
function reader(bytes,max=LIMITS.input){
 if(!(bytes instanceof Uint8Array)||bytes.length>max)throw Error('Android input exceeds its byte budget.');
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
 const span=(p,n,end=bytes.length)=>{if(!Number.isSafeInteger(p)||!Number.isSafeInteger(n)||p<0||n<0||p+n>end||end>bytes.length)throw Error('Android structure points outside its bytes.');return p;};
 return {bytes,span,u8:p=>v.getUint8(span(p,1)),u16:p=>v.getUint16(span(p,2),true),u32:p=>v.getUint32(span(p,4),true)};
}
function kind(bytes){if(bytes?.length>=8&&String.fromCharCode(...bytes.subarray(0,4))==='dex\n')return 'dex';if(bytes?.length>=4&&bytes[0]===80&&bytes[1]===75&&bytes[2]===3&&bytes[3]===4)return 'zip';return '';}
function leb(r,pos){let n=0;for(let i=0;i<5;i++){const b=r.u8(pos.p++);if(i===4&&(b&240))throw Error('Oversized DEX LEB128.');n+=(b&127)*2**(i*7);if(!(b&128))return n;}throw Error('Unterminated DEX LEB128.');}
function adler(bytes){let a=1,b=0;for(const x of bytes){a=(a+x)%65521;b=(b+a)%65521;}return (b*65536+a)>>>0;}
function dex(bytes){
 const r=reader(bytes,LIMITS.dex),{u16,u32,span}=r;
 span(0,112);const version=String.fromCharCode(...bytes.subarray(4,7));
 if(kind(bytes)!=='dex'||bytes[7]!==0||!['035','037','038','039','040'].includes(version))throw Error('Supported DEX versions: 035, 037–040. Compact/optimized DEX and 041 containers need a separate reader.');
 if(u32(32)!==bytes.length||u32(36)!==112||u32(40)!==0x12345678)throw Error('Unsupported DEX header, size, or byte order.');
 const warnings=[];if(adler(bytes.subarray(12))!==u32(8))warnings.push('DEX Adler-32 does not match. The bytes may be modified or corrupt.');
 function table(at,width,limit){const n=u32(at),off=u32(at+4);if(n>limit||n&&off<112||off%4)throw Error('DEX table count, alignment or offset is invalid.');span(off,n*width);return {n,off};}
 const st=table(56,4,LIMITS.strings),tt=table(64,4,65536),pt=table(72,12,65536),ft=table(80,8,65536),mt=table(88,8,LIMITS.methods),ct=table(96,32,LIMITS.classes);
 const dataSize=u32(104),dataOff=u32(108);span(dataOff,dataSize);const mapOff=u32(52);if(mapOff){const n=u32(mapOff);if(n>256)throw Error('DEX map count exceeds its budget.');span(mapOff+4,n*12);}
 const strings=new Array(st.n);let stringUnits=0;
 function str(i){
  if(i>=st.n)throw Error('DEX string index is invalid.');if(strings[i]!==undefined)return strings[i];
  const pos={p:u32(st.off+i*4)},len=leb(r,pos);if(len>65536||(stringUnits+=len)>8*MiB)throw Error('DEX string budget exceeded.');
  const units=[];for(let j=0;j<len;j++){
   const a=r.u8(pos.p++);let c;
   if(a>0&&a<128)c=a;
   else if((a&224)===192){const b=r.u8(pos.p++);if((b&192)!==128)throw Error('Invalid DEX MUTF-8.');c=((a&31)<<6)|(b&63);if(c&&c<128)throw Error('Overlong DEX MUTF-8.');}
   else if((a&240)===224){const b=r.u8(pos.p++),d=r.u8(pos.p++);if((b&192)!==128||(d&192)!==128)throw Error('Invalid DEX MUTF-8.');c=((a&15)<<12)|((b&63)<<6)|(d&63);if(c<2048)throw Error('Overlong DEX MUTF-8.');}
   else throw Error('Invalid DEX MUTF-8.');
   units.push(c);
  }
  if(r.u8(pos.p++)!==0)throw Error('DEX string length/terminator mismatch.');
  let out='';for(let p=0;p<units.length;p+=4096)out+=String.fromCharCode(...units.slice(p,p+4096));return strings[i]=out;
 }
 function type(i){if(i>=tt.n)throw Error('DEX type index is invalid.');return str(u32(tt.off+i*4));}
 const protos=new Map();
 function proto(i){if(protos.has(i))return protos.get(i);if(i>=pt.n)throw Error('DEX prototype index is invalid.');const at=pt.off+i*12,off=u32(at+8),ret=type(u32(at+4));let args='';if(off){const n=u32(off);if(n>255)throw Error('DEX argument budget exceeded.');span(off+4,n*2);for(let j=0;j<n;j++){args+=type(u16(off+4+j*2));if(args.length>4096)throw Error('DEX prototype text budget exceeded.');}}const result='('+args+')'+ret;if(result.length>4096)throw Error('DEX prototype text budget exceeded.');protos.set(i,result);return result;}
 const classes=[],seen=new Set();let methodCount=0,metadataUnits=0;
 const account=n=>{if((metadataUnits+=n)>8*MiB)throw Error('DEX metadata text budget exceeded.');};
 for(let i=0;i<ct.n;i++){
  const at=ct.off+i*32,descriptor=type(u32(at)),access=u32(at+4),parent=u32(at+8),source=u32(at+16),classData=u32(at+24);
  if(!/^L[^;\0]+;$/.test(descriptor)||descriptor.length>4096||seen.has(descriptor))throw Error('Invalid or duplicate DEX class descriptor.');seen.add(descriptor);
  const item={index:i,descriptor,name:descriptor.slice(1,-1),access,superclass:parent===0xffffffff?null:type(parent),source:source===0xffffffff?null:str(source),offset:at,methods:[],fields:[]};
  if(classData){
   const pos={p:classData},counts=[leb(r,pos),leb(r,pos),leb(r,pos),leb(r,pos)];
   if(counts[0]+counts[1]>ft.n||counts[2]+counts[3]>mt.n||(methodCount+=counts[2]+counts[3])>100000)throw Error('DEX member count budget exceeded.');
   for(let group=0;group<4;group++){let index=0;for(let j=0;j<counts[group];j++){
    const delta=leb(r,pos);if(j&&delta===0)throw Error('Duplicate DEX member.');index+=delta;const flags=leb(r,pos);
    if(group<2){if(index>=ft.n)throw Error('Invalid DEX field index.');const f=ft.off+index*8;if(type(u16(f))!==descriptor)throw Error('DEX field owner mismatch.');item.fields.push({index,name:str(u32(f+4)),type:type(u16(f+2)),access:flags});}
    else{if(index>=mt.n)throw Error('Invalid DEX method index.');const m=mt.off+index*8;if(type(u16(m))!==descriptor)throw Error('DEX method owner mismatch.');const codeOffset=leb(r,pos),method={index,name:str(u32(m+4)),descriptor:proto(u16(m+2)),access:flags,codeOffset,offset:m};
     if(codeOffset){if(codeOffset%4)throw Error('Misaligned DEX code.');span(codeOffset,16);const units=u32(codeOffset+12);span(codeOffset+16,units*2);method.instructionOffset=codeOffset+16;method.instructionBytes=units*2;method.registers=u16(codeOffset);method.inputs=u16(codeOffset+2);method.tries=u16(codeOffset+6);}
     item.methods.push(method);
    }
   }}
  }
  account(item.name.length+(item.superclass?.length||0)+(item.source?.length||0)+item.fields.reduce((n,f)=>n+f.name.length+f.type.length,0)+item.methods.reduce((n,m)=>n+m.name.length+m.descriptor.length,0));classes.push(item);
 }
 return {version,classes,counts:{classes:ct.n,strings:st.n,types:tt.n,methods:mt.n,fields:ft.n},warnings};
}
function chunk(r,p,end){r.span(p,8,end);const type=r.u16(p),header=r.u16(p+2),size=r.u32(p+4);if(header<8||size<header)throw Error('Invalid Android resource chunk.');r.span(p,size,end);return {p,type,header,size,end:p+size};}
function pool(r,c){
 if(c.type!==1||c.header<28)throw Error('Invalid Android string pool.');const count=r.u32(c.p+8),styles=r.u32(c.p+12),flags=r.u32(c.p+16),start=c.p+r.u32(c.p+20),styleStart=r.u32(c.p+24),end=styleStart?c.p+styleStart:c.end;
 if(count>LIMITS.strings||styles>LIMITS.strings||start<c.p+c.header+(count+styles)*4||end<start||end>c.end)throw Error('Android string pool bounds exceeded.');r.span(c.p+c.header,(count+styles)*4,c.end);
 const out=[];let total=0;const len8=pos=>{let n=r.u8(pos.p++);if(n&128)n=((n&127)<<8)|r.u8(pos.p++);return n;},len16=pos=>{let n=r.u16(pos.p);pos.p+=2;if(n&32768){n=(n&32767)*65536+r.u16(pos.p);pos.p+=2;}return n;};
 for(let i=0;i<count;i++){const pos={p:start+r.u32(c.p+c.header+i*4)};r.span(pos.p,1,end);let s;
  if(flags&256){const units=len8(pos),n=len8(pos);r.span(pos.p,n+1,end);s=utf8.decode(r.bytes.subarray(pos.p,pos.p+n));if(s.length!==units||r.u8(pos.p+n)!==0)throw Error('Invalid UTF-8 resource string.');}
  else{const n=len16(pos);r.span(pos.p,n*2+2,end);if(n>65536||r.u16(pos.p+n*2)!==0)throw Error('Invalid UTF-16 resource string.');s='';for(let j=0;j<n;j++)s+=String.fromCharCode(r.u16(pos.p+j*2));}
  total+=s.length;if(total>8*MiB)throw Error('Resource string budget exceeded.');out.push(s);
 }
 return out;
}
const xmlEscape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
function value(r,p,strings){if(r.u16(p)!==8||r.u8(p+2)!==0)throw Error('Unsupported Android typed value.');const t=r.u8(p+3),n=r.u32(p+4);if(t===3){if(n>=strings.length)throw Error('Invalid resource value string.');return strings[n];}if(t===0)return n===0?'@null':'@empty';if(t===1||t===7)return '@0x'+n.toString(16).padStart(8,'0');if(t===2||t===8)return '?0x'+n.toString(16).padStart(8,'0');if(t===18)return n?'true':'false';if(t===16)return String(n|0);if(t===17)return '0x'+n.toString(16);if(t>=28&&t<=31)return '#'+n.toString(16).padStart(8,'0');if(t===4)return String(new DataView(r.bytes.buffer,r.bytes.byteOffset+p+4,4).getFloat32(0,true));return '[type 0x'+t.toString(16)+' · data 0x'+n.toString(16)+']';}
function xml(bytes){
 const r=reader(bytes,16*MiB);if(bytes.length&&[60,239].includes(bytes[0])){const text=utf8.decode(bytes);if(text.length>LIMITS.text)throw Error('XML text budget exceeded.');return {text,warnings:['Plain XML displayed as supplied. No external entities or URLs are resolved.'],elements:[]};}
 const top=chunk(r,0,bytes.length);if(top.type!==3||top.end!==bytes.length)throw Error('Not Android binary XML.');let strings=null,at=top.header,lines=[],stack=[],namespaces=new Map(),pending=[],elements=[],nodes=0,textSize=0;
 const str=i=>{if(!strings||i>=strings.length)throw Error('Invalid XML string index.');return strings[i];};
 const qname=(ns,name)=>ns===0xffffffff?str(name):(namespaces.has(ns)?(namespaces.get(ns)?namespaces.get(ns)+':':''):'ns'+ns+':')+str(name);
 function line(s){lines.push('  '.repeat(Math.min(stack.length,32))+s);if((textSize+=lines[lines.length-1].length+1)>LIMITS.text)throw Error('XML text budget exceeded.');}
 while(at<top.end){const c=chunk(r,at,top.end);if(++nodes>50000)throw Error('XML node budget exceeded.');
  if(c.type===1){if(strings)throw Error('Duplicate XML string pool.');strings=pool(r,c);}
  else if(c.type===0x180){if(c.header!==8||(c.size-8)%4)throw Error('Invalid XML resource map.');}
  else if(c.type>=0x100&&c.type<=0x104){
   if(c.header<16)throw Error('Invalid XML node header.');const p=c.p+c.header;
   if(c.type===0x100||c.type===0x101){r.span(p,8,c.end);const prefix=r.u32(p),uri=r.u32(p+4);if(c.type===0x100){namespaces.set(uri,str(prefix));pending.push('xmlns'+(str(prefix)?':'+str(prefix):'')+'="'+xmlEscape(str(uri))+'"');}else namespaces.delete(uri);}
   else if(c.type===0x102){r.span(p,20,c.end);const ns=r.u32(p),ni=r.u32(p+4),name=qname(ns,ni),start=r.u16(p+8),width=r.u16(p+10),count=r.u16(p+12);if(start<20||width<20||count>1024||stack.length>128)throw Error('XML attribute/depth budget exceeded.');r.span(p+start,count*width,c.end);let attrChars=0;const attrs=[],record={name:str(ni),namespace:ns===0xffffffff?null:str(ns),offset:at,attributes:[]};
    for(let i=0;i<count;i++){const a=p+start+i*width,an=qname(r.u32(a),r.u32(a+4)),raw=r.u32(a+8),val=raw===0xffffffff?value(r,a+12,strings):str(raw);if((attrChars+=an.length+val.length)>LIMITS.text)throw Error('XML attribute text budget exceeded.');attrs.push(an+'="'+xmlEscape(val)+'"');record.attributes.push({name:str(r.u32(a+4)),namespace:r.u32(a)===0xffffffff?null:str(r.u32(a)),value:val});}
    line('<'+name+[...pending,...attrs].map(a=>' '+a).join('')+'>');pending=[];stack.push(name);elements.push(record);
   }else if(c.type===0x103){r.span(p,8,c.end);const name=qname(r.u32(p),r.u32(p+4));if(stack.pop()!==name)throw Error('Mismatched binary XML elements.');line('</'+name+'>');}
   else{r.span(p,12,c.end);line(xmlEscape(str(r.u32(p))));}
  }else throw Error('Unsupported XML chunk 0x'+c.type.toString(16)+'.');
  at=c.end;
 }
 if(!strings||stack.length)throw Error('Incomplete binary XML.');
 return {text:lines.join('\n'),elements,warnings:['Resource references remain numeric IDs; Android framework defaults and resource overlays are not applied.']};
}
function resources(bytes){
 const r=reader(bytes,32*MiB),top=chunk(r,0,bytes.length);if(top.type!==2||top.header<12||top.end!==bytes.length)throw Error('Not an Android resource table.');
 let at=top.header,strings=[],packages=[],entries=[],warnings=[],chunks=0,totalValues=0,valueText=0;
 const accountValue=v=>{if(++totalValues>100000||(valueText+=v.length)>4*MiB)throw Error('Resource value output budget exceeded.');return v;};
 while(at<top.end){const c=chunk(r,at,top.end);if(++chunks>10000)throw Error('Resource chunk budget exceeded.');
  if(c.type===1)strings=pool(r,c);
  else if(c.type===0x200){
   if(c.header<284)throw Error('Invalid resource package.');const id=r.u32(at+8);let name='';for(let p=at+12;p<at+268;p+=2){const u=r.u16(p);if(!u)break;name+=String.fromCharCode(u);}
   const typeOffset=r.u32(at+268),keyOffset=r.u32(at+276),typeIdOffset=c.header>=288?r.u32(at+284):0;
   const types=pool(r,chunk(r,at+typeOffset,c.end)),keys=pool(r,chunk(r,at+keyOffset,c.end));packages.push({id,name});
   let p=at+c.header;
   while(p<c.end){const t=chunk(r,p,c.end);if(++chunks>10000)throw Error('Resource chunk budget exceeded.');
    if(t.type===0x201){
     if(t.header<24)throw Error('Invalid resource type.');const tid=r.u8(p+8),flags=r.u8(p+9),count=r.u32(p+12),start=r.u32(p+16),configSize=r.u32(p+20);
     if(!tid||tid>types.length||flags&~3||count>65536||configSize<4||20+configSize>t.header||start<t.header||start>t.size)throw Error('Resource type bounds exceeded.');
     const sparse=flags&1,short=flags&2,width=short&&!sparse?2:4;r.span(p+t.header,count*width,p+start);
     const config=Array.from(bytes.subarray(p+20,p+20+configSize),b=>b.toString(16).padStart(2,'0')).join('');
     for(let i=0;i<count;i++){
      const table=p+t.header+i*width,idx=sparse?r.u16(table):i,off=sparse?r.u16(table+2)*4:short?(r.u16(table)===65535?0xffffffff:r.u16(table)*4):r.u32(table);if(off===0xffffffff)continue;
      const e=p+start+off;r.span(e,8,t.end);const size=r.u16(e),eflags=r.u16(e+2),ki=r.u32(e+4);
      if(eflags&8){warnings.push('Compact resource entries are not decoded.');continue;}if(size<8||ki>=keys.length||e+size>t.end)throw Error('Invalid resource entry.');
      const rid=(((id&255)<<24)|(((tid+typeIdOffset)&255)<<16)|idx)>>>0,item={id:'0x'+rid.toString(16).padStart(8,'0'),package:name,type:types[tid-1],name:keys[ki],config,offset:e};
      if(eflags&1){if(size<16)throw Error('Invalid resource bag.');const n=r.u32(e+12);if(n>4096)throw Error('Resource bag budget exceeded.');r.span(e+size,n*12,t.end);item.parent='0x'+r.u32(e+8).toString(16);item.values=[];for(let j=0;j<n;j++){const v=e+size+j*12;item.values.push({id:'0x'+r.u32(v).toString(16),value:accountValue(value(r,v+4,strings))});}}
      else{r.span(e+size,8,t.end);item.value=accountValue(value(r,e+size,strings));}
      entries.push(item);if(entries.length>LIMITS.resourceEntries)throw Error('Resource entry budget exceeded.');
     }
    }
    p=t.end;
   }
  }else warnings.push('Unexpanded resource chunk 0x'+c.type.toString(16)+'.');
  at=c.end;
 }
 if(packages.length!==r.u32(8))warnings.push('Declared resource package count does not match decoded packages.');return {packages,entries,warnings:[...new Set(warnings)],note:'Resource variants retain raw configuration bytes. Values are evidence, not a rebuilt resources directory.'};
}
root.SpectraAndroid={LIMITS,kind,dex,xml,resources,adler};if(typeof module!=='undefined')module.exports=root.SpectraAndroid;
})(globalThis);
