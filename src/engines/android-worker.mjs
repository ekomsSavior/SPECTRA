import {AndroidSession} from './session.mjs';
let session=null,busy=false;
onmessage=async({data:m})=>{
 if(busy){postMessage({id:m.id,error:'Android worker is busy.'});return;}
 busy=true;
 try{
  if(m.action==='open'){session=new AndroidSession();const inventory=await session.open(new Uint8Array(m.buffer),message=>postMessage({id:m.id,progress:message}));postMessage({id:m.id,inventory});}
  else if(!session)throw Error('Read the APK/DEX inventory first.');
  else if(m.action==='class'){postMessage({id:m.id,detail:session.detail(m.dex,m.index)});}
  else if(m.action==='decompile'){const result=await session.reconstruct(m.dex,m.index,message=>postMessage({id:m.id,progress:message}));postMessage({id:m.id,result});}
  else if(m.action==='methodBytes'){
   const d=session.detail(m.dex,m.index),method=d.methods[m.method];if(!method)throw Error('Method selection is invalid.');
   let text=method.name+method.descriptor+'\n'+d.file+' · SHA-256 '+d.sha256+'\n';
   if(!method.codeOffset)text+='No code item: this method may be abstract or native.';
   else{const bytes=session.dexes[m.dex].bytes,start=method.instructionOffset,end=Math.min(start+method.instructionBytes,start+256);text+='DEX instruction range 0x'+start.toString(16)+' + '+method.instructionBytes+' bytes · '+method.registers+' registers\n';for(let p=start;p<end;p+=16)text+='0x'+p.toString(16).padStart(8,'0')+'  '+Array.from(bytes.subarray(p,Math.min(p+16,end)),b=>b.toString(16).padStart(2,'0')).join(' ')+'\n';if(method.instructionBytes>256)text+='First 256 bytes shown. Open the DEX in Hex explorer for the rest.';}
   postMessage({id:m.id,methodBytes:text});
  }
  else if(m.action==='resource'){postMessage({id:m.id,resource:await session.resource(m.name)});}
  else if(m.action==='extract'){const bytes=(await session.extract(m.name)).slice();postMessage({id:m.id,member:{name:m.name,buffer:bytes.buffer}},[bytes.buffer]);}
  else throw Error('Unknown Android analysis action.');
 }catch(e){postMessage({id:m.id,error:String(e.message||e).slice(0,3000)});}
 finally{busy=false;}
};
postMessage({ready:true});
