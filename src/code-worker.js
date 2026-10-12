/* Retain the static traversal frontier between bounded, explicit UI requests. */
let codeSession=null;
onmessage=async({data})=>{
 try{
  if(data.action==='start'){
   codeSession?.close();codeSession=null;
   const cs=await MCapstone({wasmBinary:data.wasm});
   codeSession=SpectraCode.createSession(cs,new Uint8Array(data.buffer),data.meta,data.options);
  }else if(data.action!=='continue'||!codeSession)throw Error('No retained analysis. Run Analyze code again.');
  const result=codeSession.advance(data.budget);
  postMessage({result});
  if(!result.continuation.canContinue){codeSession.close();codeSession=null;}
 }catch(e){codeSession?.close();codeSession=null;postMessage({error:String(e.message||e)});}
};
