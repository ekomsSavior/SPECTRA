// Stream fixed release archives from static chunks without buffering the archive.
export async function archiveResponse(request,env,manifest,headers){
 const h=new Headers(headers);h.set('Content-Type','application/zip');h.set('Content-Disposition','attachment; filename="'+manifest.name+'"');h.set('Content-Length',String(manifest.bytes));h.set('ETag','"'+manifest.sha256+'"');h.set('Cache-Control','public, max-age=0, must-revalidate');
 if(request.method==='HEAD')return new Response(null,{headers:h});
 let index=0,reader=null,received=0,expected=0,cancelled=false;
 const body=new ReadableStream({
  async pull(controller){
   try{
    while(!cancelled){
     if(!reader){if(index===manifest.parts.length){controller.close();return;}const p=manifest.parts[index++];const u=new URL(p.path,request.url);const r=await env.ASSETS.fetch(new Request(u.href,{method:'GET'}));if(cancelled){await r.body?.cancel();return;}if(!r.ok||!r.body)throw Error('Archive part unavailable');expected=p.bytes;received=0;reader=r.body.getReader();}
     const {done,value}=await reader.read();if(cancelled)return;
     if(done){reader.releaseLock();reader=null;if(received!==expected)throw Error('Archive part truncated');continue;}
     received+=value.byteLength;if(received>expected)throw Error('Archive part too large');controller.enqueue(value);return;
    }
   }catch(e){await reader?.cancel().catch(()=>{});reader=null;if(!cancelled)controller.error(e);}
  },
  async cancel(){cancelled=true;await reader?.cancel();reader=null;}
 });
 return new Response(body,{headers:h});
}
