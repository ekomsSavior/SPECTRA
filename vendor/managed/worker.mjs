import {decompile} from './main.mjs';
postMessage({ready:true});
onmessage=({data:m})=>{try{
 if(typeof m.base64!=='string'||m.base64.length>22369624)throw Error('Managed input cap: 16 MiB.');
 const token=m.token??0;if(!Number.isInteger(token)||![0,-1].includes(token)&&![2,6].includes(token>>>24))throw Error('Select an assembly, type, or method.');
 const result=decompile(m.base64,token);if(result.code.length>2000000||result.types.length>10000||result.types.reduce((n,t)=>n+t.methods.length,0)>50000)throw Error('Output limit exceeded. Select a smaller assembly/type.');
 postMessage({id:m.id,result});
 }catch(e){postMessage({id:m.id,error:String(e.message||e).slice(0,3000)});}};
