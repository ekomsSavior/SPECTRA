(function(root){
'use strict';
const CATEGORIES=['crypto','auth','network','serialization','filesystem'];
const API_RULES=[
 ['crypto',/^System\.Security\.Cryptography\./],['crypto',/^Org\.BouncyCastle\.Crypto\./],
 ['auth',/^System\.(?:Security\.(?:Authentication|Principal|Claims)|IdentityModel)\./],
 ['auth',/^Microsoft\.(?:Identity\.|AspNetCore\.Authentication\.|IdentityModel\.)/],
 ['auth',/^System\.Net\.(?:NetworkCredential|CredentialCache)::/],
 ['network',/^System\.Net\.(?:Http\.|Sockets\.|WebSockets\.|WebClient::|WebRequest::|HttpWebRequest::|HttpWebResponse::|Dns::)/],
 ['network',/^(?:RestSharp\.|Grpc\.|System\.ServiceModel\.)/],
 ['serialization',/^System\.(?:Text\.Json\.|Xml\.|Runtime\.Serialization\.)/],
 ['serialization',/^(?:Newtonsoft\.Json\.|ProtoBuf\.|MessagePack\.)/],
 ['filesystem',/^System\.IO\.(?:File|Directory|FileStream|FileInfo|DirectoryInfo|FileSystemWatcher)(?:::|\.)/]
];
const NAME_RULES=[['crypto',/(?:encrypt|decrypt|cipher|hmac|sha256|sha512|aes|rsa)/i],['auth',/(?:authenticat|authoriz|login|signin|logon|validatetoken|refreshtoken|oauth)/i],['network',/(?:http|socket|sendrequest|fetchasync|download|upload)/i],['serialization',/(?:serializ|deserializ|parsejson|parsexml)/i]];
function enrich(types){
 const byType=new Map(types.map(t=>[t.fullName||[t.ns,t.name].filter(Boolean).join('.'),t]));
 for(const t of types)for(const m of t.methods){
  const evidence=(m.evidence||[]).map(e=>({...e,sourceToken:m.token}));
  if(m.stateMachine){const name=m.stateMachine.split(',')[0];const sm=byType.get(name);for(const generated of sm?.methods||[])if(generated.name==='MoveNext')for(const e of generated.evidence||[])evidence.push({...e,sourceToken:generated.token,stateMachine:true});}
  const labels=new Map();
  function add(category,basis,e){let label=labels.get(category);if(!label){label={category,evidence:[]};labels.set(category,label);}if(label.evidence.length<16)label.evidence.push({basis,...e});}
  for(const e of evidence){
   if(e.kind!=='string'){for(const [cat,re]of API_RULES)if(re.test(e.value))add(cat,e.scope==='local module'?'local symbol hint':e.kind==='call'?'IL call':'IL reference',e);}
   else if(/\b(?:authorization|bearer|oauth|access_token|refresh_token)\b/i.test(e.value))add('auth','string hint',e);
   else if(/^https?:\/\//i.test(e.value))add('network','string hint',e);
  }
  for(const [cat,re]of NAME_RULES)if(re.test(m.name)&&!labels.has(cat))add(cat,'name hint',{value:m.name,sourceToken:m.token});
  m.labels=Array.from(labels.values());
 }
 for(const t of types)t.labels=CATEGORIES.filter(c=>t.methods.some(m=>m.labels.some(l=>l.category===c)));
 return types;
}
function example(type){
 if(type==='string')return '';if(type==='char')return 'x';if(type==='bool')return false;if(type.endsWith('[]'))return [];
 if(['long','ulong'].includes(type))return '0';if(['byte','sbyte','short','ushort','int','uint','float','double','System.Decimal'].includes(type))return 0;
 return null;
}
function readiness(m){
 if(m.name==='.ctor')return 'Constructor: use its token in constructorToken.';
 if(m.name==='.cctor')return 'Type initializer: not directly callable by this runner.';
 if(m.genericArity)return 'Open generic type/method: needs an adapter.';
 if(m.isAbstract||!m.rva)return 'No IL body: needs runtime/dependency support.';
 if(m.returnType==='void'&&m.stateMachine)return 'async void: needs an async-aware host.';
 if([m.returnType,...(m.parameters||[]).map(p=>p.type)].some(t=>/[&*]|^!|(?:System\.)?(?:ReadOnly)?Span`/.test(t)))return 'Pointer, ref/out, generic or ref-struct signature: needs an adapter.';
 return m.isStatic?'Static method. Supply arguments.':'Instance method. Supply constructor/session state.';
}
function manifest({types,assembly,sha256,sample,selected,analysisWarnings=[]}){
 if(!/^[a-f\d]{64}$/i.test(sha256||''))throw Error('Wait for the sample SHA-256 before exporting.');
 if(!assembly?.mvid)throw Error('Browse .NET types first.');
 const chosen=new Set(selected);if(!chosen.size||chosen.size>2000)throw Error('Select between 1 and 2,000 methods.');
 const methods=types.flatMap(t=>t.methods.filter(m=>chosen.has(m.token)).map(m=>({...m,type:t.fullName||[t.ns,t.name].filter(Boolean).join('.'),typeToken:t.token,exampleArguments:(m.parameters||[]).map(p=>example(p.type)),readiness:readiness(m)})));
 if(methods.length!==chosen.size)throw Error('Selection belongs to a different assembly. Select methods again.');
 return {schema:'spectra-harness/1',tool:'SPECTRA 0.14',sample,sha256,assembly,createdAt:new Date().toISOString(),analysisWarnings,methods,
  limitations:['Evidence-based labels are hypotheses, not proof of behavior.','The downloaded driver runs real code only after --execute; it is not a sandbox.','Modern .NET runner; legacy Framework/UI/native dependencies may require another host.','Proxy defaults are optional and are not universal interception.']};
}
function projectFiles(input,templates,target='net10.0',platform='AnyCPU',recipe=null){
 if(!['net8.0','net10.0','net48'].includes(target))throw Error('Choose .NET 8, .NET 10, or the experimental Framework 4.8 host.');if(!['AnyCPU','x86','x64'].includes(platform))throw Error('Choose AnyCPU, x86 or x64.');
 const data=manifest(input),first=data.methods.find(m=>m.token===input.primaryToken)||data.methods.find(m=>m.name[0]!=='.'&&!m.genericArity&&!m.isAbstract);
 if(!first||first.name.startsWith('.'))throw Error('Select an ordinary method for the runner; constructors can accompany it. Export selection + clues for a constructor-only catalog.');
 let config={methodToken:first.token,arguments:first.exampleArguments,constructorToken:null,constructorArguments:[],setup:[]};
 data.host={target,platform,validation:target==='net48'?'Compile-tested; Windows execution untested.':'Modern .NET runner; match the client OS and runtime.'};
 if(recipe){if(typeof recipe!=='object'||Array.isArray(recipe)||!data.methods.some(m=>m.token===recipe.methodToken)||!Array.isArray(recipe.arguments)||!Array.isArray(recipe.setup)||recipe.setup.length>32||recipe.setup.some(s=>!data.methods.some(m=>m.token===s.methodToken)||!Array.isArray(s.arguments)))throw Error('Recipe methods must be selected; provide arguments and at most 32 setup calls.');if(JSON.stringify(recipe).length>100000)throw Error('Recipe cap: 100,000 characters.');config=recipe;}
 const files={
  'SpectraHarness.csproj':`<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>${target}</TargetFramework>\n    <ImplicitUsings>enable</ImplicitUsings>\n    <Nullable>enable</Nullable>\n    <LangVersion>12.0</LangVersion>\n    <NuGetAudit>false</NuGetAudit>\n    <PlatformTarget>${platform}</PlatformTarget>\n    <Prefer32Bit>false</Prefer32Bit>\n  </PropertyGroup>\n</Project>\n`,
  'Program.cs':templates.program,'LabHooks.cs':templates.hooks,'README.txt':templates.readme,
  'selection.json':JSON.stringify(data,null,2)+'\n','invocation.json':JSON.stringify(config,null,2)+'\n',
  '.gitignore':'bin/\nobj/\n*.user\n# Keep original samples and lab secrets out of source control.\n'
 };
 if(target==='net48'){files['Program.cs']=templates.net48Program;files['LabHooks.cs']=templates.net48Hooks;files['README.txt']=templates.net48Readme;files['SpectraHarness.csproj']=templates.net48Project.replace('<PropertyGroup>','<PropertyGroup><PlatformTarget>'+platform+'</PlatformTarget><Prefer32Bit>false</Prefer32Bit>');files['packages.lock.json']=templates.net48Lock;files['App.config']='<?xml version="1.0" encoding="utf-8"?>\n<configuration><startup useLegacyV2RuntimeActivationPolicy="true"><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8"/></startup></configuration>\n';}
 if(Object.values(files).some(v=>typeof v!=='string'))throw Error('Harness templates missing.');
 return files;
}
// Small store-only ZIP writer. All names come from fixed project templates, never sample paths.
const crcTable=Uint32Array.from({length:256},(_,n)=>{for(let i=0;i<8;i++)n=(n&1)?0xedb88320^(n>>>1):n>>>1;return n>>>0;});
function crc32(bytes){let c=0xffffffff;for(const b of bytes)c=crcTable[(c^b)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
function zip(files){
 const enc=new TextEncoder(),entries=Object.entries(files),locals=[],central=[];let offset=0,total=0;
 if(entries.length>32)throw Error('Too many archive entries.');
 for(const [name,body]of entries){
  if(!/^[a-zA-Z0-9_.-]+$/.test(name)||name==='.'||name==='..')throw Error('Unsafe archive path.');
  const n=enc.encode(name),b=enc.encode(body);total+=b.length;if(total>16*1024*1024)throw Error('Harness archive exceeds 16 MiB; select fewer methods.');
  const crc=crc32(b),local=new Uint8Array(30+n.length),v=new DataView(local.buffer);
  v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);v.setUint16(6,0x800,true);v.setUint16(12,33,true);v.setUint32(14,crc,true);v.setUint32(18,b.length,true);v.setUint32(22,b.length,true);v.setUint16(26,n.length,true);local.set(n,30);
  const cd=new Uint8Array(46+n.length),d=new DataView(cd.buffer);d.setUint32(0,0x02014b50,true);d.setUint16(4,20,true);d.setUint16(6,20,true);d.setUint16(8,0x800,true);d.setUint16(14,33,true);d.setUint32(16,crc,true);d.setUint32(20,b.length,true);d.setUint32(24,b.length,true);d.setUint16(28,n.length,true);d.setUint32(42,offset,true);cd.set(n,46);
  locals.push(local,b);central.push(cd);offset+=local.length+b.length;
 }
 const size=central.reduce((s,b)=>s+b.length,0),end=new Uint8Array(22),e=new DataView(end.buffer);e.setUint32(0,0x06054b50,true);e.setUint16(8,entries.length,true);e.setUint16(10,entries.length,true);e.setUint32(12,size,true);e.setUint32(16,offset,true);
 const out=new Uint8Array(offset+size+end.length);let at=0;for(const b of [...locals,...central,end]){out.set(b,at);at+=b.length;}return out;
}
root.SpectraHarness={enrich,manifest,projectFiles,zip,crc32,readiness,CATEGORIES};
})(typeof globalThis!=='undefined'?globalThis:this);
