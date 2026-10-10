import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {decompile} from '../vendor/managed/main.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
vm.runInThisContext(fs.readFileSync(path.join(root,'src/harness.js'),'utf8'));
const H=globalThis.SpectraHarness,bytes=fs.readFileSync(path.join(root,'fixtures/ManagedTraining.dll'));
const metadata=decompile(bytes.toString('base64'),-1),types=H.enrich(metadata.types),client=types.find(t=>t.name==='LabClient');
const method=n=>client.methods.find(m=>m.name===n),label=(n,c)=>method(n).labels.find(l=>l.category===c);
let checks=0;function check(name,fn){fn();checks++;console.log('ok',checks,name);}
check('Metadata identity and signatures',()=>{assert.match(metadata.assembly.targetFramework,/\.NETCoreApp/);assert.match(metadata.assembly.mvid,/^[a-f0-9-]{36}$/);assert.equal(method('Greet').parameters[0].type,'string');assert.equal(method('Greet').isStatic,false);});
check('Crypto call has IL evidence',()=>{assert.equal(label('Fingerprint','crypto').evidence[0].basis,'IL call');assert.match(label('Fingerprint','crypto').evidence[0].value,/SHA256::HashData/);assert.equal(typeof label('Fingerprint','crypto').evidence[0].offset,'number');});
check('Auth and serializer API labels',()=>{assert.equal(label('Credentials','auth').evidence[0].basis,'IL call');assert.equal(label('Json','serialization').evidence[0].basis,'IL call');});
check('Async MoveNext is linked to the source method',()=>{assert.ok(method('FetchAsync').stateMachine);const evidence=label('FetchAsync','network').evidence.find(e=>e.stateMachine&&/GetStringAsync/.test(e.value));assert.ok(evidence);assert.notEqual(evidence.sourceToken,method('FetchAsync').token);});
check('Names and strings remain explicitly weak hints',()=>{assert.equal(label('MisleadingNameAuth','auth'),undefined);const endpoint=label('EndpointHint','network');assert.equal(endpoint.evidence[0].basis,'string hint');const sample=H.enrich([{name:'T',ns:'',fullName:'T',methods:[{name:'AuthenticateUser',token:1,evidence:[]}]}]);assert.equal(sample[0].methods[0].labels[0].evidence[0].basis,'name hint');});
check('Constructor, generic and ref/out readiness',()=>{assert.match(H.readiness(method('Generic')),/generic/);assert.match(H.readiness(method('RefArgument')),/ref/);assert.match(H.readiness(method('.ctor')),/Constructor/);});
check('Untrusted strings stay data',()=>{assert.ok(method('DangerousLookingText').evidence.some(e=>e.value.includes('</script>')));assert.equal(method('DangerousLookingText').labels.length,0);});
const templates={program:fs.readFileSync(path.join(root,'harness-source/Program.cs'),'utf8'),hooks:fs.readFileSync(path.join(root,'harness-source/LabHooks.cs'),'utf8'),readme:fs.readFileSync(path.join(root,'harness-source/README.txt'),'utf8')};
const input={types,assembly:metadata.assembly,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),sample:'ManagedTraining.dll',selected:client.methods.map(m=>m.token),primaryToken:method('Greet').token,analysisWarnings:metadata.analysisWarnings};
Object.assign(templates,Object.fromEntries([['net48Program','Program.cs'],['net48Hooks','LabHooks.cs'],['net48Readme','README.txt'],['net48Project','SpectraHarness.csproj'],['net48Lock','packages.lock.json']].map(([k,f])=>[k,fs.readFileSync(path.join(root,'harness-source/net48',f),'utf8')])));
check('Framework host and repeatable setup recipes export with explicit validation limits',()=>{const recipe={methodToken:method('Greet').token,arguments:['world'],constructorToken:null,constructorArguments:[],setup:[{methodToken:method('SetPrefix').token,arguments:['saved session']}]},out=H.projectFiles(input,templates,'net48','x86',recipe);assert.match(out['SpectraHarness.csproj'],/<PlatformTarget>x86<\/PlatformTarget>/);assert.match(out['README.txt'],/Windows execution has not been validated/);assert.equal(JSON.parse(out['invocation.json']).setup[0].arguments[0],'saved session');assert.ok(out['App.config']);assert.throws(()=>H.projectFiles(input,templates,'net10.0','x86',{...recipe,methodToken:999}),/selected/);});
let files;
check('Selected tokens, entry, hash and templates export',()=>{files=H.projectFiles(input,templates);const manifest=JSON.parse(files['selection.json']);assert.equal(manifest.methods.length,client.methods.length);assert.equal(JSON.parse(files['invocation.json']).methodToken,method('Greet').token);assert.equal(manifest.sha256,input.sha256);assert.ok(files['LabHooks.cs']);assert.ok(!Object.keys(files).some(p=>p.endsWith('.dll')));});
check('Invalid identity, missing selection, stale token, runtime and path rejected',()=>{assert.throws(()=>H.manifest({...input,sha256:''}));assert.throws(()=>H.manifest({...input,selected:[]}));assert.throws(()=>H.manifest({...input,selected:[0x0600ffff]}));assert.throws(()=>H.projectFiles(input,templates,'net7.0'));assert.throws(()=>H.zip({'../x':'x'}));});
check('ZIP CRC and directory are valid',()=>{assert.equal(H.crc32(new TextEncoder().encode('123456789')),0xcbf43926);const zip=H.zip(files),v=new DataView(zip.buffer);assert.equal(v.getUint32(0,true),0x04034b50);assert.equal(v.getUint32(zip.length-22,true),0x06054b50);assert.equal(v.getUint16(zip.length-14,true),Object.keys(files).length);});
// Exercise instruction boundaries and malformed switch operands using the benign fixture.
function bodyPosition(buffer,rva){const pe=buffer.readUInt32LE(0x3c),count=buffer.readUInt16LE(pe+6),start=pe+24+buffer.readUInt16LE(pe+20);for(let i=0;i<count;i++){const at=start+i*40,va=buffer.readUInt32LE(at+12),length=buffer.readUInt32LE(at+16);if(rva>=va&&rva<va+length){const header=buffer.readUInt32LE(at+20)+rva-va;return {header,il:header+((buffer[header]&3)===2?1:(buffer.readUInt16LE(header)>>>12)*4)};}}throw Error('Fixture method RVA not mapped');}
check('Opcode-looking operand bytes do not invent calls',()=>{const changed=Buffer.from(bytes),where=bodyPosition(changed,method('EndpointHint').rva);changed[where.il]=0x20;changed.writeInt32LE(0x00282828,where.il+1);const read=decompile(changed.toString('base64'),-1);assert.equal(read.types.find(t=>t.name==='LabClient').methods.find(m=>m.name==='EndpointHint').evidence.length,0);});
check('Malformed switch reports partial evidence',()=>{const changed=Buffer.from(bytes),where=bodyPosition(changed,method('EndpointHint').rva);changed[where.il]=0x45;changed.writeInt32LE(0x7fffffff,where.il+1);const read=decompile(changed.toString('base64'),-1);assert.match(read.types.find(t=>t.name==='LabClient').methods.find(m=>m.name==='EndpointHint').warnings.join(' '),/Malformed/);});
check('Local namespace impersonation remains a symbol hint',()=>{const fake=H.enrich([{name:'T',ns:'',fullName:'T',methods:[{name:'X',token:1,evidence:[{offset:0,kind:'call',opcode:'call',token:2,scope:'local module',value:'System.Security.Cryptography.Aes::Create'}]}]}]);assert.equal(fake[0].methods[0].labels[0].evidence[0].basis,'local symbol hint');});
const dotnet=process.env.SPECTRA_DOTNET;
if(!dotnet){console.log(`${checks} harness metadata/export checks passed. Set SPECTRA_DOTNET to run the generated project integration checks.`);process.exit(0);}
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'spectra-harness-'));
for(const [name,text]of Object.entries(files))fs.writeFileSync(path.join(dir,name),text);
fs.writeFileSync(path.join(dir,'project.zip'),H.zip(files));
function run(exe,args,opts={}){return new Promise((resolve,reject)=>{const p=spawn(exe,args,{cwd:dir,env:process.env,...opts});let output='';p.stdout.on('data',b=>output+=b);p.stderr.on('data',b=>output+=b);const timer=setTimeout(()=>{p.kill('SIGKILL');reject(Error('Test subprocess timeout.'));},45000);p.on('error',reject);p.on('close',code=>{clearTimeout(timer);resolve({code,output});});});}
async function expect(name,args,pattern,exit=0){const r=await run(dotnet,[path.join(dir,'bin/Release/net10.0/SpectraHarness.dll'),...args]);assert.equal(r.code,exit,r.output);assert.match(r.output,pattern);checks++;console.log('ok',checks,name);return r;}
function config(name,args=[],extra={}){fs.writeFileSync(path.join(dir,'invocation.json'),JSON.stringify({methodToken:method(name).token,arguments:args,constructorToken:null,constructorArguments:[],setup:[],...extra}));}
const net48dir=fs.mkdtempSync(path.join(os.tmpdir(),'spectra-net48-'));for(const [name,text]of Object.entries(H.projectFiles(input,templates,'net48','x86')))fs.writeFileSync(path.join(net48dir,name),text);const frameworkBuild=await run(dotnet,['build','SpectraHarness.csproj','-c','Release','--disable-build-servers','-m:1','--no-restore'],{cwd:net48dir});let framework=frameworkBuild;if(framework.code!==0)framework=await run(dotnet,['build','SpectraHarness.csproj','-c','Release','--disable-build-servers','-m:1','--ignore-failed-sources'],{cwd:net48dir});assert.equal(framework.code,0,framework.output);checks++;console.log('ok',checks,'Generated net48 x86 project compiles; Windows execution untested');
const build=await run(dotnet,['build','SpectraHarness.csproj','-c','Release','--disable-build-servers','-m:1']);assert.equal(build.code,0,build.output);checks++;console.log('ok',checks,'Generated project builds without NuGet packages');
const unzip=await run('python3',['-c','import zipfile; z=zipfile.ZipFile("project.zip"); assert z.testzip() is None; assert len(z.namelist()) == 7']);assert.equal(unzip.code,0,unzip.output);checks++;console.log('ok',checks,'Exported ZIP opens and validates with Python');
const source=path.join(root,'fixtures/ManagedTraining.dll'),execute=['--assembly',source,'--execute'];
const marker=path.join(dir,'marker.txt');config('MarkExecution',[marker]);
await expect('Dry run does not execute the client',['--assembly',source],/DRY RUN\. Target not loaded/);assert.equal(fs.existsSync(marker),false);
await expect('Explicit execution invokes the selected benign method',execute,/Result: ok/);assert.equal(fs.readFileSync(marker,'utf8'),'executed benign fixture');
config('Greet',['world']);await expect('Public parameterless instance constructor',execute,/Result: ready:world/);
const ctor=client.methods.find(m=>m.name==='.ctor'&&m.parameters.length===1);
config('Greet',['world'],{constructorToken:ctor.token,constructorArguments:['hello'],setup:[{methodToken:method('SetPrefix').token,arguments:['session']}]});await expect('Explicit constructor and setup preserve instance state',execute,/Result: session:world/);
config('DoubleAsync',[21]);await expect('Task<T> is awaited',execute,/Result: 42/);
config('IncrementAsync',[41]);await expect('ValueTask<T> is awaited once',execute,/Result: 42/);
config('EchoLong',['9223372036854775807']);await expect('64-bit integer strings preserve precision',execute,/Result: 9223372036854775807/);
config('Opaque');await expect('Opaque result does not run getters or ToString',execute,/No property getters or custom ToString were called/);
config('RefArgument',[1]);await expect('Unsupported ref argument stops',execute,/ref\/out/,1);
config('Generic',[1]);await expect('Open generic method stops',execute,/Open generics/,1);
config('Greet',['ok']);const manifest=JSON.parse(files['selection.json']);fs.writeFileSync(path.join(dir,'selection.json'),JSON.stringify({...manifest,sha256:'0'.repeat(64)}));await expect('Wrong sample hash fails before loading',execute,/SHA-256 mismatch/,1);
fs.writeFileSync(path.join(dir,'selection.json'),JSON.stringify({...manifest,assembly:{...manifest.assembly,mvid:'00000000-0000-0000-0000-000000000000'}}));await expect('Wrong module identity fails before loading',execute,/MVID mismatch/,1);
fs.writeFileSync(path.join(dir,'selection.json'),files['selection.json']);
let proxyRequest;const server=http.createServer((req,res)=>{proxyRequest=req.url;res.end('lab-proxy-ok');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try {config('FetchAsync',['http://spectra-test.invalid/only-local-proxy']);await expect('HTTP defaults send the client request through a local proxy',[...execute,'--proxy',`http://127.0.0.1:${server.address().port}`],/Result: lab-proxy-ok/);assert.equal(proxyRequest,'http://spectra-test.invalid/only-local-proxy');}finally{await new Promise(resolve=>server.close(resolve));}
console.log(`${checks} harness checks passed. Generated project test directory: ${dir}`);
