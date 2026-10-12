/* Local Capstone analysis. No sample instructions are executed. */
(function(root){
'use strict';
const Depth=root.SpectraAnalysis||(typeof require==='function'?require('./analysis.js'):null);
const Knowledge=root.SpectraKnowledge||(typeof require==='function'?require('./knowledge.js'):null);
const DEFAULT_INSTRUCTIONS=60000,DEFAULT_BYTES=4*1024*1024,MAX_INSTRUCTIONS=1000000,MAX_BYTES=16*1024*1024;
function budget(input={}){const instructions=input.instructions??DEFAULT_INSTRUCTIONS,decodedBytes=input.decodedBytes??DEFAULT_BYTES;if(!Number.isSafeInteger(instructions)||instructions<1||instructions>MAX_INSTRUCTIONS||!Number.isSafeInteger(decodedBytes)||decodedBytes<16||decodedBytes>MAX_BYTES)throw Error('Analysis budget must be 1–1,000,000 instructions and 16 bytes–16 MiB.');return {instructions,decodedBytes};}
function modeFor(cs,r,override){
 const name=override||({'x86':'x86','x86-64':'x64','ARM':r.entryThumb?'thumb':'arm','ARM Thumb':'thumb','ARM64':'arm64','MIPS':r.bits===64?'mips64':'mips32','RISC-V':r.bits===64?'riscv64':'riscv32'})[r.architecture];
 const map={x86:[cs.ARCH_X86,cs.MODE_32,1],x64:[cs.ARCH_X86,cs.MODE_64,1],arm:[cs.ARCH_ARM,cs.MODE_ARM,4],thumb:[cs.ARCH_ARM,cs.MODE_THUMB,2],arm64:[cs.ARCH_ARM64,0,4],mips32:[cs.ARCH_MIPS,cs.MODE_MIPS32,4],mips64:[cs.ARCH_MIPS,cs.MODE_MIPS64,4],riscv32:[cs.ARCH_RISCV,cs.MODE_RISCV32|cs.MODE_RISCVC,2],riscv64:[cs.ARCH_RISCV,cs.MODE_RISCV64|cs.MODE_RISCVC,2]};
 if(!map[name])throw Error('No automatic decoder for this architecture yet. Choose a raw range and architecture below.');
 if(name.startsWith('riscv')&&r.endian==='big')throw Error('This RISC-V decoder supports little-endian instructions.');
 const [arch,mode,alignment]=map[name];return {name,arch,mode:mode|((r.endian==='big'&&!['x86','x64','arm64'].includes(name))?cs.MODE_BIG_ENDIAN:0),alignment};
}
function riscvFlow(i){
 const m=i.mnemonic,o=i.op_str||i.operands||'',b=i.bytes||[],word=b.length===4?(b[0]|b[1]<<8|b[2]<<16|b[3]<<24)>>>0:0,rd=(word>>>7)&31,rs=(word>>>15)&31;
 const ret=m==='ret'||m==='c.jr'&&o==='ra'||b.length===4&&(word&127)===0x67&&rd===0&&rs===1&&(word>>>20)===0;
 const call=!ret&&(m==='c.jal'||m==='c.jalr'||b.length===4&&[0x6f,0x67].includes(word&127)&&[1,5].includes(rd));
 const jump=!ret&&!call&&(/^(?:b|c\.b|j$|jr$|jalr$|c\.j$|c\.jr$)/.test(m)||b.length===4&&[0x6f,0x67].includes(word&127));
 const direct=!/jr|jalr/.test(m)&&!ret&&(call||jump),last=o.split(',').pop().trim();
 const target=direct&&/^-?(?:0x[\da-f]+|\d+)$/i.test(last)?Number(i.address)+(last.startsWith('-')?-Number(last.slice(1)):Number(last)):null;
 return {call,jump,ret,stop:ret||m==='ecall'||m.endsWith('ebreak'),conditional:jump&&/^(?:b|c\.b)/.test(m),target};
}
function createSession(cs,bytes,meta,options={}){
 let r=meta;const manual=options.manual;
 if(manual){const {offset,size,address}=manual;if(![offset,size,address].every(Number.isSafeInteger)||offset<0||size<1||offset>bytes.length-size||address<0||!Number.isSafeInteger(address+size))throw Error('Raw range needs valid file bytes and an exact base address.');r={...meta,architecture:'Raw',endian:manual.endian||'little',mappings:[{offset,size,address,permissions:'R-X',name:'raw range'}],seeds:[{address,name:'range_start',source:'user-selected range'}],symbols:[],imports:[]};}
 const mode=modeFor(cs,r,manual?.architecture),d=new cs.Capstone(mode.arch,mode.mode);d.option(cs.OPT_DETAIL,cs.OPT_ON);
 // The wrapper's cs_detail offsets do not match this build. Read the stable
 // cs_insn fields only; query groups through Capstone's native API.
 cs.Instruction=function(p){this.address=cs.getValue(p+8,'i64');this.size=cs.getValue(p+16,'i16');this.bytes=[];for(let i=0;i<this.size;i++)this.bytes.push(cs.getValue(p+18+i,'i8')&255);this.mnemonic=cs.UTF8ToString(p+42);this.op_str=cs.UTF8ToString(p+74);};
 const mappings=r.mappings||[],codeMaps=mappings.filter(s=>s.permissions.includes('X')),toOffset=va=>root.SpectraBinary.toOffset(r,va),inCode=va=>codeMaps.find(s=>va>=s.address&&va-s.address<s.size);
 if(!codeMaps.length){d.close();throw Error('No file-backed executable range found. Use a raw range if you know where the code starts.');}
 const instructions=new Map(),queue=[],queued=new Set(),seeds=new Map(),baseWarnings=[],directReferences=[];let decodedBytes=0,failed=0,overlap=0,paused=false,pauseCause=null,closed=false,dropped=0,qi=0,limits=budget(),roundLimited=false;
 const enqueue=va=>{if(Number.isSafeInteger(va)&&inCode(va)&&!queued.has(va)){if(queue.length>=MAX_INSTRUCTIONS*3){dropped++;return;}queued.add(va);queue.push(va);}};
 const seedRank=s=>({'code-address candidate':0,'executable range start':0,'direct call':1,'static indirect-call candidate':1,'analyst indirect target':1,'entry point':2,'PE unwind table':3,'user-selected range':6})[s.source]??5;
 const addSeed=(s)=>{if(!inCode(s.address))return;if(!seeds.has(s.address)){seeds.set(s.address,{...s,size:s.size||0});enqueue(s.address);}else if(seedRank(s)>seedRank(seeds.get(s.address)))seeds.set(s.address,{...s,size:s.size||0});};
 for(const s of r.seeds||[])addSeed(s);
 if(!seeds.size){for(const s of codeMaps)addSeed({address:s.address,name:'range_'+s.address.toString(16),source:'executable range start'});baseWarnings.push('No entry point or function symbols mapped to code. Range starts are only candidates.');}
 const isX86=['x86','x64'].includes(mode.name),isMips=mode.name.startsWith('mips');
 function decodeAt(address){
  if(instructions.has(address))return instructions.get(address);
  const map=inCode(address);if(!map)return null;const offset=toOffset(address);if(offset===null)return null;
  if(instructions.size>=limits.instructions||decodedBytes>=limits.decodedBytes){paused=true;pauseCause=instructions.size>=limits.instructions?"instructions":"decodedBytes";return null;}
  // Reject a second instruction starting inside a previously decoded one.
  for(let back=1;back<=(isX86?14:3);back++){const prior=instructions.get(address-back);if(prior&&prior.address+prior.size>address){overlap++;return null;}}
  const remaining=Math.min(isX86?15:4,map.size-(address-map.address),bytes.length-offset);let row=null;
  try{d.disasm_iter(bytes.subarray(offset,offset+remaining),address,(i,p)=>{const call=d.insn_group(p,cs.GRP_CALL),jump=d.insn_group(p,cs.GRP_JUMP),ret=d.insn_group(p,cs.GRP_RET)||/^ret|^iret/.test(i.mnemonic)||(mode.name==='thumb'||mode.name==='arm')&&((i.mnemonic==='bx'&&i.op_str==='lr')||(i.mnemonic==='pop'&&/\bpc\b/.test(i.op_str)))||isMips&&i.mnemonic==='jr'&&/\bra\b/.test(i.op_str);
    const stop=ret||['hlt','ud2','int3','brk','udf'].includes(i.mnemonic);const unconditional=jump&&(/^(?:jmp|ljmp|b|b\.w|br|bx|j|jr)$/.test(i.mnemonic));
    let target=null;if(call||jump){const operand=i.op_str.split(',').pop().trim();if(/^#?(?:0x[\da-f]+|\d+)$/i.test(operand))target=Number(operand.replace(/^#/,''));}
    row={address:Number(i.address),offset,size:i.size,bytes:i.bytes,mnemonic:i.mnemonic,operands:i.op_str,call,jump,ret,stop,conditional:jump&&!unconditional,target,...(mode.name.startsWith('riscv')?riscvFlow(i):{}),successors:[],functionAddress:null};return false;});}catch(e){failed++;return null;}
  if(!row){failed++;return null;}
  for(let n=1;n<row.size;n++)if(instructions.has(address+n)){overlap++;return null;}
  if(decodedBytes+row.size>limits.decodedBytes){paused=true;pauseCause="decodedBytes";return null;}instructions.set(address,row);decodedBytes+=row.size;return row;
 }
 function advance(input={}){
 if(closed)throw Error('Analysis session is closed.');const nextLimits=budget(input);if(nextLimits.instructions<instructions.size||nextLimits.decodedBytes<decodedBytes)throw Error('Continuation budget cannot discard decoded work.');limits=nextLimits;paused=false;pauseCause=null;roundLimited=false;
 let deep={references:[],tables:[],warnings:[]};
 {
  for(let round=0;round<4;round++){
  for(;qi<queue.length;qi++){
   const i=decodeAt(queue[qi]);if(!i){if(paused)break;if(manual)enqueue(queue[qi]+mode.alignment);continue;}let next=i.address+i.size;
   if(isMips&&(i.call||i.jump||i.ret)){const delay=decodeAt(next);if(paused)break;if(delay){delay.delaySlot=true;i.delaySlotAddress=next;}next+=4;}
   if(isX86&&!i.call&&!i.jump){
    const rel=i.operands.match(/\[(?:rip|eip)\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\]/i);
    const absolute=i.operands.match(/(?:^|,\s*)(0x[0-9a-f]+)$/i);
    const candidate=rel&&i.mnemonic==='lea'?i.address+i.size+(rel[1]==='-'?-1:1)*Number(rel[2]||0):absolute?Number(absolute[1]):null;
    if(candidate!==null&&inCode(candidate))addSeed({address:candidate,name:'candidate_'+candidate.toString(16),source:'code-address candidate'});
   }
   if(i.target!==null){directReferences.push({from:i.address,to:i.target,offset:i.offset,kind:i.call?'call':'branch',evidence:'decoded direct target'});if(i.call)addSeed({address:i.target,name:'sub_'+i.target.toString(16),source:'direct call'});else if(i.jump)i.successors.push(i.target);}
   if(!i.stop&&(!i.jump||i.conditional||i.call))i.successors.push(next);
   if(manual&&next<manual.address+manual.size)enqueue(next); // Continue scanning without inventing a control-flow edge.
   for(const target of i.successors)enqueue(target);
  }
  if(!Depth)break;
  deep=Depth.infer([...instructions.values()].sort((a,b)=>a.address-b.address),bytes,{...r,seeds:[...seeds.values()]},mode.name,options.hints);
  // A partial frontier can still reveal new incoming edges. Report current
  // hypotheses, but expand them only after the direct frontier is exhausted.
  if(paused)break;
  const before=queue.length;
  for(const ref of deep.references){if(!ref.follow)continue;const i=instructions.get(ref.from);if(i.call)addSeed({address:ref.to,name:'sub_'+ref.to.toString(16),source:ref.analyst?'analyst indirect target':'static indirect-call candidate'});else if(i.jump&&!i.successors.includes(ref.to)){i.successors.push(ref.to);enqueue(ref.to);}}
  if(queue.length===before)break;
  if(round===3)roundLimited=true;
  }
 }
 const pending=queue.length-qi,truncated=!!(pending||dropped),canContinue=pending>0&&(!paused||limits[pauseCause]<(pauseCause==="instructions"?MAX_INSTRUCTIONS:MAX_BYTES));
 const warnings=[...baseWarnings,...deep.warnings],references=[...directReferences,...deep.references];
 const rows=[...instructions.values()].sort((a,b)=>a.address-b.address).map(i=>({...i,successors:[...i.successors],functionAddress:null})),byAddress=new Map(rows.map(i=>[i.address,i]));
 const importMap=new Map((r.imports||[]).filter(x=>Number.isSafeInteger(x.address)).map(x=>[x.address,x]));
 const deepImports=new Set(references.filter(r=>r.kind==='import').map(r=>r.from+'@'+r.to));
 const strings=[...(meta.strings||[])].sort((a,b)=>a.offset-b.offset),ends=[];for(let i=0;i<strings.length;i++)ends.push(Math.max(ends[i-1]||0,strings[i].offset+strings[i].byteLength));
 function stringAt(offset){let lo=0,hi=strings.length;while(lo<hi){const mid=(lo+hi)>>1;if(strings[mid].offset<=offset)lo=mid+1;else hi=mid;}for(let i=lo-1;i>=0&&ends[i]>offset;i--)if(offset<strings[i].offset+strings[i].byteLength)return strings[i];return null;}
 for(const i of rows){
  const candidates=[];
  if(isX86){const re=/\[(rip|eip)\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\]/gi;let m;while((m=re.exec(i.operands))){let address=i.address+i.size+(m[2]==='-'?-1:1)*Number(m[3]||0);if(m[1]==='eip')address=address>>>0;candidates.push({address,kind:i.mnemonic==='lea'?'address':'memory',evidence:'PC-relative operand'});}const absolute=/\[(0x[0-9a-f]+)\]/gi;while((m=absolute.exec(i.operands)))candidates.push({address:Number(m[1]),kind:'memory',evidence:'absolute memory operand'});}
  if(!i.call&&!i.jump){for(const m of i.operands.matchAll(/(?:^|,\s*)#?(0x[\da-f]+)(?=\s*(?:,|$))/gi))candidates.push({address:Number(m[1]),kind:'constant',evidence:'address-sized constant; usage unconfirmed'});}
  const seen=new Set();for(const c of candidates){if(seen.has(c.address))continue;seen.add(c.address);const offset=toOffset(c.address),imp=importMap.get(c.address);if(offset===null&&!imp)continue;const str=offset!==null?stringAt(offset):null;if(!deepImports.has(i.address+'@'+c.address))references.push({from:i.address,to:c.address,offset:i.offset,targetOffset:offset,kind:imp&&(i.call||i.jump)?'import':c.kind,evidence:c.evidence,importName:imp?.name,library:imp?.library,stringId:str?.id,stringOffset:str?.offset,stringPreview:str?.text.slice(0,160)});}
 }
 const functions=[...seeds.values()].filter(s=>instructions.has(s.address)).sort((a,b)=>a.address-b.address).map(s=>({...s}));let walkBudget=Math.min(8000000,Math.max(400000,rows.length*8));
 for(const f of functions){const pending=[f.address],visited=new Set();f.instructionAddresses=[];for(let k=0;k<pending.length&&walkBudget>0;k++,walkBudget--){const va=pending[k];if(visited.has(va)||va!==f.address&&seeds.has(va))continue;visited.add(va);if(f.size&&va>=f.address+f.size)continue;const i=byAddress.get(va);if(!i)continue;f.instructionAddresses.push(va);if(i.functionAddress===null)i.functionAddress=f.address;if(i.delaySlotAddress){const delay=byAddress.get(i.delaySlotAddress);if(delay){f.instructionAddresses.push(delay.address);delay.functionAddress=f.address;}}pending.push(...i.successors);}f.instructionAddresses.sort((a,b)=>a-b);f.instructionCount=f.instructionAddresses.length;f.end=f.instructionAddresses.reduce((end,va)=>Math.max(end,va+instructions.get(va).size),f.address);}
 if(walkBudget<=0)warnings.push('Function traversal limit reached; some memberships are incomplete.');
 if(pending)warnings.push(canContinue?'Analysis paused with '+pending.toLocaleString('en-US')+' queued code locations. Results are partial; Continue analysis keeps the decoded work.':'Analysis ceiling reached (1,000,000 instructions / 16 MiB decoded). Results are partial; inspect a focused raw range for remaining code.');if(roundLimited)warnings.push('Four indirect-expansion passes completed; remaining targets can be followed with Continue analysis.');if(dropped)warnings.push('Traversal queue limit reached; some candidate targets were not queued.');
 if(failed)warnings.push(failed+' code locations could not be decoded.');if(overlap)warnings.push(overlap+' overlapping instruction starts were left unresolved.');
 if(isMips)warnings.push('MIPS delay slots are shown; branch-likely annul semantics are not modeled.');
 if(mode.name==='arm64')warnings.push('AArch64 register-built targets are resolved only for supported constant/load sequences. Other indirect targets remain unresolved; decoding more instructions does not prove their destinations.');else if(['arm','thumb'].includes(mode.name))warnings.push('Register-built targets and mixed ARM/Thumb transitions remain unresolved.');else if(['mips32','mips64','riscv32','riscv64'].includes(mode.name))warnings.push('Register-built indirect targets remain unresolved.');
 const evidence=Knowledge?Knowledge.recognize(bytes,{...r,mode:mode.name},functions,rows,references,options.signatures||[]):[];
 const recognitionMap=new Map();for(const e of evidence){const list=recognitionMap.get(e.address)||[];list.push(e);recognitionMap.set(e.address,list);}for(const f of functions)f.recognition=recognitionMap.get(f.address)||[];if(evidence.length>=4096)warnings.push('Library evidence limited to 4096 findings.');
 const resolved=new Set(deep.references.filter(r=>!r.candidate&&r.kind!=='import').map(r=>r.from));
 const unresolved=rows.filter(i=>!i.ret&&(i.call||i.jump)&&i.target===null&&!resolved.has(i.address)).length;
 return {engine:'Capstone 5 / SPECTRA 0.14',mode:mode.name,manual:!!manual,raw:manual?{...manual}:null,instructions:rows,functions,references,tables:deep.tables,recognition:evidence,warnings,decodedBytes,unresolved,truncated,limits:{...limits},continuation:{canContinue,pending,ceiling:{instructions:MAX_INSTRUCTIONS,decodedBytes:MAX_BYTES}},coverage:{decodedBytes,executableBytes:codeMaps.reduce((n,m)=>n+m.size,0)},method:manual?'linear sweep of user-selected bytes':'recursive traversal from entry, symbols, unwind records, and direct calls'};
}
 return {advance,close(){if(!closed){closed=true;d.close();}}};
}
function analyze(cs,bytes,meta,options={}){const session=createSession(cs,bytes,meta,options);try{return session.advance(options.budget);}finally{session.close();}}
root.SpectraCode={analyze,createSession,budget,modeFor,riscvFlow,DEFAULT_INSTRUCTIONS,DEFAULT_BYTES,MAX_INSTRUCTIONS,MAX_BYTES};if(typeof module!=='undefined')module.exports=root.SpectraCode;
})(globalThis);
