/* Bounded integer-routine emulation. No board, OS, MMIO, FP/SIMD, or device model. */
(function(root){
'use strict';
const D=root.SpectraDebug,{PAGE=4096,STACK,SCRATCH,AREA}=D,RETURN=0x50000000,hex=D.hex;
const profiles={
 arm:{module:'arm',prefix:'ARM',bits:32,cpu:'Cortex-A15 LE / ARM1176 BE32',names:[...Array.from({length:13},(_,i)=>'R'+i),'SP','LR','PC','CPSR'],sp:'SP',link:'LR'},
 thumb:{module:'arm',prefix:'ARM',bits:32,cpu:'Cortex-A15 LE / ARM1176 BE32',names:[...Array.from({length:13},(_,i)=>'R'+i),'SP','LR','PC','CPSR'],sp:'SP',link:'LR'},
 aarch64:{module:'aarch64',prefix:'ARM64',bits:64,cpu:'Cortex-A72',names:[...Array.from({length:29},(_,i)=>'X'+i),'FP','LR','SP','PC','NZCV'],sp:'SP',link:'LR'},
 riscv32:{module:'riscv',prefix:'RISCV',bits:32,cpu:'SiFive U34',names:['ZERO','RA','SP','GP','TP','T0','T1','T2','S0','S1',...Array.from({length:8},(_,i)=>'A'+i),...Array.from({length:10},(_,i)=>'S'+(i+2)),'T3','T4','T5','T6','PC'],sp:'SP',link:'RA'},
 riscv64:{module:'riscv',prefix:'RISCV',bits:64,cpu:'SiFive U54',names:[],sp:'SP',link:'RA'},
 mips32:{module:'mips',prefix:'MIPS',bits:32,cpu:'74KF',names:['ZERO','AT','V0','V1','A0','A1','A2','A3','T0','T1','T2','T3','T4','T5','T6','T7',...Array.from({length:8},(_,i)=>'S'+i),'T8','T9','K0','K1','GP','SP','FP','RA','HI','LO','PC'],sp:'SP',link:'RA'},
 mips64:{module:'mips',prefix:'MIPS',bits:64,cpu:'R4000',names:[],sp:'SP',link:'RA'}
};profiles.riscv64.names=profiles.riscv32.names;profiles.mips64.names=profiles.mips32.names;
const allow={
 ARM:'ADC ADD ADR AND ASR B BFC BFI BIC BL BLX BX CBZ CBNZ CLZ CMN CMP EOR IT LDM LDMDA LDMDB LDMIB LDR LDRB LDRBT LDRD LDRH LDRHT LDRSB LDRSBT LDRSH LDRSHT LDRT LSL LSR MLA MLS MOV MOVT MOVW MUL MVN NOP ORN ORR PKHBT PKHTB POP PUSH RBIT REV REV16 REVSH ROR RRX RSB RSC SBC SBFX SDIV SMLAL SMULL STM STMDA STMDB STMIB STR STRB STRBT STRD STRH STRHT STRT SUB SXTB SXTH TBB TBH TEQ TST UBFX UDIV UMLAL UMULL UXTB UXTH',
 ARM64:'ADC ADCS ADD ADDS ADR ADRP AND ANDS ASR B BFI BFXIL BIC BICS BL BLR BR CBNZ CBZ CCMP CCMN CINC CINV CLZ CLS CMN CMP CNEG CSEL CSET CSETM CSINC CSINV CSNEG EON EOR EXTR LDP LDPSW LDR LDRB LDRH LDRSB LDRSH LDRSW LDUR LDURB LDURH LDURSB LDURSH LDURSW LSL LSR MADD MNEG MOV MOVK MOVN MOVZ MSUB MUL MVN NEG NEGS NGC NGCS NOP ORN ORR RBIT RET REV REV16 REV32 ROR SBC SBCS SBFIZ SBFM SBFX SDIV SMADDL SMSUBL SMULL STP STR STRB STRH STUR STURB STURH SUB SUBS SXTB SXTH SXTW TBNZ TBZ TST UBFIZ UBFM UBFX UDIV UMADDL UMSUBL UMULL UXTB UXTH',
 MIPS:'ADD ADDI ADDIU ADDU AND ANDI B BAL BEQ BEQZ BGEZ BGEZAL BGTZ BLEZ BLTZ BLTZAL BNE BNEZ DADD DADDI DADDIU DADDU DDIV DDIVU DIV DIVU DMULT DMULTU DSLL DSLL32 DSLLV DSRA DSRA32 DSRAV DSRL DSRL32 DSRLV DSUB DSUBU J JAL JALR JR LB LBU LD LH LHU LI LUI LW LWU MFHI MFLO MOVE MOVN MOVZ MTHI MTLO MUL MULT MULTU NEGU NOP NOR NOT OR ORI SB SD SEB SEH SH SLL SLLV SLT SLTI SLTIU SLTU SRA SRAV SRL SRLV SUB SUBU SW XOR XORI',
 RISCV:'ADD ADDI ADDIW ADDW AND ANDI AUIPC BEQ BGE BGEU BLT BLTU BNE DIV DIVU DIVUW DIVW JAL JALR LB LBU LD LH LHU LUI LW LWU MUL MULH MULHSU MULHU MULW OR ORI REM REMU REMUW REMW SB SD SH SLL SLLI SLLIW SLLW SLT SLTI SLTIU SLTU SRA SRAI SRAIW SRAW SRL SRLI SRLIW SRLW SUB SUBW SW XOR XORI C_ADD C_ADDI C_ADDI16SP C_ADDI4SPN C_ADDIW C_ADDW C_AND C_ANDI C_BEQZ C_BNEZ C_J C_JAL C_JALR C_JR C_LD C_LDSP C_LI C_LUI C_LW C_LWSP C_MV C_NOP C_OR C_SD C_SDSP C_SLLI C_SRAI C_SRLI C_SUB C_SUBW C_SW C_SWSP C_XOR'
};
function prepare(bytes,meta,options){
 const p=profiles[options.mode];if(!p)throw Error('Choose a supported hardware CPU.');if(options.environment==='windows')throw Error('Windows modeling supports x86/x64. Hardware CPUs use bare routines.');
 if(options.environment==='linux')return {...root.SpectraLinux.prepare(bytes,meta,options),cpu:p.cpu};
 const endian=options.endian==='auto'||!options.endian?meta.endian||'little':options.endian;
 if(!['little','big'].includes(endian)||p.module==='riscv'&&endian==='big')throw Error('Unsupported instruction byte order. RISC-V is little endian.');
 root.SpectraNative.plan(bytes,meta,{mode:options.mode,endian,entry:options.start,acceptAbi:true,raw:options.raw?{offset:options.raw.offset,size:options.raw.size,address:options.raw.base}:null});
 const plan=D.prepare(bytes,meta,{...options,mode:p.bits===64?'x64':'x86'});
 if(plan.mapped.some(m=>m.address<RETURN+4096&&m.address+m.size>RETURN))throw Error('Mapping overlaps the synthetic return-boundary page.');
 if(plan.memoryBytes+4096>D.MAX_MEMORY)throw Error('Hardware session exceeds 16 MiB mapped-memory budget.');
 return {...plan,mode:options.mode,endian,memoryBytes:plan.memoryBytes+4096,returnBoundary:RETURN,cpu:p.cpu,scope:'Integer routines; optional analyst MMIO responses. No FP/SIMD, firmware boot, board or device simulation.'};
}
class Session{
 constructor(uc,cs,bytes,meta,options){
  this.uc=uc;this.cs=cs;this.plan=prepare(bytes,meta,options);this.mode=this.plan.mode;this.profile=profiles[this.mode];const p=this.profile;
  Object.assign(this,{steps:0,trace:[],edits:[],status:'ready',reason:this.plan.environment==='linux'?'Linux startup ready. No instructions have run.':'Hardware routine ready. Registers, stack, scratch, and a return boundary are analyst-supplied state.',breakAt:null,stopped:false,journal:[],attempts:0,frames:[],watchpoints:[],hits:[],executing:false,names:p.names,ip:'PC',sp:p.sp,word:p.bits/8});
  const modeName=({arm:'ARM',thumb:'THUMB',aarch64:'ARM',riscv32:'RISCV32',riscv64:'RISCV64',mips32:'MIPS32',mips64:'MIPS64'})[this.mode];
  this.e=new uc.Unicorn(uc['ARCH_'+p.prefix],uc['MODE_'+modeName]|(this.plan.endian==='big'?uc.MODE_BIG_ENDIAN:0));this.decoders=[];
  try{
   for(const m of this.plan.mapped){this.e.mem_map(m.address,m.size,m.perms);this.e.mem_write(m.address,new Uint8Array(m.size));}
   for(const r of this.plan.regions)this.e.mem_write(r.address,bytes.subarray(r.offset,r.offset+(r.fileSize??r.size)));
   if(this.plan.linux)root.SpectraLinux.relocate(this);
   this.e.mem_map(STACK,AREA,3);this.e.mem_map(SCRATCH,AREA,3);this.e.mem_write(STACK,new Uint8Array(AREA));this.e.mem_write(SCRATCH,new Uint8Array(AREA));this.e.mem_map(RETURN,4096,5);this.e.mem_write(RETURN,new Uint8Array(4096));
   for(const n of this.names)if(!['CPSR','NZCV'].includes(n))this.writeReg(n,0n);
   this.writeReg(this.sp,BigInt(STACK+AREA-0x100));this.writeReg(p.link,BigInt(RETURN));this.writeReg('PC',BigInt(this.plan.start));
   if(p.prefix==='ARM')this.writeReg('CPSR',(this.readReg('CPSR')&~32n)|(this.mode==='thumb'?32n:0n));
   this.allowed=new Set(allow[p.prefix].split(' ').map(n=>cs[p.prefix+'_INS_'+n]).filter(n=>n!==undefined));
   cs.Instruction=function(at){this.id=cs.getValue(at,'i32');this.address=cs.getValue(at+8,'i64');this.size=cs.getValue(at+16,'i16');this.bytes=[];for(let j=0;j<this.size;j++)this.bytes.push(cs.getValue(at+18+j,'i8')&255);this.mnemonic=cs.UTF8ToString(at+42);this.op_str=cs.UTF8ToString(at+74);};
   this.hook=this.e.hook_add(uc.HOOK_MEM_WRITE,(_e,_type,at,size)=>{at=Number(at);this.noteAccess('write',at,size,'cpu');if(!this.pending)return;this.writeEvents++;if(this.writeEvents>1024){this.writeLimit=true;this.e.emu_stop();return;}if(!this.region(at,size,2)){this.badWrite=true;this.e.emu_stop();}if(this.region(at,size,4)){this.execWrite=true;this.e.emu_stop();}if(this.pending.length<32){let before=[];try{before=Array.from(this.e.mem_read(at,Math.min(size,256)));}catch{}this.pending.push({address:at,size:Math.min(size,256),before});}});
   this.readHook=this.e.hook_add(uc.HOOK_MEM_READ_AFTER,(_e,_t,at,size)=>this.noteAccess('read',Number(at),size,'cpu'));
   this.interruptHook=this.e.hook_add(uc.HOOK_INTR,(_e,n)=>{this.exception=n;this.e.emu_stop();});
  }catch(e){this.close();throw e;}
 }
 bits(n){return ['CPSR','NZCV'].includes(n)?32:this.profile.bits;}
 readReg(n){const id=this.uc[this.profile.prefix+'_REG_'+n];return this.bits(n)===64?BigInt.asUintN(64,this.e.reg_read_i64(id)):BigInt(this.e.reg_read_i32(id)>>>0);}
 writeReg(n,v){const thumb=n==='PC'&&this.profile.prefix==='ARM'?this.readReg('CPSR'):null;const id=this.uc[this.profile.prefix+'_REG_'+n];if(this.bits(n)===64)this.e.reg_write_i64(id,BigInt.asIntN(64,v));else this.e.reg_write_i32(id,Number(BigInt.asIntN(32,v)));if(thumb!==null)this.e.reg_write_i32(this.uc.ARM_REG_CPSR,Number(thumb));}
 verificationRegisters(){return this.regs();}
 liveThumb(){return this.profile.prefix==='ARM'&&(this.readReg('CPSR')&32n)!==0n;}
 decoder(){const thumb=this.liveThumb(),key=thumb?'thumb':this.mode==='thumb'?'arm':this.mode;let d=this.decoders.find(d=>d.key===key);if(!d){const name=key==='aarch64'?'arm64':key,m=root.SpectraCode.modeFor(this.cs,{endian:this.plan.endian},name);d=new this.cs.Capstone(m.arch,m.mode);d.option(this.cs.OPT_DETAIL,this.cs.OPT_ON);d.key=key;this.decoders.push(d);}return d;}
 decode(at){const r=this.region(at,1,4);if(!r||at===RETURN)return null;const d=this.decoder();let row=null;d.disasm_iter(this.e.mem_read(at,Math.min(4,r.address+r.size-at)),at,(i,p)=>{const call=d.insn_group(p,this.cs.GRP_CALL)||['bl','blx','blr','jal','jalr','bal'].includes(i.mnemonic),jump=d.insn_group(p,this.cs.GRP_JUMP),ret=i.mnemonic==='ret'||i.mnemonic==='bx'&&i.op_str==='lr'||i.mnemonic==='jr'&&/\bra\b/.test(i.op_str)||i.mnemonic.startsWith('pop')&&/\bpc\b/.test(i.op_str);row={address:at,size:i.size,bytes:i.bytes,id:i.id,mnemonic:i.mnemonic,operands:i.op_str,privileged:d.insn_group(p,this.cs.GRP_PRIVILEGE),call,jump,ret,...(this.profile.module==='riscv'?root.SpectraCode.riscvFlow(i):{})};return false;});return row;}
 blocked(i){
  if(!i||i.privileged||!this.allowed.has(i.id))return true;
  const p=this.profile.prefix,b=i.bytes,m=i.mnemonic,o=i.operands;
  if(p==='RISCV'&&(b.length===4&&[0x73,0x0f].includes(b[0]&127)||b.length===2&&b[0]===2&&b[1]===0x90))return true;
  // Match an actual S suffix, not the final s in the LS condition (e.g. addls pc).
  if(p==='ARM'&&(/\^/.test(o)||/^(?:adc|add|and|asr|bic|eor|lsl|lsr|mla|mov|mul|mvn|orr|ror|rrx|rsb|rsc|sbc|sub)s(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?$/.test(m)&&/^pc\b/.test(o)))return true;
  if(p==='ARM64'&&/\b(?:[bhsdqv]\d+|fpcr|fpsr)\b/i.test(o))return true;
  return false;
 }
 operation(){const i=this.decode(this.pc());if(!i)return {i,cost:1};const pair=this.profile.module==='mips'&&(i.call||i.jump||i.ret||/^(?:b|j)/.test(i.mnemonic)),slot=pair?this.decode(i.address+4):null;return {i,slot,pair,cost:pair?2:1};}
 step(){
  if(this.stopped)return false;this.attempts++;const last=this.journal.at(-1);if(last?.kind==='steps')last.count++;else this.journal.push({kind:'steps',count:1});if(this.attempts>100000)return this.halt('limit','Session reached 100,000 attempted operations.');
  let op;try{if(this.pc()===RETURN)return this.halt('returned','Returned to the synthetic session boundary.');op=this.operation();}catch(e){return this.halt('fault',e.message);}const {i,slot,pair,cost}=op;
  if(!i)return this.halt('fault','No executable instruction at the current pointer.');
  if(this.blocked(i)||pair&&(!slot||this.blocked(slot)||slot.call||slot.jump||slot.ret))return this.halt('unsupported','Stopped before '+i.mnemonic+(pair?' and its delay slot':'')+'. This integer-routine profile does not model this operation or external environment.');
  if(this.steps+cost>100000)return this.halt('limit','Session instruction limit reached before the next complete operation.');
  const before=this.regs(),stack=hex(this.readReg(this.sp)),thumb=this.liveThumb();this.hits=[];this.hitsTruncated=false;this.pending=[];this.writeEvents=0;this.writeLimit=false;this.execWrite=false;this.badWrite=false;this.exception=null;this.executing=true;let fault='';
  try{const begin=i.address+(thumb?1:0),until=this.profile.module==='mips'||i.call||i.jump||i.ret?RETURN:i.address+i.size;this.e.emu_start(BigInt(begin),BigInt(until),0,1);}catch(e){fault=String(e.message||e).slice(0,600);}finally{this.executing=false;}
  const writes=this.pending.map(w=>{let after=[];try{after=Array.from(this.e.mem_read(w.address,w.size));}catch{}return {...w,after};});this.pending=null;this.steps+=cost;this.breakAt=null;
  const after=this.regs(),partial=!!fault||this.writeLimit||this.execWrite||this.badWrite||this.exception!==null;
  this.trace.push({...i,step:this.steps,delaySlot:slot,operationInstructions:cost,changes:Object.fromEntries(this.names.filter(n=>before[n]!==after[n]).map(n=>[n,{before:before[n],after:after[n]}])),writes,writesTruncated:this.writeEvents>32,partial});if(this.trace.length>200)this.trace.shift();
  if(partial)return this.halt(fault||this.badWrite?'fault':'unsupported',fault||this.exception!==null?'CPU exception or fault. State may be partial: '+(fault||this.exception):'Stopped during a protected/executable write or excessive memory operation. State may be partial.');
  const pc=this.pc();if(i.call)this.frames.push({returnAddress:i.address+i.size+(pair?4:0),stack,thumb});else if(this.frames.length&&pc===this.frames.at(-1).returnAddress&&this.readReg(this.sp)>=BigInt(this.frames.at(-1).stack))this.frames.pop();
  if(pc===RETURN)return this.halt('returned','Returned to the synthetic session boundary.');if(this.hits.length)return this.halt('watchpoint','Access completed'+(pair?' during an atomic MIPS branch/delay pair':'')+'.');
  this.status='stepped';this.reason='Stepped '+i.mnemonic+(pair?' and delay slot '+slot.mnemonic+' together.':'.');return true;
 }
 runTarget(kind){if(kind==='out'){if(!this.frames.length)throw Error('No observed caller. Step into a call first.');return {...this.frames.at(-1)};}const {i,pair}=this.operation();return i?.call?{returnAddress:i.address+i.size+(pair?4:0),stack:hex(this.readReg(this.sp)),thumb:this.liveThumb()}:null;}
 breakpoint(p){const at=D.address(typeof p==='object'?p.address:p),c=typeof p==='object'?p.condition:null;if(!c)return {address:at};if(!this.names.includes(c.register)||!['==','!=','<','<=','>','>='].includes(c.operator)||!(/^(?:0x[0-9a-f]+|\d+)$/i).test(c.value)||BigInt(c.value)>=(1n<<BigInt(this.bits(c.register))))throw Error('Invalid hardware register condition.');return {address:at,condition:c};}
 advance(count,points=[],skip=false,target=null){if(!Number.isInteger(count)||count<1||count>10000||!Array.isArray(points)||points.length>128)throw Error('Invalid run budget or breakpoints.');points=points.map(p=>this.breakpoint(p));let n=0;while(n<count&&!this.stopped){const pc=this.pc();if(target&&pc===target.returnAddress&&this.readReg(this.sp)>=BigInt(target.stack)){this.halt('target','Reached the observed return boundary.');break;}const {pair,cost}=this.operation();if(points.some(p=>(p.address===pc||pair&&p.address===pc+4)&&this.conditionMatches(p.condition))&&!(skip&&n===0)){this.breakAt=pc;this.halt('breakpoint',pair?'Breakpoint before the atomic MIPS branch/delay pair. Conditions use pre-pair registers.':'Breakpoint at '+hex(pc)+'.');break;}if(cost>count-n){this.status='budget';this.reason='Need at least two remaining instructions for an atomic MIPS branch/delay pair.';break;}const before=this.steps,ok=this.step();n+=Math.max(1,this.steps-before);if(!ok)break;}
  if(!this.stopped&&!['breakpoint','watchpoint'].includes(this.status)&&target&&this.pc()===target.returnAddress&&this.readReg(this.sp)>=BigInt(target.stack))this.halt('target','Reached the observed return boundary.');if(!this.stopped&&!['breakpoint','watchpoint','target'].includes(this.status)){this.status='budget';this.reason='Paused after '+n+' instructions. MIPS delay pairs are atomic.';}return n;}
 editRegister(n,value){if(!this.names.includes(n)||['ZERO','CPSR','NZCV'].includes(n))throw Error('Choose an editable general register. Zero and system/flag registers are read-only in this profile.');const raw=String(value);if(!/^(?:0x[0-9a-f]+|\d+)$/i.test(raw)||BigInt(raw)>=(1n<<BigInt(this.bits(n))))throw Error('Value does not fit the unsigned register.');const v=BigInt(raw);if(n==='PC'&&(!Number.isSafeInteger(Number(v))||!this.region(Number(v),1,4)||Number(v)===RETURN||Number(v)%(this.liveThumb()||this.profile.module==='riscv'?2:4)))throw Error('PC must be aligned inside mapped executable code.');if(this.edits.length>=200)throw Error('Edit log is full.');const before=hex(this.readReg(n));this.writeReg(n,v);this.edits.push({step:this.steps,register:n,before,after:hex(v)});this.journal.push({kind:'register',name:n,value:hex(v)});if(n==='PC'||n===this.sp)this.frames=[];this.stopped=false;this.breakAt=null;this.status='paused';this.reason='Analyst-supplied register value set.';}
 snapshot(memoryAddress){let pc;try{pc=this.pc();}catch{pc=null;}const assembly=[];let at=pc;for(let n=0;n<16&&at!==null;n++){try{const i=this.decode(at);if(!i)break;assembly.push(i);at+=i.size;}catch{break;}}let memory=null;try{const r=this.region(memoryAddress);if(r)memory={address:memoryAddress,bytes:Array.from(this.read(memoryAddress,Math.min(256,r.address+r.size-memoryAddress)))};}catch{}return {mode:this.mode,pc,attempts:this.attempts,frames:this.frames,watchpoints:this.watchpoints,hits:this.hits,hitsTruncated:this.hitsTruncated,registers:this.regs(),registerBits:Object.fromEntries(this.names.map(n=>[n,this.bits(n)])),readOnlyRegisters:['ZERO','CPSR','NZCV'],flags:this.profile.prefix==='ARM'?{Thumb:+this.liveThumb()}:{},steps:this.steps,status:this.status,reason:this.reason,stopped:this.stopped,assembly,trace:this.trace,edits:this.edits,memory,plan:this.plan,mappings:[...this.plan.mapped,{address:STACK,size:AREA,perms:3,name:'Stack'},{address:SCRATCH,size:AREA,perms:3,name:'Scratch'},{address:RETURN,size:4096,perms:5,name:'Synthetic return boundary'}]};}
 region(at,size=1,permission=0){if(at>=RETURN&&at+size<=RETURN+4096&&(5&permission)===permission)return {address:RETURN,size:4096,perms:5};return D.Session.prototype.region.call(this,at,size,permission);}
 close(){if(this.interruptHook){this.e.hook_del(this.interruptHook);this.interruptHook=null;}for(const d of this.decoders||[])d.close();this.decoders=[];D.Session.prototype.close.call(this);}
}
Object.setPrototypeOf(Session.prototype,D.Session.prototype);
root.SpectraHardware={profiles,prepare,Session,RETURN};if(typeof module!=='undefined')module.exports=root.SpectraHardware;
})(globalThis);
