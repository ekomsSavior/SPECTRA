/* SPECTRA static analysis core. All offsets are file offsets, never virtual addresses. */
(function (root) {
  'use strict';
  const LIMIT = 120000, MAX_TEXT = 4096;
  const printable = n => n >= 32 && n <= 126;
  function entropy(bytes) {
    if (!bytes.length) return 0;
    const counts = new Uint32Array(256);
    for (const b of bytes) counts[b]++;
    let e = 0;
    for (const n of counts) if (n) { const p = n / bytes.length; e -= p * Math.log2(p); }
    return e;
  }
  function tagsFor(text) {
    const tags = [];
    if (/\b(?:https?|ftp):\/\/[^\s<>"']+/i.test(text)) tags.push('url');
    if (/(?:^|[^\w.])(?:\d{1,3}\.){3}\d{1,3}(?:$|[^\w.])/.test(text)) {
      const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
      if (ips.some(ip => ip.split('.').every(v => +v <= 255))) tags.push('ip');
    }
    if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b/i.test(text)) tags.push('email');
    if (/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|info|biz|xyz|top|ru|cn|uk|de|edu|gov|onion|example|test)\b/i.test(text)) tags.push('domain');
    if (/(?:[A-Z]:\\|\\\\[\w.-]+\\|\/(?:tmp|etc|usr|home|var)\/|%(?:APPDATA|TEMP|USERPROFILE|PROGRAMDATA)%)/i.test(text)) tags.push('path');
    if (/\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\|Software\\(?:Microsoft|Classes)/i.test(text)) tags.push('registry');
    if (/\b(?:powershell(?:\.exe)?|cmd\.exe|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|schtasks(?:\.exe)?|wscript(?:\.exe)?|curl|wget|bash)\b/i.test(text)) tags.push('command');
    if (/\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(?:Ex)?|OpenProcess|GetProcAddress|LoadLibrary[AW]?|WinHttp\w+|InternetOpen\w*|URLDownloadToFile[AW]?|RegSetValueEx[AW]?|CryptEncrypt|IsDebuggerPresent|NtQueryInformationProcess)\b/.test(text)) tags.push('api');
    if (text.length >= 20 && text.length <= MAX_TEXT && text.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(text) && /[a-z]/.test(text) && /[A-Z]/.test(text)) tags.push('base64');
    return tags;
  }
  function extract(bytes, minLength = 4, cap = LIMIT) {
    const strings = []; let truncated = false;
    function add(start, end, encoding, chars, count) {
      if (count < minLength) return;
      if (strings.length >= cap) { truncated = true; return; }
      const text = chars.slice(0, MAX_TEXT).join('');
      strings.push({offset:start, byteLength:end-start, length:count, encoding, text, clipped:count > MAX_TEXT, tags:tagsFor(text)});
    }
    for (let i = 0; i < bytes.length && !truncated;) {
      if (!printable(bytes[i])) { i++; continue; }
      const start = i, chars = []; let count = 0;
      while (i < bytes.length && printable(bytes[i])) { if (count < MAX_TEXT) chars.push(String.fromCharCode(bytes[i])); count++; i++; }
      add(start, i, 'ASCII', chars, count);
    }
    for (const encoding of ['UTF-16LE', 'UTF-16BE']) {
      const shift = encoding === 'UTF-16LE' ? 0 : 1;
      for (let i = 0; i + 1 < bytes.length && !truncated;) {
        if (!printable(bytes[i + shift]) || bytes[i + 1 - shift] !== 0) { i++; continue; }
        const start = i, chars = []; let count = 0;
        while (i + 1 < bytes.length && printable(bytes[i + shift]) && bytes[i + 1 - shift] === 0) { if (count < MAX_TEXT) chars.push(String.fromCharCode(bytes[i + shift])); count++; i += 2; }
        add(start, i, encoding, chars, count);
      }
    }
    strings.sort((a,b) => a.offset-b.offset || a.encoding.localeCompare(b.encoding));
    strings.forEach((s,id) => s.id=id);
    return {strings, truncated};
  }
  function inspect(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), size = bytes.length;
    const result = {format:'Raw binary', architecture:'Unknown', bits:null, sections:[], imports:[], entry:null, imageBase:null, warnings:[]};
    const fits = (o,n=1) => Number.isSafeInteger(o) && o >= 0 && n >= 0 && o+n <= size;
    const u16 = o => { if (!fits(o,2)) throw Error('Truncated 16-bit field'); return view.getUint16(o,true); };
    const u32 = o => { if (!fits(o,4)) throw Error('Truncated 32-bit field'); return view.getUint32(o,true); };
    const str = (o,n=256) => { if(!fits(o)) return ''; let s=''; for(let i=o;i<Math.min(size,o+n)&&bytes[i];i++) s+=String.fromCharCode(bytes[i]); return s; };
    const bounded64 = o => { if(!fits(o,8)) throw Error('Truncated 64-bit field'); const v=view.getBigUint64(o,true); if(v>BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Address exceeds safe integer range'); return Number(v); };
    try {
      if (size>=2 && bytes[0]===0x4d && bytes[1]===0x5a) {
        result.format='DOS / MZ'; const pe=u32(0x3c);
        if(!fits(pe,24)||u32(pe)!==0x4550) { result.warnings.push('MZ header found without a valid PE signature.'); return result; }
        result.format='PE'; const machine=u16(pe+4), count=u16(pe+6), optSize=u16(pe+20), opt=pe+24, magic=u16(opt);
        result.architecture=({332:'x86',34404:'x86-64',43620:'ARM64',452:'ARM Thumb',448:'ARM'})[machine] || 'Machine 0x'+machine.toString(16);
        if(magic!==0x10b && magic!==0x20b) throw Error('Unsupported PE optional header');
        const wide=magic===0x20b; result.bits=wide?64:32; result.format=wide?'PE32+':'PE32';
        if(optSize<(wide?112:96)||!fits(opt,optSize)) throw Error('Truncated optional header');
        result.imageBase=wide?bounded64(opt+24):u32(opt+28); result.entry=result.imageBase+u32(opt+16);
        const headers=u32(opt+60), table=opt+optSize;
        if(count>96) result.warnings.push('Section count exceeds inspection limit (96).');
        for(let i=0;i<Math.min(count,96);i++) {
          const o=table+i*40; if(!fits(o,40)) { result.warnings.push('Section table is truncated.'); break; }
          const offset=u32(o+20), length=u32(o+16), flags=u32(o+36);
          const section={name:str(o,8),offset,size:length,virtualSize:u32(o+8),rva:u32(o+12),permissions:(flags&0x40000000?'R':'-')+(flags&0x80000000?'W':'-')+(flags&0x20000000?'X':'-'),entropy:entropy(bytes.subarray(offset,Math.min(size,offset+length)))};
          if(length&&!fits(offset,length)) result.warnings.push('Section '+section.name+' extends beyond the file.');
          result.sections.push(section);
        }
        const rvaToOffset=rva => {
          if(rva<headers && fits(rva)) return rva;
          for(const s of result.sections) if(rva>=s.rva && rva-s.rva<s.size && fits(s.offset+rva-s.rva)) return s.offset+rva-s.rva;
          return null;
        };
        const dd=opt+(wide?112:96), nd=u32(opt+(wide?108:92));
        if(nd>1 && dd+16<=opt+optSize) {
          const importRva=u32(dd+8), importSize=u32(dd+12), base=importRva?rvaToOffset(importRva):null;
          if(importRva && base===null) result.warnings.push('Import directory does not map to file bytes.');
          if(base!==null) for(let d=0;d<Math.min(512,Math.floor(importSize/20));d++) {
            const o=base+d*20; if(!fits(o,20)) break;
            const original=u32(o), nameRva=u32(o+12), first=u32(o+16); if(!original&&!nameRva&&!first) break;
            const nameOffset=rvaToOffset(nameRva), thunk=rvaToOffset(original||first), library=nameOffset!==null?str(nameOffset):'(unmapped)';
            if(thunk===null) continue;
            for(let j=0;j<8192 && result.imports.length<20000;j++) {
              const t=thunk+j*(wide?8:4); if(!fits(t,wide?8:4)) break;
              const raw=wide?view.getBigUint64(t,true):BigInt(u32(t)); if(raw===0n) break;
              const ordinal=(raw & (wide?0x8000000000000000n:0x80000000n))!==0n;
              const name=ordinal?'Ordinal '+Number(raw&65535n):null, target=ordinal?null:rvaToOffset(Number(raw));
              result.imports.push({library,name:name||(target!==null?str(target+2):'(unmapped name)'),offset:t,tags:tagsFor(name||(target!==null?str(target+2):''))});
            }
          }
        }
      } else if(size>=20 && bytes[0]===0x7f && str(1,3)==='ELF') {
        result.format='ELF'; result.bits=bytes[4]===2?64:32; const le=bytes[5]===1, machine=view.getUint16(18,le);
        result.architecture=({3:'x86',62:'x86-64',40:'ARM',183:'ARM64',243:'RISC-V'})[machine]||'Machine '+machine;
        result.warnings.push('This release identifies ELF headers; section and import parsing currently targets PE.');
      } else if(size>=4 && u32(0)===0x6d736100) { result.format='WebAssembly'; result.architecture='WASM'; }
      else if(size>=4 && [0xfeedface,0xfeedfacf,0xcefaedfe,0xcffaedfe,0xbebafeca].includes(u32(0))) { result.format='Mach-O'; result.architecture='See header'; }
      else if(size>=4 && u32(0)===0x04034b50) result.format='ZIP archive';
      else if(str(0,5)==='%PDF-') result.format='PDF';
      else if(size>=8 && bytes[0]===137 && str(1,3)==='PNG') result.format='PNG image';
    } catch(e) { result.warnings.push('Header inspection stopped: '+e.message+'. Strings and hex remain available.'); }
    return result;
  }
  function analyze(buffer) {
    const bytes=new Uint8Array(buffer), extracted=extract(bytes), blockSize=Math.max(1,Math.ceil(bytes.length/96)), blocks=[];
    for(let i=0;i<bytes.length;i+=blockSize) blocks.push({offset:i,size:Math.min(blockSize,bytes.length-i),entropy:entropy(bytes.subarray(i,i+blockSize))});
    const result={...extracted, ...inspect(bytes), entropy:entropy(bytes), blocks, size:bytes.length};
    return root.SpectraBinary?root.SpectraBinary.enrich(result,bytes):result;
  }
  function demo() {
    // Synthetic, non-runnable PE-shaped data. Reserved domains and documentation IPs only.
    const b=new Uint8Array(16384), v=new DataView(b.buffer), enc=new TextEncoder();
    const put=(o,s)=>b.set(enc.encode(s),o), w16=(o,n)=>v.setUint16(o,n,true), w32=(o,n)=>v.setUint32(o,n,true);
    put(0,'MZ'); w32(0x3c,0x80); put(0x80,'PE'); w16(0x84,0x8664); w16(0x86,3); w16(0x94,240); w16(0x96,0x22);
    const opt=0x98; w16(opt,0x20b); w32(opt+16,0x1000); v.setBigUint64(opt+24,0x140000000n,true); w32(opt+32,0x1000); w32(opt+36,0x200); w32(opt+60,0x400); w32(opt+108,16); w32(opt+120,0x2000); w32(opt+124,40);
    const sections=[['.text',0x1000,0x400,0x1000,0x60000020],['.rdata',0x2000,0x1400,0x1800,0x40000040],['.data',0x4000,0x2c00,0x1400,0xc0000040]];
    sections.forEach(([name,rva,o,n,f],i)=>{const h=opt+240+i*40;put(h,name);w32(h+8,n);w32(h+12,rva);w32(h+16,n);w32(h+20,o);w32(h+36,f);});
    w32(0x1400,0x2080); w32(0x140c,0x2050); w32(0x1410,0x2080); put(0x1450,'KERNEL32.dll');
    ['VirtualAlloc','WriteProcessMemory','CreateRemoteThread','GetProcAddress','IsDebuggerPresent'].forEach((s,i)=>{v.setBigUint64(0x1480+i*8,BigInt(0x2100+i*64),true);put(0x1502+i*64,s);});
    const lines=['SPECTRA / SYNTHETIC TRAINING FIXTURE / NOT AN EXECUTABLE','https://updates.northstar.example/api/v1/checkin','https://cdn.northstar.example/assets/config.dat','192.0.2.42','198.51.100.18:8443','C:\\Users\\analyst\\AppData\\Roaming\\northstar\\config.json','%APPDATA%\\Northstar\\cache.dat','HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','powershell.exe -NoProfile -File training-script.ps1','cmd.exe /c echo SPECTRA training fixture','analyst@northstar.example','User-Agent: NorthstarTraining/1.0','Content-Type: application/json','mutex_northstar_training_01','aHR0cHM6Ly9leGFtcGxlLmNvbS90cmFpbmluZw==','This fixture contains indicator-like text, not evidence of malware.','https://updates.northstar.example/api/v1/checkin','GetSystemTimeAsFileTime','Debug build: simulated beacon configuration'];
    let o=0x1800; for(const s of lines){put(o,s);o+=s.length+13;}
    o=0x2700; for(const s of ['C:\\ProgramData\\Northstar\\training.log','HKCU\\Software\\Northstar','https://wide.northstar.example/status']) { for(const c of s){w16(o,c.charCodeAt(0));o+=2;} o+=8; }
    let seed=0x1a2b3c4d;for(let i=0x3000;i<b.length;i++){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;b[i]=seed&255;}
    // Benign instruction fixture: address a string, call a local helper, branch, return.
    b.fill(0xcc,0x400,0x1400);
    b.set([0x55,0x48,0x89,0xe5,0x48,0x8d,0x0d,0x3a,0x14,0,0,0xe8,0x20,0,0,0,0x85,0xc0,0x74,0x07,0xb8,1,0,0,0,0x5d,0xc3,0x31,0xc0,0x5d,0xc3],0x400);
    b.set([72, 131, 236, 40, 199, 4, 36, 104, 116, 116, 112, 199, 68, 36, 4, 115, 58, 47, 47, 199, 68, 36, 8, 115, 116, 97, 99, 199, 68, 36, 12, 107, 46, 101, 120, 199, 68, 36, 16, 97, 109, 112, 108, 102, 199, 68, 36, 20, 101, 0, 255, 21, 24, 16, 0, 0, 72, 131, 196, 40, 195],0x430);
    b.set([50, 46, 46, 42, 41, 96, 117, 117, 50, 51, 62, 62, 63, 52, 116, 63, 34, 59, 55, 42, 54, 63, 117, 57, 50, 63, 57, 49, 51, 52, 90],0x2200);
    b.set([31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 203, 40, 41, 41, 40, 182, 210, 215, 79, 206, 207, 45, 40, 74, 45, 46, 78, 77, 209, 75, 173, 72, 204, 45, 200, 73, 5, 10, 229, 165, 101, 166, 51, 4, 7, 184, 58, 135, 4, 57, 198, 187, 71, 121, 6, 196, 187, 121, 70, 132, 132, 6, 185, 50, 0, 0, 140, 203, 67, 133, 55, 0, 0, 0],0x2300);
    return b;
  }
  function decode(text, mode, key='00') {
    let bytes;
    if(mode==='base64') { const s=text.replace(/\s/g,''); if(!/^[A-Za-z0-9+/]*={0,2}$/.test(s)||s.length%4===1) throw Error('Enter standard Base64 text.'); const raw=atob(s); bytes=Uint8Array.from(raw,c=>c.charCodeAt(0)); }
    else if(mode==='hex') { const s=text.replace(/0x/gi,'').replace(/[\s,:-]/g,''); if(s.length%2||/[^0-9a-f]/i.test(s)) throw Error('Enter complete hexadecimal byte pairs.'); bytes=Uint8Array.from(s.match(/../g)||[],v=>parseInt(v,16)); }
    else if(mode==='url') return decodeURIComponent(text);
    else if(mode==='xor') { const k=key.replace(/\s/g,''); if(!/^(?:[0-9a-f]{2})+$/i.test(k)) throw Error('XOR key must be hexadecimal byte pairs, for example 13 or CA FE.'); const keys=Uint8Array.from(k.match(/../g),v=>parseInt(v,16)); bytes=new TextEncoder().encode(text).map((b,i)=>b^keys[i%keys.length]); }
    else throw Error('Unknown decoder');
    return new TextDecoder().decode(bytes);
  }
  const api={analyze,extract,inspect,entropy,tagsFor,demo,decode,LIMIT}; root.SpectraCore=api;
  if(typeof module!=='undefined'&&module.exports) module.exports=api;
})(globalThis);
