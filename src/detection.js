(function(root){
'use strict';
const MAX_REPORT=2*1024*1024,MAX_ROWS=2000;
function normalize(raw){
 if(typeof raw!=='string'||raw.length>MAX_REPORT)throw Error('Detection report exceeds 2 MiB.');
 const data=JSON.parse(raw);if(!data||!Array.isArray(data.detects))throw Error('DiE returned an unrecognized report.');
 const rows=[],queue=data.detects.map(block=>({block,depth:0}));let visited=0;
 const text=(s,max=4096)=>typeof s==='string'?s.slice(0,max):'';
 while(queue.length){const {block,depth}=queue.shift();if(++visited>4000||depth>16)throw Error('Detection report nesting limit exceeded.');if(!block||typeof block!=='object'||Array.isArray(block))throw Error('Invalid detection block.');
  if(block.values!==undefined&&!Array.isArray(block.values))throw Error('Invalid detection values.');
  for(const v of block.values||[]){if(!v||typeof v!=='object'||typeof v.type!=='string'||typeof v.name!=='string')throw Error('Invalid detection result.');if(rows.length>=MAX_ROWS)throw Error('Detection report exceeds 2,000 findings.');
   const heuristic=v.type.startsWith('~')||/^\s*\(Heur\)/i.test(v.string||'');
   rows.push({type:text(v.type.replace(/^~/,''),100),name:text(v.name),version:text(v.version),info:text(v.info),display:text(v.string),heuristic,format:text(block.filetype,100),offset:text(block.offset,50),size:text(block.size,50),part:text(block.parentfilepart,100)});
  }
  for(const key of ['detects','children'])if(Array.isArray(block[key]))for(const child of block[key])queue.push({block:child,depth:depth+1});
 }
 return {rows,data};
}
function explanation(type){
 if(/packer|protector|obfuscat|cryptor|protection/i.test(type))return 'This matches a known protection or packing clue. Check the details and entry point. A match does not mean malware, and a missing match does not mean unpacked.';
 if(/language|compiler|linker|toolchain/i.test(type))return 'A build fingerprint. Runtimes, metadata and code patterns can point at a toolchain. Mixed-language builds and copied markers can muddy the picture.';
 if(/library|framework/i.test(type))return 'A runtime or library fingerprint. It tells you what may be involved, not which code paths the program actually uses.';
 if(/debug/i.test(type))return 'Build leftovers can give you names and source paths. They may be stale or misleading; follow them back to the file.';
 return 'DiE found this from static file evidence. Read the exact result, then check it against sections, strings and code. This is identification, not a malware verdict.';
}
root.SpectraDetection={MAX_REPORT,MAX_ROWS,normalize,explanation};if(typeof module!=='undefined')module.exports=root.SpectraDetection;
})(globalThis);
