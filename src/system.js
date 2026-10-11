/* Limits for the browser Linux lab, independent of the UI. */
(function(root){
'use strict';
const FILE=8*1024*1024,TOTAL=16*1024*1024,INODES=256,STATE=180*1024*1024;
function size(n,max=FILE){if(!Number.isSafeInteger(n)||n<0||n>max)throw Error('System lab transfer limit exceeded.');return n;}
function path(s){if(typeof s!=='string'||s.length>240||!s||s.startsWith('/')||s.split('/').some(p=>!p||p==='.'||p==='..')||/[\x00-\x1f\x7f]/.test(s))throw Error('Choose a regular file inside /mnt.');return s;}
function guardFS(fs){
 if(!fs||!Array.isArray(fs.inodes)||typeof fs.ChangeSize!=='function')throw Error('Unsupported virtual filesystem build.');
 const budget=(id,n)=>{size(n);let total=n;for(const [key,data]of Object.entries(fs.inodedata))if(Number(key)!==id)total+=data.byteLength;if(total>TOTAL)throw Error('System lab shared files exceeded 16 MiB. Reset the guest to continue.');};
 const resize=fs.ChangeSize.bind(fs);fs.ChangeSize=async(id,n)=>{budget(id,n);return resize(id,n);};
 const write=fs.Write.bind(fs);fs.Write=async(id,offset,count,b)=>{size(offset);size(count);size(offset+count);return write(id,offset,count,b);};
 const create=fs.CreateInode.bind(fs);fs.CreateInode=()=>{if(fs.inodes.length>=INODES)throw Error('System lab shared filesystem reached its 256-entry limit.');return create();};
 const set=fs.set_data.bind(fs);fs.set_data=async(id,data)=>{budget(id,data.byteLength);return set(id,data);};
 const lock=fs.Lock.bind(fs);fs.Lock=(id,...args)=>{if((fs.inodes[id]?.locks?.length||0)>=256)throw Error('System lab file lock limit reached.');return lock(id,...args);};
 fs.total_size=TOTAL;
 return fs;
}
function files(fs){const out=[],visited=new Set();function walk(id,p,depth){if(depth>16||visited.has(id))return;visited.add(id);const i=fs.inodes[id];if(!i)return;if((i.mode&0xf000)===0x8000){if(i.size<=FILE)out.push({path:p,bytes:i.size});return;}if((i.mode&0xf000)!==0x4000)return;for(const [name,child]of i.direntries){if(name==='.'||name==='..')continue;walk(child,p?p+'/'+name:name,depth+1);}}walk(0,'',0);return out.slice(0,INODES);}
function regular(fs,p){path(p);const parts=p.split('/');let id=0;for(let n=0;n<parts.length;n++){const parent=fs.inodes[id];if(!parent||(parent.mode&0xf000)!==0x4000)throw Error('Shared path is not a directory.');id=fs.Search(id,parts[n]);if(id<0)throw Error('Shared file no longer exists.');}const i=fs.inodes[id];if((i.mode&0xf000)!==0x8000)throw Error('Only regular files can leave the guest.');size(i.size);return id;}
root.SpectraSystem={FILE,TOTAL,INODES,STATE,size,path,guardFS,files,regular};if(typeof module!=='undefined')module.exports=root.SpectraSystem;
})(globalThis);
