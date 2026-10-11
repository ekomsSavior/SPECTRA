(function(root){
'use strict';
function decode(module,codec,bytes,max){if(![4,6].includes(codec)||bytes.length>1114112||!Number.isSafeInteger(max)||max<1||max>1048576)throw Error('Firmware codec bounds exceeded.');let a=0,b=0;try{a=module._malloc(Math.max(1,bytes.length));b=module._malloc(max);if(!a||!b)throw Error('Firmware codec memory exhausted.');module.HEAPU8.set(bytes,a);const size=module._spectra_decode(codec,a,bytes.length,b,max);if(size<0||size>max)throw Error('Compressed firmware block is corrupt, oversized, or uses an unsupported filter/check ('+size+').');return module.HEAPU8.slice(b,b+size);}finally{if(a)module._free(a);if(b)module._free(b);}}
root.SpectraFirmwareCodecs={decode};if(typeof module!=='undefined')module.exports=root.SpectraFirmwareCodecs;
})(globalThis);
