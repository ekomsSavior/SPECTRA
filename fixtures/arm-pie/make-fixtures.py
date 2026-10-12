#!/usr/bin/env python3
"""Build small, benign ARM/Thumb self-relocating ELF32 PIE fixtures.
Pass a LLVM bin directory containing clang and llvm-objcopy. No fixture is executed.
"""
from pathlib import Path
import struct,subprocess,sys,tempfile
root=Path(__file__).resolve().parent;llvm=Path(sys.argv[1])
for mode,name in [('arm','start'),('thumb','thumb-start')]:
 with tempfile.TemporaryDirectory() as tmp:
  obj=Path(tmp)/'code.o';raw=Path(tmp)/'code.bin'
  subprocess.run([str(llvm/'clang'),'--target=armv7-none-eabi','-c',str(root/(name+'.S')),'-o',str(obj)],check=True)
  subprocess.run([str(llvm/'llvm-objcopy'),'-O','binary','--only-section=.text',str(obj),str(raw)],check=True)
  code=raw.read_bytes()
 b=bytearray(0x1400);b[:7]=b'\x7fELF\x01\x01\x01'
 struct.pack_into('<HHIIIIIHHHHHH',b,16,3,40,1,0x100+(mode=='thumb'),52,0,0x05000200,52,32,3,40,0,0)
 for i,ph in enumerate([(1,0,0,0,0x400,0x400,5,0x1000),(1,0x1000,0x1000,0x1000,0x400,0x600,6,0x1000),(2,0x1100,0x1100,0x1100,48,48,6,4)]):struct.pack_into('<8I',b,52+32*i,*ph)
 b[0x100:0x100+len(code)]=code
 struct.pack_into('<II',b,0x200,0x1000,23)
 struct.pack_into('<I',b,0x1000,0x1020);b[0x1020:0x1024]=b'pie\n'
 for i,(tag,value) in enumerate([(17,0x200),(18,8),(19,8),(0x6ffffffa,1),(0x6ffffffb,0x08000000),(0,0)]):struct.pack_into('<II',b,0x1100+i*8,tag,value)
 (root/(mode+'-static-pie.elf')).write_bytes(b)
 print(mode,len(b),'bytes')
