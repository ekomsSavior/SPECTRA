#!/usr/bin/env python3
"""Create a small, inert APK-shaped teaching archive. It is not installable/signed.
Java sources are compiled separately with javac + D8; see README.md.
Binary XML/resource layouts follow AOSP ResourceTypes.h."""
from pathlib import Path
import struct, zipfile
root = Path(__file__).resolve().parent
u16=lambda n:struct.pack('<H',n)
u32=lambda n:struct.pack('<I',n)
def chunk(kind,header,payload):return u16(kind)+u16(8+len(header))+u32(8+len(header)+len(payload))+header+payload
def pool(strings):
    data=b'';offsets=[]
    for s in strings:
        raw=s.encode();assert len(raw)<128 and len(s)<128
        offsets.append(len(data));data+=bytes([len(s),len(raw)])+raw+b'\0'
    data+=b'\0'*(-len(data)%4)
    return chunk(1,u32(len(strings))+u32(0)+u32(256)+u32(28+4*len(strings))+u32(0),b''.join(map(u32,offsets))+data)
strings=['android','http://schemas.android.com/apk/res/android','manifest','package','org.church.spectra.training','uses-permission','name','android.permission.INTERNET','application','label','debuggable','SPECTRA Android training']
idx={s:i for i,s in enumerate(strings)}
nodehead=u32(1)+u32(0xffffffff)
def node(kind,payload):return chunk(kind,nodehead,payload)
def attr(ns,name,typ,value):
    return u32(ns)+u32(idx[name])+u32(0xffffffff)+u16(8)+bytes([0,typ])+u32(value)
def start(name,attrs):
    return node(0x102,u32(0xffffffff)+u32(idx[name])+u16(20)+u16(20)+u16(len(attrs))+u16(0)*3+b''.join(attrs))
def end(name):return node(0x103,u32(0xffffffff)+u32(idx[name]))
ns=idx['http://schemas.android.com/apk/res/android']
xml=chunk(3,b'',pool(strings)+node(0x100,u32(0)+u32(ns))+
    start('manifest',[attr(0xffffffff,'package',3,idx['org.church.spectra.training'])])+
    start('uses-permission',[attr(ns,'name',3,idx['android.permission.INTERNET'])])+end('uses-permission')+
    start('application',[attr(ns,'label',1,0x7f010000),attr(ns,'debuggable',18,0)])+end('application')+
    end('manifest')+node(0x101,u32(0)+u32(ns)))
(root/'AndroidManifest.xml.bin').write_bytes(xml)
global_strings=pool(['SPECTRA Android training'])
types=pool(['string']);keys=pool(['app_name'])
config=u32(4)
typechunk=chunk(0x201,bytes([1,0])+u16(0)+u32(1)+u32(28)+config,u32(0)+u16(8)+u16(0)+u32(0)+u16(8)+bytes([0,3])+u32(0))
package_name='org.church.spectra.training'.encode('utf-16le').ljust(256,b'\0')
package_header=u32(0x7f)+package_name+u32(288)+u32(1)+u32(288+len(types))+u32(1)+u32(0)
arsc=chunk(2,u32(1),global_strings+chunk(0x200,package_header,types+keys+typechunk))
(root/'resources.arsc').write_bytes(arsc)
with zipfile.ZipFile(root/'AndroidTraining.apk','w',zipfile.ZIP_DEFLATED) as z:
    for name,data in [
        ('AndroidManifest.xml',xml),('resources.arsc',arsc),
        ('classes.dex',(root/'classes.dex').read_bytes()),
        ('classes2.dex',(root/'classes2.dex').read_bytes()),
        ('assets/README.txt',b'Benign SPECTRA fixture. Not signed or installable. Nothing contacts a network.'),
        ('lib/x86_64/libtraining.so',(root/'libtraining.so').read_bytes()),
    ]:
        info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,data)
print(root/'AndroidTraining.apk')
