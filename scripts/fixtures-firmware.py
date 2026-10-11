#!/usr/bin/env python3
"""Build harmless SquashFS fixtures with local squashfs-tools; never execute them."""
from pathlib import Path
import tempfile,subprocess,os,hashlib,json
root=Path(__file__).resolve().parents[1]
out=root/'tests/fixtures/firmware';out.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='spectra-firmware-') as tmp:
 base=Path(tmp)/'small';(base/'etc').mkdir(parents=True);(base/'usr/share').mkdir(parents=True)
 (base/'etc/issue').write_text('SPECTRA benign firmware fixture\n')
 (base/'usr/share/config.txt').write_text('lab_host=192.0.2.10\nport=8443\n')
 (base/'banner').symlink_to('etc/issue')
 large=Path(tmp)/'large';large.mkdir()
 for i in range(180):(large/(f'item-{i:03d}-'+'a'*100)).write_bytes(bytes([i])*50)
 data=bytes(range(256))*2048+b'last-fragment'
 (large/'large.bin').write_bytes(data);(large/'sparse.bin').write_bytes(bytes(17000)+b'end');os.link(large/'large.bin',large/'hardlink.bin')
 for directory,label in [(base,'rootfs'),(large,'large')]:
  for codec in ['gzip','xz','zstd']:
   subprocess.run(['mksquashfs',str(directory),str(out/(label+'-'+codec+'.sqfs')),'-noappend','-processors','1','-comp',codec,'-b','4096','-no-xattrs','-no-exports','-all-time','0','-mkfs-time','0'],check=True)
 (out/'large-manifest.json').write_text(json.dumps({'largeSha256':hashlib.sha256(data).hexdigest(),'largeBytes':len(data),'entries':183},indent=2)+'\n')
