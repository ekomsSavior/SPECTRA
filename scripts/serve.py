#!/usr/bin/env python3
from pathlib import Path
import argparse,http.server,json,shutil
from urllib.parse import urlsplit
p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=4173);a=p.parse_args()
root=Path(__file__).resolve().parents[1]/'dist'
class Handler(http.server.SimpleHTTPRequestHandler):
 def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(root),**kwargs)
 def archive(self,head=False):
  route=urlsplit(self.path).path
  if route not in ['/debugger-source.zip','/detection-source.zip']:return False
  try:
   m=json.loads((root/'download-archives.json').read_text())[route]
   parts=[]
   for part in m['parts']:
    file=(root/part['path'].lstrip('/')).resolve()
    if not file.is_relative_to(root.resolve()) or file.stat().st_size!=part['bytes']:raise ValueError()
    parts.append(file)
  except (OSError,ValueError,KeyError):self.send_error(404,'Source archive is not included in this build.');return True
  self.send_response(200);self.send_header('Content-Type','application/zip');self.send_header('Content-Length',str(m['bytes']));self.send_header('Content-Disposition','attachment; filename="'+m['name']+'"');self.end_headers()
  if not head:
   try:
    for file in parts:
     with file.open('rb') as stream:shutil.copyfileobj(stream,self.wfile,1024*1024)
   except (BrokenPipeError,ConnectionResetError):pass
  return True
 def do_GET(self):
  if not self.archive():super().do_GET()
 def do_HEAD(self):
  if not self.archive(True):super().do_HEAD()
 def end_headers(self):
  self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src data:; worker-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
  self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Cache-Control','no-store');super().end_headers()
Handler.extensions_map.update({'.mjs':'text/javascript','.wasm':'application/wasm'})
print(f'SPECTRA local: http://127.0.0.1:{a.port}/',flush=True)
http.server.ThreadingHTTPServer(('127.0.0.1',a.port),Handler).serve_forever()
