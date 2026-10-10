#!/usr/bin/env python3
from pathlib import Path
import argparse,http.server
p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=4173);a=p.parse_args()
root=Path(__file__).resolve().parents[1]/'dist'
class Handler(http.server.SimpleHTTPRequestHandler):
 def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(root),**kwargs)
 def end_headers(self):
  self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src data:; worker-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
  self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Cache-Control','no-store');super().end_headers()
Handler.extensions_map.update({'.mjs':'text/javascript','.wasm':'application/wasm'})
print(f'SPECTRA local: http://127.0.0.1:{a.port}/',flush=True)
http.server.ThreadingHTTPServer(('127.0.0.1',a.port),Handler).serve_forever()
