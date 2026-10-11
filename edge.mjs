// SPECTRA's server only gates delivery of static files. It never accepts samples.
import {ENGINE_PATHS} from './asset-paths.mjs';
import {ARCHIVES} from './archive-manifests.mjs';
import {archiveResponse} from './downloads.mjs';
const HOST = 'spectra.churchofmalware.org';
const PATHS = new Set(['/', '/index.html', '/guide.html', '/guide', '/debugger-source.zip', '/THIRD-PARTY-LICENSES.txt', '/download-archives.json', '/detection-source.zip']);
const HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src data:; worker-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()',
  'Strict-Transport-Security': 'max-age=2592000',
  'X-Frame-Options': 'DENY',
  'X-Spectra-Edge': '0.12',
};
function reply(request, text, status, extra={}) {
  return new Response(request.method === 'HEAD' ? null : text, {status, headers:{...HEADERS, 'Content-Type':'text/plain; charset=utf-8', 'Cache-Control':'no-store', ...extra}});
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname !== HOST) return reply(request, 'Use https://' + HOST + '/', 403);
    // Cloudflare overwrites this header at its edge; never key on client X-Forwarded-For.
    const ip = request.headers.get('CF-Connecting-IP');
    if (!ip || ip.length > 64) return reply(request, 'Client address unavailable.', 403);
    try {
      const key = HOST + ':' + ip;
      const engine=ENGINE_PATHS.has(url.pathname)&&['GET','HEAD'].includes(request.method),burst=engine?env.SPECTRA_ENGINE_BURST:env.SPECTRA_BURST,minute=engine?env.SPECTRA_ENGINE_MINUTE:env.SPECTRA_MINUTE;
      if (!(await burst.limit({key})).success) return reply(request, 'Slow down a little. Try again in 10 seconds.', 429, {'Retry-After':'10'});
      if (['/debugger-source.zip','/detection-source.zip'].includes(url.pathname)&&!(await env.SPECTRA_DOWNLOAD_MINUTE.limit({key})).success)return reply(request,'Archive download limit reached. Try again in a minute.',429,{'Retry-After':'60'});
      if (!(await minute.limit({key})).success) return reply(request, 'Request limit reached. Try again in a minute.', 429, {'Retry-After':'60'});
    } catch {
      return reply(request, 'Delivery protection is temporarily unavailable. Try again shortly.', 503, {'Retry-After':'60'});
    }
    if (!['GET','HEAD'].includes(request.method)) return reply(request, 'SPECTRA accepts no uploads. Open the page and inspect your file locally.', 405, {Allow:'GET, HEAD'});
    if (request.url.length > 2048) return reply(request, 'Address too long.', 414);
    if (!PATHS.has(url.pathname)&&!ENGINE_PATHS.has(url.pathname)) return reply(request, 'Not found.', 404);
    if(Object.hasOwn(ARCHIVES,url.pathname))return archiveResponse(request,env,ARCHIVES[url.pathname],HEADERS);
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    for (const [name,value] of Object.entries(HEADERS)) headers.set(name,value);
    headers.set('Cache-Control',ENGINE_PATHS.has(url.pathname)?'public, max-age=31536000, immutable':'public, max-age=0, must-revalidate');
    return new Response(response.body, {status:response.status,statusText:response.statusText,headers});
  }
};
