// Import inside the error boundary: a static main.mjs import hides startup
// failures behind the browser's generic worker error event.
export async function startManagedWorker(scope, loadEngine = () => import('./main.mjs')) {
 let ready = false, failed = false;
 const message = error => String(error?.message || error || 'Unknown runtime error').slice(0, 3000);
 const fail = error => {
  if (failed) return;
  failed = true;
  scope.postMessage({engineError: message(error), phase: ready ? 'analysis' : 'startup'});
 };
 scope.addEventListener('unhandledrejection', event => {
  event.preventDefault();
  fail(event.reason);
 });
 try {
  const {decompile} = await loadEngine();
  if (failed) return;
  if (typeof decompile !== 'function') throw Error('ILSpy entry point is unavailable.');
  scope.onmessage = ({data: m}) => {
   if (failed) return;
   try {
    if (typeof m?.base64 !== 'string' || m.base64.length > 22369624) throw Error('Managed input cap: 16 MiB.');
    const token = m.token ?? 0;
    if (!Number.isInteger(token) || ![0, -1].includes(token) && ![2, 6].includes(token >>> 24)) throw Error('Select an assembly, type, or method.');
    const result = decompile(m.base64, token, m.dependencies || []);
    if (result.code.length > 2000000 || result.types.length > 10000 || result.types.reduce((n, t) => n + t.methods.length, 0) > 50000) throw Error('Output limit exceeded. Select a smaller assembly/type.');
    scope.postMessage({id: m.id, result});
   } catch (error) {
    scope.postMessage({id: m?.id, error: message(error)});
   }
  };
  ready = true;
  scope.postMessage({ready: true});
 } catch (error) {
  fail(error);
 }
}

if (typeof self !== 'undefined' && typeof self.postMessage === 'function') startManagedWorker(self);
