import { dotnet } from './_framework/dotnet.js';
const runtime = await dotnet.withDiagnosticTracing(false).create();
const exports = await runtime.getAssemblyExports(runtime.getConfig().mainAssemblyName);
export function decompile(base64, token = 0, dependencies = []) { return JSON.parse(exports.Program.Decompile(base64, token, JSON.stringify(dependencies))); }
