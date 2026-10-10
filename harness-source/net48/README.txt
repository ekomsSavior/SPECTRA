SPECTRA / Church of Malware — Windows Framework 4.8 harness

Experimental Windows host. Compile-tested on Linux with Microsoft's Framework
reference assemblies. Windows execution has not been validated in this release.
Run on an isolated Windows analysis machine with .NET Framework 4.8 installed.
The runner executes real selected client code after --execute; it is not a sandbox.

Build: dotnet build -c Release
Preview: bin\Release\net48\SpectraHarness.exe
Execute explicitly: bin\Release\net48\SpectraHarness.exe --assembly C:\lab\Client.dll --execute

Keep the generated support DLLs beside SpectraHarness.exe. Keep the original
client and its dependencies together. Match PlatformTarget to the client/native
DLL architecture. One client per process. The Framework binder can resolve from
the GAC and application directory; the AssemblyResolve fallback checks identity.

selection.json binds the original SHA-256, MVID and selected method tokens.
invocation.json is a reusable recipe: constructorToken/constructorArguments,
ordered setup calls, methodToken, and arguments. You can add initialization in
LabHooks.cs. Copy this folder and change the recipe to compare experiments.

The original client's EXE.config is not applied automatically. Edit App.config
for your harness and review generated binding redirects. UI message pumps, STA
thread affinity, COM, native DLL search paths and application startup sequences
may require a custom host. This template does not invent that environment.

Optional --proxy http://127.0.0.1:8080 sets WebRequest.DefaultWebProxy only.
It preserves TLS validation. Custom handlers, sockets and other stacks may not
use this proxy. Never put credentials in public recipes or source repositories.
