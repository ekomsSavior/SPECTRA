SPECTRA · .NET Harness lab
Church of Malware — https://spectra.churchofmalware.org/

WHAT YOU GOT
A reflection-based C# driver, selection.json (sample identity, signatures and
label evidence), invocation.json (editable arguments), and editable LabHooks.cs.
The original binary, its dependencies, passwords and live session state are NOT
bundled. C# reconstructed by ILSpy is not recompiled into this driver. It calls
selected methods in your exact original assembly by metadata token.

START HERE
1. Unzip into a clean folder in your isolated analysis environment.
2. Install a .NET SDK matching SpectraHarness.csproj (no NuGet packages needed).
3. Keep the original client with its DLLs, .deps.json and native dependencies.
4. Read selection.json and edit invocation.json. Copy a method's token and
   exampleArguments. Defaults are placeholders, not inferred runtime values.
5. Run: dotnet run
   This prints the plan. It does not load the target or invoke a selected method.
6. When ready to execute in your lab:
   dotnet run -- --assembly "/absolute/path/client.dll" --execute
   .exe assemblies work too. A mismatched SHA-256 or module MVID is rejected.

EXECUTION IS REAL
The downloaded runner is not a sandbox. With --execute, assembly/module/type
initializers, constructors, LabHooks, setup calls and the selected method can run
with your OS permissions and access files/network. Use an isolated VM and lab
network for untrusted clients. The browser's isolation does not follow the ZIP.
No automatic process kill or resource sandbox is provided. A hanging method
requires terminating the process. No native sample is run by the SPECTRA page.

ARGUMENTS AND STATE
Supported default conversions: primitives, strings, enums (exact name or number),
byte[] (base64 or numeric array), nullable values and arrays of supported types.
Provide all parameters in order, including optional defaults. Large integer
placeholders are strings to avoid JavaScript precision loss; the runner accepts
these strings as numbers.
ref/out, pointers, spans/ref structs, open generics and complex DTO construction
need an adapter. Custom object deserialization is not automatic.

For an instance method, the default factory calls its public parameterless
constructor. To choose an overload, select the constructor in SPECTRA and put
its token in constructorToken, with constructorArguments. Otherwise edit
LabHooks.CreateInstance for DI/UI dependencies. setup is an ordered array of
{ "methodToken": 100663297, "arguments": [] } calls. Every setup token must be
in selection.json; instance setup methods must accept the same created instance.
A setup return value is discarded. Use LabHooks for multi-object flows, assigning
login results, existing sessions, app configuration or custom argument adapters.
Task/Task<T> and ValueTask/ValueTask<T> are awaited. async void is not awaitable;
custom awaitables, UI message loops and thread-affinity require your own host.
Results show bounded strings/byte previews or primitives; arbitrary object
getters/custom ToString are not called automatically.

HTTP PROXY / INTERCEPTION
Optional, after starting your lab proxy:
  dotnet run -- --assembly "/absolute/path/client.dll" --proxy "http://127.0.0.1:8080" --execute
This sets HttpClient.DefaultProxy and WebRequest.DefaultWebProxy before loading
the target. It affects clients that use those defaults. Custom handlers,
UseProxy=false, raw sockets, native networking, WCF stacks or certificate pinning
may ignore or reject it. The runner is NOT a universal interception layer.
TLS certificate validation remains enabled. If doing HTTPS inspection, configure
the isolated lab's trust store explicitly. No certificate bypass is installed.
Proxying does not change the destination server. Configure a lab/test endpoint
through method/constructor arguments or LabHooks if the client supports it.
SPECTRA does not infer or recreate the protocol, authentication flow or UI state.

COMPATIBILITY
The supplied runner targets modern .NET. Compare the target framework and CPU
requirements in selection.json with your lab's SDK, OS and process architecture.
A modern runtime does not automatically make a .NET Framework thick client,
WPF/WinForms/WCF app or mixed-mode/native DLL portable. Those may need a matching
Windows host, project settings, legacy framework runner and custom initialization.
Dependencies are resolved locally from the original client directory/.deps.json;
there is no automatic dependency download. Rebuilding the client changes token
identity: open the new file in SPECTRA and export a fresh harness.

LABELS ARE LEADS
Crypto/auth/network/serialization/filesystem labels carry their IL offsets and
references and declared scopes (which metadata can spoof). API evidence differs from weaker name/string hints. Async/iterator
state-machine evidence is attributed with its generated method token. Labels
are not proof of behavior, reachability, maliciousness, security or vulnerability.
Indirect/dynamic calls, obfuscation and scan budgets can hide relevant behavior.
No label does not mean no behavior. Reports record partial scan warnings.
