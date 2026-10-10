using System.Globalization;
using System.Net;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using System.Security.Cryptography;
using System.Text.Json;

// The generated runner has no target reference. Nothing loads the target before --execute.
// This is a lab driver, NOT a sandbox. Inspect both this code and the target before execution.
return await Harness.Run(args);

static class Harness
{
    public static async Task<int> Run(string[] args)
    {
        try
        {
            string? assemblyPath = null, proxy = null; string configPath = "invocation.json"; bool execute = false;
            for (int i = 0; i < args.Length; i++)
            {
                string Value() => ++i < args.Length ? args[i] : throw new ArgumentException("Missing option value.");
                switch (args[i])
                {
                    case "--assembly": assemblyPath = Value(); break;
                    case "--config": configPath = Value(); break;
                    case "--proxy": proxy = Value(); break;
                    case "--execute": execute = true; break;
                    case "--help": Console.WriteLine("dotnet run -- [--config invocation.json] [--assembly /path/client.dll] [--proxy http://127.0.0.1:8080] [--execute]\nDefault: print the plan without loading the client. Execution runs real code with your OS permissions."); return 0;
                    default: throw new ArgumentException("Unknown option: " + args[i]);
                }
            }
            using var manifestDoc = ReadJson("selection.json"); var manifest = manifestDoc.RootElement;
            using var configDoc = ReadJson(configPath); var config = configDoc.RootElement;
            var allowed = manifest.GetProperty("methods").EnumerateArray().ToDictionary(m => m.GetProperty("token").GetInt32());
            int token = config.GetProperty("methodToken").GetInt32();
            if (!allowed.ContainsKey(token)) throw new ArgumentException("Choose a methodToken from selection.json.");
            Console.WriteLine("SPECTRA harness · " + manifest.GetProperty("sample").GetString());
            Console.WriteLine("Selected: " + allowed[token].GetProperty("type").GetString() + " :: " + allowed[token].GetProperty("signature").GetString());
            Console.WriteLine("Target framework: " + manifest.GetProperty("assembly").GetProperty("targetFramework").GetString());
            Console.WriteLine("Plan: " + config.GetRawText());
            if (!execute) { Console.WriteLine("DRY RUN. Target not loaded. Edit invocation.json, inspect LabHooks.cs, then supply --assembly and --execute in your isolated lab."); return 0; }
            if (assemblyPath is null) throw new ArgumentException("Supply --assembly /path/to/the/original.dll (or .exe).");
            assemblyPath = Path.GetFullPath(assemblyPath);
            using (var file = File.OpenRead(assemblyPath))
            {
                var expected = manifest.GetProperty("sha256").GetString();
                using var sha = SHA256.Create();
                var actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "");
                if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("SHA-256 mismatch. Re-export from this exact assembly in SPECTRA.");
                file.Position = 0; using var pe = new PEReader(file, PEStreamOptions.LeaveOpen);
                var metadata = pe.GetMetadataReader();
                if (metadata.GetGuid(metadata.GetModuleDefinition().Mvid).ToString() != manifest.GetProperty("assembly").GetProperty("mvid").GetString()) throw new InvalidOperationException("Module MVID mismatch.");
            }
            if (proxy is not null)
            {
                var uri = new Uri(proxy, UriKind.Absolute);
                if (uri.Scheme is not ("http" or "https") || uri.UserInfo.Length > 0 || uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0) throw new ArgumentException("Proxy must be an http(s) host:port URL without credentials, path, query or fragment.");
                var configured = new WebProxy(uri) { BypassProxyOnLocal = false };
                // .NET Framework: clients using WebRequest / default HttpClientHandler honor DefaultWebProxy.
                // Explicit handlers, proxy overrides and other HTTP stacks may ignore it.
#pragma warning disable SYSLIB0014
                WebRequest.DefaultWebProxy = configured;
#pragma warning restore SYSLIB0014
                Console.Error.WriteLine("Proxy defaults set. Explicit handlers, raw sockets, pinning and other stacks may ignore them. TLS verification stays enabled.");
            }
            Console.Error.WriteLine("EXECUTING REAL CLIENT CODE. Initializers, constructors, hooks, setup and selected methods can have side effects. This process is not sandboxed.");
            var context = new FrameworkClientContext(assemblyPath);
            var assembly = context.LoadFromAssemblyPath(assemblyPath);
            var method = Resolve(assembly, token, allowed);
            object? instance = null;
            if (!method.IsStatic)
            {
                var ctorArgs = config.TryGetProperty("constructorArguments", out var ca) ? ca : default;
                if (config.TryGetProperty("constructorToken", out var ct) && ct.ValueKind == JsonValueKind.Number)
                {
                    int ctoken = ct.GetInt32();
                    if (!allowed.ContainsKey(ctoken)) throw new ArgumentException("Constructor token must be in the exported selection.");
                    var ctor = assembly.ManifestModule.ResolveMethod(ctoken) as ConstructorInfo ?? throw new ArgumentException("Not a constructor token.");
                    if (ctor.IsStatic || ctor.DeclaringType != method.DeclaringType) throw new ArgumentException("Pick an instance constructor of the selected method's declaring type.");
                    instance = ctor.Invoke(ConvertArguments(ctor.GetParameters(), ctorArgs));
                }
                else instance = LabHooks.CreateInstance(method.DeclaringType!, ctorArgs);
            }
            LabHooks.BeforeInvoke(assembly, instance);
            if (config.TryGetProperty("setup", out var setup))
            {
                if (setup.ValueKind != JsonValueKind.Array || setup.GetArrayLength() > 32) throw new ArgumentException("setup must be an array of at most 32 calls.");
                foreach (var call in setup.EnumerateArray())
                {
                    var setupMethod = Resolve(assembly, call.GetProperty("methodToken").GetInt32(), allowed);
                    if (!setupMethod.IsStatic && (instance is null || !setupMethod.DeclaringType!.IsInstanceOfType(instance))) throw new ArgumentException("Setup instance method must accept the same instance as the selected method.");
                    await Invoke(setupMethod, setupMethod.IsStatic ? null : instance, call.GetProperty("arguments"));
                }
            }
            var result = await Invoke(method, instance, config.GetProperty("arguments"));
            PrintResult(result);
            return 0;
        }
        catch (Exception e)
        {
            if (e is TargetInvocationException { InnerException: not null } invocation) e = invocation.InnerException;
            Console.Error.WriteLine(e.GetType().FullName + ": " + e.Message);
            return 1;
        }
    }
    static bool IsRefStruct(Type t) => t.GetCustomAttributesData().Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.IsByRefLikeAttribute");
    static JsonDocument ReadJson(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 16 * 1024 * 1024) throw new ArgumentException("Configuration exceeds 16 MiB.");
        return JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 64 });
    }
    static MethodInfo Resolve(Assembly assembly, int token, Dictionary<int, JsonElement> allowed)
    {
        if (!allowed.ContainsKey(token) || (uint)token >> 24 != 6) throw new ArgumentException("Method token is outside the exported selection.");
        var method = assembly.ManifestModule.ResolveMethod(token) as MethodInfo ?? throw new ArgumentException("Pick an ordinary method, not a constructor.");
        if (method.ContainsGenericParameters || method.IsAbstract || method.ReturnType.IsByRef || method.ReturnType.IsPointer || IsRefStruct(method.ReturnType)) throw new NotSupportedException("Open generics, abstract methods and byref/pointer/ref-struct returns need a custom adapter.");
        if (method.ReturnType == typeof(void) && method.GetCustomAttributesData().Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.AsyncStateMachineAttribute")) throw new NotSupportedException("async void needs an async-aware host; select an awaitable method or add an adapter.");
        return method;
    }
    static async Task<object?> Invoke(MethodInfo method, object? instance, JsonElement args)
    {
        object? result = method.Invoke(instance, ConvertArguments(method.GetParameters(), args));
        if (result is Task task) { await task; return method.ReturnType.IsGenericType && method.ReturnType.GetGenericTypeDefinition() == typeof(Task<>) ? method.ReturnType.GetProperty("Result")!.GetValue(task) : null; }
        if (method.ReturnType == typeof(ValueTask)) { await (ValueTask)result!; return null; }
        if (method.ReturnType.IsGenericType && method.ReturnType.GetGenericTypeDefinition() == typeof(ValueTask<>))
        {
            var taskValue = (Task)method.ReturnType.GetMethod("AsTask")!.Invoke(result, null)!;
            await taskValue; return taskValue.GetType().GetProperty("Result")!.GetValue(taskValue);
        }
        return result;
    }
    public static object?[] ConvertArguments(ParameterInfo[] parameters, JsonElement args)
    {
        if (args.ValueKind == JsonValueKind.Undefined && parameters.Length == 0) return [];
        if (args.ValueKind != JsonValueKind.Array || args.GetArrayLength() != parameters.Length) throw new ArgumentException("Argument count does not match the signature. Supply every argument, including optional defaults.");
        if (parameters.Length > 128) throw new ArgumentException("Parameter cap: 128.");
        return parameters.Select((p, i) => ConvertValue(args[i], p.ParameterType)).ToArray();
    }
    static object? ConvertValue(JsonElement value, Type type)
    {
        if (type.IsByRef || type.IsPointer || IsRefStruct(type) || type.ContainsGenericParameters) throw new NotSupportedException("ref/out, pointers, ref structs and open generic arguments need an adapter.");
        var nullable = Nullable.GetUnderlyingType(type);
        if (value.ValueKind == JsonValueKind.Null) { if (!type.IsValueType || nullable is not null) return null; throw new ArgumentException("null is not valid for " + type.FullName); }
        if (nullable is not null) return ConvertValue(value, nullable);
        if (type == typeof(string)) return value.GetString();
        if (type == typeof(byte[]))
        {
            if (value.ValueKind == JsonValueKind.String) return Convert.FromBase64String(value.GetString()!);
            if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 1048576) throw new ArgumentException("byte[] needs a base64 string or a bounded byte array.");
            return value.EnumerateArray().Select(x => x.GetByte()).ToArray();
        }
        if (type.IsEnum) return Enum.Parse(type, value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText(), ignoreCase: false);
        if (type.IsArray && type.GetArrayRank() == 1)
        {
            if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 10000) throw new ArgumentException("Array argument must contain at most 10,000 values.");
            var element = type.GetElementType()!; var array = Array.CreateInstance(element, value.GetArrayLength());
            for (int i = 0; i < array.Length; i++) array.SetValue(ConvertValue(value[i], element), i);
            return array;
        }
        if (type == typeof(bool)) return value.GetBoolean();
        if (type == typeof(char)) { var s = value.GetString(); return s?.Length == 1 ? s[0] : throw new ArgumentException("char requires one character."); }
        if (type.IsPrimitive && type != typeof(IntPtr) && type != typeof(UIntPtr) || type == typeof(decimal)) return Convert.ChangeType(value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText(), type, CultureInfo.InvariantCulture);
        return LabHooks.ConvertCustomArgument(value, type);
    }
    static void PrintResult(object? result)
    {
        if (result is null) { Console.WriteLine("Result: null / void"); return; }
        if (result is string s) { Console.WriteLine("Result: " + (s.Length <= 4096 ? s : s.Substring(0, 4096) + "… [truncated]")); return; }
        if (result is byte[] bytes) { Console.WriteLine("Result: " + bytes.Length + " bytes · base64 preview: " + Convert.ToBase64String(bytes, 0, Math.Min(bytes.Length, 4096))); return; }
        var t = result.GetType();
        if (t.IsPrimitive || t.IsEnum || t == typeof(decimal)) { Console.WriteLine("Result: " + Convert.ToString(result, CultureInfo.InvariantCulture)); return; }
        Console.WriteLine("Result object: " + t.FullName + ". No property getters or custom ToString were called. Add deliberate inspection in Program.cs.");
    }
}

// Framework has a process-wide load context, not AssemblyLoadContext isolation.
sealed class FrameworkClientContext
{
    readonly string directory;
    public FrameworkClientContext(string path)
    {
        directory = Path.GetDirectoryName(path)!;
        AppDomain.CurrentDomain.AssemblyResolve += Resolve;
    }
    Assembly? Resolve(object sender, ResolveEventArgs e)
    {
        var requested = new AssemblyName(e.Name);
        if (string.IsNullOrEmpty(requested.Name) || requested.Name!.IndexOfAny(new[] { '/', '\\' }) >= 0) return null;
        string candidate = Path.Combine(directory, requested.Name + ".dll");
        if (!File.Exists(candidate)) return null;
        // Only fallback beside the analyst-selected target. No download or search outside that directory.
        var identity = AssemblyName.GetAssemblyName(candidate);
        if (!string.Equals(identity.FullName, requested.FullName, StringComparison.OrdinalIgnoreCase))
            throw new FileLoadException("Dependency identity mismatch: " + requested.FullName);
        return Assembly.LoadFrom(candidate);
    }
    public Assembly LoadFromAssemblyPath(string path) => Assembly.LoadFrom(path);
}
