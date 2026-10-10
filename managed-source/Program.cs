using System.Security.Cryptography;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices.JavaScript;
using System.Text.Json;
using System.Text.Json.Serialization;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;

public partial class Program
{
    public static void Main() { }

    [JSExport]
    public static string Decompile(string base64, int token, string dependenciesJson)
    {
        if (base64.Length > 22369624) throw new ArgumentException("Managed input exceeds 16 MiB.");
        if (token != 0 && token != -1 && ((uint)token >> 24) != 2 && ((uint)token >> 24) != 6) throw new ArgumentException("Select an assembly, type, or method.");
        byte[] bytes = Convert.FromBase64String(base64);
        if (bytes.Length > 16 * 1024 * 1024) throw new ArgumentException("Managed image exceeds 16 MiB.");
        using var image = new PEFile("sample.dll", new MemoryStream(bytes, writable: false), PEStreamOptions.PrefetchEntireImage);
        if (dependenciesJson.Length > 90000000) throw new ArgumentException("Dependency input exceeds the total byte budget.");
        var inputs = JsonSerializer.Deserialize(dependenciesJson, AnalysisJsonContext.Default.DependencyInputArray) ?? [];
        using var resolver = new LocalOnlyResolver(inputs, bytes.Length);
        var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false, UseDebugSymbols = false };
        var decompiler = new CSharpDecompiler(image, resolver, settings);
        using var pe = new PEReader(new MemoryStream(bytes, writable: false));
        var inspection = MetadataInspector.Read(pe);
        string code = token == -1 ? "" : token == 0 ? decompiler.DecompileWholeModuleAsString() : decompiler.DecompileAsString(MetadataTokens.EntityHandle(token));
        if (code.Length > 2000000) throw new ArgumentException("C# exceeds 2 million characters. Select a smaller type or method.");
        string json = JsonSerializer.Serialize(new DecompileResult(code, inspection.types, resolver.Missing.Order().ToArray(), "ILSpy 11.1.0.9782", inspection.assembly, inspection.warnings, resolver.Describe()), AnalysisJsonContext.Default.DecompileResult);
        if (json.Length > 8000000) throw new ArgumentException("Managed metadata/code output exceeds 8 million characters.");
        return json;
    }
}

sealed record DecompileResult(string code, ManagedType[] types, string[] missingReferences, string engine, ManagedAssembly assembly, string[] analysisWarnings, DependencyInfo[] dependencies);
sealed record DependencyInput(string name, string base64);
sealed record DependencyInfo(string name, string identity, string sha256, string mvid, bool resolved);
[JsonSerializable(typeof(DecompileResult))]
[JsonSerializable(typeof(DependencyInput[]))]
internal partial class AnalysisJsonContext : JsonSerializerContext { }

sealed class LocalOnlyResolver : IAssemblyResolver, IDisposable
{
    public HashSet<string> Missing { get; } = new(StringComparer.Ordinal);
    readonly Dictionary<string, PEFile> supplied = new(StringComparer.OrdinalIgnoreCase);
    readonly List<DependencyInfo> evidence = [];
    readonly HashSet<string> resolved = new(StringComparer.OrdinalIgnoreCase);
    public LocalOnlyResolver(DependencyInput[] inputs, int mainSize)
    {
        if (inputs.Length > 32) throw new ArgumentException("Local dependency cap: 32.");
        long total = mainSize;
        try { foreach (var input in inputs)
        {
            if (input.name is null || input.name.Length > 240 || input.base64 is null || input.base64.Length > 22369624) throw new ArgumentException("Invalid local dependency.");
            byte[] bytes = Convert.FromBase64String(input.base64); total += bytes.Length;
            if (bytes.Length > 16 * 1024 * 1024 || total > 64 * 1024 * 1024) throw new ArgumentException("Dependencies plus sample exceed 64 MiB, or one dependency exceeds 16 MiB.");
            var file = new PEFile(input.name, new MemoryStream(bytes, writable: false), PEStreamOptions.PrefetchEntireImage);
            if (!file.IsAssembly || !supplied.TryAdd(file.FullName, file)) { file.Dispose(); throw new ArgumentException("Duplicate assembly identity or unsupported netmodule: " + input.name); }
            var md = file.Metadata;
            evidence.Add(new(input.name, file.FullName, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), md.GetGuid(md.GetModuleDefinition().Mvid).ToString(), false));
        } } catch { Dispose(); throw; }
    }
    public DependencyInfo[] Describe() => evidence.Select(d => d with { resolved = resolved.Contains(d.identity) }).ToArray();
    public MetadataFile? Resolve(IAssemblyReference reference) { if (supplied.TryGetValue(reference.FullName, out var file)) { resolved.Add(reference.FullName); return file; } Missing.Add(reference.FullName); return null; }
    public void Dispose() { foreach (var file in supplied.Values) file.Dispose(); supplied.Clear(); }
    public MetadataFile? ResolveModule(MetadataFile mainModule, string moduleName) { Missing.Add(moduleName); return null; }
    public Task<MetadataFile?> ResolveAsync(IAssemblyReference reference) => Task.FromResult(Resolve(reference));
    public Task<MetadataFile?> ResolveModuleAsync(MetadataFile mainModule, string moduleName) => Task.FromResult(ResolveModule(mainModule, moduleName));
    public IDisposable? BeginSnapshot() => null;
}
