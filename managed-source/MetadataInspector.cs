using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

// Reads metadata/IL only. Reflection below describes the runtime's OpCodes table, never the sample.
static class MetadataInspector
{
    static readonly Dictionary<ushort, OpCode> Opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    public static string Clip(string? s, int max = 512) => s is null ? "" : s.Length > max ? s[..max] + "…" : s;
    public static ManagedMetadata Read(PEReader pe)
    {
        var md = pe.GetMetadataReader();
        if (md.TypeDefinitions.Count > 10000 || md.MethodDefinitions.Count > 50000) throw new ArgumentException("Metadata limit: 10,000 types / 50,000 methods.");
        var provider = new SignatureNames(md);
        int instructions = 0, evidenceCount = 0, ilBytes = 0;
        var warnings = new HashSet<string>();
        var types = new List<ManagedType>();
        foreach (var th in md.TypeDefinitions)
        {
            var t = md.GetTypeDefinition(th);
            var methods = new List<ManagedMethod>();
            foreach (var mh in t.GetMethods())
            {
                var m = md.GetMethodDefinition(mh);
                var name = Clip(md.GetString(m.Name));
                var notes = new List<string>();
                ManagedParameter[] parameters = [];
                string returns = "?", signature = name + "(?)";
                try
                {
                    var sig = m.DecodeSignature(provider, (object?)null);
                    if (sig.ParameterTypes.Length > 128) throw new BadImageFormatException("Parameter display limit.");
                    var names = m.GetParameters().Select(h => md.GetParameter(h)).Where(p => p.SequenceNumber > 0)
                        .GroupBy(p => p.SequenceNumber).ToDictionary(g => (int)g.Key - 1, g => Clip(md.GetString(g.First().Name)));
                    parameters = sig.ParameterTypes.Select((p, i) => new ManagedParameter(names.GetValueOrDefault(i, "arg" + i), Clip(p))).ToArray();
                    returns = Clip(sig.ReturnType); signature = Clip(returns + " " + name + "(" + string.Join(", ", parameters.Select(p => p.type + " " + p.name)) + ")", 2048);
                }
                catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException) { notes.Add("Signature could not be decoded."); }
                var evidence = new List<ManagedEvidence>();
                if (m.RelativeVirtualAddress != 0)
                {
                    if (instructions >= 500000 || evidenceCount >= 20000 || ilBytes >= 8 * 1024 * 1024) { notes.Add("IL scan skipped: assembly budget reached."); warnings.Add("IL scan is partial: assembly budget reached (500,000 instructions / 20,000 references / 8 MiB IL)."); }
                    else try
                    {
                        var body = pe.GetMethodBody(m.RelativeVirtualAddress).GetILBytes() ?? [];
                        if (body.Length > 256 * 1024 || ilBytes + body.Length > 8 * 1024 * 1024) { notes.Add("IL scan skipped: body byte limit."); warnings.Add("Some method bodies exceeded the IL byte budget."); }
                        else
                        {
                            ilBytes += body.Length;
                            for (int i = 0; i < body.Length;)
                            {
                                int offset = i;
                                ushort op = body[i++];
                                if (op == 0xfe) { if (i >= body.Length) throw new BadImageFormatException(); op = (ushort)(0xfe00 | body[i++]); }
                                if (!Opcodes.TryGetValue(op, out var opcode)) throw new BadImageFormatException();
                                int size = opcode.OperandType switch {
                                    OperandType.InlineNone => 0,
                                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                                    OperandType.InlineVar => 2,
                                    OperandType.InlineI8 or OperandType.InlineR => 8,
                                    OperandType.InlineSwitch => -1,
                                    _ => 4
                                };
                                if (size == -1) { if (i + 4 > body.Length) throw new BadImageFormatException(); int count = BitConverter.ToInt32(body, i); if (count < 0 || count > (body.Length - i - 4) / 4) throw new BadImageFormatException(); size = 4 + count * 4; }
                                if (size > body.Length - i) throw new BadImageFormatException();
                                instructions++;
                                if (size == 4 && opcode.OperandType is OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineField or OperandType.InlineTok or OperandType.InlineString)
                                {
                                    int token = BitConverter.ToInt32(body, i);
                                    string value, kind;
                                    if (opcode.OperandType == OperandType.InlineString)
                                    {
                                        if ((uint)token >> 24 != 0x70) throw new BadImageFormatException();
                                        value = Clip(md.GetUserString(MetadataTokens.UserStringHandle(token & 0xffffff)), 256); kind = "string";
                                    }
                                    else { value = provider.EntityName(MetadataTokens.EntityHandle(token)); kind = opcode.Name is "call" or "callvirt" or "newobj" ? "call" : "reference"; }
                                    evidence.Add(new ManagedEvidence(offset, opcode.Name ?? "?", kind, token, Clip(value, 1024), kind == "string" ? "user string" : provider.Scope(MetadataTokens.EntityHandle(token))));
                                    evidenceCount++;
                                }
                                i += size;
                                if (evidence.Count >= 128 || instructions >= 500000 || evidenceCount >= 20000) { if (i < body.Length) notes.Add("IL scan is partial: instruction/reference limit."); break; }
                            }
                        }
                    }
                    catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException) { notes.Add("Malformed or unreadable IL; evidence may be partial."); }
                }
                else notes.Add("No IL body (abstract, external, or runtime method).");
                string? stateMachine = null;
                foreach (var ah in m.GetCustomAttributes())
                {
                    try
                    {
                        var a = md.GetCustomAttribute(ah); var n = provider.EntityName(a.Constructor);
                        if (!n.StartsWith("System.Runtime.CompilerServices.AsyncStateMachineAttribute::", StringComparison.Ordinal) && !n.StartsWith("System.Runtime.CompilerServices.IteratorStateMachineAttribute::", StringComparison.Ordinal)) continue;
                        var reader = md.GetBlobReader(a.Value);
                        if (reader.ReadUInt16() == 1) stateMachine = Clip(reader.ReadSerializedString(), 2048);
                    }
                    catch (Exception ex) when (ex is BadImageFormatException or ArgumentException) { notes.Add("State-machine metadata could not be decoded."); }
                }
                methods.Add(new ManagedMethod(MetadataTokens.GetToken(mh), name, m.RelativeVirtualAddress, signature, returns, parameters,
                    m.Attributes.HasFlag(MethodAttributes.Static), (m.Attributes & MethodAttributes.MemberAccessMask) == MethodAttributes.Public,
                    m.Attributes.HasFlag(MethodAttributes.Abstract), m.GetGenericParameters().Count + t.GetGenericParameters().Count,
                    stateMachine, evidence.ToArray(), notes.ToArray()));
            }
            types.Add(new ManagedType(MetadataTokens.GetToken(th), Clip(md.GetString(t.Name)), Clip(md.GetString(t.Namespace)), provider.TypeName(th), methods.ToArray()));
        }
        var module = md.GetModuleDefinition();
        string framework = "Unknown", assemblyName = Clip(md.GetString(module.Name)), version = "";
        if (md.IsAssembly)
        {
            var a = md.GetAssemblyDefinition(); assemblyName = Clip(md.GetString(a.Name)); version = a.Version.ToString();
            foreach (var ah in a.GetCustomAttributes())
            {
                try { var ca = md.GetCustomAttribute(ah); if (!provider.EntityName(ca.Constructor).StartsWith("System.Runtime.Versioning.TargetFrameworkAttribute::", StringComparison.Ordinal)) continue;
                    var reader = md.GetBlobReader(ca.Value); if (reader.ReadUInt16() == 1) framework = Clip(reader.ReadSerializedString()); }
                catch (Exception ex) when (ex is BadImageFormatException or ArgumentException) { warnings.Add("Target framework metadata could not be decoded."); }
            }
        }
        return new ManagedMetadata(types.ToArray(), new ManagedAssembly(assemblyName, version, md.GetGuid(module.Mvid).ToString(), framework, pe.PEHeaders.CoffHeader.Machine.ToString(), pe.PEHeaders.CorHeader?.Flags.ToString() ?? ""), warnings.ToArray());
    }
}

sealed class SignatureNames(MetadataReader md) : ISignatureTypeProvider<string, object?>
{
    int depth;
    string Guard(Func<string> fn) { if (++depth > 24) { depth--; return "<depth limit>"; } try { return MetadataInspector.Clip(fn(), 1024); } finally { depth--; } }
    public string TypeName(TypeDefinitionHandle h) => Guard(() => { var t = md.GetTypeDefinition(h); var parent = t.GetDeclaringType(); return parent.IsNil ? Join(md.GetString(t.Namespace), md.GetString(t.Name)) : TypeName(parent) + "+" + md.GetString(t.Name); });
    public string RefName(TypeReferenceHandle h) => Guard(() => { var t = md.GetTypeReference(h); return t.ResolutionScope.Kind == HandleKind.TypeReference ? RefName((TypeReferenceHandle)t.ResolutionScope) + "+" + md.GetString(t.Name) : Join(md.GetString(t.Namespace), md.GetString(t.Name)); });
    static string Join(string ns, string name) => ns.Length == 0 ? name : ns + "." + name;
    public string EntityName(EntityHandle h) => Guard(() => h.Kind switch {
        HandleKind.TypeDefinition => TypeName((TypeDefinitionHandle)h),
        HandleKind.TypeReference => RefName((TypeReferenceHandle)h),
        HandleKind.TypeSpecification => md.GetTypeSpecification((TypeSpecificationHandle)h).DecodeSignature(this, (object?)null),
        HandleKind.MethodDefinition => MethodName((MethodDefinitionHandle)h),
        HandleKind.MemberReference => MemberName((MemberReferenceHandle)h),
        HandleKind.MethodSpecification => EntityName(md.GetMethodSpecification((MethodSpecificationHandle)h).Method),
        HandleKind.FieldDefinition => FieldName((FieldDefinitionHandle)h),
        _ => h.Kind + ":0x" + MetadataTokens.GetToken(h).ToString("x8")
    });
    public string Scope(EntityHandle h) => Guard(() => h.Kind switch {
        HandleKind.TypeDefinition or HandleKind.MethodDefinition or HandleKind.FieldDefinition => "local module",
        HandleKind.TypeReference => Scope(md.GetTypeReference((TypeReferenceHandle)h).ResolutionScope),
        HandleKind.AssemblyReference => MetadataInspector.Clip(md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)h).Name)),
        HandleKind.MemberReference => Scope(md.GetMemberReference((MemberReferenceHandle)h).Parent),
        HandleKind.MethodSpecification => Scope(md.GetMethodSpecification((MethodSpecificationHandle)h).Method),
        HandleKind.ModuleReference => "module: " + MetadataInspector.Clip(md.GetString(md.GetModuleReference((ModuleReferenceHandle)h).Name)),
        HandleKind.TypeSpecification => "generic type specification (scope unresolved)",
        _ => "scope unresolved"
    });
    string MethodName(MethodDefinitionHandle h) { var m = md.GetMethodDefinition(h); return TypeName(m.GetDeclaringType()) + "::" + md.GetString(m.Name); }
    string MemberName(MemberReferenceHandle h) { var m = md.GetMemberReference(h); return EntityName(m.Parent) + "::" + md.GetString(m.Name); }
    string FieldName(FieldDefinitionHandle h) { var f = md.GetFieldDefinition(h); return TypeName(f.GetDeclaringType()) + "::" + md.GetString(f.Name); }
    public string GetArrayType(string e, ArrayShape shape) => e + "[" + new string(',', Math.Clamp(shape.Rank - 1, 0, 16)) + "]";
    public string GetByReferenceType(string e) => e + "&";
    public string GetFunctionPointerType(MethodSignature<string> s) => "method*";
    public string GetGenericInstantiation(string g, ImmutableArray<string> args) => MetadataInspector.Clip(g + "<" + string.Join(", ", args.Take(32)) + ">", 1024);
    public string GetGenericMethodParameter(object? c, int i) => "!!" + i;
    public string GetGenericTypeParameter(object? c, int i) => "!" + i;
    public string GetModifiedType(string m, string u, bool required) => u;
    public string GetPinnedType(string e) => e;
    public string GetPointerType(string e) => e + "*";
    public string GetPrimitiveType(PrimitiveTypeCode c) => c switch { PrimitiveTypeCode.Boolean => "bool", PrimitiveTypeCode.Byte => "byte", PrimitiveTypeCode.SByte => "sbyte", PrimitiveTypeCode.Int16 => "short", PrimitiveTypeCode.UInt16 => "ushort", PrimitiveTypeCode.Int32 => "int", PrimitiveTypeCode.UInt32 => "uint", PrimitiveTypeCode.Int64 => "long", PrimitiveTypeCode.UInt64 => "ulong", PrimitiveTypeCode.Single => "float", PrimitiveTypeCode.Double => "double", PrimitiveTypeCode.Char => "char", PrimitiveTypeCode.String => "string", PrimitiveTypeCode.Void => "void", PrimitiveTypeCode.Object => "object", PrimitiveTypeCode.IntPtr => "nint", PrimitiveTypeCode.UIntPtr => "nuint", _ => c.ToString() };
    public string GetSZArrayType(string e) => e + "[]";
    public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte k) => TypeName(h);
    public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte k) => RefName(h);
    public string GetTypeFromSpecification(MetadataReader r, object? c, TypeSpecificationHandle h, byte k) => Guard(() => r.GetTypeSpecification(h).DecodeSignature(this, c));
}
sealed record ManagedParameter(string name, string type);
sealed record ManagedEvidence(int offset, string opcode, string kind, int token, string value, string scope);
sealed record ManagedMethod(int token, string name, int rva, string signature, string returnType, ManagedParameter[] parameters, bool isStatic, bool isPublic, bool isAbstract, int genericArity, string? stateMachine, ManagedEvidence[] evidence, string[] warnings);
sealed record ManagedType(int token, string name, string ns, string fullName, ManagedMethod[] methods);
sealed record ManagedAssembly(string name, string version, string mvid, string targetFramework, string machine, string corFlags);
sealed record ManagedMetadata(ManagedType[] types, ManagedAssembly assembly, string[] warnings);
