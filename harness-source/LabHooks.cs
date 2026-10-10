using System.Reflection;
using System.Text.Json;

// Edit these hooks when the client needs dependency injection, configuration or session state.
// They run only after --execute. They are ordinary code with your OS permissions.
static class LabHooks
{
    public static object CreateInstance(Type type, JsonElement constructorArguments)
    {
        if (type.ContainsGenericParameters || type.IsAbstract) throw new NotSupportedException("Choose a concrete type or provide a custom instance factory.");
        if (constructorArguments.ValueKind == JsonValueKind.Array && constructorArguments.GetArrayLength() > 0) throw new NotSupportedException("Select an exported constructorToken in invocation.json, or implement a factory here.");
        var constructor = type.GetConstructor(Type.EmptyTypes) ?? throw new NotSupportedException("No public parameterless constructor. Add its constructor to the selection or implement CreateInstance.");
        return constructor.Invoke(null);
    }
    public static void BeforeInvoke(Assembly client, object? instance)
    {
        // Example places to wire up test configuration, a lab endpoint or an authenticated session.
        // SPECTRA cannot infer the app's whole startup/auth flow. Read the decompiled caller first.
        // Nothing here silently replaces hard-coded URLs or disables TLS verification.
    }
    public static object? ConvertCustomArgument(JsonElement json, Type type)
    {
        // Build client-specific DTOs deliberately here. Automatic deserialization can execute
        // target constructors, setters and custom converters, so it is not a default.
        throw new NotSupportedException("Argument type " + type.FullName + " needs a custom adapter in LabHooks.ConvertCustomArgument.");
    }
}
