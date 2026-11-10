namespace Spectra.Fixtures;
public static class Decoder
{
    public static string Decode(byte[] encoded, byte key)
    {
        var clear = new char[encoded.Length];
        for (int i = 0; i < encoded.Length; i++) clear[i] = (char)(encoded[i] ^ key);
        return new string(clear);
    }
    public static string Classify(int value) => value < 0 ? "negative" : value == 0 ? "zero" : "positive";
    public static int Sum(int[] values)
    {
        int total = 0;
        foreach (int value in values) total += value;
        return total;
    }
}

// Benign harness fixture: HTTP only happens when an analyst/test invokes FetchAsync.
public sealed class LabClient
{
    string prefix;
    public LabClient() { prefix = "ready"; }
    public LabClient(string value) { prefix = value; }
    public void SetPrefix(string value) { prefix = value; }
    public string Greet(string name) => prefix + ":" + name;
    public static byte[] Fingerprint(byte[] data) => System.Security.Cryptography.SHA256.HashData(data);
    public static System.Net.NetworkCredential Credentials(string user, string password) => new(user, password);
    public static string Json(string value) => System.Text.Json.JsonSerializer.Serialize(value);
    public static async System.Threading.Tasks.Task<string> FetchAsync(string url)
    {
        using var client = new System.Net.Http.HttpClient();
        return await client.GetStringAsync(url);
    }
    public static async System.Threading.Tasks.Task<int> DoubleAsync(int value) { await System.Threading.Tasks.Task.Yield(); return value * 2; }
    public static System.Threading.Tasks.ValueTask<int> IncrementAsync(int value) => new(value + 1);
    public static long EchoLong(long value) => value;
    public static T Generic<T>(T value) => value;
    public static void RefArgument(ref int value) { value++; }
    public static string MisleadingNameAuth() => "ordinary text";
    public static string EndpointHint() => "https://lab.example.invalid/api";
    public static string DangerousLookingText() => "</script><img src=x onerror=alert(1)>";
    public static object Opaque() => new NoisyResult();
    public static string MarkExecution(string path) { System.IO.File.WriteAllText(path, "executed benign fixture"); return "ok"; }
    private sealed class NoisyResult
    {
        public string Value => throw new System.Exception("Getter must not be called");
        public override string ToString() => throw new System.Exception("ToString must not be called");
    }
}
