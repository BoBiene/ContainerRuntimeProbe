namespace ContainerRuntimeProbe.Internal;

internal static class Redaction
{
    private static readonly string[] SecretPatterns = ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "KEY", "CERT", "CONNECTIONSTRING", "CONNECTION_STRING", "AUTHORIZATION", "COOKIE", "CREDENTIAL", "SAS"];

    public static bool IsSensitiveKey(string key) => SecretPatterns.Any(p => key.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static string? MaybeRedact(string key, string? value, bool includeSensitive)
    {
        if (value is null) return null;
        return IsSensitiveKey(key) && !includeSensitive ? "<redacted>" : value;
    }
}
