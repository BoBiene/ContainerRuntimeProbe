using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal static class Redaction
{
    internal const string RedactedValue = "<redacted>";

    private static readonly string[] SecretPatterns = ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "KEY", "CERT", "CONNECTIONSTRING", "CONNECTION_STRING", "AUTHORIZATION", "COOKIE", "CREDENTIAL", "SAS"];

    public static bool IsSensitiveKey(string key) => SecretPatterns.Any(p => key.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static string? MaybeRedact(string key, string? value, bool includeSensitive)
    {
        if (value is null) return null;
        return IsSensitiveKey(key) && !includeSensitive ? RedactedValue : value;
    }

    public static EvidenceItem RedactEvidenceItem(EvidenceItem evidence, bool includeSensitive)
    {
        if (includeSensitive || evidence.Sensitivity != EvidenceSensitivity.Sensitive || evidence.Value is null)
        {
            return evidence;
        }

        return evidence with { Value = RedactedValue };
    }

    public static ProbeResult RedactProbeResult(ProbeResult result, bool includeSensitive)
    {
        if (includeSensitive)
        {
            return result;
        }

        return result with { Evidence = result.Evidence.Select(evidence => RedactEvidenceItem(evidence, includeSensitive)).ToArray() };
    }
}
