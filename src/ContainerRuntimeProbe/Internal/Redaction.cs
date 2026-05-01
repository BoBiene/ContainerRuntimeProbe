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

        return bool.TryParse(evidence.Value, out _)
            ? evidence
            : evidence with { Value = RedactedValue };
    }

    public static ProbeResult RedactProbeResult(ProbeResult result, bool includeSensitive)
    {
        if (includeSensitive)
        {
            return result;
        }

        return result with { Evidence = result.Evidence.Select(evidence => RedactEvidenceItem(evidence, includeSensitive)).ToArray() };
    }

    public static IReadOnlyList<PlatformEvidenceSummary> RedactPlatformEvidence(
        IReadOnlyList<PlatformEvidenceSummary> summaries,
        IReadOnlyList<ProbeResult> rawResults,
        bool includeSensitive)
    {
        if (includeSensitive)
        {
            return summaries;
        }

        var sensitiveKeys = GetSensitiveSummaryKeys(rawResults);
        return summaries
            .Select(summary => summary with
            {
                Evidence = summary.Evidence
                    .Select(item => item with { Value = RedactSummaryValue(item.Key, item.Value, sensitiveKeys, includeSensitive) })
                    .ToArray()
            })
            .ToArray();
    }

    public static IReadOnlyList<TrustedPlatformSummary> RedactTrustedPlatforms(
        IReadOnlyList<TrustedPlatformSummary> summaries,
        IReadOnlyList<ProbeResult> rawResults,
        bool includeSensitive)
    {
        if (includeSensitive)
        {
            return summaries;
        }

        var sensitiveKeys = GetSensitiveSummaryKeys(rawResults);
        return summaries
            .Select(summary => summary with
            {
                Evidence = summary.Evidence
                    .Select(item => item with { Value = RedactSummaryValue(item.Key, item.Value, sensitiveKeys, includeSensitive) })
                    .ToArray()
            })
            .ToArray();
    }

    private static HashSet<string> GetSensitiveSummaryKeys(IReadOnlyList<ProbeResult> rawResults)
        => rawResults
            .SelectMany(result => result.Evidence)
            .Where(evidence => evidence.Sensitivity == EvidenceSensitivity.Sensitive)
            .Select(evidence => evidence.Key)
            .ToHashSet(StringComparer.Ordinal);

    private static string? RedactSummaryValue(string key, string? value, IReadOnlySet<string> sensitiveKeys, bool includeSensitive)
    {
        if (includeSensitive || value is null || !sensitiveKeys.Contains(key))
        {
            return value;
        }

        return bool.TryParse(value, out _) ? value : RedactedValue;
    }
}
