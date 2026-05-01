using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe;

/// <summary>Identifies a high-level relevant finding derived from a normalized container runtime report.</summary>
public enum ReportFindingKind
{
    /// <summary>An explicitly trusted platform claim.</summary>
    TrustedPlatform,

    /// <summary>A heuristic platform evidence summary.</summary>
    PlatformEvidence,

    /// <summary>A containerization and runtime finding.</summary>
    Containerization,

    /// <summary>A broader environment finding such as cloud or on-prem.</summary>
    Environment,

    /// <summary>An orchestrator finding.</summary>
    Orchestrator,

    /// <summary>A platform vendor finding.</summary>
    PlatformVendor,

    /// <summary>A runtime-reported host operating system finding.</summary>
    HostOs,

    /// <summary>A virtualization finding.</summary>
    Virtualization,

    /// <summary>A hardware or DMI finding.</summary>
    Hardware
}

/// <summary>Structured relevant finding exposed to API consumers and renderers.</summary>
public sealed record ReportFinding(
    ReportFindingKind Kind,
    string Key,
    string? Value,
    Confidence Confidence,
    string Summary,
    IReadOnlyList<string> EvidenceKeys)
{
    /// <summary>Optional heuristic score when the finding comes from a scored summary.</summary>
    public int? Score { get; init; }

    /// <summary>Optional monotonic verification level when the finding comes from a trusted platform summary.</summary>
    public int? VerificationLevel { get; init; }

    /// <summary>Optional method or source detail associated with the finding.</summary>
    public string? Method { get; init; }
}

/// <summary>Extension methods for deriving higher-level summaries from a normalized container runtime report.</summary>
public static class ContainerRuntimeReportExtensions
{
    /// <summary>Returns the most relevant structured findings derived from the report.</summary>
    public static IReadOnlyList<ReportFinding> GetRelevantFindings(this ContainerRuntimeReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var findings = new List<ReportFinding>();
        findings.AddRange(BuildTrustedPlatformFindings(report));
        findings.AddRange(BuildPlatformEvidenceFindings(report));
        AddContainerizationFinding(findings, report);
        AddEnvironmentFinding(findings, report);
        AddOrchestratorFinding(findings, report);
        AddPlatformVendorFinding(findings, report);
        AddHostOsFinding(findings, report);
        AddVirtualizationFinding(findings, report);
        AddHardwareFinding(findings, report);
        return findings;
    }

    private static IReadOnlyList<ReportFinding> BuildTrustedPlatformFindings(ContainerRuntimeReport report)
    {
        var trustedPlatforms = report.TrustedPlatforms?
            .Where(summary => summary.State != TrustedPlatformState.None)
            .OrderByDescending(summary => summary.VerificationLevel)
            .ThenBy(summary => summary.PlatformKey, StringComparer.Ordinal)
            .ToArray() ?? [];

        return trustedPlatforms.Select(summary => new ReportFinding(
                ReportFindingKind.TrustedPlatform,
                summary.PlatformKey,
                summary.State.ToString(),
                MaxConfidence(summary.Claims.Select(claim => claim.Confidence).Concat(summary.Evidence.Select(evidence => evidence.Confidence))),
                $"Trusted platform {summary.PlatformKey} is {summary.State.ToString().ToLowerInvariant()} via {summary.VerificationMethod ?? KnownValues.Unknown} at verification level {summary.VerificationLevel}.",
                summary.Evidence.Select(item => item.Key).Distinct(StringComparer.Ordinal).ToArray())
            {
                VerificationLevel = summary.VerificationLevel,
                Method = summary.VerificationMethod
            })
            .ToArray();
    }

    private static IReadOnlyList<ReportFinding> BuildPlatformEvidenceFindings(ContainerRuntimeReport report)
    {
        var platformEvidence = report.PlatformEvidence?
            .Where(summary => summary.EvidenceLevel != PlatformEvidenceLevel.None)
            .OrderByDescending(summary => summary.Score)
            .ThenBy(summary => summary.PlatformKey, StringComparer.Ordinal)
            .ToArray() ?? [];

        return platformEvidence.Select(summary => new ReportFinding(
                ReportFindingKind.PlatformEvidence,
                summary.PlatformKey,
                summary.EvidenceLevel.ToString(),
                summary.Confidence,
                $"Platform evidence suggests {summary.PlatformKey} with {summary.EvidenceLevel} confidence (score {summary.Score}, {summary.Confidence}).",
                summary.Evidence.Select(item => item.Key).Distinct(StringComparer.Ordinal).ToArray())
            {
                Score = summary.Score,
                Method = summary.EvidenceLevel.ToString()
            })
            .ToArray();
    }

    private static void AddContainerizationFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        if (report.Classification.IsContainerized.Confidence != Confidence.Unknown)
        {
            var containerized = ClassificationValueFormatter.Format(report.Classification.IsContainerized.Value);
            var runtimeKnown = report.Classification.ContainerRuntime.Confidence != Confidence.Unknown;
            var runtime = runtimeKnown
                ? ClassificationValueFormatter.Format(report.Classification.ContainerRuntime.Value)
                : null;
            findings.Add(new ReportFinding(
                ReportFindingKind.Containerization,
                "containerization",
                containerized,
                MaxConfidence([report.Classification.IsContainerized.Confidence, report.Classification.ContainerRuntime.Confidence]),
                runtime is null
                    ? $"Containerization assessment: {containerized} ({report.Classification.IsContainerized.Confidence})."
                    : $"Containerization assessment: {containerized} with {runtime} runtime ({report.Classification.IsContainerized.Confidence}/{report.Classification.ContainerRuntime.Confidence}).",
                report.Classification.IsContainerized.Reasons
                    .Concat(report.Classification.ContainerRuntime.Reasons)
                    .SelectMany(reason => reason.EvidenceKeys)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray())
            {
                Method = runtime
            });
        }
    }

    private static void AddEnvironmentFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        if (report.Classification.Environment.Type.Confidence != Confidence.Unknown)
        {
            var environment = ClassificationValueFormatter.Format(report.Classification.Environment.Type.Value);
            var providerKnown = report.Classification.CloudProvider.Confidence != Confidence.Unknown;
            var provider = providerKnown
                ? ClassificationValueFormatter.Format(report.Classification.CloudProvider.Value)
                : null;
            findings.Add(new ReportFinding(
                ReportFindingKind.Environment,
                "environment",
                environment,
                MaxConfidence([report.Classification.Environment.Type.Confidence, report.Classification.CloudProvider.Confidence]),
                provider is null
                    ? $"Execution environment looks like {environment} ({report.Classification.Environment.Type.Confidence})."
                    : $"Execution environment looks like {environment} on {provider} ({report.Classification.Environment.Type.Confidence}/{report.Classification.CloudProvider.Confidence}).",
                report.Classification.Environment.Type.Reasons
                    .Concat(report.Classification.CloudProvider.Reasons)
                    .SelectMany(reason => reason.EvidenceKeys)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray())
            {
                Method = provider
            });
        }
    }

    private static void AddOrchestratorFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        if (report.Classification.Orchestrator.Confidence != Confidence.Unknown)
        {
            findings.Add(new ReportFinding(
                ReportFindingKind.Orchestrator,
                "orchestrator",
                ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value),
                report.Classification.Orchestrator.Confidence,
                $"Orchestrator detection: {ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value)} ({report.Classification.Orchestrator.Confidence}).",
                report.Classification.Orchestrator.Reasons.SelectMany(reason => reason.EvidenceKeys).Distinct(StringComparer.Ordinal).ToArray()));
        }
    }

    private static void AddPlatformVendorFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        if (report.Classification.PlatformVendor.Confidence != Confidence.Unknown)
        {
            findings.Add(new ReportFinding(
                ReportFindingKind.PlatformVendor,
                "platform-vendor",
                ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value),
                report.Classification.PlatformVendor.Confidence,
                $"Platform vendor classification: {ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value)} ({report.Classification.PlatformVendor.Confidence}).",
                report.Classification.PlatformVendor.Reasons.SelectMany(reason => reason.EvidenceKeys).Distinct(StringComparer.Ordinal).ToArray()));
        }
    }

    private static void AddHostOsFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        var runtimeHostOs = FormatHostOs(report.Host.RuntimeReportedHostOs.Name, report.Host.RuntimeReportedHostOs.Version);
        if (!string.Equals(runtimeHostOs, KnownValues.Unknown, StringComparison.Ordinal))
        {
            findings.Add(new ReportFinding(
                ReportFindingKind.HostOs,
                "runtime-reported-host-os",
                runtimeHostOs,
                report.Host.RuntimeReportedHostOs.Confidence,
                $"Runtime-reported host OS: {runtimeHostOs} ({report.Host.RuntimeReportedHostOs.Confidence}).",
                report.Host.RuntimeReportedHostOs.EvidenceReferences));
        }
    }

    private static void AddVirtualizationFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        if (report.Host.Virtualization.Confidence != Confidence.Unknown && report.Host.Virtualization.Kind != VirtualizationKind.Unknown)
        {
            findings.Add(new ReportFinding(
                ReportFindingKind.Virtualization,
                "virtualization",
                report.Host.Virtualization.Kind.ToString(),
                report.Host.Virtualization.Confidence,
                string.IsNullOrWhiteSpace(report.Host.Virtualization.PlatformVendor)
                    ? $"Virtualization evidence points to {report.Host.Virtualization.Kind} ({report.Host.Virtualization.Confidence})."
                    : $"Virtualization evidence points to {report.Host.Virtualization.Kind} on {report.Host.Virtualization.PlatformVendor} ({report.Host.Virtualization.Confidence}).",
                report.Host.Virtualization.EvidenceReferences)
            {
                Method = report.Host.Virtualization.PlatformVendor
            });
        }
    }

    private static void AddHardwareFinding(List<ReportFinding> findings, ContainerRuntimeReport report)
    {
        var dmiSummary = JoinNonEmpty(report.Host.Hardware.Dmi.SystemVendor, report.Host.Hardware.Dmi.ProductName);
        if (!string.IsNullOrWhiteSpace(dmiSummary))
        {
            findings.Add(new ReportFinding(
                ReportFindingKind.Hardware,
                "hardware-dmi",
                dmiSummary,
                report.Host.Hardware.Dmi.Confidence,
                $"Hardware/DMI reports {dmiSummary} ({report.Host.Hardware.Dmi.Confidence}).",
                report.Host.Hardware.Dmi.EvidenceReferences));
        }
    }

    private static Confidence MaxConfidence(IEnumerable<Confidence> values)
        => values.DefaultIfEmpty(Confidence.Unknown).Max();

    private static string FormatHostOs(string? name, string? version)
    {
        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(version))
        {
            return KnownValues.Unknown;
        }

        if (string.IsNullOrWhiteSpace(version) || (name?.Contains(version, StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return string.IsNullOrWhiteSpace(name) ? KnownValues.Unknown : name;
        }

        return $"{name} {version}";
    }

    private static string? JoinNonEmpty(params string?[] values)
    {
        var parts = values.Where(value => !string.IsNullOrWhiteSpace(value)).ToArray();
        return parts.Length == 0 ? null : string.Join(" ", parts);
    }
}