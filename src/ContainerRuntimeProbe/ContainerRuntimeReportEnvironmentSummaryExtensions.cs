using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe;

/// <summary>Builds neutral environment-oriented summary facts for a normalized report.</summary>
public static partial class ContainerRuntimeReportSummaryExtensions
{
    /// <summary>Returns the compact environment summary for a normalized report.</summary>
    public static EnvironmentSummary GetEnvironmentSummary(this ContainerRuntimeReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var sections = new List<EnvironmentSummarySection>();
        AddRuntimeSection(sections, report);
        AddExecutionContextSection(sections, report);
        AddHostSection(sections, report);
        AddPlatformSection(sections, report);
        AddTrustSection(sections, report);
        return new EnvironmentSummary(sections);
    }

    private static void AddRuntimeSection(List<EnvironmentSummarySection> sections, ContainerRuntimeReport report)
    {
        var facts = new List<SummaryFact>();

        if (report.Classification.IsContainerized.Confidence != Confidence.Unknown)
        {
            facts.Add(new SummaryFact(
                "Mode",
                report.Classification.IsContainerized.Value == ContainerizationKind.@True ? "Containerized" : "Not Containerized",
                SummaryScope.Runtime,
                Confidence: report.Classification.IsContainerized.Confidence,
                SourceKind: nameof(ReportClassification),
                EvidenceKeys: CollectEvidenceKeys(report.Classification.IsContainerized.Reasons)));
        }

        AddClassificationFact(
            facts,
            "Runtime",
            ClassificationValueFormatter.Format(report.Classification.ContainerRuntime.Value),
            report.Classification.ContainerRuntime.Confidence,
            SummaryScope.Runtime,
            report.Classification.ContainerRuntime.Reasons);

        AddClassificationFact(
            facts,
            "API",
            ClassificationValueFormatter.Format(report.Classification.RuntimeApi.Value),
            report.Classification.RuntimeApi.Confidence,
            SummaryScope.Runtime,
            report.Classification.RuntimeApi.Reasons);

        AddSection(sections, EnvironmentSummarySectionKind.Runtime, "Runtime", facts);
    }

    private static void AddExecutionContextSection(List<EnvironmentSummarySection> sections, ContainerRuntimeReport report)
    {
        var facts = new List<SummaryFact>();

        AddClassificationFact(
            facts,
            "Environment",
            ClassificationValueFormatter.Format(report.Classification.Environment.Type.Value),
            report.Classification.Environment.Type.Confidence,
            SummaryScope.Runtime,
            report.Classification.Environment.Type.Reasons);

        AddClassificationFact(
            facts,
            "Cloud",
            ClassificationValueFormatter.Format(report.Classification.CloudProvider.Value),
            report.Classification.CloudProvider.Confidence,
            SummaryScope.Platform,
            report.Classification.CloudProvider.Reasons);

        AddClassificationFact(
            facts,
            "Orchestrator",
            ClassificationValueFormatter.Format(report.Classification.Orchestrator.Value),
            report.Classification.Orchestrator.Confidence,
            SummaryScope.Runtime,
            report.Classification.Orchestrator.Reasons);

        AddSection(sections, EnvironmentSummarySectionKind.ExecutionContext, "Execution Context", facts);
    }

    private static void AddHostSection(List<EnvironmentSummarySection> sections, ContainerRuntimeReport report)
    {
        var facts = new List<SummaryFact>();
        var hostOs = GetPreferredHostOs(report);
        if (!string.IsNullOrWhiteSpace(hostOs))
        {
            facts.Add(new SummaryFact(
                "Host OS",
                hostOs,
                SummaryScope.Host,
                Confidence: report.Host.RuntimeReportedHostOs.Confidence,
                SourceKind: nameof(RuntimeReportedHostOsInfo),
                EvidenceKeys: report.Host.RuntimeReportedHostOs.EvidenceReferences));
        }

        var virtualization = GetVirtualizationValue(report);
        if (!string.IsNullOrWhiteSpace(virtualization))
        {
            facts.Add(new SummaryFact(
                "Virtualization",
                virtualization,
                SummaryScope.Host,
                Confidence: report.Host.Virtualization.Confidence,
                SourceKind: nameof(VirtualizationInfo),
                EvidenceKeys: report.Host.Virtualization.EvidenceReferences));
        }

        var hardware = JoinNonEmpty(report.Host.Hardware.Dmi.SystemVendor, report.Host.Hardware.Dmi.ProductName);
        if (!string.IsNullOrWhiteSpace(hardware))
        {
            facts.Add(new SummaryFact(
                "Hardware",
                hardware,
                SummaryScope.Host,
                Confidence: report.Host.Hardware.Dmi.Confidence,
                SourceKind: nameof(HostDmiInfo),
                EvidenceKeys: report.Host.Hardware.Dmi.EvidenceReferences));
        }

        if (!string.IsNullOrWhiteSpace(report.Host.Hardware.Cpu.ModelName))
        {
            facts.Add(new SummaryFact(
                "CPU",
                report.Host.Hardware.Cpu.ModelName,
                SummaryScope.Host,
                SourceKind: nameof(HostCpuInfo)));
        }

        var memory = FormatBytes(report.Host.Hardware.Memory.MemTotalBytes);
        if (!string.IsNullOrWhiteSpace(memory))
        {
            facts.Add(new SummaryFact(
                "Memory",
                memory,
                SummaryScope.Host,
                SourceKind: nameof(HostMemoryInfo)));
        }

        AddSection(sections, EnvironmentSummarySectionKind.Host, "Host", facts);
    }

    private static void AddPlatformSection(List<EnvironmentSummarySection> sections, ContainerRuntimeReport report)
    {
        var facts = new List<SummaryFact>();

        AddClassificationFact(
            facts,
            "Vendor",
            ClassificationValueFormatter.Format(report.Classification.PlatformVendor.Value),
            report.Classification.PlatformVendor.Confidence,
            SummaryScope.Platform,
            report.Classification.PlatformVendor.Reasons);

        if (!string.IsNullOrWhiteSpace(report.Host.Hardware.CloudMachineType))
        {
            facts.Add(new SummaryFact(
                "Machine Type",
                report.Host.Hardware.CloudMachineType,
                SummaryScope.Platform,
                SourceKind: nameof(HostHardwareInfo)));
        }

        AddSection(sections, EnvironmentSummarySectionKind.Platform, "Platform", facts);
    }

    private static void AddTrustSection(List<EnvironmentSummarySection> sections, ContainerRuntimeReport report)
    {
        var facts = report.TrustedPlatforms?
            .Where(summary => summary.State != TrustedPlatformState.None)
            .OrderByDescending(summary => summary.VerificationLevel)
            .Select(summary => new SummaryFact(
                summary.PlatformKey,
                $"{summary.State}, Level {summary.VerificationLevel}",
                SummaryScope.Platform,
                Level: summary.VerificationLevel,
                Confidence: MaxConfidence(summary.Claims.Select(claim => claim.Confidence).Concat(summary.Evidence.Select(evidence => evidence.Confidence))),
                SourceKind: nameof(TrustedPlatformSummary),
                EvidenceKeys: summary.Evidence.Select(item => item.Key).Distinct(StringComparer.Ordinal).ToArray()))
            .ToList() ?? [];

        AddSection(sections, EnvironmentSummarySectionKind.Trust, "Trust", facts);
    }

    private static void AddSection(List<EnvironmentSummarySection> sections, EnvironmentSummarySectionKind kind, string title, List<SummaryFact> facts)
    {
        if (facts.Count > 0)
        {
            sections.Add(new EnvironmentSummarySection(kind, title, facts));
        }
    }

    private static void AddClassificationFact(List<SummaryFact> facts, string label, string value, Confidence confidence, SummaryScope scope, IReadOnlyList<ClassificationReason> reasons)
    {
        if (confidence == Confidence.Unknown || string.Equals(value, KnownValues.Unknown, StringComparison.Ordinal))
        {
            return;
        }

        facts.Add(new SummaryFact(
            label,
            value,
            scope,
            Confidence: confidence,
            SourceKind: nameof(ReportClassification),
            EvidenceKeys: CollectEvidenceKeys(reasons)));
    }

    private static string? GetPreferredHostOs(ContainerRuntimeReport report)
    {
        var runtimeHostOs = FormatHostOs(report.Host.RuntimeReportedHostOs.Name, report.Host.RuntimeReportedHostOs.Version);
        if (!string.Equals(runtimeHostOs, KnownValues.Unknown, StringComparison.Ordinal))
        {
            return runtimeHostOs;
        }

        if (!string.IsNullOrWhiteSpace(report.Host.UnderlyingHostOs.Name))
        {
            return report.Host.UnderlyingHostOs.Name;
        }

        var kernel = JoinNonEmpty(report.Host.VisibleKernel.Name, report.Host.VisibleKernel.Release);
        return string.IsNullOrWhiteSpace(kernel) ? null : kernel;
    }

    private static string? GetVirtualizationValue(ContainerRuntimeReport report)
    {
        if (report.Host.Virtualization.Confidence == Confidence.Unknown || report.Host.Virtualization.Kind == VirtualizationKind.Unknown)
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(report.Host.Virtualization.PlatformVendor)
            ? report.Host.Virtualization.Kind.ToString()
            : $"{report.Host.Virtualization.Kind} ({report.Host.Virtualization.PlatformVendor})";
    }

    private static Confidence MaxConfidence(IEnumerable<Confidence> values)
        => values.DefaultIfEmpty(Confidence.Unknown).Max();

    private static IReadOnlyList<string> CollectEvidenceKeys(IEnumerable<ClassificationReason> reasons)
        => reasons.SelectMany(reason => reason.EvidenceKeys).Distinct(StringComparer.Ordinal).ToArray();

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

    private static string? FormatBytes(long? bytes)
    {
        if (bytes is null)
        {
            return null;
        }

        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        var units = new[] { "KB", "MB", "GB", "TB" };
        double value = bytes.Value;
        var index = -1;
        do
        {
            value /= 1024d;
            index++;
        }
        while (value >= 1024d && index < units.Length - 1);

        return $"{value:0.##} {units[index]}";
    }
}