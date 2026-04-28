using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

public sealed record EvidenceItem(string ProbeId, string Key, string? Value, EvidenceSensitivity Sensitivity = EvidenceSensitivity.Public);
public sealed record ProbeResult(string ProbeId, ProbeOutcome Outcome, IReadOnlyList<EvidenceItem> Evidence, string? Message = null, TimeSpan? Duration = null);
public sealed record SecurityWarning(string Code, string Message);
public sealed record ClassificationReason(string Message, IReadOnlyList<string> EvidenceKeys);
public sealed record ClassificationResult(string Value, Confidence Confidence, IReadOnlyList<ClassificationReason> Reasons);

public sealed record ReportClassification(
    ClassificationResult IsContainerized,
    ClassificationResult ContainerRuntime,
    ClassificationResult RuntimeApi,
    ClassificationResult Orchestrator,
    ClassificationResult CloudProvider,
    ClassificationResult PlatformVendor);

public sealed record ContainerRuntimeReport(
    DateTimeOffset GeneratedAt,
    TimeSpan Duration,
    IReadOnlyList<ProbeResult> Probes,
    IReadOnlyList<SecurityWarning> SecurityWarnings,
    ReportClassification Classification);

[JsonSerializable(typeof(ContainerRuntimeReport))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class ReportJsonContext : JsonSerializerContext;
