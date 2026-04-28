using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

/// <summary>An observed evidence key/value emitted by a probe.</summary>
public sealed record EvidenceItem(string ProbeId, string Key, string? Value, EvidenceSensitivity Sensitivity = EvidenceSensitivity.Public);

/// <summary>A probe execution result with normalized outcome and evidence payload.</summary>
public sealed record ProbeResult(string ProbeId, ProbeOutcome Outcome, IReadOnlyList<EvidenceItem> Evidence, string? Message = null, TimeSpan? Duration = null);

/// <summary>Security warning surfaced at report level.</summary>
public sealed record SecurityWarning(string Code, string Message);

/// <summary>Reason object including evidence references used for an inferred classification.</summary>
public sealed record ClassificationReason(string Message, IReadOnlyList<string> EvidenceKeys);

/// <summary>Single classification value with confidence and justification.</summary>
public sealed record ClassificationResult(string Value, Confidence Confidence, IReadOnlyList<ClassificationReason> Reasons);

/// <summary>Container runtime report classification dimensions.</summary>
public sealed record ReportClassification(
    ClassificationResult IsContainerized,
    ClassificationResult ContainerRuntime,
    ClassificationResult RuntimeApi,
    ClassificationResult Orchestrator,
    ClassificationResult CloudProvider,
    ClassificationResult PlatformVendor);

/// <summary>Top-level report returned by the probe engine.</summary>
public sealed record ContainerRuntimeReport(
    DateTimeOffset GeneratedAt,
    TimeSpan Duration,
    IReadOnlyList<ProbeResult> Probes,
    IReadOnlyList<SecurityWarning> SecurityWarnings,
    ReportClassification Classification);

/// <summary>Source-generation context for JSON serialization.</summary>
[JsonSerializable(typeof(ContainerRuntimeReport))]
[JsonSourceGenerationOptions(WriteIndented = true, UseStringEnumConverter = true)]
public partial class ReportJsonContext : JsonSerializerContext;
