using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

public sealed record EvidenceItem(string Source, string Key, string? Value, EvidenceSensitivity Sensitivity = EvidenceSensitivity.Public);

public sealed record ProbeFailure(string ProbeId, string Error, bool Timeout);

public sealed record ProbeResult(string ProbeId, IReadOnlyList<EvidenceItem> Evidence, ProbeFailure? Failure = null, TimeSpan? Duration = null);

public sealed record ClassificationResult(string Value, Confidence Confidence, IReadOnlyList<string> Reasons);

public sealed record ContainerRuntimeReport(
    DateTimeOffset GeneratedAt,
    TimeSpan Duration,
    IReadOnlyList<ProbeResult> Probes,
    ClassificationResult Containerization,
    ClassificationResult Runtime,
    ClassificationResult Orchestrator,
    ClassificationResult Cloud);

[JsonSerializable(typeof(ContainerRuntimeReport))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class ReportJsonContext : JsonSerializerContext;
