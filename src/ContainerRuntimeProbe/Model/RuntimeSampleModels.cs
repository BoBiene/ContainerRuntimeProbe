using System.Text.Json.Serialization;

namespace ContainerRuntimeProbe.Model;

/// <summary>Options for generating compact runtime samples and issue-prefill content.</summary>
public sealed record RuntimeSampleOptions(
    string Repository = "BoBiene/ContainerRuntimeProbe",
    string? Scenario = null,
    string? Expected = null,
    string Format = "compact",
    string BodyFormat = "compact",
    string IssueTemplate = "runtime-sample.yml",
    int MaxUrlLength = 2000,
    bool IncludeSensitive = false);

/// <summary>Rendered artifacts for a runtime sample sharing flow.</summary>
public sealed record RuntimeSampleArtifacts(
    string CompactSample,
    string ScenarioName,
    string CompactBody,
    string ExpandedBody,
    string PrefillUrl,
    IReadOnlyList<string> UrlWarnings,
    RuntimeSampleDocument Document,
    IReadOnlyList<string> SummaryLines);

/// <summary>JSON wrapper for a portable runtime sample.</summary>
public sealed record RuntimeSampleDocument(
    string Schema,
    string SchemaVersion,
    string CompactFormat,
    string CompactSample,
    RuntimeSampleToolInfo Tool,
    RuntimeSamplePayload Sample);

/// <summary>Tool metadata emitted with sample exports.</summary>
public sealed record RuntimeSampleToolInfo(string Name, string Version);

/// <summary>Runtime sample payload.</summary>
public sealed record RuntimeSamplePayload(
    string Id,
    DateTimeOffset CreatedAt,
    string ScenarioName,
    string? UserProvidedScenarioName,
    string EnvironmentKind,
    string? ExpectedClassification,
    RuntimeSampleClassification ActualClassification,
    RuntimeSampleClassificationConfidence Confidence,
    RuntimeSampleHost Host,
    IReadOnlyList<RuntimeSampleSignal> ImportantSignals,
    RuntimeSampleProbeOutcomes ProbeOutcomes,
    IReadOnlyList<string> SecurityWarnings,
    RuntimeSampleRedaction Redaction);

/// <summary>Important normalized signal retained in the sample.</summary>
public sealed record RuntimeSampleSignal(string Key, string Value, string Tag);

/// <summary>Normalized classification values.</summary>
public sealed record RuntimeSampleClassification(
    string IsContainerized,
    string ContainerRuntime,
    string RuntimeApi,
    string Orchestrator,
    string CloudProvider,
    string PlatformVendor);

/// <summary>Classification confidence values.</summary>
public sealed record RuntimeSampleClassificationConfidence(
    string IsContainerized,
    string ContainerRuntime,
    string RuntimeApi,
    string Orchestrator,
    string CloudProvider,
    string PlatformVendor);

/// <summary>Host-facing normalized sample data.</summary>
public sealed record RuntimeSampleHost(
    RuntimeSampleContainerImageOs ContainerImageOs,
    RuntimeSampleVisibleKernel VisibleKernel,
    RuntimeSampleRuntimeReportedHostOs RuntimeReportedHostOs,
    RuntimeSampleHardware Hardware,
    RuntimeSampleFingerprint? Fingerprint);

/// <summary>Container image OS sample view.</summary>
public sealed record RuntimeSampleContainerImageOs(
    string Family,
    string? Id,
    string? Version,
    string? PrettyName,
    string Architecture);

/// <summary>Visible kernel sample view.</summary>
public sealed record RuntimeSampleVisibleKernel(
    string? Name,
    string? Release,
    string? NormalizedRelease,
    string Flavor,
    string Architecture,
    RuntimeSampleKernelCompiler? Compiler);

/// <summary>Visible kernel compiler sample view.</summary>
public sealed record RuntimeSampleKernelCompiler(
    string? Name,
    string? Version,
    string? DistributionHint,
    string? DistributionVersionHint);

/// <summary>Runtime or platform reported host OS sample view.</summary>
public sealed record RuntimeSampleRuntimeReportedHostOs(
    string Source,
    string? Name,
    string? Version,
    string Architecture);

/// <summary>Visible hardware sample view.</summary>
public sealed record RuntimeSampleHardware(
    string Architecture,
    string? CpuVendor,
    string? CpuFamily,
    string? CpuModelName,
    int? LogicalProcessorCount,
    int? VisibleProcessorCount,
    string? CpuFlagsHash,
    long? MemoryTotalBytes,
    string? MemoryTotalBucket,
    string? CgroupMemoryLimitRaw);

/// <summary>Privacy-aware fingerprint sample view.</summary>
public sealed record RuntimeSampleFingerprint(
    string Algorithm,
    string Value,
    string ShortValue,
    string Stability,
    int IncludedSignalCount,
    int ExcludedSensitiveSignalCount);

/// <summary>Normalized per-probe outcomes.</summary>
public sealed record RuntimeSampleProbeOutcomes(
    string MarkerFiles,
    string Environment,
    string ProcFiles,
    string SecuritySandbox,
    string RuntimeApi,
    string Kubernetes,
    string CloudMetadata);

/// <summary>Sample redaction summary.</summary>
public sealed record RuntimeSampleRedaction(
    string Mode,
    bool FullReportContainsSensitiveValues,
    IReadOnlyList<string> ExcludedFromIssueUrl);

/// <summary>Source-generation context for runtime sample JSON serialization.</summary>
[JsonSerializable(typeof(RuntimeSampleDocument))]
[JsonSourceGenerationOptions(WriteIndented = true, UseStringEnumConverter = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
public partial class SampleJsonContext : JsonSerializerContext;
