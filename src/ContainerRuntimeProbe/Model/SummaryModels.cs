using ContainerRuntimeProbe.Abstractions;

namespace ContainerRuntimeProbe.Model;

/// <summary>Identifies the scope described by a summary fact.</summary>
public enum SummaryScope
{
    /// <summary>The scope could not be determined.</summary>
    Unknown,

    /// <summary>The scope describes the runtime implementation or API surface.</summary>
    Runtime,

    /// <summary>The scope describes the currently running workload instance.</summary>
    Workload,

    /// <summary>The scope describes a more stable deployment-level identity.</summary>
    Deployment,

    /// <summary>The scope describes the node that hosts the current workload.</summary>
    Node,

    /// <summary>The scope describes a platform runtime or appliance environment.</summary>
    Platform,

    /// <summary>The scope describes the underlying host machine or instance.</summary>
    Host
}

/// <summary>Describes how a summary fact can be consumed.</summary>
public enum SummaryUsageKind
{
    /// <summary>The fact is informational and not intended as an identity candidate.</summary>
    Informational,

    /// <summary>The fact is suitable for correlation-oriented consumers.</summary>
    Correlation,

    /// <summary>The fact is a visible candidate for stronger binding decisions.</summary>
    BindingCandidate
}

/// <summary>Identifies the broad system variant summarized by a report.</summary>
public enum SummaryVariantKind
{
    /// <summary>The broad system variant could not be determined.</summary>
    Unknown,

    /// <summary>The report describes a non-containerized Windows host.</summary>
    WindowsBare,

    /// <summary>The report describes a standalone container workload outside a cluster.</summary>
    StandaloneContainer,

    /// <summary>The report describes an industrial or appliance-oriented container workload.</summary>
    IndustrialContainer,

    /// <summary>The report describes a Kubernetes-managed workload.</summary>
    KubernetesWorkload
}

/// <summary>Identifies a top-level environment summary section.</summary>
public enum EnvironmentSummarySectionKind
{
    /// <summary>The section kind could not be determined.</summary>
    Unknown,

    /// <summary>The section summarizes runtime details.</summary>
    Runtime,

    /// <summary>The section summarizes execution-context signals.</summary>
    ExecutionContext,

    /// <summary>The section summarizes host details.</summary>
    Host,

    /// <summary>The section summarizes platform details.</summary>
    Platform,

    /// <summary>The section summarizes trust or verification signals.</summary>
    Trust
}

/// <summary>Identifies a top-level identity summary section.</summary>
public enum IdentitySummarySectionKind
{
    /// <summary>The section kind could not be determined.</summary>
    Unknown,

    /// <summary>The section summarizes workload-scoped identity candidates.</summary>
    WorkloadIdentity,

    /// <summary>The section summarizes deployment-scoped identity candidates.</summary>
    DeploymentIdentity,

    /// <summary>The section summarizes node- or platform-scoped identity candidates.</summary>
    NodePlatformIdentity,

    /// <summary>The section summarizes host-scoped identity candidates.</summary>
    HostIdentity
}

/// <summary>Represents a compact, structured fact surfaced in a summary section.</summary>
public sealed record SummaryFact(
    string Label,
    string Value,
    SummaryScope Scope = SummaryScope.Unknown,
    int? Level = null,
    Confidence Confidence = Confidence.Unknown,
    string? SourceKind = null,
    SummaryUsageKind Usage = SummaryUsageKind.Informational,
    IReadOnlyList<string>? EvidenceKeys = null);

/// <summary>Represents one neutral environment summary section.</summary>
public sealed record EnvironmentSummarySection(
    EnvironmentSummarySectionKind Kind,
    string Title,
    IReadOnlyList<SummaryFact> Facts);

/// <summary>Represents one identity summary section.</summary>
public sealed record IdentitySummarySection(
    IdentitySummarySectionKind Kind,
    string Title,
    IReadOnlyList<SummaryFact> Facts);

/// <summary>Compact environment-oriented summary facts for a report.</summary>
public sealed record EnvironmentSummary(
    IReadOnlyList<EnvironmentSummarySection> Sections);

/// <summary>Compact scope-oriented identity facts for a report.</summary>
public sealed record IdentitySummary(
    IReadOnlyList<IdentitySummarySection> Sections);

/// <summary>Top-level structured summary attached to a report.</summary>
public sealed record ReportSummary(
    EnvironmentSummary Environment,
    IdentitySummary Identity);