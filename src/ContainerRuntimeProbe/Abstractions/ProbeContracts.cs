namespace ContainerRuntimeProbe.Abstractions;

/// <summary>Represents the sensitivity level of evidence values.</summary>
public enum EvidenceSensitivity
{
    /// <summary>Evidence is safe for default output.</summary>
    Public,
    /// <summary>Evidence may contain sensitive data and should be redacted by default.</summary>
    Sensitive
}

/// <summary>Represents confidence level for an inferred classification.</summary>
public enum Confidence
{
    /// <summary>No meaningful confidence can be assigned.</summary>
    Unknown,
    /// <summary>Weak evidence set.</summary>
    Low,
    /// <summary>Moderate evidence set.</summary>
    Medium,
    /// <summary>Strong corroborated evidence set.</summary>
    High
}

/// <summary>Represents normalized outcomes for probe execution.</summary>
public enum ProbeOutcome
{
    /// <summary>Probe completed and returned evidence.</summary>
    Success,
    /// <summary>Expected resource is not available.</summary>
    Unavailable,
    /// <summary>Access was denied.</summary>
    AccessDenied,
    /// <summary>Probe timed out.</summary>
    Timeout,
    /// <summary>Probe is not supported on current platform.</summary>
    NotSupported,
    /// <summary>Unexpected error occurred.</summary>
    Error
}

/// <summary>Context passed to each probe execution.</summary>
public sealed record ProbeContext(
    TimeSpan Timeout,
    bool IncludeSensitive,
    IReadOnlySet<string>? EnabledProbes,
    Uri? KubernetesApiBase,
    Uri? AwsImdsBase,
    Uri? AzureImdsBase,
    Uri? GcpMetadataBase,
    Uri? OciMetadataBase,
    CancellationToken CancellationToken);

/// <summary>Abstraction for an evidence probe.</summary>
public interface IProbe
{
    /// <summary>Stable probe identifier used in report output and filtering.</summary>
    string Id { get; }

    /// <summary>Executes the probe and returns structured evidence.</summary>
    Task<Model.ProbeResult> ExecuteAsync(ProbeContext context);
}
