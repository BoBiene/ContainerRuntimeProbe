namespace ContainerRuntimeProbe.Abstractions;

public enum EvidenceSensitivity { Public, Sensitive }
public enum Confidence { Unknown, Low, Medium, High }
public enum ProbeOutcome { Success, Unavailable, AccessDenied, Timeout, NotSupported, Error }

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

public interface IProbe
{
    string Id { get; }
    Task<Model.ProbeResult> ExecuteAsync(ProbeContext context);
}
