namespace ContainerRuntimeProbe.Abstractions;

public enum EvidenceSensitivity
{
    Public,
    Sensitive
}

public enum Confidence
{
    Unknown,
    Low,
    Medium,
    High
}

public sealed record ProbeContext(TimeSpan Timeout, bool IncludeSensitive, IReadOnlySet<string>? EnabledProbes, CancellationToken CancellationToken);

public interface IProbe
{
    string Id { get; }
    Task<Model.ProbeResult> ExecuteAsync(ProbeContext context);
}
