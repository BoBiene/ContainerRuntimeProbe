using System.Diagnostics;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe;

/// <summary>
/// Runs configured probes, collects evidence and returns a normalized report with weighted classification.
/// </summary>
public sealed class ContainerRuntimeProbeEngine
{
    private readonly IReadOnlyList<IProbe> _probes;

    /// <summary>Initializes an engine with the default probe set or a custom probe collection.</summary>
    public ContainerRuntimeProbeEngine(IEnumerable<IProbe>? probes = null)
    {
        _probes = (probes ?? CreateDefaultProbes()).ToList();
    }

    private static IEnumerable<IProbe> CreateDefaultProbes()
    {
        yield return new MarkerFileProbe();
        yield return new EnvironmentProbe();
        yield return new PlatformContextProbe();
        yield return new SiemensIedRuntimeProbe();

        if (OperatingSystem.IsWindows())
        {
            yield return new WindowsHostProbe();
            yield return new WindowsTpmProbe();
        }
        else
        {
            yield return new UnixHostProbe();
        }

        yield return new SecuritySandboxProbe();
        yield return new RuntimeApiProbe();
        yield return new KubernetesProbe();
        yield return new CloudMetadataProbe();
    }

    /// <summary>Returns the available probe identifiers.</summary>
    public IReadOnlyList<string> ProbeIds => _probes.Select(p => p.Id).ToList();

    /// <summary>Executes selected probes and returns a complete container runtime report.</summary>
    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes = null, FingerprintMode fingerprintMode = FingerprintMode.Safe, CancellationToken cancellationToken = default)
        => await RunAsync(timeout, includeSensitive, new ProbeExecutionOptions
        {
            EnabledProbes = enabledProbes,
            FingerprintMode = fingerprintMode
        }, cancellationToken).ConfigureAwait(false);

    /// <summary>Executes selected probes and returns a complete container runtime report.</summary>
    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes, FingerprintMode fingerprintMode, KubernetesTlsVerificationMode kubernetesTlsVerificationMode, CancellationToken cancellationToken = default)
        => await RunAsync(timeout, includeSensitive, new ProbeExecutionOptions
        {
            EnabledProbes = enabledProbes,
            FingerprintMode = fingerprintMode,
            KubernetesTlsVerificationMode = kubernetesTlsVerificationMode
        }, cancellationToken).ConfigureAwait(false);

    /// <summary>Executes selected probes and returns a complete container runtime report.</summary>
    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, ProbeExecutionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sw = Stopwatch.StartNew();
        var context = new ProbeContext(
            timeout,
            includeSensitive,
            options.EnabledProbes,
            options.KubernetesApiBase,
            options.AwsImdsBase,
            options.AzureImdsBase,
            options.GcpMetadataBase,
            options.OciMetadataBase,
            cancellationToken,
            options.KubernetesTlsVerificationMode);
        var selected = options.EnabledProbes is null || options.EnabledProbes.Count == 0 ? _probes : _probes.Where(p => options.EnabledProbes.Contains(p.Id)).ToList();
        var rawResults = (await Task.WhenAll(selected.Select(probe => probe.ExecuteAsync(context))).ConfigureAwait(false)).ToList();
        var results = rawResults.Select(result => Redaction.RedactProbeResult(result, includeSensitive)).ToList();

        var warnings = new List<SecurityWarning>();
        if (rawResults.SelectMany(r => r.Evidence).Any(e => e.Key == "socket.present" && e.Value?.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) == true))
        {
            warnings.Add(new SecurityWarning("DOCKER_SOCKET_MOUNTED", "Docker-compatible socket is accessible and can imply privileged host control."));
        }

        if (rawResults.SelectMany(r => r.Evidence).Any(e => e.Key == "api.tls.verification" && e.Value == "compatibility-skip-validation"))
        {
            warnings.Add(new SecurityWarning("KUBERNETES_TLS_VALIDATION_SKIPPED", "Kubernetes API TLS certificate validation was skipped for compatibility. Use strict Kubernetes TLS mode to enforce platform trust validation."));
        }

        var rawPlatformEvidence = PlatformEvidenceBuilder.Build(rawResults);
        var rawTrustedPlatforms = TrustedPlatformBuilder.Build(rawResults);
        var classification = Classifier.Classify(rawResults, rawPlatformEvidence, rawTrustedPlatforms);
        var host = HostReportBuilder.Build(rawResults, classification, options.FingerprintMode);
        var platformEvidence = Redaction.RedactPlatformEvidence(rawPlatformEvidence, rawResults, includeSensitive);
        var trustedPlatforms = Redaction.RedactTrustedPlatforms(rawTrustedPlatforms, rawResults, includeSensitive);
        var probeToolInfo = VersionInfo.GetProbeToolMetadata();
        sw.Stop();
        return new ContainerRuntimeReport(DateTimeOffset.UtcNow, sw.Elapsed, probeToolInfo, results, warnings, classification, host, platformEvidence, trustedPlatforms);
    }
}
