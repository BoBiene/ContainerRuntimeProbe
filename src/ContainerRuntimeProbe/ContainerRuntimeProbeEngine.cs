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
        _probes = (probes ?? new IProbe[]
        {
            new MarkerFileProbe(),
            new EnvironmentProbe(),
            new ProcFilesProbe(),
            new SecuritySandboxProbe(),
            new RuntimeApiProbe(),
            new KubernetesProbe(),
            new CloudMetadataProbe()
        }).ToList();
    }

    /// <summary>Returns the available probe identifiers.</summary>
    public IReadOnlyList<string> ProbeIds => _probes.Select(p => p.Id).ToList();

    /// <summary>Executes selected probes and returns a complete container runtime report.</summary>
    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes = null, FingerprintMode fingerprintMode = FingerprintMode.Safe, CancellationToken cancellationToken = default)
        => await RunAsync(timeout, includeSensitive, enabledProbes, fingerprintMode, KubernetesTlsVerificationMode.Compatibility, cancellationToken).ConfigureAwait(false);

    /// <summary>Executes selected probes and returns a complete container runtime report.</summary>
    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes, FingerprintMode fingerprintMode, KubernetesTlsVerificationMode kubernetesTlsVerificationMode, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var context = new ProbeContext(timeout, includeSensitive, enabledProbes, null, null, null, null, null, cancellationToken, kubernetesTlsVerificationMode);
        var selected = enabledProbes is null || enabledProbes.Count == 0 ? _probes : _probes.Where(p => enabledProbes.Contains(p.Id)).ToList();
        var results = (await Task.WhenAll(selected.Select(probe => probe.ExecuteAsync(context))).ConfigureAwait(false)).ToList();

        var warnings = new List<SecurityWarning>();
        if (results.SelectMany(r => r.Evidence).Any(e => e.Key == "socket.present" && e.Value?.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) == true))
        {
            warnings.Add(new SecurityWarning("DOCKER_SOCKET_MOUNTED", "Docker-compatible socket is accessible and can imply privileged host control."));
        }

        if (results.SelectMany(r => r.Evidence).Any(e => e.Key == "api.tls.verification" && e.Value == "compatibility-skip-validation"))
        {
            warnings.Add(new SecurityWarning("KUBERNETES_TLS_VALIDATION_SKIPPED", "Kubernetes API TLS certificate validation was skipped for compatibility. Use strict Kubernetes TLS mode to enforce platform trust validation."));
        }

        var classification = Classifier.Classify(results);
        var host = HostReportBuilder.Build(results, classification, fingerprintMode);
        var probeToolInfo = VersionInfo.GetProbeToolMetadata();
        sw.Stop();
        return new ContainerRuntimeReport(DateTimeOffset.UtcNow, sw.Elapsed, probeToolInfo, results, warnings, classification, host);
    }
}
