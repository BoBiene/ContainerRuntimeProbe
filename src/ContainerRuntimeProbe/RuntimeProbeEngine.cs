using System.Diagnostics;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe;

public sealed class RuntimeProbeEngine
{
    private readonly IReadOnlyList<IProbe> _probes;

    public RuntimeProbeEngine(IEnumerable<IProbe>? probes = null)
    {
        _probes = (probes ?? new IProbe[]
        {
            new MarkerFileProbe(),
            new EnvironmentProbe(),
            new ProcFilesProbe(),
            new RuntimeApiProbe(),
            new KubernetesProbe(),
            new CloudMetadataProbe()
        }).ToList();
    }

    public IReadOnlyList<string> ProbeIds => _probes.Select(p => p.Id).ToList();

    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes = null, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var context = new ProbeContext(timeout, includeSensitive, enabledProbes, null, null, null, null, null, cancellationToken);
        var selected = enabledProbes is null || enabledProbes.Count == 0 ? _probes : _probes.Where(p => enabledProbes.Contains(p.Id)).ToList();

        var results = new List<ProbeResult>();
        foreach (var probe in selected)
        {
            results.Add(await probe.ExecuteAsync(context).ConfigureAwait(false));
        }

        var warnings = new List<SecurityWarning>();
        if (results.SelectMany(r => r.Evidence).Any(e => e.Key == "socket.present" && e.Value?.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) == true))
        {
            warnings.Add(new SecurityWarning("DOCKER_SOCKET_MOUNTED", "Docker-compatible socket is accessible and can imply privileged host control."));
        }

        var classification = Classifier.Classify(results);
        sw.Stop();
        return new ContainerRuntimeReport(DateTimeOffset.UtcNow, sw.Elapsed, results, warnings, classification);
    }
}
