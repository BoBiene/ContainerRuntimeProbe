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
        _probes = (probes ?? new IProbe[] { new MarkerFileProbe(), new EnvironmentProbe(), new CgroupProbe() }).ToList();
    }

    public async Task<ContainerRuntimeReport> RunAsync(TimeSpan timeout, bool includeSensitive, IReadOnlySet<string>? enabledProbes = null, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var context = new ProbeContext(timeout, includeSensitive, enabledProbes, cancellationToken);
        var selected = enabledProbes is null || enabledProbes.Count == 0
            ? _probes
            : _probes.Where(p => enabledProbes.Contains(p.Id)).ToList();

        var results = new List<ProbeResult>();
        foreach (var probe in selected)
        {
            results.Add(await probe.ExecuteAsync(context).ConfigureAwait(false));
        }

        var classifications = Classifier.Classify(results);
        sw.Stop();
        return new ContainerRuntimeReport(DateTimeOffset.UtcNow, sw.Elapsed, results, classifications.Containerization, classifications.Runtime, classifications.Orchestrator, classifications.Cloud);
    }
}
