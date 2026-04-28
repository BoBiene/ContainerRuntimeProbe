using System.Diagnostics;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

public sealed class MarkerFileProbe : IProbe
{
    private static readonly string[] MarkerFiles = ["/.dockerenv", "/run/.containerenv"];
    public string Id => "marker-files";

    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = MarkerFiles
            .Select(path => new EvidenceItem(Id, path, File.Exists(path).ToString()))
            .ToList();
        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, evidence, Duration: sw.Elapsed));
    }
}

public sealed class EnvironmentProbe : IProbe
{
    private static readonly string[] Keys =
    [
        "DOTNET_RUNNING_IN_CONTAINER", "KUBERNETES_SERVICE_HOST", "ECS_CONTAINER_METADATA_URI_V4", "CONTAINER_APP_NAME",
        "K_SERVICE", "K_REVISION", "K_CONFIGURATION", "WEBSITE_SITE_NAME", "NOMAD_ALLOC_ID", "HOSTNAME"
    ];

    public string Id => "environment";

    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        foreach (var key in Keys)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var sensitive = key.Contains("TOKEN", StringComparison.OrdinalIgnoreCase) ? EvidenceSensitivity.Sensitive : EvidenceSensitivity.Public;
            evidence.Add(new EvidenceItem(Id, key, sensitive == EvidenceSensitivity.Sensitive && !context.IncludeSensitive ? "<redacted>" : value, sensitive));
        }

        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, evidence, Duration: sw.Elapsed));
    }
}

public sealed class CgroupProbe : IProbe
{
    public string Id => "cgroup";

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        const string path = "/proc/self/cgroup";
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
            cts.CancelAfter(context.Timeout);
            var lines = await File.ReadAllLinesAsync(path, cts.Token).ConfigureAwait(false);
            var evidence = lines.Take(20).Select(x => new EvidenceItem(Id, "line", x)).ToList();
            sw.Stop();
            return new ProbeResult(Id, evidence, Duration: sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new ProbeResult(Id, [], new ProbeFailure(Id, ex.Message, ex is OperationCanceledException), sw.Elapsed);
        }
    }
}
