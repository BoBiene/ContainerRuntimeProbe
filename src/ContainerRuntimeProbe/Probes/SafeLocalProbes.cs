using System.Diagnostics;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal static class ProbeIo
{
    /// <summary>Maximum number of bytes to read from a probe file. Prevents memory issues on large /proc files.</summary>
    private const int MaxReadBytes = 262_144; // 256 KB

    public static async Task<(ProbeOutcome outcome, string? text, string? message)> ReadFileAsync(string path, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true);
            var buffer = new byte[MaxReadBytes];
            var bytesRead = await fs.ReadAsync(buffer.AsMemory(0, MaxReadBytes), cts.Token).ConfigureAwait(false);
            var text = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
            // If we read exactly MaxReadBytes, file may have been truncated silently; signal this in the message
            var message = bytesRead == MaxReadBytes ? $"[truncated at {MaxReadBytes} bytes]" : null;
            return (ProbeOutcome.Success, text, message);
        }
        catch (UnauthorizedAccessException ex) { return (ProbeOutcome.AccessDenied, null, ex.Message); }
        catch (OperationCanceledException ex) { return (ProbeOutcome.Timeout, null, ex.Message); }
        catch (FileNotFoundException ex) { return (ProbeOutcome.Unavailable, null, ex.Message); }
        catch (DirectoryNotFoundException ex) { return (ProbeOutcome.Unavailable, null, ex.Message); }
        catch (Exception ex) { return (ProbeOutcome.Error, null, ex.Message); }
    }
}

internal sealed class MarkerFileProbe : IProbe
{
    public string Id => "marker-files";
    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var e = new[]
        {
            new EvidenceItem(Id, "/.dockerenv", File.Exists("/.dockerenv").ToString()),
            new EvidenceItem(Id, "/run/.containerenv", File.Exists("/run/.containerenv").ToString())
        };
        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, ProbeOutcome.Success, e, Duration: sw.Elapsed));
    }
}

internal sealed class EnvironmentProbe : IProbe
{
    public string Id => "environment";
    private static readonly string[] Keys =
    [
        "DOTNET_RUNNING_IN_CONTAINER", "container", "CONTAINER", "HOSTNAME", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
        "ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4", "AWS_EXECUTION_ENV", "AWS_REGION", "AWS_DEFAULT_REGION",
        "WEBSITE_SITE_NAME", "WEBSITE_INSTANCE_ID", "CONTAINER_APP_NAME", "CONTAINER_APP_REVISION", "K_SERVICE", "K_REVISION",
        "K_CONFIGURATION", "NOMAD_ALLOC_ID", "NOMAD_JOB_NAME", "OPENSHIFT_BUILD_NAME", "OPENSHIFT_BUILD_NAMESPACE",
        "IOTEDGE_MODULEID", "IOTEDGE_DEVICEID", "IOTEDGE_WORKLOADURI", "IOTEDGE_APIVERSION", "IOTEDGE_AUTHSCHEME", "IOTEDGE_GATEWAYHOSTNAME"
    ];

    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = Keys.Select(k => (k, v: Environment.GetEnvironmentVariable(k)))
            .Where(x => !string.IsNullOrWhiteSpace(x.v))
            .Select(x => new EvidenceItem(Id, x.k, Redaction.MaybeRedact(x.k, x.v, context.IncludeSensitive), Redaction.IsSensitiveKey(x.k) ? EvidenceSensitivity.Sensitive : EvidenceSensitivity.Public))
            .ToList();
        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed));
    }
}

internal sealed class ProcFilesProbe : IProbe
{
    public string Id => "proc-files";
    private static readonly string[] Files =
    [
        "/proc/1/cgroup", "/proc/self/cgroup",
        "/proc/self/mountinfo", "/proc/1/mountinfo",
        "/proc/net/route", "/etc/resolv.conf",
        "/etc/hostname", "/proc/sys/kernel/hostname",
        "/etc/os-release", "/usr/lib/os-release",
        "/proc/version", "/proc/self/status"
    ];

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var final = ProbeOutcome.Success;
        string? message = null;
        var osReleaseRead = false;

        foreach (var file in Files)
        {
            // Skip /usr/lib/os-release if /etc/os-release was successfully read
            if (file == "/usr/lib/os-release" && osReleaseRead) continue;

            var (outcome, text, msg) = await ProbeIo.ReadFileAsync(file, context.Timeout, context.CancellationToken).ConfigureAwait(false);
            if (outcome != ProbeOutcome.Success)
            {
                if (outcome != ProbeOutcome.Unavailable)
                {
                    final = outcome;
                    message = msg;
                }
                evidence.Add(new EvidenceItem(Id, file, outcome.ToString()));
                continue;
            }

            if (file == "/proc/1/cgroup" || file == "/proc/self/cgroup")
            {
                foreach (var signal in Parsing.ParseCgroupSignals(text!))
                    evidence.Add(new EvidenceItem(Id, $"{file}:signal", signal));
            }
            else if (file.Contains("mountinfo", StringComparison.Ordinal))
            {
                foreach (var signal in Parsing.ParseMountInfoSignals(text!)) evidence.Add(new EvidenceItem(Id, $"{file}:signal", signal));
            }
            else if (file == "/proc/net/route")
            {
                foreach (var dev in Parsing.ParseDefaultRoutes(text!)) evidence.Add(new EvidenceItem(Id, "default-route-device", dev));
            }
            else if (file == "/etc/resolv.conf")
            {
                foreach (var domain in Parsing.ParseResolvSearchDomains(text!)) evidence.Add(new EvidenceItem(Id, "dns-search", domain));
                if (text!.Contains("127.0.0.11", StringComparison.Ordinal)) evidence.Add(new EvidenceItem(Id, "docker-dns", "127.0.0.11"));
            }
            else if (file == "/etc/os-release" || file == "/usr/lib/os-release")
            {
                var kv = Parsing.ParseKeyValueLines(text!.Split('\n'));
                if (kv.TryGetValue("ID", out var id)) evidence.Add(new EvidenceItem(Id, "os.id", id));
                if (kv.TryGetValue("VERSION_ID", out var ver)) evidence.Add(new EvidenceItem(Id, "os.version", ver));
                osReleaseRead = true;
            }
            else if (file == "/proc/self/status")
            {
                foreach (var line in text!.Split('\n').Where(l => l.StartsWith("Seccomp") || l.StartsWith("NoNewPrivs") || l.StartsWith("CapEff")))
                {
                    var p = line.Split(':', 2);
                    if (p.Length == 2) evidence.Add(new EvidenceItem(Id, $"status.{p[0].Trim()}", p[1].Trim()));
                }
            }
            else
            {
                evidence.Add(new EvidenceItem(Id, file, text!.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()));
            }
        }

        foreach (var ns in new[] { "pid", "mnt", "net", "uts", "ipc" })
        {
            var path = $"/proc/self/ns/{ns}";
            try
            {
                var target = new FileInfo(path).LinkTarget;
                evidence.Add(new EvidenceItem(Id, $"ns.{ns}", target ?? "unknown"));
            }
            catch
            {
                evidence.Add(new EvidenceItem(Id, $"ns.{ns}", "unavailable"));
            }
        }

        // cgroup v2 memory limit (if available)
        foreach (var limitFile in new[] { "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes" })
        {
            var (oc, txt, _) = await ProbeIo.ReadFileAsync(limitFile, context.Timeout, context.CancellationToken).ConfigureAwait(false);
            if (oc == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(txt))
                evidence.Add(new EvidenceItem(Id, $"cgroup.memory.limit:{limitFile}", txt.Trim()));
        }

        sw.Stop();
        return new ProbeResult(Id, final, evidence, message, sw.Elapsed);
    }
}
