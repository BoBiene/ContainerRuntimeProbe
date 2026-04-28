using System.Diagnostics;
using System.Text;
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
            var text = Encoding.UTF8.GetString(buffer, 0, bytesRead);
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
            .Select(x =>
            {
                var isSensitive = x.k.Equals("HOSTNAME", StringComparison.OrdinalIgnoreCase) || Redaction.IsSensitiveKey(x.k);
                var value = isSensitive && !context.IncludeSensitive ? "<redacted>" : x.v;
                return new EvidenceItem(Id, x.k, value, isSensitive ? EvidenceSensitivity.Sensitive : EvidenceSensitivity.Public);
            })
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
        "/proc/version", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/ostype", "/proc/sys/kernel/version",
        "/proc/cpuinfo", "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/possible", "/sys/devices/system/cpu/present",
        "/proc/meminfo", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    ];

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var final = ProbeOutcome.Success;
        string? message = null;
        var osReleaseRead = false;
        string? procVersion = null;
        string? kernelOsRelease = null;
        string? kernelOsType = null;
        string? kernelVersion = null;

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
                var os = HostParsing.ParseOsRelease(text!);
                AddEvidenceIfPresent(evidence, "os.id", os.Id);
                foreach (var item in os.IdLike) evidence.Add(new EvidenceItem(Id, "os.id_like", item));
                AddEvidenceIfPresent(evidence, "os.name", os.Name);
                AddEvidenceIfPresent(evidence, "os.pretty_name", os.PrettyName);
                AddEvidenceIfPresent(evidence, "os.version", os.Version);
                AddEvidenceIfPresent(evidence, "os.version_id", os.VersionId);
                AddEvidenceIfPresent(evidence, "os.version_codename", os.VersionCodename);
                AddEvidenceIfPresent(evidence, "os.build_id", os.BuildId);
                AddEvidenceIfPresent(evidence, "os.variant", os.Variant);
                AddEvidenceIfPresent(evidence, "os.variant_id", os.VariantId);
                AddEvidenceIfPresent(evidence, "os.home_url", os.HomeUrl);
                AddEvidenceIfPresent(evidence, "os.support_url", os.SupportUrl);
                AddEvidenceIfPresent(evidence, "os.bug_report_url", os.BugReportUrl);
                osReleaseRead = true;
            }
            else if (file == "/proc/version")
            {
                procVersion = text;
                evidence.Add(new EvidenceItem(Id, file, text!.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()));
            }
            else if (file == "/proc/sys/kernel/osrelease")
            {
                kernelOsRelease = text;
                AddEvidenceIfPresent(evidence, "kernel.release", text?.Trim());
            }
            else if (file == "/proc/sys/kernel/ostype")
            {
                kernelOsType = text;
                AddEvidenceIfPresent(evidence, "kernel.name", text?.Trim());
            }
            else if (file == "/proc/sys/kernel/version")
            {
                kernelVersion = text;
                AddEvidenceIfPresent(evidence, "kernel.version", text?.Trim());
            }
            else if (file == "/proc/cpuinfo")
            {
                var cpu = HostParsing.ParseCpuInfo(text!);
                AddEvidenceIfPresent(evidence, "cpu.logical_processors", cpu.LogicalProcessorCount?.ToString());
                AddEvidenceIfPresent(evidence, "cpu.vendor", cpu.Vendor);
                AddEvidenceIfPresent(evidence, "cpu.model_name", cpu.ModelName);
                AddEvidenceIfPresent(evidence, "cpu.family", cpu.Family);
                AddEvidenceIfPresent(evidence, "cpu.model", cpu.Model);
                AddEvidenceIfPresent(evidence, "cpu.stepping", cpu.Stepping);
                AddEvidenceIfPresent(evidence, "cpu.microcode", cpu.Microcode);
                AddEvidenceIfPresent(evidence, "cpu.flags.count", cpu.FlagsCount?.ToString());
                AddEvidenceIfPresent(evidence, "cpu.flags.hash", cpu.FlagsHash is null ? null : $"sha256:{cpu.FlagsHash}");
                AddEvidenceIfPresent(evidence, "cpu.hardware", cpu.Hardware);
                AddEvidenceIfPresent(evidence, "cpu.revision", cpu.Revision);
                var sanitizedSerial = HostParsing.SanitizeCpuSerial(cpu.Serial, context.IncludeSensitive);
                if (!string.IsNullOrWhiteSpace(sanitizedSerial))
                {
                    evidence.Add(new EvidenceItem(Id, "cpu.serial", sanitizedSerial, EvidenceSensitivity.Sensitive));
                }
            }
            else if (file is "/sys/devices/system/cpu/online" or "/sys/devices/system/cpu/possible" or "/sys/devices/system/cpu/present")
            {
                var key = file.Split('/').Last();
                AddEvidenceIfPresent(evidence, $"cpu.{key}", text?.Trim());
                AddEvidenceIfPresent(evidence, $"cpu.{key}.count", HostParsing.ParseCpuRangeCount(text)?.ToString());
            }
            else if (file == "/proc/meminfo")
            {
                var memory = HostParsing.ParseMemInfo(text!);
                AddEvidenceIfPresent(evidence, "memory.mem_total_bytes", memory.MemTotalBytes?.ToString());
                AddEvidenceIfPresent(evidence, "memory.mem_available_bytes", memory.MemAvailableBytes?.ToString());
            }
            else if (file is "/sys/fs/cgroup/memory.max" or "/sys/fs/cgroup/memory/memory.limit_in_bytes")
            {
                AddEvidenceIfPresent(evidence, "memory.cgroup.limit_raw", text?.Trim());
                AddEvidenceIfPresent(evidence, "memory.cgroup.limit_bytes", NormalizeCgroupBytes(text)?.ToString());
            }
            else if (file is "/sys/fs/cgroup/memory.current" or "/sys/fs/cgroup/memory/memory.usage_in_bytes")
            {
                AddEvidenceIfPresent(evidence, "memory.cgroup.current_bytes", HostParsing.ParseNullableLong(text)?.ToString());
            }
            else if (file == "/sys/fs/cgroup/cpu.max")
            {
                var raw = text?.Trim();
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    evidence.Add(new EvidenceItem(Id, "cpu.cgroup.max", raw));
                    var parts = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (parts.Length > 0 && parts[0] != "max")
                    {
                        AddEvidenceIfPresent(evidence, "cpu.cgroup.quota", parts[0]);
                    }
                }
            }
            else if (file == "/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
            {
                AddEvidenceIfPresent(evidence, "cpu.cgroup.quota", HostParsing.ParseNullableLong(text)?.ToString());
            }
            else
            {
                var value = text!.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (file is "/etc/hostname" or "/proc/sys/kernel/hostname")
                {
                    evidence.Add(new EvidenceItem(Id, file, context.IncludeSensitive ? value : "redacted", EvidenceSensitivity.Sensitive));
                }
                else
                {
                    evidence.Add(new EvidenceItem(Id, file, value));
                }
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

        var kernel = HostParsing.ParseKernel(procVersion, kernelOsRelease, kernelOsType, kernelVersion);
        AddEvidenceIfPresent(evidence, "kernel.name", kernel.Name);
        AddEvidenceIfPresent(evidence, "kernel.release", kernel.Release);
        AddEvidenceIfPresent(evidence, "kernel.version", kernel.Version);
        AddEvidenceIfPresent(evidence, "kernel.compiler", kernel.Compiler);
        if (kernel.Flavor != KernelFlavor.Unknown)
        {
            evidence.Add(new EvidenceItem(Id, "kernel.flavor", kernel.Flavor.ToString()));
        }

        sw.Stop();
        return new ProbeResult(Id, final, evidence, message, sw.Elapsed);
    }

    private static void AddEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem("proc-files", key, value.Trim()));
        }
    }

    private static long? NormalizeCgroupBytes(string? raw)
    {
        var value = raw?.Trim();
        return value == "max" ? null : HostParsing.ParseNullableLong(value);
    }
}

/// <summary>Probes Linux security and sandbox attributes for the current process.</summary>
internal sealed class SecuritySandboxProbe : IProbe
{
    public string Id => "security-sandbox";

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();

        // /proc/self/status: Seccomp, NoNewPrivs, CapEff, CapBnd, CapPrm
        var (statusOc, statusText, _) = await ProbeIo.ReadFileAsync("/proc/self/status", context.Timeout, context.CancellationToken).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "proc.self.status.outcome", statusOc.ToString()));
        if (statusOc == ProbeOutcome.Success && statusText is not null)
        {
            foreach (var line in statusText.Split('\n'))
            {
                foreach (var field in new[] { "Seccomp", "NoNewPrivs", "CapEff", "CapBnd", "CapPrm" })
                {
                    if (line.StartsWith(field, StringComparison.Ordinal))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                            evidence.Add(new EvidenceItem(Id, $"status.{field}", parts[1].Trim()));
                    }
                }
            }
        }

        // /proc/self/attr/current: AppArmor profile name or SELinux context
        var (attrOc, attrText, _) = await ProbeIo.ReadFileAsync("/proc/self/attr/current", context.Timeout, context.CancellationToken).ConfigureAwait(false);
        if (attrOc == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(attrText))
        {
            var attr = attrText.Trim('\n', '\0', ' ');
            // SELinux context contains ':' separators; AppArmor is a plain label or "unconfined"
            var key = attr.Contains(':') ? "selinux.context" : "apparmor.profile";
            evidence.Add(new EvidenceItem(Id, key, attr));
        }

        // /sys/fs/selinux: directory existence indicates SELinux is mounted
        evidence.Add(new EvidenceItem(Id, "selinux.mount.present", Directory.Exists("/sys/fs/selinux").ToString()));

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed);
    }
}
