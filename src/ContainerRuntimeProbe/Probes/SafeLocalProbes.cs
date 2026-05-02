using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal static class ProbeIo
{
    /// <summary>Maximum number of bytes to read from a probe file. Prevents memory issues on large /proc files.</summary>
    private const int MaxReadBytes = 262_144; // 256 KB

    public static async Task<(ProbeOutcome outcome, byte[]? bytes, string? message)> ReadFileBytesAsync(string path, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true);
            var buffer = new byte[MaxReadBytes];
            var bytesRead = await fs.ReadAsync(buffer.AsMemory(0, MaxReadBytes), cts.Token).ConfigureAwait(false);
            var bytes = buffer[..bytesRead];
            // If we read exactly MaxReadBytes, file may have been truncated silently; signal this in the message
            var message = bytesRead == MaxReadBytes ? $"[truncated at {MaxReadBytes} bytes]" : null;
            return (ProbeOutcome.Success, bytes, message);
        }
        catch (UnauthorizedAccessException ex) { return (ProbeOutcome.AccessDenied, null, ex.Message); }
        catch (OperationCanceledException ex) { return (ProbeOutcome.Timeout, null, ex.Message); }
        catch (FileNotFoundException ex) { return (ProbeOutcome.Unavailable, null, ex.Message); }
        catch (DirectoryNotFoundException ex) { return (ProbeOutcome.Unavailable, null, ex.Message); }
        catch (Exception ex) { return (ProbeOutcome.Error, null, ex.Message); }
    }

    public static async Task<(ProbeOutcome outcome, string? text, string? message)> ReadFileAsync(string path, TimeSpan timeout, CancellationToken ct)
    {
        var (outcome, bytes, message) = await ReadFileBytesAsync(path, timeout, ct).ConfigureAwait(false);
        return (outcome, bytes is null ? null : Encoding.UTF8.GetString(bytes), message);
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

internal sealed class UnixHostProbe : IProbe
{
    public string Id => "proc-files";
    private readonly IReadOnlyList<string> _files;
    private readonly Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> _readFileAsync;
    private readonly Func<string, IEnumerable<string>> _enumerateFiles;
    private readonly Func<string, IEnumerable<string>> _enumerateEntries;

    private const string KernelSysctlDirectory = "/proc/sys/kernel";

    private static readonly string[] BaseKernelSysctlFiles =
    [
        "/proc/sys/kernel/hostname",
        "/proc/sys/kernel/osrelease",
        "/proc/sys/kernel/ostype",
        "/proc/sys/kernel/version"
    ];

    private static readonly string[] PublicKernelSysctlSuffixes =
    [
        "_hw_version",
        "_hw_revision",
        "_install_flag"
    ];

    private static readonly string[] PublicDmiFiles =
    [
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_family",
        "/sys/class/dmi/id/product_version",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/board_name",
        "/sys/class/dmi/id/chassis_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/modalias"
    ];

    private static readonly string[] SensitiveDmiFiles =
    [
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/product_serial",
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/chassis_serial"
    ];

    private static readonly string[] PublicDeviceTreeFiles =
    [
        "/proc/device-tree/model",
        "/proc/device-tree/compatible",
        "/sys/firmware/devicetree/base/model",
        "/sys/firmware/devicetree/base/compatible"
    ];

    private static readonly string[] SensitiveDeviceTreeFiles =
    [
        "/proc/device-tree/serial-number",
        "/sys/firmware/devicetree/base/serial-number"
    ];

    private static readonly string[] PublicSocFiles =
    [
        "/sys/devices/soc0/machine",
        "/sys/devices/soc0/family",
        "/sys/devices/soc0/soc_id",
        "/sys/devices/soc0/revision"
    ];

    private static readonly string[] SensitiveSocFiles =
    [
        "/sys/devices/soc0/serial_number"
    ];

    private static readonly string[] VirtualizationFiles =
    [
        "/proc/modules",
        "/sys/hypervisor/type"
    ];

    private static readonly string[] PlatformDeviceRoots =
    [
        "/sys/bus/platform/devices"
    ];

    private static readonly string[] TpmDevicePaths =
    [
        "/dev/tpm0",
        "/dev/tpmrm0",
        "/dev/vtpmx"
    ];

    private const string TpmClassDirectory = "/sys/class/tpm";

    private static readonly (string RelativePath, string EvidenceKey)[] TpmPublicMaterialCandidates =
    {
        ("device/ek_cert", "device.tpm.ek_cert.sha256"),
        ("device/pubek", "device.tpm.pubek.sha256")
    };

    private static readonly string[] InterestingVirtualizationModules =
    [
        "hv_vmbus",
        "hv_utils",
        "hv_storvsc",
        "hv_netvsc",
        "hv_balloon",
        "hid_hyperv",
        "vmw_vmci",
        "vmxnet3",
        "vmw_pvscsi",
        "vmw_balloon",
        "vmwgfx",
        "vboxguest",
        "vboxsf",
        "vboxvideo",
        "xen_evtchn",
        "xen_blkfront",
        "xen_netfront"
    ];

    private const string VmbusDevicesDirectory = "/sys/bus/vmbus/devices";

        private readonly Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, byte[]? bytes, string? message)>> _readFileBytesAsync;
    private static readonly string[] Files =
    [
        "/proc/1/cgroup", "/proc/self/cgroup",
        "/proc/self/mountinfo", "/proc/1/mountinfo",
        "/proc/net/route", "/etc/resolv.conf",
        "/etc/hostname",
        "/etc/machine-id", "/var/lib/dbus/machine-id",
        "/etc/os-release", "/usr/lib/os-release",
        "/proc/version",
        .. BaseKernelSysctlFiles,
        "/proc/cpuinfo", "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/possible", "/sys/devices/system/cpu/present",
        .. PublicDmiFiles,
        .. SensitiveDmiFiles,
        .. PublicDeviceTreeFiles,
        .. SensitiveDeviceTreeFiles,
        .. PublicSocFiles,
        .. SensitiveSocFiles,
        .. VirtualizationFiles,
        "/proc/meminfo", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    ];

    private readonly Func<string, bool> _directoryExists;
    private readonly Func<string, bool> _pathExists;

    public UnixHostProbe() : this([], ProbeIo.ReadFileAsync, Directory.EnumerateFiles, Directory.EnumerateFileSystemEntries, Directory.Exists, File.Exists, ProbeIo.ReadFileBytesAsync) { }

    internal UnixHostProbe(
        IReadOnlyList<string> files,
        Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> readFileAsync,
        Func<string, IEnumerable<string>>? enumerateFiles = null,
        Func<string, IEnumerable<string>>? enumerateEntries = null,
        Func<string, bool>? directoryExists = null,
        Func<string, bool>? pathExists = null,
        Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, byte[]? bytes, string? message)>>? readFileBytesAsync = null)
    {
        _files = files;
        _readFileAsync = readFileAsync;
        _readFileBytesAsync = readFileBytesAsync ?? ProbeIo.ReadFileBytesAsync;
        _enumerateFiles = enumerateFiles ?? Directory.EnumerateFiles;
        _enumerateEntries = enumerateEntries ?? Directory.EnumerateFileSystemEntries;
        _directoryExists = directoryExists ?? Directory.Exists;
        _pathExists = pathExists ?? File.Exists;
    }

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var final = ProbeOutcome.Success;
        string? message = null;
        var osReleaseRead = false;
        var machineIdRead = false;
        string? procVersion = null;
        string? kernelOsRelease = null;
        string? kernelOsType = null;
        string? kernelVersion = null;
        var files = _files.Count == 0 ? BuildDefaultFiles() : _files;
        var readTasks = files.ToDictionary(file => file, file => _readFileAsync(file, context.Timeout, context.CancellationToken));

        foreach (var file in files)
        {
            // Skip /usr/lib/os-release if /etc/os-release was successfully read
            if (file == "/usr/lib/os-release" && osReleaseRead) continue;
            if (file == "/var/lib/dbus/machine-id" && machineIdRead) continue;

            var (outcome, text, msg) = await readTasks[file].ConfigureAwait(false);
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
                {
                    evidence.Add(new EvidenceItem(Id, $"{file}:signal", signal));
                    var (podUid, containerToken) = Parsing.ExtractKubernetesWorkloadIdentifiers(signal);
                    AddSensitiveEvidenceIfPresent(evidence, "kubernetes.cgroup.pod_uid", podUid, context.IncludeSensitive);
                    AddSensitiveEvidenceIfPresent(evidence, "kubernetes.cgroup.container_token", containerToken, context.IncludeSensitive);
                }
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
            else if (file is "/etc/machine-id" or "/var/lib/dbus/machine-id")
            {
                var value = text?.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    evidence.Add(new EvidenceItem(Id, "machine.id", context.IncludeSensitive ? value : "redacted", EvidenceSensitivity.Sensitive));
                    machineIdRead = true;
                }
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
            else if (file.StartsWith("/proc/sys/kernel/", StringComparison.Ordinal))
            {
                var key = file.Split('/').Last();
                if (string.Equals(key, "hostname", StringComparison.Ordinal))
                {
                    var value = text?.Trim();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        evidence.Add(new EvidenceItem(Id, "kernel.hostname", context.IncludeSensitive ? value : "redacted", EvidenceSensitivity.Sensitive));
                    }
                }
                else
                {
                    AddEvidenceIfPresent(evidence, $"kernel.{key}", text?.Trim());
                }
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
                AddEvidenceIfPresent(evidence, "cpu.flag.hypervisor", cpu.HypervisorPresent?.ToString());
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
            else if (file.StartsWith("/sys/class/dmi/id/", StringComparison.Ordinal))
            {
                var key = file.Split('/').Last();
                if (key is "product_uuid" or "product_serial" or "board_serial" or "chassis_serial")
                {
                    AddSensitiveEvidenceIfPresent(evidence, $"dmi.{key}", text, context.IncludeSensitive);
                }
                else
                {
                    AddEvidenceIfPresent(evidence, $"dmi.{key}", text?.Trim());
                }
            }
            else if (file.StartsWith("/sys/devices/soc0/", StringComparison.Ordinal))
            {
                var key = file.Split('/').Last();
                if (key == "serial_number")
                {
                    AddSensitiveEvidenceIfPresent(evidence, $"soc.{key}", text, context.IncludeSensitive);
                }
                else
                {
                    AddEvidenceIfPresent(evidence, $"soc.{key}", text?.Trim());
                }
            }
            else if (file == "/proc/modules")
            {
                var loadedModules = text!
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault())
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Distinct(StringComparer.Ordinal)
                    .ToHashSet(StringComparer.Ordinal);

                foreach (var moduleName in InterestingVirtualizationModules.Where(loadedModules.Contains))
                {
                    evidence.Add(new EvidenceItem(Id, $"module.{moduleName}.loaded", bool.TrueString));
                }
            }
            else if (file == "/sys/hypervisor/type")
            {
                AddEvidenceIfPresent(evidence, "sys.hypervisor.type", text?.Trim());
            }
            else if (file.EndsWith("/modalias", StringComparison.Ordinal)
                && file.StartsWith("/sys/bus/platform/devices/", StringComparison.Ordinal))
            {
                AddEvidenceIfPresent(evidence, "platform.modalias", text?.Trim());
            }
            else if (file.EndsWith("/uevent", StringComparison.Ordinal)
                && file.StartsWith("/sys/bus/platform/devices/", StringComparison.Ordinal))
            {
                foreach (var line in text!.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (line.StartsWith("OF_COMPATIBLE_", StringComparison.Ordinal))
                    {
                        AddEvidenceIfPresent(evidence, "platform.of_compatible", SplitUeventValue(line));
                    }
                    else if (line.StartsWith("MODALIAS=", StringComparison.Ordinal))
                    {
                        AddEvidenceIfPresent(evidence, "platform.modalias", SplitUeventValue(line));
                    }
                }
            }
            else if (file is "/proc/device-tree/model" or "/sys/firmware/devicetree/base/model")
            {
                AddEvidenceIfPresent(evidence, "device_tree.model", NormalizeDeviceTreeText(text));
            }
            else if (file is "/proc/device-tree/compatible" or "/sys/firmware/devicetree/base/compatible")
            {
                AddEvidenceIfPresent(evidence, "device_tree.compatible", NormalizeDeviceTreeText(text));
            }
            else if (file is "/proc/device-tree/serial-number" or "/sys/firmware/devicetree/base/serial-number")
            {
                AddSensitiveEvidenceIfPresent(evidence, "device_tree.serial_number", NormalizeDeviceTreeText(text), context.IncludeSensitive);
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

        if (_directoryExists(VmbusDevicesDirectory))
        {
            evidence.Add(new EvidenceItem(Id, "bus.vmbus.present", bool.TrueString));
        }

        foreach (var devicePath in TpmDevicePaths)
        {
            if (_pathExists(devicePath))
            {
                evidence.Add(new EvidenceItem(Id, "device.tpm.path", devicePath));
            }
        }

        await AddVisibleTpmPublicMaterialEvidenceAsync(evidence, context).ConfigureAwait(false);

        var kernel = HostParsing.ParseKernel(procVersion, kernelOsRelease, kernelOsType, kernelVersion);
        AddEvidenceIfPresent(evidence, "kernel.architecture", HostParsing.NormalizeArchitectureRaw(RuntimeInformation.OSArchitecture));
        AddEvidenceIfPresent(evidence, "kernel.name", kernel.Name);
        AddEvidenceIfPresent(evidence, "kernel.release", kernel.Release);
        AddEvidenceIfPresent(evidence, "kernel.version", kernel.Version);
        AddEvidenceIfPresent(evidence, "kernel.compiler", kernel.Compiler?.Raw);
        AddEvidenceIfPresent(evidence, "kernel.compiler.raw", kernel.Compiler?.Raw);
        AddEvidenceIfPresent(evidence, "kernel.compiler.name", kernel.Compiler?.Name);
        AddEvidenceIfPresent(evidence, "kernel.compiler.version", kernel.Compiler?.Version);
        AddEvidenceIfPresent(evidence, "kernel.compiler.distribution_hint", kernel.Compiler?.DistributionHint);
        AddEvidenceIfPresent(evidence, "kernel.compiler.distribution_version_hint", kernel.Compiler?.DistributionVersionHint);
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

    private static void AddSensitiveEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value, bool includeSensitive)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem("proc-files", key, includeSensitive ? value.Trim() : "redacted", EvidenceSensitivity.Sensitive));
        }
    }

        private async Task AddVisibleTpmPublicMaterialEvidenceAsync(List<EvidenceItem> evidence, ProbeContext context)
        {
            foreach (var candidate in DiscoverTpmPublicMaterialFiles())
            {
                var (outcome, bytes, _) = await _readFileBytesAsync(candidate.Path, context.Timeout, context.CancellationToken).ConfigureAwait(false);
                if (outcome != ProbeOutcome.Success || bytes is not { Length: > 0 })
                {
                    continue;
                }

                var digest = $"sha256:{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}";
                AddSensitiveEvidenceIfPresent(evidence, candidate.EvidenceKey, digest, context.IncludeSensitive);
            }
        }

    private IReadOnlyList<string> BuildDefaultFiles()
        => Files
            .Concat(DiscoverPublicKernelSysctlFiles())
            .Concat(DiscoverPlatformMetadataFiles())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private IReadOnlyList<string> DiscoverPublicKernelSysctlFiles()
    {
        try
        {
            return _enumerateFiles(KernelSysctlDirectory)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Where(name => PublicKernelSysctlSuffixes.Any(suffix => name!.EndsWith(suffix, StringComparison.Ordinal)))
                .OrderBy(name => name, StringComparer.Ordinal)
                .Select(name => $"{KernelSysctlDirectory}/{name}")
                .ToArray();
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (DirectoryNotFoundException)
        {
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    private IReadOnlyList<string> DiscoverPlatformMetadataFiles()
    {
        var candidates = new List<string>();

        foreach (var root in PlatformDeviceRoots)
        {
            try
            {
                foreach (var entry in _enumerateEntries(root))
                {
                    var name = Path.GetFileName(entry);
                    if (string.IsNullOrWhiteSpace(name) || char.IsDigit(name[0]))
                    {
                        continue;
                    }

                    candidates.Add($"{entry.TrimEnd('/')}/modalias");
                    candidates.Add($"{entry.TrimEnd('/')}/uevent");
                }
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }
            catch (IOException)
            {
            }
        }

        return candidates
            .Distinct(StringComparer.Ordinal)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private IReadOnlyList<(string Path, string EvidenceKey)> DiscoverTpmPublicMaterialFiles()
    {
        var candidates = new List<(string Path, string EvidenceKey)>();

        try
        {
            foreach (var entry in _enumerateEntries(TpmClassDirectory))
            {
                var name = Path.GetFileName(entry);
                if (string.IsNullOrWhiteSpace(name) || !name.StartsWith("tpm", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var root = entry.TrimEnd('/');
                foreach (var candidate in TpmPublicMaterialCandidates)
                {
                    candidates.Add(($"{root}/{candidate.RelativePath}", candidate.EvidenceKey));
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (IOException)
        {
        }

        return candidates;
    }

    private static string? SplitUeventValue(string line)
    {
        var idx = line.IndexOf('=');
        return idx < 0 ? null : line[(idx + 1)..].Trim();
    }

    private static long? NormalizeCgroupBytes(string? raw)
    {
        var value = raw?.Trim();
        return value == "max" ? null : HostParsing.ParseNullableLong(value);
    }

    private static string? NormalizeDeviceTreeText(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var parts = raw.Split('\0', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
        {
            return raw.Trim('\0', '\n', '\r', ' ');
        }

        return string.Join(", ", parts.Select(part => part.Trim())).Trim();
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
        var selinuxMounted = Directory.Exists("/sys/fs/selinux");

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
            evidence.Add(new EvidenceItem(Id, ClassifyCurrentAttrKey(attr), attr));
        }

        // /sys/fs/selinux: directory existence indicates SELinux is mounted
        evidence.Add(new EvidenceItem(Id, "selinux.mount.present", selinuxMounted.ToString()));

        var (selinuxEnforceOutcome, selinuxEnforceText, _) = await ProbeIo.ReadFileAsync("/sys/fs/selinux/enforce", context.Timeout, context.CancellationToken).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "selinux.enforce.outcome", selinuxEnforceOutcome.ToString()));
        if (selinuxEnforceOutcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(selinuxEnforceText))
        {
            evidence.Add(new EvidenceItem(Id, "selinux.enforce", selinuxEnforceText.Trim()));
        }

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed);
    }

    internal static string ClassifyCurrentAttrKey(string attr)
        => LooksLikeSelinuxContext(attr) ? "selinux.context" : "apparmor.profile";

    internal static bool LooksLikeSelinuxContext(string attr)
    {
        var parts = attr.Split(':', StringSplitOptions.None | StringSplitOptions.TrimEntries);
        return parts.Length >= 4 && parts.All(part => !string.IsNullOrWhiteSpace(part));
    }
}
