using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal static class HostReportBuilder
{
    public static HostReport Build(IReadOnlyList<ProbeResult> probes, ReportClassification classification, FingerprintMode fingerprintMode)
    {
        var evidence = probes.SelectMany(probe => probe.Evidence).ToList();
        var defaultArchitectureRaw = HostParsing.NormalizeArchitectureRaw(RuntimeInformation.ProcessArchitecture);

        var containerImageOs = BuildContainerImageOs(evidence, defaultArchitectureRaw);
        var visibleKernel = BuildVisibleKernel(evidence, defaultArchitectureRaw);
        var runtimeHostOs = BuildRuntimeReportedHostOs(evidence);
        var virtualization = BuildVirtualization(evidence, visibleKernel);
        var underlyingHostOs = BuildUnderlyingHostOs(runtimeHostOs, virtualization, visibleKernel);
        var hardware = BuildHardware(evidence, runtimeHostOs, visibleKernel, defaultArchitectureRaw);
        var fingerprint = BuildFingerprint(evidence, classification, runtimeHostOs, visibleKernel, hardware, fingerprintMode);

        return new HostReport(containerImageOs, visibleKernel, runtimeHostOs, virtualization, underlyingHostOs, hardware, fingerprint);
    }

    private static ContainerImageOsInfo BuildContainerImageOs(IReadOnlyList<EvidenceItem> evidence, string defaultArchitectureRaw)
    {
        var idLike = GetValues(evidence, "os.id_like");
        var family = HostParsing.NormalizeOperatingSystemFamily(
            GetValue(evidence, "os.id"),
            idLike,
            GetValue(evidence, "os.name"),
            GetValue(evidence, "os.pretty_name"));
        var rawArchitecture = defaultArchitectureRaw;
        return new ContainerImageOsInfo(
            family,
            GetValue(evidence, "os.id"),
            idLike,
            GetValue(evidence, "os.name"),
            GetValue(evidence, "os.pretty_name"),
            GetValue(evidence, "os.version"),
            GetValue(evidence, "os.version_id"),
            GetValue(evidence, "os.version_codename"),
            GetValue(evidence, "os.build_id"),
            GetValue(evidence, "os.variant"),
            GetValue(evidence, "os.variant_id"),
            GetValue(evidence, "os.home_url"),
            GetValue(evidence, "os.support_url"),
            GetValue(evidence, "os.bug_report_url"),
            HostParsing.NormalizeArchitecture(rawArchitecture),
            rawArchitecture,
            family == OperatingSystemFamily.Unknown ? Confidence.Unknown : Confidence.High,
            GetEvidenceReferences(evidence, "os."));
    }

    private static VisibleKernelInfo BuildVisibleKernel(IReadOnlyList<EvidenceItem> evidence, string defaultArchitectureRaw)
    {
        var release = GetValue(evidence, "kernel.release");
        var architectureRaw = GetValue(evidence, "kernel.architecture") ?? GetValue(evidence, "runtime.architecture") ?? defaultArchitectureRaw;
        var flavor = Enum.TryParse<KernelFlavor>(GetValue(evidence, "kernel.flavor"), ignoreCase: true, out var parsedFlavor) ? parsedFlavor : KernelFlavor.Unknown;
        var compilerRaw = GetValue(evidence, "kernel.compiler.raw") ?? GetValue(evidence, "kernel.compiler");
        var parsedCompiler = HostParsing.ParseKernelCompiler(compilerRaw);
        KernelCompilerInfo? compiler = null;
        if (parsedCompiler is not null || !string.IsNullOrWhiteSpace(compilerRaw))
        {
            compiler = new KernelCompilerInfo(
                GetValue(evidence, "kernel.compiler.name") ?? parsedCompiler?.Name,
                GetValue(evidence, "kernel.compiler.version") ?? parsedCompiler?.Version,
                compilerRaw,
                GetValue(evidence, "kernel.compiler.distribution_hint") ?? parsedCompiler?.DistributionHint,
                GetValue(evidence, "kernel.compiler.distribution_version_hint") ?? parsedCompiler?.DistributionVersionHint);
        }

        return new VisibleKernelInfo(
            GetValue(evidence, "kernel.name"),
            release,
            GetValue(evidence, "kernel.version"),
            HostParsing.NormalizeArchitecture(architectureRaw),
            architectureRaw,
            flavor,
            compiler,
            string.IsNullOrWhiteSpace(release) ? Confidence.Unknown : Confidence.Medium,
            GetEvidenceReferences(evidence, "kernel."));
    }

    private static RuntimeReportedHostOsInfo BuildRuntimeReportedHostOs(IReadOnlyList<EvidenceItem> evidence)
    {
        var candidates = new List<ParsedRuntimeHostInfo>();

        var kubernetes = BuildRuntimeHostFromEvidence(
            evidence,
            RuntimeReportedHostSource.KubernetesNodeInfo,
            "kubernetes.nodeInfo.osImage",
            "kubernetes.nodeInfo.kernelVersion",
            "kubernetes.nodeInfo.architecture",
            ["kubernetes.nodeInfo.osImage", "kubernetes.nodeInfo.kernelVersion", "kubernetes.nodeInfo.architecture", "kubernetes.nodeInfo.containerRuntimeVersion"]);
        if (kubernetes is not null)
        {
            candidates.Add(kubernetes);
        }

        var docker = BuildRuntimeHostFromEvidence(
            evidence,
            RuntimeReportedHostSource.DockerInfo,
            "docker.info.operating_system",
            "docker.info.kernel_version",
            "docker.info.architecture",
            ["docker.info.operating_system", "docker.info.kernel_version", "docker.info.architecture"]);
        if (docker is not null)
        {
            candidates.Add(docker);
        }

        var podman = BuildRuntimeHostFromEvidence(
            evidence,
            RuntimeReportedHostSource.PodmanInfo,
            "podman.info.distribution",
            "podman.info.kernel",
            "podman.info.architecture",
            ["podman.info.distribution", "podman.info.kernel", "podman.info.architecture"]);
        if (podman is not null)
        {
            candidates.Add(podman);
        }

        var cloudCandidate = BuildRuntimeHostFromCloud(evidence);
        if (cloudCandidate is not null)
        {
            candidates.Add(cloudCandidate);
        }

        var selected = candidates.FirstOrDefault();
        if (selected is null)
        {
            return new RuntimeReportedHostOsInfo(
                OperatingSystemFamily.Unknown,
                null,
                null,
                null,
                ArchitectureKind.Unknown,
                null,
                RuntimeReportedHostSource.Unknown,
                Confidence.Unknown,
                []);
        }

        var confidence = selected.Source switch
        {
            RuntimeReportedHostSource.DockerInfo or RuntimeReportedHostSource.PodmanInfo or RuntimeReportedHostSource.KubernetesNodeInfo => Confidence.High,
            RuntimeReportedHostSource.AzureImds or RuntimeReportedHostSource.AwsMetadata or RuntimeReportedHostSource.GcpMetadata or RuntimeReportedHostSource.OciMetadata => Confidence.Medium,
            _ => Confidence.Low
        };

        return new RuntimeReportedHostOsInfo(
            selected.Family,
            selected.Name,
            selected.Version,
            selected.KernelVersion,
            HostParsing.NormalizeArchitecture(selected.RawArchitecture),
            selected.RawArchitecture,
            selected.Source,
            confidence,
            selected.EvidenceReferences);
    }

    private static VirtualizationInfo BuildVirtualization(IReadOnlyList<EvidenceItem> evidence, VisibleKernelInfo visibleKernel)
    {
        var release = GetValue(evidence, "kernel.release");
        var procVersion = GetValue(evidence, "/proc/version");
        var evidenceReferences = new HashSet<string>(StringComparer.Ordinal);

        if (visibleKernel.Flavor == KernelFlavor.WSL2)
        {
            foreach (var reference in GetEvidenceReferences(evidence, "kernel.flavor"))
            {
                evidenceReferences.Add(reference);
            }
        }

        if (HostParsing.ContainsWsl2Signal(release))
        {
            foreach (var reference in GetEvidenceReferences(evidence, "kernel.release"))
            {
                evidenceReferences.Add(reference);
            }
        }

        if (HostParsing.ContainsWsl2Signal(procVersion))
        {
            foreach (var reference in GetEvidenceReferences(evidence, "/proc/version"))
            {
                evidenceReferences.Add(reference);
            }
        }

        if (evidenceReferences.Count > 0)
        {
            return new VirtualizationInfo(
                VirtualizationKind.WSL2,
                "Microsoft",
                Confidence.High,
                evidenceReferences.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return new VirtualizationInfo(VirtualizationKind.Unknown, null, Confidence.Unknown, []);
    }

    private static UnderlyingHostOsInfo BuildUnderlyingHostOs(RuntimeReportedHostOsInfo runtimeReportedHostOs, VirtualizationInfo virtualization, VisibleKernelInfo visibleKernel)
    {
        if (virtualization.Kind == VirtualizationKind.WSL2)
        {
            return new UnderlyingHostOsInfo(
                OperatingSystemFamily.Windows,
                "Windows host via WSL2 virtualization",
                null,
                null,
                UnderlyingHostOsSource.Virtualization,
                Confidence.High,
                virtualization.EvidenceReferences);
        }

        if (runtimeReportedHostOs.Family == OperatingSystemFamily.Unknown
            && TryMapKernelFlavorToOperatingSystemFamily(visibleKernel.Flavor, out var family))
        {
            return new UnderlyingHostOsInfo(
                family,
                $"{visibleKernel.Flavor} kernel flavor",
                null,
                visibleKernel.Compiler?.DistributionVersionHint,
                UnderlyingHostOsSource.VisibleKernel,
                Confidence.Medium,
                visibleKernel.EvidenceReferences);
        }

        return new UnderlyingHostOsInfo(OperatingSystemFamily.Unknown, null, null, null, UnderlyingHostOsSource.Unknown, Confidence.Unknown, []);
    }

    private static HostHardwareInfo BuildHardware(
        IReadOnlyList<EvidenceItem> evidence,
        RuntimeReportedHostOsInfo runtimeHostOs,
        VisibleKernelInfo visibleKernel,
        string defaultArchitectureRaw)
    {
        var rawArchitecture = runtimeHostOs.RawArchitecture ?? visibleKernel.RawArchitecture ?? GetValue(evidence, "runtime.architecture") ?? defaultArchitectureRaw;
        var logicalProcessors = GetNullableInt(evidence, "cpu.logical_processors") ?? GetNullableInt(evidence, "docker.info.ncpu") ?? GetNullableInt(evidence, "podman.info.cpus");
        var visibleProcessors = GetNullableInt(evidence, "cpu.online.count")
            ?? GetNullableInt(evidence, "cpu.present.count")
            ?? GetNullableInt(evidence, "cpu.possible.count")
            ?? logicalProcessors;
        var vendor = GetValue(evidence, "cpu.vendor");
        var modelName = GetValue(evidence, "cpu.model_name");

        var cpu = new HostCpuInfo(
            logicalProcessors,
            visibleProcessors,
            vendor,
            modelName,
            HostParsing.NormalizeCpuFamily(vendor, modelName),
            GetValue(evidence, "cpu.flags.hash"),
            GetNullableInt(evidence, "cpu.flags.count"),
            GetNullableLong(evidence, "cpu.cgroup.quota"),
            GetValue(evidence, "cpu.cgroup.max"));

        var memTotalBytes = GetNullableLong(evidence, "memory.mem_total_bytes") ?? GetNullableLong(evidence, "docker.info.mem_total") ?? GetNullableLong(evidence, "podman.info.mem_total");
        var memory = new HostMemoryInfo(
            memTotalBytes,
            GetNullableLong(evidence, "memory.cgroup.limit_bytes"),
            GetNullableLong(evidence, "memory.cgroup.current_bytes"),
            GetValue(evidence, "memory.cgroup.limit_raw"));

        var dmiReferences = GetEvidenceReferences(evidence, "dmi.");
        var dmi = new HostDmiInfo(
            GetValue(evidence, "dmi.sys_vendor"),
            GetValue(evidence, "dmi.product_name"),
            GetValue(evidence, "dmi.product_family"),
            GetValue(evidence, "dmi.product_version"),
            GetValue(evidence, "dmi.board_vendor"),
            GetValue(evidence, "dmi.board_name"),
            GetValue(evidence, "dmi.chassis_vendor"),
            GetValue(evidence, "dmi.bios_vendor"),
            GetValue(evidence, "dmi.modalias"),
            dmiReferences.Count == 0 ? Confidence.Unknown : Confidence.High,
            dmiReferences);

        var deviceTreeReferences = GetEvidenceReferences(evidence, "device_tree.");
        var deviceTree = new HostDeviceTreeInfo(
            GetValue(evidence, "device_tree.model"),
            GetValue(evidence, "device_tree.compatible"),
            deviceTreeReferences.Count == 0 ? Confidence.Unknown : Confidence.High,
            deviceTreeReferences);

        return new HostHardwareInfo(
            HostParsing.NormalizeArchitecture(rawArchitecture),
            rawArchitecture,
            cpu,
            memory,
            dmi,
            deviceTree,
            GetValue(evidence, "cloud.machine_type"));
    }

    private static HostFingerprint? BuildFingerprint(
        IReadOnlyList<EvidenceItem> evidence,
        ReportClassification classification,
        RuntimeReportedHostOsInfo runtimeHostOs,
        VisibleKernelInfo visibleKernel,
        HostHardwareInfo hardware,
        FingerprintMode fingerprintMode)
    {
        if (fingerprintMode == FingerprintMode.None)
        {
            return null;
        }

        var included = new Dictionary<string, string>(StringComparer.Ordinal);
        void AddIncluded(string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                included[key] = value.Trim();
            }
        }

        AddIncluded("runtime.host.os.normalized", runtimeHostOs.Family != OperatingSystemFamily.Unknown ? runtimeHostOs.Family.ToString() : null);
        AddIncluded("runtime.host.os.version", HostParsing.NormalizeVersionMajorMinor(runtimeHostOs.Version));
        AddIncluded("kernel.release", visibleKernel.Release);
        AddIncluded("kernel.flavor", visibleKernel.Flavor != KernelFlavor.Unknown ? visibleKernel.Flavor.ToString() : null);
        AddIncluded("architecture.normalized", hardware.Architecture != ArchitectureKind.Unknown ? hardware.Architecture.ToString() : null);
        AddIncluded("cpu.vendor", hardware.Cpu.Vendor);
        AddIncluded("cpu.family", hardware.Cpu.Family);
        AddIncluded("cpu.modelName.normalized", HostParsing.NormalizeModelName(hardware.Cpu.ModelName));
        AddIncluded("cpu.flags.hash", hardware.Cpu.FlagsHash);
        AddIncluded("memory.total.bucket", HostParsing.NormalizeMemoryBucket(hardware.Memory.MemTotalBytes));
        AddIncluded("runtime.api.type", classification.RuntimeApi.Value != RuntimeApiKind.Unknown ? ClassificationValueFormatter.Format(classification.RuntimeApi.Value) : null);
        AddIncluded("runtime.engine.version.majorMinor", HostParsing.NormalizeVersionMajorMinor(GetValue(evidence, "runtime.engine.version")));
        AddIncluded("cloud.provider", classification.CloudProvider.Value != CloudProviderKind.Unknown ? ClassificationValueFormatter.Format(classification.CloudProvider.Value) : null);
        AddIncluded("cloud.machine.type", hardware.CloudMachineType);
        AddIncluded("cloud.region.bucket", NormalizeRegionBucket(GetValue(evidence, "cloud.region")));
        AddIncluded("kubernetes.node.containerRuntimeVersion.majorMinor", HostParsing.NormalizeVersionMajorMinor(GetValue(evidence, "kubernetes.nodeInfo.containerRuntimeVersion")));

        if (fingerprintMode == FingerprintMode.Extended)
        {
            AddIncluded("kubernetes.node.osImage", GetValue(evidence, "kubernetes.nodeInfo.osImage"));
            AddIncluded("runtime.host.kernel", runtimeHostOs.KernelVersion);
            AddIncluded("memory.cgroup.limit.bucket", HostParsing.NormalizeMemoryBucket(hardware.Memory.CgroupMemoryLimitBytes));
        }

        var excluded = new List<HostFingerprintComponent>();
        AddExcludedIfPresent(evidence, excluded, "hostname", "/etc/hostname", "/proc/sys/kernel/hostname", "HOSTNAME");
        AddExcludedIfPresent(evidence, excluded, "cpu.serial", "cpu.serial");
        AddExcludedIfPresent(evidence, excluded, "container.inspect", "container.inspect.status", "container.inspect.outcome");
        AddExcludedIfPresent(evidence, excluded, "cloud.project", "gcp.project_id");
        AddExcludedIfPresent(evidence, excluded, "cloud.instance_id", "aws.instance_id", "azure.vm_id", "oci.instance_id");

        var components = included
            .OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Select(kvp => new HostFingerprintComponent(kvp.Key, true, kvp.Value))
            .Concat(excluded)
            .ToArray();

        var stability = runtimeHostOs.Source switch
        {
            RuntimeReportedHostSource.DockerInfo or RuntimeReportedHostSource.PodmanInfo or RuntimeReportedHostSource.KubernetesNodeInfo => FingerprintStability.RuntimeApiBacked,
            RuntimeReportedHostSource.AzureImds or RuntimeReportedHostSource.AwsMetadata or RuntimeReportedHostSource.GcpMetadata or RuntimeReportedHostSource.OciMetadata => FingerprintStability.CloudMetadataBacked,
            _ when !string.IsNullOrWhiteSpace(visibleKernel.Release) => FingerprintStability.KernelOnly,
            _ when !string.IsNullOrWhiteSpace(GetValue(evidence, "os.id")) => FingerprintStability.ContainerOnly,
            _ => FingerprintStability.Unknown
        };

        return new HostFingerprint(
            "CRP-HOST-FP-v1",
            HostParsing.ComputeFingerprint(included),
            stability,
            included.Count,
            excluded.Count,
            components,
            ["Fingerprint is diagnostic only and not a security identity."]);
    }

    private static ParsedRuntimeHostInfo? BuildRuntimeHostFromEvidence(
        IReadOnlyList<EvidenceItem> evidence,
        RuntimeReportedHostSource source,
        string nameKey,
        string kernelKey,
        string architectureKey,
        IReadOnlyList<string> evidenceReferences)
    {
        var name = GetValue(evidence, nameKey);
        var kernelVersion = GetValue(evidence, kernelKey);
        var rawArchitecture = GetValue(evidence, architectureKey);
        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(kernelVersion) && string.IsNullOrWhiteSpace(rawArchitecture))
        {
            return null;
        }

        return new ParsedRuntimeHostInfo(
            HostParsing.NormalizeOperatingSystemFamily(name, [], name, name),
            name,
            HostParsing.NormalizeVersionMajorMinor(name),
            kernelVersion,
            rawArchitecture,
            source,
            evidenceReferences.Where(reference => evidence.Any(item => item.Key == reference)).ToArray());
    }

    private static ParsedRuntimeHostInfo? BuildRuntimeHostFromCloud(IReadOnlyList<EvidenceItem> evidence)
    {
        var osType = GetValue(evidence, "cloud.os_type");
        var architecture = GetValue(evidence, "cloud.architecture");
        var source = GetValue(evidence, "cloud.source") switch
        {
            "AzureImds" => RuntimeReportedHostSource.AzureImds,
            "AwsMetadata" => RuntimeReportedHostSource.AwsMetadata,
            "GcpMetadata" => RuntimeReportedHostSource.GcpMetadata,
            "OciMetadata" => RuntimeReportedHostSource.OciMetadata,
            _ => RuntimeReportedHostSource.Unknown
        };

        if (source == RuntimeReportedHostSource.Unknown && string.IsNullOrWhiteSpace(osType) && string.IsNullOrWhiteSpace(architecture))
        {
            return null;
        }

        return new ParsedRuntimeHostInfo(
            HostParsing.NormalizeOperatingSystemFamily(osType, [], osType, osType),
            osType,
            HostParsing.NormalizeVersionMajorMinor(osType),
            null,
            architecture,
            source,
            GetEvidenceReferences(evidence, "cloud."));
    }

    private static void AddExcludedIfPresent(IReadOnlyList<EvidenceItem> evidence, ICollection<HostFingerprintComponent> excluded, string name, params string[] keys)
    {
        if (keys.Any(key => evidence.Any(item => item.Key == key)))
        {
            excluded.Add(new HostFingerprintComponent(name, false, "redacted"));
        }
    }

    private static string? GetValue(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.LastOrDefault(item => item.Key == key)?.Value;

    private static IReadOnlyList<string> GetValues(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.Where(item => item.Key == key)
            .Select(item => item.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> GetEvidenceReferences(IReadOnlyList<EvidenceItem> evidence, string prefix)
        => evidence.Where(item => item.Key.StartsWith(prefix, StringComparison.Ordinal))
            .Select(item => $"{item.ProbeId}:{item.Key}")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

    private static int? GetNullableInt(IReadOnlyList<EvidenceItem> evidence, string key)
        => int.TryParse(GetValue(evidence, key), out var parsed) ? parsed : null;

    private static long? GetNullableLong(IReadOnlyList<EvidenceItem> evidence, string key)
        => HostParsing.ParseNullableLong(GetValue(evidence, key));

    private static bool TryMapKernelFlavorToOperatingSystemFamily(KernelFlavor flavor, out OperatingSystemFamily family)
    {
        family = flavor switch
        {
            KernelFlavor.Ubuntu => OperatingSystemFamily.Ubuntu,
            KernelFlavor.Debian => OperatingSystemFamily.Debian,
            _ => OperatingSystemFamily.Unknown
        };

        return family != OperatingSystemFamily.Unknown;
    }

    private static string? NormalizeRegionBucket(string? region)
    {
        if (string.IsNullOrWhiteSpace(region))
        {
            return null;
        }

        var value = region.Trim();
        if (value.Contains('/'))
        {
            value = value[(value.LastIndexOf('/') + 1)..];
        }

        var parts = value.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length >= 2)
        {
            return $"{parts[0]}-{parts[1]}";
        }

        var zoneParts = value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return zoneParts.Length > 0 ? zoneParts[^1] : value;
    }
}
