using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal static class HostReportBuilder
{
    private const string KernelReleaseKey = "kernel.release";

    public static HostReport Build(IReadOnlyList<ProbeResult> probes, ReportClassification classification, FingerprintMode fingerprintMode)
    {
        var evidence = probes.SelectMany(probe => probe.Evidence).ToList();
        var defaultArchitectureRaw = HostParsing.NormalizeArchitectureRaw(RuntimeInformation.ProcessArchitecture);

        var containerImageOs = BuildContainerImageOs(evidence, defaultArchitectureRaw);
        var visibleKernel = BuildVisibleKernel(evidence, defaultArchitectureRaw);
        var runtimeHostOs = BuildRuntimeReportedHostOs(evidence);
        var virtualization = BuildVirtualization(evidence);
        var underlyingHostOs = BuildUnderlyingHostOs(runtimeHostOs, virtualization, visibleKernel);
        var hardware = BuildHardware(evidence, runtimeHostOs, visibleKernel, defaultArchitectureRaw);
        var diagnosticFingerprints = BuildDiagnosticFingerprints(evidence, classification, runtimeHostOs, visibleKernel, hardware, fingerprintMode);
        var identityAnchors = BuildIdentityAnchors(evidence);

        return new HostReport(containerImageOs, visibleKernel, runtimeHostOs, virtualization, underlyingHostOs, hardware, diagnosticFingerprints, identityAnchors);
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
        var release = GetValue(evidence, KernelReleaseKey);
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

        var localCandidate = BuildRuntimeHostFromLocalEvidence(evidence);
        if (localCandidate is not null)
        {
            candidates.Add(localCandidate);
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
            RuntimeReportedHostSource.LocalHost => Confidence.High,
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

    private static VirtualizationInfo BuildVirtualization(IReadOnlyList<EvidenceItem> evidence)
    {
        var match = VirtualizationDetection.Detect(evidence);
        return match is null
            ? new VirtualizationInfo(VirtualizationKind.Unknown, null, Confidence.Unknown, [])
            : new VirtualizationInfo(match.Kind, match.PlatformVendor, match.Confidence, match.EvidenceReferences);
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

    private static IReadOnlyList<DiagnosticFingerprint> BuildDiagnosticFingerprints(
        IReadOnlyList<EvidenceItem> evidence,
        ReportClassification classification,
        RuntimeReportedHostOsInfo runtimeHostOs,
        VisibleKernelInfo visibleKernel,
        HostHardwareInfo hardware,
        FingerprintMode fingerprintMode)
    {
        if (fingerprintMode == FingerprintMode.None)
        {
            return [];
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
        AddIncluded(KernelReleaseKey, visibleKernel.Release);
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

        var excluded = new List<DiagnosticFingerprintComponent>();
        AddExcludedIfPresent(evidence, excluded, "hostname", "/etc/hostname", "/proc/sys/kernel/hostname", "kernel.hostname", "HOSTNAME");
        AddExcludedIfPresent(evidence, excluded, "cpu.serial", "cpu.serial");
        AddExcludedIfPresent(evidence, excluded, "container.inspect", "container.inspect.status", "container.inspect.outcome");
        AddExcludedIfPresent(evidence, excluded, "cloud.project", "gcp.project_id");
        AddExcludedIfPresent(evidence, excluded, "cloud.instance_id", "aws.instance_id", "azure.vm_id", "oci.instance_id");

        var components = included
            .OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
            .Select(kvp => new DiagnosticFingerprintComponent(kvp.Key, true, kvp.Value))
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

        var sourceClasses = ClassifyDiagnosticSourceClasses(included.Keys).ToArray();
        var stabilityLevel = ClassifyDiagnosticStabilityLevel(included);
        var uniquenessLevel = ClassifyDiagnosticUniquenessLevel(included);
        var corroborationLevel = ClassifyDiagnosticCorroborationLevel(sourceClasses);
        var reasons = BuildDiagnosticFingerprintReasons(stabilityLevel, sourceClasses, excluded.Count).ToArray();

        return
        [
            new DiagnosticFingerprint(
                DiagnosticFingerprintPurpose.EnvironmentCorrelation,
                "CRP-HOST-FP-v1",
                HostParsing.ComputeFingerprint(included),
                stability,
                stabilityLevel,
                uniquenessLevel,
                corroborationLevel,
                included.Count,
                excluded.Count,
                sourceClasses,
                components,
                ["Fingerprint is diagnostic only and not a security identity."],
                reasons)
        ];
    }

    private static IReadOnlyList<IdentityAnchor> BuildIdentityAnchors(IReadOnlyList<EvidenceItem> evidence)
    {
        var anchors = new List<IdentityAnchor>();
        anchors.AddRange(BuildCloudInstanceIdentityAnchors(evidence));

        var kubernetesNodeAnchor = BuildKubernetesNodeIdentityAnchor(evidence);
        if (kubernetesNodeAnchor is not null)
        {
            anchors.Add(kubernetesNodeAnchor);
        }

        return anchors;
    }

    private static IReadOnlyList<IdentityAnchor> BuildCloudInstanceIdentityAnchors(IReadOnlyList<EvidenceItem> evidence)
    {
        var anchors = new List<IdentityAnchor>();
        AddCloudInstanceIdentityAnchor(anchors, evidence, "aws.instance_id", "aws");
        AddCloudInstanceIdentityAnchor(anchors, evidence, "azure.vm_id", "azure");
        AddCloudInstanceIdentityAnchor(anchors, evidence, "gcp.instance_id", "gcp");
        AddCloudInstanceIdentityAnchor(anchors, evidence, "oci.instance_id", "oci");
        return anchors;
    }

    private static void AddCloudInstanceIdentityAnchor(List<IdentityAnchor> anchors, IReadOnlyList<EvidenceItem> evidence, string key, string provider)
    {
        var instanceId = GetValue(evidence, key);
        if (string.IsNullOrWhiteSpace(instanceId) || string.Equals(instanceId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return;
        }

        anchors.Add(new IdentityAnchor(
            IdentityAnchorKind.CloudInstanceIdentity,
            "CRP-CLOUD-INSTANCE-v1",
            ComputeIdentityAnchorDigest($"cloud-instance:{provider}", instanceId),
            IdentityAnchorScope.Host,
            BindingSuitability.LicenseBinding,
            IdentityAnchorStrength.Strong,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, key, "cloud.source"),
            [],
            [$"Digest derived from observed {provider} instance identity metadata."]));
    }

    private static IdentityAnchor? BuildKubernetesNodeIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var nodeUid = GetValue(evidence, "kubernetes.node.uid");
        if (!string.IsNullOrWhiteSpace(nodeUid) && !string.Equals(nodeUid, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return new IdentityAnchor(
                IdentityAnchorKind.KubernetesNodeIdentity,
                "CRP-KUBERNETES-NODE-v1",
                ComputeIdentityAnchorDigest("kubernetes-node:uid", nodeUid),
                IdentityAnchorScope.Host,
                BindingSuitability.LicenseBinding,
                IdentityAnchorStrength.Strong,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "kubernetes.node.uid", "kubernetes.node.name", "kubernetes.node.provider_id"),
                [],
                ["Digest derived from Kubernetes node metadata UID."]);
        }

        var providerId = GetValue(evidence, "kubernetes.node.provider_id");
        if (!string.IsNullOrWhiteSpace(providerId) && !string.Equals(providerId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return new IdentityAnchor(
                IdentityAnchorKind.KubernetesNodeIdentity,
                "CRP-KUBERNETES-NODE-v1",
                ComputeIdentityAnchorDigest("kubernetes-node:provider-id", providerId),
                IdentityAnchorScope.Host,
                BindingSuitability.LicenseBinding,
                IdentityAnchorStrength.Medium,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "kubernetes.node.provider_id", "kubernetes.node.name"),
                [],
                ["Digest derived from Kubernetes node provider ID because no node UID was visible."]);
        }

        return null;
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

    private static ParsedRuntimeHostInfo? BuildRuntimeHostFromLocalEvidence(IReadOnlyList<EvidenceItem> evidence)
    {
        var productName = GetValue(evidence, "windows.product_name");
        if (string.IsNullOrWhiteSpace(productName))
        {
            return null;
        }

        var version = GetValue(evidence, "windows.display_version");
        var rawArchitecture = GetValue(evidence, "kernel.architecture") ?? GetValue(evidence, "runtime.architecture");
        var references = GetEvidenceReferences(evidence, "windows.")
            .Concat(GetEvidenceReferences(evidence, "kernel."))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new ParsedRuntimeHostInfo(
            HostParsing.NormalizeOperatingSystemFamily(productName, [], productName, productName),
            productName,
            version,
            GetValue(evidence, "kernel.release"),
            rawArchitecture,
            RuntimeReportedHostSource.LocalHost,
            references);
    }

    private static IReadOnlyList<DiagnosticFingerprintSourceClass> ClassifyDiagnosticSourceClasses(IEnumerable<string> keys)
        => keys
            .Select(ClassifyDiagnosticSourceClass)
            .Where(sourceClass => sourceClass != DiagnosticFingerprintSourceClass.Unknown)
            .Distinct()
            .OrderBy(sourceClass => sourceClass)
            .ToArray();

    private static DiagnosticFingerprintSourceClass ClassifyDiagnosticSourceClass(string key)
        => key switch
        {
            var value when value.StartsWith("kernel.", StringComparison.Ordinal) => DiagnosticFingerprintSourceClass.KernelSignal,
            var value when value.StartsWith("runtime.", StringComparison.Ordinal) => DiagnosticFingerprintSourceClass.RuntimeApi,
            var value when value.StartsWith("cloud.", StringComparison.Ordinal) => DiagnosticFingerprintSourceClass.CloudMetadata,
            var value when value.StartsWith("kubernetes.", StringComparison.Ordinal) => DiagnosticFingerprintSourceClass.KubernetesMetadata,
            var value when value.StartsWith("architecture.", StringComparison.Ordinal)
                || value.StartsWith("cpu.", StringComparison.Ordinal)
                || value.StartsWith("memory.", StringComparison.Ordinal) => DiagnosticFingerprintSourceClass.HardwareProfile,
            _ => DiagnosticFingerprintSourceClass.Unknown
        };

    private static DiagnosticFingerprintStabilityLevel ClassifyDiagnosticStabilityLevel(IReadOnlyDictionary<string, string> included)
    {
        if (included.Keys.Any(key => key is KernelReleaseKey or "runtime.engine.version.majorMinor" or "kubernetes.node.containerRuntimeVersion.majorMinor" or "runtime.host.kernel"))
        {
            return DiagnosticFingerprintStabilityLevel.UpdateSensitive;
        }

        if (included.Keys.Any(key => key is "architecture.normalized" or "cpu.vendor" or "cpu.family" or "cpu.modelName.normalized" or "memory.total.bucket"))
        {
            return DiagnosticFingerprintStabilityLevel.ProfileStable;
        }

        return DiagnosticFingerprintStabilityLevel.Ephemeral;
    }

    private static DiagnosticFingerprintUniquenessLevel ClassifyDiagnosticUniquenessLevel(IReadOnlyDictionary<string, string> included)
    {
        var hasCpuFlagsHash = included.ContainsKey("cpu.flags.hash");
        var hasCloudMachineType = included.ContainsKey("cloud.machine.type");
        if (hasCpuFlagsHash && hasCloudMachineType)
        {
            return DiagnosticFingerprintUniquenessLevel.Medium;
        }

        if (hasCpuFlagsHash || hasCloudMachineType)
        {
            return DiagnosticFingerprintUniquenessLevel.Low;
        }

        return DiagnosticFingerprintUniquenessLevel.Unknown;
    }

    private static DiagnosticFingerprintCorroborationLevel ClassifyDiagnosticCorroborationLevel(IReadOnlyCollection<DiagnosticFingerprintSourceClass> sourceClasses)
    {
        if (sourceClasses.Count >= 2)
        {
            return DiagnosticFingerprintCorroborationLevel.CrossSource;
        }

        if (sourceClasses.Count == 1)
        {
            return DiagnosticFingerprintCorroborationLevel.SingleSource;
        }

        return DiagnosticFingerprintCorroborationLevel.Unknown;
    }

    private static IReadOnlyList<string> BuildDiagnosticFingerprintReasons(
        DiagnosticFingerprintStabilityLevel stabilityLevel,
        IReadOnlyCollection<DiagnosticFingerprintSourceClass> sourceClasses,
        int excludedSensitiveSignalCount)
    {
        var reasons = new List<string>();
        if (stabilityLevel == DiagnosticFingerprintStabilityLevel.UpdateSensitive)
        {
            reasons.Add("Includes kernel or runtime version signals and is expected to change across updates.");
        }

        if (sourceClasses.Count >= 2)
        {
            reasons.Add("Combines multiple source classes for broader environment correlation.");
        }

        if (excludedSensitiveSignalCount > 0)
        {
            reasons.Add("Sensitive identifiers remain excluded from the diagnostic fingerprint payload.");
        }

        return reasons;
    }

    private static void AddExcludedIfPresent(IReadOnlyList<EvidenceItem> evidence, ICollection<DiagnosticFingerprintComponent> excluded, string name, params string[] keys)
    {
        if (keys.Any(key => evidence.Any(item => item.Key == key)))
        {
            excluded.Add(new DiagnosticFingerprintComponent(name, false, "redacted"));
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

    private static IReadOnlyList<string> GetEvidenceReferencesForKeys(IReadOnlyList<EvidenceItem> evidence, params string[] keys)
        => evidence.Where(item => keys.Contains(item.Key, StringComparer.Ordinal))
            .Select(item => $"{item.ProbeId}:{item.Key}")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

    private static string ComputeIdentityAnchorDigest(string scopeKey, string rawValue)
        => $"sha256:{HostParsing.ComputeSha256Hex($"{scopeKey}\n{rawValue.Trim()}")}";

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
