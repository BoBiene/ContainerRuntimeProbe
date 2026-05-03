using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

internal static class HostReportBuilder
{
    private const string KernelReleaseKey = "kernel.release";
    private static readonly string[] WorkloadHostnameEvidenceKeys = ["HOSTNAME", "kernel.hostname", "/etc/hostname", "/proc/sys/kernel/hostname"];

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
        var identityAnchors = BuildIdentityAnchors(evidence, classification, runtimeHostOs, visibleKernel, virtualization, hardware);

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
        AddExcludedIfPresent(evidence, excluded, "tpm.public_material", "device.tpm.ek_cert.sha256", "device.tpm.pubek.sha256");
        AddExcludedIfPresent(evidence, excluded, "cloud.environment", "aws.account_id", "azure.subscription_id", "gcp.project_id", "oci.compartment_id");
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

        var purpose = classification.IsContainerized.Value == ContainerizationKind.@True
            && classification.Orchestrator.Value == OrchestratorKind.Unknown
            && classification.PlatformVendor.Value == PlatformVendorKind.Unknown
            ? DiagnosticFingerprintPurpose.RuntimeProfile
            : DiagnosticFingerprintPurpose.EnvironmentCorrelation;

        return
        [
            new DiagnosticFingerprint(
                purpose,
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

    private static IReadOnlyList<IdentityAnchor> BuildIdentityAnchors(
        IReadOnlyList<EvidenceItem> evidence,
        ReportClassification classification,
        RuntimeReportedHostOsInfo runtimeHostOs,
        VisibleKernelInfo visibleKernel,
        VirtualizationInfo virtualization,
        HostHardwareInfo hardware)
    {
        var anchors = new List<IdentityAnchor>();
        anchors.AddRange(BuildCloudInstanceIdentityAnchors(evidence));
        anchors.AddRange(BuildCloudEnvironmentIdentityAnchors(evidence));
        anchors.AddRange(BuildKubernetesNodeIdentityAnchors(evidence));

        var kubernetesEnvironmentAnchor = BuildKubernetesEnvironmentIdentityAnchor(evidence);
        if (kubernetesEnvironmentAnchor is not null)
        {
            anchors.Add(kubernetesEnvironmentAnchor);
        }

        var deploymentEnvironmentAnchor = BuildDeploymentEnvironmentIdentityAnchor(evidence);
        if (deploymentEnvironmentAnchor is not null)
        {
            anchors.Add(deploymentEnvironmentAnchor);
        }

        var windowsMachineIdAnchor = BuildWindowsMachineIdAnchor(evidence, classification);
        if (windowsMachineIdAnchor is not null)
        {
            anchors.Add(windowsMachineIdAnchor);
        }

        var linuxMachineIdAnchor = BuildLinuxMachineIdAnchor(evidence, classification);
        if (linuxMachineIdAnchor is not null)
        {
            anchors.Add(linuxMachineIdAnchor);
        }

        var hypervisorIdentityAnchor = BuildHypervisorIdentityAnchor(evidence, virtualization);
        if (hypervisorIdentityAnchor is not null)
        {
            anchors.Add(hypervisorIdentityAnchor);
        }

        var tpmPublicKeyAnchor = BuildTpmPublicKeyAnchor(evidence);
        if (tpmPublicKeyAnchor is not null)
        {
            anchors.Add(tpmPublicKeyAnchor);
        }

        var hardwareIdentityAnchor = BuildHardwareIdentityAnchor(evidence);
        if (hardwareIdentityAnchor is not null)
        {
            anchors.Add(hardwareIdentityAnchor);
        }

        var weakHostProfileAnchor = BuildWeakHostProfileIdentityAnchor(evidence, runtimeHostOs, visibleKernel, virtualization, hardware);
        if (weakHostProfileAnchor is not null)
        {
            anchors.Add(weakHostProfileAnchor);
        }

        anchors.AddRange(BuildContainerRuntimeIdentityAnchors(evidence, classification));

        var siemensIedRuntimeAnchor = BuildSiemensIedRuntimeIdentityAnchor(evidence);
        if (siemensIedRuntimeAnchor is not null)
        {
            anchors.Add(siemensIedRuntimeAnchor);
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

    private static IReadOnlyList<IdentityAnchor> BuildCloudEnvironmentIdentityAnchors(IReadOnlyList<EvidenceItem> evidence)
    {
        var anchors = new List<IdentityAnchor>();
        AddCloudEnvironmentIdentityAnchor(anchors, evidence, "aws.account_id", "aws");
        AddCloudEnvironmentIdentityAnchor(anchors, evidence, "azure.subscription_id", "azure");
        AddCloudEnvironmentIdentityAnchor(anchors, evidence, "gcp.project_id", "gcp");
        AddCloudEnvironmentIdentityAnchor(anchors, evidence, "oci.compartment_id", "oci");
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

    private static void AddCloudEnvironmentIdentityAnchor(List<IdentityAnchor> anchors, IReadOnlyList<EvidenceItem> evidence, string key, string provider)
    {
        var environmentId = GetValue(evidence, key);
        if (string.IsNullOrWhiteSpace(environmentId) || string.Equals(environmentId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return;
        }

        anchors.Add(new IdentityAnchor(
            IdentityAnchorKind.CloudEnvironmentIdentity,
            "CRP-CLOUD-ENVIRONMENT-v1",
            ComputeIdentityAnchorDigest($"cloud-environment:{provider}", environmentId),
            IdentityAnchorScope.Platform,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, key, "cloud.source", "cloud.region", "cloud.zone"),
            [$"Cloud environment identifiers may change when workloads move across {provider} accounts, subscriptions, projects, or compartments."],
            [$"Digest derived from observed {provider} environment metadata."]));
    }

    private static IReadOnlyList<IdentityAnchor> BuildKubernetesNodeIdentityAnchors(IReadOnlyList<EvidenceItem> evidence)
    {
        var anchors = new List<IdentityAnchor>();

        var nodeUid = GetValue(evidence, "kubernetes.node.uid");
        if (!string.IsNullOrWhiteSpace(nodeUid) && !string.Equals(nodeUid, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            anchors.Add(new IdentityAnchor(
                IdentityAnchorKind.KubernetesNodeIdentity,
                "CRP-KUBERNETES-NODE-v1",
                ComputeIdentityAnchorDigest("kubernetes-node:uid", nodeUid),
                IdentityAnchorScope.Host,
                BindingSuitability.LicenseBinding,
                IdentityAnchorStrength.Strong,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "kubernetes.node.uid", "kubernetes.node.name", "kubernetes.node.provider_id"),
                [],
                ["Digest derived from Kubernetes node metadata UID."]));
        }

        var providerId = GetValue(evidence, "kubernetes.node.provider_id");
        if (!string.IsNullOrWhiteSpace(providerId) && !string.Equals(providerId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            anchors.Add(new IdentityAnchor(
                IdentityAnchorKind.KubernetesNodeIdentity,
                "CRP-KUBERNETES-NODE-v1",
                ComputeIdentityAnchorDigest("kubernetes-node:provider-id", providerId),
                IdentityAnchorScope.Host,
                BindingSuitability.LicenseBinding,
                IdentityAnchorStrength.Medium,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "kubernetes.node.provider_id", "kubernetes.node.name"),
                [],
                ["Digest derived from Kubernetes node provider ID as a weaker fallback node identity."]));
        }

            return anchors;
    }

    private static IdentityAnchor? BuildKubernetesEnvironmentIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var serviceAccountCaDigest = GetValue(evidence, "serviceaccount.ca.sha256");
        if (string.IsNullOrWhiteSpace(serviceAccountCaDigest) || string.Equals(serviceAccountCaDigest, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        return new IdentityAnchor(
            IdentityAnchorKind.KubernetesEnvironmentIdentity,
            "CRP-KUBERNETES-CLUSTER-CA-v1",
            ComputeIdentityAnchorDigest("kubernetes-cluster:ca", serviceAccountCaDigest),
            IdentityAnchorScope.Platform,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Public,
            GetEvidenceReferencesForKeys(evidence, "serviceaccount.ca.sha256", "env.KUBERNETES_SERVICE_HOST", "api.version.outcome"),
            ["Cluster CA digests may change during control-plane certificate rotation or cluster recreation."],
            ["Digest derived from the visible Kubernetes service-account CA bundle without requiring RBAC."]);
    }

    private static IdentityAnchor? BuildDeploymentEnvironmentIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        static bool IsDeploymentMetadataKey(string key)
            => key == "compose.label.com.docker.compose.project"
               || key == "compose.label.com.docker.stack.namespace"
               || (key.StartsWith("compose.label.io.portainer.", StringComparison.Ordinal)
                   && (key.Contains("stack", StringComparison.OrdinalIgnoreCase)
                       || key.Contains("project", StringComparison.OrdinalIgnoreCase)
                       || key.EndsWith(".name", StringComparison.OrdinalIgnoreCase)
                       || key.EndsWith(".namespace", StringComparison.OrdinalIgnoreCase)));

        var components = evidence
            .Where(item => IsDeploymentMetadataKey(item.Key)
                && !string.IsNullOrWhiteSpace(item.Value)
                && !string.Equals(item.Value, Redaction.RedactedValue, StringComparison.Ordinal))
            .Select(item => (item.Key, Value: item.Value!.Trim()))
            .Distinct()
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .ToArray();

        if (components.Length == 0)
        {
            return null;
        }

        var digestSeed = string.Join("\n", components.Select(component => $"{component.Key}:{component.Value}"));
        return new IdentityAnchor(
            IdentityAnchorKind.DeploymentEnvironmentIdentity,
            "CRP-DEPLOYMENT-METADATA-v1",
            ComputeIdentityAnchorDigest("deployment-metadata", digestSeed),
            IdentityAnchorScope.ApplicationHost,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Public,
            GetEvidenceReferencesForKeys(evidence, components.Select(component => component.Key).ToArray()),
            ["Deployment metadata digests may change when a Compose or Portainer project is renamed, restacked, or redeployed under a different namespace."],
            ["Digest derived from visible Compose or Portainer deployment metadata labels."]);
    }

    private static IdentityAnchor? BuildSiemensIedRuntimeIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var tlsBinding = GetValue(evidence, "trust.ied.endpoint.tls.binding");
        if (!string.Equals(tlsBinding, "matched", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var documentedChainDigest = GetValue(evidence, "trust.ied.certsips.cert_chain_sha256");
        if (string.IsNullOrWhiteSpace(documentedChainDigest) || string.Equals(documentedChainDigest, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        var serviceName = GetValue(evidence, "trust.ied.certsips.service_name");
        var anchorSeed = string.IsNullOrWhiteSpace(serviceName)
            ? documentedChainDigest
            : $"{serviceName.Trim()}\n{documentedChainDigest.Trim()}";

        return new IdentityAnchor(
            IdentityAnchorKind.VendorRuntimeIdentity,
            "CRP-SIEMENS-IED-v1",
            ComputeIdentityAnchorDigest("siemens-ied-runtime:tls-binding", anchorSeed),
            IdentityAnchorScope.Platform,
            BindingSuitability.LicenseBinding,
            IdentityAnchorStrength.Strong,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(
                evidence,
                "trust.ied.certsips.service_name",
                "trust.ied.certsips.cert_chain_sha256",
                "trust.ied.endpoint.tls.binding",
                "trust.ied.endpoint.tls.issuer",
                "trust.ied.endpoint.tls.subject"),
            [],
            ["Digest derived from Siemens IED runtime certificate-chain evidence with matched local TLS binding."]);
    }

    private static IdentityAnchor? BuildWindowsMachineIdAnchor(IReadOnlyList<EvidenceItem> evidence, ReportClassification classification)
    {
        if (classification.IsContainerized.Value == ContainerizationKind.@True)
        {
            return null;
        }

        var machineGuid = GetValue(evidence, "windows.machine_guid");
        if (string.IsNullOrWhiteSpace(machineGuid) || string.Equals(machineGuid, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        return new IdentityAnchor(
            IdentityAnchorKind.MachineIdDigest,
            "CRP-WINDOWS-MACHINE-ID-v1",
            ComputeIdentityAnchorDigest("windows-machine-guid", machineGuid),
            IdentityAnchorScope.Host,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, "windows.machine_guid", "windows.product_name", "kernel.release"),
            ["MachineGuid is installation-stable but may change across OS reinstallation, templating, or image cloning."],
            ["Digest derived from observed Windows MachineGuid registry value."]);
    }

    private static IdentityAnchor? BuildLinuxMachineIdAnchor(IReadOnlyList<EvidenceItem> evidence, ReportClassification classification)
    {
        if (classification.IsContainerized.Value == ContainerizationKind.@True)
        {
            return null;
        }

        var machineId = GetValue(evidence, "machine.id");
        if (string.IsNullOrWhiteSpace(machineId) || string.Equals(machineId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        return new IdentityAnchor(
            IdentityAnchorKind.MachineIdDigest,
            "CRP-LINUX-MACHINE-ID-v1",
            ComputeIdentityAnchorDigest("linux-machine-id", machineId),
            IdentityAnchorScope.Host,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, "machine.id", "os.id", KernelReleaseKey),
            ["machine-id is installation-stable but may change across reinstallation, image cloning, or explicit regeneration."],
            ["Digest derived from observed Linux machine-id value."]);
    }

    private static IdentityAnchor? BuildHardwareIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var components = new[]
        {
            (Key: "dmi.product_uuid", Value: GetValue(evidence, "dmi.product_uuid")),
            (Key: "dmi.product_serial", Value: GetValue(evidence, "dmi.product_serial")),
            (Key: "dmi.board_serial", Value: GetValue(evidence, "dmi.board_serial")),
            (Key: "dmi.chassis_serial", Value: GetValue(evidence, "dmi.chassis_serial")),
            (Key: "device_tree.serial_number", Value: GetValue(evidence, "device_tree.serial_number")),
            (Key: "soc.serial_number", Value: GetValue(evidence, "soc.serial_number")),
            (Key: "cpu.serial", Value: GetValue(evidence, "cpu.serial"))
        }
        .Where(component => !string.IsNullOrWhiteSpace(component.Value) && !string.Equals(component.Value, Redaction.RedactedValue, StringComparison.Ordinal))
        .OrderBy(component => component.Key, StringComparer.Ordinal)
        .ToArray();

        if (components.Length == 0)
        {
            return null;
        }

        var digestSeed = string.Join("\n", components.Select(component => $"{component.Key}:{component.Value!.Trim()}"));
        var evidenceKeys = components.Select(component => component.Key).ToArray();

        return new IdentityAnchor(
            IdentityAnchorKind.HardwareIdentity,
            "CRP-HARDWARE-ID-v1",
            ComputeIdentityAnchorDigest("hardware-identity", digestSeed),
            IdentityAnchorScope.Host,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, evidenceKeys),
            ["Hardware identifiers may change after board replacement, firmware reset, or vendor-specific re-provisioning."],
            ["Digest derived from explicit host-visible hardware identifier signals."]);
    }

    private static IdentityAnchor? BuildHypervisorIdentityAnchor(IReadOnlyList<EvidenceItem> evidence, VirtualizationInfo virtualization)
    {
        if (virtualization.Kind == VirtualizationKind.Unknown)
        {
            return null;
        }

        var productUuid = GetValue(evidence, "dmi.product_uuid");
        if (string.IsNullOrWhiteSpace(productUuid) || string.Equals(productUuid, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        return new IdentityAnchor(
            IdentityAnchorKind.HypervisorIdentity,
            "CRP-HYPERVISOR-INSTANCE-v1",
            ComputeIdentityAnchorDigest("hypervisor-instance", productUuid),
            IdentityAnchorScope.Hypervisor,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Medium,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, "dmi.product_uuid", "cpu.flag.hypervisor", "sys.hypervisor.type", "dmi.sys_vendor", "dmi.product_name"),
            ["Guest-visible VM UUIDs identify the virtual guest or substrate instance, not the physical hypervisor host."],
            [$"Digest derived from a guest-visible VM UUID under {virtualization.Kind} virtualization."]);
    }

    private static IdentityAnchor? BuildTpmPublicKeyAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var source = new[]
        {
            (Key: "device.tpm.ek_cert.sha256", Value: GetValue(evidence, "device.tpm.ek_cert.sha256"), Source: "ek_cert"),
            (Key: "device.tpm.pubek.sha256", Value: GetValue(evidence, "device.tpm.pubek.sha256"), Source: "pubek")
        }
        .FirstOrDefault(candidate => !string.IsNullOrWhiteSpace(candidate.Value) && !string.Equals(candidate.Value, Redaction.RedactedValue, StringComparison.Ordinal));

        if (string.IsNullOrWhiteSpace(source.Value))
        {
            return null;
        }

        return new IdentityAnchor(
            IdentityAnchorKind.TpmPublicKeyDigest,
            "CRP-TPM-PUBLIC-v1",
            ComputeIdentityAnchorDigest("tpm-public-material", source.Value),
            IdentityAnchorScope.Host,
            BindingSuitability.ExternalAttestation,
            IdentityAnchorStrength.Strong,
            IdentityAnchorSensitivity.Sensitive,
            GetEvidenceReferencesForKeys(evidence, source.Key, "device.tpm.path", "trust.windows.tpm.outcome"),
            ["TPM public material identifies a TPM device but does not by itself prove quote freshness, current ownership, or caller binding."],
            [$"Digest derived from read-only TPM public material ({source.Source}) visible to the current process."]);
    }

    private static IdentityAnchor? BuildWeakHostProfileIdentityAnchor(
        IReadOnlyList<EvidenceItem> evidence,
        RuntimeReportedHostOsInfo runtimeHostOs,
        VisibleKernelInfo visibleKernel,
        VirtualizationInfo virtualization,
        HostHardwareInfo hardware)
    {
        var included = new Dictionary<string, string>(StringComparer.Ordinal);
        AddHostProfileComponent(included, "runtime.host.os.normalized", runtimeHostOs.Family != OperatingSystemFamily.Unknown ? runtimeHostOs.Family.ToString() : null);
        AddHostProfileComponent(included, KernelReleaseKey, visibleKernel.Release);
        AddHostProfileComponent(included, "kernel.flavor", visibleKernel.Flavor != KernelFlavor.Unknown ? visibleKernel.Flavor.ToString() : null);
        AddHostProfileComponent(included, "architecture.normalized", hardware.Architecture != ArchitectureKind.Unknown ? hardware.Architecture.ToString() : null);
        AddHostProfileComponent(included, "cpu.vendor", NormalizeHostProfileToken(hardware.Cpu.Vendor));
        AddHostProfileComponent(included, "cpu.family", NormalizeHostProfileToken(hardware.Cpu.Family));
        AddHostProfileComponent(included, "cpu.model_name.normalized", HostParsing.NormalizeModelName(hardware.Cpu.ModelName));
        AddHostProfileComponent(included, "memory.total.bucket", HostParsing.NormalizeMemoryBucket(hardware.Memory.MemTotalBytes));
        AddHostProfileComponent(included, "virtualization.kind", virtualization.Kind != VirtualizationKind.Unknown ? virtualization.Kind.ToString() : null);
        AddHostProfileComponent(included, "virtualization.vendor", NormalizeHostProfileToken(virtualization.PlatformVendor));
        AddHostProfileComponent(included, "dmi.sys_vendor.normalized", NormalizeHostProfileToken(hardware.Dmi.SystemVendor));
        AddHostProfileComponent(included, "dmi.product_name.normalized", NormalizeHostProfileToken(hardware.Dmi.ProductName));
        AddHostProfileComponent(included, "dmi.product_family.normalized", NormalizeHostProfileToken(hardware.Dmi.ProductFamily));
        AddHostProfileComponent(included, "dmi.modalias.family", NormalizeModaliasFamily(hardware.Dmi.Modalias));
        AddHostProfileComponent(included, "platform.modalias.family", NormalizeModaliasFamily(GetValue(evidence, "platform.modalias")));
        AddHostProfileComponent(included, "device_tree.model.normalized", NormalizeHostProfileToken(hardware.DeviceTree.Model));
        AddHostProfileComponent(included, "device_tree.compatible.family", NormalizeCompatibleFamily(hardware.DeviceTree.Compatible));

        var hasProfileSignals = included.Keys.Any(key => key.StartsWith("cpu.", StringComparison.Ordinal)
            || key.StartsWith("memory.", StringComparison.Ordinal)
            || key.StartsWith("dmi.", StringComparison.Ordinal)
            || key.StartsWith("device_tree.", StringComparison.Ordinal)
            || key.StartsWith("platform.", StringComparison.Ordinal)
            || key.StartsWith("virtualization.", StringComparison.Ordinal));
        if (!hasProfileSignals || included.Count < 4)
        {
            return null;
        }

        var fingerprint = HostParsing.ComputeFingerprint(included);
        var evidenceReferences = runtimeHostOs.EvidenceReferences
            .Concat(virtualization.EvidenceReferences)
            .Concat(GetEvidenceReferencesForKeys(
                evidence,
                KernelReleaseKey,
                "runtime.architecture",
                "cpu.vendor",
                "cpu.model_name",
                "memory.mem_total_bytes",
                "docker.info.mem_total",
                "podman.info.mem_total",
                "dmi.sys_vendor",
                "dmi.product_name",
                "dmi.product_family",
                "dmi.modalias",
                "platform.modalias",
                "device_tree.model",
                "device_tree.compatible",
                "cpu.flag.hypervisor",
                "bus.vmbus.present",
                "sys.hypervisor.type"))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        return new IdentityAnchor(
            IdentityAnchorKind.HostProfileIdentity,
            "CRP-HOST-PROFILE-v1",
            ComputeIdentityAnchorDigest("host-profile", fingerprint),
            IdentityAnchorScope.Host,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Weak,
            IdentityAnchorSensitivity.Public,
            evidenceReferences,
            ["Public host-profile digests are weak correlation hints and may collide across similar hosts or drift after kernel, memory, virtualization, or hardware-profile changes."],
            ["Digest derived from coarse host profile signals because no explicit host-bound identifier was visible."]);
    }

    private static void AddHostProfileComponent(IDictionary<string, string> included, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            included[key] = value.Trim();
        }
    }

    private static string? NormalizeHostProfileToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var parts = value.Trim()
            .ToLowerInvariant()
            .Split([' ', '\t', '/', '\\', ',', ';', ':', '|', '(', ')', '[', ']'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(6)
            .ToArray();

        return parts.Length == 0 ? null : string.Join('-', parts);
    }

    private static string? NormalizeModaliasFamily(string? value)
    {
        var normalized = NormalizeHostProfileToken(value);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        var parts = normalized.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(3)
            .ToArray();

        return parts.Length == 0 ? null : string.Join('-', parts);
    }

    private static string? NormalizeCompatibleFamily(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var firstCompatible = value.Split([',', '\n', '\0'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return NormalizeHostProfileToken(firstCompatible);
    }

    private static IdentityAnchor? BuildWorkloadProfileIdentityAnchor(IReadOnlyList<EvidenceItem> evidence)
    {
        var workloadHostname = GetVisibleWorkloadHostname(evidence);
        var kubernetesPodUid = NormalizeWorkloadProfileToken(GetFirstVisibleValue(evidence, "kubernetes.pod.uid", "kubernetes.cgroup.pod_uid"));
        var kubernetesContainerToken = NormalizeWorkloadProfileToken(GetValue(evidence, "kubernetes.cgroup.container_token"));
        var composeProject = NormalizeWorkloadProfileToken(GetValue(evidence, "compose.label.com.docker.compose.project"));
        var composeStackNamespace = NormalizeWorkloadProfileToken(GetValue(evidence, "compose.label.com.docker.stack.namespace"));

        var hasOrchestratorOrComposeContext = !string.IsNullOrWhiteSpace(kubernetesPodUid)
            || !string.IsNullOrWhiteSpace(kubernetesContainerToken)
            || !string.IsNullOrWhiteSpace(composeProject)
            || !string.IsNullOrWhiteSpace(composeStackNamespace);

        // Always drop ephemeral container-ID-style hostnames regardless of context:
        // in Compose/Swarm HOSTNAME defaults to the container ID which changes every restart.
        if (IsLikelyEphemeralWorkloadHostname(workloadHostname))
        {
            workloadHostname = null;
        }

        var included = new Dictionary<string, string>(StringComparer.Ordinal);
        AddWorkloadProfileComponent(included, "workload.hostname", workloadHostname);
        AddWorkloadProfileComponent(included, "kubernetes.pod.uid", kubernetesPodUid);
        AddWorkloadProfileComponent(included, "kubernetes.container.token", kubernetesContainerToken);
        AddWorkloadProfileComponent(included, "compose.project", composeProject);
        AddWorkloadProfileComponent(included, "compose.stack.namespace", composeStackNamespace);

        // Namespace inode signals are weakly workload-scoped only when anchored by stable workload context.
        if (hasOrchestratorOrComposeContext || !string.IsNullOrWhiteSpace(workloadHostname))
        {
            AddWorkloadProfileComponent(included, "namespace.pid", NormalizeWorkloadProfileToken(GetValue(evidence, "ns.pid")));
            AddWorkloadProfileComponent(included, "namespace.mnt", NormalizeWorkloadProfileToken(GetValue(evidence, "ns.mnt")));
            AddWorkloadProfileComponent(included, "namespace.net", NormalizeWorkloadProfileToken(GetValue(evidence, "ns.net")));
        }

        if (included.Count == 0)
        {
            return null;
        }

        var fingerprint = HostParsing.ComputeFingerprint(included);
        var evidenceReferences = GetEvidenceReferencesForKeys(
            evidence,
            "HOSTNAME",
            "kernel.hostname",
            "/etc/hostname",
            "/proc/sys/kernel/hostname",
            "kubernetes.pod.uid",
            "kubernetes.cgroup.pod_uid",
            "kubernetes.cgroup.container_token",
            "ns.pid",
            "ns.mnt",
            "ns.net",
            "compose.label.com.docker.compose.project",
            "compose.label.com.docker.stack.namespace");

        return new IdentityAnchor(
            IdentityAnchorKind.WorkloadProfileIdentity,
            "CRP-WORKLOAD-PROFILE-v1",
            ComputeIdentityAnchorDigest("workload-profile", fingerprint),
            IdentityAnchorScope.Workload,
            BindingSuitability.Correlation,
            IdentityAnchorStrength.Weak,
            IdentityAnchorSensitivity.Sensitive,
            evidenceReferences,
            ["Workload profile digests are correlation-only hints and may change when the workload hostname, namespaces, pod placement, or compose context changes."],
            ["Digest derived from workload-scoped hostname and visible namespace or orchestration signals inside the current container."]);
    }

    private static void AddWorkloadProfileComponent(IDictionary<string, string> included, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            included[key] = value.Trim();
        }
    }

    private static string? GetVisibleWorkloadHostname(IReadOnlyList<EvidenceItem> evidence)
    {
        foreach (var key in WorkloadHostnameEvidenceKeys)
        {
            var normalized = NormalizeWorkloadHostname(GetValue(evidence, key));
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized;
            }
        }

        return null;
    }

    private static string? GetFirstVisibleValue(IReadOnlyList<EvidenceItem> evidence, params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = GetValue(evidence, key);
            if (!string.IsNullOrWhiteSpace(value) && !string.Equals(value, Redaction.RedactedValue, StringComparison.Ordinal))
            {
                return value;
            }
        }

        return null;
    }

    private static string? NormalizeWorkloadHostname(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        var normalized = value.Trim().Trim('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized is "localhost" or "localhost.localdomain" or "(none)" or "none" or "unknown")
        {
            return null;
        }

        return normalized;
    }

    private static bool IsLikelyEphemeralWorkloadHostname(string? normalizedHostname)
    {
        if (string.IsNullOrWhiteSpace(normalizedHostname))
        {
            return false;
        }

        var value = normalizedHostname.Trim();
        return (value.Length == 12 || value.Length == 64)
            && value.All(static character => char.IsAsciiHexDigit(character));
    }

    private static string? NormalizeWorkloadProfileToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            return null;
        }

        return value.Trim().ToLowerInvariant();
    }

    private static IReadOnlyList<IdentityAnchor> BuildContainerRuntimeIdentityAnchors(IReadOnlyList<EvidenceItem> evidence, ReportClassification classification)
    {
        if (classification.IsContainerized.Value != ContainerizationKind.@True)
        {
            return [];
        }

        var anchors = new List<IdentityAnchor>();

        var workloadProfileAnchor = BuildWorkloadProfileIdentityAnchor(evidence);
        if (workloadProfileAnchor is not null)
        {
            anchors.Add(workloadProfileAnchor);
        }

        var containerId = GetValue(evidence, "container.id");
        if (!string.IsNullOrWhiteSpace(containerId) && !string.Equals(containerId, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            anchors.Add(new IdentityAnchor(
                IdentityAnchorKind.ContainerRuntimeIdentity,
                "CRP-CONTAINER-INSTANCE-v1",
                ComputeIdentityAnchorDigest("container-runtime:id", containerId),
                IdentityAnchorScope.Workload,
                BindingSuitability.Correlation,
                IdentityAnchorStrength.Medium,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "container.id", "container.inspect.outcome"),
                ["Container IDs are runtime-scoped and change whenever the container instance is recreated."],
                ["Digest derived from observed runtime inspect container ID."]));
        }

        var kubernetesPodUid = new[]
        {
            GetValue(evidence, "kubernetes.pod.uid"),
            GetValue(evidence, "kubernetes.cgroup.pod_uid")
        }
        .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value) && !string.Equals(value, Redaction.RedactedValue, StringComparison.Ordinal));

        var kubernetesContainerToken = GetValue(evidence, "kubernetes.cgroup.container_token");
        if (!string.IsNullOrWhiteSpace(kubernetesContainerToken) && !string.Equals(kubernetesContainerToken, Redaction.RedactedValue, StringComparison.Ordinal))
        {
            var anchorSeed = string.IsNullOrWhiteSpace(kubernetesPodUid)
                ? kubernetesContainerToken
                : $"{kubernetesPodUid}\n{kubernetesContainerToken}";

            anchors.Add(new IdentityAnchor(
                IdentityAnchorKind.ContainerRuntimeIdentity,
                "CRP-KUBERNETES-WORKLOAD-v1",
                ComputeIdentityAnchorDigest("kubernetes-workload:container-token", anchorSeed),
                IdentityAnchorScope.Workload,
                BindingSuitability.Correlation,
                IdentityAnchorStrength.Medium,
                IdentityAnchorSensitivity.Sensitive,
                GetEvidenceReferencesForKeys(evidence, "kubernetes.pod.uid", "kubernetes.cgroup.pod_uid", "kubernetes.cgroup.container_token"),
                ["Kubernetes workload tokens are pod or container-instance scoped and change whenever the pod is recreated or the container is restarted."],
                ["Digest derived from Kubernetes pod metadata and cgroup-derived container token as a workload-scoped fallback identity."]));
        }

        return anchors;
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
