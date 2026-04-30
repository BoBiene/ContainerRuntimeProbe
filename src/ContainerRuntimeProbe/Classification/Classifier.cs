using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal static class Classifier
{
    public static ReportClassification Classify(IReadOnlyList<ProbeResult> probes)
    {
        var e = probes.SelectMany(x => x.Evidence).ToList();

        static Confidence ScoreToConfidence(int score) => score switch { >= 8 => Confidence.High, >= 4 => Confidence.Medium, >= 1 => Confidence.Low, _ => Confidence.Unknown };
        ClassificationResult<TValue> Make<TValue>(TValue value, int score, params ClassificationReason[] reasons) where TValue : struct, Enum => new(value, ScoreToConfidence(score), reasons);
        ClassificationResult<TValue> MakeWithConfidence<TValue>(TValue value, Confidence confidence, params ClassificationReason[] reasons) where TValue : struct, Enum => new(value, confidence, reasons);

        // Helper: match evidence key in both raw (VARNAME) and env-prefixed (env.VARNAME) forms
        static bool HasEnvKey(List<EvidenceItem> ev, string key) =>
            ev.Any(x => x.Key == key || x.Key == "env." + key);

        static string? GetFirstMatchingValue(IEnumerable<EvidenceItem> ev, params string[] keys)
            => ev.FirstOrDefault(item => keys.Contains(item.Key, StringComparer.Ordinal))?.Value;

        static IEnumerable<string> GetValues(IEnumerable<EvidenceItem> ev, params string[] keys)
            => ev.Where(item => keys.Contains(item.Key, StringComparer.Ordinal))
                .Select(item => item.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))!;

        static int? ParseLeadingMajor(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            var segments = value.Trim().Split(['.', '-', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var token = segments.FirstOrDefault();
            return int.TryParse(token, out var major) ? major : null;
        }

        static bool ContainsAny(string? value, params string[] fragments)
            => !string.IsNullOrWhiteSpace(value) && fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));

        static bool ContainsAnySignal(string? value, IEnumerable<string> fragments)
            => !string.IsNullOrWhiteSpace(value) && fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));

        static bool IsCloudMetadataSuccess(EvidenceItem item)
            => item.Key is "aws.imds.identity.outcome" or "azure.imds.outcome" or "gcp.metadata.outcome" or "oci.metadata.outcome"
               && string.Equals(item.Value, "Success", StringComparison.Ordinal);

        static bool IsConsumerCpu(string? cpuModel)
            // Keep this list conservative and update it as common consumer/workstation families evolve (reviewed for 2026-era models).
            => ContainsAny(cpuModel, "pentium", "celeron", "ryzen", "athlon", "threadripper", "core i", "intel core", "apple m");

        static bool IsHomeDns(string? dnsDomain)
        {
            if (string.IsNullOrWhiteSpace(dnsDomain))
            {
                return false;
            }

            var normalizedDomain = dnsDomain.Trim().TrimEnd('.');
            if (normalizedDomain.Equals("cluster.local", StringComparison.OrdinalIgnoreCase)
                || normalizedDomain.EndsWith(".cluster.local", StringComparison.OrdinalIgnoreCase)
                || normalizedDomain.Equals("dns.podman", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return DetectionMaps.HomeDnsSignals.Any(signal =>
                string.Equals(signal, "lan", StringComparison.Ordinal)
                    ? normalizedDomain.Equals(signal, StringComparison.OrdinalIgnoreCase)
                    : normalizedDomain.EndsWith(signal, StringComparison.OrdinalIgnoreCase));
        }

        static bool IsCorporateDns(string? dnsDomain)
        {
            if (string.IsNullOrWhiteSpace(dnsDomain) || IsHomeDns(dnsDomain))
            {
                return false;
            }

            if (!dnsDomain.Contains('.', StringComparison.Ordinal))
            {
                return false;
            }

            return !dnsDomain.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                && !dnsDomain.EndsWith(".localdomain", StringComparison.OrdinalIgnoreCase)
                && !dnsDomain.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                && !dnsDomain.Equals("internal", StringComparison.OrdinalIgnoreCase)
                && !dnsDomain.Equals("localdomain", StringComparison.OrdinalIgnoreCase);
        }

        static bool IsCustomCompiler(string? compiler, string? procVersion)
                => ContainsAnySignal(compiler, DetectionMaps.CustomCompilerSignals)
                    || ContainsAnySignal(procVersion, DetectionMaps.CustomCompilerSignals);

        static bool IsVendorAppliance(string? osId, string? osName, string? prettyName)
                => ContainsAnySignal(osId, DetectionMaps.VendorApplianceSignals)
                    || ContainsAnySignal(osName, DetectionMaps.VendorApplianceSignals)
                    || ContainsAnySignal(prettyName, DetectionMaps.VendorApplianceSignals);

        static bool IsAppliancePlatformVendor(PlatformVendorKind vendor)
            => vendor is PlatformVendorKind.Synology
                or PlatformVendorKind.Siemens
                or PlatformVendorKind.SiemensIndustrialEdge
                or PlatformVendorKind.Wago
                or PlatformVendorKind.Beckhoff
                or PlatformVendorKind.PhoenixContact
                or PlatformVendorKind.Advantech
                or PlatformVendorKind.Moxa
                or PlatformVendorKind.BoschRexroth
                or PlatformVendorKind.SchneiderElectric
                or PlatformVendorKind.BAndR
                or PlatformVendorKind.IoTEdge;

        static bool IsKernelUserspaceMismatch(string? osVersion, int? kernelMajor)
        {
            if (kernelMajor is null || kernelMajor >= 4)
            {
                return false;
            }

            var distroMajor = ParseLeadingMajor(osVersion);
            return distroMajor is >= 10;
        }

        // ── IsContainerized ──────────────────────────────────────────────────────
        var containerScore = 0;
        var containerReasons = new List<ClassificationReason>();
        if (e.Any(x => x.Key == "/.dockerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/.dockerenv exists", new[] { "/.dockerenv" })); }
        if (e.Any(x => x.Key == "/run/.containerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/run/.containerenv exists", new[] { "/run/.containerenv" })); }
        var hasDockerCgroupSignal = e.Any(x =>
            (x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal"))
            && x.Value?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true);
        if (hasDockerCgroupSignal) { containerScore += 3; containerReasons.Add(new("Cgroup contains docker path", new[] { "/proc/self/cgroup", "/proc/1/cgroup" })); }
        if (e.Any(x => x.Key.Contains("mountinfo:signal", StringComparison.OrdinalIgnoreCase) && string.Equals(x.Value, "overlay", StringComparison.OrdinalIgnoreCase))) { containerScore += 3; containerReasons.Add(new("Overlay mount detected", new[] { "/proc/self/mountinfo", "/proc/1/mountinfo" })); }
        if (HasEnvKey(e, "KUBERNETES_SERVICE_HOST")) { containerScore += 2; containerReasons.Add(new("Kubernetes service environment detected", new[] { "KUBERNETES_SERVICE_HOST" })); }
        if (e.Any(x => x.Key == "serviceaccount.token")) { containerScore += 3; containerReasons.Add(new("Kubernetes service account token mounted", new[] { "serviceaccount.token" })); }
        if (e.Any(x => x.Key.Contains("mountinfo:signal", StringComparison.OrdinalIgnoreCase) && x.Value is "kubelet" or "kubernetes-serviceaccount")) { containerScore += 3; containerReasons.Add(new("Kubernetes mount signal detected", new[] { "/proc/self/mountinfo", "/proc/1/mountinfo" })); }
        var containerEvidenceAvailable =
            probes.Any(probe => probe.ProbeId == "marker-files")
            || probes.Any(probe => probe.ProbeId == "proc-files" && probe.Outcome == ProbeOutcome.Success);
        var isContainerized = containerScore > 0
            ? Make(ContainerizationKind.@True, containerScore, containerReasons.ToArray())
            : containerEvidenceAvailable
                ? MakeWithConfidence(ContainerizationKind.@False, Confidence.High, new ClassificationReason("No container markers detected in marker files, cgroup paths, or mountinfo", new[] { "/.dockerenv", "/proc/self/cgroup", "/proc/self/mountinfo" }))
                : MakeWithConfidence(ContainerizationKind.Unknown, Confidence.Unknown, new ClassificationReason("Container markers were not available", Array.Empty<string>()));

        // ── Virtualization / Host / Environment ────────────────────────────────
        var virtualizationMatch = VirtualizationDetection.Detect(e);
        var virtualizationReasons = virtualizationMatch is null
            ? Array.Empty<ClassificationReason>()
            : [new ClassificationReason(virtualizationMatch.Summary, virtualizationMatch.EvidenceReferences)];

        var virtualization = virtualizationMatch is not null
            ? MakeWithConfidence(VirtualizationDetection.ToClassificationKind(virtualizationMatch.Kind), virtualizationMatch.Confidence, virtualizationReasons)
            : MakeWithConfidence(
                probes.Any(probe => probe.ProbeId == "proc-files" && probe.Outcome == ProbeOutcome.Success)
                    ? VirtualizationClassificationKind.None
                    : VirtualizationClassificationKind.Unknown,
                probes.Any(probe => probe.ProbeId == "proc-files" && probe.Outcome == ProbeOutcome.Success) ? Confidence.Medium : Confidence.Unknown,
                new ClassificationReason("No virtualization fingerprint detected", new[] { "cpu.flag.hypervisor", "sys.hypervisor.type", "dmi.sys_vendor", "dmi.product_name" }));

        var hostFamily = virtualization.Value == VirtualizationClassificationKind.WSL2
            ? MakeWithConfidence(OperatingSystemFamily.Windows, Confidence.High, new ClassificationReason("WSL2 implies a Windows underlying host OS", new[] { "kernel.release", "/proc/version" }))
            : MakeWithConfidence(OperatingSystemFamily.Linux, e.Any(x => x.Key is "kernel.release" or "/proc/version" or "os.id") ? Confidence.High : Confidence.Unknown, new ClassificationReason("Visible kernel does not match WSL2 and remains Linux", new[] { "kernel.release", "/proc/version", "os.id" }));

        var kernelRelease = GetFirstMatchingValue(e, "kernel.release");
        var kernelMajor = ParseLeadingMajor(kernelRelease);
        var osId = GetFirstMatchingValue(e, "os.id");
        var osName = GetFirstMatchingValue(e, "os.name");
        var prettyName = GetFirstMatchingValue(e, "os.pretty_name");
        var osVersion = GetFirstMatchingValue(e, "os.version_id", "os.version");
        var kernelCompiler = GetFirstMatchingValue(e, "kernel.compiler");
        var procVersion = GetFirstMatchingValue(e, "/proc/version");
        var vendor = VendorDetection.Detect(e, osId, osName, prettyName);

        var applianceScore = 0;
        var applianceReasons = new List<ClassificationReason>();
        if (IsVendorAppliance(osId, osName, prettyName))
        {
            applianceScore += 5;
            applianceReasons.Add(new("OS release identifies a vendor appliance distribution", new[] { "os.id", "os.name", "os.pretty_name" }));
        }
        if (kernelMajor is < 4)
        {
            applianceScore += 3;
            applianceReasons.Add(new("Kernel major version is older than 4.x", new[] { "kernel.release" }));
        }
        if (IsKernelUserspaceMismatch(osVersion, kernelMajor))
        {
            applianceScore += 3;
            applianceReasons.Add(new("Kernel version is much older than the detected userspace release", new[] { "kernel.release", "os.version_id", "os.version" }));
        }
        if (IsCustomCompiler(kernelCompiler, procVersion))
        {
            applianceScore += 2;
            applianceReasons.Add(new("Kernel compiler/toolchain looks vendor-customized", new[] { "kernel.compiler", "/proc/version" }));
        }

        var hostType = virtualization.Value == VirtualizationClassificationKind.WSL2
            ? MakeWithConfidence(HostTypeKind.WSL2, Confidence.High, virtualizationReasons.ToArray())
            : applianceScore >= 5
                ? Make(HostTypeKind.Appliance, applianceScore, applianceReasons.ToArray())
                : IsAppliancePlatformVendor(vendor.Value)
                    ? MakeWithConfidence(HostTypeKind.Appliance, vendor.Confidence, vendor.Reasons.ToArray())
                : kernelMajor is >= 5
                    ? MakeWithConfidence(HostTypeKind.StandardLinux, osId is null ? Confidence.Medium : Confidence.High, new ClassificationReason("Modern kernel and userspace do not show appliance mismatch signals", new[] { "kernel.release", "os.id", "os.version_id" }))
                    : MakeWithConfidence(HostTypeKind.Unknown, Confidence.Low, new ClassificationReason("Linux host signals are incomplete or not conclusive enough for StandardLinux/Appliance", new[] { "kernel.release", "os.version_id", "kernel.compiler" }));

        var environmentReasons = new List<ClassificationReason>();
        var metadataSuccess = e.Where(IsCloudMetadataSuccess).ToArray();
        var environmentType = metadataSuccess.Length > 0
            ? MakeWithConfidence(EnvironmentTypeKind.Cloud, Confidence.High, new ClassificationReason("Cloud metadata endpoint responded successfully", metadataSuccess.Select(item => item.Key).ToArray()))
            : BuildOnPrem();

        ClassificationResult<EnvironmentTypeKind> BuildOnPrem()
        {
            var onPremScore = 0;
            if (probes.Any(probe => probe.ProbeId == "cloud-metadata"))
            {
                onPremScore += 1;
                environmentReasons.Add(new("No cloud metadata endpoint succeeded", new[] { "aws.imds.identity.outcome", "azure.imds.outcome", "gcp.metadata.outcome", "oci.metadata.outcome" }));
            }

            var cpuModel = GetFirstMatchingValue(e, "cpu.model_name");
            if (IsConsumerCpu(cpuModel))
            {
                onPremScore += 2;
                environmentReasons.Add(new("CPU model resembles a consumer/workstation system", new[] { "cpu.model_name" }));
            }

            var homeDnsSignals = GetValues(e, "dns-search").Where(IsHomeDns).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (homeDnsSignals.Length > 0)
            {
                onPremScore += 2;
                environmentReasons.Add(new("DNS search domain looks like a home or LAN network", new[] { "dns-search" }));
            }

            var corporateDnsSignals = GetValues(e, "dns-search").Where(IsCorporateDns).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (corporateDnsSignals.Length > 0)
            {
                onPremScore += 2;
                environmentReasons.Add(new("DNS search domain looks like a managed corporate domain", new[] { "dns-search" }));
            }

            if (hostType.Value == HostTypeKind.Appliance)
            {
                onPremScore += 2;
                environmentReasons.Add(new("Host signals indicate a non-cloud appliance-style system", new[] { "os.id", "kernel.release", "kernel.compiler" }));
            }
            else if (hostType.Value == HostTypeKind.StandardLinux && hostType.Confidence is Confidence.Medium or Confidence.High)
            {
                onPremScore += 1;
                environmentReasons.Add(new("Host signals indicate a conventional Linux machine outside WSL2", new[] { "kernel.release", "os.id", "os.version_id" }));
            }

            if (e.Any(item => item.Key == "default-route-device"))
            {
                onPremScore += 1;
                environmentReasons.Add(new("Default route device is visible from the host network stack", new[] { "default-route-device" }));
            }

            return onPremScore >= 4
                ? Make(EnvironmentTypeKind.OnPrem, onPremScore, environmentReasons.ToArray())
                : MakeWithConfidence(EnvironmentTypeKind.Unknown, onPremScore > 0 ? Confidence.Low : Confidence.Unknown, environmentReasons.Count == 0 ? [new ClassificationReason("No cloud metadata success and no strong on-prem corroboration", new[] { "aws.imds.identity.outcome", "azure.imds.outcome", "gcp.metadata.outcome", "oci.metadata.outcome", "cpu.model_name", "dns-search", "default-route-device", "kernel.release", "os.id" })] : environmentReasons.ToArray());
        }

        // ── ContainerRuntime ─────────────────────────────────────────────────────
        var runtimeScore = new Dictionary<ContainerRuntimeKind, int>();
        var runtimeReasons = new Dictionary<ContainerRuntimeKind, List<ClassificationReason>>();
        void AddRuntime(ContainerRuntimeKind name, int points, string reason, params string[] refs)
        {
            runtimeScore[name] = runtimeScore.GetValueOrDefault(name) + points;
            if (!runtimeReasons.TryGetValue(name, out var list)) { list = new List<ClassificationReason>(); runtimeReasons[name] = list; }
            list.Add(new ClassificationReason(reason, refs));
        }

        // Podman: libpod endpoint key or body containing "Podman"
        if (e.Any(x => x.Key.Contains("/libpod/", StringComparison.OrdinalIgnoreCase))) AddRuntime(ContainerRuntimeKind.Podman, 6, "Libpod API endpoint present", "runtime-api");
        if (e.Any(x => x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime(ContainerRuntimeKind.Podman, 4, "Podman in API response body", "runtime-api");
        if (e.Any(x => x.Key == "socket.present" && x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime(ContainerRuntimeKind.Podman, 2, "Podman socket path present", "runtime-api");
        if (e.Any(x => x.Key is "container" or "CONTAINER" && (x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true || x.Value?.Contains("libpod", StringComparison.OrdinalIgnoreCase) == true))) AddRuntime(ContainerRuntimeKind.Podman, 4, "Environment reports Podman container runtime", "environment");

        // Docker: _ping on docker.sock or Docker in version body
        if (e.Any(x => x.Key.Contains("/_ping", StringComparison.OrdinalIgnoreCase) && x.Key.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) AddRuntime(ContainerRuntimeKind.Docker, 6, "Docker /_ping succeeded", "runtime-api");
        if (e.Any(x => x.Value?.Contains("\"docker\"", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime(ContainerRuntimeKind.Docker, 4, "Docker in API version body", "runtime-api");
        if (e.Any(x => x.Value?.Contains("containerd", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime(ContainerRuntimeKind.Containerd, 4, "containerd signal in API body", "runtime-api");
        if (e.Any(x => (x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal")) && x.Value?.Contains("/docker/", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime(ContainerRuntimeKind.Docker, 3, "Docker cgroup path", "proc-files");
        if (e.Any(x => (x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal")) && x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime(ContainerRuntimeKind.Podman, 3, "Podman cgroup path", "proc-files");
        if (e.Any(x => x.Value?.Contains("containerd", StringComparison.OrdinalIgnoreCase) == true && x.Key.Contains("mountinfo", StringComparison.OrdinalIgnoreCase))) AddRuntime(ContainerRuntimeKind.Containerd, 3, "containerd mount signal", "proc-files");

        var runtime = runtimeScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var runtimeClass = runtime.Equals(default(KeyValuePair<ContainerRuntimeKind, int>))
            ? Make(ContainerRuntimeKind.Unknown, 0, new ClassificationReason("No runtime evidence", Array.Empty<string>()))
            : Make(runtime.Key, runtime.Value, (runtimeReasons.TryGetValue(runtime.Key, out var rtReasons) ? rtReasons : new List<ClassificationReason>()).ToArray());

        // ── RuntimeApi ───────────────────────────────────────────────────────────
        var runtimeApiScore = 0;
        var runtimeApiName = RuntimeApiKind.Unknown;
        if (e.Any(x => x.Key.Contains("/libpod/_ping", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) { runtimeApiScore = 8; runtimeApiName = RuntimeApiKind.PodmanLibpodApi; }
        else if (e.Any(x => x.Key.Contains("/_ping", StringComparison.OrdinalIgnoreCase) && x.Key.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) { runtimeApiScore = 7; runtimeApiName = RuntimeApiKind.DockerEngineApi; }
        else if (e.Any(x => x.Key.Contains("/libpod/", StringComparison.OrdinalIgnoreCase))) { runtimeApiScore = 5; runtimeApiName = RuntimeApiKind.PodmanLibpodApi; }
        else if (e.Any(x => x.Key == "api.version.outcome" && x.Value == "Success")) { runtimeApiScore = 5; runtimeApiName = RuntimeApiKind.KubernetesApi; }
        var runtimeApi = Make(runtimeApiName, runtimeApiScore, new ClassificationReason("Runtime API probe outcomes", new[] { "runtime-api" }));

        // ── Orchestrator ─────────────────────────────────────────────────────────
        var orchScore = new Dictionary<OrchestratorKind, int>();
        void AddOrch(OrchestratorKind n, int p) => orchScore[n] = orchScore.GetValueOrDefault(n) + p;
        if (e.Any(x => x.Key.StartsWith("env.KUBERNETES_") || x.Key.StartsWith("KUBERNETES_")) || e.Any(x => x.Key == "serviceaccount.token")) AddOrch(OrchestratorKind.Kubernetes, 8);
        if (e.Any(x => x.Key.StartsWith("ecs.") && x.Value == "Success")) AddOrch(OrchestratorKind.AwsEcs, 8);
        if (e.Any(x => x.Key is "env.K_SERVICE" or "K_SERVICE" or "env.K_REVISION" or "K_REVISION" or "env.K_CONFIGURATION" or "K_CONFIGURATION")) AddOrch(OrchestratorKind.CloudRun, 7);
        if (e.Any(x => x.Key is "env.CONTAINER_APP_NAME" or "CONTAINER_APP_NAME" or "env.CONTAINER_APP_REVISION" or "CONTAINER_APP_REVISION")) AddOrch(OrchestratorKind.AzureContainerApps, 7);
        if (e.Any(x => x.Key is "env.NOMAD_JOB_NAME" or "NOMAD_JOB_NAME" or "env.NOMAD_ALLOC_ID" or "NOMAD_ALLOC_ID")) AddOrch(OrchestratorKind.Nomad, 6);
        if (HasEnvKey(e, "OPENSHIFT_BUILD_NAME") || HasEnvKey(e, "OPENSHIFT_BUILD_NAMESPACE")) AddOrch(OrchestratorKind.OpenShift, 6);
        if (e.Any(x => x.Key.Contains("compose", StringComparison.OrdinalIgnoreCase))) AddOrch(OrchestratorKind.DockerCompose, 5);
        var orch = orchScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var orchestrator = orch.Equals(default(KeyValuePair<OrchestratorKind, int>))
            ? Make(OrchestratorKind.Unknown, 0, new ClassificationReason("No orchestrator markers", Array.Empty<string>()))
            : Make(orch.Key, orch.Value, new ClassificationReason("Weighted orchestrator score", new[] { "environment", "kubernetes", "cloud-metadata" }));

        // ── CloudProvider ────────────────────────────────────────────────────────
        // Only attribute cloud when there is positive (Success) evidence, not just probe-ran evidence.
        var cloud = CloudProviderKind.Unknown;
        var cloudScore = 0;

        // AWS: IMDS token+identity succeeded, or ECS metadata succeeded, or explicit AWS env
        if (e.Any(x => x.Key == "aws.imds.identity.outcome" && x.Value == "Success")) { cloud = CloudProviderKind.AWS; cloudScore = 8; }
        else if (e.Any(x => x.Key.StartsWith("ecs.") && x.Value == "Success")) { cloud = CloudProviderKind.AWS; cloudScore = 6; }
        else if (e.Any(x => x.Key.StartsWith("env.AWS_") || x.Key.StartsWith("AWS_"))) { cloud = CloudProviderKind.AWS; cloudScore = 4; }
        // Azure: IMDS succeeded or Azure-specific env vars
        else if (e.Any(x => x.Key == "azure.imds.outcome" && x.Value == "Success")) { cloud = CloudProviderKind.Azure; cloudScore = 8; }
        else if (e.Any(x => x.Key is "env.WEBSITE_SITE_NAME" or "WEBSITE_SITE_NAME" or "env.WEBSITE_INSTANCE_ID" or "WEBSITE_INSTANCE_ID")) { cloud = CloudProviderKind.Azure; cloudScore = 5; }
        // GCP: metadata server succeeded
        else if (e.Any(x => x.Key == "gcp.metadata.outcome" && x.Value == "Success")) { cloud = CloudProviderKind.GoogleCloud; cloudScore = 8; }
        // OCI: metadata server succeeded
        else if (e.Any(x => x.Key == "oci.metadata.outcome" && x.Value == "Success")) { cloud = CloudProviderKind.OracleCloud; cloudScore = 7; }
        var cloudProvider = Make(cloud, cloudScore, new ClassificationReason("Cloud metadata/env markers", new[] { "cloud-metadata" }));

        return new ReportClassification(
            isContainerized,
            runtimeClass,
            virtualization,
            new HostClassificationResult(hostFamily, hostType),
            new EnvironmentClassificationResult(environmentType),
            runtimeApi,
            orchestrator,
            cloudProvider,
            vendor);
    }
}
