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
        ClassificationResult Make(string value, int score, params ClassificationReason[] reasons) => new(value, ScoreToConfidence(score), reasons);
        ClassificationResult MakeWithConfidence(string value, Confidence confidence, params ClassificationReason[] reasons) => new(value, confidence, reasons);

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

        static bool IsCloudMetadataSuccess(EvidenceItem item)
            => item.Key is "aws.imds.identity.outcome" or "azure.imds.outcome" or "gcp.metadata.outcome" or "oci.metadata.outcome"
               && string.Equals(item.Value, "Success", StringComparison.Ordinal);

        static bool IsConsumerCpu(string? cpuModel)
            // Keep this list conservative and update it as common consumer/workstation families evolve (reviewed for 2026-era models).
            => ContainsAny(cpuModel, "pentium", "celeron", "ryzen", "athlon", "threadripper", "core i", "intel core", "apple m");

        static bool IsHomeDns(string? dnsDomain)
            => !string.IsNullOrWhiteSpace(dnsDomain)
               && (dnsDomain.Equals("lan", StringComparison.OrdinalIgnoreCase)
                   || dnsDomain.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
                   || dnsDomain.EndsWith(".home", StringComparison.OrdinalIgnoreCase)
                   || dnsDomain.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                   || dnsDomain.EndsWith("fritz.box", StringComparison.OrdinalIgnoreCase));

        static bool IsCorporateDns(string? dnsDomain)
            => !string.IsNullOrWhiteSpace(dnsDomain)
               && dnsDomain.Contains('.', StringComparison.Ordinal)
               && !IsHomeDns(dnsDomain);

        static bool IsOnPremDmiVendor(string? dmiVendor)
            => ContainsAny(dmiVendor, "dell", "lenovo", "hewlett-packard", "hp", "asus", "asustek", "supermicro", "gigabyte", "msi", "fujitsu", "vmware", "qemu", "innotek", "oracle virtualbox")
               && !ContainsAny(dmiVendor, "amazon ec2", "google", "microsoft corporation", "oraclecloud", "alibaba");

        static bool IsCustomCompiler(string? compiler, string? procVersion)
            => ContainsAny(compiler, "crosstool", "buildroot", "uclibc", "musl", "synology", "qnap")
               || ContainsAny(procVersion, "crosstool", "buildroot", "uclibc", "synology", "qnap");

        static bool IsVendorAppliance(string? osId, string? osName, string? prettyName)
            => ContainsAny(osId, "synology", "qnap", "qts", "quts", "dsm")
               || ContainsAny(osName, "synology", "qnap", "diskstation", "qts", "quts")
               || ContainsAny(prettyName, "synology", "qnap", "diskstation", "qts", "quts");

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
        var containerEvidenceAvailable =
            probes.Any(probe => probe.ProbeId == "marker-files")
            || probes.Any(probe => probe.ProbeId == "proc-files" && probe.Outcome == ProbeOutcome.Success);
        var isContainerized = containerScore > 0
            ? Make("True", containerScore, containerReasons.ToArray())
            : containerEvidenceAvailable
                ? MakeWithConfidence("False", Confidence.High, new ClassificationReason("No container markers detected in marker files, cgroup paths, or mountinfo", new[] { "/.dockerenv", "/proc/self/cgroup", "/proc/self/mountinfo" }))
                : MakeWithConfidence("Unknown", Confidence.Unknown, new ClassificationReason("Container markers were not available", Array.Empty<string>()));

        // ── Virtualization / Host / Environment ────────────────────────────────
        var virtualizationReasons = new List<ClassificationReason>();
        if (e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "WSL2", StringComparison.OrdinalIgnoreCase)))
        {
            virtualizationReasons.Add(new("kernel.flavor reports WSL2", new[] { "kernel.flavor" }));
        }
        if (e.Any(x => x.Key == "kernel.release" && HostParsing.ContainsWsl2Signal(x.Value)))
        {
            virtualizationReasons.Add(new("kernel.release contains microsoft-standard-WSL2", new[] { "kernel.release" }));
        }
        if (e.Any(x => x.Key == "/proc/version" && HostParsing.ContainsWsl2Signal(x.Value)))
        {
            virtualizationReasons.Add(new("/proc/version contains microsoft-standard-WSL2", new[] { "/proc/version" }));
        }

        var virtualization = virtualizationReasons.Count > 0
            ? MakeWithConfidence("WSL2", Confidence.High, virtualizationReasons.ToArray())
            : MakeWithConfidence("None", probes.Any(probe => probe.ProbeId == "proc-files" && probe.Outcome == ProbeOutcome.Success) ? Confidence.Medium : Confidence.Unknown, new ClassificationReason("No WSL2 kernel fingerprint detected", new[] { "kernel.release", "/proc/version" }));

        var hostFamily = virtualization.Value == "WSL2"
            ? MakeWithConfidence("Windows", Confidence.High, new ClassificationReason("WSL2 implies a Windows underlying host OS", new[] { "kernel.release", "/proc/version" }))
            : MakeWithConfidence("Linux", e.Any(x => x.Key is "kernel.release" or "/proc/version" or "os.id") ? Confidence.High : Confidence.Unknown, new ClassificationReason("Visible kernel does not match WSL2 and remains Linux", new[] { "kernel.release", "/proc/version", "os.id" }));

        var kernelRelease = GetFirstMatchingValue(e, "kernel.release");
        var kernelMajor = ParseLeadingMajor(kernelRelease);
        var osId = GetFirstMatchingValue(e, "os.id");
        var osName = GetFirstMatchingValue(e, "os.name");
        var prettyName = GetFirstMatchingValue(e, "os.pretty_name");
        var osVersion = GetFirstMatchingValue(e, "os.version_id", "os.version");
        var kernelCompiler = GetFirstMatchingValue(e, "kernel.compiler");
        var procVersion = GetFirstMatchingValue(e, "/proc/version");

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

        var hostType = virtualization.Value == "WSL2"
            ? MakeWithConfidence("WSL2", Confidence.High, virtualizationReasons.ToArray())
            : applianceScore >= 5
                ? Make("Appliance", applianceScore, applianceReasons.ToArray())
                : kernelMajor is >= 5
                    ? MakeWithConfidence("StandardLinux", osId is null ? Confidence.Medium : Confidence.High, new ClassificationReason("Modern kernel and userspace do not show appliance mismatch signals", new[] { "kernel.release", "os.id", "os.version_id" }))
                    : MakeWithConfidence("Unknown", Confidence.Low, new ClassificationReason("Linux host signals are incomplete or not conclusive enough for StandardLinux/Appliance", new[] { "kernel.release", "os.version_id", "kernel.compiler" }));

        var environmentReasons = new List<ClassificationReason>();
        var metadataSuccess = e.Where(IsCloudMetadataSuccess).ToArray();
        var environmentType = metadataSuccess.Length > 0
            ? MakeWithConfidence("Cloud", Confidence.High, new ClassificationReason("Cloud metadata endpoint responded successfully", metadataSuccess.Select(item => item.Key).ToArray()))
            : BuildOnPrem();

        ClassificationResult BuildOnPrem()
        {
            var onPremScore = 0;
            if (probes.Any(probe => probe.ProbeId == "cloud-metadata") && metadataSuccess.Length == 0)
            {
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
                environmentReasons.Add(new("DNS search domain looks like a managed corporate network", new[] { "dns-search" }));
            }

            var dmiVendor = GetFirstMatchingValue(e, "dmi.sys_vendor");
            if (IsOnPremDmiVendor(dmiVendor))
            {
                onPremScore += 4;
                environmentReasons.Add(new("DMI vendor resembles non-cloud workstation/server hardware", new[] { "dmi.sys_vendor" }));
            }

            return onPremScore >= 4
                ? Make("OnPrem", onPremScore, environmentReasons.ToArray())
                : MakeWithConfidence("Unknown", onPremScore > 0 ? Confidence.Low : Confidence.Unknown, environmentReasons.Count == 0 ? [new ClassificationReason("No cloud metadata success and no strong on-prem corroboration", new[] { "aws.imds.identity.outcome", "azure.imds.outcome", "gcp.metadata.outcome", "oci.metadata.outcome", "cpu.model_name", "dns-search" })] : environmentReasons.ToArray());
        }

        // ── ContainerRuntime ─────────────────────────────────────────────────────
        var runtimeScore = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var runtimeReasons = new Dictionary<string, List<ClassificationReason>>(StringComparer.OrdinalIgnoreCase);
        void AddRuntime(string name, int points, string reason, params string[] refs)
        {
            runtimeScore[name] = runtimeScore.GetValueOrDefault(name) + points;
            if (!runtimeReasons.TryGetValue(name, out var list)) { list = new List<ClassificationReason>(); runtimeReasons[name] = list; }
            list.Add(new ClassificationReason(reason, refs));
        }

        // Podman: libpod endpoint key or body containing "Podman"
        if (e.Any(x => x.Key.Contains("/libpod/", StringComparison.OrdinalIgnoreCase))) AddRuntime("Podman", 6, "Libpod API endpoint present", "runtime-api");
        if (e.Any(x => x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime("Podman", 4, "Podman in API response body", "runtime-api");
        if (e.Any(x => x.Key == "socket.present" && x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("Podman", 2, "Podman socket path present", "runtime-api");

        // Docker: _ping on docker.sock or Docker in version body
        if (e.Any(x => x.Key.Contains("/_ping", StringComparison.OrdinalIgnoreCase) && x.Key.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) AddRuntime("Docker", 6, "Docker /_ping succeeded", "runtime-api");
        if (e.Any(x => x.Value?.Contains("\"docker\"", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime("Docker", 4, "Docker in API version body", "runtime-api");
        if (e.Any(x => x.Value?.Contains("containerd", StringComparison.OrdinalIgnoreCase) == true && x.Key.EndsWith(":body", StringComparison.OrdinalIgnoreCase))) AddRuntime("containerd", 4, "containerd signal in API body", "runtime-api");
        if (e.Any(x => (x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal")) && x.Value?.Contains("/docker/", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("Docker", 3, "Docker cgroup path", "proc-files");
        if (e.Any(x => (x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal")) && x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("Podman", 3, "Podman cgroup path", "proc-files");
        if (e.Any(x => x.Value?.Contains("containerd", StringComparison.OrdinalIgnoreCase) == true && x.Key.Contains("mountinfo", StringComparison.OrdinalIgnoreCase))) AddRuntime("containerd", 3, "containerd mount signal", "proc-files");

        var runtime = runtimeScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var runtimeClass = runtime.Key is null
            ? Make("Unknown", 0, new ClassificationReason("No runtime evidence", Array.Empty<string>()))
            : Make(runtime.Key, runtime.Value, (runtimeReasons.TryGetValue(runtime.Key, out var rtReasons) ? rtReasons : new List<ClassificationReason>()).ToArray());

        // ── RuntimeApi ───────────────────────────────────────────────────────────
        var runtimeApiScore = 0;
        var runtimeApiName = "Unknown";
        if (e.Any(x => x.Key.Contains("/libpod/_ping", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) { runtimeApiScore = 8; runtimeApiName = "PodmanLibpodApi"; }
        else if (e.Any(x => x.Key.Contains("/_ping", StringComparison.OrdinalIgnoreCase) && x.Key.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) && x.Value == "Success")) { runtimeApiScore = 7; runtimeApiName = "DockerEngineApi"; }
        else if (e.Any(x => x.Key.Contains("/libpod/", StringComparison.OrdinalIgnoreCase))) { runtimeApiScore = 5; runtimeApiName = "PodmanLibpodApi"; }
        else if (e.Any(x => x.Key == "api.version.outcome" && x.Value == "Success")) { runtimeApiScore = 5; runtimeApiName = "KubernetesApi"; }
        var runtimeApi = Make(runtimeApiName, runtimeApiScore, new ClassificationReason("Runtime API probe outcomes", new[] { "runtime-api" }));

        // ── Orchestrator ─────────────────────────────────────────────────────────
        var orchScore = new Dictionary<string, int>();
        void AddOrch(string n, int p) => orchScore[n] = orchScore.GetValueOrDefault(n) + p;
        if (e.Any(x => x.Key.StartsWith("env.KUBERNETES_") || x.Key.StartsWith("KUBERNETES_")) || e.Any(x => x.Key == "serviceaccount.token")) AddOrch("Kubernetes", 8);
        if (e.Any(x => x.Key.StartsWith("ecs.") && x.Value == "Success")) AddOrch("AWS ECS", 8);
        if (e.Any(x => x.Key is "env.K_SERVICE" or "K_SERVICE" or "env.K_REVISION" or "K_REVISION" or "env.K_CONFIGURATION" or "K_CONFIGURATION")) AddOrch("Cloud Run", 7);
        if (e.Any(x => x.Key is "env.CONTAINER_APP_NAME" or "CONTAINER_APP_NAME" or "env.CONTAINER_APP_REVISION" or "CONTAINER_APP_REVISION")) AddOrch("Azure Container Apps", 7);
        if (e.Any(x => x.Key is "env.NOMAD_JOB_NAME" or "NOMAD_JOB_NAME" or "env.NOMAD_ALLOC_ID" or "NOMAD_ALLOC_ID")) AddOrch("Nomad", 6);
        if (HasEnvKey(e, "OPENSHIFT_BUILD_NAME") || HasEnvKey(e, "OPENSHIFT_BUILD_NAMESPACE")) AddOrch("OpenShift", 6);
        if (e.Any(x => x.Key.Contains("compose", StringComparison.OrdinalIgnoreCase))) AddOrch("DockerCompose", 5);
        var orch = orchScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var orchestrator = orch.Key is null
            ? Make("Unknown", 0, new ClassificationReason("No orchestrator markers", Array.Empty<string>()))
            : Make(orch.Key, orch.Value, new ClassificationReason("Weighted orchestrator score", new[] { "environment", "kubernetes", "cloud-metadata" }));

        // ── CloudProvider ────────────────────────────────────────────────────────
        // Only attribute cloud when there is positive (Success) evidence, not just probe-ran evidence.
        var cloud = "Unknown";
        var cloudScore = 0;

        // AWS: IMDS token+identity succeeded, or ECS metadata succeeded, or explicit AWS env
        if (e.Any(x => x.Key == "aws.imds.identity.outcome" && x.Value == "Success")) { cloud = "AWS"; cloudScore = 8; }
        else if (e.Any(x => x.Key.StartsWith("ecs.") && x.Value == "Success")) { cloud = "AWS"; cloudScore = 6; }
        else if (e.Any(x => x.Key.StartsWith("env.AWS_") || x.Key.StartsWith("AWS_"))) { cloud = "AWS"; cloudScore = 4; }
        // Azure: IMDS succeeded or Azure-specific env vars
        else if (e.Any(x => x.Key == "azure.imds.outcome" && x.Value == "Success")) { cloud = "Azure"; cloudScore = 8; }
        else if (e.Any(x => x.Key is "env.WEBSITE_SITE_NAME" or "WEBSITE_SITE_NAME" or "env.WEBSITE_INSTANCE_ID" or "WEBSITE_INSTANCE_ID")) { cloud = "Azure"; cloudScore = 5; }
        // GCP: metadata server succeeded
        else if (e.Any(x => x.Key == "gcp.metadata.outcome" && x.Value == "Success")) { cloud = "GoogleCloud"; cloudScore = 8; }
        // OCI: metadata server succeeded
        else if (e.Any(x => x.Key == "oci.metadata.outcome" && x.Value == "Success")) { cloud = "OracleCloud"; cloudScore = 7; }
        var cloudProvider = Make(cloud, cloudScore, new ClassificationReason("Cloud metadata/env markers", new[] { "cloud-metadata" }));

        // ── PlatformVendor ───────────────────────────────────────────────────────
        // IoTEdge: any evidence key or value containing "iotedge" indicates Azure IoT Edge / Siemens IE hosting.
        // IoTEdge alone → classify as "IoTEdge" (conservative; could be any IoTEdge deployment).
        // IoTEdge + Siemens-specific signals → "Siemens Industrial Edge".
        var iotedgeScore = 0;
        var iotedgeReasons = new List<ClassificationReason>();
        if (e.Any(x => x.Key.Contains("iotedge", StringComparison.OrdinalIgnoreCase)))
        {
            iotedgeScore += 5;
            iotedgeReasons.Add(new("IoTEdge env marker detected", new[] { "environment" }));
        }

        // Siemens-specific: key or value references "siemens" or "industrial"
        var hasSiemensSpecific = e.Any(x =>
            x.Key.Contains("siemens", StringComparison.OrdinalIgnoreCase) ||
            x.Key.Contains("industrial", StringComparison.OrdinalIgnoreCase) ||
            x.Value?.Contains("siemens", StringComparison.OrdinalIgnoreCase) == true);

        var ieScore = 0;
        var ieReasons = new List<ClassificationReason>();
        if (iotedgeScore > 0 && hasSiemensSpecific)
        {
            ieScore = iotedgeScore + 4;
            ieReasons.AddRange(iotedgeReasons);
            ieReasons.Add(new("Siemens-specific signals corroborate IoTEdge", new[] { "environment", "runtime-api" }));
            // Compose further corroborates Siemens Industrial Edge context
            if (e.Any(x => x.Key.Contains("compose", StringComparison.OrdinalIgnoreCase)))
            {
                ieScore += 2;
                ieReasons.Add(new("Docker Compose corroboration", new[] { "runtime-api" }));
            }
        }

        var wsl2VendorDetected =
            e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "WSL2", StringComparison.OrdinalIgnoreCase))
            || e.Any(x => x.Key == "kernel.release" && HostParsing.ContainsWsl2Signal(x.Value))
            || e.Any(x => x.Key == "/proc/version" && HostParsing.ContainsWsl2Signal(x.Value));

        var dockerInfoOperatingSystem = GetFirstMatchingValue(e, "docker.info.operating_system");
        var dockerInfoKernelVersion = GetFirstMatchingValue(e, "docker.info.kernel_version");

        var appleScore = 0;
        var appleReasons = new List<ClassificationReason>();
        var dockerDesktopLinuxkitDetected =
            e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "DockerDesktop", StringComparison.OrdinalIgnoreCase))
            || e.Any(x => x.Key == "kernel.release" && x.Value?.Contains("linuxkit", StringComparison.OrdinalIgnoreCase) == true)
            || e.Any(x => x.Key == "/proc/version" && x.Value?.Contains("linuxkit", StringComparison.OrdinalIgnoreCase) == true)
            || ContainsAny(dockerInfoKernelVersion, "linuxkit");

        if (dockerDesktopLinuxkitDetected)
        {
            appleScore += 2;
            appleReasons.Add(new("LinuxKit kernel fingerprint suggests Docker Desktop VM", new[] { "kernel.flavor", "kernel.release", "/proc/version", "docker.info.kernel_version" }));
        }

        if (ContainsAny(dockerInfoOperatingSystem, "docker desktop"))
        {
            appleScore += 1;
            appleReasons.Add(new("Runtime API reports Docker Desktop operating system", new[] { "docker.info.operating_system" }));
        }

        var cpuModelForVendor = GetFirstMatchingValue(e, "cpu.model_name");
        if (ContainsAny(cpuModelForVendor, "apple", "intel(r) core"))
        {
            appleScore += 1;
            appleReasons.Add(new("CPU model is consistent with desktop/laptop developer hosts", new[] { "cpu.model_name" }));
        }

        var vendor = wsl2VendorDetected
            ? Make("Microsoft", 8, new ClassificationReason("WSL2 kernel fingerprint detected", new[] { "kernel.flavor", "kernel.release", "/proc/version" }))
            : appleScore >= 2
                ? Make("Apple", appleScore, appleReasons.ToArray())
            : ieScore >= 4
                ? Make("Siemens Industrial Edge", ieScore, ieReasons.ToArray())
                : iotedgeScore > 0
                    ? Make("IoTEdge", iotedgeScore, iotedgeReasons.ToArray())
                    : Make("Unknown", 0, new ClassificationReason("No vendor-specific proofs", Array.Empty<string>()));

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
