using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal static class Classifier
{
    public static ReportClassification Classify(IReadOnlyList<ProbeResult> probes)
    {
        var e = probes.SelectMany(x => x.Evidence).ToList();

        static Confidence ScoreToConfidence(int score) => score switch { >= 8 => Confidence.High, >= 4 => Confidence.Medium, >= 1 => Confidence.Low, _ => Confidence.Unknown };
        ClassificationResult Make(string value, int score, params ClassificationReason[] reasons) => new(value, ScoreToConfidence(score), reasons);

        // Helper: match evidence key in both raw (VARNAME) and env-prefixed (env.VARNAME) forms
        static bool HasEnvKey(List<EvidenceItem> ev, string key) =>
            ev.Any(x => x.Key == key || x.Key == "env." + key);

        // ── IsContainerized ──────────────────────────────────────────────────────
        var containerScore = 0;
        var containerReasons = new List<ClassificationReason>();
        if (e.Any(x => x.Key == "/.dockerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/.dockerenv exists", new[] { "/.dockerenv" })); }
        if (e.Any(x => x.Key == "/run/.containerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/run/.containerenv exists", new[] { "/run/.containerenv" })); }
        if (e.Any(x => x.Key.StartsWith("ns.") && x.Value != "unavailable")) { containerScore += 1; containerReasons.Add(new("Namespace info visible", new[] { "ns.pid", "ns.mnt" })); }
        if (e.Any(x => x.Key.StartsWith("/proc/self/cgroup:signal") || x.Key.StartsWith("/proc/1/cgroup:signal"))) { containerScore += 3; containerReasons.Add(new("Cgroup container signals detected", new[] { "/proc/self/cgroup", "/proc/1/cgroup" })); }
        if (HasEnvKey(e, "KUBERNETES_SERVICE_HOST") || e.Any(x => x.Key == "env.KUBERNETES_SERVICE_HOST")) { containerScore += 3; containerReasons.Add(new("Kubernetes env marker", new[] { "env.KUBERNETES_SERVICE_HOST" })); }
        if (e.Any(x => x.Key == "socket.present")) { containerScore += 2; containerReasons.Add(new("Container runtime socket present", new[] { "runtime-api" })); }

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

        var vendor = ieScore >= 4
            ? Make("Siemens Industrial Edge", ieScore, ieReasons.ToArray())
            : iotedgeScore > 0
                ? Make("IoTEdge", iotedgeScore, iotedgeReasons.ToArray())
                : Make("Unknown", 0, new ClassificationReason("No vendor-specific proofs", Array.Empty<string>()));

        return new ReportClassification(
            Make(containerScore > 0 ? "True" : "Unknown", containerScore, containerReasons.ToArray()),
            runtimeClass,
            runtimeApi,
            orchestrator,
            cloudProvider,
            vendor);
    }
}
