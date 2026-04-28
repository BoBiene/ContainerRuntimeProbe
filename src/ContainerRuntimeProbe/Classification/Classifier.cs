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

        var containerScore = 0;
        var containerReasons = new List<ClassificationReason>();
        if (e.Any(x => x.Key == "/.dockerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/.dockerenv exists", new[]{"/.dockerenv"})); }
        if (e.Any(x => x.Key == "/run/.containerenv" && x.Value == bool.TrueString)) { containerScore += 4; containerReasons.Add(new("/run/.containerenv exists", new[]{"/run/.containerenv"})); }
        if (e.Any(x => x.Key.StartsWith("ns.") && x.Value != "unavailable")) { containerScore += 1; containerReasons.Add(new("Namespace info visible", new[]{"ns.pid", "ns.mnt"})); }
        if (e.Any(x => x.Key == "env.KUBERNETES_SERVICE_HOST")) { containerScore += 3; containerReasons.Add(new("Kubernetes env marker", new[]{"env.KUBERNETES_SERVICE_HOST"})); }

        var runtimeScore = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        void AddRuntime(string name, int points, string reason, params string[] refs)
        {
            runtimeScore[name] = runtimeScore.GetValueOrDefault(name) + points;
            containerReasons.Add(new ClassificationReason(reason, refs));
        }
        if (e.Any(x => x.Key.Contains("libpod", StringComparison.OrdinalIgnoreCase) || x.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("Podman", 6, "Podman/libpod signals", "runtime-api");
        if (e.Any(x => x.Key.Contains("docker.sock", StringComparison.OrdinalIgnoreCase) || x.Value?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("Docker", 5, "Docker signals", "runtime-api");
        if (e.Any(x => x.Value?.Contains("containerd", StringComparison.OrdinalIgnoreCase) == true)) AddRuntime("containerd", 4, "containerd signal", "mountinfo");

        var runtime = runtimeScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var runtimeClass = runtime.Key is null ? Make("Unknown", 0, new ClassificationReason("No runtime evidence", Array.Empty<string>())) : Make(runtime.Key, runtime.Value, new ClassificationReason($"Weighted score {runtime.Value}", new[]{"runtime-api"}));

        var runtimeApiScore = 0;
        var runtimeApiName = "Unknown";
        if (e.Any(x => x.Key.Contains("/_ping") && x.Key.Contains("docker.sock"))) { runtimeApiScore = 7; runtimeApiName = "DockerEngineApi"; }
        if (e.Any(x => x.Key.Contains("/libpod/_ping"))) { runtimeApiScore = Math.Max(runtimeApiScore, 7); runtimeApiName = "PodmanLibpodApi"; }
        if (e.Any(x => x.Key == "api.version.outcome")) { runtimeApiScore = Math.Max(runtimeApiScore, 5); runtimeApiName = "KubernetesApi"; }
        var runtimeApi = Make(runtimeApiName, runtimeApiScore, new ClassificationReason("Runtime API probe outcomes", new[]{"runtime-api"}));

        var orchScore = new Dictionary<string, int>();
        void AddOrch(string n, int p) => orchScore[n] = orchScore.GetValueOrDefault(n) + p;
        if (e.Any(x => x.Key.StartsWith("env.KUBERNETES_")) || e.Any(x => x.Key == "serviceaccount.token")) AddOrch("Kubernetes", 8);
        if (e.Any(x => x.Key.StartsWith("ecs."))) AddOrch("AWS ECS", 8);
        if (e.Any(x => x.Key == "env.K_SERVICE" || x.Key == "env.K_REVISION" || x.Key == "env.K_CONFIGURATION")) AddOrch("Cloud Run", 7);
        if (e.Any(x => x.Key.Contains("compose", StringComparison.OrdinalIgnoreCase))) AddOrch("DockerCompose", 5);
        var orch = orchScore.OrderByDescending(x => x.Value).FirstOrDefault();
        var orchestrator = orch.Key is null ? Make("Unknown", 0, new ClassificationReason("No orchestrator markers", Array.Empty<string>())) : Make(orch.Key, orch.Value, new ClassificationReason("Weighted orchestrator score", new[]{"environment", "kubernetes", "cloud-metadata"}));

        var cloud = "Unknown"; var cloudScore = 0;
        if (e.Any(x => x.Key.StartsWith("aws.")) || e.Any(x => x.Key.StartsWith("env.AWS") || x.Key.StartsWith("ecs."))) { cloud = "AWS"; cloudScore = 6; }
        else if (e.Any(x => x.Key.StartsWith("azure.")) || e.Any(x => x.Key == "env.WEBSITE_SITE_NAME" || x.Key == "env.CONTAINER_APP_NAME")) { cloud = "Azure"; cloudScore = 6; }
        else if (e.Any(x => x.Key.StartsWith("gcp.")) || e.Any(x => x.Key == "env.K_SERVICE")) { cloud = "GoogleCloud"; cloudScore = 6; }
        else if (e.Any(x => x.Key.StartsWith("oci."))) { cloud = "OracleCloud"; cloudScore = 5; }
        var cloudProvider = Make(cloud, cloudScore, new ClassificationReason("Cloud metadata/env markers", new[]{"cloud-metadata"}));

        var vendor = e.Any(x => x.Key.Contains("industrial", StringComparison.OrdinalIgnoreCase) || x.Value?.Contains("siemens", StringComparison.OrdinalIgnoreCase) == true)
            ? Make("Siemens Industrial Edge", 5, new ClassificationReason("Siemens-specific hints observed", new[]{"environment", "runtime-api"}))
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
