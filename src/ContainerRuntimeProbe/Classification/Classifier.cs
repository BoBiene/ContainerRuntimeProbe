using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

public static class Classifier
{
    public static (ClassificationResult Containerization, ClassificationResult Runtime, ClassificationResult Orchestrator, ClassificationResult Cloud) Classify(IReadOnlyList<ProbeResult> probes)
    {
        var evidence = probes.SelectMany(p => p.Evidence).ToList();

        var containerReasons = new List<string>();
        if (evidence.Any(e => e.Key == "/.dockerenv" && e.Value == bool.TrueString)) containerReasons.Add("/.dockerenv exists");
        if (evidence.Any(e => e.Key.Contains("KUBERNETES_SERVICE_HOST", StringComparison.OrdinalIgnoreCase))) containerReasons.Add("Kubernetes env markers found");
        if (evidence.Any(e => e.Value?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true)) containerReasons.Add("cgroup contains docker hint");

        var containerization = containerReasons.Count switch
        {
            >= 2 => new ClassificationResult("LikelyContainerized", Confidence.High, containerReasons),
            1 => new ClassificationResult("PossiblyContainerized", Confidence.Medium, containerReasons),
            _ => new ClassificationResult("Unknown", Confidence.Unknown, ["No strong container markers observed"])
        };

        var runtime = evidence.Any(e => e.Value?.Contains("podman", StringComparison.OrdinalIgnoreCase) == true)
            ? new ClassificationResult("Podman", Confidence.Medium, ["podman signal in cgroup or environment"])
            : evidence.Any(e => e.Value?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true)
                ? new ClassificationResult("Docker", Confidence.Medium, ["docker marker signal found"])
                : new ClassificationResult("Unknown", Confidence.Unknown, ["No runtime API evidence collected"]);

        var orchestrator = evidence.Any(e => e.Key.StartsWith("KUBERNETES_", StringComparison.OrdinalIgnoreCase))
            ? new ClassificationResult("Kubernetes", Confidence.Medium, ["Kubernetes service env vars detected"])
            : evidence.Any(e => e.Key.StartsWith("ECS_", StringComparison.OrdinalIgnoreCase))
                ? new ClassificationResult("AWS ECS", Confidence.Medium, ["ECS metadata env var detected"])
                : evidence.Any(e => e.Key is "K_SERVICE" or "K_REVISION" or "K_CONFIGURATION")
                    ? new ClassificationResult("Cloud Run/Knative", Confidence.Medium, ["Cloud Run env var set"])
                    : new ClassificationResult("Unknown", Confidence.Unknown, ["No orchestrator-specific evidence"]);

        var cloud = evidence.Any(e => e.Key.StartsWith("AWS_", StringComparison.OrdinalIgnoreCase) || e.Key.StartsWith("ECS_", StringComparison.OrdinalIgnoreCase))
            ? new ClassificationResult("AWS", Confidence.Low, ["AWS related env vars present"])
            : evidence.Any(e => e.Key.StartsWith("WEBSITE_", StringComparison.OrdinalIgnoreCase) || e.Key.StartsWith("CONTAINER_APP_", StringComparison.OrdinalIgnoreCase))
                ? new ClassificationResult("Azure", Confidence.Low, ["Azure-related env vars present"])
                : evidence.Any(e => e.Key is "K_SERVICE" or "K_REVISION" or "K_CONFIGURATION")
                    ? new ClassificationResult("GoogleCloud", Confidence.Low, ["Cloud Run markers observed"])
                    : new ClassificationResult("Unknown", Confidence.Unknown, ["No cloud metadata probes executed"]);

        return (containerization, runtime, orchestrator, cloud);
    }
}
