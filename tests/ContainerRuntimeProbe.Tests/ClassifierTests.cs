using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class ClassifierTests
{
    [Fact]
    public void Classifier_DetectsKubernetes()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [new EvidenceItem("environment", "env.KUBERNETES_SERVICE_HOST", "10.0.0.1")]),
            new ProbeResult("kubernetes", ProbeOutcome.Success, [new EvidenceItem("kubernetes", "serviceaccount.token", "present")])
        ]);

        Assert.Equal("Kubernetes", report.Orchestrator.Value);
        Assert.True(report.Orchestrator.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_DetectsCloudRun()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [new EvidenceItem("cloud", "env.K_SERVICE", "svc")])
        ]);
        Assert.Equal("Cloud Run", report.Orchestrator.Value);
    }
}
