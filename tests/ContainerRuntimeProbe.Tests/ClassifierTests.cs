using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class ClassifierTests
{
    // ── IsContainerized scenarios ────────────────────────────────────────────

    [Fact]
    public void Classifier_MarkerFileOnly_LowOrMediumContainerizedConfidence()
    {
        var report = Classifier.Classify([
            new ProbeResult("marker-files", ProbeOutcome.Success, [
                new EvidenceItem("marker-files", "/.dockerenv", "True")
            ])
        ]);

        Assert.Equal("True", report.IsContainerized.Value);
        // /.dockerenv alone → Low or Medium confidence (score=4 = Medium; acceptable per spec)
        Assert.True(report.IsContainerized.Confidence is Confidence.Low or Confidence.Medium);
        Assert.Equal("Unknown", report.ContainerRuntime.Value);
        Assert.Equal(Confidence.Unknown, report.ContainerRuntime.Confidence);
    }

    [Fact]
    public void Classifier_NoContainerEvidence_UnknownContainerized()
    {
        var report = Classifier.Classify([
            new ProbeResult("marker-files", ProbeOutcome.Success, [
                new EvidenceItem("marker-files", "/.dockerenv", "False"),
                new EvidenceItem("marker-files", "/run/.containerenv", "False")
            ])
        ]);

        Assert.Equal("Unknown", report.IsContainerized.Value);
        Assert.Equal(Confidence.Unknown, report.IsContainerized.Confidence);
    }

    // ── ContainerRuntime scenarios ───────────────────────────────────────────

    [Fact]
    public void Classifier_DockerCgroup_DetectsDockerRuntime()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "/proc/self/cgroup:signal", "12:memory:/docker/abc1234567890abc")
            ])
        ]);

        Assert.Equal("Docker", report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_OverlayMount_DetectsContainerized()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "/proc/self/mountinfo:signal", "overlay")
            ])
        ]);

        Assert.Equal("True", report.IsContainerized.Value);
        Assert.True(report.IsContainerized.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_DockerSocketPingSuccess_DockerHighConfidence()
    {
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "socket.present", "/var/run/docker.sock"),
                new EvidenceItem("runtime-api", "/var/run/docker.sock:/_ping:outcome", "Success"),
                new EvidenceItem("runtime-api", "/var/run/docker.sock:/_ping:body", "OK")
            ])
        ]);

        Assert.Equal("Docker", report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Medium);
        Assert.Equal("DockerEngineApi", report.RuntimeApi.Value);
        Assert.True(report.RuntimeApi.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_PodmanLibpodResponse_DetectsPodman()
    {
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "socket.present", "/run/podman/podman.sock"),
                new EvidenceItem("runtime-api", "/run/podman/podman.sock:/libpod/_ping:outcome", "Success"),
                new EvidenceItem("runtime-api", "/run/podman/podman.sock:/libpod/version:body", "{\"Version\":\"4.0\",\"Os\":\"linux\"}")
            ])
        ]);

        Assert.Equal("Podman", report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Medium);
        Assert.Equal("PodmanLibpodApi", report.RuntimeApi.Value);
        Assert.True(report.RuntimeApi.Confidence >= Confidence.High);
    }

    // ── Orchestrator scenarios ───────────────────────────────────────────────

    [Fact]
    public void Classifier_DetectsKubernetes()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [new EvidenceItem("environment", "env.KUBERNETES_SERVICE_HOST", "10.0.0.1")]),
            new ProbeResult("kubernetes", ProbeOutcome.Success, [new EvidenceItem("kubernetes", "serviceaccount.token", "present")])
        ]);

        Assert.Equal("Kubernetes", report.Orchestrator.Value);
        Assert.True(report.Orchestrator.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_DetectsCloudRun()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [new EvidenceItem("cloud", "env.K_SERVICE", "svc")])
        ]);
        Assert.Equal("Cloud Run", report.Orchestrator.Value);
    }

    [Fact]
    public void Classifier_AzureContainerApps_DetectsACA()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "env.CONTAINER_APP_NAME", "my-app"),
                new EvidenceItem("environment", "env.CONTAINER_APP_REVISION", "my-app--rev1")
            ])
        ]);

        Assert.Equal("Azure Container Apps", report.Orchestrator.Value);
        Assert.True(report.Orchestrator.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_NomadEnv_DetectsNomad()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "env.NOMAD_JOB_NAME", "web"),
                new EvidenceItem("environment", "env.NOMAD_ALLOC_ID", "abc-123")
            ])
        ]);

        Assert.Equal("Nomad", report.Orchestrator.Value);
    }

    // ── CloudProvider scenarios ──────────────────────────────────────────────

    [Fact]
    public void Classifier_AwsImdsSuccess_DetectsAws()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "aws.imds.identity.outcome", "Success")
            ])
        ]);

        Assert.Equal("AWS", report.CloudProvider.Value);
        Assert.True(report.CloudProvider.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_EcsMetadataSuccess_DetectsAwsEcsOrchestrator()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "ecs..outcome", "Success")
            ])
        ]);

        // Only exact "ecs." prefix keys contribute - verify AWS cloud from env
        var reportWithEnv = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "ecs.task.outcome", "Success")
            ])
        ]);

        Assert.Equal("AWS", reportWithEnv.CloudProvider.Value);
        Assert.Equal("AWS ECS", reportWithEnv.Orchestrator.Value);
    }

    [Fact]
    public void Classifier_AzureImdsSuccess_DetectsAzure()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Success")
            ])
        ]);

        Assert.Equal("Azure", report.CloudProvider.Value);
        Assert.True(report.CloudProvider.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_AzureImdsUnavailable_CloudUnknown()
    {
        // Key presence with non-Success value must NOT classify as Azure
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Timeout"),
                new EvidenceItem("cloud-metadata", "oci.metadata.outcome", "Unavailable")
            ])
        ]);

        Assert.Equal("Unknown", report.CloudProvider.Value);
    }

    [Fact]
    public void Classifier_GcpMetadataSuccess_DetectsGcp()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Success")
            ])
        ]);

        Assert.Equal("GoogleCloud", report.CloudProvider.Value);
        Assert.True(report.CloudProvider.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_CloudRunEnv_GcpCloudUnknownWithoutImds()
    {
        // K_SERVICE sets Orchestrator=Cloud Run but NOT CloudProvider=GoogleCloud without IMDS success
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "env.K_SERVICE", "my-service")
            ])
        ]);

        Assert.Equal("Cloud Run", report.Orchestrator.Value);
        Assert.Equal("Unknown", report.CloudProvider.Value);
    }

    // ── PlatformVendor / Siemens IE scenarios ────────────────────────────────

    [Fact]
    public void Classifier_ComposeOnlyEvidence_NotSiemens()
    {
        // Docker Compose evidence alone must NOT classify as Siemens Industrial Edge
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "compose.service", "web")
            ])
        ]);

        Assert.Equal("Unknown", report.PlatformVendor.Value);
    }

    [Fact]
    public void Classifier_SiemensSignalWithCompose_IoTEdgeOnly_NoSiemensSpecific()
    {
        // iotedge.module key + compose.service but no Siemens-specific indicator
        // → should classify as "IoTEdge", not "Siemens Industrial Edge"
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "iotedge.module", "my-module"),
                new EvidenceItem("runtime-api", "compose.service", "web")
            ])
        ]);

        Assert.Equal("IoTEdge", report.PlatformVendor.Value);
        Assert.NotEqual("Siemens Industrial Edge", report.PlatformVendor.Value);
    }

    [Fact]
    public void Classifier_SiemensSignalPlusSiemensIndicator_DetectsIE()
    {
        // IoTEdge signal + Siemens-specific label → Industrial Edge
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "iotedge.module", "my-module"),
                new EvidenceItem("runtime-api", "compose.label.com.siemens.ie.version", "1.5.0")
            ])
        ]);

        Assert.Equal("Siemens Industrial Edge", report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_IoTEdgeAlone_DetectsIoTEdge()
    {
        // IOTEDGE_MODULEID without any Siemens-specific evidence → "IoTEdge", not "Siemens Industrial Edge"
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "IOTEDGE_MODULEID", "my-module"),
                new EvidenceItem("environment", "IOTEDGE_DEVICEID", "my-device")
            ])
        ]);

        Assert.Equal("IoTEdge", report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
        Assert.NotEqual("Siemens Industrial Edge", report.PlatformVendor.Value);
    }

    [Fact]
    public void Classifier_OpenShift_DetectsOpenShift()
    {
        // OPENSHIFT_BUILD_NAME from EnvironmentProbe (bare key, no env. prefix)
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "OPENSHIFT_BUILD_NAME", "my-build"),
                new EvidenceItem("environment", "OPENSHIFT_BUILD_NAMESPACE", "dev")
            ])
        ]);

        Assert.Equal("OpenShift", report.Orchestrator.Value);
        Assert.True(report.Orchestrator.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_OpenShiftEnvPrefixed_DetectsOpenShift()
    {
        // env.OPENSHIFT_BUILD_NAME (prefixed, as might come from cloud-metadata style emission)
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "env.OPENSHIFT_BUILD_NAME", "my-build")
            ])
        ]);

        Assert.Equal("OpenShift", report.Orchestrator.Value);
    }

    [Fact]
    public void Classifier_IoTEdgeEnvKeys_AppearInEvidence_DoNotOverclaimSiemens()
    {
        // IOTEDGE_WORKLOADURI and IOTEDGE_GATEWAYHOSTNAME without any Siemens label → "IoTEdge"
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "IOTEDGE_WORKLOADURI", "http://iotedged:15082/"),
                new EvidenceItem("environment", "IOTEDGE_GATEWAYHOSTNAME", "gateway.local")
            ])
        ]);

        Assert.Equal("IoTEdge", report.PlatformVendor.Value);
        Assert.NotEqual("Siemens Industrial Edge", report.PlatformVendor.Value);
    }

    [Fact]
    public void Classifier_Wsl2Kernel_DetectsMicrosoftPlatformVendor()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.flavor", "WSL2"),
                new EvidenceItem("proc-files", "kernel.release", "5.15.167.4-microsoft-standard-WSL2"),
                new EvidenceItem("proc-files", "/proc/version", "Linux version 5.15.167.4-microsoft-standard-WSL2")
            ])
        ]);

        Assert.Equal("Microsoft", report.PlatformVendor.Value);
        Assert.Equal(Confidence.High, report.PlatformVendor.Confidence);
    }

    // ── Reasons separation ───────────────────────────────────────────────────

    [Fact]
    public void Classifier_ContainerReasons_DoNotContainRuntimeApiReasons()
    {
        // ContainerRuntime reasons must not bleed into IsContainerized reasons
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "socket.present", "/var/run/docker.sock"),
                new EvidenceItem("runtime-api", "/var/run/docker.sock:/_ping:outcome", "Success")
            ])
        ]);

        // IsContainerized reasons should only reflect container evidence (socket presence), not runtime API body details
        var containerReasonsText = string.Join("|", report.IsContainerized.Reasons.Select(r => r.Message));
        Assert.DoesNotContain("Weighted score", containerReasonsText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("API response body", containerReasonsText, StringComparison.OrdinalIgnoreCase);

        // Runtime reasons should be in ContainerRuntime.Reasons, not IsContainerized.Reasons
        var runtimeReasonsText = string.Join("|", report.ContainerRuntime.Reasons.Select(r => r.Message));
        Assert.Contains("Docker /_ping", runtimeReasonsText, StringComparison.OrdinalIgnoreCase);
    }
}
