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

        Assert.Equal(ContainerizationKind.@True, report.IsContainerized.Value);
        // /.dockerenv alone → Low or Medium confidence (score=4 = Medium; acceptable per spec)
        Assert.True(report.IsContainerized.Confidence is Confidence.Low or Confidence.Medium);
        Assert.Equal(ContainerRuntimeKind.Unknown, report.ContainerRuntime.Value);
        Assert.Equal(Confidence.Unknown, report.ContainerRuntime.Confidence);
    }

    [Fact]
    public void Classifier_NoContainerEvidence_ClassifiesAsHost()
    {
        var report = Classifier.Classify([
            new ProbeResult("marker-files", ProbeOutcome.Success, [
                new EvidenceItem("marker-files", "/.dockerenv", "False"),
                new EvidenceItem("marker-files", "/run/.containerenv", "False")
            ])
        ]);

        Assert.Equal(ContainerizationKind.@False, report.IsContainerized.Value);
        Assert.Equal(Confidence.High, report.IsContainerized.Confidence);
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

        Assert.Equal(ContainerRuntimeKind.Docker, report.ContainerRuntime.Value);
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

        Assert.Equal(ContainerizationKind.@True, report.IsContainerized.Value);
        Assert.True(report.IsContainerized.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_ClearKubernetesPodSignals_RaiseContainerizedConfidence()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "KUBERNETES_SERVICE_HOST", "10.96.0.1")
            ]),
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "/proc/self/mountinfo:signal", "overlay"),
                new EvidenceItem("proc-files", "/proc/self/mountinfo:signal", "kubelet"),
                new EvidenceItem("proc-files", "/proc/self/mountinfo:signal", "kubernetes-serviceaccount")
            ]),
            new ProbeResult("kubernetes", ProbeOutcome.Success, [
                new EvidenceItem("kubernetes", "serviceaccount.token", "present")
            ])
        ]);

        Assert.Equal(ContainerizationKind.@True, report.IsContainerized.Value);
        Assert.True(report.IsContainerized.Confidence >= Confidence.Medium);
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

        Assert.Equal(ContainerRuntimeKind.Docker, report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Medium);
        Assert.Equal(RuntimeApiKind.DockerEngineApi, report.RuntimeApi.Value);
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

        Assert.Equal(ContainerRuntimeKind.Podman, report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Medium);
        Assert.Equal(RuntimeApiKind.PodmanLibpodApi, report.RuntimeApi.Value);
        Assert.True(report.RuntimeApi.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_PodmanEnvironmentHintWithoutRuntimeApi_DetectsPodmanRuntime()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "container", "podman")
            ]),
            new ProbeResult("runtime-api", ProbeOutcome.Unavailable, [])
        ]);

        Assert.Equal(ContainerRuntimeKind.Podman, report.ContainerRuntime.Value);
        Assert.True(report.ContainerRuntime.Confidence >= Confidence.Low);
        Assert.Equal(RuntimeApiKind.Unknown, report.RuntimeApi.Value);
    }

    // ── Orchestrator scenarios ───────────────────────────────────────────────

    [Fact]
    public void Classifier_DetectsKubernetes()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [new EvidenceItem("environment", "env.KUBERNETES_SERVICE_HOST", "10.0.0.1")]),
            new ProbeResult("kubernetes", ProbeOutcome.Success, [new EvidenceItem("kubernetes", "serviceaccount.token", "present")])
        ]);

        Assert.Equal(OrchestratorKind.Kubernetes, report.Orchestrator.Value);
        Assert.True(report.Orchestrator.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_DetectsCloudRun()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [new EvidenceItem("cloud", "env.K_SERVICE", "svc")])
        ]);
        Assert.Equal(OrchestratorKind.CloudRun, report.Orchestrator.Value);
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

        Assert.Equal(OrchestratorKind.AzureContainerApps, report.Orchestrator.Value);
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

        Assert.Equal(OrchestratorKind.Nomad, report.Orchestrator.Value);
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

        Assert.Equal(CloudProviderKind.AWS, report.CloudProvider.Value);
        Assert.True(report.CloudProvider.Confidence >= Confidence.High);
    }

    [Fact]
    public void Classifier_EcsMetadataSuccess_DetectsAwsEcsOrchestrator()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "ecsx.task.outcome", "Success")
            ])
        ]);
        Assert.Equal(CloudProviderKind.Unknown, report.CloudProvider.Value);
        Assert.Equal(OrchestratorKind.Unknown, report.Orchestrator.Value);

        // Only exact "ecs." prefix keys contribute - verify AWS cloud from env
        var reportWithEnv = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "ecs.task.outcome", "Success")
            ])
        ]);

        Assert.Equal(CloudProviderKind.AWS, reportWithEnv.CloudProvider.Value);
        Assert.Equal(OrchestratorKind.AwsEcs, reportWithEnv.Orchestrator.Value);
    }

    [Fact]
    public void Classifier_AzureImdsSuccess_DetectsAzure()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Success")
            ])
        ]);

        Assert.Equal(CloudProviderKind.Azure, report.CloudProvider.Value);
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

        Assert.Equal(CloudProviderKind.Unknown, report.CloudProvider.Value);
    }

    [Fact]
    public void Classifier_GcpMetadataSuccess_DetectsGcp()
    {
        var report = Classifier.Classify([
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Success")
            ])
        ]);

        Assert.Equal(CloudProviderKind.GoogleCloud, report.CloudProvider.Value);
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

        Assert.Equal(OrchestratorKind.CloudRun, report.Orchestrator.Value);
        Assert.Equal(CloudProviderKind.Unknown, report.CloudProvider.Value);
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

        Assert.Equal(PlatformVendorKind.Unknown, report.PlatformVendor.Value);
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

        Assert.Equal(PlatformVendorKind.IoTEdge, report.PlatformVendor.Value);
        Assert.NotEqual(PlatformVendorKind.SiemensIndustrialEdge, report.PlatformVendor.Value);
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

        Assert.Equal(PlatformVendorKind.SiemensIndustrialEdge, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_SiemensDmiPlusIoTEdge_DetectsIndustrialEdge()
    {
        var report = Classifier.Classify([
            new ProbeResult("environment", ProbeOutcome.Success, [
                new EvidenceItem("environment", "IOTEDGE_MODULEID", "edge-agent")
            ]),
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "dmi.sys_vendor", "Siemens AG"),
                new EvidenceItem("proc-files", "device_tree.model", "SIMATIC IPC127E")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.SiemensIndustrialEdge, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
    }

    [Fact]
    public void Classifier_SiemensDmiWithoutIoTEdge_DetectsSiemensHardware()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "dmi.sys_vendor", "Siemens AG"),
                new EvidenceItem("proc-files", "device_tree.compatible", "siemens,simatic-ipc")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Siemens, report.PlatformVendor.Value);
        Assert.Equal(HostTypeKind.Appliance, report.Host.Type.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
    }

    [Theory]
    [InlineData("dmi.sys_vendor", "WAGO Kontakttechnik GmbH & Co. KG")]
    [InlineData("dmi.chassis_vendor", "Beckhoff Automation")]
    [InlineData("device_tree.model", "Phoenix Contact PLCnext AXC F 2152")]
    [InlineData("dmi.sys_vendor", "Advantech Co., Ltd.")]
    [InlineData("device_tree.compatible", "moxa,uc-8410a")]
    [InlineData("dmi.sys_vendor", "Bosch Rexroth AG")]
    [InlineData("dmi.sys_vendor", "Schneider Electric")]
    [InlineData("dmi.sys_vendor", "B&R Industrial Automation GmbH")]
    public void Classifier_CandidateOtVendorSignals_DoNotYetClassifyVendor(string key, string value)
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", key, value)
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Unknown, report.PlatformVendor.Value);
    }

    [Fact]
    public void Classifier_DockerInfoDockerDesktopLinuxkit_DetectsAppleVendor()
    {
        var report = Classifier.Classify([
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "docker.info.operating_system", "Docker Desktop"),
                new EvidenceItem("runtime-api", "docker.info.kernel_version", "6.10.14-linuxkit")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Apple, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_DesktopCpuOnly_DoesNotOverclassifyApple()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Core(TM) i7-10700")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Unknown, report.PlatformVendor.Value);
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

        Assert.Equal(PlatformVendorKind.IoTEdge, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
        Assert.NotEqual(PlatformVendorKind.SiemensIndustrialEdge, report.PlatformVendor.Value);
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

        Assert.Equal(OrchestratorKind.OpenShift, report.Orchestrator.Value);
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

        Assert.Equal(OrchestratorKind.OpenShift, report.Orchestrator.Value);
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

        Assert.Equal(PlatformVendorKind.IoTEdge, report.PlatformVendor.Value);
        Assert.NotEqual(PlatformVendorKind.SiemensIndustrialEdge, report.PlatformVendor.Value);
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

        Assert.Equal(PlatformVendorKind.Microsoft, report.PlatformVendor.Value);
        Assert.Equal(Confidence.High, report.PlatformVendor.Confidence);
        Assert.Equal(VirtualizationClassificationKind.WSL2, report.Virtualization.Value);
        Assert.Equal(OperatingSystemFamily.Windows, report.Host.Family.Value);
        Assert.Equal(HostTypeKind.WSL2, report.Host.Type.Value);
        Assert.Equal(EnvironmentTypeKind.Unknown, report.Environment.Type.Value);
    }

    [Fact]
    public void Classifier_OldKernelMismatchAndCustomCompiler_DetectsAppliance()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.release", "3.10.108"),
                new EvidenceItem("proc-files", "kernel.compiler", "gcc version 8.3.0 (crosstool-NG 1.24.0)"),
                new EvidenceItem("proc-files", "os.id", "debian"),
                new EvidenceItem("proc-files", "os.version_id", "12"),
                new EvidenceItem("proc-files", "cpu.model_name", "AMD Ryzen 7 5800U"),
                new EvidenceItem("proc-files", "dns-search", "fritz.box")
            ]),
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Unavailable")
            ])
        ]);

        Assert.Equal(OperatingSystemFamily.Linux, report.Host.Family.Value);
        Assert.Equal(HostTypeKind.Appliance, report.Host.Type.Value);
        Assert.Equal(Confidence.High, report.Host.Type.Confidence);
        Assert.Equal(EnvironmentTypeKind.OnPrem, report.Environment.Type.Value);
        Assert.Equal(Confidence.Medium, report.Environment.Type.Confidence);
    }

    [Fact]
    public void Classifier_KubernetesClusterDns_DoesNotCountAsHomeNetworkSignal()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "cpu.model_name", "Intel Xeon Platinum 8370C"),
                new EvidenceItem("proc-files", "dns-search", "default.svc.cluster.local"),
                new EvidenceItem("proc-files", "dns-search", "svc.cluster.local"),
                new EvidenceItem("proc-files", "dns-search", "cluster.local")
            ]),
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Unavailable")
            ])
        ]);

        Assert.Equal(EnvironmentTypeKind.Unknown, report.Environment.Type.Value);
        Assert.Equal(Confidence.Low, report.Environment.Type.Confidence);
    }

    [Fact]
    public void Classifier_ModernKernelAndMetadataSuccess_DetectsStandardLinuxInCloud()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.release", "6.6.10-generic"),
                new EvidenceItem("proc-files", "os.id", "ubuntu"),
                new EvidenceItem("proc-files", "os.version_id", "24.04")
            ]),
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Success")
            ])
        ]);

        Assert.Equal(OperatingSystemFamily.Linux, report.Host.Family.Value);
        Assert.Equal(HostTypeKind.StandardLinux, report.Host.Type.Value);
        Assert.Equal(EnvironmentTypeKind.Cloud, report.Environment.Type.Value);
        Assert.Equal(Confidence.High, report.Environment.Type.Confidence);
    }

    [Fact]
    public void Classifier_CorporateDnsAndDefaultRoute_DetectsOnPremWithoutConsumerCpuHints()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.release", "6.8.0-58-generic"),
                new EvidenceItem("proc-files", "os.id", "ubuntu"),
                new EvidenceItem("proc-files", "os.version_id", "24.04"),
                new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) Silver 4314 CPU"),
                new EvidenceItem("proc-files", "dns-search", "corp.example.com"),
                new EvidenceItem("proc-files", "default-route-device", "eno1")
            ]),
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "aws.imds.identity.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "oci.metadata.outcome", "Unavailable")
            ])
        ]);

        Assert.Equal(HostTypeKind.StandardLinux, report.Host.Type.Value);
        Assert.Equal(EnvironmentTypeKind.OnPrem, report.Environment.Type.Value);
        Assert.Equal(Confidence.Medium, report.Environment.Type.Confidence);
    }

    [Fact]
    public void Classifier_InternalDnsWithoutOtherSignals_RemainsUnknown()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.release", "6.8.0-58-generic"),
                new EvidenceItem("proc-files", "os.id", "ubuntu"),
                new EvidenceItem("proc-files", "os.version_id", "24.04"),
                new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) Silver 4314 CPU"),
                new EvidenceItem("proc-files", "dns-search", "compute.internal")
            ]),
            new ProbeResult("cloud-metadata", ProbeOutcome.Success, [
                new EvidenceItem("cloud-metadata", "aws.imds.identity.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "azure.imds.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "gcp.metadata.outcome", "Unavailable"),
                new EvidenceItem("cloud-metadata", "oci.metadata.outcome", "Unavailable")
            ])
        ]);

        Assert.Equal(EnvironmentTypeKind.Unknown, report.Environment.Type.Value);
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

        // Socket access alone is no longer enough to classify the current process as containerized.
        Assert.Equal(ContainerizationKind.Unknown, report.IsContainerized.Value);

        // IsContainerized reasons should only reflect container evidence, not runtime API body details
        var containerReasonsText = string.Join("|", report.IsContainerized.Reasons.Select(r => r.Message));
        Assert.DoesNotContain("Weighted score", containerReasonsText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("API response body", containerReasonsText, StringComparison.OrdinalIgnoreCase);

        // Runtime reasons should be in ContainerRuntime.Reasons, not IsContainerized.Reasons
        var runtimeReasonsText = string.Join("|", report.ContainerRuntime.Reasons.Select(r => r.Message));
        Assert.Contains("Docker /_ping", runtimeReasonsText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Classifier_SynologyKernelFlavor_DetectsSynologyVendor()
    {
        var report = Classifier.Classify([
            new ProbeResult("marker-files", ProbeOutcome.Success, [
                new EvidenceItem("marker-files", "/.dockerenv", "True")
            ]),
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.flavor", "Synology"),
                new EvidenceItem("proc-files", "kernel.release", "5.10.55+"),
                new EvidenceItem("proc-files", "os.id", "debian")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Synology, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_SynologyOsSignals_DetectsSynologyVendor()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "os.id", "synology"),
                new EvidenceItem("proc-files", "os.name", "Synology"),
                new EvidenceItem("proc-files", "kernel.release", "5.10.55+"),
                new EvidenceItem("proc-files", "kernel.flavor", "Generic")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Synology, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Low);
    }

    [Fact]
    public void Classifier_SynologyProcAndDmiSignals_DetectsVendorAndApplianceHost()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.syno_hw_version", "DS925+"),
                new EvidenceItem("proc-files", "dmi.sys_vendor", "Synology Inc."),
                new EvidenceItem("proc-files", "dmi.product_name", "DS925+"),
                new EvidenceItem("proc-files", "dmi.modalias", "dmi:bvnInsydeCorp.:svnSynologyInc.:pnDS925+:pvr1:"),
                new EvidenceItem("proc-files", "kernel.release", "5.10.55+")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Synology, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
        Assert.Equal(HostTypeKind.Appliance, report.Host.Type.Value);
    }

    [Fact]
    public void Classifier_GenericHwVersionAndBoardDmiSignals_DetectsSynologyVendor()
    {
        var report = Classifier.Classify([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "kernel.vendor_hw_version", "DS925+"),
                new EvidenceItem("proc-files", "dmi.board_vendor", "Synology Inc."),
                new EvidenceItem("proc-files", "dmi.board_name", "DiskStation"),
                new EvidenceItem("proc-files", "kernel.release", "5.10.55+")
            ])
        ]);

        Assert.Equal(PlatformVendorKind.Synology, report.PlatformVendor.Value);
        Assert.True(report.PlatformVendor.Confidence >= Confidence.Medium);
    }
}
