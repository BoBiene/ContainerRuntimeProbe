using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

internal static class TestReportFactory
{
    public static ContainerRuntimeReport CreateSampleReport()
        => new(
            DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(1),
            new ProbeToolMetadata("1.0.0-test"),
            [new ProbeResult("p", ProbeOutcome.Success, [new EvidenceItem("p", "k", "v")])],
            [],
            new ReportClassification(
                new(ContainerizationKind.@True, Confidence.High, []),
                new(ContainerRuntimeKind.Docker, Confidence.Medium, []),
                new(VirtualizationClassificationKind.None, Confidence.Medium, []),
                new(new(OperatingSystemFamily.Linux, Confidence.High, []), new(HostTypeKind.StandardLinux, Confidence.High, [])),
                new(new(EnvironmentTypeKind.Cloud, Confidence.Medium, [])),
                new(RuntimeApiKind.DockerEngineApi, Confidence.Medium, []),
                new(OrchestratorKind.Unknown, Confidence.Unknown, []),
                new(CloudProviderKind.Azure, Confidence.Medium, []),
                new(PlatformVendorKind.Unknown, Confidence.Unknown, [])),
            new HostReport(
                new ContainerImageOsInfo(
                    OperatingSystemFamily.Debian,
                    "debian",
                    [],
                    "Debian GNU/Linux",
                    "Debian GNU/Linux 12 (bookworm)",
                    "12",
                    "12",
                    "bookworm",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    ArchitectureKind.X64,
                    "x86_64",
                    Confidence.High,
                    ["proc-files:os.id"]),
                new VisibleKernelInfo(
                    "Linux",
                    "6.17.0-1011-azure",
                    "#11~24.04.2-Ubuntu SMP",
                    ArchitectureKind.X64,
                    "x86_64",
                    KernelFlavor.Azure,
                       new KernelCompilerInfo(
                           "gcc",
                           "13.3.0",
                           "gcc (Ubuntu 13.3.0) 13.3.0",
                           "Ubuntu",
                           null),
                    Confidence.Medium,
                    ["proc-files:kernel.release"]),
                new RuntimeReportedHostOsInfo(
                    OperatingSystemFamily.Ubuntu,
                    "Ubuntu",
                    "24.04",
                    "6.17.0-1011-azure",
                    ArchitectureKind.X64,
                    "x86_64",
                    RuntimeReportedHostSource.DockerInfo,
                    Confidence.High,
                    ["runtime-api:docker.info.operating_system"]),
                new VirtualizationInfo(
                    VirtualizationKind.Unknown,
                    null,
                    Confidence.Unknown,
                    []),
                new UnderlyingHostOsInfo(
                    OperatingSystemFamily.Unknown,
                    null,
                    null,
                    null,
                    UnderlyingHostOsSource.Unknown,
                    Confidence.Unknown,
                    []),
                new HostHardwareInfo(
                    ArchitectureKind.X64,
                    "x86_64",
                    new HostCpuInfo(4, 4, "GenuineIntel", "Intel(R) Xeon(R)", "IntelXeon", "sha256:flags", 32, null, "max"),
                    new HostMemoryInfo(16L * 1024 * 1024 * 1024, null, null, "max"),
                    "Standard_D4s_v5"),
                new HostFingerprint(
                    "CRP-HOST-FP-v1",
                    "sha256:0123456789abcdef",
                    FingerprintStability.RuntimeApiBacked,
                    10,
                    2,
                    [new HostFingerprintComponent("kernel.release", true, "6.17.0-1011-azure")],
                    ["Fingerprint is diagnostic only and not a security identity."])));
}
