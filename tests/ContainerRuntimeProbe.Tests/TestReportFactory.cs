using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

internal static class TestReportFactory
{
    public static ContainerRuntimeReport CreateSampleReport()
        => new(
            DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(1),
            new ProbeToolMetadata("1.0.0-test", "abcdef1"),
            [new ProbeResult("p", ProbeOutcome.Success, [new EvidenceItem("p", "k", "v")])],
            [],
            new ReportClassification(
                new(ContainerizationKind.@True, Confidence.High, []),
                new(ContainerRuntimeKind.Docker, Confidence.Medium, []),
                new(VirtualizationClassificationKind.HyperV, Confidence.High, [new ClassificationReason("Hyper-V DMI and guest integration signals detected", ["proc-files:dmi.sys_vendor", "proc-files:dmi.product_family"])]),
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
                    VirtualizationKind.HyperV,
                    "Microsoft Hyper-V",
                    Confidence.High,
                    ["proc-files:dmi.sys_vendor", "proc-files:dmi.product_family"]),
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
                    new HostDmiInfo(
                        "Microsoft Corporation",
                        "Virtual Machine",
                        "Hyper-V",
                        "7.0",
                        "Microsoft Corporation",
                        "Virtual Machine",
                        "Microsoft Corporation",
                        "American Megatrends Inc.",
                        "dmi:bvnAmericanMegatrendsInc.:svnMicrosoftCorporation:pnVirtualMachine:",
                        Confidence.High,
                        ["proc-files:dmi.sys_vendor", "proc-files:dmi.product_name"]),
                    new HostDeviceTreeInfo(
                        "Unknown",
                        "Unknown",
                        Confidence.Unknown,
                        []),
                    "Standard_D4s_v5"),
                [
                    new DiagnosticFingerprint(
                        DiagnosticFingerprintPurpose.EnvironmentCorrelation,
                        "CRP-HOST-FP-v1",
                        "sha256:0123456789abcdef",
                        FingerprintStability.RuntimeApiBacked,
                        DiagnosticFingerprintStabilityLevel.UpdateSensitive,
                        DiagnosticFingerprintUniquenessLevel.Medium,
                        DiagnosticFingerprintCorroborationLevel.CrossSource,
                        10,
                        2,
                        [DiagnosticFingerprintSourceClass.KernelSignal, DiagnosticFingerprintSourceClass.RuntimeApi],
                        [new DiagnosticFingerprintComponent("kernel.release", true, "6.17.0-1011-azure")],
                        ["Fingerprint is diagnostic only and not a security identity."],
                        ["Includes kernel and runtime signals for environment correlation."])
                ],
                    [
                        new IdentityAnchor(
                        IdentityAnchorKind.CloudInstanceIdentity,
                        "CRP-CLOUD-INSTANCE-v1",
                        "<redacted>",
                        IdentityAnchorScope.Host,
                        BindingSuitability.LicenseBinding,
                        IdentityAnchorStrength.Strong,
                        IdentityAnchorSensitivity.Sensitive,
                        ["cloud-metadata:aws.instance_id"],
                        [],
                        ["Digest derived from observed aws instance identity metadata."])
                    ]));
}
