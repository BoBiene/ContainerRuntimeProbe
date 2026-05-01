using System.Runtime.InteropServices;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Probes;
using ContainerRuntimeProbe.Rendering;

namespace ContainerRuntimeProbe.Tests;

public sealed class HostParsingAndReportingTests
{
    [Theory]
    [InlineData("ID=debian\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", OperatingSystemFamily.Debian)]
    [InlineData("ID=ubuntu\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n", OperatingSystemFamily.Ubuntu)]
    [InlineData("ID=alpine\nNAME=\"Alpine Linux\"\nVERSION_ID=3.20.1\n", OperatingSystemFamily.Alpine)]
    [InlineData("ID=amzn\nNAME=\"Amazon Linux\"\nVERSION_ID=\"2023\"\n", OperatingSystemFamily.AmazonLinux)]
    [InlineData("ID=azurelinux\nNAME=\"Azure Linux\"\nVERSION_ID=\"3.0\"\n", OperatingSystemFamily.AzureLinux)]
    [InlineData("ID=mydistro\nNAME=\"MyDistro\"\nVERSION_ID=\"1\"\n", OperatingSystemFamily.Unknown)]
    public void ParseOsRelease_NormalizesKnownFamilies(string text, OperatingSystemFamily expectedFamily)
    {
        var parsed = HostParsing.ParseOsRelease(text);

        Assert.Equal(expectedFamily, parsed.Family);
    }

    [Theory]
    [InlineData("x86_64", ArchitectureKind.X64)]
    [InlineData("amd64", ArchitectureKind.X64)]
    [InlineData("aarch64", ArchitectureKind.Arm64)]
    [InlineData("arm64", ArchitectureKind.Arm64)]
    [InlineData("armv7l", ArchitectureKind.Arm)]
    [InlineData("s390x", ArchitectureKind.S390x)]
    [InlineData("ppc64le", ArchitectureKind.Ppc64le)]
    [InlineData("riscv64", ArchitectureKind.RiscV64)]
    public void NormalizeArchitecture_MapsCommonValues(string raw, ArchitectureKind expected)
    {
        Assert.Equal(expected, HostParsing.NormalizeArchitecture(raw));
    }

    [Theory]
    [InlineData("Linux version 6.17.0-1011-azure (buildd@lcy02-amd64) (gcc (Ubuntu 13.3.0) 13.3.0) #11~24.04.2-Ubuntu SMP", "6.17.0-1011-azure", KernelFlavor.Azure)]
    [InlineData("Linux version 6.1.79-99.167.amzn2023.x86_64 (mockbuild@buildhost) (gcc version 11.4.1) #1 SMP", "6.1.79-99.167.amzn2023.x86_64", KernelFlavor.Aws)]
    [InlineData("Linux version 6.6.10-generic (builder@host) (gcc version 13.2.0) #1 SMP", "6.6.10-generic", KernelFlavor.Generic)]
    [InlineData("Linux version 6.10.14-linuxkit (root@buildkitsandbox) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1 SMP PREEMPT_DYNAMIC", "6.10.14-linuxkit", KernelFlavor.DockerDesktop)]
    [InlineData("Linux version 5.15.167.4-microsoft-standard-WSL2 (Microsoft@Microsoft.com) (gcc version 11.2.0) #1 SMP", "5.15.167.4-microsoft-standard-WSL2", KernelFlavor.WSL2)]
    [InlineData("Linux version 5.10.55-synology (synology@synology) (gcc (Synology 7.3) 7.3) #1 SMP", "5.10.55+", KernelFlavor.Synology)]
    [InlineData("Linux version 5.4.0-216-generic (buildd@lcy02-amd64) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025", "5.4.0-216-generic", KernelFlavor.Ubuntu)]
    [InlineData("Linux version 4.19.0-27-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.316-1 (2024-06-25)", "4.19.0-27-amd64", KernelFlavor.Debian)]
    public void ParseKernel_ExtractsReleaseAndFlavor(string procVersion, string osRelease, KernelFlavor expectedFlavor)
    {
        var parsed = HostParsing.ParseKernel(procVersion, osRelease, "Linux", "#1 SMP");

        Assert.Equal(osRelease, parsed.Release);
        Assert.Equal(expectedFlavor, parsed.Flavor);
    }

    [Fact]
    public void ParseKernel_WithoutProcSignals_UsesRuntimeOsDescription()
    {
        var parsed = HostParsing.ParseKernel(null, null, null, null);

        Assert.Equal(RuntimeInformation.OSDescription, parsed.Name);
        Assert.Null(parsed.Release);
    }

    [Fact]
    public void ParseCpuInfo_X64_ExtractsVendorModelAndFlagsHash()
    {
        const string cpuInfo = """
            processor   : 0
            vendor_id   : GenuineIntel
            cpu family  : 6
            model       : 79
            model name  : Intel(R) Xeon(R) CPU
            flags       : sse sse2 avx avx2

            processor   : 1
            vendor_id   : GenuineIntel
            model name  : Intel(R) Xeon(R) CPU
            flags       : sse sse2 avx avx2
            """;

        var parsed = HostParsing.ParseCpuInfo(cpuInfo);

        Assert.Equal(2, parsed.LogicalProcessorCount);
        Assert.Equal("GenuineIntel", parsed.Vendor);
        Assert.Equal("Intel(R) Xeon(R) CPU", parsed.ModelName);
        Assert.Equal(4, parsed.FlagsCount);
        Assert.NotNull(parsed.FlagsHash);
    }

    [Fact]
    public void ParseCpuInfo_Arm_ExtractsHardwareRevisionAndSerial()
    {
        const string cpuInfo = """
            processor   : 0
            model name  : ARMv7 Processor rev 4 (v7l)
            Features    : fp asimd evtstrm aes pmull sha1 sha2 crc32
            CPU architecture: 8
            Hardware    : BCM2711
            Revision    : c03114
            Serial      : 00000000abcdef12
            """;

        var parsed = HostParsing.ParseCpuInfo(cpuInfo);

        Assert.Equal("BCM2711", parsed.Hardware);
        Assert.Equal("c03114", parsed.Revision);
        Assert.Equal("00000000abcdef12", parsed.Serial);
        Assert.Equal("redacted", HostParsing.SanitizeCpuSerial(parsed.Serial, includeSensitive: false));
    }

    [Fact]
    public void ParseCpuInfo_Arm_ExtractsBoardHintsOutsideFirstProcessorSection()
    {
        const string cpuInfo = """
            processor   : 0
            model name  : ARMv7 Processor rev 5 (v7l)
            Features    : half thumb fastmult vfp edsp neon vfpv3 tls vfpd32 

            processor   : 1
            model name  : ARMv7 Processor rev 5 (v7l)
            Features    : half thumb fastmult vfp edsp neon vfpv3 tls vfpd32 

            Hardware    : Generic DT based system
            Revision    : 0000
            Serial      : 0000000000000000
            """;

        var parsed = HostParsing.ParseCpuInfo(cpuInfo);

        Assert.Equal(2, parsed.LogicalProcessorCount);
        Assert.Equal("ARMv7 Processor rev 5 (v7l)", parsed.ModelName);
        Assert.Equal("Generic DT based system", parsed.Hardware);
        Assert.Equal("0000", parsed.Revision);
        Assert.Equal("0000000000000000", parsed.Serial);
    }

    [Fact]
    public void ParseMemInfo_ParsesBytes()
    {
        var parsed = HostParsing.ParseMemInfo("MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\n");

        Assert.Equal(16_777_216_000L, parsed.MemTotalBytes);
        Assert.Equal(12_288_000_000L, parsed.MemAvailableBytes);
    }

    [Theory]
    [InlineData("max", null)]
    [InlineData("17179869184", 17179869184L)]
    [InlineData("9223372036854771712", 9223372036854771712L)]
    public void ParseNullableLong_HandlesCgroupLimits(string raw, long? expected)
    {
        Assert.Equal(expected, HostParsing.ParseNullableLong(raw));
    }

    [Fact]
    public void Fingerprint_IsStableForSameSignalsRegardlessOfOrder()
    {
        var first = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.17.0-1011-azure"),
            new EvidenceItem("proc-files", "kernel.flavor", "Azure"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) CPU"),
            new EvidenceItem("proc-files", "cpu.flags.hash", "sha256:abc"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
            new EvidenceItem("runtime-api", "docker.info.kernel_version", "6.17.0-1011-azure"),
            new EvidenceItem("runtime-api", "docker.info.architecture", "x86_64"),
            new EvidenceItem("runtime-api", "runtime.engine.version", "28.1.1"),
            new EvidenceItem("runtime-api", "runtime.architecture", "x86_64"),
            new EvidenceItem("cloud-metadata", "cloud.machine_type", "Standard_D4s_v5"),
            new EvidenceItem("cloud-metadata", "cloud.region", "eastus")
        ]);

        var second = BuildHostReport([
            new EvidenceItem("cloud-metadata", "cloud.region", "eastus"),
            new EvidenceItem("cloud-metadata", "cloud.machine_type", "Standard_D4s_v5"),
            new EvidenceItem("runtime-api", "runtime.architecture", "x86_64"),
            new EvidenceItem("runtime-api", "runtime.engine.version", "28.1.1"),
            new EvidenceItem("runtime-api", "docker.info.architecture", "x86_64"),
            new EvidenceItem("runtime-api", "docker.info.kernel_version", "6.17.0-1011-azure"),
            new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("proc-files", "cpu.flags.hash", "sha256:abc"),
            new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) CPU"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "kernel.flavor", "Azure"),
            new EvidenceItem("proc-files", "kernel.release", "6.17.0-1011-azure")
        ]);

        Assert.Equal(first.Host.Fingerprint?.Value, second.Host.Fingerprint?.Value);
    }

    [Fact]
    public void Fingerprint_ChangesWhenRelevantSignalChanges_AndExcludesSensitiveIdentifiers()
    {
        var baseline = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.17.0-1011-azure"),
            new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("environment", "HOSTNAME", "sensitive-hostname")
        ]);

        var changed = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.17.0-1012-azure"),
            new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("environment", "HOSTNAME", "sensitive-hostname")
        ]);

        Assert.NotEqual(baseline.Host.Fingerprint?.Value, changed.Host.Fingerprint?.Value);
        Assert.Contains(baseline.Host.Fingerprint!.Components, component => component.Name == "hostname" && !component.Included);
        Assert.DoesNotContain("sensitive-hostname", string.Join('|', baseline.Host.Fingerprint.Components.Select(component => component.RawValueRedacted)));
    }

    [Fact]
    public void Fingerprint_ExcludesKernelHostname_WhenItIsTheOnlyHostnameSignal()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.17.0-1011-azure"),
            new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("proc-files", "kernel.hostname", "redacted", EvidenceSensitivity.Sensitive)
        ]);

        Assert.Equal(1, report.Host.Fingerprint!.ExcludedSensitiveSignalCount);
        Assert.Contains(report.Host.Fingerprint.Components, component => component.Name == "hostname" && !component.Included);
    }

    [Fact]
    public void HostReport_Wsl2Kernel_InfersVirtualizationAndUnderlyingWindowsHost()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.flavor", "WSL2"),
            new EvidenceItem("proc-files", "kernel.release", "5.15.167.4-microsoft-standard-WSL2"),
            new EvidenceItem("proc-files", "/proc/version", "Linux version 5.15.167.4-microsoft-standard-WSL2 (Microsoft@Microsoft.com)")
        ]);

        Assert.Equal(VirtualizationKind.WSL2, report.Host.Virtualization.Kind);
        Assert.Equal("Microsoft", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
        Assert.Equal(OperatingSystemFamily.Windows, report.Host.UnderlyingHostOs.Family);
        Assert.Null(report.Host.UnderlyingHostOs.Version);
        Assert.Equal(Confidence.High, report.Host.UnderlyingHostOs.Confidence);
    }

    [Fact]
    public void HostReport_DmiHyperVSignals_InfersHyperVVirtualization()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "dmi.sys_vendor", "Microsoft Corporation"),
            new EvidenceItem("proc-files", "dmi.product_name", "Virtual Machine"),
            new EvidenceItem("proc-files", "dmi.product_family", "Hyper-V")
        ]);

        Assert.Equal(VirtualizationKind.HyperV, report.Host.Virtualization.Kind);
        Assert.Equal("Microsoft Hyper-V", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
    }

    [Fact]
    public void HostReport_WindowsFriendlyVersion_PopulatesRuntimeHostOsAndTextOutput()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "windows.product_name", "Windows 11 Pro"),
            new EvidenceItem("proc-files", "windows.display_version", "24H2"),
            new EvidenceItem("proc-files", "kernel.release", "10.0.26200"),
            new EvidenceItem("proc-files", "kernel.architecture", "x86_64")
        ]);

        Assert.Equal(RuntimeReportedHostSource.LocalHost, report.Host.RuntimeReportedHostOs.Source);
        Assert.Equal(OperatingSystemFamily.Windows, report.Host.RuntimeReportedHostOs.Family);
        Assert.Equal("Windows 11 Pro", report.Host.RuntimeReportedHostOs.Name);
        Assert.Equal("24H2", report.Host.RuntimeReportedHostOs.Version);
        Assert.Equal(Confidence.High, report.Host.RuntimeReportedHostOs.Confidence);

        var text = ReportRenderer.ToText(report);
        Assert.Contains("Windows 11 Pro 24H2", text, StringComparison.Ordinal);
    }

    [Fact]
    public void HostReport_Windows11BuildWithLegacyProductName_UsesNormalizedProductName()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "windows.product_name", WindowsHostProbe.NormalizeWindowsProductName("Windows 10 Pro", "10.0.26200")),
            new EvidenceItem("proc-files", "windows.display_version", "24H2"),
            new EvidenceItem("proc-files", "kernel.release", "10.0.26200"),
            new EvidenceItem("proc-files", "kernel.architecture", "x86_64")
        ]);

        Assert.Equal("Windows 11 Pro", report.Host.RuntimeReportedHostOs.Name);

        var text = ReportRenderer.ToText(report);
        Assert.Contains("Windows 11 Pro 24H2", text, StringComparison.Ordinal);
    }

    [Fact]
    public void HostReport_VmwareDmiAndModuleSignals_InfersVmwareVirtualization()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.flag.hypervisor", bool.TrueString),
            new EvidenceItem("proc-files", "dmi.sys_vendor", "VMware, Inc."),
            new EvidenceItem("proc-files", "dmi.product_name", "VMware Virtual Platform"),
            new EvidenceItem("proc-files", "module.vmxnet3.loaded", bool.TrueString)
        ]);

        Assert.Equal(VirtualizationKind.VMware, report.Host.Virtualization.Kind);
        Assert.Equal("VMware", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
    }

    [Fact]
    public void HostReport_VirtualBoxDmiSignals_InfersVirtualBoxVirtualization()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.flag.hypervisor", bool.TrueString),
            new EvidenceItem("proc-files", "dmi.sys_vendor", "innotek GmbH"),
            new EvidenceItem("proc-files", "dmi.product_name", "VirtualBox")
        ]);

        Assert.Equal(VirtualizationKind.VirtualBox, report.Host.Virtualization.Kind);
        Assert.Equal("Oracle VirtualBox", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
    }

    [Fact]
    public void HostReport_XenHypervisorType_InfersXenVirtualization()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.flag.hypervisor", bool.TrueString),
            new EvidenceItem("proc-files", "sys.hypervisor.type", "xen"),
            new EvidenceItem("proc-files", "module.xen_evtchn.loaded", bool.TrueString)
        ]);

        Assert.Equal(VirtualizationKind.Xen, report.Host.Virtualization.Kind);
        Assert.Equal("Xen", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
    }

    [Fact]
    public void HostReport_QemuDmiSignals_InfersKvmVirtualization()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.flag.hypervisor", bool.TrueString),
            new EvidenceItem("proc-files", "dmi.sys_vendor", "QEMU"),
            new EvidenceItem("proc-files", "dmi.product_name", "Standard PC (Q35 + ICH9, 2009)")
        ]);

        Assert.Equal(VirtualizationKind.Kvm, report.Host.Virtualization.Kind);
        Assert.Equal("QEMU", report.Host.Virtualization.PlatformVendor);
        Assert.Equal(Confidence.High, report.Host.Virtualization.Confidence);
    }

    [Fact]
    public void Renderer_OutputsHostSectionsAndJsonHostObject()
    {
        var report = TestReportFactory.CreateSampleReport();

        var markdown = ReportRenderer.ToMarkdown(report);
        var json = ReportRenderer.ToJson(report);
        var text = ReportRenderer.ToText(report);

    Assert.Contains("## Key Findings", markdown);
    Assert.Contains("- Runtime-reported host OS: Ubuntu 24.04 (High).", markdown);
        Assert.Contains("## Host OS / Node", markdown);
        Assert.Contains("## Probe Tool Information", markdown);
        Assert.Contains("- Git Commit: abcdef1", markdown);
        Assert.Contains("### Virtualization", markdown);
        Assert.Contains("- Platform Vendor: Microsoft Hyper-V", markdown);
        Assert.Contains("### Platform / DMI", markdown);
        Assert.Contains("### Device Tree", markdown);
        Assert.Contains("- System Vendor: Microsoft Corporation", markdown);
        Assert.Contains("\"Host\":", json, StringComparison.Ordinal);
        Assert.Contains("\"ProbeToolInfo\":", json, StringComparison.Ordinal);
        Assert.Contains("\"GitCommit\": \"abcdef1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Virtualization\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Dmi\":", json, StringComparison.Ordinal);
        Assert.Contains("\"DeviceTree\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Family\": \"Debian\"", json, StringComparison.Ordinal);
        Assert.Contains("HardwareVendor", text);
        Assert.Contains("Architecture", text);
        Assert.Contains("DeviceTreeModel", text);
        Assert.Contains("abcdef1", text);
        Assert.Contains("Runtime-reported host OS: Ubuntu 24.04 (High).", text);
        Assert.Matches(@"HostFingerprint\s+:\s+sha256:", text);
    }

    private static ContainerRuntimeReport BuildHostReport(IReadOnlyList<EvidenceItem> evidence)
    {
        var report = new ContainerRuntimeReport(
            DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(1),
            null,
            [
                new ProbeResult("proc-files", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "proc-files").ToArray()),
                new ProbeResult("runtime-api", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "runtime-api").ToArray()),
                new ProbeResult("environment", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "environment").ToArray()),
                new ProbeResult("cloud-metadata", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "cloud-metadata").ToArray())
            ],
            [],
            new ReportClassification(
                new(ContainerizationKind.@True, Confidence.High, []),
                new(ContainerRuntimeKind.Docker, Confidence.High, []),
                new(VirtualizationClassificationKind.None, Confidence.Medium, []),
                new(new(OperatingSystemFamily.Linux, Confidence.High, []), new(HostTypeKind.StandardLinux, Confidence.High, [])),
                new(new(EnvironmentTypeKind.Cloud, Confidence.Medium, [])),
                new(RuntimeApiKind.DockerEngineApi, Confidence.High, []),
                new(OrchestratorKind.Unknown, Confidence.Unknown, []),
                new(CloudProviderKind.Azure, Confidence.Medium, []),
                new(PlatformVendorKind.Unknown, Confidence.Unknown, [])),
            TestReportFactory.CreateSampleReport().Host);

        var host = HostReportBuilder.Build(report.Probes, report.Classification, FingerprintMode.Safe);
        return report with { Host = host };
    }
}
