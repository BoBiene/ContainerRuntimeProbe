using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;
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
    [InlineData("Linux version 5.15.167.4-microsoft-standard-WSL2 (Microsoft@Microsoft.com) (gcc version 11.2.0) #1 SMP", "5.15.167.4-microsoft-standard-WSL2", KernelFlavor.WSL2)]
    public void ParseKernel_ExtractsReleaseAndFlavor(string procVersion, string osRelease, KernelFlavor expectedFlavor)
    {
        var parsed = HostParsing.ParseKernel(procVersion, osRelease, "Linux", "#1 SMP");

        Assert.Equal(osRelease, parsed.Release);
        Assert.Equal(expectedFlavor, parsed.Flavor);
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
        Assert.Equal(Confidence.Medium, report.Host.UnderlyingHostOs.Confidence);
    }

    [Fact]
    public void Renderer_OutputsHostSectionsAndJsonHostObject()
    {
        var report = TestReportFactory.CreateSampleReport();

        var markdown = ReportRenderer.ToMarkdown(report);
        var json = ReportRenderer.ToJson(report);
        var text = ReportRenderer.ToText(report);

        Assert.Contains("## Host OS / Node", markdown);
        Assert.Contains("### Virtualization", markdown);
        Assert.Contains("\"Host\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Virtualization\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Family\": \"Debian\"", json, StringComparison.Ordinal);
        Assert.Contains("HostFingerprint=sha256:", text, StringComparison.Ordinal);
    }

    private static ContainerRuntimeReport BuildHostReport(IReadOnlyList<EvidenceItem> evidence)
    {
        var report = new ContainerRuntimeReport(
            DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(1),
            [
                new ProbeResult("proc-files", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "proc-files").ToArray()),
                new ProbeResult("runtime-api", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "runtime-api").ToArray()),
                new ProbeResult("environment", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "environment").ToArray()),
                new ProbeResult("cloud-metadata", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "cloud-metadata").ToArray())
            ],
            [],
            new ReportClassification(
                new("True", Confidence.High, []),
                new("Docker", Confidence.High, []),
                new("DockerEngineApi", Confidence.High, []),
                new("Unknown", Confidence.Unknown, []),
                new("Azure", Confidence.Medium, []),
                new("Unknown", Confidence.Unknown, [])),
            TestReportFactory.CreateSampleReport().Host);

        var host = HostReportBuilder.Build(report.Probes, report.Classification, FingerprintMode.Safe);
        return report with { Host = host };
    }
}
