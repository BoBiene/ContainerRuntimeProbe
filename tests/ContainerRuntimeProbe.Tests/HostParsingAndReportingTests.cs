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

        Assert.Equal(first.Host.DiagnosticFingerprints.FirstOrDefault()?.Value, second.Host.DiagnosticFingerprints.FirstOrDefault()?.Value);
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

        var baselineFingerprint = Assert.Single(baseline.Host.DiagnosticFingerprints);
        var changedFingerprint = Assert.Single(changed.Host.DiagnosticFingerprints);

        Assert.NotEqual(baselineFingerprint.Value, changedFingerprint.Value);
        Assert.Contains(baselineFingerprint.Components, component => component.Name == "hostname" && !component.Included);
        Assert.DoesNotContain("sensitive-hostname", string.Join('|', baselineFingerprint.Components.Select(component => component.RawValueRedacted)));
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

        var fingerprint = Assert.Single(report.Host.DiagnosticFingerprints);

        Assert.Equal(1, fingerprint.ExcludedSensitiveSignalCount);
        Assert.Contains(fingerprint.Components, component => component.Name == "hostname" && !component.Included);
    }

    [Fact]
    public void IdentityAnchors_BuildsWorkloadProfileIdentity_FromHostnameAndNamespaceSignals()
    {
        var report = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "Web-01", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));

        Assert.Equal("CRP-WORKLOAD-PROFILE-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Workload, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Weak, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("Web-01", anchor.Value, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "environment:HOSTNAME");
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:ns.pid");
    }

    [Fact]
    public void IdentityAnchors_WorkloadProfileIdentity_ChangesWhenHostnameChanges()
    {
        var baseline = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "web-01", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        var changed = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "web-02", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        var baselineAnchor = Assert.Single(baseline.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));
        var changedAnchor = Assert.Single(changed.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));

        Assert.NotEqual(baselineAnchor.Value, changedAnchor.Value);
    }

    [Fact]
    public void IdentityAnchors_WorkloadProfileIdentity_IsStableForSameSignalsRegardlessOfOrder()
    {
        var first = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "web-01", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]"),
            new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "stack-a")
        ]);

        var second = BuildHostReport([
            new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "stack-a"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("environment", "HOSTNAME", "web-01", EvidenceSensitivity.Sensitive)
        ]);

        var firstAnchor = Assert.Single(first.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));
        var secondAnchor = Assert.Single(second.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));

        Assert.Equal(firstAnchor.Value, secondAnchor.Value);
    }

    [Fact]
    public void IdentityAnchors_WorkloadProfileIdentity_DoesNotBuild_FromEphemeralDockerHostnameAndNamespacesOnly()
    {
        var report = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "70c7f56c9119", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        Assert.DoesNotContain(report.Host.IdentityAnchors, item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity);
    }

    [Fact]
    public void IdentityAnchors_WorkloadProfileIdentity_DropsEphemeralHostname_EvenWithComposeContext()
    {
        // Compose/Swarm sets HOSTNAME to the container ID by default — this must not be included in the digest.
        var baseline = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "70c7f56c9119", EvidenceSensitivity.Sensitive),
            new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "my-stack"),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        var restarted = BuildHostReport([
            new EvidenceItem("environment", "HOSTNAME", "aabbccddeeff", EvidenceSensitivity.Sensitive), // different container ID after restart
            new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "my-stack"),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532841]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532838]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532777]")
        ]);

        var baselineAnchor = Assert.Single(baseline.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));
        var restartedAnchor = Assert.Single(restarted.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));

        Assert.Equal(baselineAnchor.Value, restartedAnchor.Value);
    }

    [Fact]
    public void IdentityAnchors_BuildsCloudAndKubernetesDigests_FromExplicitStableSources()
    {
        var report = BuildHostReport([
            new EvidenceItem("cloud-metadata", "aws.instance_id", "i-0abc123def4567890", EvidenceSensitivity.Sensitive),
            new EvidenceItem("cloud-metadata", "cloud.source", RuntimeReportedHostSource.AwsMetadata.ToString()),
            new EvidenceItem("kubernetes", "kubernetes.node.name", "worker-a", EvidenceSensitivity.Sensitive),
            new EvidenceItem("kubernetes", "kubernetes.node.uid", "8e5fd1d0-6245-4ff8-b22f-7a3e1b10d111", EvidenceSensitivity.Sensitive),
            new EvidenceItem("kubernetes", "kubernetes.node.provider_id", "azure:///subscriptions/demo/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/aks-worker-a", EvidenceSensitivity.Sensitive)
        ]);

        Assert.Equal(3, report.Host.IdentityAnchors.Count);

        var cloudAnchor = Assert.Single(report.Host.IdentityAnchors.Where(anchor => anchor.Kind == IdentityAnchorKind.CloudInstanceIdentity));
        Assert.Equal("CRP-CLOUD-INSTANCE-v1", cloudAnchor.Algorithm);
        Assert.Equal(IdentityAnchorStrength.Strong, cloudAnchor.Strength);
        Assert.Equal(BindingSuitability.LicenseBinding, cloudAnchor.BindingSuitability);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, cloudAnchor.Sensitivity);
        Assert.StartsWith("sha256:", cloudAnchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("i-0abc123def4567890", cloudAnchor.Value, StringComparison.Ordinal);

        var kubernetesAnchors = report.Host.IdentityAnchors.Where(anchor => anchor.Kind == IdentityAnchorKind.KubernetesNodeIdentity).ToArray();
        var kubernetesAnchor = Assert.Single(kubernetesAnchors.Where(anchor => anchor.Strength == IdentityAnchorStrength.Strong));
        Assert.Contains(kubernetesAnchors, anchor => anchor.Strength == IdentityAnchorStrength.Medium);
        Assert.Equal(BindingSuitability.LicenseBinding, kubernetesAnchor.BindingSuitability);
        Assert.StartsWith("sha256:", kubernetesAnchor.Value, StringComparison.Ordinal);
        Assert.Contains(kubernetesAnchor.EvidenceReferences, reference => reference == "kubernetes:kubernetes.node.uid");
    }

    [Fact]
    public void IdentityAnchors_BuildsSiemensIedDigest_FromMatchedTlsBindingAndDocumentedChain()
    {
        var report = BuildHostReport([
            new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.cert_chain_sha256", "expected-chain-hash", EvidenceSensitivity.Sensitive),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.subject", "CN=edge-iot-core.proxy-redirect"),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.issuer", "CN=Siemens Local Root"),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.binding", "matched")
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.VendorRuntimeIdentity));

        Assert.Equal("CRP-SIEMENS-IED-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Platform, anchor.Scope);
        Assert.Equal(BindingSuitability.LicenseBinding, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Strong, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("expected-chain-hash", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "siemens-ied-runtime:trust.ied.certsips.cert_chain_sha256");
        Assert.Contains(anchor.Reasons, reason => reason.Contains("matched local TLS binding", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_DoesNotBuildSiemensIedAnchor_WithoutMatchedTlsBinding()
    {
        var report = BuildHostReport([
            new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.cert_chain_sha256", "expected-chain-hash", EvidenceSensitivity.Sensitive),
            new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.binding", "mismatch")
        ]);

        Assert.DoesNotContain(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.VendorRuntimeIdentity);
    }

    [Fact]
    public void IdentityAnchors_BuildsWindowsMachineIdDigest_AsConservativeHostCorrelationAnchor()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "windows.machine_guid", "9f8b2b2f-6d45-4a28-90ea-3c3a2f06d111", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "windows.product_name", "Windows 11 Pro"),
            new EvidenceItem("proc-files", "kernel.release", "10.0.26200")
        ], ContainerizationKind.@False);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.MachineIdDigest));

        Assert.Equal("CRP-WINDOWS-MACHINE-ID-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("9f8b2b2f-6d45-4a28-90ea-3c3a2f06d111", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:windows.machine_guid");
        Assert.Contains(anchor.Warnings, warning => warning.Contains("installation-stable", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_BuildsLinuxMachineIdDigest_AsConservativeHostCorrelationAnchor()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "machine.id", "87c4bc1848a84471997203ee530d2fda", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "os.id", "debian"),
            new EvidenceItem("proc-files", "kernel.release", "6.8.0-59-generic")
        ], ContainerizationKind.@False);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.MachineIdDigest && item.Algorithm == "CRP-LINUX-MACHINE-ID-v1"));

        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("87c4bc1848a84471997203ee530d2fda", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:machine.id");
    }

    [Fact]
    public void IdentityAnchors_DoesNotBuildMachineIdDigest_ForContainerizedEnvironment()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "machine.id", "87c4bc1848a84471997203ee530d2fda", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "windows.machine_guid", "9f8b2b2f-6d45-4a28-90ea-3c3a2f06d111", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@True);

        Assert.DoesNotContain(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.MachineIdDigest);
    }

    [Fact]
    public void IdentityAnchors_BuildsHardwareIdentity_FromExplicitDmiIdentifiers_InContainerizedEnvironment()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "dmi.product_uuid", "7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "dmi.product_serial", "SN-123456", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.HardwareIdentity));

        Assert.Equal("CRP-HARDWARE-ID-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:dmi.product_uuid");
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:dmi.product_serial");
    }

    [Fact]
    public void IdentityAnchors_BuildsHypervisorIdentity_FromVirtualizedGuestUuid()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.flag.hypervisor", bool.TrueString),
            new EvidenceItem("proc-files", "dmi.sys_vendor", "QEMU"),
            new EvidenceItem("proc-files", "dmi.product_name", "Standard PC (Q35 + ICH9, 2009)"),
            new EvidenceItem("proc-files", "dmi.product_uuid", "7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", EvidenceSensitivity.Sensitive)
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.HypervisorIdentity));

        Assert.Equal("CRP-HYPERVISOR-INSTANCE-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Hypervisor, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:dmi.product_uuid");
        Assert.Contains(anchor.Warnings, warning => warning.Contains("virtual guest or substrate instance", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_DoesNotBuildHypervisorIdentity_WithoutVirtualizationSignals()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "dmi.product_uuid", "7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", EvidenceSensitivity.Sensitive)
        ]);

        Assert.DoesNotContain(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.HypervisorIdentity);
    }

    [Fact]
    public void IdentityAnchors_BuildsHardwareIdentity_FromCpuAndSocSerialSignals()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "cpu.serial", "ABC123XYZ", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "soc.serial_number", "SOC-0001", EvidenceSensitivity.Sensitive)
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.HardwareIdentity));

        Assert.Equal("CRP-HARDWARE-ID-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("ABC123XYZ", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:cpu.serial");
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:soc.serial_number");
    }

    [Fact]
    public void IdentityAnchors_BuildsKubernetesEnvironmentIdentity_FromServiceAccountCaDigest()
    {
        var report = BuildHostReport([
            new EvidenceItem("kubernetes", "serviceaccount.ca.sha256", "sha256:9a0ef8f0e6fa0f6f3eb9c3d7cc6ed1111111111111111111111111111111111"),
            new EvidenceItem("kubernetes", "env.KUBERNETES_SERVICE_HOST", "10.96.0.1"),
            new EvidenceItem("kubernetes", "api.version.outcome", ProbeOutcome.Success.ToString())
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.KubernetesEnvironmentIdentity));

        Assert.Equal("CRP-KUBERNETES-CLUSTER-CA-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Platform, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Public, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("9a0ef8f0e6fa0f6f3eb9c3d7cc6ed1111111111111111111111111111111111", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "kubernetes:serviceaccount.ca.sha256");
        Assert.Contains(anchor.Reasons, reason => reason.Contains("without requiring RBAC", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_BuildsCloudEnvironmentIdentity_FromProviderBoundaryMetadata()
    {
        var report = BuildHostReport([
            new EvidenceItem("cloud-metadata", "aws.account_id", "123456789012", EvidenceSensitivity.Sensitive),
            new EvidenceItem("cloud-metadata", "cloud.source", RuntimeReportedHostSource.AwsMetadata.ToString()),
            new EvidenceItem("cloud-metadata", "cloud.region", "eu-central-1")
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.CloudEnvironmentIdentity));

        Assert.Equal("CRP-CLOUD-ENVIRONMENT-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Platform, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("123456789012", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "cloud-metadata:aws.account_id");
        Assert.Contains(anchor.Warnings, warning => warning.Contains("aws accounts", StringComparison.Ordinal));
        Assert.Contains(anchor.Reasons, reason => reason.Contains("aws environment metadata", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_BuildsDeploymentEnvironmentIdentity_FromComposeAndPortainerLabels()
    {
        var report = BuildHostReport([
            new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "edge-stack"),
            new EvidenceItem("runtime-api", "compose.label.com.docker.stack.namespace", "edge-stack-swarm"),
            new EvidenceItem("runtime-api", "compose.label.io.portainer.stack.name", "portainer-edge")
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.DeploymentEnvironmentIdentity));

        Assert.Equal("CRP-DEPLOYMENT-METADATA-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.ApplicationHost, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Public, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("edge-stack", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "runtime-api:compose.label.com.docker.compose.project");
        Assert.Contains(anchor.Reasons, reason => reason.Contains("Compose or Portainer", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_BuildsKubernetesWorkloadIdentity_FromPodUidAndCgroupToken_WhenInspectIdUnavailable()
    {
        var report = BuildHostReport([
            new EvidenceItem("kubernetes", "kubernetes.pod.uid", "550e8400-e29b-41d4-a716-446655440000", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "kubernetes.cgroup.container_token", "0123456789abcdef", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@True);

        var runtimeAnchors = report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.ContainerRuntimeIdentity).ToArray();
        var anchor = Assert.Single(runtimeAnchors.Where(item => item.Strength == IdentityAnchorStrength.Medium));
        Assert.Contains(report.Host.IdentityAnchors, item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity && item.Strength == IdentityAnchorStrength.Weak);

        Assert.Equal("CRP-KUBERNETES-WORKLOAD-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Workload, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("0123456789abcdef", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "kubernetes:kubernetes.pod.uid");
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:kubernetes.cgroup.container_token");
    }

    [Fact]
    public void IdentityAnchors_BuildsContainerRuntimeIdentity_ForContainerizedEnvironment()
    {
        var report = BuildHostReport([
            new EvidenceItem("runtime-api", "container.id", "f54f4f0f068f4d4b9c8cf6c16c9f111111111111111111111111111111111111", EvidenceSensitivity.Sensitive),
            new EvidenceItem("runtime-api", "container.inspect.outcome", ProbeOutcome.Success.ToString())
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.ContainerRuntimeIdentity));

        Assert.Equal("CRP-CONTAINER-INSTANCE-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Workload, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Medium, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("f54f4f0f068f4d4b9c8cf6c16c9f111111111111111111111111111111111111", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "runtime-api:container.id");
    }

    [Fact]
    public void IdentityAnchors_DoesNotBuildWorkloadProfileIdentity_FromNamespaceTupleAlone_WhenInspectIdIsUnavailable()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532964]"),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532961]"),
            new EvidenceItem("proc-files", "ns.net", "net:[4026532890]")
        ], ContainerizationKind.@True);

        Assert.DoesNotContain(report.Host.IdentityAnchors, item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity);
    }

    [Fact]
    public void IdentityAnchors_DoesNotBuildContainerRuntimeIdentity_ForNonContainerizedEnvironment()
    {
        var report = BuildHostReport([
            new EvidenceItem("runtime-api", "container.id", "f54f4f0f068f4d4b9c8cf6c16c9f111111111111111111111111111111111111", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@False);

        Assert.DoesNotContain(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.ContainerRuntimeIdentity);
    }

    [Fact]
    public void IdentityAnchors_BuildsWorkloadProfileIdentity_FromHostnameOnly_WithoutPromotingHostIdentity()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "device.tpm.path", "/dev/tpm0"),
            new EvidenceItem("environment", "HOSTNAME", "edge-host", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "kernel.hostname", "edge-host", EvidenceSensitivity.Sensitive)
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.WorkloadProfileIdentity));

        Assert.Equal(IdentityAnchorScope.Workload, anchor.Scope);
        Assert.Equal(IdentityAnchorStrength.Weak, anchor.Strength);
        Assert.DoesNotContain(report.Host.IdentityAnchors, item => item.Kind == IdentityAnchorKind.HostProfileIdentity || item.Kind == IdentityAnchorKind.HardwareIdentity || item.Kind == IdentityAnchorKind.MachineIdDigest);
    }

    [Fact]
    public void IdentityAnchors_BuildsTpmPublicKeyDigest_FromVisiblePublicMaterial()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "device.tpm.path", "/dev/tpm0"),
            new EvidenceItem("proc-files", "device.tpm.pubek.sha256", "sha256:abcdef0123456789", EvidenceSensitivity.Sensitive)
        ]);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.TpmPublicKeyDigest));

        Assert.Equal("CRP-TPM-PUBLIC-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.ExternalAttestation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Strong, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Sensitive, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.NotEqual("sha256:abcdef0123456789", anchor.Value);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:device.tpm.pubek.sha256");
        Assert.Contains(anchor.Warnings, warning => warning.Contains("does not by itself prove", StringComparison.Ordinal));
        Assert.Contains(anchor.Reasons, reason => reason.Contains("read-only TPM public material", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_BuildsWeakHostProfileIdentity_WhenOnlyCoarseHostProfileSignalsAreVisible()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.8.0-59-generic"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("proc-files", "platform.modalias", "acpi:VMBUS:00"),
            new EvidenceItem("proc-files", "bus.vmbus.present", "true")
        ], ContainerizationKind.@True);

        var anchor = Assert.Single(report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.HostProfileIdentity));

        Assert.Equal("CRP-HOST-PROFILE-v1", anchor.Algorithm);
        Assert.Equal(IdentityAnchorScope.Host, anchor.Scope);
        Assert.Equal(BindingSuitability.Correlation, anchor.BindingSuitability);
        Assert.Equal(IdentityAnchorStrength.Weak, anchor.Strength);
        Assert.Equal(IdentityAnchorSensitivity.Public, anchor.Sensitivity);
        Assert.StartsWith("sha256:", anchor.Value, StringComparison.Ordinal);
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:kernel.release");
        Assert.Contains(anchor.EvidenceReferences, reference => reference == "proc-files:platform.modalias");
        Assert.Contains(anchor.Warnings, warning => warning.Contains("weak correlation", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentityAnchors_StacksWeakHostProfileIdentity_WhenExplicitHostIdentityExists()
    {
        var report = BuildHostReport([
            new EvidenceItem("proc-files", "kernel.release", "6.8.0-59-generic"),
            new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
            new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz"),
            new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184"),
            new EvidenceItem("proc-files", "dmi.product_uuid", "7A9C2D19-4FA1-4F91-93EA-0D4D7D1F5B1A", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@True);

        Assert.Contains(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.HardwareIdentity);
        Assert.Contains(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.HostProfileIdentity && anchor.Strength == IdentityAnchorStrength.Weak);
    }

    [Fact]
    public void IdentityAnchors_DoesNotStackNamespaceOnlyWorkloadFallback_WhenRuntimeInspectIdentityExists()
    {
        var report = BuildHostReport([
            new EvidenceItem("runtime-api", "container.id", "f54f4f0f068f4d4b9c8cf6c16c9f111111111111111111111111111111111111", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.pid", "pid:[4026532964]", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.mnt", "mnt:[4026532954]", EvidenceSensitivity.Sensitive),
            new EvidenceItem("proc-files", "ns.net", "net:[4026533104]", EvidenceSensitivity.Sensitive)
        ], ContainerizationKind.@True);

        var runtimeAnchors = report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.ContainerRuntimeIdentity).ToArray();

        Assert.Contains(runtimeAnchors, anchor => anchor.Algorithm == "CRP-CONTAINER-INSTANCE-v1" && anchor.Strength == IdentityAnchorStrength.Medium);
        Assert.DoesNotContain(report.Host.IdentityAnchors, anchor => anchor.Kind == IdentityAnchorKind.WorkloadProfileIdentity);
    }

    [Fact]
    public void IdentityAnchors_StacksKubernetesNodeProviderId_WhenNodeUidExists()
    {
        var report = BuildHostReport([
            new EvidenceItem("kubernetes", "kubernetes.node.uid", "8e5fd1d0-6245-4ff8-b22f-7a3e1b10d111", EvidenceSensitivity.Sensitive),
            new EvidenceItem("kubernetes", "kubernetes.node.provider_id", "azure:///subscriptions/demo/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/aks-worker-a", EvidenceSensitivity.Sensitive)
        ]);

        var anchors = report.Host.IdentityAnchors.Where(item => item.Kind == IdentityAnchorKind.KubernetesNodeIdentity).ToArray();

        Assert.Contains(anchors, anchor => anchor.Strength == IdentityAnchorStrength.Strong);
        Assert.Contains(anchors, anchor => anchor.Strength == IdentityAnchorStrength.Medium);
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

        Assert.Contains("## Summary", markdown);
        Assert.Contains("### Environment", markdown);
        Assert.Contains("### Identity", markdown);
        Assert.Contains("#### Host", markdown);
        Assert.Contains("| Host OS | Ubuntu 24.04 |", markdown);
        Assert.Contains("| Cloud Host ID | <redacted> | L3 | BindingCandidate |", markdown);
        Assert.Contains("## Host OS / Node", markdown);
        Assert.Contains("## Probe Tool Information", markdown);
        Assert.Contains("- Git Commit: abcdef1", markdown);
        Assert.Contains("### Virtualization", markdown);
        Assert.Contains("- Platform Vendor: Microsoft Hyper-V", markdown);
        Assert.Contains("### Platform / DMI", markdown);
        Assert.Contains("### Device Tree", markdown);
        Assert.Contains("### Identity Anchors", markdown);
        Assert.Contains("- Kind: CloudInstanceIdentity", markdown);
        Assert.Contains("- System Vendor: Microsoft Corporation", markdown);
        Assert.Contains("\"Host\":", json, StringComparison.Ordinal);
        Assert.Contains("\"ProbeToolInfo\":", json, StringComparison.Ordinal);
        Assert.Contains("\"GitCommit\": \"abcdef1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Virtualization\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Dmi\":", json, StringComparison.Ordinal);
        Assert.Contains("\"DeviceTree\":", json, StringComparison.Ordinal);
        Assert.Contains("\"IdentityAnchors\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Summary\":", json, StringComparison.Ordinal);
        Assert.Contains("\"Family\": \"Debian\"", json, StringComparison.Ordinal);
        Assert.Contains("HardwareVendor", text);
        Assert.Contains("Architecture", text);
        Assert.Contains("DeviceTreeModel", text);
        Assert.Contains("IdentityAnchors", text);
        Assert.Contains("Environment", text);
        Assert.Contains("Identity", text);
        Assert.Contains("abcdef1", text);
        Assert.Contains("Host OS", text);
        Assert.Contains("Cloud Host ID", text);
        Assert.Matches(@"DiagnosticFingerprint\s+:\s+sha256:", text);
    }

    private static ContainerRuntimeReport BuildHostReport(IReadOnlyList<EvidenceItem> evidence, ContainerizationKind containerizationKind = ContainerizationKind.@True)
    {
        var report = new ContainerRuntimeReport(
            DateTimeOffset.UtcNow,
            TimeSpan.FromSeconds(1),
            null,
            [
                new ProbeResult("proc-files", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "proc-files").ToArray()),
                new ProbeResult("runtime-api", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "runtime-api").ToArray()),
                new ProbeResult("environment", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "environment").ToArray()),
                new ProbeResult("cloud-metadata", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "cloud-metadata").ToArray()),
                new ProbeResult("kubernetes", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "kubernetes").ToArray()),
                new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, evidence.Where(item => item.ProbeId == "siemens-ied-runtime").ToArray())
            ],
            [],
            new ReportClassification(
                new(containerizationKind, Confidence.High, []),
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
