using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class ClassifierSampleProbeTests
{
    [Theory]
    [InlineData("my-report.json")]
    [InlineData("wsl2-report.json")]
    [InlineData("wsl2-system2.json")]
    [InlineData("wsl2-system3.json")]
    public void Wsl2SampleProbes_ReclassifyAsMicrosoftVendor(string fixtureName)
    {
        var fixturePath = Path.Combine(FindSampleProbeDirectory(), fixtureName);
        var report = JsonSerializer.Deserialize(
            File.ReadAllText(fixturePath),
            ReportJsonContext.Default.ContainerRuntimeReport);

        Assert.NotNull(report);

        var classification = Classifier.Classify(report!.Probes);

        Assert.Equal(VirtualizationClassificationKind.WSL2, classification.Virtualization.Value);
        Assert.Equal(PlatformVendorKind.Microsoft, classification.PlatformVendor.Value);
        Assert.Equal(HostTypeKind.WSL2, classification.Host.Type.Value);
    }

    [Theory]
    [InlineData("mac-os-intel.json")]
    [InlineData("mac-os-m2-macbook-air.json")]
    [InlineData("mac-os-m5-macbook-pro.json")]
    public void MacSampleProbes_ReclassifyAsAppleVendor(string fixtureName)
    {
        var fixturePath = Path.Combine(FindSampleProbeDirectory(), fixtureName);
        var report = JsonSerializer.Deserialize(
            File.ReadAllText(fixturePath),
            ReportJsonContext.Default.ContainerRuntimeReport);

        Assert.NotNull(report);

        var classification = Classifier.Classify(report!.Probes);

        Assert.Equal(ContainerRuntimeKind.Containerd, classification.ContainerRuntime.Value);
        Assert.Equal(PlatformVendorKind.Apple, classification.PlatformVendor.Value);
        Assert.True(classification.PlatformVendor.Confidence >= Confidence.Low);
    }

    [Theory]
    [InlineData("ubuntu-host1.json")]
    public void UbuntuHostSampleProbes_ReclassifyWithDockerAndUbuntuKernel(string fixtureName)
    {
        var fixturePath = Path.Combine(FindSampleProbeDirectory(), fixtureName);
        var report = JsonSerializer.Deserialize(
            File.ReadAllText(fixturePath),
            ReportJsonContext.Default.ContainerRuntimeReport);

        Assert.NotNull(report);

        var classification = Classifier.Classify(report!.Probes);

        Assert.Equal(ContainerRuntimeKind.Docker, classification.ContainerRuntime.Value);
        // Ubuntu is the host, not a vendor appliance — vendor stays Unknown
        Assert.Equal(PlatformVendorKind.Unknown, classification.PlatformVendor.Value);
    }

    [Theory]
    [InlineData("Debian-VM-Intel-CPU-ispone.json")]
    public void DebianVmSampleProbes_ReclassifyWithDockerAndDebianKernel(string fixtureName)
    {
        var fixturePath = Path.Combine(FindSampleProbeDirectory(), fixtureName);
        var report = JsonSerializer.Deserialize(
            File.ReadAllText(fixturePath),
            ReportJsonContext.Default.ContainerRuntimeReport);

        Assert.NotNull(report);

        var classification = Classifier.Classify(report!.Probes);

        Assert.Equal(ContainerRuntimeKind.Docker, classification.ContainerRuntime.Value);
        Assert.Equal(PlatformVendorKind.Unknown, classification.PlatformVendor.Value);
    }

    private static string FindSampleProbeDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ContainerRuntimeProbe.sln")))
            {
                var fixtures = Path.Combine(directory.FullName, "docker", "sample-probes");
                if (Directory.Exists(fixtures))
                {
                    return fixtures;
                }
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate docker/sample-probes from the test output directory.");
    }
}
