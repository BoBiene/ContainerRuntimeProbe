using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class DetectionMapsTests
{
    [Fact]
    public void KernelFlavorSignals_HaveUniqueNonEmptySignals()
    {
        Assert.All(DetectionMaps.KernelFlavorSignals, signal => Assert.False(string.IsNullOrWhiteSpace(signal.Signal)));

        var duplicates = DetectionMaps.KernelFlavorSignals
            .GroupBy(signal => signal.Signal, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();

        Assert.Empty(duplicates);
    }

    [Theory]
    [InlineData("ID=pop\nNAME=Pop!_OS\nVERSION_ID=\"22.04\"\n", OperatingSystemFamily.Debian)]
    [InlineData("ID=arch\nNAME=Arch Linux\n", OperatingSystemFamily.Arch)]
    [InlineData("ID=openwrt\nNAME=OpenWrt\nVERSION_ID=\"23.05\"\n", OperatingSystemFamily.OpenWrt)]
    public void ParseOsRelease_UsesDistroIdFallbackMappings(string text, OperatingSystemFamily expectedFamily)
    {
        var parsed = HostParsing.ParseOsRelease(text);

        Assert.Equal(expectedFamily, parsed.Family);
    }

    [Theory]
    [InlineData("Linux version 6.17.0-1011-azure (buildd@lcy02-amd64) (gcc (Ubuntu 13.3.0) 13.3.0) #11~24.04.2-Ubuntu SMP", KernelFlavor.Azure)]
    [InlineData("Linux version 5.15.0-qnap (builder@nas) (gcc version 11.2.0) #1 SMP", KernelFlavor.Qnap)]
    [InlineData("Linux version 6.1.0-openwrt (builder@lede) (gcc version 12.3.0) #0 SMP PREEMPT", KernelFlavor.Embedded)]
    [InlineData("Linux version 6.6.3-yocto-standard (builder@poky) (gcc version 13.2.0) #1 SMP", KernelFlavor.Embedded)]
    public void ParseKernel_RecognizesMappedKernelFlavorSignals(string procVersion, KernelFlavor expectedFlavor)
    {
        var parsed = HostParsing.ParseKernel(procVersion, null, "Linux", null);

        Assert.Equal(expectedFlavor, parsed.Flavor);
    }

    [Theory]
    [InlineData("ID=linuxmint\nNAME=\"Linux Mint\"\nVERSION_ID=\"22\"\nPRETTY_NAME=\"Linux Mint 22\"\n", OperatingSystemFamily.Debian)]
    [InlineData("ID=manjaro\nNAME=\"Manjaro Linux\"\nPRETTY_NAME=\"Manjaro Linux\"\n", OperatingSystemFamily.Arch)]
    [InlineData("ID=openwrt\nNAME=\"OpenWrt\"\nVERSION_ID=\"23.05.3\"\nPRETTY_NAME=\"OpenWrt 23.05.3\"\n", OperatingSystemFamily.OpenWrt)]
    [InlineData("ID=wolfi\nNAME=\"Wolfi\"\nVERSION_ID=\"20230201\"\nPRETTY_NAME=\"Wolfi 20230201\"\n", OperatingSystemFamily.Wolfi)]
    public void RepresentativeOsReleaseFixtures_MapToExpectedFamilies(string text, OperatingSystemFamily expectedFamily)
    {
        var parsed = HostParsing.ParseOsRelease(text);

        Assert.Equal(expectedFamily, parsed.Family);
    }
}