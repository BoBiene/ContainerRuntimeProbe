using ContainerRuntimeProbe.Internal;

namespace ContainerRuntimeProbe.Tests;

public sealed class VersionInfoTests
{
    [Fact]
    public void ParseProbeToolMetadata_ExtractsVersionAndShortCommit()
    {
        var metadata = VersionInfo.ParseProbeToolMetadata("0.1.0-preview.3.8+7789e369c4b2");

        Assert.Equal("0.1.0-preview.3.8", metadata.Version);
        Assert.Equal("7789e36", metadata.GitCommit);
    }

    [Fact]
    public void ParseProbeToolMetadata_LeavesCommitEmpty_WhenInformationalVersionHasNoMetadata()
    {
        var metadata = VersionInfo.ParseProbeToolMetadata("0.1.0-preview");

        Assert.Equal("0.1.0-preview", metadata.Version);
        Assert.Null(metadata.GitCommit);
    }

    [Fact]
    public void ParseProbeToolMetadata_UsesUnknownFallbacks_WhenInformationalVersionIsBlank()
    {
        var metadata = VersionInfo.ParseProbeToolMetadata(string.Empty);

        Assert.Equal("unknown", metadata.Version);
        Assert.Null(metadata.GitCommit);
    }
}