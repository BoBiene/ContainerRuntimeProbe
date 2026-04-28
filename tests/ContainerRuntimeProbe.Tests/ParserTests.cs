using ContainerRuntimeProbe.Internal;

namespace ContainerRuntimeProbe.Tests;

public sealed class ParserTests
{
    [Fact]
    public void ParseOsRelease_Works()
    {
        var dict = Parsing.ParseKeyValueLines(["ID=ubuntu", "VERSION_ID=\"22.04\""]);
        Assert.Equal("ubuntu", dict["ID"]);
        Assert.Equal("22.04", dict["VERSION_ID"]);
    }

    [Fact]
    public void ParseRoute_DefaultDevice()
    {
        var text = "Iface\tDestination\tGateway\neth0\t00000000\t01020304\n";
        Assert.Contains("eth0", Parsing.ParseDefaultRoutes(text));
    }

    [Fact]
    public void ParseResolv_SearchDomain()
    {
        var text = "search svc.cluster.local corp.local\nnameserver 10.0.0.10\n";
        Assert.Contains("svc.cluster.local", Parsing.ParseResolvSearchDomains(text));
    }

    [Fact]
    public void ParseCgroupSignals_DockerV1()
    {
        var text = "12:memory:/docker/abc1234567890abcdef\n11:blkio:/docker/abc1234567890abcdef\n0::/ \n";
        var signals = Parsing.ParseCgroupSignals(text).ToList();
        Assert.NotEmpty(signals);
        Assert.Contains(signals, s => s.Contains("/docker/", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseCgroupSignals_KubepodV1()
    {
        var text = "10:cpuset:/kubepods/burstable/pod1234/containerabc\n0::/ \n";
        var signals = Parsing.ParseCgroupSignals(text).ToList();
        Assert.NotEmpty(signals);
        Assert.Contains(signals, s => s.Contains("/kubepods/", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseCgroupSignals_HostRootOnly_Empty()
    {
        // Pure host cgroup v2 (single root, no container marker)
        var text = "0::/\n";
        var signals = Parsing.ParseCgroupSignals(text).ToList();
        Assert.Empty(signals);
    }

    [Fact]
    public void ParseCgroupSignals_PodmanContainer()
    {
        var text = "0::/machine.slice/libpod-abc123.scope\n";
        var signals = Parsing.ParseCgroupSignals(text).ToList();
        Assert.NotEmpty(signals);
        Assert.Contains(signals, s => s.Contains("podman", StringComparison.OrdinalIgnoreCase) || s.Contains("libpod", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ParseCgroupSignals_LargeInput_TruncatedAt50Lines()
    {
        var lines = Enumerable.Range(0, 200).Select(i => $"{i}:memory:/docker/id{i}");
        var text = string.Join('\n', lines);
        var signals = Parsing.ParseCgroupSignals(text).ToList();
        Assert.True(signals.Count <= 50);
    }
}
