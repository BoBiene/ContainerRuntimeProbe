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
}
