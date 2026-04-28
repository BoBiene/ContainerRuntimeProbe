using ContainerRuntimeProbe.Internal;

namespace ContainerRuntimeProbe.IntegrationTests;

public sealed class FixtureIntegrationTests
{
    [Theory]
    [InlineData("docker", "docker", "overlay", "ubuntu")]
    [InlineData("kubernetes", "kubepods", "kubernetes-serviceaccount", "debian")]
    [InlineData("podman", "libpod", "podman", "fedora")]
    public void RuntimeFixtures_ParseExpectedSignals(string scenario, string cgroupSignal, string mountSignal, string osId)
    {
        var fixtureDirectory = GetFixtureDirectory(scenario);
        var cgroup = File.ReadAllText(Path.Combine(fixtureDirectory, "cgroup.txt"));
        var mountInfo = File.ReadAllText(Path.Combine(fixtureDirectory, "mountinfo.txt"));
        var osRelease = File.ReadAllText(Path.Combine(fixtureDirectory, "os-release.txt"));

        Assert.Contains(Parsing.ParseCgroupSignals(cgroup), signal => signal.Contains(cgroupSignal, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(Parsing.ParseMountInfoSignals(mountInfo), signal => signal.Equals(mountSignal, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(osId, HostParsing.ParseOsRelease(osRelease).Id);
    }

    [Fact]
    public void Wsl2Fixture_ParsesUbuntuUserspaceWithoutContainerSignals()
    {
        var fixtureDirectory = GetFixtureDirectory("wsl2");
        var cgroup = File.ReadAllText(Path.Combine(fixtureDirectory, "cgroup.txt"));
        var mountInfo = File.ReadAllText(Path.Combine(fixtureDirectory, "mountinfo.txt"));
        var osRelease = File.ReadAllText(Path.Combine(fixtureDirectory, "os-release.txt"));

        Assert.Empty(Parsing.ParseCgroupSignals(cgroup));
        Assert.DoesNotContain(Parsing.ParseMountInfoSignals(mountInfo), signal => signal.Equals("overlay", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("ubuntu", HostParsing.ParseOsRelease(osRelease).Id);
    }

    private static string GetFixtureDirectory(string scenario)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ContainerRuntimeProbe.sln")))
            {
                var fixtures = Path.Combine(directory.FullName, "tests", "ContainerRuntimeProbe.IntegrationTests", "Fixtures", scenario);
                if (Directory.Exists(fixtures))
                {
                    return fixtures;
                }
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Could not locate integration fixture directory for '{scenario}'.");
    }
}
