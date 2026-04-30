using System.Text.Json;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.IntegrationTests;

public sealed class SmokeIntegrationTests
{
    [Fact]
    public async Task Engine_CompletesWithinTimeoutBudget()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);
        Assert.True(report.Duration < TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("debian.json")]
    [InlineData("wsl2-report.json")]
    public void SampleReportFixtures_ContainProcMountAndOsEvidence(string fixtureName)
    {
        var report = LoadSampleReport(fixtureName);
        var procEvidence = report.Probes.First(probe => probe.ProbeId == "proc-files").Evidence;

        Assert.Contains(procEvidence, item => item.Key.Contains("mountinfo:signal", StringComparison.Ordinal));
        Assert.Contains(procEvidence, item => item.Key == "os.id");
    }

    [Fact]
    public void Wsl2SampleReportFixture_ContainsCgroupAndKernelSignals()
    {
        var report = LoadSampleReport("wsl2-report.json");
        var procEvidence = report.Probes.First(probe => probe.ProbeId == "proc-files").Evidence;

        Assert.Contains(procEvidence, item => item.Key.Contains("cgroup:signal", StringComparison.Ordinal));
        Assert.Contains(procEvidence, item => item.Key == "kernel.flavor" && item.Value == "WSL2");
    }

    private static ContainerRuntimeReport LoadSampleReport(string fixtureName)
    {
        var fixturePath = Path.Combine(FindSampleProbeDirectory(), fixtureName);
        return JsonSerializer.Deserialize(File.ReadAllText(fixturePath), ReportJsonContext.Default.ContainerRuntimeReport)
            ?? throw new InvalidOperationException($"Could not deserialize sample fixture '{fixtureName}'.");
    }

    private static string FindSampleProbeDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ContainerRuntimeProbe.sln")))
            {
                var fixtures = Path.Combine(directory.FullName, "docker", "real-world-samples");
                if (Directory.Exists(fixtures))
                {
                    return fixtures;
                }
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate docker/real-world-samples from the test output directory.");
    }
}
