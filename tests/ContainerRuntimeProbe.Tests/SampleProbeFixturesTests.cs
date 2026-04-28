using System.Text.Json;
using System.Text.RegularExpressions;

namespace ContainerRuntimeProbe.Tests;

public sealed class SampleProbeFixturesTests
{
    [Fact]
    public void SampleProbeJsonFiles_AreValidAndContainNoIndexedCharCorruption()
    {
        var fixturesDirectory = FindSampleProbeDirectory();
        var jsonFiles = Directory.GetFiles(fixturesDirectory, "*.json", SearchOption.TopDirectoryOnly);

        Assert.NotEmpty(jsonFiles);

        foreach (var jsonFile in jsonFiles)
        {
            var raw = File.ReadAllText(jsonFile);

            // Detect legacy corruption pattern like: "0=/ 1=. 2=d ..." inside arrays.
            Assert.DoesNotMatch(new Regex(@"(?m)^\s*\d+=", RegexOptions.CultureInvariant), raw);

            using var _ = JsonDocument.Parse(raw);
        }
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
