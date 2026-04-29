using System.Text.Json;
using ContainerRuntimeProbe.Rendering;

namespace ContainerRuntimeProbe.Tests;

public sealed class SampleRegressionTests
{
    [SkippableFact]
    public void ExampleSamples_AreSupported_AndCompactSamplesParse()
    {
        var examplesDirectory = FindExamplesDirectory();
        Skip.If(examplesDirectory is null, "Examples directory not found");

        var jsonFiles = Directory.GetFiles(examplesDirectory!, "*.sample.json", SearchOption.TopDirectoryOnly);
        Skip.If(jsonFiles.Length == 0, "No committed sample fixtures found");

        foreach (var jsonFile in jsonFiles)
        {
            using var document = JsonDocument.Parse(File.ReadAllText(jsonFile));
            var root = document.RootElement;
            Assert.Equal("1.0", root.GetProperty("schemaVersion").GetString());
            Assert.Equal("crp1", root.GetProperty("compactFormat").GetString());

            var compactSample = root.GetProperty("compactSample").GetString();
            Assert.False(string.IsNullOrWhiteSpace(compactSample));

            var parsed = RuntimeSampleRenderer.ParseCompactSample(compactSample!);
            Assert.True(parsed.IsValid, string.Join(Environment.NewLine, parsed.Diagnostics));

            var sample = root.GetProperty("sample");
            Assert.True(sample.TryGetProperty("host", out var host));
            Assert.True(host.TryGetProperty("fingerprint", out _));

            var lower = root.GetRawText().ToLowerInvariant();
            Assert.DoesNotContain("\"hostname\":", lower, StringComparison.Ordinal);
            Assert.DoesNotContain("\"instanceid\":", lower, StringComparison.Ordinal);

            var txtFile = Path.ChangeExtension(jsonFile, ".txt");
            if (File.Exists(txtFile))
            {
                var txt = File.ReadAllText(txtFile).Trim();
                Assert.Equal(compactSample, txt);
            }
        }
    }

    private static string? FindExamplesDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ContainerRuntimeProbe.sln")))
            {
                var examples = Path.Combine(directory.FullName, "docs", "samples", "examples");
                return Directory.Exists(examples) ? examples : null;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
