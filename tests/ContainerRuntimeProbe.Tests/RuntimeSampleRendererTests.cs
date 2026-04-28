using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Rendering;

namespace ContainerRuntimeProbe.Tests;

public sealed class RuntimeSampleRendererTests
{
    [Fact]
    public void CompactSample_UsesCanonicalCrp1Shape_AndAsciiOnly()
    {
        var artifacts = RuntimeSampleRenderer.Build(TestReportFactory.CreateSampleReport());

        Assert.StartsWith("crp1;cls=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";conf=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";host=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";hw=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";fp=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";p=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";sig=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains(";sec=", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.All(artifacts.CompactSample, ch => Assert.InRange((int)ch, 32, 126));
    }

    [Fact]
    public void CompactSample_PreservesKernelFlavor_WhenPlatformVendorIsUnknown()
    {
        var report = TestReportFactory.CreateSampleReport() with
        {
            Classification = new ReportClassification(
                new ClassificationResult("True", Confidence.High, []),
                new ClassificationResult("Docker", Confidence.Low, []),
                new ClassificationResult("Unknown", Confidence.Unknown, []),
                new ClassificationResult("Unknown", Confidence.Unknown, []),
                new ClassificationResult("Unknown", Confidence.Unknown, []),
                new ClassificationResult("Unknown", Confidence.Unknown, [])),
            Host = TestReportFactory.CreateSampleReport().Host with
            {
                VisibleKernel = TestReportFactory.CreateSampleReport().Host.VisibleKernel with
                {
                    Release = "5.15.167.4-microsoft-standard-WSL2",
                    Flavor = KernelFlavor.WSL2
                },
                RuntimeReportedHostOs = new RuntimeReportedHostOsInfo(
                    OperatingSystemFamily.Unknown,
                    null,
                    null,
                    null,
                    ArchitectureKind.Unknown,
                    null,
                    RuntimeReportedHostSource.Unknown,
                    Confidence.Unknown,
                    [])
            }
        };

        var artifacts = RuntimeSampleRenderer.Build(report);

        Assert.Contains("kf:WSL2", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains("pv0", artifacts.CompactSample, StringComparison.Ordinal);
        Assert.Contains("docker-wsl2", artifacts.PrefillUrl, StringComparison.Ordinal);
    }

    [Fact]
    public void CompactSampleParser_AcceptsValidDenseSample()
    {
        var artifacts = RuntimeSampleRenderer.Build(TestReportFactory.CreateSampleReport());

        var parsed = RuntimeSampleRenderer.ParseCompactSample(artifacts.CompactSample);

        Assert.True(parsed.IsValid);
        Assert.Contains("cls", parsed.Sections.Keys);
        Assert.Contains("sig", parsed.Sections.Keys);
    }

    [Theory]
    [InlineData("crp2;cls=c1")]
    [InlineData("crp1;cls=")]
    [InlineData("crp1;cls=c1;sig=api:docker,http://bad")]
    public void CompactSampleParser_RejectsMalformedExamples(string sample)
    {
        var parsed = RuntimeSampleRenderer.ParseCompactSample(sample);

        Assert.False(parsed.IsValid);
        Assert.NotEmpty(parsed.Diagnostics);
    }

    [Fact]
    public void SampleJson_ContainsCompactSample_AndScenario()
    {
        var artifacts = RuntimeSampleRenderer.Build(TestReportFactory.CreateSampleReport());

        var json = RuntimeSampleRenderer.ToJson(artifacts);
        using var document = JsonDocument.Parse(json);

        Assert.Equal("crp1", document.RootElement.GetProperty("compactFormat").GetString());
        Assert.Equal(artifacts.CompactSample, document.RootElement.GetProperty("compactSample").GetString());
        Assert.False(string.IsNullOrWhiteSpace(document.RootElement.GetProperty("sample").GetProperty("scenarioName").GetString()));
    }

    [Fact]
    public void UrlGeneration_ShrinksBody_WhenTargetLengthIsSmall()
    {
        var artifacts = RuntimeSampleRenderer.Build(
            TestReportFactory.CreateSampleReport(),
            new RuntimeSampleOptions(MaxUrlLength: 450, BodyFormat: "expanded"));

        Assert.NotEmpty(artifacts.UrlWarnings);
        Assert.Contains("issues/new?template=runtime-sample.yml", artifacts.PrefillUrl, StringComparison.Ordinal);
    }
}
