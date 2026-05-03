using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Rendering;

namespace ContainerRuntimeProbe.Tests;

public sealed class RendererGoldenTests
{
    [Fact]
    public void TextRenderer_ContainsFields()
    {
        var report = TestReportFactory.CreateSampleReport();

        var text = ReportRenderer.ToText(report);
        Assert.Contains("Summary", text);
        Assert.Contains("Environment", text);
        Assert.Contains("Identity", text);
        Assert.Contains("Runtime", text);
        Assert.Contains("Mode", text);
        Assert.Contains("Containerized", text);
        Assert.Contains("Deployment / Environment Identity", text);
        Assert.Contains("Details", text);
        Assert.Matches(@"Runtime\s+:\s+Docker", text);
        Assert.Matches(@"HostOS\s+:\s+Ubuntu", text);          // runtime-reported host, not container OS
        Assert.Matches(@"ContainerOS\s+:\s+Debian", text);     // container image OS
        Assert.Matches(@"DiagnosticFingerprint\s+:\s+sha256:", text);
        Assert.Contains("IdentityAnchors", text);
    }
}
