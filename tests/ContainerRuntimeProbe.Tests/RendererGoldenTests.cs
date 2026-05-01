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
        Assert.Contains("Findings", text);
        Assert.Contains("Containerization assessment: True with Docker runtime", text);
        Assert.Contains("Details", text);
        Assert.Matches(@"Runtime\s+:\s+Docker", text);
        Assert.Matches(@"HostOS\s+:\s+Ubuntu", text);          // runtime-reported host, not container OS
        Assert.Matches(@"ContainerOS\s+:\s+Debian", text);     // container image OS
        Assert.Matches(@"HostFingerprint\s+:\s+sha256:", text);
    }
}
