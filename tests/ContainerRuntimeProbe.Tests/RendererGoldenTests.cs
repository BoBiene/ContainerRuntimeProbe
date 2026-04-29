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
        Assert.Matches(@"Runtime\s+:\s+Docker", text);
        Assert.Matches(@"HostFingerprint\s+:\s+sha256:", text);
    }
}
