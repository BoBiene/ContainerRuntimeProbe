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
        Assert.Contains("Runtime=Docker", text);
        Assert.Contains("HostFingerprint=sha256:", text);
    }
}
