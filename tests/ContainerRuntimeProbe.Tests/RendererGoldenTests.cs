using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Rendering;

namespace ContainerRuntimeProbe.Tests;

public sealed class RendererGoldenTests
{
    [Fact]
    public void TextRenderer_ContainsFields()
    {
        var report = new ContainerRuntimeReport(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1),
            [new ProbeResult("p", ProbeOutcome.Success, [new EvidenceItem("p", "k", "v")])],
            [],
            new ReportClassification(
                new("True", Confidence.High, []), new("Docker", Confidence.Medium, []), new("DockerEngineApi", Confidence.Medium, []), new("Unknown", Confidence.Unknown, []), new("Unknown", Confidence.Unknown, []), new("Unknown", Confidence.Unknown, [])));

        var text = ReportRenderer.ToText(report);
        Assert.Contains("Runtime=Docker", text);
    }
}
