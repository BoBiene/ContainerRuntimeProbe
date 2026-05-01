using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class PlatformEvidenceBuilderTests
{
    [Fact]
    public void Build_NoPlatformSignals_ReturnsEmpty()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [])
        ]);

        Assert.Empty(summaries);
    }

    [Fact]
    public void Build_GenericEdgeWord_DoesNotCreateIndustrialEdgeSummary()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "mountinfo.signal", "edge")
            ])
        ]);

        Assert.Empty(summaries);
    }

    [Fact]
    public void Build_IotEdgeOnly_ReturnsHeuristicWithWarning()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "env.signal", "iotedge")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal("siemens-industrial-edge", summary.PlatformKey);
        Assert.Equal(5, summary.Score);
        Assert.Equal(PlatformEvidenceLevel.Heuristic, summary.EvidenceLevel);
        Assert.Equal(Confidence.Medium, summary.Confidence);
        Assert.Contains(summary.Warnings, warning => warning.Contains("not Siemens-specific", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_IndustrialEdgePathAndDnsHint_ReturnsHeuristicSummary()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "mountinfo.signal", "industrial-edge"),
                new EvidenceItem("platform-context", "dns.signal", "industrial-edge")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(7, summary.Score);
        Assert.Equal(PlatformEvidenceLevel.Heuristic, summary.EvidenceLevel);
        Assert.Contains(summary.Evidence, item => item.Type == PlatformEvidenceType.ExecutionContext && item.Key == "mountinfo.signal");
        Assert.Contains(summary.Evidence, item => item.Type == PlatformEvidenceType.NetworkContext && item.Key == "dns.signal");
    }

    [Fact]
    public void Build_SiemensHardwareAndIoTEdge_ReturnsStrongHeuristicSummary()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "env.signal", "iotedge"),
                new EvidenceItem("platform-context", "env.signal", "siemens")
            ]),
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "dmi.sys_vendor", "Siemens AG")
            ]),
            new ProbeResult("runtime-api", ProbeOutcome.Success, [
                new EvidenceItem("runtime-api", "compose.label.com.docker.compose.project", "industrial-edge-stack")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(19, summary.Score);
        Assert.Equal(PlatformEvidenceLevel.StrongHeuristic, summary.EvidenceLevel);
        Assert.Equal(Confidence.High, summary.Confidence);
        Assert.Contains(summary.Evidence, item => item.Type == PlatformEvidenceType.Hardware && item.Key == "dmi.sys_vendor");
        Assert.Contains(summary.Evidence, item => item.Key == "siemens+iotedge");
    }

    [Fact]
    public void Build_TokenOnlySignal_ReturnsWeakHintWithAmbiguityWarning()
    {
        var summaries = PlatformEvidenceBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "hostname.signal", "ied", EvidenceSensitivity.Sensitive)
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(4, summary.Score);
        Assert.Equal(PlatformEvidenceLevel.Heuristic, summary.EvidenceLevel);
        Assert.Contains(summary.Warnings, warning => warning.Contains("ambiguous", StringComparison.OrdinalIgnoreCase));
    }
}