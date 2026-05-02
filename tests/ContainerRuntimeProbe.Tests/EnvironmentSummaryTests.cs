using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class EnvironmentSummaryTests
{
    [Fact]
    public void GetEnvironmentSummary_ReturnsCompactKnownFacts()
    {
        var report = TestReportFactory.CreateSampleReport();

        var summary = report.GetEnvironmentSummary();

        var runtimeSection = Assert.Single(summary.Sections.Where(section => section.Kind == EnvironmentSummarySectionKind.Runtime));
        Assert.Contains(runtimeSection.Facts, fact => fact.Label == "Mode" && fact.Value == "Containerized");
        Assert.Contains(runtimeSection.Facts, fact => fact.Label == "Runtime" && fact.Value == "Docker");
        Assert.Contains(runtimeSection.Facts, fact => fact.Label == "API" && fact.Value == "DockerEngineApi");

        var executionContextSection = Assert.Single(summary.Sections.Where(section => section.Kind == EnvironmentSummarySectionKind.ExecutionContext));
        Assert.Contains(executionContextSection.Facts, fact => fact.Label == "Environment" && fact.Value == "Cloud");
        Assert.Contains(executionContextSection.Facts, fact => fact.Label == "Cloud" && fact.Value == "Azure");

        var hostSection = Assert.Single(summary.Sections.Where(section => section.Kind == EnvironmentSummarySectionKind.Host));
        Assert.Contains(hostSection.Facts, fact => fact.Label == "Host OS" && fact.Value == "Ubuntu 24.04");
        Assert.Contains(hostSection.Facts, fact => fact.Label == "Hardware" && fact.Value == "Microsoft Corporation Virtual Machine");
        Assert.Contains(hostSection.Facts, fact => fact.Label == "CPU" && fact.Value == "Intel(R) Xeon(R)");
        Assert.Contains(hostSection.Facts, fact => fact.Label == "Memory" && fact.Value == "16 GB");

        var platformSection = Assert.Single(summary.Sections.Where(section => section.Kind == EnvironmentSummarySectionKind.Platform));
        Assert.Contains(platformSection.Facts, fact => fact.Label == "Machine Type" && fact.Value == "Standard_D4s_v5");

        Assert.DoesNotContain(summary.Sections.SelectMany(section => section.Facts), fact => fact.Value == "Unknown");
    }

    [Fact]
    public void GetEnvironmentSummary_UsesVisibleKernelMetadata_WhenRuntimeHostOsIsUnavailable()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                RuntimeReportedHostOs = baseReport.Host.RuntimeReportedHostOs with
                {
                    Name = null,
                    Version = null,
                    Confidence = Confidence.Unknown,
                    EvidenceReferences = []
                }
            }
        };

        var summary = report.GetEnvironmentSummary();

        var hostSection = Assert.Single(summary.Sections.Where(section => section.Kind == EnvironmentSummarySectionKind.Host));
        var hostOsFact = Assert.Single(hostSection.Facts.Where(fact => fact.Label == "Host OS"));
        Assert.Equal("Linux 6.17.0-1011-azure", hostOsFact.Value);
        Assert.Equal(Confidence.Medium, hostOsFact.Confidence);
        Assert.Equal(nameof(VisibleKernelInfo), hostOsFact.SourceKind);
        Assert.Contains("proc-files:kernel.release", hostOsFact.EvidenceKeys ?? []);
    }
}