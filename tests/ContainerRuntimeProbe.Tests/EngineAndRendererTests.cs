using ContainerRuntimeProbe.Rendering;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using System.Threading;

namespace ContainerRuntimeProbe.Tests;

public sealed class EngineAndRendererTests
{
    [Fact]
    public async Task RunAsync_ProducesReport()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(200), includeSensitive: false);

        Assert.NotNull(report);
        Assert.NotEmpty(report.Probes);
    }

    [Fact]
    public async Task MarkdownRenderer_IncludesHeader()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(200), includeSensitive: false);
        var markdown = ReportRenderer.ToMarkdown(report);

        Assert.Contains("# Container Runtime Report", markdown);
        Assert.Contains("## Host OS / Node", markdown);
    }

    [Fact]
    public void Renderers_IncludeGenericPlatformSections()
    {
        var report = TestReportFactory.CreateSampleReport() with
        {
            PlatformEvidence = [
                new PlatformEvidenceSummary(
                    "siemens-industrial-edge",
                    9,
                    PlatformEvidenceLevel.StrongHeuristic,
                    Confidence.High,
                    [new PlatformEvidenceItem(PlatformEvidenceType.ExecutionContext, "mountinfo.signal", "industrial-edge", Confidence.High, "Industrial Edge path detected")],
                    [])
            ],
            TrustedPlatforms = [
                new TrustedPlatformSummary(
                    "siemens-ied-runtime",
                    TrustedPlatformState.Verified,
                    "local-runtime-tls-binding",
                    null,
                    "edge-iot-core.proxy-redirect",
                    null,
                    [new TrustedPlatformClaim(TrustedPlatformClaimScope.RuntimePresence, "siemens-ied-runtime", "tls-bound", Confidence.High, "TLS-bound runtime claim")],
                    [new TrustedPlatformEvidence(TrustedPlatformSourceType.TlsBinding, "trust.ied.endpoint.tls.binding", "matched", Confidence.High, "TLS binding matched")],
                    [])
                {
                    VerificationLevel = 4
                }
            ]
        };

        var markdown = ReportRenderer.ToMarkdown(report);
        var text = ReportRenderer.ToText(report);
        var json = ReportRenderer.ToJson(report);

        Assert.Contains("## Platform Evidence", markdown);
        Assert.Contains("## Trusted Platforms", markdown);
        Assert.Contains("PlatformEvidence : siemens-industrial-edge", text);
        Assert.Contains("TrustedPlatform  : siemens-ied-runtime", text);
        Assert.Contains("\"PlatformEvidence\":", json, StringComparison.Ordinal);
        Assert.Contains("\"TrustedPlatforms\":", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task JsonRenderer_ContainsClassification()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(200), includeSensitive: false);
        var json = ReportRenderer.ToJson(report);

        Assert.Contains("isContainerized", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"Host\":", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_ExecutesProbesConcurrently_AndPreservesOrder()
    {
        var allStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var startedCount = 0;
        var engine = new ContainerRuntimeProbeEngine(
        [
            new CoordinatedProbe("first", allStarted, () => Interlocked.Increment(ref startedCount), expectedStartedCount: 2),
            new CoordinatedProbe("second", allStarted, () => Interlocked.Increment(ref startedCount), expectedStartedCount: 2)
        ]);

        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);

        Assert.Equal(["first", "second"], report.Probes.Select(probe => probe.ProbeId));
    }

    [Fact]
    public async Task RunAsync_AddsWarning_WhenKubernetesTlsValidationIsSkipped()
    {
        var engine = new ContainerRuntimeProbeEngine(
        [
            new FixedProbe("kubernetes",
            [
                new EvidenceItem("kubernetes", "api.tls.verification", "compatibility-skip-validation")
            ])
        ]);

        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: false);

        Assert.Contains(report.SecurityWarnings, warning => warning.Code == "KUBERNETES_TLS_VALIDATION_SKIPPED");
    }

    private sealed class FixedProbe(string id, IReadOnlyList<EvidenceItem> evidence) : IProbe
    {
        public string Id => id;

        public Task<ProbeResult> ExecuteAsync(ProbeContext context)
            => Task.FromResult(new ProbeResult(id, ProbeOutcome.Success, evidence));
    }

    private sealed class CoordinatedProbe(
        string id,
        TaskCompletionSource<bool> allStarted,
        Func<int> signalStarted,
        int expectedStartedCount) : IProbe
    {
        public string Id => id;

        public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
        {
            if (signalStarted() == expectedStartedCount)
            {
                allStarted.TrySetResult(true);
            }

            await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(1), context.CancellationToken);
            return new ProbeResult(id, ProbeOutcome.Success, []);
        }
    }
}
