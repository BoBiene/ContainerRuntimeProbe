using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Rendering;

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
    public async Task JsonRenderer_ContainsClassification()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(200), includeSensitive: false);
        var json = ReportRenderer.ToJson(report);

        Assert.Contains("isContainerized", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"Host\":", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_ExecutesProbesInParallel()
    {
        var engine = new ContainerRuntimeProbeEngine(
        [
            new DelayedProbe("first", TimeSpan.FromMilliseconds(150)),
            new DelayedProbe("second", TimeSpan.FromMilliseconds(150)),
            new DelayedProbe("third", TimeSpan.FromMilliseconds(150))
        ]);

        var startedAt = DateTimeOffset.UtcNow;
        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);
        var elapsed = DateTimeOffset.UtcNow - startedAt;

        Assert.Equal(3, report.Probes.Count);
        Assert.True(elapsed < TimeSpan.FromMilliseconds(350), $"Expected parallel probe execution, but took {elapsed}.");
    }

    private sealed class DelayedProbe(string id, TimeSpan delay) : IProbe
    {
        public string Id => id;

        public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
        {
            await Task.Delay(delay, context.CancellationToken);
            return new ProbeResult(id, ProbeOutcome.Success, []);
        }
    }
}
