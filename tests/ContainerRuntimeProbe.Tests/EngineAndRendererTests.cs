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
        var coordinator = new ParallelProbeCoordinator(expectedStarts: 3);
        var engine = new ContainerRuntimeProbeEngine(
        [
            new CoordinatedProbe("first", coordinator),
            new CoordinatedProbe("second", coordinator),
            new CoordinatedProbe("third", coordinator)
        ]);

        var runTask = engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);

        await coordinator.AllStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        coordinator.Release.TrySetResult();

        var report = await runTask;

        Assert.Equal(3, report.Probes.Count);
        Assert.Equal(3, coordinator.StartedCount);
    }

    private sealed class CoordinatedProbe(string id, ParallelProbeCoordinator coordinator) : IProbe
    {
        public string Id => id;

        public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
        {
            coordinator.SignalStarted();
            await coordinator.Release.Task.WaitAsync(context.CancellationToken);
            return new ProbeResult(id, ProbeOutcome.Success, []);
        }
    }

    private sealed class ParallelProbeCoordinator(int expectedStarts)
    {
        private int _startedCount;

        public TaskCompletionSource AllStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int StartedCount => _startedCount;

        public void SignalStarted()
        {
            if (Interlocked.Increment(ref _startedCount) == expectedStarts)
            {
                AllStarted.TrySetResult();
            }
        }
    }
}
