namespace ContainerRuntimeProbe.IntegrationTests;

public sealed class SmokeIntegrationTests
{
    [Fact]
    public async Task Engine_CompletesWithinTimeoutBudget()
    {
        var engine = new ContainerRuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);
        Assert.True(report.Duration < TimeSpan.FromSeconds(5));
    }
}
