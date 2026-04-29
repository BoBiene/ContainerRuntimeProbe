using System.Threading;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class ProcFilesProbeTests
{
    [Fact]
    public async Task ProcFilesProbe_StartsReadsConcurrently_WhilePreservingFileProcessing()
    {
        var allStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var startedCount = 0;
        var probe = new ProcFilesProbe(
            ["/proc/version", "/proc/sys/kernel/osrelease"],
            async (_, _, cancellationToken) =>
            {
                if (Interlocked.Increment(ref startedCount) == 2)
                {
                    allStarted.TrySetResult(true);
                }

                await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(1), cancellationToken);
                return (ProbeOutcome.Unavailable, null, (string?)null);
            });

        var context = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, null, null, null, null, CancellationToken.None);
        var result = await probe.ExecuteAsync(context);

        Assert.Equal("proc-files", result.ProbeId);
        Assert.Contains(result.Evidence, item => item.Key == "/proc/version" && item.Value == ProbeOutcome.Unavailable.ToString());
        Assert.Contains(result.Evidence, item => item.Key == "/proc/sys/kernel/osrelease" && item.Value == ProbeOutcome.Unavailable.ToString());
    }
}