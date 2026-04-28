using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

/// <summary>Unit tests for SecuritySandboxProbe evidence parsing and probe listing.</summary>
public sealed class SecuritySandboxProbeTests
{
    // The probe reads live system files so most tests run against the live system.
    // We validate key structural properties rather than exact values.

    [Fact]
    public async Task SecuritySandboxProbe_HasExpectedProbeId()
    {
        var probe = new SecuritySandboxProbe();
        Assert.Equal("security-sandbox", probe.Id);
    }

    [Fact]
    public async Task SecuritySandboxProbe_ReturnsProbeResult_WithExpectedOutcome()
    {
        var probe = new SecuritySandboxProbe();
        var ctx = new ProbeContext(TimeSpan.FromSeconds(2), false, null, null, null, null, null, null, CancellationToken.None);

        var result = await probe.ExecuteAsync(ctx);

        // Should always succeed (all failures are mapped into evidence values, not thrown)
        Assert.Equal(ProbeOutcome.Success, result.Outcome);
        Assert.Equal("security-sandbox", result.ProbeId);
    }

    [Fact]
    public async Task SecuritySandboxProbe_EmitsStatusOutcomeEvidence()
    {
        var probe = new SecuritySandboxProbe();
        var ctx = new ProbeContext(TimeSpan.FromSeconds(2), false, null, null, null, null, null, null, CancellationToken.None);

        var result = await probe.ExecuteAsync(ctx);

        // proc.self.status.outcome must always be present
        Assert.Contains(result.Evidence, e => e.Key == "proc.self.status.outcome");
    }

    [Fact]
    public async Task SecuritySandboxProbe_EmitsSelinuxMountEvidence()
    {
        var probe = new SecuritySandboxProbe();
        var ctx = new ProbeContext(TimeSpan.FromSeconds(2), false, null, null, null, null, null, null, CancellationToken.None);

        var result = await probe.ExecuteAsync(ctx);

        // selinux.mount.present must always be present (True or False)
        var item = result.Evidence.FirstOrDefault(e => e.Key == "selinux.mount.present");
        Assert.NotNull(item);
        Assert.True(item.Value is "True" or "False");
    }

    [Fact]
    public async Task SecuritySandboxProbe_OnLinuxWithProcStatus_HasSecurityFields()
    {
        // This test is Linux-only; on /proc-less systems the outcome will be Unavailable
        if (!OperatingSystem.IsLinux()) return;

        var probe = new SecuritySandboxProbe();
        var ctx = new ProbeContext(TimeSpan.FromSeconds(2), false, null, null, null, null, null, null, CancellationToken.None);

        var result = await probe.ExecuteAsync(ctx);
        var statusOutcome = result.Evidence.FirstOrDefault(e => e.Key == "proc.self.status.outcome")?.Value;

        if (statusOutcome == "Success")
        {
            // On Linux with /proc, at least one of the known fields should be present
            var hasAnyField = result.Evidence.Any(e =>
                e.Key is "status.Seccomp" or "status.NoNewPrivs" or "status.CapEff" or "status.CapBnd" or "status.CapPrm");
            Assert.True(hasAnyField, "Expected at least one security status field from /proc/self/status");
        }
        // If /proc/self/status is unavailable or access denied, the test still passes
        // since the probe itself is not expected to throw.
    }

    [Fact]
    public async Task SecuritySandboxProbe_IsIncludedInDefaultProbeSet()
    {
        var engine = new RuntimeProbeEngine();
        Assert.Contains("security-sandbox", engine.ProbeIds);
    }

    [Fact]
    public async Task SecuritySandboxProbe_DoesNotDuplicateStatusFields_WithProcFilesProbe()
    {
        // ProcFilesProbe no longer reads /proc/self/status; verify no overlap in a full engine run
        var engine = new RuntimeProbeEngine();
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(500), includeSensitive: false);

        // proc-files probe should not contain status.Seccomp etc.
        var procFilesEvidence = report.Probes.FirstOrDefault(p => p.ProbeId == "proc-files")?.Evidence ?? [];
        Assert.DoesNotContain(procFilesEvidence, e => e.Key.StartsWith("status."));

        // security-sandbox probe owns those keys
        var sandboxEvidence = report.Probes.FirstOrDefault(p => p.ProbeId == "security-sandbox")?.Evidence ?? [];
        Assert.Contains(sandboxEvidence, e => e.Key == "proc.self.status.outcome");
    }
}
