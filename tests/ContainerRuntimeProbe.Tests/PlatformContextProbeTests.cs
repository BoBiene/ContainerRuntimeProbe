using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class PlatformContextProbeTests
{
    [Theory]
    [InlineData("iem", true)]
    [InlineData("/apps/iem-runtime", true)]
    [InlineData("medium", false)]
    [InlineData("fried", false)]
    public void PlatformSignalMatching_ContainsToken_MatchesBoundariesOnly(string value, bool expected)
    {
        Assert.Equal(expected, PlatformSignalMatching.ContainsToken(value, "iem") || PlatformSignalMatching.ContainsToken(value, "ied"));
    }

    [Fact]
    public async Task PlatformContextProbe_CollectsSignalsAndRedactsSensitiveValues()
    {
        var environment = new Dictionary<string, string?>
        {
            ["IOTEDGE_MODULEID"] = "edge-agent",
            ["SIEMENS_API_TOKEN"] = "top-secret"
        };

        var files = new Dictionary<string, (ProbeOutcome outcome, string? text, string? message)>
        {
            ["/proc/self/mountinfo"] = (ProbeOutcome.Success, "101 42 0:1 / /data/industrial-edge rw,relatime - ext4 /dev/root rw", null),
            ["/proc/1/mountinfo"] = (ProbeOutcome.Unavailable, null, null),
            ["/proc/self/cgroup"] = (ProbeOutcome.Success, "0::/system.slice/siemens-ied.service", null),
            ["/proc/1/cgroup"] = (ProbeOutcome.Unavailable, null, null),
            ["/etc/hostname"] = (ProbeOutcome.Success, "ied-edge-node", null),
            ["/proc/sys/kernel/hostname"] = (ProbeOutcome.Unavailable, null, null),
            ["/etc/resolv.conf"] = (ProbeOutcome.Success, "search corp industrial-edge.local", null),
            ["/var/run/devicemodel/edgedevice/certsips.json"] = (ProbeOutcome.Success, "{" +
                "\"auth-api-path\":\"/api/v1/auth\"," +
                "\"edge-ips\":\"10.0.0.5\"," +
                "\"edge-certificates\":{\"service-name\":\"edge-iot-core.proxy-redirect\",\"certificates-chain\":\"pem\"}}", null)
        };

        var probe = new PlatformContextProbe(
            () => environment,
            (path, _, _) => Task.FromResult(files.TryGetValue(path, out var result)
                ? result
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)));

        var result = await probe.ExecuteAsync(new ProbeContext(
            TimeSpan.FromMilliseconds(50),
            IncludeSensitive: false,
            EnabledProbes: null,
            KubernetesApiBase: null,
            AwsImdsBase: null,
            AzureImdsBase: null,
            GcpMetadataBase: null,
            OciMetadataBase: null,
            CancellationToken.None));

        Assert.Equal(ProbeOutcome.Success, result.Outcome);
        Assert.Contains(result.Evidence, item => item.Key == "env.IOTEDGE_MODULEID" && item.Value == "edge-agent");
        Assert.Contains(result.Evidence, item => item.Key == "env.SIEMENS_API_TOKEN" && item.Value == "<redacted>");
        Assert.Contains(result.Evidence, item => item.Key == "mountinfo.signal" && item.Value == "industrial-edge");
        Assert.Contains(result.Evidence, item => item.Key == "cgroup.signal" && item.Value == "siemens");
        Assert.Contains(result.Evidence, item => item.Key == "hostname.signal" && item.Value == "ied");
        Assert.Contains(result.Evidence, item => item.Key == "dns.signal" && item.Value == "industrial-edge");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.outcome" && item.Value == "Success");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.service_name" && item.Value == "edge-iot-core.proxy-redirect");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.certificates_chain_present" && item.Value == bool.TrueString);
    }

    [Fact]
    public async Task Engine_DefaultProbeList_IncludesPlatformContextProbe()
    {
        var engine = new ContainerRuntimeProbeEngine();

        Assert.Contains("platform-context", engine.ProbeIds);
        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: false);
        Assert.Contains(report.Probes, probe => probe.ProbeId == "platform-context");
    }
}