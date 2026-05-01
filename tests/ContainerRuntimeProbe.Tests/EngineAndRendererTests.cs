using ContainerRuntimeProbe.Rendering;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using System.Threading;
using ContainerRuntimeProbe.Internal;

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

        Assert.Contains("## Key Findings", markdown);
        Assert.Contains("Trusted platform siemens-ied-runtime is verified via local-runtime-tls-binding at verification level 4.", markdown);
        Assert.Contains("Findings", text);
        Assert.Contains("Trusted platform siemens-ied-runtime is verified via local-runtime-tls-binding at verification level 4.", text);
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

    [Fact]
    public async Task RunAsync_RedactsSensitiveTrustedEvidence_WhenIncludeSensitiveIsFalse()
    {
        var engine = new ContainerRuntimeProbeEngine(
            [
                new FixedProbe("siemens-ied-runtime",
                [
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.auth_api_path", "/api/v1/auth"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.cert_chain_sha256", "expected-chain-hash", EvidenceSensitivity.Sensitive),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.reachable", bool.TrueString),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.status", "401"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.subject", "CN=edge-iot-core.proxy-redirect"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.issuer", "CN=Siemens Local Root"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.not_after", "2026-05-01T00:00:00.0000000+00:00"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.chain_sha256", "presented-chain-hash", EvidenceSensitivity.Sensitive),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.binding", "matched")
                ])
            ]);

        var report = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: false);

        Assert.Contains(report.Probes.SelectMany(probe => probe.Evidence), evidence => evidence.Key == "trust.ied.certsips.certificates_chain_present" && evidence.Value == bool.TrueString);
        Assert.Contains(report.Probes.SelectMany(probe => probe.Evidence), evidence => evidence.Key == "trust.ied.certsips.cert_chain_sha256" && evidence.Value == Redaction.RedactedValue);
        Assert.Contains(report.Probes.SelectMany(probe => probe.Evidence), evidence => evidence.Key == "trust.ied.endpoint.tls.chain_sha256" && evidence.Value == Redaction.RedactedValue);

        var trustedPlatform = Assert.Single(report.TrustedPlatforms!);
        Assert.Equal(4, trustedPlatform.VerificationLevel);
        Assert.Contains(trustedPlatform.Evidence, evidence => evidence.Key == "trust.ied.certsips.cert_chain_sha256" && evidence.Value == Redaction.RedactedValue);
        Assert.Contains(trustedPlatform.Evidence, evidence => evidence.Key == "trust.ied.endpoint.tls.chain_sha256" && evidence.Value == Redaction.RedactedValue);
    }

    [Fact]
    public async Task RunAsync_RedactsIdentityAnchorValues_WhenIncludeSensitiveIsFalse()
    {
        var engine = new ContainerRuntimeProbeEngine(
            [
                new FixedProbe("cloud-metadata",
                [
                    new EvidenceItem("cloud-metadata", "cloud.source", RuntimeReportedHostSource.AwsMetadata.ToString()),
                    new EvidenceItem("cloud-metadata", "aws.instance_id", "i-0abc123def4567890", EvidenceSensitivity.Sensitive)
                ])
            ]);

        var redactedReport = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: false);
        var sensitiveReport = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: true);

        var redactedAnchor = Assert.Single(redactedReport.Host.IdentityAnchors);
        var sensitiveAnchor = Assert.Single(sensitiveReport.Host.IdentityAnchors);

        Assert.Equal(Redaction.RedactedValue, redactedAnchor.Value);
        Assert.StartsWith("sha256:", sensitiveAnchor.Value, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_RedactsSiemensIdentityAnchorValues_WhenIncludeSensitiveIsFalse()
    {
        var engine = new ContainerRuntimeProbeEngine(
            [
                new FixedProbe("siemens-ied-runtime",
                [
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.cert_chain_sha256", "expected-chain-hash", EvidenceSensitivity.Sensitive),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.subject", "CN=edge-iot-core.proxy-redirect"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.issuer", "CN=Siemens Local Root"),
                    new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.binding", "matched")
                ])
            ]);

        var redactedReport = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: false);
        var sensitiveReport = await engine.RunAsync(TimeSpan.FromMilliseconds(50), includeSensitive: true);

        var redactedAnchor = Assert.Single(redactedReport.Host.IdentityAnchors.Where(anchor => anchor.Kind == IdentityAnchorKind.VendorRuntimeIdentity));
        var sensitiveAnchor = Assert.Single(sensitiveReport.Host.IdentityAnchors.Where(anchor => anchor.Kind == IdentityAnchorKind.VendorRuntimeIdentity));

        Assert.Equal(Redaction.RedactedValue, redactedAnchor.Value);
        Assert.StartsWith("sha256:", sensitiveAnchor.Value, StringComparison.Ordinal);
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
