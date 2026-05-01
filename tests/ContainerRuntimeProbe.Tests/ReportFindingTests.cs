using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class ReportFindingTests
{
    [Fact]
    public void GetRelevantFindings_ReturnsStructuredFindingsForApiConsumers()
    {
        var report = TestReportFactory.CreateSampleReport() with
        {
            PlatformEvidence =
            [
                new PlatformEvidenceSummary(
                    "siemens-industrial-edge",
                    9,
                    PlatformEvidenceLevel.StrongHeuristic,
                    Confidence.High,
                    [new PlatformEvidenceItem(PlatformEvidenceType.ExecutionContext, "mountinfo.signal", "industrial-edge", Confidence.High, "Industrial Edge path detected")],
                    [])
            ],
            TrustedPlatforms =
            [
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

        var findings = report.GetRelevantFindings();

        var trustedFinding = Assert.Single(findings.Where(finding => finding.Kind == ReportFindingKind.TrustedPlatform));
        Assert.Equal("siemens-ied-runtime", trustedFinding.Key);
        Assert.Equal("Verified", trustedFinding.Value);
        Assert.Equal(4, trustedFinding.VerificationLevel);
        Assert.Equal("local-runtime-tls-binding", trustedFinding.Method);
        Assert.Contains("trust.ied.endpoint.tls.binding", trustedFinding.EvidenceKeys);

        var evidenceFinding = Assert.Single(findings.Where(finding => finding.Kind == ReportFindingKind.PlatformEvidence));
        Assert.Equal("siemens-industrial-edge", evidenceFinding.Key);
        Assert.Equal("StrongHeuristic", evidenceFinding.Value);
        Assert.Equal(9, evidenceFinding.Score);
        Assert.Contains("mountinfo.signal", evidenceFinding.EvidenceKeys);

        var hostFinding = Assert.Single(findings.Where(finding => finding.Kind == ReportFindingKind.HostOs));
        Assert.Equal("Ubuntu 24.04", hostFinding.Value);
        Assert.Contains("runtime-api:docker.info.operating_system", hostFinding.EvidenceKeys);
    }
}