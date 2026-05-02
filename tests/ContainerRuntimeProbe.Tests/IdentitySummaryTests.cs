using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class IdentitySummaryTests
{
    [Fact]
    public void GetIdentitySummary_GroupsAnchorsByScope()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.CloudInstanceIdentity, "CRP-CLOUD-INSTANCE-v1", "sha256:host", IdentityAnchorScope.Host, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["cloud.instance"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.KubernetesNodeIdentity, "CRP-K8S-NODE-v1", "sha256:node", IdentityAnchorScope.Host, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["kubernetes.node.uid"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.ContainerRuntimeIdentity, "CRP-CONTAINER-INSTANCE-v1", "sha256:container", IdentityAnchorScope.Workload, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Sensitive, ["container.id"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.VendorRuntimeIdentity, "CRP-SIEMENS-IED-v1", "sha256:platform", IdentityAnchorScope.Platform, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["trust.ied.certsips.cert_chain_sha256"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var workloadSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.WorkloadIdentity));
        Assert.Contains(workloadSection.Facts, fact => fact.Label == "Container ID" && fact.Value == "sha256:container" && fact.Level == 2);

        var nodePlatformSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.NodePlatformIdentity));
        Assert.Contains(nodePlatformSection.Facts, fact => fact.Label == "Node ID" && fact.Value == "sha256:node" && fact.Level == 3);
        Assert.Contains(nodePlatformSection.Facts, fact => fact.Label == "Platform ID" && fact.Value == "sha256:platform" && fact.Level == 3);

        var hostSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.HostIdentity));
        Assert.Contains(hostSection.Facts, fact => fact.Label == "Cloud Host ID" && fact.Value == "sha256:host" && fact.Level == 3);
    }

    [Fact]
    public void GetIdentitySummary_UsesTrustedPlatformVerificationLevel_ForCorroboratedPlatformIdentity()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.VendorRuntimeIdentity, "CRP-SIEMENS-IED-v1", "sha256:platform", IdentityAnchorScope.Platform, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["trust.ied.certsips.cert_chain_sha256"], [], [])
                ]
            },
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

        var summary = report.GetIdentitySummary();

        var nodePlatformSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.NodePlatformIdentity));
        Assert.Contains(nodePlatformSection.Facts, fact => fact.Label == "Platform ID" && fact.Level == 4);
    }
}