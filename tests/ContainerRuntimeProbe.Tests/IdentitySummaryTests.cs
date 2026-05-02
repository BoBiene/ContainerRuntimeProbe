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

    [Fact]
    public void GetIdentitySummary_AddsDeploymentFingerprint_ForContainerizedVariants()
    {
        var report = TestReportFactory.CreateSampleReport();

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Deployment ID" && fact.Level == 1 && fact.Scope == SummaryScope.Deployment);
    }

    [Fact]
    public void GetIdentitySummary_KubernetesVariant_UsesEnvironmentId_ForWeakDeploymentCorrelation()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Classification = baseReport.Classification with
            {
                Orchestrator = new ClassificationResult<OrchestratorKind>(OrchestratorKind.Kubernetes, Confidence.High, []),
                PlatformVendor = new ClassificationResult<PlatformVendorKind>(PlatformVendorKind.Unknown, Confidence.Unknown, [])
            },
            Host = baseReport.Host with
            {
                IdentityAnchors = []
            }
        };

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Environment ID" && fact.Level == 1 && fact.Scope == SummaryScope.Platform);
    }

    [Fact]
    public void GetIdentitySummary_KubernetesVariant_CarriesWorkloadNodeAndHostTracks()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Classification = baseReport.Classification with
            {
                Orchestrator = new ClassificationResult<OrchestratorKind>(OrchestratorKind.Kubernetes, Confidence.High, []),
                PlatformVendor = new ClassificationResult<PlatformVendorKind>(PlatformVendorKind.Unknown, Confidence.Unknown, [])
            },
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.ContainerRuntimeIdentity, "CRP-CONTAINER-INSTANCE-v1", "sha256:container", IdentityAnchorScope.Workload, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Sensitive, ["container.id"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.KubernetesNodeIdentity, "CRP-K8S-NODE-v1", "sha256:node", IdentityAnchorScope.Host, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["kubernetes.node.uid"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.CloudInstanceIdentity, "CRP-CLOUD-INSTANCE-v1", "sha256:host", IdentityAnchorScope.Host, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["cloud.instance"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        Assert.Contains(summary.Sections, section => section.Kind == IdentitySummarySectionKind.WorkloadIdentity && section.Facts.Any(fact => fact.Label == "Container ID"));
        Assert.Contains(summary.Sections, section => section.Kind == IdentitySummarySectionKind.NodePlatformIdentity && section.Facts.Any(fact => fact.Label == "Node ID"));
        Assert.Contains(summary.Sections, section => section.Kind == IdentitySummarySectionKind.HostIdentity && section.Facts.Any(fact => fact.Label == "Cloud Host ID"));
    }

    [Theory]
    [InlineData(ContainerizationKind.False, OrchestratorKind.Unknown, OperatingSystemFamily.Windows, PlatformVendorKind.Unknown, SummaryVariantKind.WindowsBare)]
    [InlineData(ContainerizationKind.True, OrchestratorKind.Unknown, OperatingSystemFamily.Unknown, PlatformVendorKind.Unknown, SummaryVariantKind.StandaloneContainer)]
    [InlineData(ContainerizationKind.True, OrchestratorKind.Unknown, OperatingSystemFamily.Unknown, PlatformVendorKind.Wago, SummaryVariantKind.IndustrialContainer)]
    [InlineData(ContainerizationKind.True, OrchestratorKind.Kubernetes, OperatingSystemFamily.Unknown, PlatformVendorKind.Unknown, SummaryVariantKind.KubernetesWorkload)]
    public void GetSummaryVariant_MapsKnownVariants(ContainerizationKind containerization, OrchestratorKind orchestrator, OperatingSystemFamily hostOsFamily, PlatformVendorKind platformVendor, SummaryVariantKind expected)
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Classification = baseReport.Classification with
            {
                IsContainerized = new ClassificationResult<ContainerizationKind>(containerization, Confidence.High, []),
                Orchestrator = new ClassificationResult<OrchestratorKind>(orchestrator, orchestrator == OrchestratorKind.Unknown ? Confidence.Unknown : Confidence.High, []),
                PlatformVendor = new ClassificationResult<PlatformVendorKind>(platformVendor, platformVendor == PlatformVendorKind.Unknown ? Confidence.Unknown : Confidence.High, [])
            },
            Host = baseReport.Host with
            {
                RuntimeReportedHostOs = baseReport.Host.RuntimeReportedHostOs with
                {
                    Family = hostOsFamily
                }
            }
        };

        Assert.Equal(expected, report.GetSummaryVariant());
    }
}