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
                    new IdentityAnchor(IdentityAnchorKind.WorkloadProfileIdentity, "CRP-WORKLOAD-PROFILE-v1", "sha256:workload", IdentityAnchorScope.Workload, BindingSuitability.Correlation, IdentityAnchorStrength.Weak, IdentityAnchorSensitivity.Sensitive, ["environment:HOSTNAME"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.ContainerRuntimeIdentity, "CRP-CONTAINER-INSTANCE-v1", "sha256:container", IdentityAnchorScope.Workload, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Sensitive, ["container.id"], [], []),
                    new IdentityAnchor(IdentityAnchorKind.VendorRuntimeIdentity, "CRP-SIEMENS-IED-v1", "sha256:platform", IdentityAnchorScope.Platform, BindingSuitability.LicenseBinding, IdentityAnchorStrength.Strong, IdentityAnchorSensitivity.Sensitive, ["trust.ied.certsips.cert_chain_sha256"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var workloadSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.WorkloadIdentity));
        Assert.Contains(workloadSection.Facts, fact => fact.Label == "Workload ID" && fact.Value == "sha256:workload" && fact.Level == 1);
        Assert.Contains(workloadSection.Facts, fact => fact.Label == "Container ID" && fact.Value == "sha256:container" && fact.Level == 2);

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Platform ID" && fact.Value == "sha256:platform" && fact.Level == 3);

        var nodePlatformSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.NodePlatformIdentity));
        Assert.Contains(nodePlatformSection.Facts, fact => fact.Label == "Node ID" && fact.Value == "sha256:node" && fact.Level == 3);

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

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Platform ID" && fact.Level == 4);
    }

    [Fact]
    public void GetIdentitySummary_AddsDeploymentFingerprint_ForContainerizedVariants()
    {
        var report = TestReportFactory.CreateSampleReport();

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Equal("Deployment / Environment Identity", deploymentSection.Title);
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Runtime Profile ID" && fact.Level == 1 && fact.Scope == SummaryScope.Runtime);
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
                DiagnosticFingerprints =
                [
                    baseReport.Host.DiagnosticFingerprints.Single() with
                    {
                        Purpose = DiagnosticFingerprintPurpose.EnvironmentCorrelation
                    }
                ],
                IdentityAnchors = []
            }
        };

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Environment ID" && fact.Level == 1 && fact.Scope == SummaryScope.Platform);
    }

    [Fact]
    public void GetIdentitySummary_WorkloadProfileIdentity_UsesWorkloadLabel_AndDoesNotCreateHostSection()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.WorkloadProfileIdentity, "CRP-WORKLOAD-PROFILE-v1", "sha256:workload", IdentityAnchorScope.Workload, BindingSuitability.Correlation, IdentityAnchorStrength.Weak, IdentityAnchorSensitivity.Sensitive, ["environment:HOSTNAME"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        Assert.Contains(summary.Sections, section => section.Kind == IdentitySummarySectionKind.WorkloadIdentity && section.Facts.Any(fact => fact.Label == "Workload ID" && fact.Value == "sha256:workload"));
        Assert.DoesNotContain(summary.Sections, section => section.Kind == IdentitySummarySectionKind.HostIdentity);
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

    [Fact]
    public void GetIdentitySummary_KubernetesEnvironmentAnchor_UsesEnvironmentLabelAndLevel2()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Classification = baseReport.Classification with
            {
                Orchestrator = new ClassificationResult<OrchestratorKind>(OrchestratorKind.Kubernetes, Confidence.High, [])
            },
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.KubernetesEnvironmentIdentity, "CRP-KUBERNETES-CLUSTER-CA-v1", "sha256:cluster", IdentityAnchorScope.Platform, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Public, ["kubernetes:serviceaccount.ca.sha256"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Environment ID" && fact.Value == "sha256:cluster" && fact.Level == 2 && fact.Scope == SummaryScope.Platform);
    }

    [Fact]
    public void GetIdentitySummary_StacksExplicitDeploymentAnchor_AndFingerprintFallback()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.DeploymentEnvironmentIdentity, "CRP-DEPLOYMENT-METADATA-v1", "sha256:deployment", IdentityAnchorScope.ApplicationHost, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Public, ["runtime-api:compose.label.com.docker.compose.project"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Deployment ID" && fact.Value == "sha256:deployment" && fact.Level == 2 && fact.Scope == SummaryScope.Deployment && fact.SourceKind == "DeploymentEnvironmentIdentity");
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Runtime Profile ID" && fact.Level == 1 && fact.Scope == SummaryScope.Runtime);
    }

    [Fact]
    public void GetIdentitySummary_MapsCloudEnvironmentIdentity_ToEnvironmentId()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.CloudEnvironmentIdentity, "CRP-CLOUD-ENVIRONMENT-v1", "sha256:cloud-environment", IdentityAnchorScope.Platform, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Sensitive, ["cloud-metadata:aws.account_id"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var deploymentSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.DeploymentIdentity));
        Assert.Contains(deploymentSection.Facts, fact => fact.Label == "Environment ID" && fact.Value == "sha256:cloud-environment" && fact.Level == 2 && fact.Scope == SummaryScope.Platform);
    }

    [Fact]
    public void GetIdentitySummary_MapsHypervisorIdentity_ToHypervisorId()
    {
        var baseReport = TestReportFactory.CreateSampleReport();
        var report = baseReport with
        {
            Host = baseReport.Host with
            {
                IdentityAnchors =
                [
                    new IdentityAnchor(IdentityAnchorKind.HypervisorIdentity, "CRP-HYPERVISOR-INSTANCE-v1", "sha256:hypervisor", IdentityAnchorScope.Hypervisor, BindingSuitability.Correlation, IdentityAnchorStrength.Medium, IdentityAnchorSensitivity.Sensitive, ["proc-files:dmi.product_uuid"], [], [])
                ]
            }
        };

        var summary = report.GetIdentitySummary();

        var nodePlatformSection = Assert.Single(summary.Sections.Where(section => section.Kind == IdentitySummarySectionKind.NodePlatformIdentity));
        Assert.Contains(nodePlatformSection.Facts, fact => fact.Label == "Hypervisor ID" && fact.Value == "sha256:hypervisor" && fact.Level == 2 && fact.Scope == SummaryScope.Hypervisor);
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