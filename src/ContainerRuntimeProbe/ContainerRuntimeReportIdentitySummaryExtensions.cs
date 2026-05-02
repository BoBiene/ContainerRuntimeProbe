using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe;

/// <summary>Builds scope-oriented identity summary facts for a normalized report.</summary>
public static partial class ContainerRuntimeReportSummaryExtensions
{
    /// <summary>Returns the compact identity summary for a normalized report.</summary>
    public static IdentitySummary GetIdentitySummary(this ContainerRuntimeReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var sections = new List<IdentitySummarySection>();
        AddIdentitySection(sections, report, IdentitySummarySectionKind.WorkloadIdentity, "Workload Identity", IsWorkloadAnchor);
        AddDeploymentIdentitySection(sections, report);
        AddIdentitySection(sections, report, IdentitySummarySectionKind.NodePlatformIdentity, "Node/Platform Identity", IsNodeOrPlatformAnchor);
        AddIdentitySection(sections, report, IdentitySummarySectionKind.HostIdentity, "Host Identity", IsHostAnchor);
        return new IdentitySummary(sections);
    }

    private static void AddDeploymentIdentitySection(List<IdentitySummarySection> sections, ContainerRuntimeReport report)
    {
        var variant = report.GetSummaryVariant();
        var anchorFacts = report.Host.IdentityAnchors
            .Where(IsDeploymentOrEnvironmentAnchor)
            .OrderByDescending(anchor => GetIdentityLevel(report, anchor))
            .Select(anchor => new SummaryFact(
                GetDeploymentLabel(anchor),
                anchor.Value,
                GetDeploymentScope(anchor),
                Level: GetIdentityLevel(report, anchor),
                Confidence: MapAnchorConfidence(anchor.Strength),
                SourceKind: anchor.Kind.ToString(),
                Usage: MapUsage(anchor.BindingSuitability),
                EvidenceKeys: anchor.EvidenceReferences))
            .ToArray();

        var facts = report.Host.DiagnosticFingerprints
            .Where(fingerprint => fingerprint.Purpose is DiagnosticFingerprintPurpose.EnvironmentCorrelation or DiagnosticFingerprintPurpose.RuntimeProfile)
            .Select(fingerprint => new SummaryFact(
                GetDeploymentFingerprintLabel(variant, fingerprint),
                fingerprint.Value,
                GetDeploymentFingerprintScope(variant, fingerprint),
                Level: 1,
                Confidence: MapFingerprintConfidence(fingerprint.UniquenessLevel),
                SourceKind: fingerprint.Algorithm,
                Usage: SummaryUsageKind.Correlation,
                EvidenceKeys: fingerprint.Components.Where(component => component.Included).Select(component => component.Name).ToArray()))
            .ToArray();

        var combinedFacts = anchorFacts.Concat(facts).ToArray();
        if (combinedFacts.Length > 0)
        {
            sections.Add(new IdentitySummarySection(IdentitySummarySectionKind.DeploymentIdentity, "Deployment / Environment Identity", combinedFacts));
        }
    }

    private static void AddIdentitySection(
        List<IdentitySummarySection> sections,
        ContainerRuntimeReport report,
        IdentitySummarySectionKind kind,
        string title,
        Func<IdentityAnchor, bool> predicate)
    {
        var facts = report.Host.IdentityAnchors
            .Where(predicate)
            .OrderByDescending(anchor => GetIdentityLevel(report, anchor))
            .ThenBy(anchor => GetIdentityLabel(anchor), StringComparer.Ordinal)
            .Select(anchor => new SummaryFact(
                GetIdentityLabel(anchor),
                anchor.Value,
                GetSummaryScope(anchor),
                Level: GetIdentityLevel(report, anchor),
                Confidence: MapAnchorConfidence(anchor.Strength),
                SourceKind: anchor.Kind.ToString(),
                Usage: MapUsage(anchor.BindingSuitability),
                EvidenceKeys: anchor.EvidenceReferences))
            .ToArray();

        if (facts.Length > 0)
        {
            sections.Add(new IdentitySummarySection(kind, title, facts));
        }
    }

    private static bool IsWorkloadAnchor(IdentityAnchor anchor)
        => anchor.Kind == IdentityAnchorKind.WorkloadProfileIdentity
           || anchor.Kind == IdentityAnchorKind.ContainerRuntimeIdentity
           || anchor.Kind == IdentityAnchorKind.ContainerDeviceAnchor
           || anchor.Scope == IdentityAnchorScope.Workload
           || anchor.Scope == IdentityAnchorScope.ContainerRuntime;

    private static bool IsDeploymentOrEnvironmentAnchor(IdentityAnchor anchor)
        => anchor.Kind == IdentityAnchorKind.DeploymentEnvironmentIdentity
           || anchor.Kind == IdentityAnchorKind.KubernetesEnvironmentIdentity
           || anchor.Kind == IdentityAnchorKind.CloudEnvironmentIdentity
           || anchor.Kind == IdentityAnchorKind.VendorRuntimeIdentity;

    private static bool IsNodeOrPlatformAnchor(IdentityAnchor anchor)
        => anchor.Kind == IdentityAnchorKind.KubernetesNodeIdentity
           || anchor.Kind == IdentityAnchorKind.HypervisorIdentity
           || ((anchor.Scope == IdentityAnchorScope.Platform || anchor.Scope == IdentityAnchorScope.Hypervisor) && !IsDeploymentOrEnvironmentAnchor(anchor));

    private static bool IsHostAnchor(IdentityAnchor anchor)
        => !IsWorkloadAnchor(anchor) && !IsNodeOrPlatformAnchor(anchor) && !IsDeploymentOrEnvironmentAnchor(anchor);

    private static string GetIdentityLabel(IdentityAnchor anchor)
        => anchor.Kind switch
        {
            IdentityAnchorKind.WorkloadProfileIdentity => "Workload ID",
            IdentityAnchorKind.ContainerRuntimeIdentity => "Container ID",
            IdentityAnchorKind.ContainerDeviceAnchor => "Runtime ID",
            IdentityAnchorKind.KubernetesNodeIdentity => "Node ID",
            IdentityAnchorKind.HypervisorIdentity => "Hypervisor ID",
            IdentityAnchorKind.CloudEnvironmentIdentity => "Environment ID",
            IdentityAnchorKind.KubernetesEnvironmentIdentity => "Environment ID",
            IdentityAnchorKind.VendorRuntimeIdentity => "Platform ID",
            IdentityAnchorKind.CloudInstanceIdentity => "Cloud Host ID",
            IdentityAnchorKind.HardwareIdentity => "Host ID",
            IdentityAnchorKind.HostProfileIdentity => "Host ID",
            _ => "Host ID"
        };

    private static SummaryScope GetSummaryScope(IdentityAnchor anchor)
        => anchor.Kind switch
        {
            IdentityAnchorKind.WorkloadProfileIdentity => SummaryScope.Workload,
            IdentityAnchorKind.ContainerRuntimeIdentity => SummaryScope.Workload,
            IdentityAnchorKind.ContainerDeviceAnchor => SummaryScope.Runtime,
            IdentityAnchorKind.KubernetesNodeIdentity => SummaryScope.Node,
            IdentityAnchorKind.HypervisorIdentity => SummaryScope.Hypervisor,
            IdentityAnchorKind.CloudEnvironmentIdentity => SummaryScope.Platform,
            IdentityAnchorKind.KubernetesEnvironmentIdentity => SummaryScope.Platform,
            IdentityAnchorKind.VendorRuntimeIdentity => SummaryScope.Platform,
            IdentityAnchorKind.CloudInstanceIdentity => SummaryScope.Host,
            IdentityAnchorKind.HardwareIdentity => SummaryScope.Host,
            IdentityAnchorKind.HostProfileIdentity => SummaryScope.Host,
            _ => anchor.Scope switch
            {
                IdentityAnchorScope.ContainerRuntime => SummaryScope.Runtime,
                IdentityAnchorScope.Workload => SummaryScope.Workload,
                IdentityAnchorScope.Hypervisor => SummaryScope.Hypervisor,
                IdentityAnchorScope.Platform => SummaryScope.Platform,
                IdentityAnchorScope.Host => SummaryScope.Host,
                _ => SummaryScope.Unknown
            }
        };

    private static int GetIdentityLevel(ContainerRuntimeReport report, IdentityAnchor anchor)
    {
        var baseLevel = anchor.Strength switch
        {
            IdentityAnchorStrength.Strong => 3,
            IdentityAnchorStrength.Medium => 2,
            IdentityAnchorStrength.Weak => 1,
            _ => 0
        };

        return Math.Max(baseLevel, GetCorroboratingLevel(report, anchor));
    }

    private static int GetCorroboratingLevel(ContainerRuntimeReport report, IdentityAnchor anchor)
    {
        string[]? platformKeys = anchor.Kind switch
        {
            IdentityAnchorKind.VendorRuntimeIdentity => ["siemens-ied-runtime"],
            IdentityAnchorKind.TpmPublicKeyDigest => ["windows-host-tpm", "container-tpm-visible"],
            IdentityAnchorKind.ContainerDeviceAnchor => ["container-tpm-visible"],
            _ => null
        };

        if (platformKeys is null || report.TrustedPlatforms is null)
        {
            return 0;
        }

        return report.TrustedPlatforms
            .Where(summary => platformKeys.Contains(summary.PlatformKey, StringComparer.Ordinal))
            .Select(summary => summary.VerificationLevel)
            .DefaultIfEmpty(0)
            .Max();
    }

    private static Confidence MapAnchorConfidence(IdentityAnchorStrength strength)
        => strength switch
        {
            IdentityAnchorStrength.Strong => Confidence.High,
            IdentityAnchorStrength.Medium => Confidence.Medium,
            IdentityAnchorStrength.Weak => Confidence.Low,
            _ => Confidence.Unknown
        };

    private static SummaryUsageKind MapUsage(BindingSuitability suitability)
        => suitability switch
        {
            BindingSuitability.Correlation => SummaryUsageKind.Correlation,
            BindingSuitability.LicenseBinding => SummaryUsageKind.BindingCandidate,
            BindingSuitability.ExternalAttestation => SummaryUsageKind.BindingCandidate,
            _ => SummaryUsageKind.Informational
        };

    private static string GetDeploymentLabel(IdentityAnchor anchor)
        => anchor.Kind switch
        {
            IdentityAnchorKind.DeploymentEnvironmentIdentity => "Deployment ID",
            IdentityAnchorKind.KubernetesEnvironmentIdentity => "Environment ID",
            IdentityAnchorKind.CloudEnvironmentIdentity => "Environment ID",
            IdentityAnchorKind.VendorRuntimeIdentity => "Platform ID",
            _ => "Deployment ID"
        };

    private static SummaryScope GetDeploymentScope(IdentityAnchor anchor)
        => anchor.Kind switch
        {
            IdentityAnchorKind.DeploymentEnvironmentIdentity => SummaryScope.Deployment,
            IdentityAnchorKind.KubernetesEnvironmentIdentity => SummaryScope.Platform,
            IdentityAnchorKind.CloudEnvironmentIdentity => SummaryScope.Platform,
            IdentityAnchorKind.VendorRuntimeIdentity => SummaryScope.Platform,
            _ => SummaryScope.Deployment
        };

    private static string GetDeploymentFingerprintLabel(SummaryVariantKind variant, DiagnosticFingerprint fingerprint)
        => fingerprint.Purpose switch
        {
            DiagnosticFingerprintPurpose.RuntimeProfile => "Runtime Profile ID",
            DiagnosticFingerprintPurpose.EnvironmentCorrelation when variant is SummaryVariantKind.KubernetesWorkload or SummaryVariantKind.IndustrialContainer => "Environment ID",
            _ => "Runtime Profile ID"
        };

    private static SummaryScope GetDeploymentFingerprintScope(SummaryVariantKind variant, DiagnosticFingerprint fingerprint)
        => fingerprint.Purpose switch
        {
            DiagnosticFingerprintPurpose.RuntimeProfile => SummaryScope.Runtime,
            DiagnosticFingerprintPurpose.EnvironmentCorrelation when variant is SummaryVariantKind.KubernetesWorkload or SummaryVariantKind.IndustrialContainer => SummaryScope.Platform,
            _ => SummaryScope.Runtime
        };

    private static int GetFingerprintLevel(DiagnosticFingerprint fingerprint)
        => fingerprint.StabilityLevel switch
        {
            DiagnosticFingerprintStabilityLevel.PlatformAnchored => 4,
            DiagnosticFingerprintStabilityLevel.ProfileStable => 3,
            DiagnosticFingerprintStabilityLevel.UpdateSensitive => 2,
            DiagnosticFingerprintStabilityLevel.Ephemeral => 1,
            _ => 0
        };

    private static Confidence MapFingerprintConfidence(DiagnosticFingerprintUniquenessLevel uniquenessLevel)
        => uniquenessLevel switch
        {
            DiagnosticFingerprintUniquenessLevel.High => Confidence.High,
            DiagnosticFingerprintUniquenessLevel.Medium => Confidence.Medium,
            DiagnosticFingerprintUniquenessLevel.Low => Confidence.Low,
            _ => Confidence.Unknown
        };
}