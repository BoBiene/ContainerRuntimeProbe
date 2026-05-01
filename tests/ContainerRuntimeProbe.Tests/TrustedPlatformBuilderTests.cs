using System.Globalization;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Classification;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

public sealed class TrustedPlatformBuilderTests
{
    [Fact]
    public void Build_NoTrustedArtifact_ReturnsEmpty()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, [])
        ]);

        Assert.Empty(summaries);
    }

    [Fact]
    public void Build_WindowsTpmPresentOnly_ReturnsClaimedLevel1()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("windows-trust", ProbeOutcome.Success, [
                new EvidenceItem("windows-trust", "trust.windows.tpm.outcome", "Success")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal("windows-host-tpm", summary.PlatformKey);
        Assert.Equal(TrustedPlatformState.Claimed, summary.State);
        Assert.Equal(1, summary.VerificationLevel);
        Assert.Contains(summary.Claims, claim => claim.Type == "windows-host-tpm" && claim.Value == "device-present");
        Assert.Contains(summary.Warnings, warning => warning.Contains("does not attest", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_ContainerTpmVisibility_ReturnsClaimedLevel1()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("proc-files", ProbeOutcome.Success, [
                new EvidenceItem("proc-files", "device.tpm.path", "/dev/tpm0"),
                new EvidenceItem("proc-files", "device.tpm.path", "/dev/vtpmx")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal("container-tpm-visible", summary.PlatformKey);
        Assert.Equal(TrustedPlatformState.Claimed, summary.State);
        Assert.Equal(1, summary.VerificationLevel);
        Assert.Equal("local-device-node", summary.VerificationMethod);
        Assert.Contains(summary.Claims, claim => claim.Type == "container-tpm-visible" && claim.Value == "device-node-visible");
        Assert.Contains(summary.Claims, claim => claim.Type == "container-vtpm-visible" && claim.Value == "virtual-device-node-visible");
        Assert.Contains(summary.Evidence, item => item.SourceType == TrustedPlatformSourceType.LocalDeviceNode && item.Value == "/dev/tpm0");
        Assert.Contains(summary.Warnings, warning => warning.Contains("do not prove host identity", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_WindowsTpmWithPlausibleDeviceInfo_ReturnsClaimedLevel2()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("windows-trust", ProbeOutcome.Success, [
                new EvidenceItem("windows-trust", "trust.windows.tpm.outcome", "Success"),
                new EvidenceItem("windows-trust", "trust.windows.tpm.version", "2.0"),
                new EvidenceItem("windows-trust", "trust.windows.tpm.interface_type", "3"),
                new EvidenceItem("windows-trust", "trust.windows.tpm.implementation_revision", "0x00010002")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal("windows-host-tpm", summary.PlatformKey);
        Assert.Equal(TrustedPlatformState.Claimed, summary.State);
        Assert.Equal(2, summary.VerificationLevel);
        Assert.Equal("local-tbs-device-info", summary.VerificationMethod);
        Assert.Contains(summary.Claims, claim => claim.Type == "windows-host-tpm" && claim.Value == "device-info-validated");
        Assert.Contains(summary.Evidence, item => item.SourceType == TrustedPlatformSourceType.LocalHardwareApi && item.Key == "trust.windows.tpm.version");
    }

    [Fact]
    public void Build_CertsIpsPresentOnly_ReturnsClaimedLevel1()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, [
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal("siemens-ied-runtime", summary.PlatformKey);
        Assert.Equal(TrustedPlatformState.Claimed, summary.State);
        Assert.Equal(1, summary.VerificationLevel);
        Assert.Contains(summary.Claims, claim => claim.Type == "siemens-ied-runtime" && claim.Value == "artifact-present");
        Assert.Contains(summary.Warnings, warning => warning.Contains("plausibility", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_ValidPlausibleArtifact_ReturnsClaimedLevel2()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, [
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.auth_api_path", "/api/v1/auth"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.secure_storage_api_path", "/api/v1/storage"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive)
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(TrustedPlatformState.Claimed, summary.State);
        Assert.Equal(2, summary.VerificationLevel);
        Assert.Equal("edge-iot-core.proxy-redirect", summary.Subject);
        Assert.DoesNotContain(summary.Warnings, warning => warning.Contains("plausibility", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(summary.Evidence, item => item.Key == "trust.ied.certsips.service_name");
        Assert.Contains(summary.Evidence, item => item.Key == "trust.ied.certsips.certificates_chain_present");
        Assert.DoesNotContain(summary.Evidence, item => item.Key == "trust.ied.certsips.certificate_chain");
        Assert.Contains(summary.Claims, claim => claim.Type == "local-service-name");
    }

    [Fact]
    public void Build_ReachableEndpoint_RaisesTrustedLevelTo3()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, [
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.auth_api_path", "/api/v1/auth"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.reachable", bool.TrueString),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.status", "401")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(TrustedPlatformState.Verified, summary.State);
        Assert.Equal(3, summary.VerificationLevel);
        Assert.Equal("local-runtime-endpoint", summary.VerificationMethod);
        Assert.Contains(summary.Claims, claim => claim.Value == "endpoint-verified");
    }

    [Fact]
    public void Build_TlsBinding_RaisesTrustedLevelTo4()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("siemens-ied-runtime", ProbeOutcome.Success, [
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.outcome", "Success"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.auth_api_path", "/api/v1/auth"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.service_name", "edge-iot-core.proxy-redirect"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.certsips.cert_chain_sha256", "abc123"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.reachable", bool.TrueString),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.auth_api.status", "401"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.subject", "CN=edge-iot-core.proxy-redirect"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.issuer", "CN=Siemens Local Root"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.not_after", "2026-05-01T00:00:00.0000000+00:00"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.chain_sha256", "abc123"),
                new EvidenceItem("siemens-ied-runtime", "trust.ied.endpoint.tls.binding", "matched")
            ])
        ]);

        var summary = Assert.Single(summaries);
        Assert.Equal(TrustedPlatformState.Verified, summary.State);
        Assert.Equal(4, summary.VerificationLevel);
        Assert.Equal("local-runtime-tls-binding", summary.VerificationMethod);
        Assert.Equal("CN=Siemens Local Root", summary.Issuer);
        Assert.Equal(DateTimeOffset.Parse("2026-05-01T00:00:00.0000000+00:00", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind), summary.ExpiresAt);
        Assert.Contains(summary.Claims, claim => claim.Value == "tls-bound");
        Assert.Contains(summary.Evidence, item => item.Key == "trust.ied.endpoint.tls.binding");
        Assert.Contains(summary.Evidence, item => item.Key == "trust.ied.endpoint.tls.chain_sha256" && item.Value == "abc123");
    }

    [Fact]
    public void Build_GenericSignals_DoNotBecomeTrusted()
    {
        var summaries = TrustedPlatformBuilder.Build([
            new ProbeResult("platform-context", ProbeOutcome.Success, [
                new EvidenceItem("platform-context", "mountinfo.signal", "industrial-edge"),
                new EvidenceItem("platform-context", "dns.signal", "industrial-edge")
            ])
        ]);

        Assert.Empty(summaries);
    }
}