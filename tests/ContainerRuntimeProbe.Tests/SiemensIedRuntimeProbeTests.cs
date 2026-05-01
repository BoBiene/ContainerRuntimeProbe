using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class SiemensIedRuntimeProbeTests
{
    [Fact]
    public async Task SiemensIedRuntimeProbe_CollectsTrustArtifactEvidence()
    {
        var files = new Dictionary<string, (ProbeOutcome outcome, string? text, string? message)>
        {
            ["/var/run/devicemodel/edgedevice/certsips.json"] = (ProbeOutcome.Success, "{" +
                "\"auth-api-path\":\"/api/v1/auth\"," +
                "\"edge-ips\":\"10.0.0.5\"," +
                "\"edge-certificates\":{\"service-name\":\"edge-iot-core.proxy-redirect\",\"certificates-chain\":\"pem\"}}", null)
        };

        var probe = new SiemensIedRuntimeProbe(
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
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.outcome" && item.Value == "Success");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.service_name" && item.Value == "edge-iot-core.proxy-redirect");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.certificates_chain_present" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.edge_ips" && item.Value == Redaction.RedactedValue);
    }

    [Fact]
    public async Task SiemensIedRuntimeProbe_MissingEdgeIps_DoesNotEmitRedactedPlaceholder()
    {
        var files = new Dictionary<string, (ProbeOutcome outcome, string? text, string? message)>
        {
            ["/var/run/devicemodel/edgedevice/certsips.json"] = (ProbeOutcome.Success, "{" +
                "\"auth-api-path\":\"/api/v1/auth\"," +
                "\"edge-certificates\":{\"service-name\":\"edge-iot-core.proxy-redirect\",\"certificates-chain\":\"pem\"}}", null)
        };

        var probe = new SiemensIedRuntimeProbe(
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

        Assert.DoesNotContain(result.Evidence, item => item.Key == "trust.ied.certsips.edge_ips");
    }

    [Fact]
    public async Task SiemensIedRuntimeProbe_MalformedCertificateChain_RecordsParseErrorWithoutFailingProbe()
    {
        var files = new Dictionary<string, (ProbeOutcome outcome, string? text, string? message)>
        {
            ["/var/run/devicemodel/edgedevice/certsips.json"] = (ProbeOutcome.Success, "{" +
                "\"auth-api-path\":\"/api/v1/auth\"," +
                "\"edge-certificates\":{\"service-name\":\"edge-iot-core.proxy-redirect\",\"certificates-chain\":" +
                JsonSerializer.Serialize("-----BEGIN CERTIFICATE-----invalid-----END CERTIFICATE-----") + "}}", null)
        };

        var probe = new SiemensIedRuntimeProbe(
            (path, _, _) => Task.FromResult(files.TryGetValue(path, out var result)
                ? result
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)),
            (_, _, _) => throw new InvalidOperationException("Endpoint probing should not run when PEM parsing fails."));

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
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.parse_error" && item.Value == bool.TrueString);
        Assert.DoesNotContain(result.Evidence, item => item.Key == "trust.ied.endpoint.auth_api.outcome");
    }

    [Fact]
    public void SiemensIedRuntimeProbe_SelectCandidateAddresses_RequiresLocalResolutionAndDocumentedEdgeIpMatch()
    {
        var selected = SiemensIedRuntimeProbe.SelectCandidateAddresses(
            [IPAddress.Parse("127.0.0.1"), IPAddress.Parse("203.0.113.10")],
            [IPAddress.Parse("127.0.0.1"), IPAddress.Parse("8.8.8.8")]);

        var address = Assert.Single(selected);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), address);
    }

    [Fact]
    public void SiemensIedRuntimeProbe_SelectCandidateAddresses_RejectsPublicOnlyResolution()
    {
        var selected = SiemensIedRuntimeProbe.SelectCandidateAddresses(
            [IPAddress.Parse("203.0.113.10")],
            []);

        Assert.Empty(selected);
    }

    [Fact]
    public void SiemensIedRuntimeProbe_MatchesExpectedCertificate_RequiresLeafMatch()
    {
        var expectedLeafPem = CreateSelfSignedPemCertificate("CN=expected-leaf");
        var sharedRootPem = CreateSelfSignedPemCertificate("CN=shared-root");
        using var sharedRootCertificate = X509Certificate2.CreateFromPem(sharedRootPem);

        var matched = SiemensIedRuntimeProbe.MatchesExpectedCertificate(
            expectedLeafPem + Environment.NewLine + sharedRootPem,
            [sharedRootCertificate.RawData.ToArray()]);

        Assert.False(matched);
    }

    [Fact]
    public async Task SiemensIedRuntimeProbe_CollectsEndpointAndTlsTrustEvidence()
    {
        var certificate = CreateSelfSignedPemCertificate();
        using var parsedCertificate = X509Certificate2.CreateFromPem(certificate);
        var expectedChainSha256 = ComputeCertificateChainSha256(parsedCertificate);
        var certificateNotAfter = parsedCertificate.NotAfter.ToUniversalTime();
        var files = new Dictionary<string, (ProbeOutcome outcome, string? text, string? message)>
        {
            ["/var/run/devicemodel/edgedevice/certsips.json"] = (ProbeOutcome.Success, "{" +
                "\"auth-api-path\":\"/api/v1/auth\"," +
                "\"edge-certificates\":{\"service-name\":\"edge-iot-core.proxy-redirect\",\"certificates-chain\":" +
                JsonSerializer.Serialize(certificate) + "}}", null)
        };

        var probe = new SiemensIedRuntimeProbe(
            (path, _, _) => Task.FromResult(files.TryGetValue(path, out var result)
                ? result
                : (ProbeOutcome.Unavailable, (string?)null, (string?)null)),
            (_, _, _) => Task.FromResult(new IedEndpointProbeResult(
                ProbeOutcome.Success,
                401,
                "CN=edge-iot-core.proxy-redirect",
                "CN=Siemens Local Root",
                new DateTimeOffset(certificateNotAfter, TimeSpan.Zero),
                expectedChainSha256,
                true)));

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

        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.auth_api.reachable" && item.Value == bool.TrueString);
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.auth_api.status" && item.Value == "401");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.tls.subject" && item.Value == "CN=edge-iot-core.proxy-redirect");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.tls.issuer" && item.Value == "CN=Siemens Local Root");
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.tls.not_after" && item.Value == new DateTimeOffset(certificateNotAfter, TimeSpan.Zero).ToString("O"));
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.certsips.cert_chain_sha256" && item.Value == expectedChainSha256);
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.tls.chain_sha256" && item.Value == expectedChainSha256);
        Assert.Contains(result.Evidence, item => item.Key == "trust.ied.endpoint.tls.binding" && item.Value == "matched");
    }

    private static string ComputeCertificateChainSha256(X509Certificate2 certificate)
    {
        var rawData = certificate.RawData;
        return Convert.ToHexString(SHA256.HashData(rawData)).ToLowerInvariant();
    }

    private static string CreateSelfSignedPemCertificate(string subjectName = "CN=siemens")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return certificate.ExportCertificatePem();
    }
}