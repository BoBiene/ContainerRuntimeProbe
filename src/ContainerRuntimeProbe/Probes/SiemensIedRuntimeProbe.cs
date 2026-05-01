using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal sealed record IedEndpointProbeRequest(string ServiceName, string AuthApiPath, string? CertificateChainPem, string? EdgeIps);

internal sealed record IedEndpointProbeResult(
    ProbeOutcome Outcome,
    int? StatusCode,
    string? ServerSubject,
    string? ServerIssuer,
    DateTimeOffset? ServerExpiresAt,
    string? PresentedChainSha256,
    bool TlsBindingMatched,
    string? Message = null);

internal sealed class SiemensIedRuntimeProbe : IProbe
{
    internal const string ProbeId = "siemens-ied-runtime";

    private const string CertsipsPath = "/var/run/devicemodel/edgedevice/certsips.json";

    private readonly Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> _readFileAsync;
    private readonly Func<IedEndpointProbeRequest, TimeSpan, CancellationToken, Task<IedEndpointProbeResult>> _probeIedEndpointAsync;

    public string Id => ProbeId;

    public SiemensIedRuntimeProbe()
        : this(ProbeIo.ReadFileAsync, ProbeIedEndpointAsync)
    {
    }

    internal SiemensIedRuntimeProbe(
        Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> readFileAsync,
        Func<IedEndpointProbeRequest, TimeSpan, CancellationToken, Task<IedEndpointProbeResult>>? probeIedEndpointAsync = null)
    {
        _readFileAsync = readFileAsync;
        _probeIedEndpointAsync = probeIedEndpointAsync ?? ProbeIedEndpointAsync;
    }

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();

        var (outcome, text, message) = await _readFileAsync(CertsipsPath, context.Timeout, context.CancellationToken).ConfigureAwait(false);
        if (outcome != ProbeOutcome.Success)
        {
            sw.Stop();
            return new ProbeResult(Id, outcome, [new EvidenceItem(Id, "trust.ied.certsips.outcome", outcome.ToString())], message, sw.Elapsed);
        }

        await AddIedTrustArtifactEvidenceAsync(evidence, text, context.IncludeSensitive, context.Timeout, context.CancellationToken).ConfigureAwait(false);

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence.Distinct().ToArray(), null, sw.Elapsed);
    }

    private async Task AddIedTrustArtifactEvidenceAsync(
        List<EvidenceItem> evidence,
        string? text,
        bool includeSensitive,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.outcome", ProbeOutcome.Success.ToString()));
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            var authApiPath = JsonHelper.GetString(root, "auth-api-path");
            var secureStorageApiPath = JsonHelper.GetString(root, "secure-storage-api-path");
            var edgeIps = JsonHelper.GetString(root, "edge-ips");
            var certChain = JsonHelper.GetString(root, "cert-chain");
            string? certificatesChain = null;
            string? serviceName = null;

            AddIfPresent(evidence, "trust.ied.certsips.auth_api_path", authApiPath);
            AddIfPresent(evidence, "trust.ied.certsips.secure_storage_api_path", secureStorageApiPath);
            if (!string.IsNullOrWhiteSpace(edgeIps))
            {
                AddIfPresent(evidence, "trust.ied.certsips.edge_ips", includeSensitive ? edgeIps : Redaction.RedactedValue, EvidenceSensitivity.Sensitive);
            }

            if (root.TryGetProperty("edge-certificates", out var edgeCertificates) && edgeCertificates.ValueKind == JsonValueKind.Object)
            {
                serviceName = JsonHelper.GetString(edgeCertificates, "service-name");
                AddIfPresent(evidence, "trust.ied.certsips.service_name", serviceName);
                certificatesChain = JsonHelper.GetString(edgeCertificates, "certificates-chain");
                if (!string.IsNullOrWhiteSpace(certificatesChain))
                {
                    evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
                }
            }

            if (!string.IsNullOrWhiteSpace(certChain))
            {
                evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.cert_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
            }

            var expectedChainPem = certificatesChain ?? certChain;
            if (!TryComputePemChainSha256(expectedChainPem, out var documentedChainSha256))
            {
                evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.parse_error", bool.TrueString));
                return;
            }

            if (!string.IsNullOrWhiteSpace(documentedChainSha256))
            {
                AddIfPresent(evidence, "trust.ied.certsips.cert_chain_sha256", documentedChainSha256, EvidenceSensitivity.Sensitive);
            }

            if (IsAbsoluteApiPath(authApiPath) && IsPlausibleServiceName(serviceName))
            {
                var endpointResult = await _probeIedEndpointAsync(
                    new IedEndpointProbeRequest(serviceName!, authApiPath!, expectedChainPem, edgeIps),
                    timeout,
                    cancellationToken).ConfigureAwait(false);

                evidence.Add(new EvidenceItem(Id, "trust.ied.endpoint.auth_api.outcome", endpointResult.Outcome.ToString()));
                if (endpointResult.StatusCode.HasValue)
                {
                    evidence.Add(new EvidenceItem(Id, "trust.ied.endpoint.auth_api.status", endpointResult.StatusCode.Value.ToString()));
                    evidence.Add(new EvidenceItem(Id, "trust.ied.endpoint.auth_api.reachable", bool.TrueString));
                }

                if (!string.IsNullOrWhiteSpace(endpointResult.ServerSubject))
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.tls.subject", endpointResult.ServerSubject);
                }

                if (!string.IsNullOrWhiteSpace(endpointResult.ServerIssuer))
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.tls.issuer", endpointResult.ServerIssuer);
                }

                if (endpointResult.ServerExpiresAt.HasValue)
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.tls.not_after", endpointResult.ServerExpiresAt.Value.ToString("O"));
                }

                if (!string.IsNullOrWhiteSpace(endpointResult.PresentedChainSha256))
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.tls.chain_sha256", endpointResult.PresentedChainSha256, EvidenceSensitivity.Sensitive);
                }

                if (endpointResult.StatusCode.HasValue || endpointResult.Outcome == ProbeOutcome.Success)
                {
                    evidence.Add(new EvidenceItem(
                        Id,
                        "trust.ied.endpoint.tls.binding",
                        endpointResult.TlsBindingMatched ? "matched" : "mismatched"));
                }

                if (!string.IsNullOrWhiteSpace(endpointResult.Message))
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.auth_api.message", endpointResult.Message);
                }
            }
        }
        catch (JsonException)
        {
            evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.parse_error", bool.TrueString));
        }
    }

    private static void AddIfPresent(List<EvidenceItem> evidence, string key, string? value, EvidenceSensitivity sensitivity = EvidenceSensitivity.Public)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem(ProbeId, key, value.Trim(), sensitivity));
        }
    }

    private static async Task<IedEndpointProbeResult> ProbeIedEndpointAsync(
        IedEndpointProbeRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        string? serverSubject = null;
        string? serverIssuer = null;
        DateTimeOffset? serverExpiresAt = null;
        IReadOnlyList<byte[]> presentedCertificates = [];

        var (resolutionOutcome, candidateAddresses, resolutionMessage) = await ResolveCandidateAddressesAsync(request, cancellationToken).ConfigureAwait(false);
        if (resolutionOutcome != ProbeOutcome.Success)
        {
            return new IedEndpointProbeResult(resolutionOutcome, null, null, null, null, null, false, resolutionMessage);
        }

        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = (context, ct) => ConnectToCandidateAddressAsync(candidateAddresses, context.DnsEndPoint.Port, ct),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, _) =>
                {
                    CaptureServerCertificate(certificate, out serverSubject, out serverIssuer, out serverExpiresAt);
                    presentedCertificates = CopyPresentedCertificates(certificate, chain);
                    return true;
                }
            }
        };

        try
        {
            using var client = new HttpClient(handler)
            {
                BaseAddress = new Uri($"https://{request.ServiceName}", UriKind.Absolute),
                Timeout = timeout
            };

            using var response = await client.GetAsync(request.AuthApiPath, cancellationToken).ConfigureAwait(false);
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, presentedCertificates);
            return new IedEndpointProbeResult(
                ProbeOutcome.Success,
                (int)response.StatusCode,
                serverSubject,
                serverIssuer,
                serverExpiresAt,
                ComputePresentedChainSha256(presentedCertificates),
                bindingMatched);
        }
        catch (OperationCanceledException ex)
        {
            return new IedEndpointProbeResult(
                ProbeOutcome.Timeout,
                null,
                serverSubject,
                serverIssuer,
                serverExpiresAt,
                ComputePresentedChainSha256(presentedCertificates),
                false,
                ex.Message);
        }
        catch (HttpRequestException ex)
        {
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, presentedCertificates);
            return new IedEndpointProbeResult(
                ProbeOutcome.Unavailable,
                null,
                serverSubject,
                serverIssuer,
                serverExpiresAt,
                ComputePresentedChainSha256(presentedCertificates),
                bindingMatched,
                ex.Message);
        }
        catch (Exception ex)
        {
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, presentedCertificates);
            return new IedEndpointProbeResult(
                ProbeOutcome.Error,
                null,
                serverSubject,
                serverIssuer,
                serverExpiresAt,
                ComputePresentedChainSha256(presentedCertificates),
                bindingMatched,
                ex.Message);
        }
    }

    internal static IReadOnlyList<IPAddress> SelectCandidateAddresses(IReadOnlyList<IPAddress> resolvedAddresses, IReadOnlyList<IPAddress> documentedEdgeIps)
    {
        var localResolved = resolvedAddresses
            .Where(IsLocalAddress)
            .DistinctBy(NormalizeIpAddress)
            .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ThenBy(address => NormalizeIpAddress(address), StringComparer.Ordinal)
            .ToArray();
        if (localResolved.Length == 0)
        {
            return [];
        }

        var documentedLocalSet = documentedEdgeIps
            .Where(IsLocalAddress)
            .Select(NormalizeIpAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (documentedLocalSet.Count == 0)
        {
            return localResolved;
        }

        return localResolved
            .Where(address => documentedLocalSet.Contains(NormalizeIpAddress(address)))
            .ToArray();
    }

    internal static bool MatchesExpectedCertificate(string? pemChain, IReadOnlyList<byte[]> presentedCertificates)
    {
        if (string.IsNullOrWhiteSpace(pemChain) || presentedCertificates.Count == 0)
        {
            return false;
        }

        if (!TryExtractPemCertificateBytes(pemChain, out var expectedCertificates))
        {
            return false;
        }

        if (expectedCertificates.Count == 0)
        {
            return false;
        }

        return expectedCertificates[0].AsSpan().SequenceEqual(presentedCertificates[0]);
    }

    private static bool TryComputePemChainSha256(string? pemChain, out string? sha256)
    {
        sha256 = null;
        if (string.IsNullOrWhiteSpace(pemChain))
        {
            return true;
        }

        if (!TryExtractPemCertificateBytes(pemChain, out var certificates))
        {
            return false;
        }

        if (certificates.Count == 0)
        {
            return true;
        }

        sha256 = ComputeChainSha256(certificates);
        return true;
    }

    private static bool TryExtractPemCertificateBytes(string pemChain, out IReadOnlyList<byte[]> certificateBytes)
    {
        try
        {
            certificateBytes = Regex.Matches(pemChain, "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline)
                .Select(match => match.Value)
                .Select(static pem =>
                {
                    using var certificate = X509Certificate2.CreateFromPem(pem);
                    return certificate.RawData.ToArray();
                })
                .ToArray();
            return true;
        }
        catch (CryptographicException)
        {
            certificateBytes = [];
            return false;
        }
        catch (ArgumentException)
        {
            certificateBytes = [];
            return false;
        }
    }

    private static string? ComputePresentedChainSha256(IReadOnlyList<byte[]> presentedCertificates)
        => presentedCertificates.Count == 0 ? null : ComputeChainSha256(presentedCertificates);

    private static async Task<(ProbeOutcome outcome, IReadOnlyList<IPAddress> candidateAddresses, string? message)> ResolveCandidateAddressesAsync(
        IedEndpointProbeRequest request,
        CancellationToken cancellationToken)
    {
        IPAddress[] resolvedAddresses;
        try
        {
            resolvedAddresses = await Dns.GetHostAddressesAsync(request.ServiceName, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            return (ProbeOutcome.Unavailable, [], ex.Message);
        }
        catch (ArgumentException ex)
        {
            return (ProbeOutcome.Unavailable, [], ex.Message);
        }

        var documentedEdgeIps = ParseDocumentedEdgeIps(request.EdgeIps);
        var candidateAddresses = SelectCandidateAddresses(resolvedAddresses, documentedEdgeIps);
        if (candidateAddresses.Count > 0)
        {
            return (ProbeOutcome.Success, candidateAddresses, null);
        }

        var message = documentedEdgeIps.Count > 0
            ? "Service name did not resolve to a documented local edge IP."
            : "Service name did not resolve to a local private, loopback, or link-local address.";
        return (ProbeOutcome.Unavailable, [], message);
    }

    private static IReadOnlyList<IPAddress> ParseDocumentedEdgeIps(string? edgeIps)
    {
        if (string.IsNullOrWhiteSpace(edgeIps))
        {
            return [];
        }

        var addresses = new List<IPAddress>();
        foreach (var token in Regex.Split(edgeIps, "[,;\\s]+", RegexOptions.CultureInvariant))
        {
            var candidate = token.Trim().Trim('"', '\'', '[', ']');
            if (!string.IsNullOrWhiteSpace(candidate) && IPAddress.TryParse(candidate, out var address))
            {
                addresses.Add(address);
            }
        }

        return addresses
            .DistinctBy(NormalizeIpAddress)
            .ToArray();
    }

    private static bool IsLocalAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.Equals(IPAddress.IPv6Loopback))
            {
                return true;
            }

            var bytes = address.GetAddressBytes();
            return (bytes[0] & 0xfe) == 0xfc;
        }

        return false;
    }

    private static string NormalizeIpAddress(IPAddress address)
        => address.MapToIPv6().ToString();

    private static async ValueTask<Stream> ConnectToCandidateAddressAsync(IReadOnlyList<IPAddress> candidateAddresses, int port, CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        foreach (var address in candidateAddresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex)
            {
                lastError = ex;
                socket.Dispose();
            }
        }

        throw lastError ?? new SocketException((int)SocketError.HostUnreachable);
    }

    private static void CaptureServerCertificate(
        X509Certificate? certificate,
        out string? subject,
        out string? issuer,
        out DateTimeOffset? expiresAt)
    {
        subject = null;
        issuer = null;
        expiresAt = null;

        if (certificate is null)
        {
            return;
        }

        if (certificate is X509Certificate2 x509Certificate)
        {
            subject = x509Certificate.Subject;
            issuer = x509Certificate.Issuer;
            expiresAt = new DateTimeOffset(x509Certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            return;
        }

        using var converted = new X509Certificate2(certificate);
        subject = converted.Subject;
        issuer = converted.Issuer;
        expiresAt = new DateTimeOffset(converted.NotAfter.ToUniversalTime(), TimeSpan.Zero);
    }

    private static IReadOnlyList<byte[]> CopyPresentedCertificates(X509Certificate? certificate, X509Chain? chain)
    {
        if (chain is not null && chain.ChainElements.Count > 0)
        {
            return chain.ChainElements
                .Cast<X509ChainElement>()
                .Select(element => element.Certificate.RawData.ToArray())
                .ToArray();
        }

        if (certificate is null)
        {
            return [];
        }

        if (certificate is X509Certificate2 x509Certificate)
        {
            return [x509Certificate.RawData.ToArray()];
        }

        using var converted = new X509Certificate2(certificate);
        return [converted.RawData.ToArray()];
    }

    private static string ComputeChainSha256(IEnumerable<byte[]> certificateBytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var rawData in certificateBytes)
        {
            hash.AppendData(rawData);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static bool IsAbsoluteApiPath(string? path)
        => !string.IsNullOrWhiteSpace(path)
           && path.StartsWith("/", StringComparison.Ordinal)
           && path.Length > 1;

    private static bool IsPlausibleServiceName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsWhiteSpace))
        {
            return false;
        }

        return value.All(character => char.IsLetterOrDigit(character) || character is '-' or '.');
    }
}