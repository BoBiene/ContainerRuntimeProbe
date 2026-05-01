using System.Collections;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal sealed record IedEndpointProbeRequest(string ServiceName, string AuthApiPath, string? CertificateChainPem);

internal sealed record IedEndpointProbeResult(
    ProbeOutcome Outcome,
    int? StatusCode,
    string? ServerSubject,
    bool TlsBindingMatched,
    string? Message = null);

internal sealed class PlatformContextProbe : IProbe
{
    private static readonly string[] PlatformEnvironmentPrefixes =
    [
        "SIEMENS",
        "IEM",
        "IED",
        "IE_",
        "INDUSTRIAL_EDGE",
        "INDUSTRIALEDGE",
        "IOTEDGE"
    ];

    private static readonly string[] Files =
    [
        "/proc/self/mountinfo",
        "/proc/1/mountinfo",
        "/proc/self/cgroup",
        "/proc/1/cgroup",
        "/etc/hostname",
        "/proc/sys/kernel/hostname",
        "/etc/resolv.conf",
        "/var/run/devicemodel/edgedevice/certsips.json"
    ];

    private readonly Func<IEnumerable<KeyValuePair<string, string?>>> _getEnvironment;
    private readonly Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> _readFileAsync;
    private readonly Func<IedEndpointProbeRequest, TimeSpan, CancellationToken, Task<IedEndpointProbeResult>> _probeIedEndpointAsync;

    public string Id => "platform-context";

    public PlatformContextProbe()
        : this(GetEnvironmentVariables, ProbeIo.ReadFileAsync, ProbeIedEndpointAsync)
    {
    }

    internal PlatformContextProbe(
        Func<IEnumerable<KeyValuePair<string, string?>>> getEnvironment,
        Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> readFileAsync,
        Func<IedEndpointProbeRequest, TimeSpan, CancellationToken, Task<IedEndpointProbeResult>>? probeIedEndpointAsync = null)
    {
        _getEnvironment = getEnvironment;
        _readFileAsync = readFileAsync;
        _probeIedEndpointAsync = probeIedEndpointAsync ?? ProbeIedEndpointAsync;
    }

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var outcome = ProbeOutcome.Success;
        string? message = null;

        AddEnvironmentEvidence(evidence, context);

        foreach (var file in Files)
        {
            var (fileOutcome, text, fileMessage) = await _readFileAsync(file, context.Timeout, context.CancellationToken).ConfigureAwait(false);
            if (fileOutcome != ProbeOutcome.Success)
            {
                if (fileOutcome != ProbeOutcome.Unavailable && outcome == ProbeOutcome.Success)
                {
                    outcome = fileOutcome;
                    message = fileMessage;
                }

                if (file == "/var/run/devicemodel/edgedevice/certsips.json")
                {
                    evidence.Add(new EvidenceItem(Id, "trust.ied.certsips.outcome", fileOutcome.ToString()));
                }

                continue;
            }

            switch (file)
            {
                case "/proc/self/mountinfo":
                case "/proc/1/mountinfo":
                    AddSignalEvidence(evidence, "mountinfo.signal", text, includeGenericIndustrial: false);
                    break;
                case "/proc/self/cgroup":
                case "/proc/1/cgroup":
                    AddSignalEvidence(evidence, "cgroup.signal", text, includeGenericIndustrial: false);
                    break;
                case "/etc/hostname":
                case "/proc/sys/kernel/hostname":
                    AddSignalEvidence(evidence, "hostname.signal", text, includeGenericIndustrial: false, sensitivity: EvidenceSensitivity.Sensitive);
                    break;
                case "/etc/resolv.conf":
                    foreach (var domain in Parsing.ParseResolvSearchDomains(text!))
                    {
                        foreach (var signal in PlatformSignalMatching.FindSignals(domain, includeGenericIndustrial: true))
                        {
                            evidence.Add(new EvidenceItem(Id, "dns.signal", signal));
                        }
                    }
                    break;
                case "/var/run/devicemodel/edgedevice/certsips.json":
                    await AddIedTrustArtifactEvidenceAsync(evidence, text, context.IncludeSensitive, context.Timeout, context.CancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        sw.Stop();
        return new ProbeResult(Id, outcome, evidence.Distinct().ToArray(), message, sw.Elapsed);
    }

    private void AddEnvironmentEvidence(List<EvidenceItem> evidence, ProbeContext context)
    {
        var environment = _getEnvironment().ToArray();
        var hostname = environment.FirstOrDefault(pair => string.Equals(pair.Key, "HOSTNAME", StringComparison.OrdinalIgnoreCase)).Value;
        foreach (var signal in PlatformSignalMatching.FindSignals(hostname, includeGenericIndustrial: false))
        {
            evidence.Add(new EvidenceItem(Id, "hostname.signal", signal, EvidenceSensitivity.Sensitive));
        }

        foreach (var (key, value) in environment
                     .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
                     .Where(pair => PlatformEnvironmentPrefixes.Any(prefix => pair.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))))
        {
            var sensitive = Redaction.IsSensitiveKey(key) || key.Equals("HOSTNAME", StringComparison.OrdinalIgnoreCase);
            var redactedValue = sensitive ? Redaction.MaybeRedact(key, value, context.IncludeSensitive) : value?.Trim();
            evidence.Add(new EvidenceItem(Id, $"env.{key}", redactedValue, sensitive ? EvidenceSensitivity.Sensitive : EvidenceSensitivity.Public));

            foreach (var signal in PlatformSignalMatching.FindSignalsFromEnvironmentKey(key))
            {
                evidence.Add(new EvidenceItem(Id, "env.signal", signal));
            }

            foreach (var signal in PlatformSignalMatching.FindSignals(value, includeGenericIndustrial: false))
            {
                evidence.Add(new EvidenceItem(Id, "env.signal", signal));
            }
        }
    }

    private static void AddSignalEvidence(
        List<EvidenceItem> evidence,
        string key,
        string? text,
        bool includeGenericIndustrial,
        EvidenceSensitivity sensitivity = EvidenceSensitivity.Public)
    {
        foreach (var signal in PlatformSignalMatching.FindSignals(text, includeGenericIndustrial))
        {
            evidence.Add(new EvidenceItem("platform-context", key, signal, sensitivity));
        }
    }

    private async Task AddIedTrustArtifactEvidenceAsync(
        List<EvidenceItem> evidence,
        string? text,
        bool includeSensitive,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.outcome", ProbeOutcome.Success.ToString()));
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
            var certificatesChain = default(string);
            var serviceName = default(string);

            AddIfPresent(evidence, "trust.ied.certsips.auth_api_path", authApiPath);
            AddIfPresent(evidence, "trust.ied.certsips.secure_storage_api_path", secureStorageApiPath);
            AddIfPresent(evidence, "trust.ied.certsips.edge_ips", includeSensitive ? edgeIps : "<redacted>", EvidenceSensitivity.Sensitive);

            if (root.TryGetProperty("edge-certificates", out var edgeCertificates) && edgeCertificates.ValueKind == JsonValueKind.Object)
            {
                serviceName = JsonHelper.GetString(edgeCertificates, "service-name");
                AddIfPresent(evidence, "trust.ied.certsips.service_name", serviceName);
                certificatesChain = JsonHelper.GetString(edgeCertificates, "certificates-chain");
                if (!string.IsNullOrWhiteSpace(certificatesChain))
                {
                    evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
                }
            }

            if (!string.IsNullOrWhiteSpace(certChain))
            {
                evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.cert_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
            }

            if (IsAbsoluteApiPath(authApiPath) && IsPlausibleServiceName(serviceName))
            {
                var endpointResult = await _probeIedEndpointAsync(
                    new IedEndpointProbeRequest(serviceName!, authApiPath!, certificatesChain ?? certChain),
                    timeout,
                    cancellationToken).ConfigureAwait(false);

                evidence.Add(new EvidenceItem("platform-context", "trust.ied.endpoint.auth_api.outcome", endpointResult.Outcome.ToString()));
                if (endpointResult.StatusCode.HasValue)
                {
                    evidence.Add(new EvidenceItem("platform-context", "trust.ied.endpoint.auth_api.status", endpointResult.StatusCode.Value.ToString()));
                    evidence.Add(new EvidenceItem("platform-context", "trust.ied.endpoint.auth_api.reachable", bool.TrueString));
                }

                if (!string.IsNullOrWhiteSpace(endpointResult.ServerSubject))
                {
                    AddIfPresent(evidence, "trust.ied.endpoint.tls.subject", endpointResult.ServerSubject);
                }

                if (endpointResult.StatusCode.HasValue || endpointResult.Outcome == ProbeOutcome.Success)
                {
                    evidence.Add(new EvidenceItem(
                        "platform-context",
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
            evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.parse_error", bool.TrueString));
        }
    }

    private static void AddIfPresent(List<EvidenceItem> evidence, string key, string? value, EvidenceSensitivity sensitivity = EvidenceSensitivity.Public)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem("platform-context", key, value.Trim(), sensitivity));
        }
    }

    private static IEnumerable<KeyValuePair<string, string?>> GetEnvironmentVariables()
    {
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key)
            {
                yield return new KeyValuePair<string, string?>(key, entry.Value?.ToString());
            }
        }
    }

    private static async Task<IedEndpointProbeResult> ProbeIedEndpointAsync(
        IedEndpointProbeRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        X509Certificate2? serverCertificate = null;
        X509Chain? serverChain = null;

        using var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (_, certificate, chain, _) =>
        {
            serverCertificate = certificate is null ? null : new X509Certificate2(certificate);
            serverChain = chain;
            return true;
        };

        try
        {
            using var client = new HttpClient(handler)
            {
                BaseAddress = new Uri($"https://{request.ServiceName}", UriKind.Absolute),
                Timeout = timeout
            };

            using var response = await client.GetAsync(request.AuthApiPath, cancellationToken).ConfigureAwait(false);
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, serverCertificate, serverChain);
            return new IedEndpointProbeResult(
                ProbeOutcome.Success,
                (int)response.StatusCode,
                serverCertificate?.Subject,
                bindingMatched);
        }
        catch (OperationCanceledException ex)
        {
            return new IedEndpointProbeResult(ProbeOutcome.Timeout, null, serverCertificate?.Subject, false, ex.Message);
        }
        catch (HttpRequestException ex)
        {
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, serverCertificate, serverChain);
            return new IedEndpointProbeResult(ProbeOutcome.Unavailable, null, serverCertificate?.Subject, bindingMatched, ex.Message);
        }
        catch (Exception ex)
        {
            var bindingMatched = MatchesExpectedCertificate(request.CertificateChainPem, serverCertificate, serverChain);
            return new IedEndpointProbeResult(ProbeOutcome.Error, null, serverCertificate?.Subject, bindingMatched, ex.Message);
        }
    }

    private static bool MatchesExpectedCertificate(string? pemChain, X509Certificate2? serverCertificate, X509Chain? serverChain)
    {
        if (string.IsNullOrWhiteSpace(pemChain) || serverCertificate is null)
        {
            return false;
        }

        var expectedThumbprints = ExtractPemCertificates(pemChain)
            .Select(certificate => certificate.Thumbprint)
            .Where(thumbprint => !string.IsNullOrWhiteSpace(thumbprint))
            .Select(thumbprint => thumbprint!.Replace(" ", string.Empty, StringComparison.Ordinal))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (expectedThumbprints.Count == 0)
        {
            return false;
        }

        if (expectedThumbprints.Contains(serverCertificate.Thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal)))
        {
            return true;
        }

        if (serverChain is null)
        {
            return false;
        }

        return serverChain.ChainElements
            .Cast<X509ChainElement>()
            .Any(element => expectedThumbprints.Contains(element.Certificate.Thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal)));
    }

    private static IReadOnlyList<X509Certificate2> ExtractPemCertificates(string pemChain)
        => Regex.Matches(pemChain, "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline)
            .Select(match => match.Value)
            .Select(pem => X509Certificate2.CreateFromPem(pem))
            .ToArray();

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