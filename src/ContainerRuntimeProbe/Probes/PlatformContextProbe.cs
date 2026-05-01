using System.Collections;
using System.Diagnostics;
using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

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

    public string Id => "platform-context";

    public PlatformContextProbe()
        : this(GetEnvironmentVariables, ProbeIo.ReadFileAsync)
    {
    }

    internal PlatformContextProbe(
        Func<IEnumerable<KeyValuePair<string, string?>>> getEnvironment,
        Func<string, TimeSpan, CancellationToken, Task<(ProbeOutcome outcome, string? text, string? message)>> readFileAsync)
    {
        _getEnvironment = getEnvironment;
        _readFileAsync = readFileAsync;
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
                    AddIedTrustArtifactEvidence(evidence, text, context.IncludeSensitive);
                    break;
            }
        }

        sw.Stop();
        return new ProbeResult(Id, outcome, evidence.Distinct().ToArray(), message, sw.Elapsed);
    }

    private void AddEnvironmentEvidence(List<EvidenceItem> evidence, ProbeContext context)
    {
        foreach (var (key, value) in _getEnvironment()
                     .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
                     .Where(pair => PlatformEnvironmentPrefixes.Any(prefix => pair.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))))
        {
            var sensitive = Redaction.IsSensitiveKey(key) || key.Equals("HOSTNAME", StringComparison.OrdinalIgnoreCase);
            var redactedValue = sensitive ? Redaction.MaybeRedact(key, value, context.IncludeSensitive) : value?.Trim();
            evidence.Add(new EvidenceItem(Id, $"env.{key}", redactedValue, sensitive ? EvidenceSensitivity.Sensitive : EvidenceSensitivity.Public));

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

    private static void AddIedTrustArtifactEvidence(List<EvidenceItem> evidence, string? text, bool includeSensitive)
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
            AddIfPresent(evidence, "trust.ied.certsips.auth_api_path", JsonHelper.GetString(root, "auth-api-path"));
            AddIfPresent(evidence, "trust.ied.certsips.secure_storage_api_path", JsonHelper.GetString(root, "secure-storage-api-path"));
            AddIfPresent(evidence, "trust.ied.certsips.edge_ips", Redaction.MaybeRedact("edge_ips", JsonHelper.GetString(root, "edge-ips"), includeSensitive), EvidenceSensitivity.Sensitive);

            if (root.TryGetProperty("edge-certificates", out var edgeCertificates) && edgeCertificates.ValueKind == JsonValueKind.Object)
            {
                AddIfPresent(evidence, "trust.ied.certsips.service_name", JsonHelper.GetString(edgeCertificates, "service-name"));
                var certificateChain = JsonHelper.GetString(edgeCertificates, "certificates-chain");
                if (!string.IsNullOrWhiteSpace(certificateChain))
                {
                    evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.certificates_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
                }
            }

            if (!string.IsNullOrWhiteSpace(JsonHelper.GetString(root, "cert-chain")))
            {
                evidence.Add(new EvidenceItem("platform-context", "trust.ied.certsips.cert_chain_present", bool.TrueString, EvidenceSensitivity.Sensitive));
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
}