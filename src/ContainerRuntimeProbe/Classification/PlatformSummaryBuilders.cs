using System.Globalization;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Classification;

internal static class PlatformEvidenceBuilder
{
    internal static IReadOnlyList<PlatformEvidenceSummary> Build(IReadOnlyList<ProbeResult> probes)
    {
        var flattened = probes.SelectMany(probe => probe.Evidence).ToArray();
        var siemensIndustrialEdge = BuildSiemensIndustrialEdge(flattened);
        return siemensIndustrialEdge is null ? [] : [siemensIndustrialEdge];
    }

    private static PlatformEvidenceSummary? BuildSiemensIndustrialEdge(IReadOnlyList<EvidenceItem> evidence)
    {
        var score = 0;
        var items = new List<PlatformEvidenceItem>();
        var warnings = new List<string>();

        var industrialEdge = FindPlatformContextSignal(evidence, ["industrial-edge", "industrialedge"]);
        var iotedge = FindPlatformContextSignal(evidence, ["iotedge"])
            ?? evidence.FirstOrDefault(item => Contains(item.Key, "iotedge") || Contains(item.Value, "iotedge"));
        var siemensHardware = FindSiemensHardwareEvidence(evidence);
        var siemensTextual = FindPlatformContextSignal(evidence, ["siemens"])
            ?? evidence.FirstOrDefault(item => item.ProbeId == "environment"
                && item.Key.StartsWith("SIEMENS", StringComparison.OrdinalIgnoreCase))
            ?? evidence.FirstOrDefault(item => item.ProbeId == "runtime-api"
                && (Contains(item.Key, "siemens") || Contains(item.Value, "siemens")));
        var tokenSignal = FindPlatformContextSignal(evidence, ["iem", "ied"]);
        var composeHint = evidence.FirstOrDefault(item => item.ProbeId == "runtime-api"
            && item.Key.StartsWith("compose.label.", StringComparison.Ordinal));
        var networkHint = evidence.FirstOrDefault(item => item.ProbeId == "platform-context"
            && item.Key is "dns.signal" or "hostname.signal");

        if (industrialEdge is not null)
        {
            score += 6;
            items.Add(ToEvidenceItem(industrialEdge, 6, "Industrial Edge naming was found in local platform context."));
        }

        if (iotedge is not null)
        {
            score += 5;
            items.Add(ToEvidenceItem(iotedge, 5, "IoT Edge runtime markers were found in the local environment."));
        }

        if (siemensHardware is not null)
        {
            score += 5;
            items.Add(ToEvidenceItem(siemensHardware, 5, "Hardware or firmware evidence identifies Siemens or SIMATIC."));
        }

        if (siemensTextual is not null)
        {
            score += 3;
            items.Add(ToEvidenceItem(siemensTextual, 3, "Siemens-specific textual markers were found in local platform context."));
        }

        if (tokenSignal is not null)
        {
            score += 3;
            items.Add(ToEvidenceItem(tokenSignal, 3, "Short IEM/IED token markers were found with token boundaries."));
        }

        if (composeHint is not null)
        {
            score += 2;
            items.Add(ToEvidenceItem(composeHint, 2, "Runtime metadata contains Docker Compose deployment context."));
        }

        if (networkHint is not null)
        {
            score += 1;
            items.Add(ToEvidenceItem(networkHint, 1, "Hostname or DNS context hints reference Industrial Edge naming."));
        }

        if (siemensTextual is not null && iotedge is not null)
        {
            score += 4;
            items.Add(new PlatformEvidenceItem(
                PlatformEvidenceType.Signal,
                "siemens+iotedge",
                "corroborated",
                Confidence.High,
                "Siemens markers and IoT Edge runtime markers corroborate each other."));
        }

        if (industrialEdge is not null && iotedge is not null)
        {
            score += 5;
            items.Add(new PlatformEvidenceItem(
                PlatformEvidenceType.Signal,
                "industrial-edge+iotedge",
                "corroborated",
                Confidence.High,
                "Industrial Edge naming and IoT Edge runtime markers corroborate each other."));
        }

        if (score == 0)
        {
            return null;
        }

        if (iotedge is not null && industrialEdge is null && siemensHardware is null && siemensTextual is null)
        {
            warnings.Add("IoT Edge markers alone are not Siemens-specific and can describe generic Azure IoT Edge deployments.");
        }

        if (networkHint is not null && industrialEdge is null && iotedge is null && siemensHardware is null && siemensTextual is null)
        {
            warnings.Add("Hostname and DNS hints are easy to spoof and remain weak without execution or hardware corroboration.");
        }

        if (tokenSignal is not null && industrialEdge is null && iotedge is null && siemensHardware is null && siemensTextual is null)
        {
            warnings.Add("Short IEM/IED token matches remain ambiguous without stronger corroboration.");
        }

        return new PlatformEvidenceSummary(
            "siemens-industrial-edge",
            score,
            ScoreToEvidenceLevel(score),
            ScoreToConfidence(score),
            items,
            warnings);
    }

    private static PlatformEvidenceLevel ScoreToEvidenceLevel(int score)
        => score switch
        {
            >= 8 => PlatformEvidenceLevel.StrongHeuristic,
            >= 4 => PlatformEvidenceLevel.Heuristic,
            >= 1 => PlatformEvidenceLevel.WeakHint,
            _ => PlatformEvidenceLevel.None
        };

    private static Confidence ScoreToConfidence(int score)
        => score switch
        {
            >= 8 => Confidence.High,
            >= 4 => Confidence.Medium,
            >= 1 => Confidence.Low,
            _ => Confidence.Unknown
        };

    private static PlatformEvidenceItem ToEvidenceItem(EvidenceItem evidence, int weight, string description)
        => new(
            ClassifyEvidenceType(evidence),
            evidence.Key,
            evidence.Value,
            ScoreToConfidence(weight),
            description);

    private static PlatformEvidenceType ClassifyEvidenceType(EvidenceItem evidence)
    {
        if (evidence.Key.StartsWith("env.", StringComparison.Ordinal))
        {
            return PlatformEvidenceType.Environment;
        }

        if (evidence.Key is "mountinfo.signal" or "cgroup.signal")
        {
            return PlatformEvidenceType.ExecutionContext;
        }

        if (evidence.Key is "dns.signal" or "hostname.signal")
        {
            return PlatformEvidenceType.NetworkContext;
        }

        if (VendorCatalog.ExplicitHardwareEvidenceKeys.Contains(evidence.Key, StringComparer.Ordinal))
        {
            return PlatformEvidenceType.Hardware;
        }

        if (evidence.ProbeId == "runtime-api")
        {
            return PlatformEvidenceType.RuntimeMetadata;
        }

        if (evidence.Key.StartsWith("trust.", StringComparison.Ordinal))
        {
            return PlatformEvidenceType.TrustArtifact;
        }

        return PlatformEvidenceType.Signal;
    }

    private static EvidenceItem? FindPlatformContextSignal(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> expectedSignals)
        => evidence.FirstOrDefault(item => item.ProbeId == "platform-context"
            && item.Key.EndsWith(".signal", StringComparison.Ordinal)
            && expectedSignals.Contains(item.Value ?? string.Empty, StringComparer.Ordinal));

    private static EvidenceItem? FindSiemensHardwareEvidence(IReadOnlyList<EvidenceItem> evidence)
    {
        var siemensEntry = VendorCatalog.RuntimeActiveHardwareVendors.First(entry => entry.Vendor == PlatformVendorKind.Siemens);
        return evidence.FirstOrDefault(item => siemensEntry.EvidenceKeys.Contains(item.Key, StringComparer.Ordinal)
            && siemensEntry.MatchFragments.Any(fragment => Contains(item.Value, fragment)));
    }

    private static bool Contains(string? value, string fragment)
        => !string.IsNullOrWhiteSpace(value)
           && value.Contains(fragment, StringComparison.OrdinalIgnoreCase);
}

internal static class TrustedPlatformBuilder
{
    private const string WindowsTrustProbeId = "windows-trust";

    internal static IReadOnlyList<TrustedPlatformSummary> Build(IReadOnlyList<ProbeResult> probes)
    {
        var flattened = probes.SelectMany(probe => probe.Evidence).ToArray();
        var containerTpmVisible = BuildContainerTpmVisible(flattened);
        var windowsHostTpm = BuildWindowsHostTpm(flattened);
        var siemensIedRuntime = BuildSiemensIedRuntime(flattened);
        return [.. new[] { containerTpmVisible, windowsHostTpm, siemensIedRuntime }.OfType<TrustedPlatformSummary>()];
    }

    private static TrustedPlatformSummary? BuildContainerTpmVisible(IReadOnlyList<EvidenceItem> evidence)
    {
        var devicePaths = evidence
            .Where(item => item.ProbeId == "proc-files" && item.Key == "device.tpm.path" && !string.IsNullOrWhiteSpace(item.Value))
            .Select(item => item.Value!)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
        if (devicePaths.Length == 0)
        {
            return null;
        }

        var trustEvidence = devicePaths
            .Select(path => new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalDeviceNode,
                "device.tpm.path",
                path,
                Confidence.Low,
                "A TPM-related device node is visible to the current process inside the observed environment."))
            .ToArray();

        var claims = new List<TrustedPlatformClaim>
        {
            new(
                TrustedPlatformClaimScope.RuntimePresence,
                "container-tpm-visible",
                "device-node-visible",
                Confidence.Low,
                "At least one TPM-related device node is visible inside the current container or process environment.")
        };

        if (devicePaths.Any(path => path.Contains("vtpm", StringComparison.OrdinalIgnoreCase)))
        {
            claims.Add(new TrustedPlatformClaim(
                TrustedPlatformClaimScope.RuntimePresence,
                "container-vtpm-visible",
                "virtual-device-node-visible",
                Confidence.Low,
                "A virtual TPM device node is visible inside the current container or process environment."));
        }

        return new TrustedPlatformSummary(
            "container-tpm-visible",
            TrustedPlatformState.Claimed,
            "local-device-node",
            null,
            null,
            null,
            claims,
            trustEvidence,
            ["Visible TPM device nodes are an explicit local artifact, but they do not prove host identity, dedicated ownership, or any caller-specific binding on their own."])
        {
            VerificationLevel = 1
        };
    }

    private static TrustedPlatformSummary? BuildWindowsHostTpm(IReadOnlyList<EvidenceItem> evidence)
    {
        var tpmOutcome = evidence.FirstOrDefault(item => item.ProbeId == WindowsTrustProbeId
            && item.Key == "trust.windows.tpm.outcome");
        var tpmOutcomeValue = tpmOutcome?.Value;
        if (!string.Equals(tpmOutcomeValue, ProbeOutcome.Success.ToString(), StringComparison.Ordinal))
        {
            return null;
        }

        var version = evidence.FirstOrDefault(item => item.ProbeId == WindowsTrustProbeId
            && item.Key == "trust.windows.tpm.version")?.Value;
        var interfaceType = evidence.FirstOrDefault(item => item.ProbeId == WindowsTrustProbeId
            && item.Key == "trust.windows.tpm.interface_type")?.Value;
        var implementationRevision = evidence.FirstOrDefault(item => item.ProbeId == WindowsTrustProbeId
            && item.Key == "trust.windows.tpm.implementation_revision")?.Value;

        var trustEvidence = new List<TrustedPlatformEvidence>
        {
            new(
                TrustedPlatformSourceType.LocalHardwareApi,
                "trust.windows.tpm.outcome",
                tpmOutcomeValue,
                Confidence.Low,
                "Windows Trusted Base Services reported a local TPM device.")
        };

        if (!string.IsNullOrWhiteSpace(version))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalHardwareApi,
                "trust.windows.tpm.version",
                version,
                Confidence.Medium,
                "The local Windows TPM API reported a TPM specification version."));
        }

        if (!string.IsNullOrWhiteSpace(interfaceType))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalHardwareApi,
                "trust.windows.tpm.interface_type",
                interfaceType,
                Confidence.Low,
                "The local Windows TPM API reported a TPM interface type."));
        }

        if (!string.IsNullOrWhiteSpace(implementationRevision))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalHardwareApi,
                "trust.windows.tpm.implementation_revision",
                implementationRevision,
                Confidence.Low,
                "The local Windows TPM API reported an implementation revision."));
        }

        var plausible = string.Equals(version, "1.2", StringComparison.Ordinal)
            || string.Equals(version, "2.0", StringComparison.Ordinal);
        var level = plausible ? 2 : 1;
        var warnings = new List<string>
        {
            "Local TPM presence alone does not attest the Windows host identity and does not bind a container without a stronger quote or caller-provided validation flow."
        };

        if (!plausible)
        {
            warnings.Add("The TPM device was visible, but the reported TPM version was not recognized as a standard 1.2 or 2.0 device.");
        }

        return new TrustedPlatformSummary(
            "windows-host-tpm",
            TrustedPlatformState.Claimed,
            level >= 2 ? "local-tbs-device-info" : null,
            null,
            null,
            null,
            [
                new TrustedPlatformClaim(
                    TrustedPlatformClaimScope.PlatformPresence,
                    "windows-host-tpm",
                    level >= 2 ? "device-info-validated" : "device-present",
                    level >= 2 ? Confidence.Medium : Confidence.Low,
                    level >= 2
                        ? "The local Windows TPM API returned a plausible TPM device description."
                        : "A local TPM device was reported by Windows, but the device description remains incomplete."),
                new TrustedPlatformClaim(
                    TrustedPlatformClaimScope.PlatformPresence,
                    "windows-platform",
                    "hardware-backed-tpm-visible",
                    Confidence.Low,
                    "A hardware-backed TPM was visible through the local Windows TPM API.")
            ],
            trustEvidence,
            warnings)
        {
            VerificationLevel = level
        };
    }

    private static TrustedPlatformSummary? BuildSiemensIedRuntime(IReadOnlyList<EvidenceItem> evidence)
    {
        var certsipsOutcome = evidence.FirstOrDefault(item => item.ProbeId == SiemensIedRuntimeProbe.ProbeId
            && item.Key == "trust.ied.certsips.outcome");
        var certsipsOutcomeValue = certsipsOutcome?.Value;
        if (!string.Equals(certsipsOutcomeValue, ProbeOutcome.Success.ToString(), StringComparison.Ordinal))
        {
            return null;
        }

        var warnings = new List<string>();
        var trustEvidence = new List<TrustedPlatformEvidence>
        {
            new(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.outcome",
                certsipsOutcomeValue,
                Confidence.Low,
                "Documented IED runtime artifact is present at the expected local path.")
        };

        var parseError = evidence.Any(item => item.ProbeId == SiemensIedRuntimeProbe.ProbeId
            && item.Key == "trust.ied.certsips.parse_error");
        var authApiPath = FirstValue(evidence, "trust.ied.certsips.auth_api_path");
        var secureStoragePath = FirstValue(evidence, "trust.ied.certsips.secure_storage_api_path");
        var serviceName = FirstValue(evidence, "trust.ied.certsips.service_name");
        var hasCertificateChain = HasTrustKey(evidence, "trust.ied.certsips.cert_chain_present")
            || HasTrustKey(evidence, "trust.ied.certsips.certificates_chain_present");

        var plausible = !parseError
            && IsAbsoluteApiPath(authApiPath)
            && IsPlausibleServiceName(serviceName)
            && hasCertificateChain;
        var endpointReachable = HasTrustKey(evidence, "trust.ied.endpoint.auth_api.reachable");
        var tlsBindingMatched = string.Equals(
            FirstValue(evidence, "trust.ied.endpoint.tls.binding"),
            "matched",
            StringComparison.Ordinal);

        var level = plausible ? 2 : 1;
        if (plausible && endpointReachable)
        {
            level = 3;
        }

        if (level >= 3 && tlsBindingMatched)
        {
            level = 4;
        }

        var state = level >= 3 ? TrustedPlatformState.Verified : TrustedPlatformState.Claimed;
        var claimConfidence = level switch
        {
            >= 4 => Confidence.High,
            >= 2 => Confidence.Medium,
            _ => Confidence.Low
        };

        if (!string.IsNullOrWhiteSpace(authApiPath))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.auth_api_path",
                authApiPath,
                Confidence.Medium,
                "The artifact exposes a local auth API path for the IED runtime."));
        }

        if (!string.IsNullOrWhiteSpace(secureStoragePath))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.secure_storage_api_path",
                secureStoragePath,
                Confidence.Low,
                "The artifact exposes a local secure storage API path."));
        }

        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.service_name",
                serviceName,
                Confidence.Medium,
                "The artifact names the local service expected to back the IED runtime APIs."));
        }

        if (HasTrustKey(evidence, "trust.ied.certsips.cert_chain_present"))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
            "trust.ied.certsips.cert_chain_present",
                bool.TrueString,
                Confidence.Medium,
                "The artifact includes certificate material for later endpoint binding checks."));
        }

        if (HasTrustKey(evidence, "trust.ied.certsips.certificates_chain_present"))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
            TrustedPlatformSourceType.LocalFile,
            "trust.ied.certsips.certificates_chain_present",
            bool.TrueString,
            Confidence.Medium,
            "The artifact includes certificate material for later endpoint binding checks."));
        }

        if (endpointReachable)
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalEndpoint,
                "trust.ied.endpoint.auth_api.reachable",
                bool.TrueString,
                Confidence.High,
                "The documented local IED auth endpoint was reachable over HTTPS."));
        }

        var endpointStatus = FirstValue(evidence, "trust.ied.endpoint.auth_api.status");
        if (!string.IsNullOrWhiteSpace(endpointStatus))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalEndpoint,
                "trust.ied.endpoint.auth_api.status",
                endpointStatus,
                Confidence.Medium,
                "The local IED auth endpoint returned an HTTP status code."));
        }

        var tlsSubject = FirstValue(evidence, "trust.ied.endpoint.tls.subject");
        var tlsIssuer = FirstValue(evidence, "trust.ied.endpoint.tls.issuer");
        var documentedChainSha256 = FirstValue(evidence, "trust.ied.certsips.cert_chain_sha256");
        var presentedChainSha256 = FirstValue(evidence, "trust.ied.endpoint.tls.chain_sha256");
        var expiresAt = ParseDateTimeOffset(FirstValue(evidence, "trust.ied.endpoint.tls.not_after"));
        if (!string.IsNullOrWhiteSpace(tlsSubject))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.TlsBinding,
                "trust.ied.endpoint.tls.subject",
                tlsSubject,
                Confidence.Medium,
                "The local IED endpoint presented a TLS certificate subject."));
        }

        if (!string.IsNullOrWhiteSpace(tlsIssuer))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.TlsBinding,
                "trust.ied.endpoint.tls.issuer",
                tlsIssuer,
                Confidence.Medium,
                "The local IED endpoint presented a TLS certificate issuer."));
        }

        if (!string.IsNullOrWhiteSpace(documentedChainSha256))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.cert_chain_sha256",
                documentedChainSha256,
                Confidence.Medium,
                "The documented IED runtime artifact includes a stable SHA-256 fingerprint of the expected certificate chain."));
        }

        if (!string.IsNullOrWhiteSpace(presentedChainSha256))
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.TlsBinding,
                "trust.ied.endpoint.tls.chain_sha256",
                presentedChainSha256,
                Confidence.High,
                "The local IED endpoint presented a certificate chain with this SHA-256 fingerprint."));
        }

        if (level >= 4)
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.TlsBinding,
                "trust.ied.endpoint.tls.binding",
                "matched",
                Confidence.High,
                "The local IED endpoint TLS certificate matches documented certificate material."));
        }

        if (parseError)
        {
            warnings.Add("certsips.json is present but could not be parsed; trust remains at artifact-presence only.");
        }
        else if (!plausible)
        {
            warnings.Add("certsips.json is present but misses one or more plausibility checks for auth path, service name, or certificate material.");
        }
        else if (!endpointReachable)
        {
            warnings.Add("certsips.json is plausible, but the documented local IED endpoint was not reachable yet.");
        }
        else if (!tlsBindingMatched)
        {
            warnings.Add("The local IED endpoint is reachable, but TLS binding to the documented certificate material is not verified yet.");
        }

        var claims = new List<TrustedPlatformClaim>
        {
            new(
                TrustedPlatformClaimScope.RuntimePresence,
                "siemens-ied-runtime",
                level >= 4 ? "tls-bound" : level >= 3 ? "endpoint-verified" : plausible ? "documented-and-plausible" : "artifact-present",
                claimConfidence,
                level >= 4
                    ? "A documented local IED runtime artifact is present, reachable, and TLS-bound to documented certificate material."
                    : level >= 3
                        ? "A documented local IED runtime artifact is present, plausible, and locally reachable over HTTPS."
                        : plausible
                            ? "A documented local IED runtime artifact is present and structurally plausible."
                            : "A documented local IED runtime artifact is present, but local verification is still limited.")
        };

        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            claims.Add(new TrustedPlatformClaim(
                TrustedPlatformClaimScope.RuntimePresence,
                "local-service-name",
                serviceName,
                claimConfidence,
                "The documented IED runtime service name is available for later local connectivity checks."));
        }

        return new TrustedPlatformSummary(
            "siemens-ied-runtime",
            state,
            level >= 4 ? "local-runtime-tls-binding" : level >= 3 ? "local-runtime-endpoint" : "local-runtime-artifact",
            tlsIssuer,
            serviceName,
            expiresAt,
            claims,
            trustEvidence,
            warnings)
        {
            VerificationLevel = level
        };
    }

    private static DateTimeOffset? ParseDateTimeOffset(string? value)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) ? parsed : null;

    private static string? FirstValue(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.FirstOrDefault(item => item.ProbeId == SiemensIedRuntimeProbe.ProbeId && item.Key == key)?.Value;

    private static bool HasTrustKey(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.Any(item => item.ProbeId == SiemensIedRuntimeProbe.ProbeId && item.Key == key);

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