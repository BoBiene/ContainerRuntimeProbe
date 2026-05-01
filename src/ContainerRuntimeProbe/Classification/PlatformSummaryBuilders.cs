using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

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
                && item.Key.StartsWith("SIEMENS", StringComparison.OrdinalIgnoreCase));
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
    internal static IReadOnlyList<TrustedPlatformSummary> Build(IReadOnlyList<ProbeResult> probes)
    {
        var flattened = probes.SelectMany(probe => probe.Evidence).ToArray();
        var siemensIedRuntime = BuildSiemensIedRuntime(flattened);
        return siemensIedRuntime is null ? [] : [siemensIedRuntime];
    }

    private static TrustedPlatformSummary? BuildSiemensIedRuntime(IReadOnlyList<EvidenceItem> evidence)
    {
        var certsipsOutcome = evidence.FirstOrDefault(item => item.ProbeId == "platform-context"
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

        var parseError = evidence.Any(item => item.ProbeId == "platform-context"
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

        var level = plausible ? 2 : 1;
        var claimConfidence = plausible ? Confidence.Medium : Confidence.Low;

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

        if (hasCertificateChain)
        {
            trustEvidence.Add(new TrustedPlatformEvidence(
                TrustedPlatformSourceType.LocalFile,
                "trust.ied.certsips.certificate_chain",
                bool.TrueString,
                Confidence.Medium,
                "The artifact includes certificate material for later endpoint binding checks."));
        }

        if (parseError)
        {
            warnings.Add("certsips.json is present but could not be parsed; trust remains at artifact-presence only.");
        }
        else if (!plausible)
        {
            warnings.Add("certsips.json is present but misses one or more plausibility checks for auth path, service name, or certificate material.");
        }

        var claims = new List<TrustedPlatformClaim>
        {
            new(
                TrustedPlatformClaimScope.RuntimePresence,
                "siemens-ied-runtime",
                plausible ? "documented-and-plausible" : "artifact-present",
                claimConfidence,
                plausible
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
            TrustedPlatformState.Claimed,
            "local-runtime-artifact",
            null,
            serviceName,
            null,
            claims,
            trustEvidence,
            warnings)
        {
            VerificationLevel = level
        };
    }

    private static string? FirstValue(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.FirstOrDefault(item => item.ProbeId == "platform-context" && item.Key == key)?.Value;

    private static bool HasTrustKey(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.Any(item => item.ProbeId == "platform-context" && item.Key == key);

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