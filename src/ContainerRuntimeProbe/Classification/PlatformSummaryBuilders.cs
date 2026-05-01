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
        => [];
}