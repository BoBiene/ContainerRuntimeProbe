using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

/// <summary>
/// Encapsulates all PlatformVendor detection heuristics.
/// Accepts pre-extracted OS evidence values from the classifier so the main Classify() method
/// stays orchestration-focused instead of accumulating platform-specific rule blocks.
/// </summary>
internal static class VendorDetection
{
    /// <summary>Scoring thresholds — keep consistent with the main ScoreToConfidence table in Classifier.</summary>
    private static Confidence Score(int s) => s switch { >= 8 => Confidence.High, >= 4 => Confidence.Medium, >= 1 => Confidence.Low, _ => Confidence.Unknown };

    private static ClassificationResult<PlatformVendorKind> Make(PlatformVendorKind value, int score, params ClassificationReason[] reasons)
        => new(value, Score(score), reasons);

    private static bool ContainsAny(string? value, params string[] fragments)
        => !string.IsNullOrWhiteSpace(value)
           && fragments.Any(f => value.Contains(f, StringComparison.OrdinalIgnoreCase));

    private static string? FirstValue(IEnumerable<EvidenceItem> ev, params string[] keys)
        => ev.FirstOrDefault(x => keys.Contains(x.Key, StringComparer.Ordinal))?.Value;

    private static EvidenceItem? FirstByKeyPattern(IEnumerable<EvidenceItem> ev, string prefix, string suffix)
        => ev.FirstOrDefault(x => x.Key.StartsWith(prefix, StringComparison.Ordinal)
            && x.Key.EndsWith(suffix, StringComparison.Ordinal)
            && !string.IsNullOrWhiteSpace(x.Value));

    private static readonly string[] ExplicitVendorEvidenceKeys =
    [
        "dmi.sys_vendor",
        "dmi.board_vendor",
        "dmi.product_name",
        "dmi.board_name",
        "dmi.product_family",
        "dmi.chassis_vendor",
        "dmi.modalias",
        "device_tree.model",
        "device_tree.compatible"
    ];

    private static (PlatformVendorKind vendor, string[] matchedKeys) DetectExplicitPlatformVendor(IReadOnlyList<EvidenceItem> evidence)
    {
        var explicitEvidence = evidence
            .Where(item => ExplicitVendorEvidenceKeys.Contains(item.Key, StringComparer.Ordinal))
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .ToArray();

        foreach (var mapping in DetectionMaps.ExplicitPlatformVendorSignals)
        {
            var matchedKeys = explicitEvidence
                .Where(item => ContainsAny(item.Value, mapping.Fragments))
                .Select(item => item.Key)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (matchedKeys.Length > 0)
            {
                return (mapping.Vendor, matchedKeys);
            }
        }

        return (PlatformVendorKind.Unknown, []);
    }

    /// <summary>
    /// Evaluates all platform vendor signals and returns the best-matching vendor classification.
    /// Vendors are checked in priority order: Microsoft (WSL2) → Synology → Apple → Siemens/IoTEdge.
    /// Each vendor requires a minimum score of 2 to prevent single-weak-signal false positives,
    /// except Microsoft (WSL2) which is a deterministic high-confidence signal.
    /// </summary>
    internal static ClassificationResult<PlatformVendorKind> Detect(
        IReadOnlyList<EvidenceItem> e,
        string? osId,
        string? osName,
        string? prettyName)
    {
        // ── Microsoft / WSL2 ─────────────────────────────────────────────────
        // WSL2 is a deterministic kernel signal — no threshold needed.
        var wsl2 =
            e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "WSL2", StringComparison.OrdinalIgnoreCase))
            || e.Any(x => x.Key == "kernel.release" && HostParsing.ContainsWsl2Signal(x.Value))
            || e.Any(x => x.Key == "/proc/version" && HostParsing.ContainsWsl2Signal(x.Value));

        if (wsl2)
            return Make(PlatformVendorKind.Microsoft, 8, new ClassificationReason("WSL2 kernel fingerprint detected", ["kernel.flavor", "kernel.release", "/proc/version"]));

        // ── Synology NAS ──────────────────────────────────────────────────────
        // Minimum score of 2 required to avoid false positives from a single weak signal.
        // "dsm" is intentionally excluded from the kernel flavor check (too short/ambiguous)
        // and removed from OS name matching to require "synology" or "diskstation" instead.
        var synologyScore = 0;
        var synologyReasons = new List<ClassificationReason>();
        var publicHwVersion = FirstByKeyPattern(e, "kernel.", "_hw_version");
        var dmiSysVendor = FirstValue(e, "dmi.sys_vendor");
        var dmiBoardVendor = FirstValue(e, "dmi.board_vendor");
        var dmiProductName = FirstValue(e, "dmi.product_name");
        var dmiBoardName = FirstValue(e, "dmi.board_name");
        var dmiModalias = FirstValue(e, "dmi.modalias");
        var synologyOsDetected = ContainsAny(osId, "synology")
            || ContainsAny(osName, "synology", "diskstation")
            || ContainsAny(prettyName, "synology", "diskstation");
        var synologyVendorDetected = ContainsAny(dmiSysVendor, "synology")
            || ContainsAny(dmiBoardVendor, "synology")
            || ContainsAny(dmiModalias, "svnsynologyinc.");
        var synologyProductDetected = ContainsAny(dmiProductName, "diskstation", "rackstation", "flashstation", "disk station", "rack station", "flash station")
            || ContainsAny(dmiBoardName, "diskstation", "rackstation", "flashstation", "disk station", "rack station", "flash station");

        if (e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "Synology", StringComparison.OrdinalIgnoreCase)))
        {
            synologyScore += 4; // Normalized kernel flavor is a strong signal
            synologyReasons.Add(new("Kernel flavor identified as Synology DSM", ["kernel.flavor"]));
        }

        if (synologyOsDetected)
        {
            synologyScore += 2;
            synologyReasons.Add(new("OS release identifies Synology distribution", ["os.id", "os.name", "os.pretty_name"]));
        }

        if (publicHwVersion is not null
            && (publicHwVersion.Key.Contains("syno", StringComparison.OrdinalIgnoreCase)
                || synologyOsDetected
                || synologyVendorDetected
                || synologyProductDetected))
        {
            synologyScore += 5;
            synologyReasons.Add(new("Public kernel hardware-version sysctl exposed host hardware model", [publicHwVersion.Key]));
        }

        if (synologyVendorDetected)
        {
            synologyScore += 4;
            synologyReasons.Add(new("DMI vendor identifies a Synology system", ["dmi.sys_vendor", "dmi.board_vendor", "dmi.modalias"]));
        }

        if (synologyProductDetected)
        {
            synologyScore += 2;
            synologyReasons.Add(new("DMI product name identifies a Synology appliance line", ["dmi.product_name", "dmi.board_name"]));
        }

        if (synologyScore >= 2)
            return Make(PlatformVendorKind.Synology, synologyScore, synologyReasons.ToArray());

        // ── Apple / Docker Desktop ────────────────────────────────────────────
        // Requires score >= 2 to prevent a stray "Intel Core" CPU name from firing alone.
        var dockerInfoOs = FirstValue(e, "docker.info.operating_system");
        var dockerInfoKernel = FirstValue(e, "docker.info.kernel_version");
        var appleScore = 0;
        var appleReasons = new List<ClassificationReason>();

        var linuxKitDetected =
            e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "DockerDesktop", StringComparison.OrdinalIgnoreCase))
            || e.Any(x => x.Key == "kernel.release" && x.Value?.Contains("linuxkit", StringComparison.OrdinalIgnoreCase) == true)
            || e.Any(x => x.Key == "/proc/version" && x.Value?.Contains("linuxkit", StringComparison.OrdinalIgnoreCase) == true)
            || ContainsAny(dockerInfoKernel, "linuxkit");

        if (linuxKitDetected)
        {
            appleScore += 2;
            appleReasons.Add(new("LinuxKit kernel fingerprint suggests Docker Desktop VM", ["kernel.flavor", "kernel.release", "/proc/version", "docker.info.kernel_version"]));
        }

        if (ContainsAny(dockerInfoOs, "docker desktop"))
        {
            appleScore += 1;
            appleReasons.Add(new("Runtime API reports Docker Desktop operating system", ["docker.info.operating_system"]));
        }

        var cpuModel = FirstValue(e, "cpu.model_name");
        if (ContainsAny(cpuModel, "apple", "intel(r) core"))
        {
            appleScore += 1;
            appleReasons.Add(new("CPU model is consistent with desktop/laptop developer hosts", ["cpu.model_name"]));
        }

        if (appleScore >= 2)
            return Make(PlatformVendorKind.Apple, appleScore, appleReasons.ToArray());

        var (explicitPlatformVendor, explicitVendorKeys) = DetectExplicitPlatformVendor(e);

        if (explicitPlatformVendor != PlatformVendorKind.Unknown && explicitPlatformVendor != PlatformVendorKind.Siemens)
        {
            var otScore = explicitVendorKeys.Length >= 2 ? 8 : 5;
            return Make(explicitPlatformVendor, otScore, new ClassificationReason("DMI or device-tree identifies the underlying OT hardware vendor", explicitVendorKeys));
        }

        if (explicitPlatformVendor == PlatformVendorKind.Siemens)
        {
            var siemensScore = explicitVendorKeys.Length >= 2 ? 8 : 5;
            var siemensReason = new ClassificationReason("DMI or device-tree identifies Siemens hardware", explicitVendorKeys);

            if (!e.Any(x => x.Key.Contains("iotedge", StringComparison.OrdinalIgnoreCase)))
            {
                return Make(PlatformVendorKind.Siemens, siemensScore, siemensReason);
            }
        }

        // ── Siemens Industrial Edge / IoTEdge ─────────────────────────────────
        var iotedgeScore = 0;
        var iotedgeReasons = new List<ClassificationReason>();

        if (e.Any(x => x.Key.Contains("iotedge", StringComparison.OrdinalIgnoreCase)))
        {
            iotedgeScore += 5;
            iotedgeReasons.Add(new("IoTEdge env marker detected", ["environment"]));
        }

        if (iotedgeScore > 0)
        {
            var hasSiemens = explicitPlatformVendor == PlatformVendorKind.Siemens
                || e.Any(x =>
                    x.Key.Contains("siemens", StringComparison.OrdinalIgnoreCase) ||
                    x.Key.Contains("industrial", StringComparison.OrdinalIgnoreCase) ||
                    x.Value?.Contains("siemens", StringComparison.OrdinalIgnoreCase) == true);

            if (hasSiemens)
            {
                var ieScore = iotedgeScore + 4;
                var ieReasons = new List<ClassificationReason>(iotedgeReasons)
                    { new("Siemens-specific signals corroborate IoTEdge", ["environment", "runtime-api"]) };

                if (explicitVendorKeys.Length > 0)
                {
                    ieScore += explicitVendorKeys.Length >= 2 ? 3 : 2;
                    ieReasons.Add(new("DMI or device-tree corroborates Siemens hardware", explicitVendorKeys));
                }

                if (e.Any(x => x.Key.Contains("compose", StringComparison.OrdinalIgnoreCase)))
                {
                    ieScore += 2;
                    ieReasons.Add(new("Docker Compose corroboration", ["runtime-api"]));
                }

                return Make(PlatformVendorKind.SiemensIndustrialEdge, ieScore, ieReasons.ToArray());
            }

            return Make(PlatformVendorKind.IoTEdge, iotedgeScore, iotedgeReasons.ToArray());
        }

        return Make(PlatformVendorKind.Unknown, 0, new ClassificationReason("No vendor-specific proofs", []));
    }
}
