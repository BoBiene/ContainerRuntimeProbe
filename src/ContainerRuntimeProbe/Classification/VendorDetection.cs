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

        if (e.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "Synology", StringComparison.OrdinalIgnoreCase)))
        {
            synologyScore += 4; // Normalized kernel flavor is a strong signal
            synologyReasons.Add(new("Kernel flavor identified as Synology DSM", ["kernel.flavor"]));
        }

        if (ContainsAny(osId, "synology")
            || ContainsAny(osName, "synology", "diskstation")
            || ContainsAny(prettyName, "synology", "diskstation"))
        {
            synologyScore += 2;
            synologyReasons.Add(new("OS release identifies Synology distribution", ["os.id", "os.name", "os.pretty_name"]));
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
            var hasSiemens = e.Any(x =>
                x.Key.Contains("siemens", StringComparison.OrdinalIgnoreCase) ||
                x.Key.Contains("industrial", StringComparison.OrdinalIgnoreCase) ||
                x.Value?.Contains("siemens", StringComparison.OrdinalIgnoreCase) == true);

            if (hasSiemens)
            {
                var ieScore = iotedgeScore + 4;
                var ieReasons = new List<ClassificationReason>(iotedgeReasons)
                    { new("Siemens-specific signals corroborate IoTEdge", ["environment", "runtime-api"]) };

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
