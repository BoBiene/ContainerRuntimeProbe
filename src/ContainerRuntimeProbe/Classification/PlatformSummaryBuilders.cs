using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal static class PlatformEvidenceBuilder
{
    internal static IReadOnlyList<PlatformEvidenceSummary> Build(IReadOnlyList<ProbeResult> probes)
        => [];
}

internal static class TrustedPlatformBuilder
{
    internal static IReadOnlyList<TrustedPlatformSummary> Build(IReadOnlyList<ProbeResult> probes)
        => [];
}