using System.Reflection;
using System.Text;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Internal;

/// <summary>Helper to extract probe tool version and git commit information.</summary>
internal static class VersionInfo
{
    /// <summary>Returns probe tool metadata with version and git commit hash if available.</summary>
    public static ProbeToolMetadata GetProbeToolMetadata()
    {
        var informationalVersion = GetInformationalVersion();
        return new ProbeToolMetadata(GetSemanticVersion(informationalVersion), GetShortGitCommit(informationalVersion));
    }

    private static string GetInformationalVersion()
    {
        var assembly = typeof(VersionInfo).Assembly;
        return assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
            ?? "unknown";
    }

    private static string GetSemanticVersion(string informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
        {
            return "unknown";
        }

        var plus = informationalVersion.IndexOf('+', StringComparison.Ordinal);
        return plus >= 0 ? informationalVersion[..plus] : informationalVersion;
    }

    private static string? GetShortGitCommit(string informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
        {
            return null;
        }

        var plus = informationalVersion.IndexOf('+', StringComparison.Ordinal);
        if (plus < 0 || plus == informationalVersion.Length - 1)
        {
            return null;
        }

        var commit = informationalVersion[(plus + 1)..];
        return commit.Length > 7 ? commit[..7] : commit;
    }
}
