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
        return new ProbeToolMetadata(GetAssemblyVersion());
    }

    /// <summary>
    /// Gets assembly version from AssemblyInformationalVersion, shortening the build-metadata
    /// git hash (after <c>+</c>) to 7 chars to match the git short-hash convention.
    /// </summary>
    private static string GetAssemblyVersion()
    {
        var assembly = typeof(VersionInfo).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        if (string.IsNullOrWhiteSpace(informationalVersion))
            return "unknown";

        var plus = informationalVersion.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0 && informationalVersion.Length - plus - 1 > 7)
            return informationalVersion[..(plus + 8)]; // keep prefix + '+' + 7 hex chars

        return informationalVersion;
    }
}
