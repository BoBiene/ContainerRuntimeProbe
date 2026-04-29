using System.Diagnostics;

namespace ContainerRuntimeProbe.Tests;

/// <summary>
/// Locates and optionally downloads the which-distro/os-release fixture repository
/// (GPL-2.0-or-later) for local development and CI use.
///
/// The fixture data is NEVER committed to this repository. It is downloaded on demand
/// into third_party/which-distro-os-release/ which is .gitignore'd.
///
/// Usage: call <see cref="TryGetRoot"/> from a test. Returns null (and skips) when
/// neither the local cache nor a git clone is possible.
/// </summary>
internal static class GplFixtureDownloader
{
    private const string RepoUrl = "https://github.com/which-distro/os-release.git";
    private const string RelativePath = "third_party/which-distro-os-release";

    private static string? _cachedRoot;
    private static bool _alreadyTried;

    /// <summary>
    /// Returns the root path of the which-distro/os-release fixture directory,
    /// cloning it on demand if absent. Returns <c>null</c> if unavailable (e.g. offline).
    /// </summary>
    public static string? TryGetRoot()
    {
        if (_alreadyTried)
        {
            return _cachedRoot;
        }

        _alreadyTried = true;
        _cachedRoot = ResolveOrClone();
        return _cachedRoot;
    }

    /// <summary>
    /// Returns the os-release file path for a given distro directory and version,
    /// e.g. ("ubuntu", "22.04") → ".../ubuntu/22.04".
    /// </summary>
    public static string? TryGetOsReleasePath(string distroDir, string version)
    {
        var root = TryGetRoot();
        if (root is null) return null;

        var path = Path.Combine(root, distroDir, version);
        return File.Exists(path) ? path : null;
    }

    /// <summary>
    /// Returns the latest (lexicographically highest) version file under a distro
    /// directory, optionally inside a variant sub-directory.
    /// </summary>
    public static string? TryGetLatestOsReleasePath(string distroDir, string? variantDir = null)
    {
        var root = TryGetRoot();
        if (root is null) return null;

        var searchDir = variantDir is not null
            ? Path.Combine(root, distroDir, variantDir)
            : Path.Combine(root, distroDir);

        if (!Directory.Exists(searchDir)) return null;

        var latest = Directory.GetFiles(searchDir)
            .OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        return latest;
    }

    // ── private ─────────────────────────────────────────────────────────────

    private static string? ResolveOrClone()
    {
        var existing = FindExistingRoot();
        if (existing is not null) return existing;

        var solutionDir = FindSolutionDirectory();
        if (solutionDir is null) return null;

        var targetDir = Path.GetFullPath(Path.Combine(solutionDir, RelativePath));

        try
        {
            if (!RunGit("clone", "--depth", "1", RepoUrl, targetDir))
            {
                return null;
            }

            return Directory.Exists(targetDir) ? targetDir : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? FindExistingRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            var candidate = Path.Combine(dir, RelativePath);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            if (File.Exists(Path.Combine(dir, "ContainerRuntimeProbe.sln")))
            {
                break; // found solution root but no fixture dir → stop searching upward
            }

            dir = Path.GetDirectoryName(dir);
        }

        return null;
    }

    private static string? FindSolutionDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "ContainerRuntimeProbe.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }

    private static bool RunGit(params string[] args)
    {
        var psi = new ProcessStartInfo("git")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi);
        if (process is null) return false;

        process.WaitForExit(120_000);
        return process.ExitCode == 0;
    }
}
