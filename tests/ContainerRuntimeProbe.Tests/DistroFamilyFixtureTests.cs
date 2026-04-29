using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Tests;

/// <summary>
/// Tests <see cref="HostParsing.ParseOsRelease"/> against real os-release files from
/// the which-distro/os-release collection (GPL-2.0-or-later).
///
/// The fixture data is downloaded on demand into third_party/which-distro-os-release/
/// (which is .gitignore'd). In CI environments the download happens automatically via
/// <see cref="GplFixtureDownloader"/>. Tests are skipped when the data is unavailable.
///
/// See: https://github.com/which-distro/os-release
/// </summary>
public sealed class DistroFamilyFixtureTests
{
    // ── RHEL family ──────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("rhel", "9.6", OperatingSystemFamily.RedHatEnterpriseLinux)]
    [InlineData("eurolinux", "9.2", OperatingSystemFamily.RedHatEnterpriseLinux)]
    [InlineData("miraclelinux", "9.4", OperatingSystemFamily.RedHatEnterpriseLinux)]
    [InlineData("scientific", "7.5", OperatingSystemFamily.RedHatEnterpriseLinux)]
    [InlineData("tencentos", "4.2", OperatingSystemFamily.RedHatEnterpriseLinux)]
    [InlineData("clearos", "7", OperatingSystemFamily.RedHatEnterpriseLinux)]
    public void RhelFamilyDistros_MapToRedHatEnterpriseLinux(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── CentOS / Rocky / Alma ────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("centos", "9", OperatingSystemFamily.CentOS)]
    [InlineData("rocky", "9.5", OperatingSystemFamily.RockyLinux)]
    [InlineData("almalinux", "9.6", OperatingSystemFamily.AlmaLinux)]
    public void CentOsFamilyDistros_MapToExpectedFamily(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Fedora & Universal Blue immutable variants ───────────────────────────
    [SkippableTheory]
    [InlineData("fedora", "workstation", "40", OperatingSystemFamily.Fedora)]
    public void FedoraWithVariant_MapsToFedora(string distro, string variant, string version, OperatingSystemFamily expected)
        => AssertFixtureFamilyVariant(distro, variant, version, expected);

    [SkippableTheory]
    [InlineData("bazzite", "40", OperatingSystemFamily.Fedora)]
    [InlineData("bluefin", "41", OperatingSystemFamily.Fedora)]
    [InlineData("fedoraremixforwsl", "31", OperatingSystemFamily.Fedora)]
    public void FedoraImmutableVariants_MapToFedora(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Amazon Linux ─────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("amzn", "2023", OperatingSystemFamily.AmazonLinux)]
    [InlineData("amzn", "2", OperatingSystemFamily.AmazonLinux)]
    public void AmazonLinux_MapsToAmazonLinux(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Ubuntu ───────────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("ubuntu", "24.04", OperatingSystemFamily.Ubuntu)]
    [InlineData("ubuntu", "22.04", OperatingSystemFamily.Ubuntu)]
    [InlineData("zorin", "17", OperatingSystemFamily.Ubuntu)]
    public void UbuntuFamilyDistros_MapToUbuntu(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Debian ───────────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("debian", "debian", OperatingSystemFamily.Debian)]
    [InlineData("kali", "2019.4", OperatingSystemFamily.Debian)]
    [InlineData("raspbian", "8", OperatingSystemFamily.Debian)]
    [InlineData("devuan", "5", OperatingSystemFamily.Debian)]
    [InlineData("parrot", "5.3", OperatingSystemFamily.Debian)]
    [InlineData("pureos", "10.0", OperatingSystemFamily.Debian)]
    public void DebianFamilyDistros_MapToDebian(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Alpine ───────────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("alpine", "3.19.0", OperatingSystemFamily.Alpine)]
    [InlineData("alpine", "3.21.4", OperatingSystemFamily.Alpine)]
    public void Alpine_MapsToAlpine(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Arch ─────────────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("steamos", "3.7.16", OperatingSystemFamily.Arch)]
    [InlineData("endeavouros", "endeavouros", OperatingSystemFamily.Arch)]
    [InlineData("garuda", "garuda", OperatingSystemFamily.Arch)]
    public void ArchFamilyDistros_MapToArch(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── SUSE / openSUSE ──────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("opensuse-leap", "16.0", OperatingSystemFamily.OpenSuse)]
    [InlineData("suse-microos", "5.1", OperatingSystemFamily.OpenSuse)]  // key fix: was Suse before ID-first lookup
    [InlineData("sles", "15.7", OperatingSystemFamily.Suse)]
    public void SuseFamilyDistros_MapToExpectedFamily(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Oracle Linux ─────────────────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("ol", "server", "9.5", OperatingSystemFamily.OracleLinux)]
    public void OracleLinux_MapsToOracleLinux(string distro, string variant, string version, OperatingSystemFamily expected)
        => AssertFixtureFamilyVariant(distro, variant, version, expected);

    // ── Container-optimized / cloud-native ───────────────────────────────────
    [SkippableTheory]
    [InlineData("wolfi", "20230201", OperatingSystemFamily.Wolfi)]
    [InlineData("flatcar", "4459.0.0", OperatingSystemFamily.Flatcar)]
    [InlineData("cos", "97", OperatingSystemFamily.ContainerOptimizedOS)]
    [InlineData("coreos", "766.3.0", OperatingSystemFamily.CoreOS)]
    public void ContainerOptimizedDistros_MapToExpectedFamily(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── New / independent families ───────────────────────────────────────────
    [SkippableTheory]
    [InlineData("nixos", "24.05", OperatingSystemFamily.NixOS)]
    [InlineData("void", "void", OperatingSystemFamily.VoidLinux)]
    [InlineData("gentoo", "gentoo", OperatingSystemFamily.Gentoo)]
    [InlineData("openEuler", "24.03", OperatingSystemFamily.OpenEuler)]
    [InlineData("clear-linux-os", "clear-linux-os", OperatingSystemFamily.ClearLinux)]
    public void IndependentFamilyDistros_MapToExpectedFamily(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Cloud / vendor-specific ───────────────────────────────────────────────
    [SkippableTheory]
    [InlineData("azurelinux", "3.0", OperatingSystemFamily.AzureLinux)]
    [InlineData("mariner", "2.0", OperatingSystemFamily.Mariner)]
    [InlineData("bottlerocket", "1.19.4", OperatingSystemFamily.Bottlerocket)]
    [InlineData("photon", "5.0", OperatingSystemFamily.PhotonOS)]
    public void CloudVendorDistros_MapToExpectedFamily(string distro, string version, OperatingSystemFamily expected)
        => AssertFixtureFamily(distro, version, expected);

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void AssertFixtureFamily(string distro, string version, OperatingSystemFamily expected)
    {
        var path = GplFixtureDownloader.TryGetOsReleasePath(distro, version);
        Skip.If(path is null, $"Fixture not available: {distro}/{version}");

        var content = File.ReadAllText(path!);
        var parsed = HostParsing.ParseOsRelease(content);

        Assert.Equal(expected, parsed.Family);
    }

    private static void AssertFixtureFamilyVariant(string distro, string variant, string version, OperatingSystemFamily expected)
    {
        var root = GplFixtureDownloader.TryGetRoot();
        Skip.If(root is null, "GPL fixture data not available");

        var path = Path.Combine(root!, distro, variant, version);
        Skip.If(!File.Exists(path), $"Fixture not available: {distro}/{variant}/{version}");

        var content = File.ReadAllText(path);
        var parsed = HostParsing.ParseOsRelease(content);

        Assert.Equal(expected, parsed.Family);
    }
}
