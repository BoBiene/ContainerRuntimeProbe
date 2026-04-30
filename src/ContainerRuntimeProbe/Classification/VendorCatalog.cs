using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal enum VendorCatalogEntryStatus
{
    VerifiedFromUserSample,
    VerifiedFromPublicSource,
    Candidate
}

internal sealed record VendorCatalogEntry(
    PlatformVendorKind Vendor,
    VendorCatalogEntryStatus Status,
    IReadOnlyList<string> EvidenceKeys,
    IReadOnlyList<string> MatchFragments);

internal static class VendorCatalog
{
    internal static readonly IReadOnlyList<string> SynologyHardwareEvidenceKeys =
    [
        "kernel.syno_hw_version",
        "dmi.sys_vendor",
        "dmi.board_vendor",
        "dmi.product_name",
        "dmi.board_name",
        "dmi.modalias"
    ];

    internal static readonly IReadOnlyList<string> ExplicitHardwareEvidenceKeys =
    [
        "dmi.sys_vendor",
        "dmi.board_vendor",
        "dmi.product_name",
        "dmi.board_name",
        "dmi.product_family",
        "dmi.chassis_vendor",
        "dmi.modalias",
        "device_tree.model",
        "device_tree.compatible",
        "platform.modalias",
        "platform.of_compatible"
    ];

    internal static readonly IReadOnlyList<VendorCatalogEntry> HardwareVendors =
    [
        new(PlatformVendorKind.Synology, VendorCatalogEntryStatus.VerifiedFromUserSample, SynologyHardwareEvidenceKeys, ["synology", "diskstation", "rackstation", "flashstation", "svnsynologyinc."]),
        new(PlatformVendorKind.Siemens, VendorCatalogEntryStatus.VerifiedFromPublicSource, ExplicitHardwareEvidenceKeys, ["siemens", "simatic"]),
        new(PlatformVendorKind.Wago, VendorCatalogEntryStatus.VerifiedFromUserSample, ExplicitHardwareEvidenceKeys, ["wago"]),
        new(PlatformVendorKind.Beckhoff, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["beckhoff"]),
        new(PlatformVendorKind.PhoenixContact, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["phoenix contact", "phoenixcontact", "plcnext"]),
        new(PlatformVendorKind.Advantech, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["advantech"]),
        new(PlatformVendorKind.Moxa, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["moxa", "moxart"]),
        new(PlatformVendorKind.BoschRexroth, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["bosch rexroth", "boschrexroth", "rexroth", "ctrlx"]),
        new(PlatformVendorKind.SchneiderElectric, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["schneider electric", "schneiderelectric", "modicon"]),
        new(PlatformVendorKind.BAndR, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["b&r", "bernecker", "rainer", "br automation", "brautomation"]),
        new(PlatformVendorKind.Opto22, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["opto 22", "opto22", "groov epic"]),
        new(PlatformVendorKind.Stratus, VendorCatalogEntryStatus.Candidate, ExplicitHardwareEvidenceKeys, ["stratus", "ztc edge", "stratus ztc edge"])
    ];

    internal static IReadOnlyList<VendorCatalogEntry> RuntimeActiveHardwareVendors { get; } =
        HardwareVendors
            .Where(entry => entry.Status is VendorCatalogEntryStatus.VerifiedFromPublicSource or VendorCatalogEntryStatus.VerifiedFromUserSample)
            .ToArray();

    internal static IReadOnlyList<VendorCatalogEntry> CandidateHardwareVendors { get; } =
        HardwareVendors
            .Where(entry => entry.Status == VendorCatalogEntryStatus.Candidate)
            .ToArray();
}