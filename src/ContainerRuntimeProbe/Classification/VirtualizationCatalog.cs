using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal sealed record VirtualizationCatalogEntry(
    VirtualizationKind Kind,
    string PlatformVendor,
    IReadOnlyList<string> DmiEvidenceKeys,
    IReadOnlyList<string> MatchFragments,
    IReadOnlyList<string> SupportingEvidenceKeys);

internal static class VirtualizationCatalog
{
    internal static readonly IReadOnlyList<string> HypervisorPresenceEvidenceKeys =
    [
        "cpu.flag.hypervisor",
        "sys.hypervisor.type",
        "bus.vmbus.present"
    ];

    internal static readonly IReadOnlyList<string> HyperVSupportingEvidenceKeys =
    [
        "bus.vmbus.present",
        "module.hv_vmbus.loaded",
        "module.hv_utils.loaded",
        "module.hv_storvsc.loaded",
        "module.hv_netvsc.loaded",
        "module.hv_balloon.loaded",
        "module.hid_hyperv.loaded"
    ];

    internal static readonly IReadOnlyList<string> VMwareSupportingEvidenceKeys =
    [
        "module.vmw_vmci.loaded",
        "module.vmxnet3.loaded",
        "module.vmw_pvscsi.loaded",
        "module.vmw_balloon.loaded",
        "module.vmwgfx.loaded"
    ];

    internal static readonly IReadOnlyList<string> VirtualBoxSupportingEvidenceKeys =
    [
        "module.vboxguest.loaded",
        "module.vboxsf.loaded",
        "module.vboxvideo.loaded"
    ];

    internal static readonly IReadOnlyList<string> XenSupportingEvidenceKeys =
    [
        "module.xen_evtchn.loaded",
        "module.xen_blkfront.loaded",
        "module.xen_netfront.loaded"
    ];

    internal static readonly IReadOnlyList<VirtualizationCatalogEntry> Providers =
    [
        new(
            VirtualizationKind.HyperV,
            "Microsoft Hyper-V",
            ["dmi.sys_vendor", "dmi.board_vendor", "dmi.chassis_vendor", "dmi.product_name", "dmi.product_family", "dmi.bios_vendor", "dmi.modalias"],
            ["microsoft", "hyper-v", "virtual machine", "microsoftcorporation"],
            HyperVSupportingEvidenceKeys),
        new(
            VirtualizationKind.VMware,
            "VMware",
            ["dmi.sys_vendor", "dmi.board_vendor", "dmi.chassis_vendor", "dmi.product_name", "dmi.product_family", "dmi.bios_vendor", "dmi.modalias"],
            ["vmware", "vmware virtual platform", "svnvmwareinc.", "esxi"],
            VMwareSupportingEvidenceKeys),
        new(
            VirtualizationKind.VirtualBox,
            "Oracle VirtualBox",
            ["dmi.sys_vendor", "dmi.board_vendor", "dmi.chassis_vendor", "dmi.product_name", "dmi.product_family", "dmi.bios_vendor", "dmi.modalias"],
            ["virtualbox", "innotek"],
            VirtualBoxSupportingEvidenceKeys),
        new(
            VirtualizationKind.Xen,
            "Xen",
            ["dmi.sys_vendor", "dmi.board_vendor", "dmi.chassis_vendor", "dmi.product_name", "dmi.product_family", "dmi.bios_vendor", "dmi.modalias", "sys.hypervisor.type"],
            ["xen", "domu", "hvm domu"],
            XenSupportingEvidenceKeys),
        new(
            VirtualizationKind.Kvm,
            "KVM/QEMU",
            ["dmi.sys_vendor", "dmi.board_vendor", "dmi.chassis_vendor", "dmi.product_name", "dmi.product_family", "dmi.bios_vendor", "dmi.modalias", "sys.hypervisor.type"],
            ["qemu", "kvm"],
            [])
    ];
}