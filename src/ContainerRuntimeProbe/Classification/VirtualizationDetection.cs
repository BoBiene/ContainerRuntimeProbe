using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Classification;

internal sealed record VirtualizationDetectionResult(
    VirtualizationKind Kind,
    string? PlatformVendor,
    Confidence Confidence,
    string Summary,
    IReadOnlyList<string> EvidenceReferences);

internal static class VirtualizationDetection
{
    public static VirtualizationDetectionResult? Detect(IReadOnlyList<EvidenceItem> evidence)
    {
        var wslReferences = DetectWsl2(evidence);
        if (wslReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.WSL2,
                "Microsoft",
                Confidence.High,
                "WSL2 kernel fingerprint detected",
                wslReferences);
        }

        var hypervisorReferences = DetectGenericHypervisorSignals(evidence);

        var hyperV = DetectHyperV(evidence, hypervisorReferences);
        if (hyperV is not null)
        {
            return hyperV;
        }

        var vmware = DetectVmware(evidence, hypervisorReferences);
        if (vmware is not null)
        {
            return vmware;
        }

        var virtualBox = DetectVirtualBox(evidence, hypervisorReferences);
        if (virtualBox is not null)
        {
            return virtualBox;
        }

        var xen = DetectXen(evidence, hypervisorReferences);
        if (xen is not null)
        {
            return xen;
        }

        var kvm = DetectKvm(evidence, hypervisorReferences);
        if (kvm is not null)
        {
            return kvm;
        }

        if (hypervisorReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.VirtualMachine,
                GetValue(evidence, "sys.hypervisor.type"),
                Confidence.Medium,
                "Generic hypervisor signals detected but provider is not yet explicit",
                hypervisorReferences);
        }

        return null;
    }

    internal static VirtualizationClassificationKind ToClassificationKind(VirtualizationKind kind)
        => kind switch
        {
            VirtualizationKind.WSL2 => VirtualizationClassificationKind.WSL2,
            VirtualizationKind.HyperV => VirtualizationClassificationKind.HyperV,
            VirtualizationKind.VMware => VirtualizationClassificationKind.VMware,
            VirtualizationKind.VirtualBox => VirtualizationClassificationKind.VirtualBox,
            VirtualizationKind.Xen => VirtualizationClassificationKind.Xen,
            VirtualizationKind.Kvm => VirtualizationClassificationKind.Kvm,
            VirtualizationKind.VirtualMachine => VirtualizationClassificationKind.VirtualMachine,
            _ => VirtualizationClassificationKind.Unknown
        };

    private static IReadOnlyList<string> DetectWsl2(IReadOnlyList<EvidenceItem> evidence)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);

        if (evidence.Any(x => x.Key == "kernel.flavor" && string.Equals(x.Value, "WSL2", StringComparison.OrdinalIgnoreCase)))
        {
            AddEvidenceReferences(references, evidence, "kernel.flavor");
        }

        if (HostParsing.ContainsWsl2Signal(GetValue(evidence, "kernel.release")))
        {
            AddEvidenceReferences(references, evidence, "kernel.release");
        }

        if (HostParsing.ContainsWsl2Signal(GetValue(evidence, "/proc/version")))
        {
            AddEvidenceReferences(references, evidence, "/proc/version");
        }

        return references.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyList<string> DetectGenericHypervisorSignals(IReadOnlyList<EvidenceItem> evidence)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);

        foreach (var key in VirtualizationCatalog.HypervisorPresenceEvidenceKeys)
        {
            if (key == "sys.hypervisor.type")
            {
                if (!string.IsNullOrWhiteSpace(GetValue(evidence, key)))
                {
                    AddEvidenceReferences(references, evidence, key);
                }

                continue;
            }

            if (HasTrueValue(evidence, key))
            {
                AddEvidenceReferences(references, evidence, key);
            }
        }

        return references.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static VirtualizationDetectionResult? DetectHyperV(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> hypervisorReferences)
    {
        var entry = VirtualizationCatalog.Get(VirtualizationKind.HyperV);
        var references = new HashSet<string>(StringComparer.Ordinal);
        var vendorReferences = FindContainingReferences(evidence, entry.VendorEvidenceKeys, entry.VendorFragments);
        var productReferences = FindContainingReferences(evidence, entry.MatchEvidenceKeys, entry.MatchFragments);
        var supportReferences = GetTrueEvidenceReferences(evidence, entry.SupportingEvidenceKeys);

        references.UnionWith(vendorReferences);
        references.UnionWith(productReferences);
        references.UnionWith(supportReferences);

        if (vendorReferences.Count > 0 && (productReferences.Count > 0 || supportReferences.Count > 0))
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.HyperV,
                entry.PlatformVendor,
                Confidence.High,
                "Hyper-V DMI and guest integration signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        if (supportReferences.Count > 0 && hypervisorReferences.Count > 0)
        {
            references.UnionWith(hypervisorReferences);
            return new VirtualizationDetectionResult(
                VirtualizationKind.HyperV,
                entry.PlatformVendor,
                Confidence.Medium,
                "Hyper-V guest integration signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return null;
    }

    private static VirtualizationDetectionResult? DetectVmware(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> hypervisorReferences)
    {
        var entry = VirtualizationCatalog.Get(VirtualizationKind.VMware);
        var references = new HashSet<string>(StringComparer.Ordinal);
        var dmiReferences = FindContainingReferences(evidence, entry.MatchEvidenceKeys, entry.MatchFragments);
        var supportReferences = GetTrueEvidenceReferences(evidence, entry.SupportingEvidenceKeys);

        references.UnionWith(dmiReferences);
        references.UnionWith(supportReferences);

        if (dmiReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.VMware,
                ContainsFragment(evidence, entry.MatchEvidenceKeys, ["esxi"]) ? "VMware ESXi" : entry.PlatformVendor,
                Confidence.High,
                "VMware DMI signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        if (supportReferences.Count > 0 && hypervisorReferences.Count > 0)
        {
            references.UnionWith(hypervisorReferences);
            return new VirtualizationDetectionResult(
                VirtualizationKind.VMware,
                entry.PlatformVendor,
                Confidence.Medium,
                "VMware guest driver signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return null;
    }

    private static VirtualizationDetectionResult? DetectVirtualBox(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> hypervisorReferences)
    {
        var entry = VirtualizationCatalog.Get(VirtualizationKind.VirtualBox);
        var references = new HashSet<string>(StringComparer.Ordinal);
        var dmiReferences = FindContainingReferences(evidence, entry.MatchEvidenceKeys, entry.MatchFragments);
        var supportReferences = GetTrueEvidenceReferences(evidence, entry.SupportingEvidenceKeys);

        references.UnionWith(dmiReferences);
        references.UnionWith(supportReferences);

        if (dmiReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.VirtualBox,
                entry.PlatformVendor,
                Confidence.High,
                "VirtualBox DMI signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        if (supportReferences.Count > 0 && hypervisorReferences.Count > 0)
        {
            references.UnionWith(hypervisorReferences);
            return new VirtualizationDetectionResult(
                VirtualizationKind.VirtualBox,
                entry.PlatformVendor,
                Confidence.Medium,
                "VirtualBox guest addition signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return null;
    }

    private static VirtualizationDetectionResult? DetectXen(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> hypervisorReferences)
    {
        var entry = VirtualizationCatalog.Get(VirtualizationKind.Xen);
        var references = new HashSet<string>(StringComparer.Ordinal);
        var hypervisorTypeReferences = FindContainingReferences(evidence, ["sys.hypervisor.type"], ["xen"]);
        var dmiReferences = FindContainingReferences(
            evidence,
            entry.MatchEvidenceKeys.Where(key => key != "sys.hypervisor.type").ToArray(),
            entry.MatchFragments);
        var supportReferences = GetTrueEvidenceReferences(evidence, entry.SupportingEvidenceKeys);

        references.UnionWith(hypervisorTypeReferences);
        references.UnionWith(dmiReferences);
        references.UnionWith(supportReferences);

        if (hypervisorTypeReferences.Count > 0 || dmiReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.Xen,
                entry.PlatformVendor,
                Confidence.High,
                "Xen hypervisor signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        if (supportReferences.Count > 0 && hypervisorReferences.Count > 0)
        {
            references.UnionWith(hypervisorReferences);
            return new VirtualizationDetectionResult(
                VirtualizationKind.Xen,
                entry.PlatformVendor,
                Confidence.Medium,
                "Xen guest driver signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return null;
    }

    private static VirtualizationDetectionResult? DetectKvm(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> hypervisorReferences)
    {
        var entry = VirtualizationCatalog.Get(VirtualizationKind.Kvm);
        var references = new HashSet<string>(StringComparer.Ordinal);
        var hypervisorTypeReferences = FindContainingReferences(evidence, ["sys.hypervisor.type"], ["kvm"]);
        var dmiReferences = FindContainingReferences(
            evidence,
            entry.MatchEvidenceKeys.Where(key => key != "sys.hypervisor.type").ToArray(),
            entry.MatchFragments);

        references.UnionWith(hypervisorTypeReferences);
        references.UnionWith(dmiReferences);

        if (dmiReferences.Count > 0 || hypervisorTypeReferences.Count > 0)
        {
            return new VirtualizationDetectionResult(
                VirtualizationKind.Kvm,
                ContainsFragment(evidence, entry.MatchEvidenceKeys, ["qemu"])
                    ? "QEMU"
                    : entry.PlatformVendor,
                dmiReferences.Count > 0 ? Confidence.High : Confidence.Medium,
                "KVM/QEMU hypervisor signals detected",
                references.OrderBy(value => value, StringComparer.Ordinal).ToArray());
        }

        return null;
    }

    private static bool HasTrueValue(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.Any(item => item.Key == key && string.Equals(item.Value, bool.TrueString, StringComparison.OrdinalIgnoreCase));

    private static string? GetValue(IReadOnlyList<EvidenceItem> evidence, string key)
        => evidence.FirstOrDefault(item => item.Key == key)?.Value;

    private static bool ContainsFragment(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> keys, IReadOnlyList<string> fragments)
        => evidence.Any(item => keys.Contains(item.Key, StringComparer.Ordinal)
            && !string.IsNullOrWhiteSpace(item.Value)
            && fragments.Any(fragment => item.Value.Contains(fragment, StringComparison.OrdinalIgnoreCase)));

    private static IReadOnlyList<string> FindContainingReferences(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> keys, IReadOnlyList<string> fragments)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);

        foreach (var item in evidence.Where(item => keys.Contains(item.Key, StringComparer.Ordinal)))
        {
            if (string.IsNullOrWhiteSpace(item.Value))
            {
                continue;
            }

            if (fragments.Any(fragment => item.Value.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
            {
                references.Add($"{item.ProbeId}:{item.Key}");
            }
        }

        return references.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyList<string> GetTrueEvidenceReferences(IReadOnlyList<EvidenceItem> evidence, IReadOnlyList<string> keys)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);

        foreach (var key in keys)
        {
            if (HasTrueValue(evidence, key))
            {
                AddEvidenceReferences(references, evidence, key);
            }
        }

        return references.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static void AddEvidenceReferences(HashSet<string> references, IReadOnlyList<EvidenceItem> evidence, string key)
    {
        foreach (var item in evidence.Where(item => item.Key == key))
        {
            references.Add($"{item.ProbeId}:{item.Key}");
        }
    }
}