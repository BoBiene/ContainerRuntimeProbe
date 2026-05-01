using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal sealed class WindowsTpmProbe : IProbe
{
    internal const string ProbeId = "windows-trust";

    private readonly Func<bool> _isWindows;
    private readonly Func<WindowsTpmDeviceInfo> _getDeviceInfo;

    public string Id => ProbeId;

    public WindowsTpmProbe()
        : this(
            () => OperatingSystem.IsWindows(),
            () => OperatingSystem.IsWindows()
                ? ReadDeviceInfoIfSupported()
                : new WindowsTpmDeviceInfo(ProbeOutcome.NotSupported, null, null, null, "Windows TPM signals are not available on this platform."))
    {
    }

    internal WindowsTpmProbe(
        Func<bool> isWindows,
        Func<WindowsTpmDeviceInfo> getDeviceInfo)
    {
        _isWindows = isWindows;
        _getDeviceInfo = getDeviceInfo;
    }

    public Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();

        if (!_isWindows())
        {
            sw.Stop();
            return Task.FromResult(new ProbeResult(Id, ProbeOutcome.NotSupported, [], "Windows TPM signals are not available on this platform.", sw.Elapsed));
        }

        var deviceInfo = _getDeviceInfo();
        var evidence = new List<EvidenceItem>
        {
            new(Id, "trust.windows.tpm.outcome", deviceInfo.Outcome.ToString())
        };

        AddEvidenceIfPresent(evidence, Id, "trust.windows.tpm.version", deviceInfo.Version);
        AddEvidenceIfPresent(evidence, Id, "trust.windows.tpm.interface_type", deviceInfo.InterfaceType);
        AddEvidenceIfPresent(evidence, Id, "trust.windows.tpm.implementation_revision", deviceInfo.ImplementationRevision);

        sw.Stop();
        return Task.FromResult(new ProbeResult(Id, deviceInfo.Outcome, evidence, deviceInfo.Message, sw.Elapsed));
    }

    private static void AddEvidenceIfPresent(List<EvidenceItem> evidence, string probeId, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem(probeId, key, value.Trim()));
        }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsTpmDeviceInfo ReadDeviceInfoIfSupported()
    {
        try
        {
            var result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TpmDeviceInfoNative>(), out var native);
            if (result != 0)
            {
                return new WindowsTpmDeviceInfo(ProbeOutcome.Unavailable, null, null, null, $"Windows TPM device info is unavailable (TBS 0x{result:X8}).");
            }

            return new WindowsTpmDeviceInfo(
                ProbeOutcome.Success,
                MapTpmVersion(native.TpmVersion),
                native.TpmInterfaceType.ToString(System.Globalization.CultureInfo.InvariantCulture),
                $"0x{native.TpmImpRevision:X8}");
        }
        catch (DllNotFoundException)
        {
            return new WindowsTpmDeviceInfo(ProbeOutcome.NotSupported, null, null, null, "Windows TPM base services are not available on this host.");
        }
        catch (EntryPointNotFoundException)
        {
            return new WindowsTpmDeviceInfo(ProbeOutcome.NotSupported, null, null, null, "Windows TPM device information is not supported on this host.");
        }
        catch (Exception ex)
        {
            return new WindowsTpmDeviceInfo(ProbeOutcome.Error, null, null, null, ex.Message);
        }
    }

    private static string? MapTpmVersion(uint version)
        => version switch
        {
            1 => "1.2",
            2 => "2.0",
            _ => version == 0 ? null : version.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

    [DllImport("tbs.dll", ExactSpelling = true)]
    private static extern uint Tbsi_GetDeviceInfo(uint size, out TpmDeviceInfoNative info);

    [StructLayout(LayoutKind.Sequential)]
    private struct TpmDeviceInfoNative
    {
        public uint StructVersion;
        public uint TpmVersion;
        public uint TpmInterfaceType;
        public uint TpmImpRevision;
    }
}

internal sealed record WindowsTpmDeviceInfo(
    ProbeOutcome Outcome,
    string? Version,
    string? InterfaceType,
    string? ImplementationRevision,
    string? Message = null);