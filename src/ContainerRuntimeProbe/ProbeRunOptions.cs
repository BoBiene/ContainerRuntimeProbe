namespace ContainerRuntimeProbe;

/// <summary>Optional overrides for probe execution endpoints and security behavior.</summary>
public sealed record ProbeRunOptions(
    Uri? KubernetesApiBase = null,
    Uri? AwsImdsBase = null,
    Uri? AzureImdsBase = null,
    Uri? GcpMetadataBase = null,
    Uri? OciMetadataBase = null,
    bool KubernetesSkipTlsValidation = false);
