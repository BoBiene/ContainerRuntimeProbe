using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class KubernetesProbeTlsTests
{
    [Fact]
    public void CreateHttpClientHandler_CompatibilityMode_SkipsCertificateValidation()
    {
        using var handler = KubernetesProbe.CreateHttpClientHandler(KubernetesTlsVerificationMode.Compatibility);

        Assert.NotNull(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void CreateHttpClientHandler_StrictMode_UsesPlatformValidation()
    {
        using var handler = KubernetesProbe.CreateHttpClientHandler(KubernetesTlsVerificationMode.Strict);

        Assert.Null(handler.ServerCertificateCustomValidationCallback);
    }
}