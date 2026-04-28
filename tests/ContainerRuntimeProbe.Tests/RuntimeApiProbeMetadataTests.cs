using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class RuntimeApiProbeMetadataTests
{
    [Fact]
    public void ExtractPodmanInfoEvidence_ParsesRemoteServiceAndSocketPath()
    {
        const string json = """
            {
              "host": {
                "arch": "arm64",
                "kernel": "6.6.10-linuxkit",
                "cpus": 10,
                "memTotal": 17179869184,
                "serviceIsRemote": true,
                "remoteSocket": {
                  "path": "/run/user/1000/podman/podman.sock"
                },
                "distribution": {
                  "distribution": "fedora",
                  "version": "40"
                }
              }
            }
            """;

        var evidence = RuntimeApiProbe.ExtractPodmanInfoEvidence("runtime-api", json);

        Assert.Contains(evidence, item => item.Key == "podman.info.architecture" && item.Value == "arm64");
        Assert.Contains(evidence, item => item.Key == "podman.info.service_is_remote" && item.Value == bool.TrueString);
        Assert.Contains(evidence, item => item.Key == "podman.info.remote_socket_path" && item.Value == "/run/user/1000/podman/podman.sock");
        Assert.Contains(evidence, item => item.Key == "podman.info.distribution" && item.Value == "fedora 40");
    }

    [Fact]
    public void ExtractPodmanInfoEvidence_MissingHost_ReturnsEmpty()
    {
        const string json = "{ \"version\": { \"Version\": \"5.0\" } }";

        var evidence = RuntimeApiProbe.ExtractPodmanInfoEvidence("runtime-api", json);

        Assert.Empty(evidence);
    }

    [Fact]
    public void CreateNetworkClient_SharedPool_ReusesHandlersPerBaseAddress()
    {
        var baseline = HttpProbe.SharedNetworkHandlerCount;

        using var aws = HttpProbe.CreateNetworkClient(new Uri("http://169.254.169.254"), TimeSpan.FromSeconds(1), shareConnectionPool: true);
        using var azure = HttpProbe.CreateNetworkClient(new Uri("http://169.254.169.254"), TimeSpan.FromSeconds(1), shareConnectionPool: true);
        using var oci = HttpProbe.CreateNetworkClient(new Uri("http://169.254.169.254"), TimeSpan.FromSeconds(1), shareConnectionPool: true);
        using var gcp = HttpProbe.CreateNetworkClient(new Uri("http://metadata.google.internal"), TimeSpan.FromSeconds(1), shareConnectionPool: true);

        Assert.Equal(baseline + 2, HttpProbe.SharedNetworkHandlerCount);
        Assert.Equal(new Uri("http://169.254.169.254"), aws.BaseAddress);
        Assert.Equal(new Uri("http://169.254.169.254"), azure.BaseAddress);
        Assert.Equal(new Uri("http://169.254.169.254"), oci.BaseAddress);
        Assert.Equal(new Uri("http://metadata.google.internal"), gcp.BaseAddress);
    }
}
