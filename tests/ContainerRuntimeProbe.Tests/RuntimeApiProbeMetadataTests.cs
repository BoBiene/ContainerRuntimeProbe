using ContainerRuntimeProbe.Abstractions;
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
}
