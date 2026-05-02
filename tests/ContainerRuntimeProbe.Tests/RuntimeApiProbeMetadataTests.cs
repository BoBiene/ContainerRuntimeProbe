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

    [Fact]
    public void ExtractFromInspectJson_ExtractsComposeStackAndPortainerLabels()
    {
        const string json = """
            {
              "Id": "0123456789abcdef",
              "Config": {
                "Labels": {
                  "com.docker.compose.project": "edge-stack",
                  "com.docker.stack.namespace": "edge-stack-swarm",
                  "io.portainer.stack.name": "portainer-edge",
                  "io.portainer.endpoint.id": "5",
                  "unrelated.label": "ignored"
                }
              }
            }
            """;

        var evidence = ComposeLabels.ExtractFromInspectJson("runtime-api", json).ToArray();

        Assert.Contains(evidence, item => item.Key == "container.id" && item.Value == "0123456789abcdef");
        Assert.Contains(evidence, item => item.Key == "compose.label.com.docker.compose.project" && item.Value == "edge-stack");
        Assert.Contains(evidence, item => item.Key == "compose.label.com.docker.stack.namespace" && item.Value == "edge-stack-swarm");
        Assert.Contains(evidence, item => item.Key == "compose.label.io.portainer.stack.name" && item.Value == "portainer-edge");
        Assert.Contains(evidence, item => item.Key == "compose.label.io.portainer.endpoint.id" && item.Value == "5");
        Assert.DoesNotContain(evidence, item => item.Key == "compose.label.unrelated.label");
    }
}
