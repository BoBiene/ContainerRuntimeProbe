using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.Tests;

public sealed class CloudMetadataProbeTests
{
    [Fact]
    public void CreateClientPool_ReusesClientsForEquivalentBaseAddresses()
    {
        var clientPool = CloudMetadataProbe.CreateClientPool(
        [
            new Uri("http://169.254.169.254"),
            new Uri("http://169.254.169.254/"),
            new Uri("http://metadata.google.internal")
        ],
        TimeSpan.FromSeconds(1));

        try
        {
            Assert.Equal(2, clientPool.Count);
            Assert.Contains("http://169.254.169.254/", clientPool.Keys);
            Assert.Contains("http://metadata.google.internal/", clientPool.Keys);
        }
        finally
        {
            foreach (var client in clientPool.Values)
            {
                client.Dispose();
            }
        }
    }
}