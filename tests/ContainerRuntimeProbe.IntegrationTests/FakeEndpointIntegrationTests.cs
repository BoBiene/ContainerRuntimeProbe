using System.Net;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;

namespace ContainerRuntimeProbe.IntegrationTests;

public sealed class FakeEndpointIntegrationTests
{
    [Fact]
    public async Task CloudMetadataProbe_UsesFakeAzureEndpoint()
    {
        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var cts = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    await using var sw = new StreamWriter(ctx.Response.OutputStream);
                    await sw.WriteAsync("{}");
                    ctx.Response.Close();
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (HttpListenerException)
                {
                    break;
                }
            }
        });

        var probe = new CloudMetadataProbe();
        var ctxProbe = new ProbeContext(TimeSpan.FromSeconds(1), false, null, null, new Uri($"http://127.0.0.1:{port}"), new Uri($"http://127.0.0.1:{port}"), new Uri($"http://127.0.0.1:{port}"), new Uri($"http://127.0.0.1:{port}"), CancellationToken.None);
        var result = await probe.ExecuteAsync(ctxProbe);

        Assert.Contains(result.Evidence, e => e.Key == "azure.imds.outcome");
        cts.Cancel();
        listener.Stop();
        await server;
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }
}
