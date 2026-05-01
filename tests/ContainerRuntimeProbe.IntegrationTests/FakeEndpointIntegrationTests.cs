using System.Net;
using System.Text;
using System.Diagnostics;
using ContainerRuntimeProbe.Model;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Probes;
using ContainerRuntimeProbe.Rendering;

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
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }
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

    [Fact]
    public async Task Engine_RunAsync_UsesConfiguredCloudMetadataOverrides()
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
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }
            }
        });

        try
        {
            var engine = new ContainerRuntimeProbeEngine([new CloudMetadataProbe()]);
            var report = await engine.RunAsync(
                TimeSpan.FromSeconds(1),
                includeSensitive: false,
                new ProbeExecutionOptions
                {
                    EnabledProbes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "cloud-metadata" },
                    AwsImdsBase = new Uri($"http://127.0.0.1:{port}"),
                    AzureImdsBase = new Uri($"http://127.0.0.1:{port}"),
                    GcpMetadataBase = new Uri($"http://127.0.0.1:{port}"),
                    OciMetadataBase = new Uri($"http://127.0.0.1:{port}")
                });

            Assert.Contains(report.Probes.SelectMany(probe => probe.Evidence), e => e.Key == "azure.imds.outcome");
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task CloudMetadataProbe_FansOutMetadataRequestsConcurrently()
    {
        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pendingRequests = new List<Task>();
        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var ctx = await listener.GetContextAsync();
                    pendingRequests.Add(HandleCloudMetadataRequestAsync(ctx));
                }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }
            }

            await Task.WhenAll(pendingRequests);
        });

        try
        {
            var probe = new CloudMetadataProbe();
            var probeContext = new ProbeContext(
                TimeSpan.FromSeconds(5),
                false,
                null,
                null,
                new Uri($"http://127.0.0.1:{port}"),
                new Uri($"http://127.0.0.1:{port}"),
                new Uri($"http://127.0.0.1:{port}"),
                new Uri($"http://127.0.0.1:{port}"),
                CancellationToken.None);

            var stopwatch = Stopwatch.StartNew();
            var result = await probe.ExecuteAsync(probeContext);
            stopwatch.Stop();

            Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(1200), $"Expected concurrent fan-out, got {stopwatch.Elapsed}.");
            Assert.Contains(result.Evidence, e => e.Key == "aws.imds.identity.outcome" && e.Value == "Success");
            Assert.Contains(result.Evidence, e => e.Key == "aws.instance_id" && e.Value == "i-0abc123def4567890");
            Assert.Contains(result.Evidence, e => e.Key == "azure.imds.outcome" && e.Value == "Success");
            Assert.Contains(result.Evidence, e => e.Key == "azure.vm_id" && e.Value == "5d77f1f6-4e57-4d8c-9f9e-9fd8e67f21d2");
            Assert.Contains(result.Evidence, e => e.Key == "gcp.metadata.outcome" && e.Value == "Success");
            Assert.Contains(result.Evidence, e => e.Key == "gcp.instance_id" && e.Value == "9876543210123456789");
            Assert.Contains(result.Evidence, e => e.Key == "oci.metadata.outcome" && e.Value == "Success");
            Assert.Contains(result.Evidence, e => e.Key == "oci.instance_id" && e.Value == "ocid1.instance.oc1.eu-frankfurt-1.exampleuniqueid");
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await server;
        }
    }

    // ── Compose label extraction unit tests (no HTTP, pure JSON parsing) ─────

    [Fact]
    public void ComposeLabels_ExtractFromInspectJson_ReturnsKnownLabels()
    {
        const string json = """
            {
              "Config": {
                "Labels": {
                  "com.docker.compose.project": "myproject",
                  "com.docker.compose.service": "web",
                  "com.docker.compose.version": "2.24.0",
                  "com.docker.compose.container-number": "1",
                  "com.example.custom": "should-be-ignored"
                }
              }
            }
            """;

        var items = ComposeLabels.ExtractFromInspectJson("runtime-api", json).ToList();

        Assert.Contains(items, e => e.Key == "compose.label.com.docker.compose.project" && e.Value == "myproject");
        Assert.Contains(items, e => e.Key == "compose.label.com.docker.compose.service" && e.Value == "web");
        Assert.Contains(items, e => e.Key == "compose.label.com.docker.compose.version" && e.Value == "2.24.0");
        Assert.Contains(items, e => e.Key == "compose.label.com.docker.compose.container-number" && e.Value == "1");
        // Unknown labels must NOT be emitted
        Assert.DoesNotContain(items, e => e.Key.Contains("custom"));
    }

    [Fact]
    public void ComposeLabels_ExtractFromInspectJson_NoLabels_ReturnsEmpty()
    {
        const string json = """{"Config":{"Labels":{}}}""";
        var items = ComposeLabels.ExtractFromInspectJson("runtime-api", json).ToList();
        Assert.Empty(items);
    }

    [Fact]
    public void ComposeLabels_ExtractFromInspectJson_NoConfigSection_ReturnsEmpty()
    {
        const string json = """{"Id":"abc123"}""";
        var items = ComposeLabels.ExtractFromInspectJson("runtime-api", json).ToList();
        Assert.Empty(items);
    }

    [Fact]
    public void ComposeLabels_ExtractFromInspectJson_InvalidJson_ReturnsEmpty()
    {
        var items = ComposeLabels.ExtractFromInspectJson("runtime-api", "not-json{{").ToList();
        Assert.Empty(items);
    }

    [Fact]
    public void ComposeLabels_ExtractFromInspectJson_LongPathValue_IsTruncatedAt256()
    {
        var longPath = new string('/', 300);
        var json = $"{{\"Config\":{{\"Labels\":{{\"com.docker.compose.project.working_dir\":\"{longPath}\"}}}}}}";
        var items = ComposeLabels.ExtractFromInspectJson("runtime-api", json).ToList();
        Assert.Single(items);
        Assert.Equal(256, items[0].Value?.Length);
    }

    // ── Kubernetes probe integration test ─────────────────────────────────────

    [Fact]
    public async Task KubernetesProbe_FakeServer_ApiVersionSuccess()
    {
        // Arrange: create temp service-account files
        var tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tmpDir);
        var tokenFile = Path.Combine(tmpDir, "token");
        var nsFile = Path.Combine(tmpDir, "namespace");
        await File.WriteAllTextAsync(tokenFile, "fake-bearer-token");
        await File.WriteAllTextAsync(nsFile, "test-namespace");

        // Start a fake HTTP server that returns a synthetic /version response
        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }

                var path = ctx.Request.Url?.AbsolutePath ?? "";
                int statusCode;
                string body;

                if (path == "/version")
                {
                    statusCode = 200;
                    body = """{"major":"1","minor":"28","gitVersion":"v1.28.0"}""";
                }
                else if (path.StartsWith("/api/v1/namespaces/"))
                {
                    // Simulate 403 Forbidden for pod lookup (RBAC not granted)
                    statusCode = 403;
                    body = """{"kind":"Status","status":"Failure","reason":"Forbidden"}""";
                }
                else
                {
                    statusCode = 404;
                    body = "{}";
                }

                ctx.Response.StatusCode = statusCode;
                ctx.Response.ContentType = "application/json";
                var bytes = Encoding.UTF8.GetBytes(body);
                await ctx.Response.OutputStream.WriteAsync(bytes, cts.Token);
                ctx.Response.Close();
            }
        });

        try
        {
            var probe = new KubernetesProbe(
                tokenPaths: [tokenFile],
                namespacePaths: [nsFile],
                serviceHostOverride: "127.0.0.1");

            var probeCtx = new ProbeContext(
                Timeout: TimeSpan.FromSeconds(5),
                IncludeSensitive: false,
                EnabledProbes: null,
                KubernetesApiBase: new Uri($"http://127.0.0.1:{port}"),
                AwsImdsBase: null,
                AzureImdsBase: null,
                GcpMetadataBase: null,
                OciMetadataBase: null,
                CancellationToken: CancellationToken.None);

            var result = await probe.ExecuteAsync(probeCtx);

            // ServiceAccount files found
            Assert.Contains(result.Evidence, e => e.Key == "serviceaccount.token" && e.Value == "present");
            Assert.Contains(result.Evidence, e => e.Key == "serviceaccount.namespace" && e.Value == "test-namespace");

            // /version succeeded
            Assert.Contains(result.Evidence, e => e.Key == "api.version.outcome" && e.Value == "Success");
            Assert.Contains(result.Evidence, e => e.Key == "api.version.body" && e.Value!.Contains("v1.28"));

            // Probe must complete without throwing; overall outcome is Success
            Assert.Equal(ProbeOutcome.Success, result.Outcome);

            // Pod lookup (if HOSTNAME is set in this environment) should be mapped as evidence, not throw
            var podOutcome = result.Evidence.FirstOrDefault(e => e.Key == "api.pod.outcome");
            if (podOutcome is not null)
            {
                // 403 from fake server should map to AccessDenied, not an exception
                Assert.Equal("AccessDenied", podOutcome.Value);
            }
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await server;
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public async Task KubernetesProbe_FakeServer_UnauthorizedMappedAsEvidence()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tmpDir);
        var tokenFile = Path.Combine(tmpDir, "token");
        var nsFile = Path.Combine(tmpDir, "namespace");
        await File.WriteAllTextAsync(tokenFile, "expired-token");
        await File.WriteAllTextAsync(nsFile, "default");

        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }

                // Always return 401 Unauthorized
                ctx.Response.StatusCode = 401;
                ctx.Response.ContentType = "application/json";
                var bytes = Encoding.UTF8.GetBytes("""{"kind":"Status","reason":"Unauthorized"}""");
                await ctx.Response.OutputStream.WriteAsync(bytes, cts.Token);
                ctx.Response.Close();
            }
        });

        try
        {
            var probe = new KubernetesProbe(
                tokenPaths: [tokenFile],
                namespacePaths: [nsFile],
                serviceHostOverride: "127.0.0.1");

            var probeCtx = new ProbeContext(
                Timeout: TimeSpan.FromSeconds(5),
                IncludeSensitive: false,
                EnabledProbes: null,
                KubernetesApiBase: new Uri($"http://127.0.0.1:{port}"),
                AwsImdsBase: null,
                AzureImdsBase: null,
                GcpMetadataBase: null,
                OciMetadataBase: null,
                CancellationToken: CancellationToken.None);

            var result = await probe.ExecuteAsync(probeCtx);

            // Probe must not throw; 401 is mapped to AccessDenied evidence
            Assert.Contains(result.Evidence, e => e.Key == "api.version.outcome" && e.Value == "AccessDenied");
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await server;
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public async Task KubernetesProbe_FakeServer_EmitsStableNodeIdentityEvidence()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tmpDir);
        var tokenFile = Path.Combine(tmpDir, "token");
        var nsFile = Path.Combine(tmpDir, "namespace");
        await File.WriteAllTextAsync(tokenFile, "fake-bearer-token");
        await File.WriteAllTextAsync(nsFile, "test-namespace");

        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var previousHostName = Environment.GetEnvironmentVariable("HOSTNAME");
        Environment.SetEnvironmentVariable("HOSTNAME", "test-pod");

        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }

                var path = ctx.Request.Url?.AbsolutePath ?? string.Empty;
                int statusCode;
                string body;

                if (path == "/version")
                {
                    statusCode = 200;
                    body = """{"major":"1","minor":"28","gitVersion":"v1.28.0"}""";
                }
                else if (path == "/api/v1/namespaces/test-namespace/pods/test-pod")
                {
                    statusCode = 200;
                    body = """
                        {"spec":{"nodeName":"worker-a"}}
                        """;
                }
                else if (path == "/api/v1/nodes/worker-a")
                {
                    statusCode = 200;
                    body = """
                        {
                          "metadata":{"uid":"8e5fd1d0-6245-4ff8-b22f-7a3e1b10d111"},
                          "spec":{"providerID":"azure:///subscriptions/demo/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/aks-worker-a"},
                          "status":{"nodeInfo":{"osImage":"Ubuntu 24.04.4 LTS","kernelVersion":"6.6.10-generic","operatingSystem":"linux","architecture":"amd64","containerRuntimeVersion":"containerd://2.0.1","kubeletVersion":"v1.31.1"}}
                        }
                        """;
                }
                else
                {
                    statusCode = 404;
                    body = "{}";
                }

                ctx.Response.StatusCode = statusCode;
                ctx.Response.ContentType = "application/json";
                var bytes = Encoding.UTF8.GetBytes(body);
                await ctx.Response.OutputStream.WriteAsync(bytes, cts.Token);
                ctx.Response.Close();
            }
        });

        try
        {
            var probe = new KubernetesProbe(
                tokenPaths: [tokenFile],
                namespacePaths: [nsFile],
                serviceHostOverride: "127.0.0.1");

            var probeCtx = new ProbeContext(
                Timeout: TimeSpan.FromSeconds(5),
                IncludeSensitive: false,
                EnabledProbes: null,
                KubernetesApiBase: new Uri($"http://127.0.0.1:{port}"),
                AwsImdsBase: null,
                AzureImdsBase: null,
                GcpMetadataBase: null,
                OciMetadataBase: null,
                CancellationToken: CancellationToken.None);

            var result = await probe.ExecuteAsync(probeCtx);

            Assert.Contains(result.Evidence, e => e.Key == "kubernetes.node.name" && e.Value == "worker-a");
            Assert.Contains(result.Evidence, e => e.Key == "kubernetes.node.uid" && e.Value == "8e5fd1d0-6245-4ff8-b22f-7a3e1b10d111");
            Assert.Contains(result.Evidence, e => e.Key == "kubernetes.node.provider_id" && e.Value!.Contains("aks-worker-a", StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOSTNAME", previousHostName);
            cts.Cancel();
            listener.Stop();
            await server;
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public async Task KubernetesProbe_NoEnvAndNoToken_ReturnsUnavailable()
    {
        var probe = new KubernetesProbe(
            tokenPaths: ["/nonexistent/token"],
            namespacePaths: ["/nonexistent/namespace"],
            serviceHostOverride: null);

        var probeCtx = new ProbeContext(
            Timeout: TimeSpan.FromSeconds(1),
            IncludeSensitive: false,
            EnabledProbes: null,
            KubernetesApiBase: null,
            AwsImdsBase: null,
            AzureImdsBase: null,
            GcpMetadataBase: null,
            OciMetadataBase: null,
            CancellationToken: CancellationToken.None);

        var result = await probe.ExecuteAsync(probeCtx);
        Assert.Equal(ProbeOutcome.Unavailable, result.Outcome);
    }

    [Fact]
    public async Task Engine_FakeDockerInfoEvidence_MapsHostModel()
    {
        var engine = new ContainerRuntimeProbeEngine(
        [
            new FixedProbe("proc-files",
            [
                new EvidenceItem("proc-files", "os.id", "debian"),
                new EvidenceItem("proc-files", "os.pretty_name", "Debian GNU/Linux 12 (bookworm)"),
                new EvidenceItem("proc-files", "kernel.release", "6.17.0-1011-azure"),
                new EvidenceItem("proc-files", "kernel.flavor", "Azure"),
                new EvidenceItem("proc-files", "cpu.logical_processors", "4"),
                new EvidenceItem("proc-files", "cpu.vendor", "GenuineIntel"),
                new EvidenceItem("proc-files", "cpu.model_name", "Intel(R) Xeon(R) CPU"),
                new EvidenceItem("proc-files", "cpu.flags.hash", "sha256:abc"),
                new EvidenceItem("proc-files", "memory.mem_total_bytes", "17179869184")
            ]),
            new FixedProbe("runtime-api",
            [
                new EvidenceItem("runtime-api", "docker.info.operating_system", "Ubuntu 24.04.4 LTS"),
                new EvidenceItem("runtime-api", "docker.info.kernel_version", "6.17.0-1011-azure"),
                new EvidenceItem("runtime-api", "docker.info.architecture", "x86_64"),
                new EvidenceItem("runtime-api", "docker.info.ncpu", "4"),
                new EvidenceItem("runtime-api", "docker.info.mem_total", "17179869184"),
                new EvidenceItem("runtime-api", "runtime.engine.version", "28.1.1"),
                new EvidenceItem("runtime-api", "runtime.architecture", "x86_64"),
                new EvidenceItem("runtime-api", "/var/run/docker.sock:/_ping:outcome", "Success")
            ])
        ]);

        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);

        Assert.Equal(RuntimeReportedHostSource.DockerInfo, report.Host.RuntimeReportedHostOs.Source);
        Assert.Equal("Ubuntu 24.04.4 LTS", report.Host.RuntimeReportedHostOs.Name);
        Assert.Equal(4, report.Host.Hardware.Cpu.LogicalProcessorCount);
        Assert.Equal(17179869184L, report.Host.Hardware.Memory.MemTotalBytes);
        Assert.Contains("## Host OS / Node", ReportRenderer.ToMarkdown(report));
    }

    [Fact]
    public async Task Engine_FakeKubernetesNodeInfo_MapsHostModel()
    {
        var engine = new ContainerRuntimeProbeEngine(
        [
            new FixedProbe("proc-files",
            [
                new EvidenceItem("proc-files", "kernel.release", "6.6.10-generic"),
                new EvidenceItem("proc-files", "memory.mem_total_bytes", "8589934592")
            ]),
            new FixedProbe("kubernetes",
            [
                new EvidenceItem("kubernetes", "api.version.outcome", "Success"),
                new EvidenceItem("kubernetes", "kubernetes.nodeInfo.osImage", "Ubuntu 24.04.4 LTS"),
                new EvidenceItem("kubernetes", "kubernetes.nodeInfo.kernelVersion", "6.6.10-generic"),
                new EvidenceItem("kubernetes", "kubernetes.nodeInfo.operatingSystem", "linux"),
                new EvidenceItem("kubernetes", "kubernetes.nodeInfo.architecture", "amd64"),
                new EvidenceItem("kubernetes", "kubernetes.nodeInfo.containerRuntimeVersion", "containerd://2.0.1")
            ])
        ]);

        var report = await engine.RunAsync(TimeSpan.FromSeconds(1), includeSensitive: false);

        Assert.Equal(RuntimeReportedHostSource.KubernetesNodeInfo, report.Host.RuntimeReportedHostOs.Source);
        Assert.Equal("Ubuntu 24.04.4 LTS", report.Host.RuntimeReportedHostOs.Name);
        Assert.Equal("6.6.10-generic", report.Host.RuntimeReportedHostOs.KernelVersion);
        Assert.Equal(ArchitectureKind.X64, report.Host.RuntimeReportedHostOs.Architecture);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static async Task HandleCloudMetadataRequestAsync(HttpListenerContext context)
    {
        await Task.Delay(250).ConfigureAwait(false);

        var request = context.Request;
        var path = request.Url?.AbsolutePath ?? string.Empty;
        var statusCode = 200;
        var body = path switch
        {
            "/latest/api/token" when string.Equals(request.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase) => "fake-token",
            "/latest/dynamic/instance-identity/document" => """
                {"instanceId":"i-0abc123def4567890","instanceType":"c7g.large","region":"eu-central-1","availabilityZone":"eu-central-1a","architecture":"arm64"}
                """,
            "/metadata/instance" => """
                {"compute":{"vmId":"5d77f1f6-4e57-4d8c-9f9e-9fd8e67f21d2","vmSize":"Standard_D4s_v5","location":"westeurope","zone":"2","osType":"Linux"}}
                """,
            "/computeMetadata/v1/instance/id" => "9876543210123456789",
            "/computeMetadata/v1/instance/machine-type" => "projects/123456/machineTypes/e2-standard-4",
            "/computeMetadata/v1/instance/zone" => "projects/123456/zones/europe-west3-b",
            "/opc/v2/instance/" => """
                {"id":"ocid1.instance.oc1.eu-frankfurt-1.exampleuniqueid","shape":"VM.Standard.E4.Flex","region":"eu-frankfurt-1","availabilityDomain":"Uocm:EU-FRANKFURT-1-AD-1"}
                """,
            _ => "{}"
        };

        if (path is not "/latest/api/token" and not "/latest/dynamic/instance-identity/document" and not "/metadata/instance" and not "/computeMetadata/v1/instance/id" and not "/computeMetadata/v1/instance/machine-type" and not "/computeMetadata/v1/instance/zone" and not "/opc/v2/instance/")
        {
            statusCode = 404;
        }

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        var bytes = Encoding.UTF8.GetBytes(body);
        await context.Response.OutputStream.WriteAsync(bytes);
        context.Response.Close();
    }

    private sealed class FixedProbe(string id, IReadOnlyList<EvidenceItem> evidence) : IProbe
    {
        public string Id => id;

        public Task<ProbeResult> ExecuteAsync(ProbeContext context)
            => Task.FromResult(new ProbeResult(id, ProbeOutcome.Success, evidence));
    }
}
