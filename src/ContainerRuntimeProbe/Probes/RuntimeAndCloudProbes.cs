using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using ContainerRuntimeProbe.Abstractions;
using ContainerRuntimeProbe.Internal;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Probes;

internal static class HttpProbe
{
    public static HttpClient CreateUnixSocketClient(string socketPath, TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (ctx, ct) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
        };
        return new HttpClient(handler) { BaseAddress = new Uri("http://unix"), Timeout = timeout };
    }

    public static async Task<(ProbeOutcome outcome, string? body, int? status, string? message)> GetAsync(HttpClient client, string path, Dictionary<string, string>? headers = null, CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, path);
            if (headers is not null)
            {
                foreach (var kv in headers) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if ((int)resp.StatusCode is 401 or 403) return (ProbeOutcome.AccessDenied, text, (int)resp.StatusCode, null);
            if (!resp.IsSuccessStatusCode) return (ProbeOutcome.Unavailable, text, (int)resp.StatusCode, null);
            return (ProbeOutcome.Success, text, (int)resp.StatusCode, null);
        }
        catch (UnauthorizedAccessException ex) { return (ProbeOutcome.AccessDenied, null, null, ex.Message); }
        catch (OperationCanceledException ex) { return (ProbeOutcome.Timeout, null, null, ex.Message); }
        catch (HttpRequestException ex) { return (ProbeOutcome.Unavailable, null, null, ex.Message); }
        catch (Exception ex) { return (ProbeOutcome.Error, null, null, ex.Message); }
    }
}

internal static class ComposeLabels
{
    /// <summary>Well-known Docker Compose label keys to extract from container inspect response.</summary>
    internal static readonly string[] KnownLabels =
    [
        "com.docker.compose.project",
        "com.docker.compose.service",
        "com.docker.compose.version",
        "com.docker.compose.container-number",
        "com.docker.compose.project.working_dir",
        "com.docker.compose.project.config_files"
    ];

    /// <summary>
    /// Parses Docker container-inspect JSON and emits evidence for Compose labels.
    /// Uses JsonDocument (AOT-safe) to navigate Config.Labels without reflection.
    /// </summary>
    public static IEnumerable<EvidenceItem> ExtractFromInspectJson(string probeId, string json)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch { yield break; }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("Config", out var config)) yield break;
            if (!config.TryGetProperty("Labels", out var labels)) yield break;
            if (labels.ValueKind != JsonValueKind.Object) yield break;

            foreach (var prop in labels.EnumerateObject())
            {
                // Only emit the well-known Compose labels to keep output bounded
                if (Array.IndexOf(KnownLabels, prop.Name) < 0) continue;
                var rawValue = prop.Value.GetString() ?? string.Empty;
                // Truncate path values (working_dir, config_files) to avoid excessively long output
                var value = rawValue.Length > 256 ? rawValue[..256] : rawValue;
                yield return new EvidenceItem(probeId, $"compose.label.{prop.Name}", value);
            }
        }
    }
}

internal sealed class RuntimeApiProbe : IProbe
{
    public string Id => "runtime-api";

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var sockets = new List<string> { "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock" };

        // Discover per-user Podman sockets via XDG_RUNTIME_DIR or by enumerating /run/user/
        var xdgDir = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (!string.IsNullOrWhiteSpace(xdgDir))
        {
            sockets.Add(Path.Combine(xdgDir, "podman", "podman.sock"));
        }
        else if (Directory.Exists("/run/user"))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories("/run/user"))
                    sockets.Add(Path.Combine(dir, "podman", "podman.sock"));
            }
            catch { /* /run/user may be unreadable */ }
        }

        foreach (var socket in sockets.Distinct())
        {
            if (!File.Exists(socket)) continue;
            evidence.Add(new EvidenceItem(Id, "socket.present", socket));

            using var client = HttpProbe.CreateUnixSocketClient(socket, context.Timeout);
            foreach (var endpoint in new[] { "/_ping", "/version", "/info", "/libpod/_ping", "/libpod/version", "/libpod/info" })
            {
                var (oc, body, status, msg) = await HttpProbe.GetAsync(client, endpoint, ct: context.CancellationToken).ConfigureAwait(false);
                evidence.Add(new EvidenceItem(Id, $"{socket}:{endpoint}:outcome", oc.ToString()));
                if (status.HasValue) evidence.Add(new EvidenceItem(Id, $"{socket}:{endpoint}:status", status.Value.ToString()));
                if (oc == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(body))
                {
                    AddRuntimeMetadataEvidence(evidence, endpoint, body);
                }
                if (!string.IsNullOrWhiteSpace(msg)) evidence.Add(new EvidenceItem(Id, $"{socket}:{endpoint}:message", msg));
            }

            // Container inspection for Docker Compose labels.
            // Try the current container's hostname as the container identifier.
            await ProbeComposeLabelsAsync(client, evidence, context.CancellationToken).ConfigureAwait(false);
        }

        sw.Stop();
        var outcome = evidence.Count == 0 ? ProbeOutcome.Unavailable : ProbeOutcome.Success;
        return new ProbeResult(Id, outcome, evidence, outcome == ProbeOutcome.Unavailable ? "No docker/podman socket found" : null, sw.Elapsed);
    }

    private async Task ProbeComposeLabelsAsync(HttpClient client, List<EvidenceItem> evidence, CancellationToken ct)
    {
        // Gather candidate container identifiers from well-known sources.
        var candidates = new List<string>();
        var hostname = Environment.GetEnvironmentVariable("HOSTNAME");
        if (!string.IsNullOrWhiteSpace(hostname)) candidates.Add(hostname);

        foreach (var path in new[] { "/etc/hostname", "/proc/sys/kernel/hostname" })
        {
            try
            {
                var h = (await File.ReadAllTextAsync(path, ct).ConfigureAwait(false)).Trim();
                if (!string.IsNullOrEmpty(h) && !candidates.Contains(h)) candidates.Add(h);
            }
            catch { /* unavailable */ }
        }

        foreach (var candidate in candidates)
        {
            var (oc, body, status, _) = await HttpProbe.GetAsync(client, $"/containers/{Uri.EscapeDataString(candidate)}/json", ct: ct).ConfigureAwait(false);

            evidence.Add(new EvidenceItem(Id, $"container.inspect.outcome", oc.ToString()));
            if (status.HasValue && status.Value != 200)
                evidence.Add(new EvidenceItem(Id, "container.inspect.status", status.Value.ToString()));

            if (oc == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(body))
            {
                foreach (var item in ComposeLabels.ExtractFromInspectJson(Id, body))
                    evidence.Add(item);
                // Once we get a successful inspection, no need to try other candidates
                return;
            }
        }
    }

    private void AddRuntimeMetadataEvidence(List<EvidenceItem> evidence, string endpoint, string body)
    {
        try
        {
            switch (endpoint)
            {
                case "/version":
                    AddDockerVersionEvidence(evidence, body);
                    break;
                case "/info":
                    AddDockerInfoEvidence(evidence, body);
                    break;
                case "/libpod/version":
                    AddPodmanVersionEvidence(evidence, body);
                    break;
                case "/libpod/info":
                    AddPodmanInfoEvidence(evidence, body);
                    break;
                default:
                    if (endpoint.EndsWith("_ping", StringComparison.OrdinalIgnoreCase))
                    {
                        evidence.Add(new EvidenceItem(Id, "runtime.api.endpoint", endpoint));
                    }
                    break;
            }
        }
        catch
        {
            // Ignore malformed runtime metadata bodies; outcome evidence is still retained.
        }
    }

    private void AddDockerVersionEvidence(List<EvidenceItem> evidence, string body)
    {
        using var doc = JsonDocument.Parse(body);
        AddEvidenceIfPresent(evidence, Id, "runtime.engine.version", JsonHelper.GetString(doc.RootElement, "Version"));
        AddEvidenceIfPresent(evidence, Id, "runtime.engine.api_version", JsonHelper.GetString(doc.RootElement, "ApiVersion"));
    }

    private void AddDockerInfoEvidence(List<EvidenceItem> evidence, string body)
    {
        using var doc = JsonDocument.Parse(body);
        AddEvidenceIfPresent(evidence, Id, "docker.info.operating_system", JsonHelper.GetString(doc.RootElement, "OperatingSystem"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.os_type", JsonHelper.GetString(doc.RootElement, "OSType"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.architecture", JsonHelper.GetString(doc.RootElement, "Architecture"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.kernel_version", JsonHelper.GetString(doc.RootElement, "KernelVersion"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.ncpu", JsonHelper.GetString(doc.RootElement, "NCPU"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.mem_total", JsonHelper.GetString(doc.RootElement, "MemTotal"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.server_version", JsonHelper.GetString(doc.RootElement, "ServerVersion"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.cgroup_driver", JsonHelper.GetString(doc.RootElement, "CgroupDriver"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.cgroup_version", JsonHelper.GetString(doc.RootElement, "CgroupVersion"));
        AddEvidenceIfPresent(evidence, Id, "docker.info.default_runtime", JsonHelper.GetString(doc.RootElement, "DefaultRuntime"));
        if (doc.RootElement.TryGetProperty("SecurityOptions", out var securityOptions) && securityOptions.ValueKind == JsonValueKind.Array)
        {
            evidence.Add(new EvidenceItem(Id, "docker.info.security_options_count", securityOptions.GetArrayLength().ToString()));
        }
        evidence.Add(new EvidenceItem(Id, "runtime.architecture", JsonHelper.GetString(doc.RootElement, "Architecture") ?? string.Empty));
    }

    private void AddPodmanVersionEvidence(List<EvidenceItem> evidence, string body)
    {
        using var doc = JsonDocument.Parse(body);
        AddEvidenceIfPresent(evidence, Id, "runtime.engine.version", JsonHelper.GetString(doc.RootElement, "Version"));
        AddEvidenceIfPresent(evidence, Id, "runtime.engine.api_version", JsonHelper.GetString(doc.RootElement, "ApiVersion"));
    }

    private void AddPodmanInfoEvidence(List<EvidenceItem> evidence, string body)
    {
        foreach (var item in ExtractPodmanInfoEvidence(Id, body))
        {
            evidence.Add(item);
        }
    }

    internal static IReadOnlyList<EvidenceItem> ExtractPodmanInfoEvidence(string probeId, string body)
    {
        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("host", out var host) || host.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        var evidence = new List<EvidenceItem>();
        AddEvidenceIfPresent(evidence, probeId, "podman.info.architecture", JsonHelper.GetString(host, "arch"));
        AddEvidenceIfPresent(evidence, probeId, "podman.info.kernel", JsonHelper.GetString(host, "kernel"));
        AddEvidenceIfPresent(evidence, probeId, "podman.info.mem_total", JsonHelper.GetString(host, "memTotal"));
        AddEvidenceIfPresent(evidence, probeId, "podman.info.cpus", JsonHelper.GetString(host, "cpus"));
        AddEvidenceIfPresent(evidence, probeId, "podman.info.service_is_remote", JsonHelper.GetString(host, "serviceIsRemote"));
        AddEvidenceIfPresent(evidence, probeId, "runtime.architecture", JsonHelper.GetString(host, "arch"));

        if (host.TryGetProperty("remoteSocket", out var remoteSocket) && remoteSocket.ValueKind == JsonValueKind.Object)
        {
            AddEvidenceIfPresent(evidence, probeId, "podman.info.remote_socket_path", JsonHelper.GetString(remoteSocket, "path"));
        }

        if (host.TryGetProperty("distribution", out var distribution) && distribution.ValueKind == JsonValueKind.Object)
        {
            var distro = $"{JsonHelper.GetString(distribution, "distribution")} {JsonHelper.GetString(distribution, "version")}".Trim();
            AddEvidenceIfPresent(evidence, probeId, "podman.info.distribution", string.IsNullOrWhiteSpace(distro) ? null : distro);
        }

        return evidence;
    }

    private static void AddEvidenceIfPresent(List<EvidenceItem> evidence, string probeId, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem(probeId, key, value.Trim()));
        }
    }

}

internal sealed class KubernetesProbe : IProbe
{
    public string Id => "kubernetes";

    private readonly IReadOnlyList<string> _tokenPaths;
    private readonly IReadOnlyList<string> _namespacePaths;
    private readonly string? _serviceHostOverride;

    private static readonly string[] DefaultTokenPaths =
        ["/run/secrets/kubernetes.io/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/token"];
    private static readonly string[] DefaultNamespacePaths =
        ["/run/secrets/kubernetes.io/serviceaccount/namespace", "/var/run/secrets/kubernetes.io/serviceaccount/namespace"];

    /// <summary>Production constructor using standard Kubernetes service-account mount paths.</summary>
    public KubernetesProbe() : this(DefaultTokenPaths, DefaultNamespacePaths, null) { }

    /// <summary>Test constructor allowing injection of custom paths and a service-host override.</summary>
    internal KubernetesProbe(IReadOnlyList<string> tokenPaths, IReadOnlyList<string> namespacePaths, string? serviceHostOverride)
    {
        _tokenPaths = tokenPaths;
        _namespacePaths = namespacePaths;
        _serviceHostOverride = serviceHostOverride;
    }

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var host = _serviceHostOverride ?? Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST");
        var port = Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_PORT") ?? "443";
        if (!string.IsNullOrWhiteSpace(host)) evidence.Add(new EvidenceItem(Id, "env.KUBERNETES_SERVICE_HOST", host));

        var tokenPath = _tokenPaths.FirstOrDefault(File.Exists);
        var nsPath = _namespacePaths.FirstOrDefault(File.Exists);
        if (tokenPath is not null) evidence.Add(new EvidenceItem(Id, "serviceaccount.token", "present", EvidenceSensitivity.Sensitive));
        if (nsPath is not null) evidence.Add(new EvidenceItem(Id, "serviceaccount.namespace", (await File.ReadAllTextAsync(nsPath, context.CancellationToken).ConfigureAwait(false)).Trim()));

        if (string.IsNullOrWhiteSpace(host) || tokenPath is null)
        {
            sw.Stop();
            return new ProbeResult(Id, ProbeOutcome.Unavailable, evidence, "Kubernetes env/token missing", sw.Elapsed);
        }

        var api = context.KubernetesApiBase ?? new Uri($"https://{host}:{port}");
        if (string.Equals(api.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            var tlsVerification = context.KubernetesTlsVerificationMode == KubernetesTlsVerificationMode.Strict
                ? "strict"
                : "compatibility-skip-validation";
            evidence.Add(new EvidenceItem(Id, "api.tls.verification", tlsVerification));
        }

        using var client = new HttpClient(CreateHttpClientHandler(context.KubernetesTlsVerificationMode)) { BaseAddress = api, Timeout = context.Timeout };
        var token = await File.ReadAllTextAsync(tokenPath, context.CancellationToken).ConfigureAwait(false);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());

        var version = await HttpProbe.GetAsync(client, "/version", ct: context.CancellationToken).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "api.version.outcome", version.outcome.ToString()));
        if (version.body is not null) evidence.Add(new EvidenceItem(Id, "api.version.body", version.body.Length > 300 ? version.body[..300] : version.body));

        var ns = evidence.FirstOrDefault(e => e.Key == "serviceaccount.namespace")?.Value;
        var pod = Environment.GetEnvironmentVariable("HOSTNAME");
        if (!string.IsNullOrWhiteSpace(ns) && !string.IsNullOrWhiteSpace(pod))
        {
            var podResult = await HttpProbe.GetAsync(client, $"/api/v1/namespaces/{ns}/pods/{pod}", ct: context.CancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, "api.pod.outcome", podResult.outcome.ToString()));
            if (podResult.status.HasValue) evidence.Add(new EvidenceItem(Id, "api.pod.status", podResult.status.Value.ToString()));
            if (podResult.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(podResult.body))
            {
                await ProbeNodeInfoAsync(client, evidence, podResult.body!, context.CancellationToken).ConfigureAwait(false);
            }
        }

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed);
    }

    internal static HttpClientHandler CreateHttpClientHandler(KubernetesTlsVerificationMode tlsVerificationMode)
    {
        var handler = new HttpClientHandler();
        if (tlsVerificationMode == KubernetesTlsVerificationMode.Compatibility)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        return handler;
    }

    private async Task ProbeNodeInfoAsync(HttpClient client, List<EvidenceItem> evidence, string podJson, CancellationToken ct)
    {
        using var podDoc = JsonDocument.Parse(podJson);
        if (!podDoc.RootElement.TryGetProperty("spec", out var spec) ||
            spec.ValueKind != JsonValueKind.Object ||
            !spec.TryGetProperty("nodeName", out var nodeNameElement) ||
            nodeNameElement.ValueKind != JsonValueKind.String)
        {
            return;
        }

        var nodeName = nodeNameElement.GetString();
        if (string.IsNullOrWhiteSpace(nodeName))
        {
            return;
        }

        var nodeResult = await HttpProbe.GetAsync(client, $"/api/v1/nodes/{Uri.EscapeDataString(nodeName)}", ct: ct).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "api.node.outcome", nodeResult.outcome.ToString()));
        if (nodeResult.status.HasValue) evidence.Add(new EvidenceItem(Id, "api.node.status", nodeResult.status.Value.ToString()));
        if (nodeResult.outcome != ProbeOutcome.Success || string.IsNullOrWhiteSpace(nodeResult.body))
        {
            return;
        }

        using var nodeDoc = JsonDocument.Parse(nodeResult.body);
        if (!nodeDoc.RootElement.TryGetProperty("status", out var status) ||
            status.ValueKind != JsonValueKind.Object ||
            !status.TryGetProperty("nodeInfo", out var nodeInfo) ||
            nodeInfo.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.osImage", JsonHelper.GetString(nodeInfo, "osImage"));
        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.kernelVersion", JsonHelper.GetString(nodeInfo, "kernelVersion"));
        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.operatingSystem", JsonHelper.GetString(nodeInfo, "operatingSystem"));
        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.architecture", JsonHelper.GetString(nodeInfo, "architecture"));
        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.containerRuntimeVersion", JsonHelper.GetString(nodeInfo, "containerRuntimeVersion"));
        AddEvidenceIfPresent(evidence, "kubernetes.nodeInfo.kubeletVersion", JsonHelper.GetString(nodeInfo, "kubeletVersion"));
    }

    private void AddEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem(Id, key, value.Trim()));
        }
    }
}

internal sealed class CloudMetadataProbe : IProbe
{
    public string Id => "cloud-metadata";

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();
        var ecs = Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI_V4") ?? Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI");

        var ecsBase = string.IsNullOrWhiteSpace(ecs)
            ? null
            : new Uri(ecs.EndsWith("/", StringComparison.Ordinal) ? ecs : ecs + '/');
        var awsBase = context.AwsImdsBase ?? new Uri("http://169.254.169.254");
        var azureBase = context.AzureImdsBase ?? new Uri("http://169.254.169.254");
        var gcpBase = context.GcpMetadataBase ?? new Uri("http://metadata.google.internal");
        var ociBase = context.OciMetadataBase ?? new Uri("http://169.254.169.254");
        var baseAddresses = new List<Uri> { awsBase, azureBase, gcpBase, ociBase };
        if (ecsBase is not null)
        {
            baseAddresses.Add(ecsBase);
        }

        var clientPool = CreateClientPool(baseAddresses, context.Timeout);

        try
        {
            var probeTasks = new List<Task<IReadOnlyList<EvidenceItem>>>
            {
                ProbeAwsAsync(GetClient(clientPool, awsBase), context.CancellationToken),
                ProbeAzureAsync(GetClient(clientPool, azureBase), context.CancellationToken),
                ProbeGcpAsync(GetClient(clientPool, gcpBase), context.CancellationToken),
                ProbeOciAsync(GetClient(clientPool, ociBase), context.CancellationToken)
            };

            if (ecsBase is not null)
            {
                probeTasks.Insert(0, ProbeEcsAsync(GetClient(clientPool, ecsBase), context.CancellationToken));
            }

            var providerEvidence = await Task.WhenAll(probeTasks).ConfigureAwait(false);
            foreach (var items in providerEvidence)
            {
                evidence.AddRange(items);
            }
        }
        finally
        {
            foreach (var client in clientPool.Values)
            {
                client.Dispose();
            }
        }

        // Cloud Run/AppService/ACA/Nomad markers
        foreach (var key in new[] { "K_SERVICE", "K_REVISION", "K_CONFIGURATION", "WEBSITE_SITE_NAME", "CONTAINER_APP_NAME", "NOMAD_JOB_NAME" })
        {
            var v = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(v)) evidence.Add(new EvidenceItem(Id, $"env.{key}", v));
        }

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed);
    }

    internal static IReadOnlyDictionary<string, HttpClient> CreateClientPool(IEnumerable<Uri> baseAddresses, TimeSpan timeout)
    {
        var clients = new Dictionary<string, HttpClient>(StringComparer.OrdinalIgnoreCase);
        foreach (var baseAddress in baseAddresses)
        {
            var normalized = NormalizeBaseAddress(baseAddress);
            if (!clients.ContainsKey(normalized.AbsoluteUri))
            {
                clients[normalized.AbsoluteUri] = new HttpClient { BaseAddress = normalized, Timeout = timeout };
            }
        }

        return clients;
    }

    private static HttpClient GetClient(IReadOnlyDictionary<string, HttpClient> clientPool, Uri baseAddress)
        => clientPool[NormalizeBaseAddress(baseAddress).AbsoluteUri];

    private static Uri NormalizeBaseAddress(Uri baseAddress)
    {
        var builder = new UriBuilder(baseAddress);
        if (string.IsNullOrEmpty(builder.Path))
        {
            builder.Path = "/";
        }
        else if (!builder.Path.EndsWith("/", StringComparison.Ordinal))
        {
            builder.Path += "/";
        }

        return builder.Uri;
    }

    private async Task<IReadOnlyList<EvidenceItem>> ProbeEcsAsync(HttpClient ecsClient, CancellationToken cancellationToken)
    {
        var evidence = new List<EvidenceItem>();
        foreach (var path in new[] { "", "task", "stats" })
        {
            var result = await HttpProbe.GetAsync(ecsClient, path, ct: cancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, $"ecs.{path}.outcome", result.outcome.ToString()));
        }

        return evidence;
    }

    private async Task<IReadOnlyList<EvidenceItem>> ProbeAwsAsync(HttpClient awsClient, CancellationToken cancellationToken)
    {
        var evidence = new List<EvidenceItem>();
        try
        {
            using var tokenReq = new HttpRequestMessage(HttpMethod.Put, "/latest/api/token");
            tokenReq.Headers.Add("X-aws-ec2-metadata-token-ttl-seconds", "60");
            using var tokenResp = await awsClient.SendAsync(tokenReq, cancellationToken).ConfigureAwait(false);
            var token = await tokenResp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!tokenResp.IsSuccessStatusCode)
            {
                return evidence;
            }

            var headers = new Dictionary<string, string> { ["X-aws-ec2-metadata-token"] = token };
            var identity = await HttpProbe.GetAsync(awsClient, "/latest/dynamic/instance-identity/document", headers, cancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, "aws.imds.identity.outcome", identity.outcome.ToString()));
            if (identity.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(identity.body))
            {
                AddAwsEvidence(evidence, identity.body!);
            }
        }
        catch
        {
        }

        return evidence;
    }

    private async Task<IReadOnlyList<EvidenceItem>> ProbeAzureAsync(HttpClient azureClient, CancellationToken cancellationToken)
    {
        var evidence = new List<EvidenceItem>();
        var result = await HttpProbe.GetAsync(azureClient, "/metadata/instance?api-version=2021-02-01", new() { ["Metadata"] = "true" }, cancellationToken).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "azure.imds.outcome", result.outcome.ToString()));
        if (result.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(result.body))
        {
            AddAzureEvidence(evidence, result.body!);
        }

        return evidence;
    }

    private async Task<IReadOnlyList<EvidenceItem>> ProbeGcpAsync(HttpClient gcpClient, CancellationToken cancellationToken)
    {
        var evidence = new List<EvidenceItem>();
        var headers = new Dictionary<string, string> { ["Metadata-Flavor"] = "Google" };
        var machineTypeTask = HttpProbe.GetAsync(gcpClient, "/computeMetadata/v1/instance/machine-type", headers, cancellationToken);
        var zoneTask = HttpProbe.GetAsync(gcpClient, "/computeMetadata/v1/instance/zone", headers, cancellationToken);

        var machineType = await machineTypeTask.ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "gcp.metadata.machine_type.outcome", machineType.outcome.ToString()));
        if (machineType.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(machineType.body))
        {
            AddEvidenceIfPresent(evidence, "cloud.machine_type", machineType.body!.Trim().Split('/').LastOrDefault());
            evidence.Add(new EvidenceItem(Id, "cloud.source", RuntimeReportedHostSource.GcpMetadata.ToString()));
        }

        var zone = await zoneTask.ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "gcp.metadata.zone.outcome", zone.outcome.ToString()));
        if (zone.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(zone.body))
        {
            var zoneValue = zone.body!.Trim().Split('/').LastOrDefault() ?? zone.body.Trim();
            AddEvidenceIfPresent(evidence, "cloud.zone", zoneValue);
            var lastDash = zoneValue.LastIndexOf('-');
            AddEvidenceIfPresent(evidence, "cloud.region", lastDash > 0 ? zoneValue[..lastDash] : zoneValue);
            evidence.Add(new EvidenceItem(Id, "cloud.source", RuntimeReportedHostSource.GcpMetadata.ToString()));
        }

        var gcpOutcome = machineType.outcome == ProbeOutcome.Success || zone.outcome == ProbeOutcome.Success ? ProbeOutcome.Success : zone.outcome;
        evidence.Add(new EvidenceItem(Id, "gcp.metadata.outcome", gcpOutcome.ToString()));
        return evidence;
    }

    private async Task<IReadOnlyList<EvidenceItem>> ProbeOciAsync(HttpClient ociClient, CancellationToken cancellationToken)
    {
        var evidence = new List<EvidenceItem>();
        var result = await HttpProbe.GetAsync(ociClient, "/opc/v2/instance/", new() { ["Authorization"] = "Bearer Oracle" }, cancellationToken).ConfigureAwait(false);
        evidence.Add(new EvidenceItem(Id, "oci.metadata.outcome", result.outcome.ToString()));
        if (result.outcome == ProbeOutcome.Success && !string.IsNullOrWhiteSpace(result.body))
        {
            AddOciEvidence(evidence, result.body!);
        }

        return evidence;
    }

    private void AddAwsEvidence(List<EvidenceItem> evidence, string body)
    {
        var parsed = HostParsing.ParseAwsIdentity(body, Id);
        if (parsed is null)
        {
            return;
        }

        AddEvidenceIfPresent(evidence, "cloud.machine_type", parsed.MachineType);
        AddEvidenceIfPresent(evidence, "cloud.region", parsed.Region);
        AddEvidenceIfPresent(evidence, "cloud.zone", parsed.Zone);
        AddEvidenceIfPresent(evidence, "cloud.architecture", parsed.RawArchitecture);
        evidence.Add(new EvidenceItem(Id, "cloud.source", parsed.Source.ToString()));
    }

    private void AddAzureEvidence(List<EvidenceItem> evidence, string body)
    {
        var parsed = HostParsing.ParseAzureMetadata(body, Id);
        if (parsed is null)
        {
            return;
        }

        AddEvidenceIfPresent(evidence, "cloud.machine_type", parsed.MachineType);
        AddEvidenceIfPresent(evidence, "cloud.region", parsed.Region);
        AddEvidenceIfPresent(evidence, "cloud.zone", parsed.Zone);
        AddEvidenceIfPresent(evidence, "cloud.os_type", parsed.OsType);
        evidence.Add(new EvidenceItem(Id, "cloud.source", parsed.Source.ToString()));
    }

    private void AddOciEvidence(List<EvidenceItem> evidence, string body)
    {
        var parsed = HostParsing.ParseOciMetadata(body, Id);
        if (parsed is null)
        {
            return;
        }

        AddEvidenceIfPresent(evidence, "cloud.machine_type", parsed.MachineType);
        AddEvidenceIfPresent(evidence, "cloud.region", parsed.Region);
        AddEvidenceIfPresent(evidence, "cloud.zone", parsed.Zone);
        evidence.Add(new EvidenceItem(Id, "cloud.source", parsed.Source.ToString()));
    }

    private void AddEvidenceIfPresent(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evidence.Add(new EvidenceItem(Id, key, value.Trim()));
        }
    }
}
