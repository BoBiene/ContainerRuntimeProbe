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
                if (!string.IsNullOrWhiteSpace(body)) evidence.Add(new EvidenceItem(Id, $"{socket}:{endpoint}:body", body.Length > 512 ? body[..512] : body));
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
        using var client = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true }) { BaseAddress = api, Timeout = context.Timeout };
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
        }

        sw.Stop();
        return new ProbeResult(Id, ProbeOutcome.Success, evidence, Duration: sw.Elapsed);
    }
}

internal sealed class CloudMetadataProbe : IProbe
{
    public string Id => "cloud-metadata";

    public async Task<ProbeResult> ExecuteAsync(ProbeContext context)
    {
        var sw = Stopwatch.StartNew();
        var evidence = new List<EvidenceItem>();

        // ECS
        var ecs = Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI_V4") ?? Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI");
        if (!string.IsNullOrWhiteSpace(ecs))
        {
            using var ecsClient = new HttpClient { BaseAddress = new Uri(ecs.EndsWith('/') ? ecs : ecs + '/'), Timeout = context.Timeout };
            foreach (var p in new[] { "", "task", "stats" })
            {
                var r = await HttpProbe.GetAsync(ecsClient, p, ct: context.CancellationToken).ConfigureAwait(false);
                evidence.Add(new EvidenceItem(Id, $"ecs.{p}.outcome", r.outcome.ToString()));
            }
        }

        // AWS IMDSv2 safe
        using (var aws = new HttpClient { BaseAddress = context.AwsImdsBase ?? new Uri("http://169.254.169.254"), Timeout = context.Timeout })
        {
            try
            {
                using var tokenReq = new HttpRequestMessage(HttpMethod.Put, "/latest/api/token");
                tokenReq.Headers.Add("X-aws-ec2-metadata-token-ttl-seconds", "60");
                using var tokenResp = await aws.SendAsync(tokenReq, context.CancellationToken).ConfigureAwait(false);
                var tok = await tokenResp.Content.ReadAsStringAsync(context.CancellationToken).ConfigureAwait(false);
                if (tokenResp.IsSuccessStatusCode)
                {
                    var headers = new Dictionary<string, string> { ["X-aws-ec2-metadata-token"] = tok };
                    var idDoc = await HttpProbe.GetAsync(aws, "/latest/dynamic/instance-identity/document", headers, context.CancellationToken).ConfigureAwait(false);
                    evidence.Add(new EvidenceItem(Id, "aws.imds.identity.outcome", idDoc.outcome.ToString()));
                }
            }
            catch { }
        }

        // Azure IMDS
        using (var az = new HttpClient { BaseAddress = context.AzureImdsBase ?? new Uri("http://169.254.169.254"), Timeout = context.Timeout })
        {
            var azr = await HttpProbe.GetAsync(az, "/metadata/instance?api-version=2021-02-01", new() { ["Metadata"] = "true" }, context.CancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, "azure.imds.outcome", azr.outcome.ToString()));
        }

        // GCP metadata
        using (var gcp = new HttpClient { BaseAddress = context.GcpMetadataBase ?? new Uri("http://metadata.google.internal"), Timeout = context.Timeout })
        {
            var gr = await HttpProbe.GetAsync(gcp, "/computeMetadata/v1/project/project-id", new() { ["Metadata-Flavor"] = "Google" }, context.CancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, "gcp.metadata.outcome", gr.outcome.ToString()));
        }

        // OCI metadata
        using (var oci = new HttpClient { BaseAddress = context.OciMetadataBase ?? new Uri("http://169.254.169.254"), Timeout = context.Timeout })
        {
            var or = await HttpProbe.GetAsync(oci, "/opc/v2/instance/", new() { ["Authorization"] = "Bearer Oracle" }, context.CancellationToken).ConfigureAwait(false);
            evidence.Add(new EvidenceItem(Id, "oci.metadata.outcome", or.outcome.ToString()));
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
}
