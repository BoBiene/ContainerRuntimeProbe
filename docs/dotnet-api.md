# .NET API

`ContainerRuntimeProbe` is a read-only runtime inspection library.

The library is designed to observe, classify, summarize, and redact environment signals that are visible from the current process. It does not mutate the system, provision trust, rewrite certificates, or perform caller-specific binding on behalf of the application.

If an application needs stronger policy decisions such as certificate pinning, attestation, device ownership checks, or tenant-specific trust binding, that validation should happen in the consuming application on top of the report returned by this library.

## Main entry point

Use `ContainerRuntimeProbeEngine` when you want a single normalized report for the current runtime environment.

```csharp
using ContainerRuntimeProbe;

var engine = new ContainerRuntimeProbeEngine();
var report = await engine.RunAsync(
    timeout: TimeSpan.FromSeconds(2),
    includeSensitive: false,
    cancellationToken: cancellationToken);
```

The engine:

- runs the configured probes concurrently
- normalizes the collected evidence into a single `ContainerRuntimeReport`
- applies central redaction when `includeSensitive` is `false`
- builds higher-level summaries such as `Classification`, `Host`, `PlatformEvidence`, and `TrustedPlatforms`
- separates diagnostic host fingerprints from future bindable identity anchors

You can also pass explicit `ProbeExecutionOptions` when you want to narrow the probe set or override cloud and Kubernetes endpoints for testing.

When you want the most relevant findings as a structured API instead of renderer-specific text, call `report.GetRelevantFindings()`:

```csharp
using ContainerRuntimeProbe;

var findings = report.GetRelevantFindings();

foreach (var finding in findings)
{
  Console.WriteLine($"[{finding.Kind}] {finding.Summary}");
}
```

Each `ReportFinding` carries a stable `Kind`, a `Key`, optional `Value`, a human-readable `Summary`, `Confidence`, and referenced evidence keys. Trusted-platform findings also expose `VerificationLevel`, while heuristic platform findings expose `Score`.

## ContainerRuntimeReport

`ContainerRuntimeReport` is the top-level DTO returned by the engine.

- `GeneratedAt`, `Duration`, `ProbeToolInfo`
  - metadata about when and with which build the report was produced
- `Probes`
  - raw probe outcomes and normalized evidence after redaction
- `SecurityWarnings`
  - report-level warnings such as a visible Docker socket or relaxed Kubernetes TLS mode
- `Classification`
  - weighted conclusions about containerization, runtime, orchestrator, cloud, host, virtualization, and platform vendor
- `Host`
  - normalized host-visible operating system, kernel, hardware, diagnostic fingerprint, and identity-anchor summaries
- `PlatformEvidence`
  - heuristic platform hypotheses that answer: what does the observed environment look like?
- `TrustedPlatforms`
  - explicit local platform claims that answer: which observed platform claims are strong enough to consume programmatically?

## Working with redaction

`includeSensitive: false` is the safe default.

When `includeSensitive` is `false`, the returned `Probes`, `PlatformEvidence`, and `TrustedPlatforms` reflect the redacted view. Some probes also redact values based on probe context before results reach the engine, so unredacted values may not always be available internally in that mode.

That means consumers can safely serialize and forward the returned report without accidentally depending on hidden internal raw values.

## DiagnosticFingerprints and IdentityAnchors

`Host` now separates two different concerns:

- `DiagnosticFingerprints`
  - read-only diagnostic correlation fingerprints
  - expected to support statistics, environment correlation, and runtime profiling
  - may remain update-sensitive on purpose
- `IdentityAnchors`
  - explicit read-only anchor candidates for stronger workload or host binding scenarios
  - intentionally kept separate from diagnostic fingerprints so diagnostics do not silently become license-binding identifiers
  - current implementation derives digested anchors from explicit cloud instance IDs, Kubernetes node identities, Siemens IED certificate-chain evidence with matched local TLS binding, and host-only `MachineIdDigest` correlation anchors from local Windows `MachineGuid` or Linux `machine-id` values when they are locally observable outside containerized environments
  - anchor values remain redacted in the default safe report even though the anchor metadata stays visible
  - environments without strong anchor sources can legitimately return an empty list

## TrustedPlatforms semantics

`TrustedPlatforms` is intentionally conservative.

It is meant for explicit local artifacts that the library can observe and evaluate without modifying the system. It is not a general-purpose attestation framework.

Current built-in entries are:

- `siemens-ied-runtime`
  - local documented runtime artifact plus bounded plausibility, endpoint reachability, and optional TLS presentation checks
- `windows-host-tpm`
  - local Windows TPM visibility via the Windows TPM API and bounded device plausibility checks
- `container-tpm-visible`
  - visible TPM-related device nodes such as `/dev/tpm0`, `/dev/tpmrm0`, or `/dev/vtpmx` inside the current process environment

Important boundary:

- `container-tpm-visible` means the current process can see TPM-related device nodes
- it does not prove host identity, dedicated ownership, caller identity, or tenant isolation
- stronger validation such as quote verification or caller-specific certificate checks is intentionally left to the consuming application

## Recommended consumption pattern

Use the report in layers:

1. Use `Classification` and `Host` for broad environment understanding.
2. Use `PlatformEvidence` for heuristic UI, diagnostics, or advisory decisions.
3. Use `TrustedPlatforms` only for explicit local claims that your application is prepared to trust.
4. Add application-specific policy or cryptographic validation outside the library when you need stronger guarantees.

## Testing

For unit tests, the probes can be injected directly into `ContainerRuntimeProbeEngine`, and the built-in probe classes also expose internal test seams used by the project test suite.

This keeps the public API small while still allowing deterministic tests for bounded local evidence collection.