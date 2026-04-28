# Report Format

`ContainerRuntimeReport` fields:
- `GeneratedAt`, `Duration`
- `Probes[]` with `ProbeId`, `Outcome`, `Evidence[]`, optional `Message`
- `SecurityWarnings[]`
- `Classification`:
  - `IsContainerized`
  - `ContainerRuntime`
  - `RuntimeApi`
  - `Orchestrator`
  - `CloudProvider`
  - `PlatformVendor`

Each classification includes `Value`, `Confidence`, and `Reasons[]` with `EvidenceKeys` references.

## JSON structure (contract)

```json
{
  "GeneratedAt": "2026-04-28T00:00:00+00:00",
  "Duration": "00:00:00.123",
  "Probes": [
    {
      "ProbeId": "runtime-api",
      "Outcome": "Success|Unavailable|AccessDenied|Timeout|NotSupported|Error",
      "Message": "optional",
      "Evidence": [
        { "ProbeId": "runtime-api", "Key": "socket.present", "Value": "/var/run/docker.sock", "Sensitivity": "Public|Sensitive" }
      ]
    }
  ],
  "SecurityWarnings": [
    { "Code": "DOCKER_SOCKET_MOUNTED", "Message": "..." }
  ],
  "Classification": {
    "IsContainerized": { "Value": "True|Unknown", "Confidence": "Low|Medium|High|Unknown", "Reasons": [] },
    "ContainerRuntime": { "Value": "Docker|Podman|...", "Confidence": "...", "Reasons": [] },
    "RuntimeApi": { "Value": "DockerEngineApi|PodmanLibpodApi|...", "Confidence": "...", "Reasons": [] },
    "Orchestrator": { "Value": "Kubernetes|AWS ECS|Cloud Run|...", "Confidence": "...", "Reasons": [] },
    "CloudProvider": { "Value": "AWS|Azure|GoogleCloud|OracleCloud|Unknown", "Confidence": "...", "Reasons": [] },
    "PlatformVendor": { "Value": "Siemens Industrial Edge|Unknown", "Confidence": "...", "Reasons": [] }
  }
}
```
