# ContainerRuntimeProbe

ContainerRuntimeProbe is a vendor-neutral .NET 8 library and CLI tool that inspects container-runtime signals and emits a structured **Container Runtime Report**.

## Packages
- `ContainerRuntimeProbe`
- `ContainerRuntimeProbe.Tool`

## Quickstart (tool)
```bash
dotnet tool install --global ContainerRuntimeProbe.Tool
container-runtime-probe --format markdown
container-runtime-probe --format json --timeout 00:00:02
```

## Quickstart (library)
```csharp
var engine = new RuntimeProbeEngine();
var report = await engine.RunAsync(TimeSpan.FromSeconds(2), includeSensitive: false);
```

## Security notes
- Allowlisted environment variable collection.
- Sensitive values are redacted by default.
- Probe failures are reported, not fatal.

## Limitations
Classification is heuristic and confidence-weighted; the tool avoids absolute claims unless strong evidence exists.
