# Report Format

`ContainerRuntimeReport` fields:
- `generatedAt`, `duration`
- `probes[]` with `probeId`, `outcome`, `evidence[]`, optional `message`
- `securityWarnings[]`
- `classification` with:
  - `isContainerized`
  - `containerRuntime`
  - `runtimeApi`
  - `orchestrator`
  - `cloudProvider`
  - `platformVendor`

Each classification includes `value`, `confidence`, and reason objects with `evidenceKeys` references.
