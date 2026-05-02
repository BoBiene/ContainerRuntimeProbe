# TODO

## Fingerprint / Identity Anchor Rollout (2026-05-01)

Statusbasis: Session-Plan mit 4 Phasen und 14 Punkten, abgeglichen gegen den aktuellen Worktree auf `feature/fingerprints`.

### Phase 1: Contract split

- [x] **1. Public Model splitten**
  - `Host.Fingerprint` wird in `DiagnosticFingerprints[]` und `IdentityAnchors[]` getrennt.
- [x] **2. Ziele und Enums explizit modellieren**
  - Diagnose- und Anchor-Zwecke, Stabilitaet, Staerke, Scope und Sensitivity sind als neue Typen modelliert.
- [x] **3. Breaking-Change-Migration festziehen**
  - Primare API- und Report-Format-Doku ist auf den neuen Contract umgestellt.

### Phase 2: Diagnostic fingerprints vs. identity anchors

- [x] **4. Diagnostic-Fingerprint-Pfad isolieren**
  - `CRP-HOST-FP-v1` lebt als erster `DiagnosticFingerprint` weiter.
- [x] **5. Identity-Anchor-Pfad real implementieren**
  - `BuildIdentityAnchors(...)` wertet jetzt explizite Cloud-Instance- und Kubernetes-Node-IDs aus.
- [x] **6. Zulaessige Anchor-Quellen festlegen und priorisieren**
  - Erster Ausbau laeuft jetzt ueber `CloudInstanceIdentity` und `KubernetesNodeIdentity`; TPM-/Zertifikat-Digests und Vendor-Runtime-IDs bleiben explizit als spaetere Erweiterung markiert.
- [x] **7. Read-only-TPM-Regel explizit machen**
  - Keine Key-Erzeugung, keine Provisionierung, nur Digests ueber bestehendes oeffentliches Material.
- [x] **8. Trust sauber von Identity trennen**
  - `IdentityAnchors` werden im Host-Builder separat aus Evidenz erzeugt und haengen nicht an `TrustedPlatforms`.
- [x] **9. Anchor-Staerken und Binding-Regeln kodieren**
  - Cloud-Instance-IDs werden als `Strong`, Kubernetes-Provider-ID-Fallbacks als `Medium`, und schwache generische Signale gar nicht als Anchor modelliert.
- [x] **10. Scope- und Privacy-Defaults festziehen**
  - Host-Report redigiert Anchor-Werte standardmaessig; Renderer, Sample-Export und Doku beschreiben den sicheren Default jetzt konsistent.

### Phase 3: Probe- und Builder-Verantwortung

- [x] **11. Anchor-faehige Evidenzpfade aufraeumen**
  - Cloud-/Kubernetes-Evidenz fuer stabile IDs wird jetzt explizit gesammelt und separat im Host-Builder ausgewertet.
- [x] **12. Rendering und Doku vollstaendig angleichen**
  - `security.md`, `probe-catalog.md`, Renderer und API-Erzaehlung muessen Diagnose/Anchor/Privacy konsistent beschreiben.

### Phase 4: Validation and limits

- [x] **13. Testmatrix aufspalten**
  - Getrennte Tests fuer Diagnose-Fingerprints, Anchor-Selektion, Redaction, Renderer und Sample-Export sind nachgezogen.
- [x] **14. Plattformgrenzen explizit machen**
  - Schwache generische Signale bleiben ohne Anchor; Doku und Tests halten leere oder fehlende Anchors explizit fuer korrekt.

### Additional Open Points Found During Validation

- [x] **15. Legacy-Ausgabelabels bereinigen**
  - Renderer-, Sample- und Beispieltexte sprechen jetzt konsistent von `DiagnosticFingerprint` bzw. `IdentityAnchors`.
- [x] **16. Beispiel- und Release-Doku nachziehen**
  - `CHANGELOG`, Beispielreports und die relevante API-/Security-Doku sind auf den aktuellen Anchor-/Redaction-Stand gebracht.
- [x] **17. RuntimeSampleRenderer Analyzer-Debt abbauen**
  - Abschlussvalidierung zeigt noch bestehenden Maintainability- und Literal-Debt in `RuntimeSampleRenderer.cs`; das ist der letzte offene technische Nachlauf dieser Runde.

## Identity Anchor Expansion (2026-05-02)

Statusbasis: naechster Ausbau nach dem abgeschlossenen Cloud-/Kubernetes-Rollout. Fokus sind drei zusaetzliche Kategorien: Siemens-Runtime, Windows-Host und Linux-/Container-Identitaet.

### Phase 1: Siemens

- [x] **18. Siemens-IED-VendorRuntimeIdentity einfuehren**
  - Ein `VendorRuntimeIdentity` darf nur aus bestehender lokaler IED-TLS-/Cert-Bindung entstehen, nicht aus Labels, Env-Variablen oder Vendor-Strings allein.

### Phase 2: Windows

- [x] **19. Windows-Anchor-Quelle definieren und implementieren**
  - TPM-Praesenz bleibt getrennt von Identitaet; ein Windows-Anchor braucht bestehendes Public-Material oder eine konservative Maschinen-ID-Regel.

### Phase 3: Linux / Container

- [x] **20. Linux-Host-Anchor aus `machine-id` pruefen und umsetzen**
  - Host-Bindung soll ueber explizite, read-only Host-IDs laufen, nicht ueber Hostname oder CPU-Serial.
- [x] **21. Container-Scoped Anchor-Regel einfuehren**
  - Wenn ein Container-Anchor kommt, dann als eigener workload-/runtime-scoped Anchor statt als schwacher Host-Ersatz.

### Phase 4: Validation and follow-up

- [x] **22. Renderer-, Doku- und Negativtests nachziehen**
  - Jede neue Anchor-Klasse braucht Default-Redaction, Renderer-Abdeckung und explizite Ausschluss-Tests fuer schwache Ersatzsignale.

## Neutral Summary Report Model (2026-05-02)

Statusbasis: naechster Ausbau nach dem abgeschlossenen Anchor-Rollout. Ziel ist eine neutrale, scope-saubere Summary-Schicht fuer Laufkontext und sichtbare Identitaetskandidaten, ohne den bisherigen Detailreport zu verlieren.

### Phase 1: Contract and structure

- [x] **23. Neutralen Summary-Rollout im Repo verankern**
  - Der neue Ausbau wird im `TODO.md` als Vier-Phasen-Plan mit neutraler Report-Sprache, Scope-Regeln und Follow-up-Pfaden festgehalten.
- [x] **24. Summary-Modelle und Scopes in dedizierten Files einfuehren**
  - `EnvironmentSummary`, `IdentitySummary` und ihre Facts sollen nicht als weitere grosse Klassen in bestehende Sammelfiles gepresst werden; Scope-Typen fuer `Host`, `Node`, `Platform`, `Deployment`, `Workload` und `Runtime` werden explizit modelliert.

### Phase 2: Summary derivation

- [x] **25. EnvironmentSummary-Ableitung implementieren**
  - Der Report soll kompakte, neutrale Fakten zu Runtime, Execution Context, Host, Platform und Trust ableiten, ohne Unknowns oder narrative Vollsaetze in die Summary zu ziehen.
- [x] **26. IdentitySummary-Ableitung und Level-Mapping implementieren**
  - Sichtbare Identitaetskandidaten werden strikt nach `Workload`, `Deployment`, `Node/Platform` und `Host` getrennt; Levels werden zentral aus bestehenden Staerke-/Trust-Signalen abgeleitet.
- [x] **27. Deployment-Identity-Pfad und Scope-Matrix kodieren**
  - Auch wenn noch nicht jede Quelle voll implementiert ist, soll das Modell den separaten `Deployment`-Scope bereits sauber tragen und die Varianten `Windows Bare`, `Standalone Container`, `Industrial Container` und `Kubernetes` explizit abdecken.

### Phase 3: Rendering and structure

- [x] **28. Summary in JSON, Markdown und Text integrieren**
  - `ContainerRuntimeReport` liefert die neue Summary strukturiert in JSON; Markdown und Text rendern oben kompakte Facts/Rows und lassen die bisherigen Detailsektionen darunter vollstaendig stehen.
- [x] **29. Summary- und Renderer-Helfer bei Bedarf aufsplitten**
  - Wenn `Renderers.cs`, `ContainerRuntimeReportExtensions.cs` oder Modellfiles durch den Ausbau zu komplex werden, werden Hilfslogik und Modelle in dedizierte Files verschoben statt mehrere grosse Klassen in einem File zu sammeln.

### Phase 4: Validation and follow-up

- [x] **30. Summary-Testmatrix und Golden-Coverage nachziehen**
  - Unit- und Renderer-Tests muessen `EnvironmentSummary`, `IdentitySummary`, Scope-Trennung, K8s-Mehrfachspuren und fehlende Unknowns absichern.
- [ ] **31. Report-/API-Doku und Beispielprofile aktualisieren**
  - `report-format.md`, `dotnet-api.md` und passende Beispielreports dokumentieren die neue Summary und die Scope-Regeln fuer die Zielvarianten.
- [ ] **32. Abschlussvalidierung und neue Open Points einsortieren**
  - Nach Build/Test/Smoke werden neue technische Schulden oder noetige Refactorings als weitere TODO-Punkte angelegt und in denselben iterativen Plan aufgenommen.

## Critical

All critical issues resolved. ✅

## High

All high priority issues resolved. ✅

## Medium

- [x] **Host OS / Node reporting** — **DONE**
  - Added structured `Host` output with `ContainerImageOs`, `VisibleKernel`, `RuntimeReportedHostOs`, `Hardware`, and `Fingerprint`.
  - Added distro, architecture, kernel flavor, runtime host source, and fingerprint stability normalization.
  - Added safe host enrichment from Docker `/info`, Podman `/libpod/info`, Kubernetes `status.nodeInfo`, and cloud metadata.
  - Added privacy-aware `CRP-HOST-FP-v1` host fingerprinting with deterministic hashing and excluded sensitive signals.

## Verified Done

- [x] Build succeeds with 0 warnings/errors (`dotnet build -c Release`)
- [x] Test suite covers host parsing, normalization, fingerprinting, renderers, and fake runtime metadata mapping
- [x] CLI tool produces host reporting for `--format json/markdown/text`
- [x] Docs updated for host reporting, fingerprint privacy, and examples

## Review Follow-Up (2026-04-29)

### Critical

- [x] **1. Parallel probe execution** — `ContainerRuntimeProbeEngine.RunAsync` now runs the selected probe set concurrently while preserving report order.
- [x] **2. Shared IMDS client/pooling** — `CloudMetadataProbe` now reuses one client per normalized base URI and fans out provider metadata requests concurrently.
- [x] **3. Kubernetes TLS mode** — default remains compatibility-first so in-cluster probing just works, but the report now emits `KUBERNETES_TLS_VALIDATION_SKIPPED` and the CLI/library can switch to strict TLS validation.

### Medium

- [x] **4. Public probe-context overrides** — `ProbeExecutionOptions` now exposes Kubernetes and metadata endpoint overrides on the public engine API.
- [x] **5. AppArmor vs SELinux parsing** — `SecuritySandboxProbe` now validates SELinux context shape explicitly and records `/sys/fs/selinux/enforce` evidence separately.
- [x] **6. Stronger OnPrem classification** — on-prem scoring now leans on corporate DNS, host-type corroboration, and visible default routes instead of giving cloud-metadata probe presence two free points.
- [x] **7. Runtime harness coverage** — `docker-harness.yml` now fans out across default Docker, `--privileged`, `--network host`, and rootless Podman runs.
- [x] **8. Parallel `/proc` reads** — `ProcFilesProbe` now starts the proc/sys file reads concurrently while preserving stable processing order.

### Nice To Have

- [x] **9. Shared JSON helper** — the duplicate `GetString(JsonElement, string)` logic now lives in a shared internal `JsonHelper`.
- [x] **10. Cross-OS unit-test matrix** — `ci.yml` now runs the main build-and-test job on Ubuntu, Windows, and macOS.
- [x] **11. TODO backlog refreshed** — this file now tracks the current review backlog instead of reporting `None known`.
- [x] **12. Stronger smoke/integration fixtures** — `SmokeIntegrationTests` now exercises real sample-report fixtures for proc, mountinfo, os-release, and WSL2-specific signals.

### Carry-Over

- [ ] **`SampleRegressionTests` pre-existing failure** — `docs/samples/examples/*.sample.json` files are missing from the repository. This failure predates the current review work.
- [ ] **Git history cleanup** — the early commits `Vendor curated os-release fixtures` and `Use license-safe detection map fixtures` on `feat/static-detection-map` contain GPL data in history. Consider `git rebase -i` squash/drop before merging to `main` if history cleanliness matters.
- [ ] **Override-Loader (stretch)** — `DetectionMaps.LoadOverrides(string? path)` + `--detection-map` CLI flag for user-supplied custom maps at runtime.
