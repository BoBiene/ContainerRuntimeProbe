# TODO

## Active Identity Candidate Rollout (2026-05-02)

Statusbasis: [docs/identity-matrix.md](docs/identity-matrix.md) beschreibt den aktuellen Ist-Stand, die Candidate-Quellen und die Ziel-Level fuer `Host`, `Container`, `Environment` und spaeter optional `Hypervisor`.

Arbeitsregeln fuer diese Runde:

- kleine, nachvollziehbare Schritte
- pro erledigtem TODO genau ein Commit
- nach jedem fachlichen Schritt Build und passende Tests
- keine grossen Umbauten ohne direkten Bezug zum aktuellen TODO

### Ready In Worktree

- [x] **34. Format-aware identity projection defaults abschliessen**
  - JSON redigiert Identity-Anchor-Werte standardmaessig, Markdown und Text lassen sie standardmaessig sichtbar, sofern kein Override gesetzt ist.
- [x] **35. Workload- und Environment-L1-Semantik fuer Containerfaelle abschliessen**
  - Containerisierte Faelle bekommen eine schwache `Container ID` aus Namespace-Tupeln und eine schwache `Deployment ID` bzw. `Environment ID` aus der Summary-Korrelation.
- [x] **36. Windows host evidence parity abschliessen**
  - Windows sammelt konservativ CPU-Familie/Modell/Stepping, sichtbaren Speicher, Chassis-Vendor und den robusteren `MachineGuid`-Pfad.
- [x] **37. Identity matrix und aktive Candidate-Planung dokumentieren**
  - Die Matrix ist als Referenzdoku verlinkt und das TODO-Backlog wird daraus in konkrete Implementierungsschritte ueberfuehrt.

### Planned Implementation Steps

- [x] **38. Linux host unique-ID evidence sammeln**
  - `proc-files` sammelt zusaetzlich hostgebundene, read-only Quellen wie SMBIOS-UUIDs/Serien und ARM-/SoC-Serienwerte, soweit sie sichtbar sind.
- [x] **39. Host-Anchor aus expliziten Hardware-IDs einfuehren**
  - Sichtbare SMBIOS-, CPU- oder SoC-Identifier werden mit klaren Staerke- und Container-Grenzen in konservative Host-Anchors umgesetzt.
- [ ] **40. Schwachen universellen Host-L1-Fallback einfuehren**
  - Wenn keine explizite Host-ID sichtbar ist, wird ein rein korrelationsgeeigneter Host-Profil-Digest als `L1` abgebildet.
- [ ] **41. Kubernetes Environment-L2 ohne RBAC einfuehren**
  - Ein Cluster-/Environment-Digest wird aus bereits sichtbarem Service-Account-CA- oder API-Zertifikatsmaterial abgeleitet, ohne neue Rechte zu erwarten.
- [ ] **42. Compose- und Portainer-Deployment-Identity erweitern**
  - Sichtbare Compose-/Portainer-Metadaten aus Socket-Inspect werden als staerkerer Deployment-/Environment-Kandidat genutzt.
- [ ] **43. Kubernetes workload candidate sources erweitern**
  - Sichtbare Pod-/Container-Korrelation aus CGroup- oder Mount-Signalen wird ausgewertet, wenn kein Runtime-Inspect moeglich ist.
- [ ] **44. Cloud Environment-L2 einfuehren**
  - Mandanten-, Projekt- oder Subscription-nahe Cloud-Metadaten werden als Environment-Kandidaten modelliert, wenn sie sichtbar und sicher nutzbar sind.
- [ ] **45. TPM public-material identity path einfuehren**
  - Read-only TPM-Public-Material wird fuer Host-/Platform-Anchors genutzt und mit bestehender Trust-Korroboration verbunden.
- [ ] **46. Hypervisor identity path einfuehren**
  - Guest-sichtbare VM-UUID-/Generation-ID-Quellen werden fuer eine dedizierte Hypervisor-Identity ausgewertet.
- [ ] **47. Abschlussvalidierung, Doku und Nachlauf**
  - Jede neue Quelle braucht passende Tests, Renderer-/Summary-Abdeckung, Doku-Updates und eine Abschlusspruefung der offenen Risiken.

## Archived Completed Rollouts

- [x] **01-17. Fingerprint / Identity Anchor Rollout**
  - Contract-Split, Anchor-/Fingerprint-Trennung, Privacy-Defaults, Doku und Testmatrix sind abgeschlossen.
- [x] **18-22. Identity Anchor Expansion**
  - Siemens-Runtime, Windows-Maschinen-ID, Linux-`machine-id`, Container-Anchor-Regeln und Validierung sind abgeschlossen.
- [x] **23-33. Neutral Summary Report Model**
  - Summary-Modelle, Scope-Trennung, Renderer-Integration, Doku und Abschlussvalidierung sind abgeschlossen.
- [x] **Review Follow-Up backlog**
  - Kritische und mittlere Review-Punkte sowie der dokumentierte Nice-to-have-Nachlauf wurden abgearbeitet, soweit nicht unten explizit verschoben.

## Deferred Or External

- [ ] **SampleRegressionTests pre-existing failure**
  - `docs/samples/examples/*.sample.json` fehlen weiterhin im Repository; der Fehler predatiert die aktuelle Candidate-Runde.
- [ ] **Git history cleanup**
  - Fruehe Commits auf dem Alt-Branch mit GPL-Daten sollten vor einem Merge nach `main` separat bereinigt werden, falls die Historie sauber bleiben soll.
- [ ] **Override-Loader stretch**
  - `DetectionMaps.LoadOverrides(string? path)` plus `--detection-map` bleibt ausserhalb dieses Candidate-Rollouts.
