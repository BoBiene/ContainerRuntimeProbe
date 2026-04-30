# Hardware Vendors

This page documents the curated hardware-vendor catalog used by Container Runtime Probe.

The goal is to keep hardware-vendor detection explainable and reviewable. Public signal presence in Linux or GitHub is not enough on its own to activate a runtime classification rule. The repository tracks vendors in a catalog with an explicit verification status.

## Verification States

- `VerifiedFromUserSample`: confirmed from a real sample captured by this project
- `VerifiedFromPublicSource`: confirmed from a public source strong enough to enable a runtime rule
- `Candidate`: useful vendor to track, but not yet enabled for runtime classification

## Public Signal Keys

The catalog only uses public, non-identity-oriented hardware signals:

- `kernel.syno_hw_version`
- `dmi.sys_vendor`
- `dmi.board_vendor`
- `dmi.product_name`
- `dmi.board_name`
- `dmi.product_family`
- `dmi.chassis_vendor`
- `dmi.modalias`
- `device_tree.model`
- `device_tree.compatible`
- `platform.modalias`
- `platform.of_compatible`

## Runtime-Active Vendors

- `Synology` — `VerifiedFromUserSample`
- `Siemens` — `VerifiedFromPublicSource`
- `Wago` — `VerifiedFromUserSample`

These entries can influence `PlatformVendor` at runtime.

## Vendor Notes

### Wago

The project now treats `Wago` as runtime-active based on real project samples from two visibility profiles:

- sample fixtures:
	- `docker/real-world-samples/wago-752-9401.json` shows the direct DMI-rich case on a WAGO x86 controller.
	- `docker/real-world-samples/wago-cc100.json` captures the constrained ARM container case where DMI and device-tree may be hidden.
- x86-style WAGO controllers can expose direct DMI signals such as `dmi.sys_vendor`, `dmi.board_vendor`, `dmi.product_name`, and `dmi.modalias`.
- constrained ARM container views may not expose DMI or device-tree files, but can still expose WAGO-specific platform metadata via `platform.of_compatible` and `platform.modalias`, for example `wago,sysinit`.

The following signals are useful for WAGO classification:

- `dmi.sys_vendor`
- `dmi.board_vendor`
- `dmi.product_name`
- `dmi.board_name`
- `dmi.modalias`
- `platform.of_compatible`
- `platform.modalias`

The following signals are not treated as sufficient on their own:

- generic ARM cpuinfo values such as `CPU part`
- generic `cpu.hardware` values such as `Generic DT based system`
- realtime kernel markers such as `PREEMPT_RT`
- opaque kernel release suffixes without a vendor fragment

## Candidate Vendors

- `Beckhoff`
- `PhoenixContact`
- `Advantech`
- `Moxa`
- `BoschRexroth`
- `SchneiderElectric`
- `BAndR`
- `Opto22`
- `Stratus`

These entries stay in the catalog for review and future promotion, but do not currently affect runtime classification.

## Maintenance Rules

- Prefer exact public signal fragments over broad marketing-name guesses.
- Keep vendor rules in `VendorCatalog.cs`, not as ad-hoc `if` chains.
- Promote a candidate only when there is a real project sample or a strong public source for the exact runtime-visible fragment.
- Do not use serial numbers, UUIDs, asset tags, or other host-identity fields.