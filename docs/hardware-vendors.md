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

## Runtime-Active Vendors

- `Synology` — `VerifiedFromUserSample`
- `Siemens` — `VerifiedFromPublicSource`

These entries can influence `PlatformVendor` at runtime.

## Candidate Vendors

- `Wago`
- `Beckhoff`
- `PhoenixContact`
- `Advantech`
- `Moxa`
- `BoschRexroth`
- `SchneiderElectric`
- `BAndR`

These entries stay in the catalog for review and future promotion, but do not currently affect runtime classification.

## Maintenance Rules

- Prefer exact public signal fragments over broad marketing-name guesses.
- Keep vendor rules in `VendorCatalog.cs`, not as ad-hoc `if` chains.
- Promote a candidate only when there is a real project sample or a strong public source for the exact runtime-visible fragment.
- Do not use serial numbers, UUIDs, asset tags, or other host-identity fields.