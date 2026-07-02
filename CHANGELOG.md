# Changelog

This repository uses two version streams:

- `atoms-vX.Y.Z`: operation data, schema, package manifests, naming rules, and documentation consumed by `ptm-atomic sync`.
- `cli-vX.Y.Z`: CLI package code, command behavior, CLI error handling, and CLI packaging changes consumed by `uv tool upgrade ptm-atomic`.

The two streams are intentionally separate. A schema or operation-library change does not imply a CLI package release, and a CLI bug fix does not imply a new operation-library release.

## Unreleased

### Added

- Add the initial atomic operation schema contract in `schemas/atomic-op.schema.yaml`.
- Add the schema field reference in `docs/schema-field-reference.md`.
- Add the naming convention baseline in `docs/naming-convention.md`.
- Add this changelog baseline with `atoms-vX.Y.Z` and `cli-vX.Y.Z` version stream guidance.
- Add TG traffic generator operation atoms:
  `tg_start_traffic_stream`, `tg_capture_traffic_result`,
  `tg_verify_traffic_loss`, `tg_stop_traffic_stream`, and
  `tg_delete_traffic_stream`.
- Add the `traffic` package manifest for TG stream lifecycle and statistics
  verification operations.
- Add schema v1.1 documentation coverage for `risk`, `credential_ref`, `session_ref`, `state_ref`, `gate`, `verification`, and `batch`.
- Add user-facing guidance for `ngfw_installation`, `ngfw_capacity_config`, `ngfw_verification`, and `ngfw_batch_config`.
- Add the CR-004 public adapter profile layer with `schemas/adapter-profile.schema.yaml`, `adapters/ngfw/default.yaml`, and `docs/API-ADAPTER-SPEC.md`.
- Add the read-only `ptm-atomic adapter <op_id>` command for querying a synced atom's referenced adapter profile operation.
- Add the allowlisted `ptm-atomic run` runner for `fw_login_web_management`, `fw_config_object`, and `fw_config_policy_route`, with dry-run by default and explicit `--execute` for live device requests.
- Add OSPFv2 atom specs, adapter profile mappings, and allowlisted runner support for global config, redistribution, network, interface, neighbor, and log endpoints.
- Add OSPFv3 and BFD atom specs, adapter profile mappings, and allowlisted runner support for config, query, delete, session, and log endpoints.
- Add release guidance for repository checks using `uv run ptm-atomic --help`, `uv run ptm-atomic packages`, `uv run --python 3.11 python scripts/validate_schema.py atoms`, `uv run --python 3.11 python scripts/layout_check.py`, and `uv run --python 3.11 python scripts/security_gate_check.py`.
- Add `fw_reset_policy_route_hitcount` and `fw_verify_policy_route_hitcount` atom specs, adapter profile mappings, and allowlisted runner support for clearing and querying policy-route hit counts over IPv4 and IPv6.
- Add iplink, iplink-group, batch-delete, and operation-log atom specs, adapter profile mappings, and allowlisted runner support: `fw_config_iplink`, `fw_update_iplink`, `fw_delete_iplink`, `fw_verify_iplink`, `fw_config_iplink_group`, `fw_update_iplink_group`, `fw_delete_iplink_group`, `fw_verify_iplink_group`, `fw_delete_batch_iplink`, `fw_delete_batch_iplink_group`, and `fw_capture_operation_log`.
- Add IP tunnel atom specs, adapter profile mappings, and allowlisted runner support: `fw_config_iptun`, `fw_update_iptun`, `fw_verify_iptun`, `fw_delete_iptun`, and `fw_delete_batch_iptun` over `/api/v1/iptun`, covering 4over6 (type 15), 6over4 (type 16), and gre (type 11) tunnels with IPv-version endpoint validation.
- Extend `fw_update_interface` and `fw_verify_interface` to support `interface-kind tunnel` for tunnel interface configuration over `/api/v1/intf` (PUT and GET only); creating an IP tunnel brings up the associated tunnel interface, which is configured through the interface runner.
- Add business-semantic aliases to `fw_config_interface`, `fw_update_interface`, `fw_verify_interface` (`pppoe`, `dhcp`, `southbound-interface`, `tunnel`, `ipip`, `gre`, `4over6`, `6over4`) and `fw_config_acl_policy`, `fw_verify_acl_policy` (`security-policy`, `ipv4-security-policy`, `control-policy`) so consumers can discover folded operations by business term.
- Add `ptm-atomic list --query <keyword>` for case-insensitive discovery of operations by `op_id`, `aliases`, `tags`, or `description`.
- Extend `ptm-atomic validate` `OP_NOT_FOUND` output with `alias_suggestions` that map a missing business op_id (e.g. `fw_config_pppoe`) to the folded operation via aliases.
- Add configuration import/export and reboot atom specs, adapter profile mappings, and allowlisted runner support: `fw_config_export_file` (3-step async download workflow over `/api/v1/downloadfilehandle` and `/api/v1/downloadfile`), `fw_config_import_file` (4-step async upload workflow over `/api/v1/uploadfile`, `/api/v1/uploadfilehandle`, and `/api/v1/importfile`), and `fw_config_reboot` over `/api/v1/reboot`. `moduletype` is an open string so non-systemconfig modules pass through unchanged.
- Extend `runner/http.py` with `request_bytes` for binary downloads and `request_multipart` for form-data uploads; add `runner/polling.py` `poll_until` for async task polling. Reboot is a terminal destructive action whose runner never issues follow-up requests, so the expected post-reboot disconnect is not misread as `DEVICE_UNREACHABLE`.
- Add HA (high availability) atom specs, adapter profile mappings, and allowlisted runner support: `fw_config_hasync`, `fw_verify_hasynclist`, `fw_config_haconfig`, `fw_config_hainterface`, `fw_verify_hainterface`, `fw_delete_hainterface`, `fw_delete_batch_hainterface`, `fw_config_havrrp`, `fw_update_havrrp`, `fw_verify_havrrp`, `fw_delete_havrrp`, `fw_delete_batch_havrrp`, `fw_config_haiplink`, `fw_verify_haiplink`, `fw_delete_haiplink`, `fw_delete_batch_haiplink`, `fw_config_halinkgroup`, `fw_verify_halinkgroup`, `fw_delete_halinkgroup`, `fw_delete_batch_halinkgroup`. haiplink/halinkgroup use a dedicated runner because their DELETE path (`/api/v1/ha/iplink`) carries an `isGroup` flag that diverges from the iplink pattern; haiplink/halinkgroup do not support PUT.

### Changed

- Update README, user manual, engineer handbook, and test-case template to reflect the verified schema v1.1, NGFW atom/package, batch contract, security gate, and read-only CLI boundary.
- Replace environment-specific repository address examples with `<ptm-atomic-git-repository-url>` placeholders.
- Align Python command examples with `uv run` and `uv tool` usage.
- Clarify that package manifests are filter views for `op_id` selection only; they do not install, copy, execute, or distribute atoms.
- Record current package integrity facts: 6 manifests, 69 package entries, 68 unique `op_id` values, and all package references resolving to `atoms/fw/*.yaml`.
- Separate working-tree repository checks from synced-cache consumer smoke checks, and document the stale-cache caveat for `list`, `show`, `packages`, and `validate`.
- Align error-code documentation with the current `scripts/security_gate_check.py` behavior and the CLI error object shape, including the optional `suggestion` field.
- Add `adapter_contract_ref` to `fw_config_policy_route` so external generators can consume the public adapter profile instead of reading `.input/capacity`.
- Include `adapters/` in the `ptm-atomic sync` sparse checkout paths so adapter profile queries can work from the local cache.
- Align `fw_config_policy_route` with the executable NGFW API shape: `POST /api/v1/policyroute` and `val.source_network` / `val.dst_network` / `val.forwarding_paths[].next_hop_ip`.
- Clarify that policy route `source_network` and `dst_network` reference address object names by default, with explicit `*_is_group` flags for address group names.
- Make successful `ptm-atomic run` stdout use the fixed envelope `op_id`, `status`, `data`, `error_type`, and `diag_snapshot_ref`; runner-specific request, session, and response details now live under `data`.
- Allow digits in the `op_id` target segment so protocol names such as `ospfv2` can be represented directly.

### Deprecated

- None.

### Removed

- None.

### Fixed

- None.

### Security

- Document that only the `ptm-atomic run` allowlist can connect to devices or push configuration, while other CLI commands remain cache/query/validation commands.
- Document the sensitive-information boundary for user-facing examples; the only allowed password-policy literal remains `Ngfw@123`.
- Document `.gitignore` hygiene for `.input/`, `process/`, `checkpoints/`, generated local `AGENTS.md`, local agent config, caches, and logs as process/runtime artifacts rather than delivery docs.
- Extend adapter validation and the default security scan to cover `adapters/`, rejecting runtime-sensitive adapter fields or values and hidden `.input/capacity` dependencies.
- Keep runner runtime material out of repository files; login accepts password material only through environment variables and writes session files outside the repo by default.

## atoms-v0.1.0 - 2026-05-13

Initial operation-library contract baseline.

### Added

- Define schema v1 terminology around `op_id`, `device_type`, mapped `parameters`, fixed `returns`, `deprecated_by`, and `since_version`.
- Define the current `op_id` naming pattern: `^(fw|tg|mock|sw)_[a-z]+_[a-z0-9_]+$`.
- Define the controlled verb baseline: `create`, `delete`, `update`, `apply`, `rollback`, `verify`, `start`, `stop`, `reset`, `capture`.
- Define the initial changelog format and release-note categories.

### Changed

- None.

### Deprecated

- Historical schema wording such as `operation_id`, `device`, `parameters` arrays, `output_schema`, `since`, `reason`, and `replaced_by` is retained only as migration context and is not accepted by schema v1.

### Removed

- None.

### Fixed

- None.

### Security

- No credential, token, private key, or production endpoint data is included in the baseline examples.

## cli-v0.1.0 - 2026-05-13

Initial CLI version stream placeholder.

### Added

- Reserve the `cli-vX.Y.Z` tag stream for future `ptm-atomic` package releases.

### Changed

- None.

### Deprecated

- None.

### Removed

- None.

### Fixed

- None.

### Security

- None.

## Maintenance Rules

- Add operation YAML, schema, package, naming, and documentation changes under the next `atoms-vX.Y.Z` section.
- Add CLI command, packaging, dependency, and runtime behavior changes under the next `cli-vX.Y.Z` section.
- Use `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, and `Security` consistently.
- Record `op_id` renames as `Deprecated` for the old operation and `Added` for the replacement.
- Keep `Unreleased` at the top and move entries into a versioned section during release preparation.
