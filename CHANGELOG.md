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
- Add schema v1.1 `transport` field (`http`/`ssh`/`telnet`/`cli`) to `schemas/atomic-op.schema.yaml` and matching `transport`/`shell` block to `schemas/adapter-profile.schema.yaml`, enabling SSH/Telnet/CLI shell-command atom contracts. The default HTTP runner returns `RUNNER_UNSUPPORTED_OP` for non-http transports; a dedicated `runner/ssh.py` and allowlist entry are required before live execution.
- Add the first SSH transport atom `fw_verify_system_version_cli` with adapter profile `transport: ssh` + `shell` block (`cat /appdata/etc/version`), the `run cli verify-system-version` subcommand, and `runner/ssh.py` live execution via the system `ssh` client (subprocess + optional `sshpass`), reading connection inputs from `--base-url` and the session file and credentials from `--credential-env`.
- Add the Telnet transport atom `fw_verify_system_version_telnet` with adapter profile `transport: telnet` + `shell` block (`cat /appdata/etc/version`), the `run cli verify-system-version-telnet` subcommand supporting an independent `--host`/`--port` pair (defaults to host parsed from `--base-url` and port 23), and `runner/ssh.py` telnet live execution via Python stdlib `telnetlib` (interactive login flow + command output capture), reading username from the session file and the credential from `--credential-env`.
- Switch the SSH runner from system `ssh`/`sshpass` subprocess to `paramiko` (pure-Python SSH) for cross-platform password authentication without `sshpass`; add `paramiko` to `pyproject.toml` dependencies. Register `STATE_MISMATCH` (52) in `repository.EXIT_CODES` (previously raised but unmapped, causing `KeyError`).
- Add SSH query atoms `fw_check_bvi_interface_config` (`etcdctl get --print-value-only /vnf-agent/vpp1/config/vpp/v2/interfaces/bvi{{id}}`, param `bvi_id`) and `fw_check_bridge_domain` (`/opt/dbappsecurity/bin/vppctl show bridge-domain`), with adapter profile `transport: ssh` + `shell` blocks, `run cli check-bvi-interface-config`/`check-bridge-domain` subcommands, and a shared `_execute_ssh_query` helper in `runner/ssh.py`.
- Add Telnet query atoms `fw_check_bvi_interface_config_telnet` and `fw_check_bridge_domain_telnet` mirroring the SSH variants with `transport: telnet`, supporting an independent `--host`/`--port` pair (defaults to host parsed from `--base-url` and port 23), reusing the `_execute_telnet_query` helper for live execution via `telnetlib`.
- Add CLI-level error codes `RUNNER_SHELL_CONNECT_FAILED` (50), `RUNNER_SHELL_COMMAND_TIMEOUT` (51), and `RUNNER_SHELL_UNEXPECTED_PROMPT` (52) to `docs/error-codes.md`.
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
- Add `fw_delete_object` atom spec, adapter profile mapping, and allowlisted runner support: `DELETE /api/v1/ippool?id=<object-name>` deletes a single NGFW address object by name, with a `restore_snapshot` rollback that recreates the object via `fw_config_object` and confirms via `fw_verify_object`.
- Add `fw_update_object` and `fw_delete_batch_object` atom specs, adapter profile mappings, and allowlisted runner support: `fw_update_object` updates an NGFW address object via `PUT /api/v1/ippool` with a top-level `id` and `val` body mirroring the POST shape; `fw_delete_batch_object` batch-deletes multiple address objects via `POST /api/v1/batch` with `DELETE /api/v1/ippool` items, mirroring the iptun batch pattern.
- Add ACL control-policy and policy-group full CRUD atom specs, adapter profile mappings, and allowlisted runner support: `fw_config_acl_policy`, `fw_update_acl_policy`, `fw_delete_acl_policy`, `fw_delete_batch_acl_policy`, `fw_verify_acl_policy` over `/api/v1/ip{4,6}policy/fwaclconf`, and `fw_config_acl_policy_group`, `fw_update_acl_policy_group`, `fw_delete_acl_policy_group`, `fw_verify_acl_policy_group` over `/api/v1/ip{4,6}policy/group`. IPv4 and IPv6 are selected by `--policy-type`, which only changes the request path; the val body is identical for both families and carries no address-family marker. `fw_config_acl_policy` and `fw_verify_acl_policy` replace the prior abstract contract atoms; the multi-device `fw_config_batch_acl_policy` batch contract is removed in favor of the single-device `fw_delete_batch_acl_policy` over `POST /api/v1/batch`. Control-policy `update` requires the `id` resolved by a `verify` query (the device returns no id on create); policy-group `update` renames via `old_name`/`new_name` with a fixed `id` of `1`.
- Extend `rollbackStrategyContract` in `schemas/atomic-op.schema.yaml` with optional `id_source`, `id_field`, `query_op`, `query_match`, and `query_match_source` fields that declare how an `inverse_op` rollback obtains the target id for its PUT/DELETE. Apply the four id-passing modes: `fw_config_policy_route` (`id_source: response`), `fw_config_object` (`id_source: args`, plus a new `side_effect: state_mutation` + `inverse_op` rollback to `fw_delete_object`), `fw_config_acl_policy` (`id_source: query` via `fw_verify_acl_policy`), and `fw_update_acl_policy_group` (rollback changed from `restore_snapshot` to `inverse_op` rename-back with `id_source: placeholder`).

- Add TG ASTF stateful operation atoms, adapter profile mappings, and allowlisted runner support: `tg_config_stateful_interface` (ASTF port L3 config + ARP + gratuitous ARP announcement of the template IP pool), `tg_apply_stateful_template` (load http/dns/ftp/mixed profiles with tunables), `tg_start_stateful_stream` (CPS multiplier + duration), `tg_verify_stateful_metrics` (zero-traffic guard, flow-count guard, and incremental loss-ratio judgement), `tg_stop_stateful_stream`, and `tg_delete_stateful_template`. Extend the `traffic` package manifest to v1.3.0 with these six operations.

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
- Repurpose `fw_verify_object` from a contract-only verification (based on `config_result_ref`) to a device query operation (`GET /api/v1/ippool?page=&size=`) aligned with `fw_verify_iptun`; the `op_id` is unchanged, the `ngfw_verification` package reference is unchanged, and `since_version` remains `1.1.0`.
- Merge the SSH and Telnet shell atoms into unified transport-aware ops: `fw_verify_system_version`, `fw_check_bvi_interface_config`, and `fw_check_bridge_domain`. Each op declares `transport: ssh` as the default in its atom file and exposes a runtime `--transport ssh|telnet` CLI parameter (plus `--host`/`--port` overrides) that routes the runner to `_run_ssh_command` (paramiko) or `_run_telnet_command` (telnetlib) via a shared `_run_shell_command` dispatcher. The legacy `fw_verify_system_version_cli`, `fw_verify_system_version_telnet`, `fw_check_bvi_interface_config_telnet`, and `fw_check_bridge_domain_telnet` op_ids are removed from `atoms/` and mapped in `DEPRECATED_OP_MAP` for backward-compatible CLI dispatch.

### Deprecated

- The per-transport op_ids `fw_verify_system_version_cli`, `fw_verify_system_version_telnet`, `fw_check_bvi_interface_config_telnet`, and `fw_check_bridge_domain_telnet` are deprecated in favor of the unified ops with the `--transport` parameter; they remain dispatchable via `DEPRECATED_OP_MAP` for one to two versions.

### Removed

- Remove the redundant per-transport atom files `atoms/fw/fw_verify_system_version_cli.yaml`, `atoms/fw/fw_verify_system_version_telnet.yaml`, `atoms/fw/fw_check_bvi_interface_config_telnet.yaml`, and `atoms/fw/fw_check_bridge_domain_telnet.yaml` after merging their SSH/Telnet variants into the unified transport-aware ops. Legacy op_ids remain dispatchable through `DEPRECATED_OP_MAP`.

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
