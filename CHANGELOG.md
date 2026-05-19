# Changelog

This repository uses two version streams:

- `atoms-vX.Y.Z`: operation data, schema, package manifests, naming rules, and documentation consumed by `atomic-ops sync`.
- `cli-vX.Y.Z`: CLI package code, command behavior, CLI error handling, and CLI packaging changes consumed by `uv tool upgrade atomic-ops`.

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

## atoms-v0.1.0 - 2026-05-13

Initial operation-library contract baseline.

### Added

- Define schema v1 terminology around `op_id`, `device_type`, mapped `parameters`, fixed `returns`, `deprecated_by`, and `since_version`.
- Define the current `op_id` naming pattern: `^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$`.
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

- Reserve the `cli-vX.Y.Z` tag stream for future `atomic-ops` package releases.

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
