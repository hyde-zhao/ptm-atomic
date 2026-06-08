# Error Codes

This document defines the atomic operation error contract and the `ptm-atomic` CLI top-level error contract.

The contract has two layers:

- Operation-level errors use `error_type` in atomic operation returns and validate findings.
- CLI-level errors use `error_code` in the top-level CLI error object and have fixed process exit codes.

The current runtime baseline contains exactly 23 error codes: 9 operation-level
codes and 14 CLI-level codes. Repository scripts additionally use static check
exit semantics; those static check exits are not `ptm-atomic` CLI-level
`error_code` values and do not represent real device execution failures.

## Operation-Level Error Types

Operation-level errors describe the result of an atomic operation or a content validation finding. They do not directly define the process exit code of the `ptm-atomic` CLI.

| error_type | Meaning | Typical trigger | Suggested handling |
|---|---|---|---|
| `TIMEOUT` | The operation did not finish within `timeout_ms`. | Device response is slow or the network is unstable. | Retry once at the orchestration layer and keep a diagnostic snapshot reference. |
| `DEVICE_UNREACHABLE` | The target device cannot be reached. | Device reboot, route failure, management endpoint unavailable. | Stop the test case and ask the environment owner to restore reachability. |
| `INVALID_PARAM` | Input parameters are invalid for this operation. | Wrong type, unsupported enum value, missing required operation parameter. | Fix the input data and rerun validation before execution. |
| `RESOURCE_CONFLICT` | The target resource already exists or is currently in use. | Duplicate creation or concurrent modification. | Remove the conflicting resource first, or use an operation that explicitly supports update semantics. |
| `RESOURCE_NOT_FOUND` | The target resource does not exist. | Deleting or verifying a missing rule, object, stream, or interface. | Check preconditions; idempotent operations may treat this as an expected terminal state. |
| `PERMISSION_DENIED` | The caller is not allowed to perform the operation. | Expired credential, insufficient role, restricted management plane permission. | Fix the access setup and escalate to the test architecture owner if needed. |
| `STATE_MISMATCH` | The device state does not satisfy the operation precondition. | A dependency is not ready, or a tight sequence step ran out of order. | Run prerequisite operations first and inspect sequence timing. |
| `INTERNAL_ERROR` | The device, adapter, or operation implementation raised an unexpected failure. | Unknown device error, firmware issue, unhandled adapter condition. | Keep the diagnostic snapshot and file a defect with the failing context. |
| `DRY_RUN` | Dry-run mode validated the operation without real execution. | A dry-run flag or planning mode is active. | Treat as planning feedback; do not count it as a real operation result. |

## CLI-Level Error Codes

CLI-level errors describe command execution failures. These are the only errors in this document that define fixed `ptm-atomic` process exit codes.

| error_code | Exit code | Meaning | Typical trigger | Suggested handling | Retryable |
|---|---:|---|---|---|---|
| `GIT_AUTH_FAILED` | 21 | Git repository authentication failed. | SSH key or system credential helper is not configured for the repository. | Configure Git authentication and rerun `ptm-atomic sync`. | No |
| `GIT_NETWORK_ERROR` | 22 | Git network access failed. | DNS failure, remote endpoint unreachable, TLS failure, offline host, git timeout. | If a valid cache exists, continue read-only work from the cache; otherwise rerun after network recovery. | Yes |
| `OP_NOT_FOUND` | 23 | The requested `op_id` or operation-level adapter reference does not exist in the local operation repository. | `show` or `validate` references an unknown operation; `adapter` references an operation without `adapter_contract_ref`; or the op_id prefix maps to no valid path. | Run `ptm-atomic sync`, check spelling, and use nearest `op_id` suggestions when available; for `adapter`, confirm the atom declares `adapter_contract_ref`. | No |
| `REPO_NOT_SYNCED` | 24 | The local operation repository cache is missing, unreadable, damaged, or missing a referenced adapter profile file. | First run before `sync`, missing `_metadata.json`, unreadable cache, incomplete clone, or cache synced before `adapters/` was included. | Run `ptm-atomic sync`; if the cache is damaged, remove the cache through the documented recovery path and sync again. | Yes |
| `PACKAGE_NOT_FOUND` | 25 | The requested package manifest does not exist. | `list --package` or `validate --package` references an unknown package name. | Run `ptm-atomic packages` and choose one of the listed package names. | No |
| `RUNNER_UNSUPPORTED_OP` | 41 | `ptm-atomic run` does not support the requested operation. | The op is not in the runner allowlist. | Use `ptm-atomic adapter` for contract lookup, or add a dedicated runner implementation. | No |
| `RUNNER_EXECUTE_REQUIRED` | 42 | Live execution was requested by workflow policy but `--execute` was missing. | A caller expected a real device action but invoked dry-run. | Add `--execute` after reviewing the dry-run output. | No |
| `RUNNER_CREDENTIAL_MISSING` | 43 | Required runtime credential input is unavailable. | `--password-env` or `--new-password-env` is absent, unset, or empty. | Set the environment variable and rerun. | No |
| `RUNNER_LOGIN_FAILED` | 44 | NGFW Web login failed. | Login response has no session reference, returns a device error, or requires default password change without explicit approval. | Check credentials, management reachability, and default-password-change policy. | No |
| `RUNNER_SESSION_INVALID` | 45 | Local session file cannot be used. | File missing, JSON invalid, session value missing, or permissions broader than `0600`. | Re-run login or fix session file permissions. | No |
| `RUNNER_DEVICE_UNREACHABLE` | 46 | Runner could not reach the device or login asset endpoint. | Timeout, connection failure, non-200 login asset response, or TLS/network failure. | Check route, device state, base URL, and TLS settings. | Yes |
| `RUNNER_RESPONSE_INVALID` | 47 | Runner received an unexpected device response shape. | Response is not JSON, JSON root is not an object, login page lacks the RSA public-key script, or an OSPFv2/OSPFv3/BFD GET returned a non-success status. | Capture sanitized diagnostics and verify firmware/API compatibility. | No |
| `RUNNER_CONFIG_REJECTED` | 48 | Device rejected a runner configuration request. | Address object, policy route, OSPFv2, OSPFv3, or BFD POST/PUT/DELETE returned a non-success status. | Check session validity, object names, route references, entry ids, parameters, and device-side validation. | No |
| `RUNNER_VALIDATION_FAILED` | 49 | Runner input failed local validation. | Missing required CLI argument, invalid base URL, invalid address object name, invalid IPv4/CIDR input, invalid OSPF metric/timer/page/size, missing update/delete id, or invalid weight. | Fix CLI parameters and retry dry-run first. | No |

## Static Repository Check Exit Semantics

The following exit codes are used by current read-only repository checks,
including `scripts/security_gate_check.py`. They are not top-level `ptm-atomic`
CLI `error_code` values and must not be used to describe a real firewall
execution result.

| Static check category | Exit code | Meaning | Typical trigger | Output boundary |
|---|---:|---|---|---|
| `SENSITIVE_PATTERN_FOUND` | 31 | A committed product file contains a forbidden sensitive assignment pattern. | A non-placeholder value assigned to keys such as `token`, `cookie`, `authorization`, `password`, `ftp_pass`, `secret` appears under the default scan paths: `atoms/`, `adapters/`, `packages/`, `docs/`, `schemas/`, `scripts/`, or `src/atomic_ops/`. | Print file path, line number, and rule name; do not print the full matched value. |
| `HIGH_RISK_GATE_MISSING` | 32 | A high-risk schema v1.1 atom is missing the required review gate contract. | `risk.level=high`, or an `op_id` matching `^fw_(install\|init\|login\|config\|config_batch)_`, without `gate.required=true` and non-empty `gate.reason`, `gate.approver_role`, and `gate.evidence_required`. | Print `op_id` and field path only. |
| `STATIC_CHECK_INPUT_ERROR` | 33 | The static check cannot read or parse its inputs. | Missing path, YAML parse error, missing schema file, unsupported file type, or invalid invocation. | Print safe path and error category; do not print file contents. |

Static checks must be read-only: they do not connect to devices, do not access
the network, do not read `.input/` runtime assets, and do not persist diagnostic
logs.

## CLI Error Object

When a CLI command fails in JSON mode, stdout remains reserved for successful results and the error object is written to stderr.

```json
{
  "error_code": "GIT_NETWORK_ERROR",
  "message": "Git network access failed while syncing the operation repository.",
  "details": {
    "command": "sync",
    "cache_status": "STALE"
  },
  "retryable": true,
  "suggestion": "Check network access to the Git repository and rerun ptm-atomic sync."
}
```

Field contract:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `error_code` | string | Yes | One of the CLI-level error codes. |
| `message` | string | Yes | Human-readable failure summary. |
| `details` | object | Yes | Machine-readable context. Use an empty object when no safe detail is available. |
| `retryable` | boolean | Yes | Whether retrying the same command may succeed after environment recovery. |
| `suggestion` | string | No | Operator-facing next action. Current CLI error paths include it for known failures, but consumers should tolerate absence for compatibility. |

## Stdout And Stderr Rules

- Successful CLI results go to stdout in the requested output format.
- Successful `ptm-atomic run` results use the fixed envelope `op_id`, `status`,
  `data`, `error_type`, and `diag_snapshot_ref`; runner-specific fields are
  nested under `data`.
- JSON-mode CLI failures write the fixed error object to stderr.
- Text-mode CLI failures write a human-readable diagnostic to stderr and must include the `error_code` string.
- Warnings and recovery notes, such as stale cache warnings, go to stderr.
- The CLI does not create a default `logs/` directory and does not persist full diagnostic logs by itself.
- `_metadata.json` may keep the latest sync status summary, including `last_error_code` or `last_warning_code`, but it is not a log archive.

## Validate Finding Boundary

`ptm-atomic validate` is a reference checker, not a full schema validator. It reads either a test-case YAML file or a package manifest from the synced cache, extracts `op_id` references, and reports missing references or test-case structure findings.

Examples:

- `INVALID_PARAM` is an operation-level `error_type` or validate finding.
- Test case YAML structure errors are validate findings.
- Missing referenced operations may appear in validate output and may also make the command fail with top-level `OP_NOT_FOUND` when the command cannot complete as requested.
- `validate --package <package_id>` is a cache-based package reference smoke test; it checks that package `operations[]` resolve in the synced cache.

Validate result entries should use fields such as `violation_code` or `finding_type` for content-level findings. They must not invent additional CLI-level `error_code` values.

Schema and static repository checks are separate from CLI validate. Schema
violations are reported by `scripts/validate_schema.py`; sensitive-pattern and
high-risk-gate failures are reported by `scripts/security_gate_check.py`.
These scripts may report categories such as:

| Finding category | Boundary |
|---|---|
| `schema_v1_1_field_family_invalid` | A v1.1-only field family is malformed, uses the wrong version, or violates enum/range constraints. |
| `schema_version_incompatible` | A document uses `inputs`, `risk`, `credential_ref`, `gate`, `verification`, or `batch` without `schema_version: "1.1"`. |
| `safety_gate_missing` | A high-risk atom lacks `risk.level=high` or a required gate. Static check exit 32 may be used by repository scripts. |
| `sensitive_pattern_found` | A forbidden sensitive pattern appears in a checked product file. Static check exit 31 may be used by repository scripts. |
| `static_check_input_error` | A repository check cannot load its inputs. Static check exit 33 may be used by repository scripts. |

## Extension Process

Adding or changing an error code is a contract change.

To add an operation-level `error_type`:

1. Create an approved change record or implementation issue that explains the trigger, consumer impact, and migration path.
2. Update the product requirements source and this document in the same change set.
3. Update schema examples, field references, operation YAML, and validation logic when the code exists.
4. Add an `atoms-vX.Y.Z` entry to `CHANGELOG.md`.

To add a CLI-level `error_code`:

1. Create an approved change record or implementation issue that explains why the failure cannot be represented by the existing 5 CLI-level errors.
2. Update the approved design evidence, this document, CLI error handling, tests, and engineer-facing documentation.
3. Assign a stable non-zero exit code and document backward compatibility.
4. Add a `cli-vX.Y.Z` entry to `CHANGELOG.md`.

To add or change a static repository check exit code:

1. Create an approved issue or change record that identifies the check, scope, and safe
   output boundary.
2. Update this document, the owning script, and validation evidence in the same
   change set.
3. Keep static check exits separate from CLI-level `error_code` values.
4. Confirm the check is read-only and does not connect to firewall devices.

## Review Checklist

- The runtime total number of operation-level and CLI-level error codes is 14.
- Operation-level errors are listed separately from CLI-level errors.
- The 5 CLI-level exit codes are exactly `21`, `22`, `23`, `24`, and `25`.
- Static repository check exits `31`, `32`, and `33` are documented separately
  from CLI-level `error_code` values.
- Process files such as `process/*` are workflow/internal artifacts ignored by source control policy; they are not shipped delivery docs for `ptm-atomic`.
- The JSON error object contains `error_code`, `message`, `details`, `retryable`, and may include `suggestion`.
- JSON-mode failures write the error object to stderr and keep stdout for successful results.
- Text-mode failures include the `error_code` string in stderr.
- `INVALID_PARAM` is not treated as a CLI top-level error code.
- New error codes are introduced only through the extension process.
