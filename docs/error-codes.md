# Error Codes

This document defines the atomic operation error contract and the `atomic-ops` CLI top-level error contract.

The contract has two layers:

- Operation-level errors use `error_type` in atomic operation returns and validate findings.
- CLI-level errors use `error_code` in the top-level CLI error object and have fixed process exit codes.

The current baseline contains exactly 14 error codes: 9 operation-level codes and 5 CLI-level codes.

## Operation-Level Error Types

Operation-level errors describe the result of an atomic operation or a content validation finding. They do not directly define the process exit code of the `atomic-ops` CLI.

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

CLI-level errors describe command execution failures. These are the only errors in this document that define fixed `atomic-ops` process exit codes.

| error_code | Exit code | Meaning | Typical trigger | Suggested handling | Retryable |
|---|---:|---|---|---|---|
| `GIT_AUTH_FAILED` | 21 | Git repository authentication failed. | SSH key or system credential helper is not configured for the repository. | Configure Git authentication and rerun `atomic-ops sync`. | No |
| `GIT_NETWORK_ERROR` | 22 | Git network access failed. | DNS failure, remote endpoint unreachable, TLS failure, offline host, git timeout. | If a valid cache exists, continue read-only work from the cache; otherwise rerun after network recovery. | Yes |
| `OP_NOT_FOUND` | 23 | The requested `op_id` does not exist in the local operation repository. | `show` or `validate` references an unknown operation, or the op_id prefix maps to no valid path. | Run `atomic-ops sync`, check spelling, and use nearest `op_id` suggestions when available. | No |
| `REPO_NOT_SYNCED` | 24 | The local operation repository cache is missing, unreadable, or damaged. | First run before `sync`, missing `_metadata.json`, unreadable cache, incomplete clone. | Run `atomic-ops sync`; if the cache is damaged, remove the cache through the documented recovery path and sync again. | Yes |
| `PACKAGE_NOT_FOUND` | 25 | The requested package manifest does not exist. | `list --package` or `validate --package` references an unknown package name. | Run `atomic-ops packages` and choose one of the listed package names. | No |

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
  "retryable": true
}
```

Field contract:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `error_code` | string | Yes | One of the 5 CLI-level error codes. |
| `message` | string | Yes | Human-readable failure summary. |
| `details` | object | Yes | Machine-readable context. Use an empty object when no safe detail is available. |
| `retryable` | boolean | Yes | Whether retrying the same command may succeed after environment recovery. |

## Stdout And Stderr Rules

- Successful CLI results go to stdout in the requested output format.
- JSON-mode CLI failures write the fixed error object to stderr.
- Text-mode CLI failures write a human-readable diagnostic to stderr and must include the `error_code` string.
- Warnings and recovery notes, such as stale cache warnings, go to stderr.
- The CLI does not create a default `logs/` directory and does not persist full diagnostic logs by itself.
- `_metadata.json` may keep the latest sync status summary, including `last_error_code` or `last_warning_code`, but it is not a log archive.

## Validate Finding Boundary

`validate` may report operation content problems without treating them as CLI top-level execution failures.

Examples:

- `INVALID_PARAM` is an operation-level `error_type` or validate finding.
- Schema violations are validate findings.
- Test case YAML structure errors are validate findings.
- Missing referenced operations may appear in validate output and may also make the command fail with top-level `OP_NOT_FOUND` when the command cannot complete as requested.

Validate result entries should use fields such as `violation_code` or `finding_type` for content-level findings. They must not invent additional CLI-level `error_code` values.

## Extension Process

Adding or changing an error code is a contract change.

To add an operation-level `error_type`:

1. Create a change request or Story that explains the trigger, consumer impact, and migration path.
2. Update `process/REQUIREMENTS.md` and this document in the same change set.
3. Update schema examples, field references, operation YAML, and validation logic when the code exists.
4. Add an `atoms-vX.Y.Z` entry to `CHANGELOG.md`.

To add a CLI-level `error_code`:

1. Create a change request or Story that explains why the failure cannot be represented by the existing 5 CLI-level errors.
2. Update `process/HLD.md`, this document, CLI error handling, tests, and engineer-facing documentation.
3. Assign a stable non-zero exit code and document backward compatibility.
4. Add a `cli-vX.Y.Z` entry to `CHANGELOG.md`.

## Review Checklist

- The total number of error codes is 14.
- Operation-level errors are listed separately from CLI-level errors.
- The 5 CLI-level exit codes are exactly `21`, `22`, `23`, `24`, and `25`.
- The JSON error object contains `error_code`, `message`, `details`, and `retryable`.
- JSON-mode failures write the error object to stderr and keep stdout for successful results.
- Text-mode failures include the `error_code` string in stderr.
- `INVALID_PARAM` is not treated as a CLI top-level error code.
- New error codes are introduced only through the extension process.
