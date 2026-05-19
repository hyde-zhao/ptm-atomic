# Batch Configuration Contract

## Scope

This document defines the static multi-device batch configuration contract for `atomic-ops`.
It documents atom YAML inputs, outputs, package scope, and safety boundaries for the ten NGFW
capacity domains. It does not define or provide a batch executor, device connection, inventory
reader, request payload, response payload, runtime log, or automatic recovery mechanism.

## Domain Coverage

| Domain | Batch op_id |
|---|---|
| `interface` | `fw_config_batch_interface` |
| `object` | `fw_config_batch_object` |
| `acl_policy` | `fw_config_batch_acl_policy` |
| `policy_route` | `fw_config_batch_policy_route` |
| `static_route` | `fw_config_batch_static_route` |
| `nat` | `fw_config_batch_nat` |
| `bandwidth` | `fw_config_batch_bandwidth` |
| `black_white_list` | `fw_config_batch_black_white_list` |
| `ssl_vpn` | `fw_config_batch_ssl_vpn` |
| `dynamic_routing` | `fw_config_batch_dynamic_routing` |

`packages/ngfw_batch_config.yaml` contains exactly these ten `fw_config_batch_<domain>` operation ids.
It is a package filter view only: it supports package listing and reference validation, but does
not install, copy, execute, or distribute atom files. It does not include single-device
`fw_config_<domain>` or `fw_verify_<domain>` operation ids.

## Inventory References

Batch atoms use `device_inventory_ref` to point to an external inventory source owned by an
orchestrator or test harness. The value must be a non-sensitive reference such as
`<device-inventory-ref>` or an external system identifier. The atom files and this document do not
inline device addresses, usernames, credentials, tokens, cookies, FTP credentials, or complete
inventory documents.

## Selectors

Batch atoms use `device_selector` to describe which devices from the inventory are in scope.
Supported selector forms are:

| Selector field | Purpose | Example |
|---|---|---|
| `device_ids` | Explicit non-sensitive device references. | `["<device-ref-a>", "<device-ref-b>"]` |
| `labels` | Non-sensitive label constraints resolved externally. | `{role: edge_firewall}` |
| `max_selected` | Optional selection limit for external resolution. | `5` |

The current CLI does not resolve selectors and does not read real inventory. It only reads local YAML
contracts and package manifests.

## Concurrency

Each batch atom has a top-level `batch` contract:

```yaml
batch:
  max_concurrency: 1
  device_inventory_ref: "<device-inventory-ref>"
  idempotency_key: "<batch-idempotency-key>"
  failure_policy: isolate_failed_device
```

Concurrency rules:

| Rule | Contract |
|---|---|
| Default | `batch.max_concurrency: 1` |
| Minimum | `1` |
| Maximum | `5` |
| High-risk default | `1` |
| Higher concurrency | Values `2..5` require gate evidence and a verification strategy. |

The concurrency value is an external executor contract. The current repository does not run worker
threads, open device sessions, or apply configuration.

## Idempotency

Every batch atom requires `idempotency_key`. For per-device repeatability, the external orchestrator
derives or records a device-level key using this stable tuple:

```text
batch_ref + op_id + device_ref + config_domain + params_digest
```

Each `per_device_results[]` item can echo the derived key with the device result so repeated intent
can be diagnosed without storing sensitive execution payloads.

## Failure Isolation

Batch configuration isolates failures at the device result level:

| Field | Meaning |
|---|---|
| `batch_status` | One of `succeeded`, `partial_failed`, `failed`, `blocked`. |
| `per_device_results[]` | One result per selected device reference. |
| `failed_devices[]` | Subset of failed device references with error and diagnostic refs. |
| `diag_snapshot_ref` | Non-sensitive diagnostic reference. |
| `handling_hint` | Human-readable manual handling signal. |

`partial_failed` is required when at least one selected device succeeds and at least one selected
device fails. Failed devices are listed in `failed_devices[]`. Successful devices are not
automatically reverted when another device fails.

## Verification Summary

Each batch atom returns `verification_summary_ref`. The referenced external summary must be able to
report:

| Summary fact | Description |
|---|---|
| `total_devices` | Number of selected device references. |
| `succeeded_count` | Number of devices with `status: succeeded`. |
| `failed_count` | Number of devices with `status: failed`. |
| `skipped_count` | Number of devices with `status: skipped`. |
| `domains[]` | Domain-level outcome entries for the batch. |

The atom contract stores only the summary reference, not raw device responses.

## Adapter Profile Boundary

Batch contracts describe per-device intent and result aggregation, but they do not provide an
executor. Public adapter profiles under `adapters/` may describe per-operation API shape for an
external script generator. They do not include runtime inventory, device addresses, session
material, credentials, production samples, or any dependency on `.input/capacity`.

## Sensitive Boundaries

The batch contract permits non-sensitive references only. Product files must not contain:

| Forbidden content | Required handling |
|---|---|
| Real device address or inventory body | Store only `device_inventory_ref` and `device_ref` placeholders. |
| Username or credential material | Store only external references such as `<state-ref>` or `<session-ref>`. |
| Token, cookie, or authorization header | Do not store; use non-sensitive references only. |
| FTP credential | Do not store; use non-sensitive external references only. |
| Request or response body | Do not copy; store diagnostic and verification references only. |
| Runtime log | Do not copy; store `diag_snapshot_ref` only. |

## No Automatic Rollback

Batch atoms do not define automatic rollback or automatic revert of successful devices. When a
device fails, the batch result records `failed_devices[]`, diagnostic references, and manual
handling hints. Any recovery behavior requires a separate requirement, design review, and
approval before it can become a product contract.

## Current Validation Facts

Current repository checks and package-reference probes can rely on these stable facts:

- 10/10 batch atom coverage.
- `risk.level=high` and `gate.required=true` on every batch atom.
- `batch.max_concurrency` default `1`, minimum `1`, maximum `5`.
- Required non-sensitive inventory, selector, batch reference, and idempotency fields.
- Required `batch_status`, `per_device_results[]`, `failed_devices[]`, and `verification_summary_ref`.
- `ngfw_batch_config` is a filter view only and contains exactly the ten batch `op_id` values listed above.
