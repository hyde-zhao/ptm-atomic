# Atomic Operation Schema Field Reference

`schemas/atomic-op.schema.yaml` is the authoritative schema contract for a
single atomic operation YAML document. This reference is the human-readable
counterpart and must stay synchronized with the schema in the same approved
change set.

## Scope

- Current contract: schema v1.1 is a contract-only extension over schema v1.
- Compatibility: existing v1.0 atoms that use `schema_version: "1.0.0"` or
  `schema_version: "1.0"` remain valid when they do not use v1.1 field families.
- v1.1 version value: new field-family atoms use `schema_version: "1.1"`.
- Extension boundary: undeclared top-level fields are rejected because the schema
  uses `additionalProperties: false`.
- Execution boundary: v1.1 fields describe atom contracts and static validation
  metadata only. They do not add a device runner, credential store, network
  connection, or CLI execution command.

## Top-Level Fields

| Field | Type | Required | Version | Description | Example |
|---|---|---:|---|---|---|
| `schema_version` | `enum` | Yes | v1.0/v1.1 | Version of the operation document schema. Allowed values are `"1.0"`, `"1.0.0"`, and `"1.1"`. | `"1.1"` |
| `op_id` | `string` | Yes | v1.0/v1.1 | Stable identifier in `device_verb_target` form. | `"fw_verify_acl_rule"` |
| `device_type` | `enum` | Yes | v1.0/v1.1 | Device family. Allowed values: `fw`, `tg`, `mock`, `sw`. | `"fw"` |
| `description` | `string` | Yes | v1.0/v1.1 | Single-sentence description, maximum 120 characters. | `"Verify whether the firewall ACL rule is present and correctly ordered."` |
| `parameters` | `object` | Yes | v1.0/v1.1 | Mapping from parameter name to parameter definition. Array form is rejected. | `rule_name: {type: string, required: true, description: ACL rule name to verify.}` |
| `inputs` | `object` | No | v1.1 only | Optional contract-only input envelope for external orchestration references. | `{state_ref: "<state-ref>"}` |
| `returns` | `object` | Yes | v1.0/v1.1 | Fixed response envelope consumed by validators and later CLI readers. | `{status: success, data: {}, error_type: VALIDATION_ERROR, diag_snapshot_ref: ""}` |
| `idempotent` | `boolean` | Yes | v1.0/v1.1 | Must be explicitly set. | `true` |
| `timeout_ms` | `integer` | Yes | v1.0/v1.1 | Expected timeout upper bound in milliseconds; must be greater than `0`. | `30000` |
| `error_types` | `array[string]` | Yes | v1.0/v1.1 | Possible error categories. Items must match uppercase underscore naming. | `["VALIDATION_ERROR", "CONFIG_APPLY_FAILED"]` |
| `risk` | `object` | Conditional | v1.1 only | Risk level and categories used by static gate checks. Required for high-risk firewall install, init, login, config, and config batch atoms. | `{level: high, categories: [configuration]}` |
| `credential_ref` | `object` | No | v1.1 only | Non-sensitive reference to external credential material. It never stores the credential value itself. | `{kind: placeholder, ref: "<credential-ref>"}` |
| `gate` | `object` | Conditional | v1.1 only | Review gate contract for high-risk operations. Required with `required: true` for high-risk atoms. | `{required: true, reason: "High-risk change", approver_role: "reviewer", evidence_required: ["plan"]}` |
| `verification` | `object` | No | v1.1 only | Verification contract and summary reference. Failure handling is diagnostic and manual; it is not automatic rollback. | `{kind: config_validation, rules: [...], summary_ref: "<summary-ref>"}` |
| `batch` | `object` | No | v1.1 only | Multi-device batch contract for inventory reference, concurrency, idempotency, and failure isolation. | `{max_concurrency: 1, device_inventory_ref: "<inventory-ref>", idempotency_key: "<idempotency-key>", failure_policy: isolate_failed_device}` |
| `adapter_contract_ref` | `string` | No | v1.1 only | JSON Pointer to a public, non-sensitive adapter profile operation. It lets external generators find API shape without reading `.input/` materials. | `"adapters/ngfw/default.yaml#/operations/fw_config_policy_route"` |
| `preconditions` | `array[string]` | No | v1.0/v1.1 | Human-readable preconditions before execution. | `["Target policy package is already published."]` |
| `postconditions` | `array[string]` | No | v1.0/v1.1 | Human-readable postconditions after success. | `["Rule hit count is greater than zero."]` |
| `tags` | `array[string]` | No | v1.0/v1.1 | Free-form discovery tags. | `["acl", "verification"]` |
| `deprecated` | `boolean` | No | v1.0/v1.1 | Marks this operation as deprecated. | `false` |
| `deprecated_by` | `string` | No | v1.0/v1.1 | Replacement operation `op_id` when deprecated. | `"fw_verify_acl_rule_alternative"` |
| `since_version` | `string` (three-part semver) | No | v1.0/v1.1 | First repository version that introduced the operation. | `"1.2.0"` |

Any v1.1-only top-level field requires `schema_version: "1.1"`. v1.0 atoms must
not use `inputs`, `risk`, `credential_ref`, `gate`, `verification`, or `batch`.

## Version Compatibility

| Contract | Accepted `schema_version` | Field-family behavior |
|---|---|---|
| v1.0 legacy | `"1.0.0"` | Existing atoms remain valid; no v1.1 field families are required or expected. |
| v1.0 compact | `"1.0"` | Accepted for compatibility with planning terminology; no v1.1 field families are required or expected. |
| v1.1 contract | `"1.1"` | Enables `inputs`, `risk`, `credential_ref`, `gate`, `verification`, and `batch`; new firewall atoms in this repository should use this value. |

`since_version` remains a repository release version and continues to use
three-part semver such as `"1.2.0"`. It is intentionally separate from
`schema_version`.

### `adapter_contract_ref`

`adapter_contract_ref` is optional and available only in v1.1. The value is a
repository-relative JSON Pointer to an operation under a public adapter profile:

```yaml
adapter_contract_ref: adapters/ngfw/default.yaml#/operations/fw_config_policy_route
```

The referenced profile is validated by `schemas/adapter-profile.schema.yaml` and
`scripts/validate_adapter_profiles.py`. The validator also checks that the
profile operation's `atom_ref` points back to the atom file. Adapter profiles
must remain shape-only: they may describe method, relative endpoint path,
payload placeholders, response status codes, and non-sensitive result refs, but
must not contain runtime endpoint inventory, credential values, session material,
production samples, or `.input/capacity` dependencies. `atomic-ops run` may
execute explicitly allowlisted adapter-backed operations, while runtime endpoint
and session material must still come from CLI arguments and the local session
file rather than from the adapter profile.

## Nested Object Contracts

### `parameters`

`parameters` is a mapping. The parameter name is the map key; array form with a
repeated `name` field is rejected.

| Field | Type | Required | Description | Example |
|---|---|---:|---|---|
| `<parameter-name>` | `object` | Yes | Parameter definition keyed by a lowercase underscore name matching `^[a-z][a-z0-9_]*$`. | `rule_name: {...}` |
| `<parameter-name>.type` | `enum` | Yes | Allowed values: `string`, `int`, `float`, `bool`, `json`, `list`. | `"string"` |
| `<parameter-name>.required` | `boolean` | Yes | Whether callers must provide the parameter. | `true` |
| `<parameter-name>.description` | `string` | Yes | Human-readable explanation of the parameter. | `"ACL rule name to verify."` |

### `inputs`

`inputs` is optional and available only in v1.1.

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `inputs.state_ref` | `string` | No | Non-sensitive reference, 1..128 characters; must not contain credential-bearing substrings. | `"<state-ref>"` |

The schema names `inputs.state_ref` and also allows additional `inputs` keys
because `inputs.additionalProperties` is currently `true`. Additional keys are
reserved for non-sensitive orchestration references only; they must not contain
credential values, raw session material, request/response payloads, or
production data. The current CLI does not resolve or persist `inputs`; it only
validates the document shape when repository checks are run.

### `returns`

`returns` keeps the existing fixed envelope. v1.1 additionally documents
contract keys that may appear under `returns.data`.

| Field | Type | Required | Description | Example |
|---|---|---:|---|---|
| `returns.status` | `string` | Yes | Result status string. | `"success"` |
| `returns.data` | `object` | Yes | Structured success payload with operation-specific keys. | `{matched_rule_count: 1}` |
| `returns.data.session_ref` | `string` | No | Non-sensitive session reference, 8..128 characters. | `"<session-ref>"` |
| `returns.data.state_ref` | `string` | No | Non-sensitive state reference. | `"<state-ref>"` |
| `returns.data.state_status` | `enum` | No | Allowed values: `valid`, `expired`, `missing`, `invalid`. | `"valid"` |
| `returns.data.expires_at` | `string` or `null` | No | ISO 8601 timestamp with timezone, or `null` when not applicable. | `null` |
| `returns.error_type` | `string` | Yes | Error category emitted on failure. | `"VALIDATION_ERROR"` |
| `returns.diag_snapshot_ref` | `string` | Yes | Diagnostic snapshot reference; empty string is allowed. | `""` |

`session_ref` and `state_ref` are references held by an external orchestrator.
They are not CLI cache entries and must not include raw authentication material.

### `risk`

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `risk.level` | `enum` | Yes | Allowed values: `low`, `medium`, `high`. | `"high"` |
| `risk.categories` | `array[string]` | Yes | At least one lowercase snake_case category; unique items. | `["configuration"]` |

For `schema_version: "1.1"`, firewall atoms whose `op_id` matches
`^fw_(install|init|login|config|config_batch)_` are treated as high-risk by this
schema and must declare `risk.level: high` plus a gate.

### `credential_ref`

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `credential_ref.kind` | `enum` | Yes | Allowed values: `vault_ref`, `env_ref`, `manual_ref`, `placeholder`. | `"placeholder"` |
| `credential_ref.ref` | `string` | Yes | Non-sensitive reference, 1..128 characters. | `"<credential-ref>"` |

Forbidden values:

- Do not store a raw password, token, cookie, authorization header, FTP
  credential, secret, device address, or response payload.
- Use placeholders such as `<credential-ref>` or a non-sensitive external
  reference name.
- `Ngfw@123` may appear only as a password policy value in documentation or atom
  descriptions; it must not be treated as a stored credential.

### `gate`

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `gate.required` | `boolean` | Yes | Must be `true` for high-risk atoms. | `true` |
| `gate.reason` | `string` | Yes | Non-empty reason. | `"High-risk firewall configuration change."` |
| `gate.approver_role` | `string` | Yes | Non-empty role name, not a user credential. | `"change_reviewer"` |
| `gate.evidence_required` | `array[string]` | Yes | At least one evidence descriptor. | `["review_ticket"]` |

`gate` is a contract for human or pipeline review. It is not an implementation
of an approval system.

### `verification`

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `verification.kind` | `enum` | Yes | Allowed values: `install_health`, `login_state`, `capacity_domain`, `config_validation`, `batch_summary`, `diagnostics`. | `"config_validation"` |
| `verification.rules` | `array[object]` | Yes | At least one rule. | `[{name: expected_state, input_ref: "<result-ref>", expected_result: "matched"}]` |
| `verification.rules[].name` | `string` | Yes | Lowercase snake_case. | `"expected_state"` |
| `verification.rules[].input_ref` | `string` | Yes | Non-sensitive reference. | `"<result-ref>"` |
| `verification.rules[].expected_result` | `string` | Yes | Human-readable expected outcome. | `"configuration present"` |
| `verification.summary_ref` | `string` | Yes | Non-sensitive summary reference. | `"<summary-ref>"` |

Verification failure handling is limited to error category, diagnostic reference,
and manual handling signal. The schema and docs do not define automatic rollback
or revert behavior.

### `batch`

| Field | Type | Required | Constraint | Example |
|---|---|---:|---|---|
| `batch.max_concurrency` | `integer` | Yes | Minimum `1`, maximum `5`, default `1`. | `1` |
| `batch.device_inventory_ref` | `string` | Yes | Non-sensitive inventory reference. | `"<inventory-ref>"` |
| `batch.idempotency_key` | `string` | Yes | Non-sensitive idempotency key. | `"<idempotency-key>"` |
| `batch.failure_policy` | `enum` | Yes | `isolate_failed_device` or `stop_batch_before_next_device`. | `"isolate_failed_device"` |

High-risk batch configuration defaults to `max_concurrency: 1`; increasing it
requires approved change evidence and verification coverage.

## Minimal Valid v1.0 Example

```yaml
schema_version: "1.0.0"
op_id: fw_verify_acl_rule
device_type: fw
description: Verify whether the firewall ACL rule is present and correctly ordered.
parameters:
  rule_name:
    type: string
    required: true
    description: ACL rule name to verify.
returns:
  status: success
  data:
    matched_rule_count: 1
  error_type: VALIDATION_ERROR
  diag_snapshot_ref: ""
idempotent: true
timeout_ms: 30000
error_types:
  - VALIDATION_ERROR
```

## Minimal Valid v1.1 Example

```yaml
schema_version: "1.1"
op_id: fw_config_interface
device_type: fw
description: Define interface configuration contract for a firewall.
parameters:
  interface_ref:
    type: string
    required: true
    description: Non-sensitive interface reference.
inputs:
  state_ref: "<state-ref>"
returns:
  status: success
  data:
    state_ref: "<state-ref>"
    state_status: valid
    expires_at: null
  error_type: INVALID_PARAM
  diag_snapshot_ref: ""
idempotent: true
timeout_ms: 30000
error_types:
  - INVALID_PARAM
  - STATE_MISMATCH
risk:
  level: high
  categories:
    - configuration
credential_ref:
  kind: placeholder
  ref: "<credential-ref>"
gate:
  required: true
  reason: High-risk firewall configuration change.
  approver_role: change_reviewer
  evidence_required:
    - review_ticket
verification:
  kind: config_validation
  rules:
    - name: expected_state
      input_ref: "<result-ref>"
      expected_result: configuration present
  summary_ref: "<summary-ref>"
```

## Minimal Valid v1.1 Batch Example

```yaml
schema_version: "1.1"
op_id: fw_config_batch_interface
device_type: fw
description: Define batch interface configuration contract for firewalls.
parameters:
  interface_ref:
    type: string
    required: true
    description: Non-sensitive interface reference.
inputs:
  state_ref: "<state-ref>"
returns:
  status: success
  data:
    batch_status: partial_failed
    verification_summary_ref: "<summary-ref>"
  error_type: STATE_MISMATCH
  diag_snapshot_ref: "<diag-snapshot-ref>"
idempotent: true
timeout_ms: 30000
error_types:
  - INVALID_PARAM
  - STATE_MISMATCH
risk:
  level: high
  categories:
    - configuration
    - batch
credential_ref:
  kind: placeholder
  ref: "<credential-ref>"
gate:
  required: true
  reason: High-risk batch firewall configuration change.
  approver_role: change_reviewer
  evidence_required:
    - review_ticket
verification:
  kind: batch_summary
  rules:
    - name: expected_batch_summary
      input_ref: "<summary-ref>"
      expected_result: per-device result summary recorded
  summary_ref: "<summary-ref>"
batch:
  max_concurrency: 1
  device_inventory_ref: "<inventory-ref>"
  idempotency_key: "<idempotency-key>"
  failure_policy: isolate_failed_device
```

## Terminology Mapping

| Historical Term | Current Field / Contract | Notes |
|---|---|---|
| `operation_id` | `op_id` | `op_id` is the only accepted identifier field. |
| `device` | `device_type` | `device_type` is restricted to `fw`, `tg`, `mock`, `sw`. |
| `parameters` array | `parameters` mapping | The current contract uses parameter names as object keys; array form is rejected. |
| `output_schema` | `returns` | The current return shape is `status`, `data`, `error_type`, `diag_snapshot_ref`. |
| `status/result/metadata` | `status/data/error_type/diag_snapshot_ref` | Historical return envelope is not accepted. |
| raw credential field | `credential_ref` | Only references or placeholders are accepted. |
| stored session value | `returns.data.session_ref` | Only non-sensitive references are accepted. |
| hidden API implementation note | `adapter_contract_ref` | Optional pointer to a public adapter profile operation. |

## Historical Fields Rejected By Schema

The following inputs may still appear in older discussion artifacts, but they
are not part of the accepted contract:

- `operation_id`
- `device`
- `parameters` as an array of objects
- `output_schema`
- `since`, `reason`, `replaced_by`
- raw credential fields such as password, token, cookie, FTP credential, secret,
  or authorization header values

For version and deprecation metadata, the schema uses `deprecated`,
`deprecated_by`, and `since_version`.

## Validation Notes

- `op_id` must match `^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$`.
- `op_id` prefix must match `device_type` and file path
  `atoms/<device_type>/<op_id>.yaml`.
- v1.1-only top-level fields require `schema_version: "1.1"`.
- High-risk firewall atoms matching
  `^fw_(install|init|login|config|config_batch)_` must include
  `risk.level: high` and `gate.required: true`.
- `credential_ref`, `session_ref`, `state_ref`, `summary_ref`,
  `device_inventory_ref`, and `idempotency_key` are non-sensitive references.
- `adapter_contract_ref` must point to a public adapter profile operation using
  `adapters/<profile>.yaml#/operations/<op_id>`. Adapter profiles describe API
  shape only and must not contain runtime-sensitive material or `.input`
  dependencies.
- Adding a top-level field requires changing both
  `schemas/atomic-op.schema.yaml` and this reference document in the same
  approved change or verification-backed follow-up.
