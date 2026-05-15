# Atomic Operation Schema Field Reference

`schemas/atomic-op.schema.yaml` is the authoritative schema contract for a single
atomic operation YAML document. This reference exists for human review and must
stay aligned with the schema file.

## Scope

- Current contract: schema v1 uses YAML as the only serialized format.
- Current truth source: HLD v2.6 terminology takes precedence over historical
  wording preserved in older requirements and use cases.
- Extension boundary: undeclared top-level fields are rejected because the
  schema uses `additionalProperties: false`.

## Top-Level Fields

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `schema_version` | `string` (semver) | Yes | Version of the operation document schema. | `"1.0.0"` |
| `op_id` | `string` | Yes | Stable identifier in `device_verb_target` form. | `"fw_verify_acl_rule"` |
| `device_type` | `enum` | Yes | Device family. Allowed values: `fw`, `tg`, `mock`, `sw`. | `"fw"` |
| `description` | `string` | Yes | Single-sentence description, maximum 120 characters. | `"Verify whether the firewall ACL rule is present and correctly ordered."` |
| `parameters` | `object` | Yes | Mapping from parameter name to parameter definition. Array form is not accepted in schema v1. | `rule_name: {type: string, required: true, description: ACL rule name to verify.}` |
| `returns` | `object` | Yes | Fixed response envelope consumed by validators and later CLI readers. | `{status: success, data: {}, error_type: VALIDATION_ERROR, diag_snapshot_ref: ""}` |
| `idempotent` | `boolean` | Yes | Must be explicitly set; omission is invalid. | `true` |
| `timeout_ms` | `integer` | Yes | Expected timeout upper bound in milliseconds; must be greater than `0`. | `30000` |
| `error_types` | `array[string]` | Yes | Possible error categories. Items must match uppercase underscore naming. | `["VALIDATION_ERROR", "CONFIG_APPLY_FAILED"]` |
| `preconditions` | `array[string]` | No | Human-readable preconditions before execution. | `["Target policy package is already published."]` |
| `postconditions` | `array[string]` | No | Human-readable postconditions after a successful run. | `["Rule hit count is greater than zero."]` |
| `tags` | `array[string]` | No | Free-form discovery tags. | `["acl", "verification"]` |
| `deprecated` | `boolean` | No | Marks this operation as deprecated. | `false` |
| `deprecated_by` | `string` | No | Replacement operation `op_id` when the current one is deprecated. | `"fw_verify_acl_rule_alternative"` |
| `since_version` | `string` (semver) | No | First repository version that introduced the operation. | `"1.2.0"` |

## Nested Object Contracts

### `parameters`

`parameters` is a mapping. The parameter name is the map key, so schema v1 does
not accept the historical array shape with a repeated `name` field.

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `<parameter-name>` | `object` | Yes | Parameter definition keyed by a lowercase underscore name matching `^[a-z][a-z0-9_]*$`. | `rule_name: {...}` |
| `<parameter-name>.type` | `enum` | Yes | Baseline parameter type vocabulary. Allowed values: `string`, `int`, `float`, `bool`, `json`, `list`. | `"string"` |
| `<parameter-name>.required` | `boolean` | Yes | Whether callers must provide the parameter. | `true` |
| `<parameter-name>.description` | `string` | Yes | Human-readable explanation of the parameter. | `"ACL rule name to verify."` |

### `returns`

`returns` keeps a fixed shape in schema v1. The schema does not describe the
deep structure of `returns.data`; downstream stories may document that later
without changing the top-level contract.

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `returns.status` | `string` | Yes | Result status string. | `"success"` |
| `returns.data` | `object` | Yes | Structured success payload with operation-specific keys. | `{matched_rule_count: 1}` |
| `returns.error_type` | `string` | Yes | Error category emitted on failure. | `"VALIDATION_ERROR"` |
| `returns.diag_snapshot_ref` | `string` | Yes | Diagnostic snapshot reference; empty string is allowed. | `""` |

## Minimal Valid Example

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
  expected_order:
    type: int
    required: false
    description: Expected rule order when ordering matters.
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
  - CONFIG_APPLY_FAILED
preconditions:
  - Target policy package is already published.
postconditions:
  - Rule hit count is greater than zero.
tags:
  - acl
  - verification
deprecated: false
deprecated_by: fw_verify_acl_rule_alternative
since_version: "1.2.0"
```

## Terminology Mapping

| Historical Term | Current Field / Contract | Notes |
|---|---|---|
| `operation_id` | `op_id` | `op_id` is the only accepted identifier field in schema v1. |
| `device` | `device_type` | `device_type` is restricted to `fw`, `tg`, `mock`, `sw`. |
| `parameters` array | `parameters` mapping | The current contract uses parameter names as object keys; array form is rejected. |
| `output_schema` | `returns` | The current return shape is `status`, `data`, `error_type`, `diag_snapshot_ref`. |
| `status/result/metadata` | `status/data/error_type/diag_snapshot_ref` | Historical return envelope is not accepted in schema v1. |

## Historical Fields Rejected By Schema v1

The following inputs may still appear in older discussion artifacts, but they
are not part of the accepted v1 contract:

- `operation_id`
- `device`
- `parameters` as an array of objects
- `output_schema`
- `since`, `reason`, `replaced_by`

For version and deprecation metadata, schema v1 uses `deprecated`,
`deprecated_by`, and `since_version`.

## Validation Notes

- `op_id` must match `^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$`.
- `error_types` only constrains array item type and uppercase underscore naming
  in STORY-01. The full error catalog is owned by `STORY-03`.
- Adding a new top-level field requires changing both
  `schemas/atomic-op.schema.yaml` and this reference document in the same Story
  or follow-up change.
