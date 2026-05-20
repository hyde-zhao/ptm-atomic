# Atomic Operation Naming Convention

## Naming Pattern

Atomic operation identifiers use the `op_id` field. The current contract is:

```text
^(fw|tg|mock|sw)_[a-z]+_[a-z0-9_]+$
```

The semantic shape is:

```text
{device_prefix}_{verb}_{target}
```

| Segment | Required | Allowed values / pattern | Meaning |
|---|---|---|---|
| `device_prefix` | Yes | `fw`, `tg`, `mock`, `sw` | Device family that owns the operation file path and `device_type` value |
| `verb` | Yes | Lowercase ASCII verb from the controlled vocabulary | Primary action or observation performed by the operation |
| `target` | Yes | Lowercase ASCII words and digits joined by `_` | Object, feature, metric, or state being acted on |

Examples:

| `op_id` | Meaning |
|---|---|
| `fw_verify_acl_rule` | Verify a firewall ACL rule state |
| `tg_start_traffic_stream` | Start a traffic generator stream |
| `mock_reset_session_state` | Reset mock session state |
| `sw_apply_vlan_config` | Apply switch VLAN configuration |

The `op_id` prefix must match the YAML `device_type` field and the file path:

```text
atoms/<device_type>/<op_id>.yaml
```

For example, `fw_verify_acl_rule` belongs under `atoms/fw/fw_verify_acl_rule.yaml`.

## Controlled Verb Vocabulary

Use the smallest verb that accurately describes the operation. Prefer existing verbs before introducing a new one.

| Verb | Use when the operation... | Example |
|---|---|---|
| `create` | Creates a new managed object | `fw_create_acl_rule` |
| `delete` | Deletes an existing managed object | `fw_delete_acl_rule` |
| `update` | Changes fields on an existing object | `fw_update_acl_rule` |
| `apply` | Applies configuration or policy state | `sw_apply_vlan_config` |
| `rollback` | Reverts a prior change | `fw_rollback_policy_package` |
| `verify` | Checks whether state matches expectation | `fw_verify_acl_rule` |
| `start` | Starts a service, stream, capture, or process | `tg_start_traffic_stream` |
| `stop` | Stops a service, stream, capture, or process | `tg_stop_traffic_stream` |
| `reset` | Resets state to a known baseline | `mock_reset_session_state` |
| `capture` | Captures packets, counters, logs, or diagnostics | `fw_capture_diagnostics` |

Additional verbs require review before use. The reviewer must confirm that no existing verb expresses the intended action and that the new verb will be reusable by more than one operation.

## Firewall v1.1 Contract Boundaries

Schema v1.1 freezes a narrower firewall vocabulary for the NGFW install,
initialization, login, configuration, batch configuration, and verification
Stories. New firewall atoms in those Stories must use the `fw_` prefix, must live
under `atoms/fw/`, and must keep `device_type: fw`.

```text
atoms/fw/<op_id>.yaml
```

| Boundary | Required value / rule | Examples |
|---|---|---|
| Prefix | `fw_` | `fw_config_interface` |
| Path | `atoms/fw/<op_id>.yaml` | `atoms/fw/fw_login_web_management.yaml` |
| `device_type` | `fw` | `device_type: fw` |
| Install action verb | `install` | `fw_install_ngfw_image` |
| Initialization action verb | `init` | `fw_init_ngfw_minimal` |
| Login action verb | `login` | `fw_login_web_management` |
| Login-state observation verb | `check` | `fw_check_login_state` |
| Configuration action verb | `config` | `fw_config_acl_policy` |
| Batch configuration action verb | `config_batch` | `fw_config_batch_acl_policy` |
| Verification action verb | `verify` | `fw_verify_acl_policy` |

`config_batch` is a frozen firewall v1.1 logical verb. The broad `op_id`
regular expression still has the mechanical shape `device_verb_target`, but the
firewall v1.1 contract treats `config_batch` as the approved batch action rather
than decomposing it into a generic `config` verb plus an arbitrary `batch_*`
target.

Firewall v1.1 atoms remain contract documents. Their verbs describe the eventual
operation contract for an external orchestrator; they do not imply that the
current `atomic-ops` CLI can connect to a firewall or execute the operation.

### Firewall v1.1 Near Misses

| Candidate | Status | Reason |
|---|---|---|
| `fw_config_interface` | Valid | Uses the v1.1 firewall configuration verb and lives under `atoms/fw/`. |
| `fw_config_batch_nat` | Valid | Uses the approved batch configuration verb. |
| `fw_apply_interface` | Invalid for NGFW v1.1 Stories | Use `fw_config_interface`; `apply` is not the frozen firewall v1.1 verb. |
| `fw_run_login` | Invalid | `run` is not an atom verb and would imply execution. |
| `fw_execute_acl_policy` | Invalid | `execute` is a CLI execution mode, not an atom verb. |
| `fw_rollback_acl_policy` | Invalid for this baseline | Automatic rollback is out of scope; verification failures produce diagnostics and manual handling signals. |
| `fw_configure_nat` | Invalid | Use `fw_config_nat`; `configure` is reserved as a forbidden CLI/action wording in this baseline. |

## CLI Command Verb Boundary

The `atomic-ops` CLI is primarily a local catalog and validation interface.
The only real-device execution entry is the allowlisted `run` command, which is
dry-run by default and requires explicit `--execute` for live device requests.

Allowed CLI command families remain:

- `sync`
- `list`
- `show`
- `adapter`
- `run`
- `packages`
- `validate`

Forbidden additional CLI command verbs include:

- `execute`
- `apply`
- `configure`
- `config`
- `install`
- `init`
- `login`
- `rollback`
- `revert`

These forbidden CLI verbs may appear in this document as prohibited examples.
They must not be added as CLI subcommands unless a future change request expands
the executor surface with a separate safety design.

## Examples And Counterexamples

| Candidate | Status | Reason |
|---|---|---|
| `fw_verify_acl_rule` | Valid | Uses an allowed prefix, controlled verb, and explicit target |
| `fw_config_ospfv2_global` | Valid | Digits are allowed in the target segment for protocol names such as OSPFv2 |
| `tg_capture_packet_trace` | Valid | Uses an allowed prefix and lowercase underscore target |
| `sw_apply_vlan_config` | Valid | Uses a known action and target |
| `firewall_verify_acl_rule` | Invalid | Prefix must be one of `fw`, `tg`, `mock`, `sw` |
| `fw_Verify_acl_rule` | Invalid | Uppercase letters are not accepted |
| `fw_verify` | Invalid | Missing target segment |
| `fw_verify_acl-rule` | Invalid | Hyphens are not accepted in `op_id` |
| `fw_check_acl_rule` | Discouraged | `verify` is the controlled verb for state checks |
| `fw_configure_nat` | Invalid | Firewall v1.1 uses `config`, not `configure` |
| `fw_execute_login` | Invalid | Uses a CLI execution concept as an atom verb |
| `operation_id: fw_verify_acl_rule` | Invalid field name | Current schema uses `op_id`; `operation_id` is historical wording only |
| `device: fw` | Invalid field name | Current schema uses `device_type`; `device` is historical wording only |

When a candidate is invalid, update the `op_id` and the file path together. Do not create aliases by adding old field names to the YAML.

## Extension Process

New prefixes or verbs affect the shared schema and repository validators. Treat them as contract changes.

To add a new device prefix:

1. Record the reason and expected consumers in an approved change record or implementation issue.
2. Update `schemas/atomic-op.schema.yaml` `device_type` enum and `op_id` pattern.
3. Update this document's prefix table and examples.
4. Update layout validation and CLI validation logic when those Stories exist.
5. Add a `CHANGELOG.md` entry under the next `atoms-vX.Y.Z` section.

To add a new verb:

1. Confirm that the action cannot be represented by the existing controlled vocabulary.
2. Add the verb to the vocabulary table with a precise use condition.
3. Add at least one valid example and one near-miss example if ambiguity is likely.
4. Add a `CHANGELOG.md` entry under the next `atoms-vX.Y.Z` section.

To rename an existing `op_id`:

1. Create the replacement operation using the new `op_id`.
2. Mark the old operation with `deprecated: true`, `deprecated_by`, and `since_version` according to schema v1.
3. Add a `CHANGELOG.md` entry under `Deprecated` and, when removal happens, under `Removed`.
4. Keep package manifests and test-case references aligned before deleting the old operation.

## Review Checklist

- The `op_id` matches `^(fw|tg|mock|sw)_[a-z]+_[a-z0-9_]+$`.
- The `op_id` prefix matches `device_type`.
- The file path is `atoms/<device_type>/<op_id>.yaml`.
- The verb appears in the controlled vocabulary, or the extension process has been followed.
- New firewall v1.1 NGFW atoms use only `install`, `init`, `login`, `check`,
  `config`, `config_batch`, or `verify`.
- New firewall v1.1 files live under `atoms/fw/` and keep `device_type: fw`.
- CLI command changes do not add real-device action verbs such as `run`,
  `execute`, `apply`, `configure`, `config`, `install`, `init`, `login`,
  `rollback`, or `revert`.
- The target is specific enough to distinguish this operation from nearby operations.
- Historical fields such as `operation_id` and `device` are not used in schema v1 YAML.
- A relevant `CHANGELOG.md` entry is present for additions, deprecations, removals, or renames.
