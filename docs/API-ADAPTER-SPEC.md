# API Adapter Spec

## Revision Record

| Version | Date | Author | Change |
|---|---|---|---|
| v0.1 | 2026-05-19 | meta-dev | Add CR-004 public adapter profile contract. |
| v0.2 | 2026-05-19 | Codex | Align policy-route adapter with executable NGFW runner contract. |

## Purpose

Adapter profiles are public, non-sensitive mapping contracts for script generators and the built-in runner allowlist. They connect an atom operation to the API shape a runner needs without storing runtime endpoint values or credentials.

The first profile is `adapters/ngfw/default.yaml`. The profile entry for `fw_config_policy_route` is referenced by:

```yaml
adapter_contract_ref: adapters/ngfw/default.yaml#/operations/fw_config_policy_route
```

## Contract Surface

| File | Role |
|---|---|
| `schemas/adapter-profile.schema.yaml` | Validates public adapter profile shape. |
| `adapters/ngfw/default.yaml` | Defines the NGFW default profile. |
| `atoms/fw/fw_config_object.yaml` | References the address-object profile operation through `adapter_contract_ref`. |
| `atoms/fw/fw_config_policy_route.yaml` | References the policy-route profile operation through `adapter_contract_ref`. |
| `atomic-ops adapter fw_config_object` | Reads the synced cache and shows the address-object adapter operation. |
| `atomic-ops adapter fw_config_policy_route` | Reads the synced cache and shows the policy-route adapter operation. |
| `scripts/validate_adapter_profiles.py` | Checks profile schema validity and atom reference integrity. |
| `scripts/security_gate_check.py` | Includes `adapters/` in the default read-only security scan and performs structured adapter sensitive-content checks. |

## Allowed Content

Adapter profiles may describe:

| Area | Allowed form |
|---|---|
| Operation link | Atom file path and operation id. |
| Request shape | HTTP method, endpoint path, content type, and placeholder payload template. |
| External session reference | Public header name with a placeholder value such as `<session-ref>`. |
| Response shape | Expected success status codes and a non-sensitive result reference. |
| Safety notes | Static notes stating that the runner owns runtime execution inputs. |

Endpoint paths must be relative paths. A profile must not contain absolute URLs or environment-specific addresses.

## Forbidden Content

Adapter profiles must not contain runtime-sensitive information or local input dependencies. The validator rejects sensitive field names or values, including:

| Forbidden class | Required handling |
|---|---|
| Device address or host material | Keep it in an external runner inventory. |
| Token, cookie, password, FTP credential, secret, or authorization material | Keep it outside this repository and pass only non-sensitive references. |
| Private key content or key references | Keep it outside this repository. |
| Production request or response samples | Use shape-only placeholders and result refs. |
| `.input/capacity` dependency | Migrate public API shape into `adapters/`; do not require consumers to read `.input/`. |

## Runtime Boundary

Most `atomic-ops` commands remain read-only. `atomic-ops run` is the only execution entry and is limited to explicit allowlisted operations. Adapter profiles still do not store device addresses, passwords, session material, or production samples.

`fw_config_object` currently maps to:

| Field | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/ippool` |
| Payload root | `val` |
| Required object fields | `val.name`, `val.networks[].ipaddr`, `val.networks[].mask` |

`fw_config_policy_route` currently maps to:

| Field | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/policyroute` |
| Payload root | `id` and `val` |
| Required route fields | `val.source_network`, `val.dst_network`, `val.source_network_is_group`, `val.dst_network_is_group`, `val.forwarding_paths[].next_hop_ip`, `val.in_interface` |

`val.source_network` and `val.dst_network` are address object names by default. If either value is an address group name, the corresponding `*_is_group` field must be `true`.

The runner obtains live session material from the local session file created by `atomic-ops run fw_login_web_management --execute`.

## Validation

Run the adapter profile check together with the normal repository checks:

```bash
uv run atomic-ops adapter fw_config_object
uv run atomic-ops adapter fw_config_policy_route
uv run --python 3.11 python scripts/validate_adapter_profiles.py
uv run --python 3.11 python scripts/security_gate_check.py
```

`atomic-ops adapter <op_id>` is a read-only cache query. It requires the local cache to be synced to a repository version that includes both the atom `adapter_contract_ref` and the referenced `adapters/` profile file.
