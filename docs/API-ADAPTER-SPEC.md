# API Adapter Spec

## Revision Record

| Version | Date | Author | Change |
|---|---|---|---|
| v0.1 | 2026-05-19 | meta-dev | Add CR-004 public adapter profile contract. |
| v0.2 | 2026-05-19 | Codex | Align policy-route adapter with executable NGFW runner contract. |
| v0.3 | 2026-05-20 | Codex | Add OSPFv2 method-level adapter operations for config, query, and delete. |
| v0.4 | 2026-05-20 | Codex | Add OSPFv3 and BFD method-level adapter operations. |
| v0.5 | 2026-07-17 | meta-dev | Add trex.default adapter profile for tg TRex operations. |

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
| `atoms/fw/fw_config_ospfv2_*.yaml` | References OSPFv2 method-level profile operations through `adapter_contract_ref`. |
| `atoms/fw/fw_config_ospfv3_*.yaml` | References OSPFv3 method-level profile operations through `adapter_contract_ref`. |
| `atoms/fw/fw_config_bfd_global.yaml` | References the BFD global profile operation through `adapter_contract_ref`. |
| `ptm-atomic adapter fw_config_object` | Reads the synced cache and shows the address-object adapter operation. |
| `ptm-atomic adapter fw_config_policy_route` | Reads the synced cache and shows the policy-route adapter operation. |
| `ptm-atomic adapter fw_config_ospfv2_global` | Reads the synced cache and shows an OSPFv2 adapter operation. |
| `ptm-atomic adapter fw_config_ospfv3_global` | Reads the synced cache and shows an OSPFv3 adapter operation. |
| `ptm-atomic adapter fw_config_bfd_global` | Reads the synced cache and shows a BFD adapter operation. |
| `adapters/trex/default.yaml` | Defines the TRex default profile for tg traffic-generator operations. |
| `atoms/tg/tg_config_interface.yaml` | References the TRex config-interface profile operation through `adapter_contract_ref`. |
| `ptm-atomic adapter tg_config_interface` | Reads the synced cache and shows the TRex config-interface adapter operation. |
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

Most `ptm-atomic` commands remain read-only. `ptm-atomic run` is the only execution entry and is limited to explicit allowlisted operations. Adapter profiles still do not store device addresses, passwords, session material, or production samples.

`fw_config_object` currently maps to:

| Field | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/ippool` |
| Payload root | `val` |
| Required object fields | `val.name`, `val.networks[].ipaddr`, `val.networks[].mask` |

`fw_update_object` currently maps to:

| Field | Value |
|---|---|
| Method | `PUT` |
| Path | `/api/v1/ippool` |
| Payload root | `id` and `val` |
| Required object fields | `id`, `val.name`, `val.networks[].ipaddr`, `val.networks[].mask` |

`fw_delete_object` currently maps to:

| Field | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/ippool` |
| Query | `id` (address-object name) |
| Body | none |

`fw_verify_object` currently maps to:

| Field | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/ippool` |
| Query | `page`, `size` |
| Body | none |

`fw_delete_batch_object` currently maps to:

| Field | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/batch` |
| Payload root | `batch` |
| Required item fields | `batch[].method=DELETE`, `batch[].resource=/api/v1/ippool`, `batch[].body.id` (non-empty list) |

`fw_config_policy_route` currently maps to:

| Field | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/policyroute` |
| Payload root | `id` and `val` |
| Required route fields | `val.source_network`, `val.dst_network`, `val.source_network_is_group`, `val.dst_network_is_group`, `val.in_interface`, and at least one of `val.forwarding_paths[].next_hop_ip` or `val.forwarding_paths[].outgoing_interface` |

`val.source_network` and `val.dst_network` are address object names by default. If either value is an address group name, the corresponding `*_is_group` field must be `true`.
`val.forwarding_paths[].next_hop_ip` may be empty for outgoing-interface forwarding mode. When it is provided, it must be a valid IPv4 or IPv6 address matching `val.type`.

The runner obtains live session material from the local session file created by `ptm-atomic run auth login --execute`.

OSPFv2 operations are represented one HTTP method at a time because adapter schema v1.0 has a single `request.method` per operation. The default NGFW profile maps:

| Operation family | Methods | Paths |
|---|---|---|
| Interface entries | `POST`, `PUT`, `DELETE`, `GET` | `/api/v1/intf` |
| Interface batch deletion | `POST` | `/api/v1/batch` |
| OSPFv2 global config | `PUT`, `GET` | `/api/v1/ospfconfig` |
| OSPFv2 redistribution | `PUT`, `GET` | `/api/v1/ospfredist` |
| OSPFv2 network entries | `POST`, `PUT`, `DELETE`, `GET` | `/api/v1/ospfnetwork` |
| OSPFv2 interface entries | `POST`, `PUT`, `DELETE`, `GET` | `/api/v1/ospfinterface` |
| OSPFv2 neighbors | `GET` | `/api/v1/ospfneighbor` |
| OSPFv2 logs | `GET` | `/api/v1/ospflog` |
| OSPFv3 global config | `PUT`, `GET` | `/api/v1/ospf6config` |
| OSPFv3 redistribution | `PUT`, `GET` | `/api/v1/ospf6redist` |
| OSPFv3 network entries | `POST`, `PUT`, `DELETE`, `GET` | `/api/v1/ospf6network` |
| OSPFv3 interface entries | `POST`, `PUT`, `DELETE`, `GET` | `/api/v1/ospf6interface` |
| OSPFv3 neighbors | `GET` | `/api/v1/ospf6neighbor` |
| OSPFv3 logs | `GET` | `/api/v1/ospf6log` |
| BFD global config | `PUT`, `GET` | `/api/v1/bfdconfig` |
| BFD sessions | `GET` | `/api/v1/bfdsession` |
| BFD logs | `GET` | `/api/v1/bfdlog` |

GET entries keep `payload_template: {}` to satisfy the schema while the runner sends no JSON body. Interface GET calls `/api/v1/intf` without filters and returns all interfaces. Interface DELETE and OSPFv2/OSPFv3 interface DELETE entries use `?id=<interface>` and send no body. Network DELETE entries use the id-only JSON shape `{"id": "<id>"}`. Interface batch deletion is modeled separately as `POST /api/v1/batch`.

## TRex Profile

The `adapters/trex/default.yaml` profile maps the six `tg` traffic-generator operations to the trex-api HTTP service. Unlike the NGFW profile, trex-api exposes a single dispatch endpoint `POST /api/v1/ops/{op_id}` for every operation (including verify and delete), and success is decided by the response `OperationEnvelope` (`{op_id, status, data, error_type, diag_snapshot_ref}`) rather than the HTTP status code, which stays `200` even on failure. The service is unauthenticated, so the profile declares a placeholder `external_credential_ref` auth entry and the runner sends no credential header at runtime.

| Operation | Method | Path | Payload |
|---|---|---|---|
| `tg_config_interface` | `POST` | `/api/v1/ops/tg_config_interface` | `interfaces` array |
| `tg_apply_traffic_template` | `POST` | `/api/v1/ops/tg_apply_traffic_template` | flat template fields (`template`, `tx_port`, `rx_port`, `l4_*`, `rate`, ...) |
| `tg_start_traffic_stream` | `POST` | `/api/v1/ops/tg_start_traffic_stream` | flat stream fields (`ports`, `txport`, `rxport`, `template`, `name`) |
| `tg_verify_traffic_loss` | `POST` | `/api/v1/ops/tg_verify_traffic_loss` | flat stream fields + `max_loss` |
| `tg_stop_traffic_stream` | `POST` | `/api/v1/ops/tg_stop_traffic_stream` | flat stream fields |
| `tg_delete_traffic_template` | `POST` | `/api/v1/ops/tg_delete_traffic_template` | `template` |

The runner reads the trex-api base URL from `--base-url` (for example `http://10.0.0.1:8000`) and does not consume the NGFW session file. On a failed envelope the runner maps `error_type` to a stable CLI error code: `INVALID_PARAM` / `RESOURCE_NOT_FOUND` / `STATE_MISMATCH` -> `RUNNER_VALIDATION_FAILED`, `RESOURCE_CONFLICT` -> `RUNNER_CONFIG_REJECTED`, `INTERNAL_ERROR` -> `RUNNER_RESPONSE_INVALID`, `DEVICE_UNREACHABLE` / `TIMEOUT` -> `RUNNER_DEVICE_UNREACHABLE`.

## Validation

Run the adapter profile check together with the normal repository checks:

```bash
uv run ptm-atomic adapter fw_config_object
uv run ptm-atomic adapter fw_config_policy_route
uv run ptm-atomic adapter fw_config_ospfv2_global
uv run ptm-atomic adapter fw_delete_ospfv2_network
uv run ptm-atomic adapter fw_config_ospfv3_global
uv run ptm-atomic adapter fw_config_bfd_global
uv run ptm-atomic adapter tg_config_interface
uv run --python 3.11 python scripts/validate_adapter_profiles.py
uv run --python 3.11 python scripts/security_gate_check.py
```

`ptm-atomic adapter <op_id>` is a read-only cache query. It requires the local cache to be synced to a repository version that includes both the atom `adapter_contract_ref` and the referenced `adapters/` profile file.
