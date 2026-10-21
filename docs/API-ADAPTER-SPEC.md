# API Adapter Spec

## Revision Record

| Version | Date | Author | Change |
|---|---|---|---|
| v0.1 | 2026-05-19 | meta-dev | Add CR-004 public adapter profile contract. |
| v0.2 | 2026-05-19 | Codex | Align policy-route adapter with executable NGFW runner contract. |
| v0.3 | 2026-05-20 | Codex | Add OSPFv2 method-level adapter operations for config, query, and delete. |
| v0.4 | 2026-05-20 | Codex | Add OSPFv3 and BFD method-level adapter operations. |
| v0.5 | 2026-07-17 | meta-dev | Add trex.default adapter profile for tg TRex operations. |
| v0.6 | 2026-07-30 | meta-dev | Add tg_acquire_ports/tg_release_ports/tg_verify_ownership operations and user_id field for multi-user port ownership. |
| v0.7 | 2026-09-14 | meta-dev | Align schema with implemented runner behaviour: `request.content_type` admits `multipart/form-data` (file-upload operations), `request.query_params` models paginated GETs, and `shell.privilege_level` admits `privileged`/`root` for appliance SSH targets. |
| v0.8 | 2026-10-13 | meta-dev | Add the IPv4 DHCP operation family and document `POST /api/v1/batchv2`, the first batch endpoint outside `/api/v1/batch`. |
| v0.9 | 2026-10-16 | meta-dev | Add the IPv6 DHCP operation family, document the nested `{"error": {...}}` envelope it answers, and correct v0.8's claim that `/api/v1/dhcpstaticip` is reachable only through batch delete. |
| v1.0 | 2026-10-19 | meta-dev | Add the IPS rule and protection-profile family, document its JSON-body GET/DELETE shape and per-id batch delete items, and document `sec_obj_data` IPS references in the `fwaclconf` control-policy operations. |
| v1.1 | 2026-10-19 | meta-dev | Add IPS security-log query (`/api/v1/monitor/seclog`), evidence metadata (`/api/v1/seclog/evidence`), pcap download (`/api/v1/downloadfile`), and license queries (`/api/v1/licensedev`, `/api/v1/license`); record `config_source` semantics and the `whiteList` exception model. |
| v1.2 | 2026-10-19 | meta-dev | Add the global log-cache merge setting (`PUT /api/v1/logsetting/logcacheset`), noting that it has no GET readback, that only `id=1` is supported and id is not gid, and that `timeSet` is an integer whose unit is device-defined. |
| v1.3 | 2026-10-19 | meta-dev | Complete IPS profile `actionWrapper`/`filters`/`capture_pkt`/source-classification modelling and add IPS log export, clear, time setting, cache read, backup list, and three-step download-task operations. |
| v1.4 | 2026-10-20 | meta-dev | Add IPS log business filters (`rule_name`/`level`/`action`/`xff`) and the AO-002/AO-003/AO-004/AO-008 SSH process-restart, resource, capture-storage, and system-log observation operations. |
| v1.5 | 2026-10-21 | meta-dev | Add the interface-pair family (`POST`/`GET`/`PUT`/`DELETE /api/v1/intf/pair`) and the read-only system-time query (`GET /api/v1/systime?id=systime`), including the L2 preparation order and client-side pair filters. |

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
| Request shape | HTTP method, endpoint path, content type, optional query parameters, and placeholder payload template. |
| Multipart upload | `content_type: multipart/form-data` with the form parts declared in `payload_template`; the HTTP client appends the boundary, so the profile never sets the header itself. |
| Pagination | Optional `query_params` map appended to `path`; each value is a template the runner URL-encodes. |
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

## SSH / Telnet / CLI Operations

Adapter profile schema v1.1 adds optional `transport` and `shell` fields to an
operation entry. When `transport: ssh`, `telnet`, or `cli`, the operation entry
MUST declare a `shell` block instead of an HTTP `request` block:

| Field | Required | Description |
|---|---|---|
| `shell.command_template` | Yes | Shell command template with `{{param}}` placeholders. Runner shell-escapes every placeholder. |
| `shell.success_pattern` | Yes | Regex matched against stdout/stderr to indicate success. |
| `shell.prompt_timeout_ms` | No | Max wait for device prompt. Defaults to the atom `timeout_ms`. |
| `shell.privilege_level` | No | `user`, `enable`, `configure`, `privileged`, or `root`. Defaults to `enable`. `user`/`enable`/`configure` describe network-CLI mode escalation; `privileged`/`root` describe OS-level privilege on appliance SSH targets (for example `vppctl`). Descriptive metadata only — the runner does not perform escalation from this field. |

Security rules:

- The profile MUST NOT pre-encode shell metacharacters (`;`, `|`, backticks, `$()`, `&&`).
- The runner MUST shell-escape every `{{param}}` substitution.
- Credentials come only from `--password-env` and the local session file, never from the profile or atom.
- `destructive`/`irreversible` shell commands MUST declare `gate.required: true` and `rollback_strategy.type: manual_required` (or `irreversible`), mirroring the reboot contract.
- Shell command stdout/stderr is written only to `diag_snapshot_ref`; never committed to the repo.

The default HTTP runner returns `RUNNER_UNSUPPORTED_OP` for ssh/telnet/cli ops
until a dedicated `runner/ssh.py` is registered in the allowlist.

## Interface Pair Profile

The interface-pair resource is `/api/v1/intf/pair` and is separate from the `/api/v1/intf` interface resource. It is a pair-forwarding object, not an L2-specific operation: no dedicated L2 atom is introduced.

| Operation | Method | Path | Body / query |
|---|---|---|---|
| `fw_config_interface_pair` | `POST` | `/api/v1/intf/pair` | `{"val": {"name", "remark", "receive_interface", "transmit_interface", "status_sync", "allowed_vlan"}}` |
| `fw_verify_interface_pair` | `GET` | `/api/v1/intf/pair` | `page`, `size` |
| `fw_update_interface_pair` | `PUT` | `/api/v1/intf/pair` | `{"id": "<pair-name>", "val": {...}}` |
| `fw_delete_interface_pair` | `DELETE` | `/api/v1/intf/pair?id=<pair-name>` | none |

`val.allowed_vlan` is a string such as `"0"` (untagged) or `"1-4094"`; the runner also accepts an integer and normalizes it to a string. `status_sync` is a boolean. The pair name is the identity: create carries no top-level `id`, update carries `id` equal to `val.name`, and delete uses the name as the `?id=` value. Swagger declares the delete `id` as `list[str]`; this single-delete operation follows the repository delete convention and sends one query value.

**Preparation order.** Configure interfaces first, then create the pair:

1. Pair forwarding: set both physical ports with `fw_update_interface` `mode="Pair"` (and the required pvid/linkType fields) before `fw_config_interface_pair`.
2. L2 switching: prepare member ports with `fw_update_interface` (mode `Switch`, `pvid`, `linkType` 1 for access), create the BVI with `fw_config_interface` (`val.type` 14 and `val.bvi.bridge.interfaces`), and only then create any pair that references those ports.
3. Pair update/delete: the referenced ports remain in pair mode; confirm create/update/delete with `fw_verify_interface_pair`.

**Query filtering.** `GET /api/v1/intf/pair` accepts only `page` and `size`; there are no server-side `name`/`receive_interface`/`transmit_interface` filters. The runner therefore fetches all pages (internal page size 100) when a filter is supplied, applies exact-match client-side filtering, and then applies the requested `page`/`size` slice to the filtered result. With no filter, the query is passed through unchanged. The returned `count` is the matching count and `vals` retains `name`, `remark`, `receive_interface`, `transmit_interface`, `allowed_vlan`, `status_sync`, `config_source` and `create_time` when the device provides them. `page` and `size` must be supplied together when filtering; supplying only one is rejected locally.

## System Time Profile

`fw_verify_system_time` maps to `GET /api/v1/systime?id=systime` and is read-only. It returns `vals[0]` fields `name`, `enable`, `date`, `time` and `ntp`. The optional `expected_date` (`YYYY-MM-DD`) and `expected_time` (`HH:MM:SS`) inputs produce exact-match flags (`matches_expected_date`, `matches_expected_time`, `matches_expected`) instead of changing the device clock. There is deliberately no modify-system-time operation; the op exists for log time baselines and time-accuracy checks.

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

## DHCP Profile

The IPv4 DHCP family is the first to use a batch endpoint other than `/api/v1/batch`. `POST /api/v1/batchv2` carries the same payload shape as `/api/v1/batch` — `{"batch": [{"method": "DELETE", "resource": "<path>", "body": {"id": ["<entry-id>"]}}]}` — but answers with a differently shaped response whose per-item keys are `id` and `data` rather than `status`/`msg`. The runner therefore does not wire `runner/batch.py#summarize_batch_result` for this family: that helper reads only `status`/`msg`/`message`/`errMsg`, so every item would be judged indeterminate and the whole batch downgraded, leaving `success_count`/`failed_count` permanently `null`. The raw response is returned instead.

`batchv2` also honours only the **first** element of a multi-element `body.id` list. Measured on 2026-10-13, a single item carrying `["8.1.1.101", "8.1.1.102"]` deleted `8.1.1.101` alone, answered one `BatchResult` entry, and left `8.1.1.102` in place with no error — a silent partial success. The body must carry **one item per id**. `build_dhcp_static_ip_batch_delete_payload` passes `carrier="per_id_item"` to the shared builder for this reason, overriding its `single_item` default; the specification's own example body is a single-element `id`, consistent with the observed behaviour.

| Operation | Method | Path | Body |
|---|---|---|---|
| `fw_config_dhcp_server` | `POST` | `/api/v1/dhcp` | `{"val": {...}}` |
| `fw_update_dhcp_server` | `PUT` | `/api/v1/dhcp` | `{"id": "<interface-name>", "val": {...}}` |
| `fw_verify_dhcp_server` | `GET` | `/api/v1/dhcp` | none |
| `fw_delete_dhcp_server` | `DELETE` | `/api/v1/dhcp?id=<interface-name>` | none |
| `fw_verify_dhcp_static_ip` | `GET` | `/api/v1/dhcp` | none |
| `fw_delete_batch_dhcp_static_ip` | `POST` | `/api/v1/batchv2` | `{"batch": [...]}`, one item per binding address |

A DHCP server is identified by the interface it binds to, so `val.ifname` is also the `?id=` value and the `fw_update_dhcp_server` body id — the create response carries no separate identifier.

The bound interface must already carry an IPv4 address and each configured subnet must sit inside that interface's own IPv4 subnet, otherwise the device answers `eDhcpdConfigIpPoolLimit`. Each static host binding address must additionally fall inside its subnet's `range` pool, not merely inside the subnet; the device answers `eDhcpdConfigHostIpInNet` (DHCP服务器保留IP应在地址池范围内) otherwise.

`val.server.lease` is a validated invariant rather than a default. The interface specification marks it optional, but a single-variable isolation test on 2026-10-13 proved that a `POST` or `PUT` to `/api/v1/dhcp` without it crashes the device management service (nginx 502, roughly 90 seconds of outage, then sessions must be re-established). The runner rejects a lease-less payload from any source — flat flags or `--payload-json` — so a caller cannot reach the device with one.

`/api/v1/dhcpstaticip` has no storage of its own and, as v0.8 measured, `GET` and `POST` both answer 405. Static address bindings are a projection of each DHCP entry's `server.hosts`, and they disappear with the server that declares them. `fw_verify_dhcp_static_ip` is therefore a client-side projection that reads `/api/v1/dhcp` and emits one `{ifname, name, addr, mac}` row per binding; the `addr` in each row is the value `fw_delete_batch_dhcp_static_ip` takes as its id. **v0.9 correction:** batch delete is not the only removal path. A direct single delete `DELETE /api/v1/dhcpstaticip?id=<addr>` exists, works, and is shared with the IPv6 family (measured 2026-10-16); v0.8 had only probed `GET`/`POST` on this resource and batchv2, and did not try the direct form. The batch operation is retained because it answers a per-id result, which the direct form never does — see the DHCPv6 profile below.

The DHCP query endpoint supports no filtering or pagination. Seven candidate parameters (`key`, `keywords`, `name`, `ifname`, `page`, `size`, `search`) were each measured as silently ignored on 2026-10-13 — the device returns the full list rather than rejecting the parameter — so the two query operations expose no query flags at all.

## DHCPv6 Profile

The IPv6 family mirrors the IPv4 one over `/api/v1/dhcpv6`, with three structural differences in the `val` payload: `server.subnet` is a **single CIDR string** rather than a `subnets` array (there is no `range` pool and no `gateway`), `server.prefix` and `server.prefix_len` are two additional required fields, and a static binding addresses its client by `duid` rather than by `mac`. Three v6-only option keys — `server.sip`, `server.sntp` and `server.domain` — are emitted as empty strings when unset.

| Operation | Method | Path | Body |
|---|---|---|---|
| `fw_config_dhcpv6_server` | `POST` | `/api/v1/dhcpv6` | `{"val": {...}}` |
| `fw_update_dhcpv6_server` | `PUT` | `/api/v1/dhcpv6` | `{"id": "<interface-name>", "val": {...}}` |
| `fw_disable_dhcpv6_server` | `PUT` | `/api/v1/dhcpv6` | `{"id": "<interface-name>", "val": <live readback with both enable flags false>}` |
| `fw_verify_dhcpv6_server` | `GET` | `/api/v1/dhcpv6` | none |
| `fw_delete_dhcpv6_server` | `DELETE` | `/api/v1/dhcpv6?id=<interface-name>` | none |
| `fw_verify_dhcpv6_static_ip` | `GET` | `/api/v1/dhcpv6` | none |
| `fw_delete_dhcpv6_static_ip` | `DELETE` | `/api/v1/dhcpstaticip?id=<binding-address>` | none |

A DHCPv6 server is likewise identified by the interface it binds to, and `/api/v1/dhcpv6` answers its list under `data` where the IPv4 endpoint uses `vals` — that key is the only response-shape divergence between the two families.

**Error envelope.** `/api/v1/dhcpv6` is the first endpoint in this repository whose failures are nested: it answers `{"error": {"code", "message", "target", "details", "innererror"}}` rather than the flat `errCode`/`errMsg` shape every other endpoint uses. `runner/dhcpv6.py#_flatten_device_error` promotes `error.code` and `error.message` onto flat `errCode`/`errMsg` keys **before** the shared judgement functions run, because those read flat keys only; without that step an "already gone" response would be invisible and the family could never self-heal on a repeat delete.

**Crash guards.** Both `val.server.lease` and `val.server.subnet` are validated invariants, not defaults. `lease` inherits the IPv4 finding: the interface specification marks it optional and a `POST`/`PUT` without it crashes the management service (nginx 502). `subnet` was proven locally on 2026-10-16 — omitting it crashes the management service the same way, roughly three minutes of outage, with no session invalidation and no residual configuration. The runner rejects a payload missing either key from any source, flat flags or `--payload-json`, and the disable replay carries both. Omitting `val.ifmode` or `server.name` is a clean 400 `eRequestParam` instead.

**Device-side rules** (not duplicated locally, because the runner performs no CIDR parsing or format rewriting): `server.subnet` must differ from `server.prefix`, otherwise `eDhcpdNetworkDuplicateWithDetail`; `server.prefix_len` must land in the inclusive range `[prefix length, prefix length + 16]`, otherwise `eDhcpdPrefixRangeErrorWithDetail`; every host binding address must fall inside `server.subnet`, otherwise `eDhcpdConfigHostIpWithinSubnetWithDetail`; and each binding's `duid` must be written as colon-separated hex such as `00:03:00:01:00:00:00:00:01:01`, otherwise `eDhcpdConfigHostDuidFormatErrorWithDetail` (保留IP DUID格式错误). Note the contrast with IPv4: there is **no** rule that the subnet must sit on the interface's own network, and `server.prefix` may equal the interface network. On readback the device normalises `prefix` — `8888::1111/96` reads back as `8888::/96`. `ifmode` accepts `SERVER` only; `CLIENT`, `RELAY`, `OFF` and arbitrary values were each rejected with 400 `eRequestParam`.

**Enable flags.** `val.enable` and `val.server.enable` are independent keys, and a `val` that omits the top-level one lets the device materialise `false` for it. This is a live defect that the IPv4 builder had: `build_dhcp_server_val` never emitted a top-level `enable`, so any static address deletion — which replays the entry — flipped the server to disabled. Both builders now emit it explicitly. There is no minimal disable body: live probing rejected `enable`-only bodies (`eRequestParam`, and `eDhcpdNoPrefixOrNetworkWithDetail` when the address pool was missing too), proving `PUT` replaces the whole configuration. The disable operation is therefore a read-modify-write: `GET` the entry by interface name, replay it verbatim with both flags `false`, `PUT` it back. Round-trip probing on 2026-10-16 showed the replay is lossless (a key-by-key diff ignoring the enable flags is empty) and reversible; enabling again is an ordinary update, so there is no dedicated enable operation.

**Not-found judgement.** `/api/v1/dhcpv6` answers 400 `eRequestParam` with the message `http请求参数错误` for a repeat delete, for an interface name that never existed, and for an empty id — three cases measured on 2026-10-16 — while a wrong HTTP method answers 405. `eRequestParam` is a **generic** code, so it cannot go into `errors.py#RESOURCE_NOT_FOUND_ERR_CODES` (that would widen every registered operation) and its message cannot go into the global marker list either (a genuinely malformed request would then be misread as goal-reached, which under-reports real residue — the unacceptable direction). The pair instead goes into the op-scoped `RESOURCE_NOT_FOUND_OP_CODE_MARKERS` table, which applies only to the op it names and is gated by the `IDEMPOTENT_ERROR_TYPES` registry as before; `validate_idempotent_registry` rejects a marker entry whose op is not registered. The judgement also assumes a non-empty id, which the runner enforces before the request leaves — a `DELETE` carrying no id at all answers 200 with a success body while leaving the configuration untouched, a false success that must never be reachable from the command layer.

**Shared static delete endpoint.** `/api/v1/dhcpstaticip` serves both families and reaches the same storage: the device's front-end constant table declares a single `staticdel` with no v6 variant, and live probing on 2026-10-16 removed an IPv4 binding through the v6 path. It is extremely permissive — a repeat delete, an address that never existed, and a `DELETE` with no id at all each answer 200 with a success body — so success never establishes that anything was removed and no resource-not-found judgement is possible on it. `fw_delete_dhcpv6_static_ip` is therefore declared `idempotent: true` **without** `RESOURCE_NOT_FOUND` and is deliberately absent from `IDEMPOTENT_ERROR_TYPES`; registering it would be dead configuration. The address is the `?id=` value and contains colons, which `urlencode` escapes as `%3A`; differential probing confirmed the device decodes the escaped form and removes exactly the addressed binding.

**Verification.** `/api/v1/dhcpstaticip` exposes no `GET`, so `fw_verify_dhcpv6_static_ip` is a projection that reads `/api/v1/dhcpv6` and emits one `{ifname, name, addr, duid}` row per binding — the only view that can confirm a static delete did anything. As with IPv4, seven candidate query parameters were each measured as silently ignored, so neither query operation exposes query flags.

## OSPFv2 and Related Profiles

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

The `adapters/trex/default.yaml` profile maps the nine `tg` traffic-generator operations to the trex-api HTTP service. Eight operations go through the single dispatch endpoint `POST /api/v1/ops/{op_id}` (including verify and delete), and success is decided by the response `OperationEnvelope` (`{op_id, status, data, error_type, diag_snapshot_ref}`) rather than the HTTP status code, which stays `200` even on failure. The `tg_verify_ownership` query uses a dedicated `GET /api/v1/ownership` endpoint and returns a raw `{count, ownerships}` object instead of an envelope; HTTP 200 alone determines success. The service is unauthenticated, so the profile declares a placeholder `external_credential_ref` auth entry and the runner sends no credential header at runtime.

All operations carry an optional `user_id` field (default `"default"` = legacy force mode). Set `user_id` to `dev<ip-suffix>-<seq>` (for example `dev171-1`) and pair `tg_acquire_ports` with `tg_config_interface` / `tg_start_traffic_stream` / `tg_stop_traffic_stream` / `tg_verify_traffic_loss` so they reuse the acquired client without re-acquiring ports. `tg_acquire_ports` and `tg_release_ports` require `user_id`.

| Operation | Method | Path | Payload |
|---|---|---|---|
| `tg_acquire_ports` | `POST` | `/api/v1/ops/tg_acquire_ports` | `user_id`, `ports` array |
| `tg_config_interface` | `POST` | `/api/v1/ops/tg_config_interface` | `user_id?`, `interfaces` array |
| `tg_apply_traffic_template` | `POST` | `/api/v1/ops/tg_apply_traffic_template` | `user_id?`, flat template fields (`template`, `tx_port`, `rx_port`, `l4_*`, `rate`, ...) |
| `tg_start_traffic_stream` | `POST` | `/api/v1/ops/tg_start_traffic_stream` | `user_id?`, flat stream fields (`ports`, `txport`, `rxport`, `template`, `name`) |
| `tg_verify_traffic_loss` | `POST` | `/api/v1/ops/tg_verify_traffic_loss` | `user_id?`, flat stream fields + `max_loss` |
| `tg_stop_traffic_stream` | `POST` | `/api/v1/ops/tg_stop_traffic_stream` | `user_id?`, flat stream fields |
| `tg_delete_traffic_template` | `POST` | `/api/v1/ops/tg_delete_traffic_template` | `user_id?`, `template` |
| `tg_release_ports` | `POST` | `/api/v1/ops/tg_release_ports` | `user_id`, `ports?` (omit to release all) |
| `tg_verify_ownership` | `GET` | `/api/v1/ownership` | none |

The runner reads the trex-api base URL from `--base-url` (for example `http://10.0.0.1:8000`) and does not consume the NGFW session file. On a failed envelope the runner maps `error_type` to a stable CLI error code: `INVALID_PARAM` / `RESOURCE_NOT_FOUND` / `STATE_MISMATCH` -> `RUNNER_VALIDATION_FAILED`, `RESOURCE_CONFLICT` -> `RUNNER_CONFIG_REJECTED`, `INTERNAL_ERROR` -> `RUNNER_RESPONSE_INVALID`, `DEVICE_UNREACHABLE` / `TIMEOUT` -> `RUNNER_DEVICE_UNREACHABLE`.

## IPS Profile

The ten IPS operations map to two resources plus the shared batch endpoint. Unlike most NGFW GET and DELETE operations in this repository, the captured traffic sends a JSON request body for both methods, so the adapter `payload_template` describes the body and no `query_params` are used.

| Operation | Method | Path | Payload |
|---|---|---|---|
| `fw_verify_ips_rule` | `GET` | `/api/v1/appsec/ips/rules` | selected-id body `{"id": [...]}` or list body `{key, page, size, config_source?, level?, direct?, os?, classtype?}` |
| `fw_config_ips_rule` | `POST` | `/api/v1/appsec/ips/rules` | `{"val": {name, desc, isProfenal}}` |
| `fw_update_ips_rule` | `PUT` | `/api/v1/appsec/ips/rules` | `{"id": "<numeric-id>", "val": {name, desc, isProfenal}}` |
| `fw_delete_ips_rule` | `DELETE` | `/api/v1/appsec/ips/rules` | `{"id": "<numeric-id>"}` |
| `fw_delete_batch_ips_rule` | `POST` | `/api/v1/batch` | one DELETE item per id with `resource: /api/v1/appsec/ips/rules` |
| `fw_verify_ips_profile` | `GET` | `/api/v1/appsec/ips/profiles` | `{key, page, size, config_source?}` |
| `fw_config_ips_profile` | `POST` | `/api/v1/appsec/ips/profiles` | `{"val": {name, actionWrapper, filters, whiteList, customAddRuleList, desc}}` |
| `fw_update_ips_profile` | `PUT` | `/api/v1/appsec/ips/profiles` | `{"id": "<numeric-id>", "val": {...}}` |
| `fw_delete_ips_profile` | `DELETE` | `/api/v1/appsec/ips/profiles` | `{"id": "<numeric-id>"}` |
| `fw_delete_batch_ips_profile` | `POST` | `/api/v1/batch` | one DELETE item per id with `resource: /api/v1/appsec/ips/profiles` |

`page`, `size`, `key` and `config_source` are sent as strings in the captured requests. Single-value rule filters are sent as scalar strings and multi-value filters as string lists. `config_source=0` means no filtering (captured list/selection requests), while `config_source=18` selects firewall-predefined entries; in responses, `config_source=18` marks predefined entries and a missing `config_source` marks custom entries. There is no `isCustom` request filter. Create responses return `{"vals": [{"Id": <numeric-id>, "Name": <name>}]}`; delete responses return `{"msg": "success"}`; batch responses return `{"BatchResult": [{"msg": "success"}, ...]}` with one entry per requested id. A repeat single delete answers `400 eConfigWrite` with the op-specific message (`删除规则失败(C)` for rules, `读取profile错误` for profiles); the runner maps each pair to `RESOURCE_NOT_FOUND` with `idempotent=true`.

The profile `whiteList` is the IPS exception-rule list: each entry carries `ruleId` and excludes that rule from the profile. It is part of the profile create/update `val`, so an update that must keep exceptions has to resend them.

The IPS security-log and related operations use query strings rather than JSON bodies:

| Operation | Method | Path | Query |
|---|---|---|---|
| `fw_capture_ips_log` | `GET` | `/api/v1/monitor/seclog` | `gid`, `page`, `size`, `timetype`, plus `starttime`/`endtime` for `custom` |
| `fw_verify_seclog_evidence` | `GET` | `/api/v1/seclog/evidence` | `meta_file` |
| `fw_download_seclog_pcap` | `GET` | `/api/v1/downloadfile` | `id=logpcap/<pcap_filename>` (URL-encoded) |
| `fw_verify_license_dev` | `GET` | `/api/v1/licensedev` | none |
| `fw_verify_license` | `GET` | `/api/v1/license` | none |
| `fw_config_log_cache_set` | `PUT` | `/api/v1/logsetting/logcacheset` | body `{"id": 1, "val": {"enable": true, "timeSet": 60}}` |
| `fw_export_ips_log` | `GET` | `/api/v1/export` | `id=logexport`, `logtype=ipslog`, `type=csv`, `timetype`, plus `starttime`/`endtime` for `custom` |
| `fw_clear_ips_log` | `DELETE` | `/api/v1/deletelog` | `logtype=ipslog` |
| `fw_config_log_time_set` | `PUT` | `/api/v1/logsetting/logtimesetting` | body `{"id": "0", "val": {"timeSet": 180}}` |
| `fw_verify_log_time_set` | `GET` | `/api/v1/logsetting/logtimesetting` | none |
| `fw_verify_log_cache_set` | `GET` | `/api/v1/logsetting/logcacheset` | none |
| `fw_verify_log_backup_list` | `GET` | `/api/v1/logsetting/logbackcsv` | `page`, `size`, `keywords` |
| `fw_create_log_download_task` | `POST` | `/api/v1/downloadfilehandle` | `{"val":{"dataId":["..."],"moduletype":"influxTask","filetype":"csv"}}` |
| `fw_verify_log_download_task` | `GET` | `/api/v1/downloadfilehandle` | `id=<taskid>` |
| `fw_download_log_file` | `GET` | `/api/v1/downloadfile` | `id=<filename>` (URL-encoded) |

`gid` defaults to 1, and the user-confirmed scope implements only `gid=1` (IPS); other security-log types are not enumerated and will be added by later features. `timetype` accepts `24h`, `all`, `1h`, `7d`, `1m`, `custom`. The top-level `count` drives pagination. The entry field set is modelled from the evidence meta (`app_protocol`, `dst_ip`, `dst_port`, `src_ip`, `src_port`, `protocol`, `rule{advice,affact,classtype,cnnvd,cve,desc,gid,name,rev,sid}`, `timestamp_us`, `pcap_filename`, `data_filename`, `highlights`, ...); the runner returns the raw JSON unchanged, so if an entry differs from that set the raw JSON remains authoritative. Identical attacks within the query window are merged by the device and their attack count is accumulated; no separate IPS noise-reduction configuration operation exists. Evidence `vals.meta.pcap_filename` feeds `fw_download_seclog_pcap`. License `module[]` entries carry `license_left`, `count`, `end`, `begin`, `enabled` and `name`; the IPS module is the entry named `入侵防御`.

`fw_config_log_cache_set` is a global log setting used by the IPS log flow to configure the merge window. It supports `PUT` only and has no GET readback, so success is the only direct signal; verify indirectly through the accumulated attack count in the `gid=1` security-log query. `id` supports only 1, and id is not gid; the setting applies to log merging for all log types. `timeSet` is modelled as an integer whose unit is device-defined (sample 60) and is not asserted as seconds or minutes.

IPS profile payloads are modelled from the captured structures. `actionWrapper` entries use `priority` 1..5 with `action` 0/1/2. `filters` entries use `protocols`, `classtype`, `builtintype` (`dmz`/`radom`), `prioritys`, `Directs`, `OsTypes`, optional `action` and `capture_pkt`; `[{}]` means all rules. `customAddRuleList` entries carry a rule `id`, `action` 0/1/2 and optional `capture_pkt` (`true` captures packets for that rule, `false` does not); per-rule and per-filter actions override the actionWrapper level action. `whiteList` remains the exception-rule list. `fw_verify_ips_profile` classifies each entry as predefined when `config_source=18` or when `id<1000`, and as custom when `id>=1000` (the captured create response assigned id 1000 to a user-created profile); versions without `config_source` fall back to the id rule.

Log management uses `GET /api/v1/export` for CSV export (the runner writes the response bytes to `output_path`), `DELETE /api/v1/deletelog` for irreversible clearing, `GET/PUT /api/v1/logsetting/logtimesetting` for backup/retention time (unit device-defined, sample 180), `GET /api/v1/logsetting/logcacheset` for the readback of the cache setting, and `GET /api/v1/logsetting/logbackcsv` for backup files (`count` plus `vals[name,mtime,logtype]`). The three-step download flow uses `POST /api/v1/downloadfilehandle` to create a task (`vals[0].downloadtaskid`), `GET /api/v1/downloadfilehandle?id=<taskid>` until `vals[0].filename` is ready, then `GET /api/v1/downloadfile?id=<filename>` for the bytes.

The IPS security-log query also accepts the business filters `rule_name`, `level`, `action` and `xff` as query values; their exact device spellings are pending confirmation, while gid=1/page/size/timetype and the custom start/end window are unchanged.

The AO-002/AO-003/AO-004/AO-008 verification operations use SSH and the shell block in the adapter:

| Operation | Command summary |
|---|---|
| `fw_verify_process_restart` | Record `ps -ef` PIDs before/after a wait window, list `/trace/coredump`, and check `/trace/log/snort_die.log` for snort. Mapping: snort -> one process; vpp -> vpp-agent-init/vpp-agent/vpp. |
| `fw_verify_system_resource` | `free -m`, `/proc/loadavg`, `top -bn1` CPU line and `df -P -k`; optional second sample for memory/disk deltas. |
| `fw_verify_capture_storage` | `df -P -k /userdata`, `du -sk /userdata`, mount lines and `ls -ld /userdata /exdisk`; classifies with_disk/no_disk/exdisk/unknown. |
| `fw_capture_system_log` | Tail `/var/log/messages`, `/var/log/syslog` or `journalctl` and match the IPv4/IPv6 control-policy load keywords. |

For these SSH operations, credentials come from the runner credential env var (`FW_SSH_PASSWORD` by default for root), and raw command output stays in the runner result. IPS configuration/rule changes take effect immediately; existing sessions are not refreshed while new sessions use the new configuration.

The control-policy create/update payloads also carry `sec_obj_data`, the device security-profile reference list. An IPS entry uses `{profile_id, profile_name, model_name: "ips"}`. The runner accepts the raw list through `--sec-obj-data-json`/`--sec-obj-data-file`, or builds the same entry from `--ips-profile-id`/`--ips-profile-name`. Omitting all of them sends an empty list, which is the previous fixed template value.

## Validation

Run the adapter profile check together with the normal repository checks:

```bash
uv run ptm-atomic adapter fw_config_object
uv run ptm-atomic adapter fw_config_policy_route
uv run ptm-atomic adapter fw_config_ospfv2_global
uv run ptm-atomic adapter fw_delete_ospfv2_network
uv run ptm-atomic adapter fw_config_ospfv3_global
uv run ptm-atomic adapter fw_config_bfd_global
uv run ptm-atomic adapter fw_verify_ips_rule
uv run ptm-atomic adapter fw_config_ips_profile
uv run ptm-atomic adapter tg_config_interface
uv run --python 3.11 python scripts/validate_adapter_profiles.py
uv run --python 3.11 python scripts/security_gate_check.py
```

`ptm-atomic adapter <op_id>` is a read-only cache query. It requires the local cache to be synced to a repository version that includes both the atom `adapter_contract_ref` and the referenced `adapters/` profile file.
