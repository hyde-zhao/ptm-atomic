"""CR-060 / C-1：shell 族 op 的返回信封形状锁。

缺陷根因（现场 `exec-20260911-dut3-dual`）：
`_execute_shell_op` 等执行器在 payload 里**自建一层** ``"data"``，而 CLI 出口
``_to_run_envelope`` 会把 payload 剩余字段整体塞进 ``envelope["data"]``，于是
对外实际是 ``envelope.data.data.<key>``；但 atom 的 ``returns`` 声明的、以及
``op_mapper.resolve_step_refs`` 读取的都是**单层** ``envelope.data.<key>``。
后果：``${STEP-001.pid}`` 恒解析失败 → ``fw_kill_process`` 从未下发。
且 dry-run 构造返回的是顶层键 → **dry-run 验证通过、execute 失败**。

本文件把三件事锁死（改回去即红）：
  1. execute 信封里**没有**内层 ``data``；
  2. atom ``returns.data`` 声明的每个键都在 ``envelope["data"]`` 第一层且非空；
  3. dry-run 与 execute 同形（dry-run 提供的声明键也在第一层，不嵌套）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from atomic_ops.commands.run import _to_run_envelope  # noqa: E402
from atomic_ops.runner import security_zone, ssh  # noqa: E402

ATOMS_DIR = REPO_ROOT / "atoms" / "fw"

SESSION = Path("/nonexistent/session.json")

# ── 造数：满足各 op 解析/成功模式的最简 stdout ────────────────

L2FIB_STDOUT = "\n".join(
    [
        "some banner",
        "  Mac-Address  BD-Idx  If-Idx  BSN-ISN  Age(min)  static  filter  bvi  SYNC  Interface-Name",
        "  00:11:22:33:44:55  5  6  1  10  0  0  0  1  GigabitEthernet0/1",
        "L2FIB total/learned entries: 1/1",
        "Learn limit: 1024",
    ]
)

BD_COLUMNS = (
    ("BD-ID", "5"),
    ("Index", "6"),
    ("BSN", "1"),
    ("Age(min)", "12"),
    ("Learning", "1"),
    ("U-Forwrd", "1"),
    ("UU-Flood", "1"),
    ("Flooding", "1"),
    ("ARP-Term", "1"),
    ("arp-ufwd", "1"),
    ("BVI-Intf", "1"),
    ("HA-F", "0"),
)


def _fixed_width_table(columns: tuple[tuple[str, str], ...]) -> str:
    """按列标签的字符位置对齐生成表头 + 一行数据（网关按固定宽度切片解析）。"""
    header = ""
    line = ""
    for label, value in columns:
        start = max(len(header) + 2, len(line))
        header = header.ljust(start) + label
        line = line.ljust(start) + value
    return header + "\n" + line


BD_STDOUT = _fixed_width_table(BD_COLUMNS)

NEIGHBOR_STDOUT = "\n".join(
    [
        "Time  IP  Flags  Ethernet  Interface  Phase  ProbesNum  ProbesDen  NextProbe(S)  Age(S)",
        "1.0  10.0.0.1  S  00:11:22:33:44:55  GigabitEthernet0/1  stale  0  /3  1.0  2.0",
    ]
)

VERSION_STDOUT = "NGFW version v5.0 build 20260101"

SHELL_STDOUT = "arbitrary shell output 2249"

DNS_STDOUT = "64 bytes from 110.242.68.66: icmp_seq=1 ttl=52 time=12.3 ms"

VPP_ZONE_STDOUT = "Name  Idx  Interface\ntrust-zone  0  port1"

# 2026-09-21 DUT3 实测输出形态（ipv4 的 policy-id:1 与 ipv6 的 policy-id:10001 并存）
ABF_POLICY_STDOUT = "\n".join(
    [
        "abf:[98]: policy-id:10001 acl:10001, action 1, priority:1, sign:7047901162892520286",
        "     path-list:[61] locks:1 flags:shared,no-uRPF, uRPF-list: None",
        "      path:[61] pl-index:61 ip6 weight=12 pref=0 recursive: ",
        "        via 2001::1 in fib:0 via-fib:55 via-dpo:[dpo-load-balance:56]",
        "abf:[99]: policy-id:1 acl:1, action 1, priority:1, sign:9515504089035501768",
        "     path-list:[18] locks:1 flags:shared,no-uRPF, uRPF-list: None",
        "      path:[32] pl-index:18 ip4 weight=123 pref=0 recursive: ",
        "        via 1.1.1.1 in fib:0 via-fib:10 via-dpo:[dpo-load-balance:12]",
        "",
        "add_counts 1182 0",
        "del_counts 1180 0",
        "max time(s) .024 .002 0.000 .002",
        "ip4 rules count: 2 ip6 rules count: 2",
    ]
)


def _fake_shell(stdout: str):
    return SimpleNamespace(exit_code=0, stdout=stdout, stderr="")


def _atom_returns_data_keys(op_id: str) -> set[str]:
    atom_path = ATOMS_DIR / f"{op_id}.yaml"
    if not atom_path.is_file():
        raise AssertionError(f"缺少 atom 契约文件：{atom_path}")
    doc = yaml.safe_load(atom_path.read_text(encoding="utf-8"))
    returns = doc.get("returns")
    if not isinstance(returns, dict) or not isinstance(returns.get("data"), dict):
        raise AssertionError(f"{op_id} 的 returns.data 不是映射")
    return set(returns["data"])


# ── op 表：(op_id, execute 函数名, dry_run 函数名或 None, 额外 kwargs, stdout) ──

_SHELL_KWARGS = dict(
    base_url="https://192.0.2.1",
    session_file=SESSION,
    transport="ssh",
    host=None,
    port=None,
    credential_env="FW_SSH_PASSWORD",
    timeout=10.0,
)

OPS = (
    (
        "fw_verify_system_version",
        "execute_verify_system_version",
        "build_verify_system_version_dry_run",
        {**_SHELL_KWARGS, "expected_version": "v5.0"},
        VERSION_STDOUT,
    ),
    (
        "fw_check_bvi_interface_config",
        "execute_check_bvi_interface_config",
        "build_check_bvi_interface_config_dry_run",
        {**_SHELL_KWARGS, "bvi_id": 1},
        SHELL_STDOUT,
    ),
    (
        "fw_check_bridge_domain",
        "execute_check_bridge_domain",
        "build_check_bridge_domain_dry_run",
        {**_SHELL_KWARGS},
        BD_STDOUT,
    ),
    (
        "fw_verify_l2fib",
        "execute_verify_l2fib",
        "build_verify_l2fib_dry_run",
        {**_SHELL_KWARGS},
        L2FIB_STDOUT,
    ),
    (
        "fw_verify_bridge_domain_mac_age",
        "execute_verify_bridge_domain_mac_age",
        "build_verify_bridge_domain_mac_age_dry_run",
        {**_SHELL_KWARGS, "username": "root", "bridge_domain_id": 5},
        BD_STDOUT,
    ),
    (
        "fw_config_bridge_domain_mac_age",
        "execute_config_bridge_domain_mac_age",
        "build_config_bridge_domain_mac_age_dry_run",
        {**_SHELL_KWARGS, "username": "root", "bridge_domain_id": 5, "age_minutes": 12},
        BD_STDOUT,
    ),
    (
        "fw_verify_process_state",
        "execute_verify_process_state",
        "build_verify_process_state_dry_run",
        {**_SHELL_KWARGS, "process": "vpp"},
        SHELL_STDOUT,
    ),
    (
        "fw_kill_process",
        "execute_kill_process",
        "build_kill_process_dry_run",
        {**_SHELL_KWARGS, "process": "vpp", "pid": "2249"},
        "",
    ),
    (
        "fw_config_dns_diag",
        "execute_dns_diag",
        "build_dns_diag_dry_run",
        {**_SHELL_KWARGS, "domain": "www.baidu.com", "mode": "ping"},
        DNS_STDOUT,
    ),
    (
        "fw_verify_neighbor_probe",
        "execute_verify_neighbor_probe",
        "build_verify_neighbor_probe_dry_run",
        {
            **_SHELL_KWARGS,
            "expected_ip": "10.0.0.1",
            "expected_interface": "GigabitEthernet0/1",
            "expected_phase": "stale",
        },
        NEIGHBOR_STDOUT,
    ),
    (
        "fw_verify_abf_policy",
        "execute_verify_abf_policy",
        "build_verify_abf_policy_dry_run",
        {**_SHELL_KWARGS, "username": "root", "policy_route_id": 1, "policy_type": "ipv4"},
        ABF_POLICY_STDOUT,
    ),
)

OPS_WITHOUT_DRY_RUN = ("fw_verify_security_zone_vpp",)


class _ShellHarness(unittest.TestCase):
    """把 ssh 族的传输层原语替换为造数 stdout。"""

    def _patch_stack(self, stdout: str):
        return (
            patch.object(ssh, "read_session_file", return_value={"username": "admin"}),
            patch.object(ssh, "_read_credential_env", return_value="secret"),
            patch.object(ssh, "_run_shell_command", return_value=_fake_shell(stdout)),
            # l2fib 走交互式 cli 会话（tgfw-cli），与一次性 exec 是两个原语
            patch.object(ssh, "_run_cli_session_command", return_value=_fake_shell(stdout)),
            # 成功模式判定由各 op 自带的解析断言（如“无数据行即 STATE_MISMATCH”）覆盖，
            # 此处只关心信封形状，故直接放行。
            patch.object(ssh, "evaluate_success", return_value=True),
            patch.object(ssh, "_shell_output_succeeded", return_value=True),
        )

    def _execute(self, op_id: str, func_name: str, kwargs: dict, stdout: str) -> dict:
        import contextlib

        with contextlib.ExitStack() as stack:
            for patcher in self._patch_stack(stdout):
                stack.enter_context(patcher)
            return getattr(ssh, func_name)(**kwargs)

    def _dry_run(self, func_name: str, kwargs: dict) -> dict:
        dry_kwargs = {k: v for k, v in kwargs.items() if k != "credential_env"}
        import contextlib

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(ssh, "read_session_file", return_value={"username": "admin"})
            )
            return getattr(ssh, func_name)(**dry_kwargs)


class ShellOpEnvelopeShapeTests(_ShellHarness):
    """execute 信封：无内层 data，且 atom 声明的键全在第一层。"""

    def test_execute_envelope_has_no_nested_data(self) -> None:
        for op_id, func_name, _dry, kwargs, stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._execute(op_id, func_name, kwargs, stdout))
                self.assertNotIn(
                    "data",
                    envelope["data"],
                    f"{op_id} 又出现了内层 data（envelope.data.data.* 就是 C-1 根因）",
                )

    def test_execute_envelope_exposes_all_declared_return_keys(self) -> None:
        for op_id, func_name, _dry, kwargs, stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._execute(op_id, func_name, kwargs, stdout))
                declared = _atom_returns_data_keys(op_id)
                missing = sorted(declared - set(envelope["data"]))
                self.assertEqual(
                    missing,
                    [],
                    f"{op_id} 未产出 atom returns.data 声明的键：{missing}",
                )

    def test_execute_declared_keys_are_truthy(self) -> None:
        """声明键不能只“存在”却是 None/空 —— ${STEP.n.<field>} 对空值同样判失败。"""
        for op_id, func_name, _dry, kwargs, stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._execute(op_id, func_name, kwargs, stdout))
                for key in sorted(_atom_returns_data_keys(op_id)):
                    value = envelope["data"][key]
                    if isinstance(value, bool):
                        continue  # False 是合法取值（matches_expected / verify_match）
                    self.assertNotIn(
                        value,
                        (None, "", 0),
                        f"{op_id}.{key} 为空值，step 引用仍会解析失败",
                    )


class ShellOpDryRunShapeTests(_ShellHarness):
    """dry-run 与 execute 同形：同样不得内层嵌套，声明键同样在第一层。"""

    def test_dry_run_envelope_has_no_nested_data(self) -> None:
        for op_id, _execute_name, dry_name, kwargs, _stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._dry_run(dry_name, kwargs))
                self.assertNotIn("data", envelope["data"], op_id)

    def test_dry_run_declared_keys_are_top_level(self) -> None:
        """dry-run 能给的声明键必须在第一层（与 execute 同形）。

        不要求全部 —— 读取类 op 的 dry-run 天然拿不到执行结果（如 l2fib_entries）。
        """
        for op_id, _execute_name, dry_name, kwargs, _stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._dry_run(dry_name, kwargs))
                declared = _atom_returns_data_keys(op_id)
                present = declared & set(envelope["data"])
                # 断言的是“不嵌套”：present 里的键都已经在第一层被取到。
                self.assertEqual(
                    sorted(present),
                    sorted(k for k in declared if k in envelope["data"]),
                )
                for key in sorted(present):
                    self.assertNotIn(
                        key, envelope["data"].get("data", {}),
                        f"{op_id}.{key} 被塞进了内层 data",
                    )


class SecurityZoneVppEnvelopeShapeTests(unittest.TestCase):
    """`fw_verify_security_zone_vpp` 走 paramiko 直连，单独造数。"""

    class _FakeStdout:
        def __init__(self, text: str) -> None:
            self._text = text

        def read(self) -> bytes:
            return self._text.encode("utf-8")

    class _FakeClient:
        def __init__(self, stdout_text: str) -> None:
            self._stdout_text = stdout_text

        def set_missing_host_key_policy(self, _policy) -> None:
            pass

        def connect(self, **_kwargs) -> None:
            pass

        def exec_command(self, _cmd, timeout=None):
            empty = SecurityZoneVppEnvelopeShapeTests._Empty()
            return empty, SecurityZoneVppEnvelopeShapeTests._FakeStdout(
                self._stdout_text
            ), empty

        def close(self) -> None:
            pass

    class _Empty:
        def read(self) -> bytes:
            return b""

    def _execute(self) -> dict:
        with patch(
            "paramiko.SSHClient",
            side_effect=lambda: SecurityZoneVppEnvelopeShapeTests._FakeClient(
                VPP_ZONE_STDOUT
            ),
        ):
            return security_zone.execute_vpp_verify(
                ssh_host="192.0.2.1",
                ssh_user="root",
                ssh_password="secret",
                zone_name="trust-zone",
                expected_interfaces=["port1"],
            )

    def test_envelope_shape(self) -> None:
        envelope = _to_run_envelope(self._execute())
        self.assertNotIn("data", envelope["data"])
        declared = _atom_returns_data_keys("fw_verify_security_zone_vpp")
        self.assertEqual(sorted(declared - set(envelope["data"])), [])
        self.assertEqual(envelope["data"]["zone_name"], "trust-zone")
        self.assertEqual(envelope["data"]["interfaces_found"], ["port1"])


class StepRefResolutionTests(_ShellHarness):
    """端到端契约：`op_mapper.resolve_step_refs` 读的就是 `envelope["data"][field]`。

    修好之前这里是 `envelope["data"]["data"]["pid"]` → 取不到 → 抛
    “字段 'pid' 在被引 step 中不存在” → `fw_kill_process` 步骤从未下发。
    """

    @staticmethod
    def _resolve_like_op_mapper(envelope: dict, field: str):
        """复刻 op_mapper.resolve_step_refs 的字段分支读取路径（单层 data）。"""
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
        value = data.get(field)
        if value in (None, "", 0):
            raise ValueError(f"字段 '{field}' 在被引 step 中不存在")
        return value

    def test_pid_resolves_for_kill_process(self) -> None:
        envelope = _to_run_envelope(
            self._execute(
                "fw_verify_process_state",
                "execute_verify_process_state",
                {**_SHELL_KWARGS, "process": "vpp"},
                "2249",
            )
        )
        self.assertEqual(self._resolve_like_op_mapper(envelope, "pid"), "2249")
        self.assertIs(self._resolve_like_op_mapper(envelope, "running"), True)
        self.assertEqual(self._resolve_like_op_mapper(envelope, "process"), "vpp")

    def test_all_declared_fields_resolve_for_every_op(self) -> None:
        """把 6 个曾经恒失败的字段逐个走一遍真实解析路径。"""
        for op_id, func_name, _dry, kwargs, stdout in OPS:
            with self.subTest(op_id=op_id):
                envelope = _to_run_envelope(self._execute(op_id, func_name, kwargs, stdout))
                for field in sorted(_atom_returns_data_keys(op_id)):
                    self._resolve_like_op_mapper(envelope, field)


if __name__ == "__main__":
    unittest.main()
