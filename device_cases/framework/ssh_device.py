"""SSH access to the NGFW device for etcd / vppctl data-plane checks."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


@dataclass
class ShellResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def contains(self, needle: str) -> bool:
        return needle in self.stdout or needle in self.stderr

    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


class SSHDevice:
    """Paramiko SSH client for root-shell commands (etcdctl / vppctl)."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 22,
        username: str = "root",
        password_env: str,
        timeout: float = 20.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password_env = password_env
        self.timeout = timeout

    def exec(self, command: str) -> ShellResult:
        import paramiko

        credential = os.environ.get(self.password_env) or ""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict[str, object] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if credential:
            connect_kwargs["password"] = credential
        client.connect(**connect_kwargs)
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            code = stdout.channel.recv_exit_status()
        finally:
            client.close()
        return ShellResult(
            exit_code=code,
            stdout=out.decode("utf-8", errors="replace"),
            stderr=err.decode("utf-8", errors="replace"),
        )

    def etcd_get(self, key: str) -> ShellResult:
        # etcd runs --client-cert-auth on DAS-OS: reach it over the TLS endpoint
        # (23790) with the device's client keypair + trusted CA. The client
        # cert CN is "root", so no --user is required. Paths confirmed by probing.
        return self.exec(
            "/opt/dbappsecurity/bin/etcdctl "
            "--endpoints=https://127.0.0.1:23790 "
            "--cacert=/appdata/etc/etcdcerts/ca.pem "
            "--cert=/appdata/etc/etcdcerts/etcd-client.pem "
            "--key=/appdata/etc/etcdcerts/etcd-client-key.pem "
            f"get --print-value-only {key}"
        )

    def vppctl(self, command: str) -> ShellResult:
        return self.exec(f"/opt/dbappsecurity/bin/vppctl {command}")
