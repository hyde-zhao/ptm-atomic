"""Device and run configuration for object-management cases.

Values are environment-overridable so the same case modules run against any
device without editing source. Credentials are injected via environment
variables at execution time and never stored here or in memory.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent  # .../ptm-atomic
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # .../ptm-auto (unused here)

# Target device
DEVICE_IP = os.environ.get("OBJECT_CASE_DEVICE", "<DUT_IP>")
BASE_URL = f"https://{DEVICE_IP}"

# Session files (independent of any existing 55.72 session)
SESSION_DIR = Path(os.environ.get("PTM_ATOMIC_STATE", str(Path.home() / ".local/state/ptm-atomic/ngfw")))
SESSION_FILE = SESSION_DIR / "session-63.json"
SSH_SESSION_FILE = SESSION_DIR / "session-root-63.json"

# Credential environment variables (web admin + SSH root are distinct accounts)
WEB_PASSWORD_ENV = "NGFW_PASSWORD"
ROOT_PASSWORD_ENV = "NGFW_ROOT_PASSWORD"

# Execution behaviour
EXECUTE = os.environ.get("OBJECT_CASE_EXECUTE", "") == "1"
VERIFY_TLS = os.environ.get("OBJECT_CASE_VERIFY_TLS", "") == "1"
TIMEOUT = float(os.environ.get("OBJECT_CASE_TIMEOUT", "20"))

# Unique name prefix for every object created by the cases (enables sweep)
PREFIX = "atc"

# etcd keys (vpp v1 config tree). Adjusted in one place if device probing
# reveals a different schema. Values are JSON blobs keyed by object name.
ETCD_IPV4_OBJECT = "/vnf-agent/vpp1/config/vpp/v1/ippool/{name}"
ETCD_IPV4_GROUP = "/vnf-agent/vpp1/config/vpp/v1/ipgroup/{name}"
ETCD_IPV6_OBJECT = "/vnf-agent/vpp1/config/vpp/v1/ip6pool/{name}"
ETCD_IPV6_GROUP = "/vnf-agent/vpp1/config/vpp/v1/ip6group/{name}"
ETCD_SERVICE = "/vnf-agent/vpp1/config/vpp/v1/servicepool/{name}"
ETCD_SERVICE_GROUP = "/vnf-agent/vpp1/config/vpp/v1/servicegroup/{name}"
ETCD_TIME = "/vnf-agent/vpp1/config/vpp/v1/timeobject/{name}"

# vppctl binary on the device
VPPCTL_BIN = "/opt/dbappsecurity/bin/vppctl"
