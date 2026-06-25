"""Read-only access to the local atomic operation repository cache."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from atomic_ops.metadata import (
    ERROR_REPO_NOT_SYNCED,
    STATUS_STALE,
    MetadataError,
    read_metadata,
    redact_sensitive,
    resolve_cache_root,
)
from atomic_ops.rollback import rollback_summary


ERROR_OP_NOT_FOUND = "OP_NOT_FOUND"
ERROR_PACKAGE_NOT_FOUND = "PACKAGE_NOT_FOUND"
ERROR_RUNNER_UNSUPPORTED_OP = "RUNNER_UNSUPPORTED_OP"
ERROR_RUNNER_EXECUTE_REQUIRED = "RUNNER_EXECUTE_REQUIRED"
ERROR_RUNNER_CREDENTIAL_MISSING = "RUNNER_CREDENTIAL_MISSING"
ERROR_RUNNER_LOGIN_FAILED = "RUNNER_LOGIN_FAILED"
ERROR_RUNNER_SESSION_INVALID = "RUNNER_SESSION_INVALID"
ERROR_RUNNER_DEVICE_UNREACHABLE = "RUNNER_DEVICE_UNREACHABLE"
ERROR_RUNNER_RESPONSE_INVALID = "RUNNER_RESPONSE_INVALID"
ERROR_RUNNER_CONFIG_REJECTED = "RUNNER_CONFIG_REJECTED"
ERROR_RUNNER_VALIDATION_FAILED = "RUNNER_VALIDATION_FAILED"

EXIT_CODES = {
    ERROR_OP_NOT_FOUND: 23,
    ERROR_REPO_NOT_SYNCED: 24,
    ERROR_PACKAGE_NOT_FOUND: 25,
    ERROR_RUNNER_UNSUPPORTED_OP: 41,
    ERROR_RUNNER_EXECUTE_REQUIRED: 42,
    ERROR_RUNNER_CREDENTIAL_MISSING: 43,
    ERROR_RUNNER_LOGIN_FAILED: 44,
    ERROR_RUNNER_SESSION_INVALID: 45,
    ERROR_RUNNER_DEVICE_UNREACHABLE: 46,
    ERROR_RUNNER_RESPONSE_INVALID: 47,
    ERROR_RUNNER_CONFIG_REJECTED: 48,
    ERROR_RUNNER_VALIDATION_FAILED: 49,
}

SUPPORTED_DEVICES = ("fw", "tg", "mock", "sw")


@dataclass(frozen=True)
class ReadError(Exception):
    """A CLI-level read failure with a fixed error code."""

    error_code: str
    message: str
    details: dict[str, Any]
    retryable: bool = False

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class OperationSummary:
    op_id: str
    description: str
    idempotent: bool
    device_type: str
    since_version: str | None
    tags: list[str]
    parameters_summary: list[dict[str, Any]]
    aliases: list[str]
    side_effect: str | None
    rollback_strategy: dict[str, Any] | None
    pre_snapshot: dict[str, Any] | None
    post_verify: dict[str, Any] | None
    dry_run_supported: bool | None
    risk_level: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationDocument:
    path: Path
    data: dict[str, Any]
    raw_text: str


@dataclass(frozen=True)
class AdapterOperationDocument:
    op_id: str
    adapter_contract_ref: str
    profile_path: str
    operation_id: str
    operation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PackageManifest:
    package_id: str
    display_name: str
    description: str
    version: str
    operations: tuple[str, ...]


@dataclass(frozen=True)
class PackageSummary:
    package_id: str
    display_name: str
    description: str
    version: str
    operation_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Repository:
    """Consume atoms and package manifests from a synced local cache."""

    def __init__(self, cache_root: Path, metadata: dict[str, Any]) -> None:
        self.cache_root = cache_root
        self.metadata = metadata
        self.atoms_root = cache_root / "atoms"
        self.packages_root = cache_root / "packages"
        self.adapters_root = cache_root / "adapters"

    @classmethod
    def from_default_cache(cls) -> "Repository":
        cache_root = resolve_cache_root()
        try:
            metadata = read_metadata(cache_root)
        except MetadataError as exc:
            raise _repo_not_synced(str(exc), cache_root=cache_root) from exc

        repo = cls(cache_root, metadata)
        repo._ensure_cache_complete()
        return repo

    @property
    def is_stale(self) -> bool:
        return self.metadata.get("last_sync_status") == STATUS_STALE

    def metadata_summary(self) -> dict[str, Any]:
        return redact_sensitive(
            {
                "ref_mode": self.metadata.get("ref_mode"),
                "current_ref": self.metadata.get("current_ref"),
                "commit_sha": self.metadata.get("commit_sha"),
                "last_sync_status": self.metadata.get("last_sync_status"),
            }
        )

    def list_operations(self, device: str | None = None) -> list[OperationSummary]:
        devices = (device,) if device in SUPPORTED_DEVICES else SUPPORTED_DEVICES
        operations: list[OperationSummary] = []
        for device_type in devices:
            device_root = self.atoms_root / device_type
            if not device_root.is_dir():
                continue
            for path in sorted(device_root.glob("*.yaml")):
                operations.append(self._operation_summary_from_path(path, device_type))
        return sorted(operations, key=lambda item: item.op_id)

    def list_package_operations(
        self,
        package_name: str,
        *,
        device: str | None = None,
    ) -> tuple[list[OperationSummary], int]:
        manifest = self.read_package(package_name)
        allowed_device = device if device in SUPPORTED_DEVICES else None
        operations: list[OperationSummary] = []
        missing_count = 0

        for op_id in manifest.operations:
            op_device = _device_from_op_id(op_id)
            if allowed_device is not None and op_device != allowed_device:
                continue
            if op_device is None:
                missing_count += 1
                continue
            path = self._operation_path(op_id)
            if path is None or not path.is_file():
                missing_count += 1
                continue
            operations.append(self._operation_summary_from_path(path, op_device))

        return sorted(operations, key=lambda item: item.op_id), missing_count

    def read_operation(self, op_id: str) -> OperationDocument:
        path = self._operation_path(op_id)
        if path is None or not path.is_file():
            raise ReadError(
                ERROR_OP_NOT_FOUND,
                f"Operation not found: {op_id}",
                {"op_id": op_id},
            )
        data, raw_text = self._read_yaml_document(path)
        if not isinstance(data, dict):
            raise _repo_not_synced("operation YAML root must be an object", cache_root=self.cache_root)
        expected_device = _device_from_op_id(op_id)
        if data.get("op_id") != op_id:
            raise _repo_not_synced(
                f"operation op_id does not match requested path: {op_id}",
                cache_root=self.cache_root,
            )
        if expected_device and data.get("device_type") != expected_device:
            raise _repo_not_synced(
                f"operation device_type does not match path prefix: {op_id}",
                cache_root=self.cache_root,
            )
        return OperationDocument(path=path, data=data, raw_text=raw_text)

    def read_adapter_operation(self, op_id: str) -> AdapterOperationDocument:
        operation_document = self.read_operation(op_id)
        adapter_ref = operation_document.data.get("adapter_contract_ref")
        if not isinstance(adapter_ref, str) or not adapter_ref.strip():
            raise ReadError(
                ERROR_OP_NOT_FOUND,
                f"Adapter profile not found for operation: {op_id}",
                {"op_id": op_id, "missing_field": "adapter_contract_ref"},
            )

        profile_part, operation_id = _parse_adapter_ref(adapter_ref)
        profile_path = self._adapter_profile_path(profile_part)
        if profile_path is None or not profile_path.is_file():
            raise _repo_not_synced(
                f"adapter profile referenced by {op_id} is missing: {profile_part}",
                cache_root=self.cache_root,
            )

        profile, _raw_text = self._read_yaml_document(profile_path)
        if not isinstance(profile, dict):
            raise _repo_not_synced("adapter profile YAML root must be an object", cache_root=self.cache_root)
        operations = profile.get("operations")
        if not isinstance(operations, dict):
            raise _repo_not_synced(
                f"adapter profile operations must be an object: {profile_part}",
                cache_root=self.cache_root,
            )
        adapter_operation = operations.get(operation_id)
        if not isinstance(adapter_operation, dict):
            raise _repo_not_synced(
                f"adapter operation referenced by {op_id} is missing: {adapter_ref}",
                cache_root=self.cache_root,
            )
        atom_ref = adapter_operation.get("atom_ref")
        expected_atom_ref = _display_cache_relative_path(operation_document.path, self.cache_root)
        if atom_ref != expected_atom_ref:
            raise _repo_not_synced(
                f"adapter operation atom_ref does not match requested operation: {adapter_ref}",
                cache_root=self.cache_root,
            )

        return AdapterOperationDocument(
            op_id=op_id,
            adapter_contract_ref=adapter_ref,
            profile_path=profile_part,
            operation_id=operation_id,
            operation=adapter_operation,
        )

    def read_package(self, package_name: str) -> PackageManifest:
        path = self._package_path(package_name)
        if path is None or not path.is_file():
            raise ReadError(
                ERROR_PACKAGE_NOT_FOUND,
                f"Package not found: {package_name}",
                {
                    "package_id": package_name,
                    "available_packages": self.available_package_ids(),
                },
            )
        data, _raw_text = self._read_yaml_document(path)
        return self._package_manifest_from_data(path, data)

    def list_packages(self) -> list[PackageSummary]:
        packages: list[PackageSummary] = []
        for path in sorted(self.packages_root.glob("*.yaml")):
            data, _raw_text = self._read_yaml_document(path)
            manifest = self._package_manifest_from_data(path, data)
            packages.append(
                PackageSummary(
                    package_id=manifest.package_id,
                    display_name=manifest.display_name,
                    description=manifest.description,
                    version=manifest.version,
                    operation_count=len(manifest.operations),
                )
            )
        return sorted(packages, key=lambda item: item.package_id)

    def available_package_ids(self) -> list[str]:
        if not self.packages_root.is_dir():
            return []
        return sorted(path.stem for path in self.packages_root.glob("*.yaml") if path.is_file())

    def _ensure_cache_complete(self) -> None:
        missing = [
            name
            for name, path in (("atoms", self.atoms_root), ("packages", self.packages_root))
            if not path.is_dir()
        ]
        for device in SUPPORTED_DEVICES:
            device_root = self.atoms_root / device
            if self.atoms_root.is_dir() and not device_root.is_dir():
                missing.append(f"atoms/{device}")
        if missing:
            raise _repo_not_synced(
                f"cache is incomplete; missing: {', '.join(missing)}",
                cache_root=self.cache_root,
            )

    def _operation_path(self, op_id: str) -> Path | None:
        device = _device_from_op_id(op_id)
        if device is None:
            return None
        return self.atoms_root / device / f"{op_id}.yaml"

    def _package_path(self, package_name: str) -> Path | None:
        if _has_path_separator(package_name) or package_name in {"", ".", ".."}:
            return None
        if ".." in Path(package_name).parts:
            return None
        return self.packages_root / f"{package_name}.yaml"

    def _adapter_profile_path(self, profile_part: str) -> Path | None:
        if _has_path_separator(profile_part.replace("/", "")) or profile_part in {"", ".", ".."}:
            return None
        path = Path(profile_part)
        parts = path.parts
        if not parts or parts[0] != "adapters" or ".." in parts or path.is_absolute():
            return None
        if path.suffix.lower() not in {".yaml", ".yml"}:
            return None
        resolved = (self.cache_root / path).resolve()
        try:
            resolved.relative_to(self.adapters_root.resolve())
        except ValueError:
            return None
        return resolved

    def _operation_summary_from_path(self, path: Path, expected_device: str) -> OperationSummary:
        data, _raw_text = self._read_yaml_document(path)
        if not isinstance(data, dict):
            raise _repo_not_synced("operation YAML root must be an object", cache_root=self.cache_root)
        op_id = _string_field(data, "op_id")
        device_type = _string_field(data, "device_type")
        if not op_id or not device_type:
            raise _repo_not_synced(
                f"operation YAML missing op_id or device_type: {path}",
                cache_root=self.cache_root,
            )
        if device_type != expected_device or _device_from_op_id(op_id) != expected_device:
            raise _repo_not_synced(
                f"operation path, op_id, and device_type are inconsistent: {path}",
                cache_root=self.cache_root,
            )
        rollback = rollback_summary(data)
        return OperationSummary(
            op_id=op_id,
            description=_string_field(data, "description"),
            idempotent=bool(data.get("idempotent", False)),
            device_type=device_type,
            since_version=_optional_string_field(data, "since_version"),
            tags=_tags_field(data, "tags"),
            parameters_summary=_parameters_summary(data.get("parameters")),
            aliases=_tags_field(data, "aliases"),
            side_effect=rollback["side_effect"],
            rollback_strategy=rollback["rollback_strategy"],
            pre_snapshot=rollback["pre_snapshot"],
            post_verify=rollback["post_verify"],
            dry_run_supported=rollback["dry_run_supported"],
            risk_level=rollback["risk_level"],
        )

    def _package_manifest_from_data(self, path: Path, data: Any) -> PackageManifest:
        if not isinstance(data, dict):
            raise _repo_not_synced("package YAML root must be an object", cache_root=self.cache_root)
        package_id = _string_field(data, "package_id") or path.stem
        if package_id != path.stem:
            raise _repo_not_synced(
                f"package_id does not match filename: {path}",
                cache_root=self.cache_root,
            )
        operations = data.get("operations")
        if not isinstance(operations, list) or not all(isinstance(item, str) for item in operations):
            raise _repo_not_synced(
                f"package operations must be a list of op_id strings: {path}",
                cache_root=self.cache_root,
            )
        return PackageManifest(
            package_id=package_id,
            display_name=_string_field(data, "display_name") or package_id,
            description=_string_field(data, "description"),
            version=_string_field(data, "version"),
            operations=tuple(operations),
        )

    def _read_yaml_document(self, path: Path) -> tuple[Any, str]:
        try:
            raw_text = path.read_text(encoding="utf-8")
            return yaml.safe_load(raw_text), raw_text
        except (OSError, yaml.YAMLError) as exc:
            raise _repo_not_synced(f"cannot read local repository YAML {path}: {exc}", cache_root=self.cache_root) from exc


def _repo_not_synced(message: str, *, cache_root: Path) -> ReadError:
    return ReadError(
        ERROR_REPO_NOT_SYNCED,
        f"Local operation repository cache is missing, unreadable, or damaged: {redact_sensitive(message)}",
        {"cache_root": str(cache_root)},
        retryable=True,
    )


def _device_from_op_id(op_id: str) -> str | None:
    if not op_id or _has_path_separator(op_id) or op_id in {".", ".."}:
        return None
    if ".." in Path(op_id).parts:
        return None
    prefix = op_id.split("_", 1)[0]
    if prefix not in SUPPORTED_DEVICES:
        return None
    return prefix


def _has_path_separator(value: str) -> bool:
    return "/" in value or "\\" in value


def _parse_adapter_ref(adapter_ref: str) -> tuple[str, str]:
    marker = "#/operations/"
    if marker not in adapter_ref:
        raise ReadError(
            ERROR_OP_NOT_FOUND,
            "Adapter profile reference must point to an operation.",
            {"adapter_contract_ref": adapter_ref},
        )
    profile_part, operation_id = adapter_ref.split(marker, 1)
    if (
        not profile_part
        or not operation_id
        or "\\" in profile_part
        or "/" in operation_id
        or "\\" in operation_id
        or ".." in Path(profile_part).parts
    ):
        raise ReadError(
            ERROR_OP_NOT_FOUND,
            "Adapter profile reference is invalid.",
            {"adapter_contract_ref": adapter_ref},
        )
    return profile_part, operation_id


def _display_cache_relative_path(path: Path, cache_root: Path) -> str:
    try:
        return path.resolve().relative_to(cache_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _string_field(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""


def _optional_string_field(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) else None


def _tags_field(data: dict[str, Any], key: str) -> list[str]:
    """从 YAML 数据中提取 tags 列表，缺失或类型不符时返回空列表。"""
    value = data.get(key)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _parameters_summary(parameters: Any) -> list[dict[str, Any]]:
    """从 YAML parameters 节点提取参数摘要：名称、类型、是否必填。"""
    if not isinstance(parameters, dict):
        return []
    result: list[dict[str, Any]] = []
    for name, spec in parameters.items():
        if isinstance(spec, dict):
            result.append({
                "name": name,
                "type": spec.get("type", ""),
                "required": bool(spec.get("required", False)),
            })
    return result
