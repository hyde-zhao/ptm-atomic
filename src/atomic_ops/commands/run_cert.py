"""Certificate runner commands (localcert-config/update/issue/delete/verify/delete-batch + localcacert-config/verify/delete-batch)."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
    _arg_list,
    _require_arg,
    _single_arg,
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="localcert-config",
            help="Create a local certificate.",
            description="Create an NGFW local certificate (RSA or SM2) through /api/v1/cert/localcert.",
            handler=_run_localcert_config,
            add_args=_add_localcert_args,
        ),
        CommandSpec(
            name="localcert-update",
            help="Update a local certificate definition.",
            description="Update an existing NGFW local certificate name/subject/option.",
            handler=_run_localcert_update,
            add_args=_add_localcert_update_args,
        ),
        CommandSpec(
            name="localcert-issue",
            help="Issue (sign) a local certificate.",
            description="Sign a pending NGFW local certificate through the /api/v1/cert/localcert PUT issue flow.",
            handler=_run_localcert_issue,
            add_args=_add_localcert_issue_args,
        ),
        CommandSpec(
            name="localcert-delete",
            help="Delete a local certificate.",
            description="Delete a single NGFW local certificate by numeric id (DELETE ?id=).",
            handler=_run_localcert_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="localcert-verify",
            help="Verify local certificates.",
            description="Query NGFW local certificates through /api/v1/cert/localcert.",
            handler=_run_localcert_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="localcert-delete-batch",
            help="Delete multiple local certificates.",
            description="Batch-delete NGFW local certificates by numeric id.",
            handler=_run_localcert_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="localcacert-config",
            help="Create a local CA certificate.",
            description="Create an NGFW self-signed local CA certificate through /api/v1/cert/localcacert.",
            handler=_run_localcacert_config,
            add_args=_add_localcacert_args,
        ),
        CommandSpec(
            name="localcacert-verify",
            help="Verify local CA certificates.",
            description="Query NGFW local CA certificates through /api/v1/cert/localcacert.",
            handler=_run_localcacert_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="localcacert-delete-batch",
            help="Delete multiple local CA certificates.",
            description="Batch-delete NGFW local CA certificates by numeric id.",
            handler=_run_localcacert_delete_batch,
            add_args=_add_delete_batch_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_subject_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--country", default="", help="Subject country field.")
    parser.add_argument("--state", default="", help="Subject state field.")
    parser.add_argument("--location", default="", help="Subject location field.")
    parser.add_argument("--organization", default="", help="Subject organization field.")
    parser.add_argument("--organ-unit", default="", help="Subject organizational unit field.")


def _add_localcert_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Local certificate name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--key-type", default="RSA", choices=["RSA", "SM2"], help="Certificate key algorithm.")
    parser.add_argument("--key-length", type=int, default=2048, help="RSA key length (ignored for SM2).")
    _add_subject_args(parser)
    _add_payload_args(parser)


def _add_localcert_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Local certificate numeric id to update. Required unless --payload-json/--payload-file is given.")
    _add_localcert_args(parser)


def _add_localcert_issue_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Local certificate numeric id to issue/sign.")
    parser.add_argument("--cacert", default="defaultLocalCA.crt", help="CA certificate file to sign with.")
    parser.add_argument("--option", default="1", help="Issue option value.")
    parser.add_argument("--time-length", type=int, default=30, help="Certificate validity length in days.")
    _add_payload_args(parser)


def _add_localcacert_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Local CA certificate name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--key-type", default="RSA", choices=["RSA", "SM2"], help="Certificate key algorithm.")
    parser.add_argument("--time-length", type=int, default=30, help="Certificate validity length in days.")
    _add_subject_args(parser)
    _add_payload_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Certificate numeric id to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Certificate numeric id to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Keyword filter for the query.")


def _run_localcert_config(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_config_localcert")


def _run_localcert_update(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_update_localcert")


def _run_localcert_issue(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_update_localcert", variant="issue")


def _run_localcert_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_cert(args, "fw_delete_localcert")


def _run_localcert_verify(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_verify_localcert")


def _run_localcert_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_cert(args, "fw_delete_batch_localcert")


def _run_localcacert_config(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_config_localcacert")


def _run_localcacert_verify(args: argparse.Namespace) -> int:
    return _run_cert(args, "fw_verify_localcacert")


def _run_localcacert_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_cert(args, "fw_delete_batch_localcacert")


def _run_cert(args: argparse.Namespace, op_id: str, *, variant: str | None = None) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.cert import (
        LOCALCACERT_RESOURCE,
        LOCALCERT_RESOURCE,
        build_cert_batch_delete_payload,
        build_cert_dry_run,
        build_localcacert_payload,
        build_localcert_issue_payload,
        build_localcert_payload,
        build_localcert_update_payload,
        execute_cert,
        validate_cert_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning(
                {"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."},
                output_format,
            )

        session_file = resolve_session_file(ctx.get("session_file"))
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 40))
        keywords = getattr(args, "keywords", "") or ""
        payload: dict[str, Any] | None

        if op_id in {"fw_config_localcert", "fw_update_localcert"}:
            if variant == "issue":
                raw_payload = load_json_payload(
                    payload_file=getattr(args, "payload_file", None),
                    payload_json=getattr(args, "payload_json", None),
                )
                if raw_payload is not None:
                    payload = raw_payload
                else:
                    _require_arg(args, "id")
                    payload = build_localcert_issue_payload(
                        entry_id=_single_arg(args, "id") or "",
                        cacert=getattr(args, "cacert", "defaultLocalCA.crt"),
                        option=getattr(args, "option", "1"),
                        time_length=int(getattr(args, "time_length", 30)),
                    )
            else:
                raw_payload = load_json_payload(
                    payload_file=getattr(args, "payload_file", None),
                    payload_json=getattr(args, "payload_json", None),
                )
                if raw_payload is not None:
                    payload = raw_payload
                else:
                    _require_arg(args, "name")
                    subject = _subject_from_args(args)
                    if op_id == "fw_config_localcert":
                        payload = build_localcert_payload(
                            name=getattr(args, "name"),
                            subject=subject,
                            key_type=getattr(args, "key_type", "RSA"),
                            key_length=int(getattr(args, "key_length", 2048)),
                        )
                    else:
                        _require_arg(args, "id")
                        payload = build_localcert_update_payload(
                            entry_id=_single_arg(args, "id") or "",
                            name=getattr(args, "name"),
                            subject=subject,
                            key_type=getattr(args, "key_type", "RSA"),
                            key_length=int(getattr(args, "key_length", 2048)),
                        )
        elif op_id == "fw_config_localcacert":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                payload = build_localcacert_payload(
                    name=getattr(args, "name"),
                    subject=_subject_from_args(args),
                    key_type=getattr(args, "key_type", "RSA"),
                    time_length=int(getattr(args, "time_length", 30)),
                )
        elif op_id == "fw_delete_localcert":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id in {"fw_delete_batch_localcert", "fw_delete_batch_localcacert"}:
            resource = LOCALCERT_RESOURCE if op_id == "fw_delete_batch_localcert" else LOCALCACERT_RESOURCE
            entry_ids = _arg_list(args, "id")
            payload = build_cert_batch_delete_payload(entry_ids=entry_ids, resource=resource)
            payload = validate_cert_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_cert_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_cert(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _subject_from_args(args: argparse.Namespace) -> dict[str, str]:
    return {
        "country": getattr(args, "country", "") or "",
        "state": getattr(args, "state", "") or "",
        "location": getattr(args, "location", "") or "",
        "organization": getattr(args, "organization", "") or "",
        "organUnit": getattr(args, "organ_unit", "") or "",
    }
