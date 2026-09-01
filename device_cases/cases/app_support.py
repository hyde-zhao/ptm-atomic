"""Shared helpers for the custom-application (自定义应用) cases.

Endpoint shapes confirmed on 55.63 (2026-09-01):

  GET    /api/v1/customappobj?page=&size=&keywords= -> {count, vals:[...]}
  POST   /api/v1/customappobj  {"val":{name_cn,name_en,pid,path,protocol,
         pattern_type,pattern,desc,customflag:true,tcpudpcfg}} -> {id} (string)
  PUT    /api/v1/customappobj?id=<name>  {"id":<name>,"val":{...}}
  DELETE /api/v1/customappobj?id=<name_cn>
  GET    /api/v1/appall -> {AppClass, AppGroup, AppStatic, AppCustom}
  POST   /api/v1/batch   批量删除

Custom apps live under a leaf app-class group (pid). ``APP_PID`` is the
device-validated 数字货币 group under 其他类 (same parent as the pre-existing
UI-automation objects app-001/uitest-app-002). The device requires ``path`` in
the POST val ("path is none in post val"), derived as 其他类/数字货币/<name>.

Predefined (preset) apps appear in /api/v1/appall AppStatic; the customappobj
endpoint rejects operations against them (see c_18243/c_18244).
"""

from __future__ import annotations

from typing import Any

from framework.context import CaseContext

APP_RES = "/api/v1/customappobj"
APPALL = "/api/v1/appall"
APP_PID = "268439771"  # 其他类/数字货币 (device-validated leaf group)
APP_PARENT = "其他类/数字货币"


def app_val(name: str, *, desc: str = "", customflag: bool = True, **over: Any) -> dict[str, Any]:
    """A valid custom-application ``val`` (overrides for invalid-variant probes)."""
    val: dict[str, Any] = {
        "name_cn": name,
        "name_en": name,
        "pid": APP_PID,
        "protocol": "TCP",
        "platform": "",
        "ip": "",
        "pattern_type": "Ascii",
        "pattern": f"atc-{name[-8:]}-sig",
        "desc": desc or "atc app",
        "customflag": customflag,
        "path": f"{APP_PARENT}/{name}",
        "tcpudpcfg": {"offset": "0", "port": "", "direct": "client"},
    }
    val.update(over)
    return val


def appall(ctx: CaseContext) -> dict[str, Any]:
    """Parsed /api/v1/appall response (AppClass/AppGroup/AppStatic/AppCustom)."""
    import requests  # noqa: PLC0415

    from cases.addr_cap_support import raw_headers  # noqa: PLC0415

    r = requests.get(f"{ctx.base_url}{APPALL}", headers=raw_headers(ctx),
                     verify=bool(ctx.verify_tls), timeout=30)
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {}
    return body if isinstance(body, dict) else {}


def app_find(ctx: CaseContext, name: str) -> dict[str, Any] | None:
    """The custom-app entry whose name_cn equals ``name`` (keywords filtered)."""
    import requests  # noqa: PLC0415

    from cases.addr_cap_support import raw_headers  # noqa: PLC0415

    url = f"{ctx.base_url}{APP_RES}?page=1&size=200&keywords={name}"
    r = requests.get(url, headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=30)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return next((e for e in vals if isinstance(e, dict)
                 and str(e.get("name_cn", "")) == name), None)


def preset_app_names(response: dict[str, Any]) -> list[str]:
    """Every name_cn in the /appall AppStatic (predefined apps) list."""
    static = response.get("AppStatic") or []
    names = []
    for entry in static:
        if isinstance(entry, dict) and isinstance(entry.get("name_cn"), str):
            names.append(entry["name_cn"])
    return names
