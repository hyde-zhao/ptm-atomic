"""Shared helpers for the file-type / file-type-group cases (1762xx/2640xx/900034).

Probe-confirmed device semantics (probe19c + c_176265 on 55.63):
  * Custom file type: POST /api/v1/appsec/filetype
    {id:0, val:{name, type:true, classify:[0], refcnt:0, description}}.
    Identity for update/delete is the NAME.
  * File type group: POST/PUT /api/v1/appsec/filetypeObj
    {id, val:{name, des, filetype:[{name, type}]}}. A CUSTOM member must carry
    type:true (type:false -> eRequestParam 文件类型列表格式错误); predefined
    members carry type:false.
  * Group delete is via POST /api/v1/batch, DELETE filetypeObj body {id:[name]}.
  * A custom file type referenced by a group cannot be deleted (400 eRequestParam
    文件类型已被引用); the group itself deletes freely (releases the reference).
  * The CLI exposes config/update/delete for the single object but NO verify op,
    so list/search (type=custom&keywords=) and refcnt reads go through
    FiletypeRest (raw HTTP, session token from ctx.session_file, never printed).
"""

from __future__ import annotations

import json
from typing import Any

import requests
import urllib3

urllib3.disable_warnings()

from framework.checks import Check, find_entries

FILETYPE_URL = "/api/v1/appsec/filetype"
GROUP_URL = "/api/v1/appsec/filetypeObj"


def entry_named(entries: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """First entry whose name matches ``name`` (case-insensitive)."""
    for e in entries:
        if str(e.get("name", "")).lower() == name.lower():
            return e
    return None


def refcnt_of(entry: dict[str, Any]) -> int:
    """Reference count of a file type entry (tolerates refcnt/refCnt/absent)."""
    v = entry.get("refcnt", entry.get("refCnt", 0))
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def refcnt_check(*, label: str, entry: dict[str, Any] | None, want: int) -> Check:
    """Build a Check asserting the entry's refcnt equals ``want``."""
    if entry is None:
        return Check(name=label, ok=False, detail="entry not found in list query")
    got = refcnt_of(entry)
    return Check(name=label, ok=got == want,
                 detail=f"refcnt={got} want={want} (name={entry.get('name')!r})")


class FiletypeRest:
    """Thin authenticated client for filetype endpoints not exposed via the CLI.

    Bulk create/delete (capacity cases) and single-object list/search (176246)
    and refcnt reads go through raw HTTP here — spawning a CLI subprocess per
    object would take minutes for the 256-object cases.
    """

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.base = f"https://{ctx.device}"
        self._sid: str | None = None
        self._verify = bool(getattr(ctx, "verify_tls", False))

    @property
    def sid(self) -> str:
        if self._sid is None:
            data = json.loads(self.ctx.session_file.read_text(encoding="utf-8"))
            self._sid = str(data["session_value"])
        return self._sid

    def _headers(self, json_body: bool) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.sid}"}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    # --- single file type -------------------------------------------------
    def create(self, name: str, description: str = "") -> requests.Response:
        val = {"name": name, "type": True, "classify": [0],
               "refcnt": 0, "description": description}
        return requests.post(f"{self.base}{FILETYPE_URL}",
                             headers=self._headers(True), json={"id": 0, "val": val},
                             verify=self._verify, timeout=30)

    def update(self, name: str, *, description: str = "", new_name: str | None = None) -> requests.Response:
        val = {"name": new_name or name, "type": True, "classify": [0],
               "refcnt": 0, "description": description}
        return requests.put(f"{self.base}{FILETYPE_URL}",
                            headers=self._headers(True), json={"id": name, "val": val},
                            verify=self._verify, timeout=30)

    def delete(self, name: str) -> requests.Response:
        return requests.delete(f"{self.base}{FILETYPE_URL}",
                               headers=self._headers(False), params={"id": name},
                               verify=self._verify, timeout=30)

    def list_entries(self, *, keywords: str = "", type_filter: str = "custom",
                     max_pages: int = 5, page_size: int = 100) -> list[dict[str, Any]]:
        """Single file type entries (discriminated by the ``classify`` field)."""
        seen: dict[str, dict[str, Any]] = {}
        for page in range(1, max_pages + 1):
            params: dict[str, Any] = {"page": page, "size": page_size}
            if type_filter:
                params["type"] = type_filter
            if keywords:
                params["keywords"] = keywords
            try:
                r = requests.get(f"{self.base}{FILETYPE_URL}",
                                 headers=self._headers(False), params=params,
                                 verify=self._verify, timeout=30)
            except requests.RequestException:
                break
            if r.status_code != 200:
                break
            try:
                body = r.json()
            except ValueError:
                break
            hits = find_entries(body, lambda e: isinstance(e, dict)
                                and "name" in e and "classify" in e)
            if not hits:
                break
            added = 0
            for e in hits:
                n = str(e.get("name", ""))
                if n and n not in seen:
                    seen[n] = e
                    added += 1
            if added < page_size:
                break
        return list(seen.values())

    # --- file type group --------------------------------------------------
    def post_group(self, name: str, *, members: list[str] | None = None,
                   des: str = "") -> requests.Response:
        val = {"name": name, "des": des,
               "filetype": [{"name": m, "type": True} for m in (members or [])]}
        return requests.post(f"{self.base}{GROUP_URL}",
                             headers=self._headers(True), json={"id": 0, "val": val},
                             verify=self._verify, timeout=30)

    def post_group_raw(self, val: dict[str, Any]) -> requests.Response:
        """POST an arbitrary group ``val`` (negative-path cases: empty object,
        over-length/illegal names, reserved IDMC- prefix)."""
        return requests.post(f"{self.base}{GROUP_URL}",
                             headers=self._headers(True), json={"id": 0, "val": val},
                             verify=self._verify, timeout=30)

    def create_group(self, name: str, *, members: list[str] | None = None,
                     des: str = "") -> requests.Response:
        return self.post_group(name, members=members, des=des)

    def update_group(self, name: str, *, members: list[str] | None = None,
                     des: str = "") -> requests.Response:
        val = {"name": name, "des": des,
               "filetype": [{"name": m, "type": True} for m in (members or [])]}
        return requests.put(f"{self.base}{GROUP_URL}",
                            headers=self._headers(True), json={"id": name, "val": val},
                            verify=self._verify, timeout=30)

    def delete_groups(self, names: list[str]) -> requests.Response:
        batch = [{"method": "DELETE", "resource": GROUP_URL,
                  "body": {"id": [n]}} for n in names if n]
        return requests.post(f"{self.base}/api/v1/batch", headers=self._headers(True),
                             json={"batch": batch}, verify=self._verify, timeout=30)

    def list_groups(self, *, keywords: str = "", page: int = 1,
                    size: int = 100, max_pages: int = 10) -> list[dict[str, Any]]:
        """File type group entries, paginated until a short page (by name, dedup)."""
        seen: dict[str, dict[str, Any]] = {}
        for p in range(page, page + max_pages):
            params: dict[str, Any] = {"page": p, "size": size}
            if keywords:
                params["keywords"] = keywords
            try:
                r = requests.get(f"{self.base}{GROUP_URL}", headers=self._headers(False),
                                 params=params, verify=self._verify, timeout=30)
            except requests.RequestException:
                break
            if r.status_code != 200:
                break
            try:
                body = r.json()
            except ValueError:
                break
            hits = find_entries(body, lambda e: isinstance(e, dict)
                                and "name" in e and "filetype" in e)
            if not hits:
                break
            added = 0
            for e in hits:
                n = str(e.get("name", ""))
                if n and n not in seen:
                    seen[n] = e
                    added += 1
            if added < size:
                break
        return list(seen.values())


def group_member_names(grp: dict[str, Any]) -> list[str]:
    members = grp.get("filetype")
    if not isinstance(members, list):
        return []
    return [str(m.get("name", "")) for m in members if isinstance(m, dict)]
