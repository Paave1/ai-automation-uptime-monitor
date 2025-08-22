#!/usr/bin/env python3
import base64
import json
import os
import sys
from pathlib import Path
from typing import Optional, Tuple
from urllib import request, error


def getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None and v != "" else default


def api_request(method: str, url: str, token: str, payload: Optional[dict] = None) -> Tuple[int, dict]:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "uptime-monitor-uploader",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.getcode(), (json.loads(body) if body else {})
    except error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else {}
        except Exception:
            parsed = {"message": body}
        return e.code, parsed


EXCLUDE_DIRS = {".git", ".venv", "venv", "__pycache__", ".idea", ".vscode"}
EXCLUDE_FILES = {".DS_Store", "uptime_log.csv"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".pyd", ".log"}


def should_exclude(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    if path.name in EXCLUDE_FILES:
        return True
    for suf in EXCLUDE_SUFFIXES:
        if path.name.endswith(suf):
            return True
    return False


def put_file(owner: str, repo: str, rel_path: str, abs_path: Path, token: str, message: str) -> None:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{request.pathname2url(rel_path)}"
    code, existing = api_request("GET", url, token)
    sha = existing.get("sha") if code == 200 else None
    content_b64 = base64.b64encode(abs_path.read_bytes()).decode("ascii")
    payload = {"message": message, "content": content_b64}
    if sha:
        payload["sha"] = sha
    code, resp = api_request("PUT", url, token, payload)
    if code not in (200, 201):
        raise RuntimeError(f"Failed to upload {rel_path}: {code} {resp}")


def ensure_repo(owner: str, repo: str, token: str, private: bool) -> None:
    code, _ = api_request("GET", f"https://api.github.com/repos/{owner}/{repo}", token)
    if code == 200:
        return
    if code != 404:
        raise RuntimeError(f"Unexpected status on repo lookup: {code}")
    payload = {"name": repo, "private": private}
    code, resp = api_request("POST", "https://api.github.com/user/repos", token, payload)
    if code not in (200, 201):
        raise RuntimeError(f"Failed to create repo: {code} {resp}")


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    token = getenv("GH_TOKEN")
    owner = getenv("GH_USERNAME") or getenv("GH_OWNER")
    repo = getenv("GH_REPO") or project_root.name
    is_private = getenv("GH_PRIVATE", "true").lower() in {"1", "true", "yes"}
    commit_message = getenv("GH_COMMIT_MESSAGE", "chore: initial import of uptime monitor")

    if not token or not owner:
        print("GH_TOKEN and GH_USERNAME (or GH_OWNER) are required", file=sys.stderr)
        return 2

    ensure_repo(owner, repo, token, is_private)

    for path in project_root.rglob("*"):
        if path.is_dir() or should_exclude(path):
            continue
        rel_path = str(path.relative_to(project_root)).replace("\\", "/")
        print(f"Uploading {rel_path}...")
        put_file(owner, repo, rel_path, path, token, commit_message)

    print(f"Done. Repo: https://github.com/{owner}/{repo}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


