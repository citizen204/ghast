"""Scan workflows straight out of GitHub repositories.

Finding one bug in your own repository is a chore.  Finding the same class of
bug across a few hundred popular repositories is a research project, and it is
the reason this mode exists: point it at a list of repositories, get back a
triage table ordered by how exploitable each finding is.

Everything here is read-only and uses the `gh` CLI so it inherits the user's
existing authentication and rate limit.  Nothing is written to any repository.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import model, taint
from .findings import Finding
from .rules import Context, run_all
from .scan import ScanResult


class GhError(RuntimeError):
    pass


def _gh(args: Sequence[str], timeout: int = 45) -> str:
    try:
        proc = subprocess.run(
            ["gh"] + list(args),
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        raise GhError("the `gh` CLI is required for hunt mode; install it from https://cli.github.com")
    except subprocess.TimeoutExpired:
        raise GhError("gh timed out running: gh {}".format(" ".join(args)))
    if proc.returncode != 0:
        raise GhError((proc.stderr or proc.stdout or "gh failed").strip().splitlines()[0])
    return proc.stdout


@dataclass
class RepoResult:
    repo: str
    findings: List[Finding] = field(default_factory=list)
    workflows: List[model.Workflow] = field(default_factory=list)
    files: int = 0
    error: Optional[str] = None

    @property
    def top_score(self) -> float:
        return max((f.score for f in self.findings), default=0.0)


def list_workflow_files(repo: str, ref: Optional[str] = None) -> List[Dict[str, str]]:
    path = "repos/{}/contents/.github/workflows".format(repo)
    if ref:
        path += "?ref=" + ref
    raw = _gh(["api", path])
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        raise GhError("unexpected response listing {}".format(repo))
    if not isinstance(entries, list):
        raise GhError("no workflow directory in {}".format(repo))
    return [
        {"name": e["name"], "path": e["path"]}
        for e in entries
        if e.get("type") == "file" and str(e.get("name", "")).endswith((".yml", ".yaml"))
    ]


def fetch_file(repo: str, path: str, ref: Optional[str] = None) -> str:
    api = "repos/{}/contents/{}".format(repo, path)
    if ref:
        api += "?ref=" + ref
    raw = _gh(["api", api])
    payload = json.loads(raw)
    content = payload.get("content") or ""
    if payload.get("encoding") == "base64":
        return base64.b64decode(content).decode("utf-8", errors="replace")
    return content


def scan_repo(repo: str, ref: Optional[str] = None,
              max_files: int = 60) -> RepoResult:
    result = RepoResult(repo=repo)
    try:
        entries = list_workflow_files(repo, ref)
    except GhError as exc:
        result.error = str(exc)
        return result
    for entry in entries[:max_files]:
        try:
            text = fetch_file(repo, entry["path"], ref)
        except (GhError, ValueError) as exc:
            result.error = str(exc)
            continue
        workflow = model.parse_text(text, "{}:{}".format(repo, entry["path"]))
        result.files += 1
        result.workflows.append(workflow)
        if workflow.parse_error or not workflow.jobs:
            continue
        engine = taint.analyse(workflow)
        ctx = Context(workflow=workflow, engine=engine)
        result.findings.extend(run_all(ctx))
    return result


def hunt(repos: Sequence[str], ref: Optional[str] = None, workers: int = 6,
         progress=None) -> List[RepoResult]:
    results: List[RepoResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(scan_repo, repo, ref): repo for repo in repos}
        for future in futures:
            pass
        for future, repo in futures.items():
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                result = RepoResult(repo=repo, error=str(exc))
            results.append(result)
            if progress is not None:
                progress(result)
    results.sort(key=lambda r: (-r.top_score, r.repo))
    return results


def to_scan_result(results: Sequence[RepoResult]) -> ScanResult:
    combined = ScanResult()
    for item in results:
        combined.findings.extend(item.findings)
        combined.files_scanned += item.files
        combined.workflows.extend(item.workflows)
        if item.error:
            combined.parse_errors.append("{}: {}".format(item.repo, item.error))
    return combined


def top_repos(language: Optional[str] = None, limit: int = 30,
              min_stars: int = 5000) -> List[str]:
    """Popular repositories, as a starting point for a hunt."""
    query = "stars:>={}".format(min_stars)
    if language:
        query += " language:{}".format(language)
    raw = _gh([
        "api", "-X", "GET", "search/repositories",
        "-f", "q=" + query, "-f", "sort=stars", "-f", "order=desc",
        "-F", "per_page={}".format(min(limit, 100)),
    ])
    payload = json.loads(raw)
    return [item["full_name"] for item in payload.get("items", [])][:limit]
