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
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import model, taint
from .findings import Finding
from .rules import Context, run_all
from .scan import ScanResult, build_index


class GhError(RuntimeError):
    pass


class RateLimited(GhError):
    """GitHub is throttling us.

    Distinct from a failure: the repository is fine and the request will
    succeed later.  GitHub enforces a *secondary* limit on burst concurrency
    separately from the hourly quota, so a scan can be throttled while
    `rate_limit` still reports 5000 remaining -- which makes "could not be
    read" an actively misleading thing to print.
    """

    def __init__(self, message: str, retry_after: Optional[float] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class NoWorkflows(GhError):
    """The repository has no `.github/workflows` directory.

    This is an ordinary outcome, not a failure: plenty of repositories -- the
    Linux kernel, most awesome-lists -- have no GitHub Actions at all.
    Reporting it as an error trains the reader to ignore the error list.
    """


_RATE_LIMIT_MARKERS = ("rate limit", "secondary rate", "abuse detection",
                       "was submitted too quickly", "403")

#: How long to wait between retries when GitHub throttles us.
_BACKOFF_SECONDS = (2.0, 5.0, 12.0, 30.0)


def _gh_once(args: Sequence[str], timeout: int = 45) -> str:
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
        message = (proc.stderr or proc.stdout or "gh failed").strip()
        first = message.splitlines()[0] if message else "gh failed"
        lowered = message.lower()
        if "404" in first or "Not Found" in first:
            raise NoWorkflows(first)
        if any(marker in lowered for marker in _RATE_LIMIT_MARKERS):
            raise RateLimited(first)
        raise GhError(first)
    return proc.stdout


def _gh(args: Sequence[str], timeout: int = 45,
        attempts: int = len(_BACKOFF_SECONDS) + 1) -> str:
    """Run `gh`, backing off when GitHub throttles rather than giving up."""
    last: Optional[RateLimited] = None
    for attempt in range(attempts):
        try:
            return _gh_once(args, timeout)
        except RateLimited as exc:
            last = exc
            if attempt + 1 >= attempts:
                break
            delay = exc.retry_after or _BACKOFF_SECONDS[min(attempt, len(_BACKOFF_SECONDS) - 1)]
            time.sleep(delay + random.uniform(0, 0.75))
    raise last if last is not None else GhError("gh failed")


@dataclass
class RepoResult:
    repo: str
    findings: List[Finding] = field(default_factory=list)
    workflows: List[model.Workflow] = field(default_factory=list)
    files: int = 0
    error: Optional[str] = None
    #: The repository uses no GitHub Actions at all.  Not an error.
    no_workflows: bool = False
    #: GitHub throttled us; the repository was never actually read.
    rate_limited: bool = False

    @property
    def status(self) -> str:
        if self.rate_limited:
            return "rate limited — not scanned"
        if self.no_workflows:
            return "no workflows"
        if self.error:
            return self.error
        return "{} finding(s) in {} file(s)".format(len(self.findings), self.files)

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
        raise NoWorkflows("no workflow directory in {}".format(repo))
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
    except NoWorkflows:
        result.no_workflows = True
        return result
    except RateLimited as exc:
        result.rate_limited = True
        result.error = str(exc)
        return result
    except GhError as exc:
        result.error = str(exc)
        return result
    if not entries:
        result.no_workflows = True
        return result
    # Fetch and parse everything first: a `workflow_run` workflow can only be
    # judged once the workflow that triggers it has been seen.
    parsed = []
    for entry in entries[:max_files]:
        try:
            text = fetch_file(repo, entry["path"], ref)
        except RateLimited as exc:
            result.rate_limited = True
            result.error = str(exc)
            break
        except (GhError, ValueError) as exc:
            result.error = str(exc)
            continue
        workflow = model.parse_text(text, "{}:{}".format(repo, entry["path"]))
        result.files += 1
        result.workflows.append(workflow)
        parsed.append(workflow)

    index = build_index(parsed)
    for workflow in parsed:
        if workflow.parse_error or not workflow.jobs:
            continue
        engine = taint.analyse(workflow)
        ctx = Context(workflow=workflow, engine=engine, index=index)
        result.findings.extend(run_all(ctx))
    return result


def hunt(repos: Sequence[str], ref: Optional[str] = None, workers: int = 4,
         progress=None) -> List[RepoResult]:
    results: List[RepoResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(scan_repo, repo, ref): repo for repo in repos}
        # Report in completion order.  Collecting in submission order means one
        # slow repository at the front holds back every line behind it, which
        # during a throttled run looks exactly like a hang.
        for future in as_completed(futures):
            repo = futures[future]
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
        if item.error and not item.rate_limited:
            combined.parse_errors.append("{}: {}".format(item.repo, item.error))
    if any(item.rate_limited for item in results):
        throttled = sum(1 for item in results if item.rate_limited)
        combined.parse_errors.append(
            "{} repositor{} skipped: GitHub throttled the scan. Re-run with fewer "
            "--workers, or wait and try again.".format(
                throttled, "y" if throttled == 1 else "ies"))
    return combined


def summarise(results: Sequence[RepoResult]) -> str:
    """One line describing the sweep, including the repositories with no CI."""
    scanned = [r for r in results if not r.no_workflows and not r.error]
    skipped = [r for r in results if r.no_workflows]
    throttled = [r for r in results if r.rate_limited]
    failed = [r for r in results if r.error and not r.no_workflows and not r.rate_limited]
    parts = ["{} repositories scanned".format(len(scanned))]
    if skipped:
        parts.append("{} use no GitHub Actions".format(len(skipped)))
    if throttled:
        parts.append("{} throttled by GitHub (not scanned)".format(len(throttled)))
    if failed:
        parts.append("{} could not be read".format(len(failed)))
    return " · ".join(parts)


def top_repos(language: Optional[str] = None, limit: int = 30,
              min_stars: int = 5000, max_stars: Optional[int] = None,
              sort: str = "stars") -> List[str]:
    """Popular repositories, as a starting point for a hunt.

    Star count is a poor proxy for "has interesting CI": the top of the
    all-languages list is awesome-lists, interview prep and free-book
    collections, which mostly have no workflows at all.  Passing a language
    filters to repositories that actually build something, and `pushed:` drops
    the ones that have been archived in all but name.
    """
    # A range matters for hunting: the very top of the star list has been
    # audited by everyone, while the tail below it has the same CI complexity
    # and far less attention.
    if max_stars:
        query = "stars:{}..{}".format(min_stars, max_stars)
    else:
        query = "stars:>={}".format(min_stars)
    query += " pushed:>2025-06-01"
    if language:
        query += " language:{}".format(language)
    raw = _gh([
        "api", "-X", "GET", "search/repositories",
        "-f", "q=" + query, "-f", "sort=" + sort, "-f", "order=desc",
        "-F", "per_page={}".format(min(limit, 100)),
    ])
    payload = json.loads(raw)
    return [item["full_name"] for item in payload.get("items", [])][:limit]
