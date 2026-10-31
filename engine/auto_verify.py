"""
engine/auto_verify.py — B-1 Code-Only -> Confirmed Active Verifier.

Built for CYBERFORGE CORRELATE (Mitigata Hackathon 2026 — PROBLEM 06 · FLAGSHIP).

Novel Capability (`B-1`):
  When SAST identifies a `Code only` vulnerability (`CWE-89`, `CWE-79`, `CWE-78`,
  `CWE-22`, `CWE-601`) inside a handler covered by an AST `RouteEntry`, this
  engine synthesizes a targeted diagnostic probe for that exact route and parameter,
  executes it against the local target through `core/config.py`'s safe `httpx` client
  (`follow_redirects=False`), and if verified at runtime:
    1. Upgrades `issue.status` from `Code only` -> `Confirmed`
    2. Marks `issue.auto_verified = True`
    3. Attaches the newly captured `dast_evidence` (`phase="B1-Auto-Verify"`)
    4. Recomputes `risk_score` and FAIR financial exposure (`fair_exposure_inr_lakhs`)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

from core.config import create_safe_async_client, validate_target_url
from core.schemas import (
    CanonicalFinding,
    CorrelatedIssue,
    IssueStatus,
    RouteEntry,
    compute_issue_risk_score,
    estimate_fair_exposure_inr_lakhs,
     normalize_cwe,
)
from engine.dast_scanner import DASTScanner

VERIFYABLE_CWES = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"}

DEFAULT_CWE_FALLBACK_PARAM: Dict[str, str] = {
    "CWE-89": "id",
    "CWE-79": "q",
    "CWE-78": "host",
    "CWE-22": "file",
    "CWE-601": "next",
}


def _match_route_for_issue(
    issue: CorrelatedIssue, routes: List[RouteEntry]
) -> Optional[RouteEntry]:
    """
    Find the AST `RouteEntry` covering a `Code only` SAST issue via:
      1. File + line span coverage (`route.covers_location(file, line)`)
      2. Handler function name or helper call-graph match (`func_name` / `called_funcs`)
      3. Canonical path match (`issue.canonical_path`)
    """
    issue_file = issue.file or issue.file_path
    issue_line = issue.line

    # 1. Exact file + line range match
    if issue_file and issue_line is not None:
        for route in routes:
            if route.covers_location(issue_file, issue_line):
                return route

    # 2. Function name or 1-hop helper call-graph match
    if issue.func_name:
        target_fn = issue.func_name.strip()
        for route in routes:
            if route.func_name == target_fn or target_fn in (route.called_funcs or []):
                return route

    # 3. Canonical route path match
    if issue.canonical_path:
        target_method = (issue.method or "GET").upper()
        for route in routes:
            if (
                route.canonical_path == issue.canonical_path
                and route.method.upper() == target_method
            ):
                return route
        for route in routes:
            if route.canonical_path == issue.canonical_path:
                return route

    return None


def _select_candidate_params(
    issue: CorrelatedIssue, route: RouteEntry, scanner: DASTScanner, cwe: str
) -> List[Tuple[str, str]]:
    """
    Prioritize `(param_name, param_source)` pairs to probe for `issue` on `route`.
    """
    default_src = "query" if route.method.upper() == "GET" else "form"
    candidates: List[Tuple[str, str]] = []
    seen: set[str] = set()

    def _add(p_name: Optional[str]) -> None:
        if not p_name:
            return
        clean = p_name.strip()
        if not clean or clean.startswith("header:") or clean.startswith("cookie:"):
            return
        if clean not in seen:
            seen.add(clean)
            src = route.param_sources.get(clean, default_src)
            candidates.append((clean, src))

    # 1. Explicit param on issue or underlying SAST finding
    _add(issue.param or issue.parameter)
    if issue.sast_finding is not None:
        _add(issue.sast_finding.param)
    for sf in issue.sast_evidence:
        _add(sf.param)

    # 2. Parameter names from `route.params` mentioned inside the SAST code snippet
    snippet_text = " ".join(
        filter(
            None,
            [
                issue.snippet,
                issue.code_snippet,
                issue.sast_finding.snippet if issue.sast_finding else None,
            ],
        )
    )
    if snippet_text and route.params:
        tokens = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", snippet_text))
        for rp in route.params:
            if rp in tokens:
                _add(rp)

    # 3. All remaining AST-extracted or inferred route parameters
    for rp, rsrc in scanner._infer_candidate_params(route):
        if rp not in seen:
            seen.add(rp)
            candidates.append((rp, rsrc))

    # 4. CWE-specific default parameter fallback
    fallback_param = DEFAULT_CWE_FALLBACK_PARAM.get(cwe)
    if fallback_param and fallback_param not in seen:
        seen.add(fallback_param)
        candidates.append((fallback_param, default_src))

    return candidates


async def _fetch_route_baseline(
    client: httpx.AsyncClient,
    scanner: DASTScanner,
    route: RouteEntry,
    semaphore: asyncio.Semaphore,
) -> Optional[httpx.Response]:
    """Fetch a clean baseline HTTP response for `route`."""
    concrete = route.concrete_path()
    url = urljoin(scanner.base_url + "/", concrete.lstrip("/"))
    baseline_params = {
        p: scanner._default_param_value(p)
        for p in route.params
        if route.param_sources.get(p) != "path"
    }
    method = route.method.upper()
    async with semaphore:
        try:
            if method == "GET":
                return await client.get(url, params=baseline_params or None)
            if route.param_sources and "json" in route.param_sources.values():
                return await client.request(method, url, json=baseline_params or {})
            resp = await client.request(method, url, data=baseline_params or None)
            if resp.status_code in (400, 415, 422) and not route.param_sources:
                json_resp = await client.request(method, url, json=baseline_params or {})
                if json_resp.status_code < 400:
                    for p in route.params:
                        route.param_sources[p] = "json"
                    return json_resp
            return resp
        except Exception:
            return None


async def _run_targeted_cwe_probe(
    scanner: DASTScanner,
    client: httpx.AsyncClient,
    route: RouteEntry,
    param_name: str,
    param_source: str,
    cwe: str,
    baseline_text: str,
    baseline_status: int,
    semaphore: asyncio.Semaphore,
) -> Optional[CanonicalFinding]:
    """Dispatch the single CWE diagnostic probe matching `cwe`."""
    if cwe == "CWE-89":
        return await scanner._check_sqli_cwe89(
            client,
            route,
            param_name,
            param_source,
            baseline_text,
            baseline_status,
            semaphore,
        )
    if cwe == "CWE-79":
        return await scanner._check_xss_cwe79(
            client, route, param_name, param_source, baseline_text, semaphore
        )
    if cwe == "CWE-601":
        return await scanner._check_open_redirect_cwe601(
            client, route, param_name, param_source, semaphore
        )
    if cwe == "CWE-22":
        return await scanner._check_path_traversal_cwe22(
            client, route, param_name, param_source, baseline_text, semaphore
        )
    if cwe == "CWE-78":
        return await scanner._check_cmd_injection_cwe78(
            client, route, param_name, param_source, baseline_text, semaphore
        )
    return None


async def auto_verify_code_only_issues(
    base_url: str,
    routes: List[RouteEntry],
    issues: List[CorrelatedIssue],
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    timeout_seconds: float = 6.0,
) -> List[CorrelatedIssue]:
    """
    `B-1` Code-Only -> Confirmed Active Verifier:
      Scans `issues` for `Code only` findings in `CWE-89`, `CWE-79`, `CWE-78`,
      `CWE-22`, and `CWE-601` that map to an AST `RouteEntry`. Synthesizes and fires
      a targeted diagnostic probe for that route + parameter, and upgrades verified
      findings to `Confirmed` with `auto_verified = True`.
    """
    if not issues or not routes:
        return issues

    validated_url = validate_target_url(base_url)
    scanner = DASTScanner(
        base_url=validated_url,
        timeout_seconds=timeout_seconds,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        transport=transport,
        enable_crawl=False,
        enable_passive_checks=False,
    )
    semaphore = asyncio.Semaphore(scanner.max_concurrency)
    baseline_cache: Dict[Tuple[str, str], Optional[httpx.Response]] = {}

    async with create_safe_async_client(
        timeout_seconds=timeout_seconds,
        headers=auth_headers,
        cookies=auth_cookies,
        transport=transport,
    ) as client:
        for issue in issues:
            status_str = (
                issue.status.value
                if isinstance(issue.status, IssueStatus)
                else str(issue.status)
            )
            if status_str != IssueStatus.CODE_ONLY.value:
                continue

            cwe = normalize_cwe(issue.cwe)
            if cwe not in VERIFYABLE_CWES:
                continue

            matched_route = _match_route_for_issue(issue, routes)
            if matched_route is None:
                continue

            route_copy = matched_route.model_copy(deep=True)
            route_key = (route_copy.method.upper(), route_copy.canonical_path)
            if route_key not in baseline_cache:
                baseline_cache[route_key] = await _fetch_route_baseline(
                    client, scanner, route_copy, semaphore
                )
            baseline_resp = baseline_cache[route_key]
            baseline_text = baseline_resp.text if baseline_resp is not None else ""
            baseline_status = (
                baseline_resp.status_code if baseline_resp is not None else 200
            )

            candidate_params = _select_candidate_params(
                issue, route_copy, scanner, cwe
            )
            verified_finding: Optional[CanonicalFinding] = None
            verified_param: Optional[str] = None

            for param_name, param_source in candidate_params:
                finding = await _run_targeted_cwe_probe(
                    scanner=scanner,
                    client=client,
                    route=route_copy,
                    param_name=param_name,
                    param_source=param_source,
                    cwe=cwe,
                    baseline_text=baseline_text,
                    baseline_status=baseline_status,
                    semaphore=semaphore,
                )
                if finding is not None:
                    verified_finding = finding
                    verified_param = param_name
                    break

            if verified_finding is not None:
                verified_finding.phase = "B1-Auto-Verify"
                verified_finding.scanner_name = "cyberforge-b1-auto-verify"
                verified_finding.fingerprint = verified_finding.compute_fingerprint()

                issue.status = IssueStatus.CONFIRMED
                issue.auto_verified = True
                issue.url = verified_finding.url
                issue.canonical_path = route_copy.canonical_path
                issue.method = verified_finding.method or route_copy.method
                issue.param = verified_finding.param or verified_param
                issue.parameter = issue.param
                issue.payload = verified_finding.payload
                issue.evidence = verified_finding.evidence
                issue.dast_finding = verified_finding

                existing_fps = {df.fingerprint for df in issue.dast_evidence}
                if verified_finding.fingerprint not in existing_fps:
                    issue.dast_evidence.append(verified_finding)

                issue.finding_count = max(
                    1, len(issue.sast_evidence) + len(issue.dast_evidence)
                )
                issue.matched_route = (
                    f"{route_copy.method} {route_copy.path_pattern} "
                    f"({route_copy.file}:{route_copy.start_line}-{route_copy.end_line})"
                )
                issue.link_reason = (
                    f"B-1 Auto-Verify upgraded this issue from `Code only` to `Confirmed`: "
                    f"synthesized targeted `{cwe}` probe for `{route_copy.method} "
                    f"{route_copy.path_pattern}` (param `{issue.param}`) and confirmed "
                    f"runtime exploitability."
                )
                issue.risk_score = compute_issue_risk_score(
                    status=issue.status,
                    severity=issue.severity,
                    cwe=issue.cwe,
                    auto_verified=True,
                )
                issue.fair_exposure_inr_lakhs = estimate_fair_exposure_inr_lakhs(
                    status=issue.status,
                    severity=issue.severity,
                    cwe=issue.cwe,
                )
                issue.estimated_exposure_inr = round(
                    issue.fair_exposure_inr_lakhs * 100000.0, 2
                )
                issue.fingerprint = issue.compute_fingerprint()

    return issues


def auto_verify_code_only_issues_sync(
    base_url: str,
    routes: List[RouteEntry],
    issues: List[CorrelatedIssue],
    **kwargs: Any,
) -> List[CorrelatedIssue]:
    """Synchronous wrapper for `auto_verify_code_only_issues`."""
    return asyncio.run(
        auto_verify_code_only_issues(
            base_url=base_url,
            routes=routes,
            issues=issues,
            **kwargs,
        )
    )
