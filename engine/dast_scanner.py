"""
engine/dast_scanner.py — 2-Phase Scope-Locked Async DAST Engine (FR-2, FR-6, FR-7).

Built for CYBERFORGE CORRELATE (Mitigata Hackathon 2026 — PROBLEM 06 · FLAGSHIP).

Architecture:
  - Strict Target Safety Lock (`core/config.py`): refuses any URL outside `localhost`,
    `127.0.0.1`, or approved local Docker Compose test-app containers, and enforces
    `follow_redirects=False` on all `httpx.AsyncClient` requests.
  - Phase A (AST-Seeded + Crawled Active Diagnostic Verification):
    Consumes `RouteEntry` items from Person A's `FR-4` AST Route Mapper (plus shallow
    local HTML link/form discovery), records a clean baseline per route, and sends
    benign diagnostic probes for:
      1. `CWE-89` (SQL Injection): syntax quote (`1'`) & boolean differential
         (`1' OR '1'='1` vs `1' AND '1'='2`) compared against the clean baseline.
      2. `CWE-79` (Cross-Site Scripting): unique canary (`<script>cyberforge_canary_79</script>`)
         verified for unescaped HTML reflection (ignoring HTML-encoded `&lt;script&gt;`
         safe decoys and `application/json` responses).
      3. `CWE-601` (Open Redirect): tests `https://cyberforge-redirect-canary.invalid/verify`
         with `follow_redirects=False` and inspects `30x Location` headers.
      4. `CWE-22` (Path Traversal) & `CWE-78` (Command Injection): benign canary diagnostics
         for file/path and command/diagnostic parameters.
  - Phase B (Passive Runtime Header / Cookie / CORS / Server Banner Auditor):
    Captures the 6 `Runtime only` (`FR-7`) security misconfigurations that have no single
    source-code sink line (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `HSTS`,
    `Set-Cookie HttpOnly/SameSite`, and `CORS wildcard / Server version disclosure`).
"""

from __future__ import annotations

import asyncio
import html
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from core.config import (
    SAFE_OPEN_REDIRECT_CANARY_URL,
    create_safe_async_client,
    validate_target_url,
)
from core.schemas import (
    CanonicalFinding,
    RouteEntry,
    ScopeReductionReport,
    extract_url_path,
    normalize_route_template,
)
from engine.scope_reducer import ScopeReducer, compute_scope_reduction

# ---------------------------------------------------------------------------
# Diagnostic Canary Constants & Detection Signatures
# ---------------------------------------------------------------------------

XSS_SCRIPT_CANARY = "<script>cyberforge_canary_79</script>"
XSS_ATTR_CANARY = '" autofocus onfocus="cyberforge_canary_79'
CMD_ECHO_CANARY_TOKEN = "cyberforge_cmd_canary_78"

SQL_ERROR_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r'near\s+["\'].*?["\']\s*:\s*syntax error', re.IGNORECASE),
    re.compile(r"unrecognized token:", re.IGNORECASE),
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"pg::syntaxerror|psycopg2\.errors|syntax error at or near", re.IGNORECASE),
    re.compile(r"sqlalchemy\.exc\.(OperationalError|ProgrammingError|DatabaseError)", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver|System\.Data\.SqlClient|Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"sql syntax.*error|database error|sql error", re.IGNORECASE),
]

PATH_TRAVERSAL_SIGNATURES: List[re.Pattern[str]] = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"\[extensions\]|\[fonts\]", re.IGNORECASE),
    re.compile(r"cyberforge_traversal_canary_22", re.IGNORECASE),
]

REDIRECT_PARAM_HINTS: Set[str] = {
    "next",
    "url",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "return_url",
    "goto",
    "dest",
    "destination",
    "continue",
    "target",
    "out",
    "view",
}

FILE_PARAM_HINTS: Set[str] = {
    "file",
    "filename",
    "path",
    "filepath",
    "template",
    "doc",
    "document",
    "page",
    "include",
    "load",
    "read",
    "download",
    "report",
    "img",
    "avatar",
}

CMD_PARAM_HINTS: Set[str] = {
    "cmd",
    "command",
    "exec",
    "ping",
    "host",
    "ip",
    "hostname",
    "domain",
    "target_host",
    "nslookup",
    "dig",
    "tool",
}


class DASTScanner:
    """
    2-Phase Async DAST Scanner (`FR-2`) with built-in Target Safety Lock (`core/config.py`)
    and deterministic finding deduplication (`FR-6`).
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 6.0,
        max_concurrency: int = 10,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        enable_crawl: bool = True,
        enable_passive_checks: bool = True,
    ) -> None:
        # Enforce PRD Page 4 Rule 1 Target Safety Lock immediately on initialization
        self.base_url = validate_target_url(base_url)
        self.timeout_seconds = timeout_seconds
        self.max_concurrency = max(1, max_concurrency)
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.transport = transport
        self.enable_crawl = enable_crawl
        self.enable_passive_checks = enable_passive_checks
        self.last_scope_reduction: Optional[ScopeReductionReport] = None

    @staticmethod
    def _enrich_scope_report(report: ScopeReductionReport) -> ScopeReductionReport:
        """Attach Task B2.3 telemetry alias attributes onto `ScopeReductionReport`."""
        try:
            setattr(report, "drifted_routes", report.runtime_drift_routes)
            setattr(report, "time_complexity_summary", report.time_complexity)
        except Exception:
            pass
        return report

    def _resolve_active_probe_plan(
        self,
        seeded_routes: List[RouteEntry],
        all_routes: List[RouteEntry],
        sast_findings: Optional[List[CanonicalFinding]] = None,
        probe_plan: Optional[ScopeReductionReport] = None,
        route_mapper: Optional[Any] = None,
    ) -> Optional[ScopeReductionReport]:
        """
        Build or update the Adaptive DAST Scope Reduction plan (`ScopeReductionReport`)
        combining AST routes, SAST findings, and live crawled endpoints (`EXACT_REPLICA`
        vs `RUNTIME_DRIFT_EXTRA`).
        """
        if probe_plan is None and sast_findings is None:
            self.last_scope_reduction = None
            return None

        # Live endpoints are all seeded AST routes plus any crawled routes (`__runtime_crawl__`),
        # excluding the synthetic `("GET", "/")` (`__runtime__`) added solely for passive header inspection.
        live_routes = [r for r in all_routes if r.file != "__runtime__"]

        if probe_plan is not None and sast_findings is None:
            known_keys = {
                (e.method.upper(), e.canonical_path)
                for e in getattr(probe_plan, "route_entries", [])
            }
            has_new_drift = any(
                (r.method.upper(), r.canonical_path) not in known_keys
                for r in live_routes
            )
            if not has_new_drift:
                self.last_scope_reduction = self._enrich_scope_report(probe_plan)
                return self.last_scope_reduction

        reducer = ScopeReducer(route_mapper=route_mapper)
        effective_sast = list(sast_findings or [])
        if hasattr(reducer, "build_dast_probe_plan"):
            report = reducer.build_dast_probe_plan(
                routes=seeded_routes,
                sast_findings=effective_sast,
                live_endpoints=live_routes,
            )
        else:
            report = compute_scope_reduction(
                routes=seeded_routes,
                sast_findings=effective_sast,
                live_endpoints=live_routes,
                route_mapper=route_mapper,
            )
        self.last_scope_reduction = self._enrich_scope_report(report)
        return self.last_scope_reduction

    async def scan(
        self,
        routes: Optional[List[RouteEntry]] = None,
        sast_findings: Optional[List[CanonicalFinding]] = None,
        probe_plan: Optional[ScopeReductionReport] = None,
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        """
        Execute the full 2-Phase DAST scan:
          - Crawl root & seed routes to collect baseline responses + HTML forms/links
          - Compute/apply Adaptive Scope Reduction when `sast_findings` or `probe_plan` is supplied
          - Phase A: Active diagnostic verification for CWE-89, CWE-79, CWE-601, CWE-22, CWE-78
          - Phase B: Passive runtime security header, cookie, CORS, and banner audit (`Runtime only`)
          - Deduplicate findings by deterministic SHA-256 `fingerprint` (`FR-6`)
        """
        seeded_routes = list(routes or [])
        findings_by_fp: Dict[str, CanonicalFinding] = {}
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async with create_safe_async_client(
            timeout_seconds=self.timeout_seconds,
            headers=self.auth_headers,
            cookies=self.auth_cookies,
            transport=self.transport,
        ) as client:
            # Step 1: Discover endpoints (combine AST RouteEntries + shallow local HTML crawl)
            all_routes, baseline_responses = await self._discover_and_baseline(
                client, seeded_routes, semaphore
            )

            # Step 1b: Resolve Adaptive Scope Reduction Plan (if SAST findings or probe_plan provided)
            active_plan = self._resolve_active_probe_plan(
                seeded_routes=seeded_routes,
                all_routes=all_routes,
                sast_findings=sast_findings,
                probe_plan=probe_plan,
                route_mapper=route_mapper,
            )

            # Step 2: Phase A — Active Diagnostic Probing across all routes & parameters
            active_tasks = [
                self._probe_route_active(
                    client,
                    route,
                    baseline_responses.get((route.method, route.canonical_path)),
                    semaphore,
                    active_plan=active_plan,
                )
                for route in all_routes
            ]
            if active_tasks:
                route_finding_lists = await asyncio.gather(*active_tasks, return_exceptions=True)
                for res in route_finding_lists:
                    if isinstance(res, list):
                        for f in res:
                            findings_by_fp.setdefault(f.fingerprint, f)

            # Step 3: Phase B — Passive Runtime Header / Cookie / CORS / Banner Audit (FR-7 Runtime only)
            if self.enable_passive_checks:
                passive_findings = self._audit_passive_runtime_responses(baseline_responses)
                for pf in passive_findings:
                    findings_by_fp.setdefault(pf.fingerprint, pf)

        return list(findings_by_fp.values())

    # -----------------------------------------------------------------------
    # Discovery & Baseline Collection
    # -----------------------------------------------------------------------

    async def _discover_and_baseline(
        self,
        client: httpx.AsyncClient,
        seeded_routes: List[RouteEntry],
        semaphore: asyncio.Semaphore,
    ) -> Tuple[List[RouteEntry], Dict[Tuple[str, str], httpx.Response]]:
        """
        Collect clean baseline HTTP responses for seeded `RouteEntry` items and optionally
        perform a shallow local crawl of `/` to discover additional routes/forms.
        """
        route_map: Dict[Tuple[str, str], RouteEntry] = {}
        for r in seeded_routes:
            for m in r.methods or [r.method]:
                key = (m.upper(), r.canonical_path)
                if key not in route_map:
                    route_copy = r.model_copy(deep=True)
                    route_copy.method = m.upper()
                    route_map[key] = route_copy

        # Always ensure root "/" is fetched for Phase B passive header/cookie inspection
        if ("GET", "/") not in route_map:
            route_map[("GET", "/")] = RouteEntry(
                method="GET",
                path_pattern="/",
                file="__runtime__",
                func_name="root_index",
                start_line=1,
                end_line=1,
                params=[],
            )

        baseline_responses: Dict[Tuple[str, str], httpx.Response] = {}

        async def _fetch_baseline(key: Tuple[str, str], route: RouteEntry) -> None:
            method, _ = key
            concrete = route.concrete_path()
            url = urljoin(self.base_url + "/", concrete.lstrip("/"))
            # Provide benign baseline values for known parameters
            baseline_params = {p: self._default_param_value(p) for p in route.params if route.param_sources.get(p) != "path"}
            async with semaphore:
                try:
                    if method == "GET":
                        resp = await client.get(url, params=baseline_params or None)
                    elif route.param_sources and "json" in route.param_sources.values():
                        resp = await client.request(method, url, json=baseline_params or {})
                    else:
                        resp = await client.request(method, url, data=baseline_params or None)
                        # If a non-GET endpoint without explicit param_sources rejects form data (400/415/422),
                        # probe with JSON payload so FastAPI/Flask JSON endpoints work out of the box
                        if resp.status_code in (400, 415, 422) and not route.param_sources:
                            json_resp = await client.request(method, url, json=baseline_params or {})
                            if json_resp.status_code < 400:
                                resp = json_resp
                                for p in route.params:
                                    route.param_sources[p] = "json"
                    baseline_responses[key] = resp
                except Exception:
                    return

        await asyncio.gather(
            *[_fetch_baseline(k, r) for k, r in list(route_map.items())],
            return_exceptions=True,
        )

        # If crawling is enabled, parse discovered HTML pages (up to 2 hops from seed routes / root)
        # so forms and inputs on child pages linked from `/` (e.g., `/feedback`, `/login`) are discovered.
        if self.enable_crawl:
            crawled_keys: set[Tuple[str, str]] = set()
            for _hop in range(2):
                newly_discovered: List[RouteEntry] = []
                for rkey, resp in list(baseline_responses.items()):
                    if rkey in crawled_keys:
                        continue
                    crawled_keys.add(rkey)
                    _, page_path = rkey
                    ctype = resp.headers.get("content-type", "").lower()
                    if "html" not in ctype and "<html" not in resp.text[:300].lower():
                        continue
                    for disc_route in self._extract_routes_from_html(resp.text, current_path=page_path):
                        dkey = (disc_route.method, disc_route.canonical_path)
                        if dkey not in route_map:
                            route_map[dkey] = disc_route
                            newly_discovered.append(disc_route)
                        else:
                            # Merge any newly discovered form/query input parameter names
                            existing = route_map[dkey]
                            for p in disc_route.params:
                                if p not in existing.params:
                                    existing.params.append(p)
                            for p, src in disc_route.param_sources.items():
                                existing.param_sources.setdefault(p, src)

                if not newly_discovered:
                    break

                await asyncio.gather(
                    *[_fetch_baseline((r.method, r.canonical_path), r) for r in newly_discovered],
                    return_exceptions=True,
                )

        return list(route_map.values()), baseline_responses

    def _extract_routes_from_html(
        self, html_text: str, current_path: str = "/"
    ) -> List[RouteEntry]:
        """Extract local links (`<a href>`) and forms (`<form action>`) from an HTML response."""
        discovered: List[RouteEntry] = []
        try:
            soup = BeautifulSoup(html_text, "html.parser")
        except Exception:
            return discovered

        base_page_path = current_path if current_path.startswith("/") else ("/" + current_path)

        # 1. Links with query parameters or local paths
        for a_tag in soup.find_all("a", href=True):
            href = str(a_tag["href"]).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            parsed = urlparse(href)
            if parsed.scheme and parsed.netloc:
                # Ignore external links
                try:
                    validate_target_url(href)
                except Exception:
                    continue
                resolved_path = parsed.path or "/"
            else:
                resolved_path = urljoin(base_page_path, parsed.path or "")
            path = extract_url_path(resolved_path or "/")
            query_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            discovered.append(
                RouteEntry(
                    method="GET",
                    path_pattern=path,
                    file="__runtime_crawl__",
                    func_name="crawled_link",
                    start_line=1,
                    end_line=1,
                    params=query_params,
                    param_sources={p: "query" for p in query_params},
                )
            )

        # 2. HTML Forms (<form action="..." method="..."> with <input name="...">)
        for form in soup.find_all("form"):
            raw_action = str(form.get("action") or "").strip()
            method = str(form.get("method") or "GET").strip().upper()
            parsed = urlparse(raw_action)
            if parsed.scheme and parsed.netloc:
                try:
                    validate_target_url(raw_action)
                except Exception:
                    continue
                resolved_path = parsed.path or "/"
            elif not raw_action:
                resolved_path = base_page_path
            else:
                resolved_path = urljoin(base_page_path, parsed.path or "")
            path = extract_url_path(resolved_path or "/")
            input_params: List[str] = [
                k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ]
            param_sources_map: Dict[str, str] = {p: "query" for p in input_params}
            param_src = "query" if method == "GET" else "form"
            for field in form.find_all(["input", "textarea", "select"]):
                fname = field.get("name")
                if fname and str(fname).strip():
                    clean_name = str(fname).strip()
                    if clean_name not in input_params:
                        input_params.append(clean_name)
                    param_sources_map[clean_name] = param_src
            discovered.append(
                RouteEntry(
                    method=method,
                    path_pattern=path,
                    file="__runtime_crawl__",
                    func_name="crawled_form",
                    start_line=1,
                    end_line=1,
                    params=input_params,
                    param_sources=param_sources_map,
                )
            )

        return discovered

    # -----------------------------------------------------------------------
    # Phase A: Active Diagnostic Probing (CWE-89, CWE-79, CWE-601, CWE-22, CWE-78)
    # -----------------------------------------------------------------------

    def _infer_candidate_params(self, route: RouteEntry) -> List[Tuple[str, str]]:
        """
        Return `(param_name, param_source)` pairs to test for a route.
        Prioritises exact AST-extracted parameters (`route.params`), and falls back
        to context-aware parameter hints when a route has no explicit AST params.
        """
        candidates: List[Tuple[str, str]] = []
        seen: Set[str] = set()

        default_src = "query" if route.method == "GET" else "form"
        for p in route.params:
            src = route.param_sources.get(p, default_src)
            candidates.append((p, src))
            seen.add(p)

        if candidates:
            return candidates

        # Fallback heuristics when testing an endpoint before AST params are attached
        path_lower = route.canonical_path.lower()
        fallback_names: List[str] = []
        if any(w in path_lower for w in ("order", "product", "item", "user", "invoice", "detail")):
            fallback_names.extend(["id", "q"])
        elif any(w in path_lower for w in ("search", "query", "find", "filter", "catalog", "comment", "review")):
            fallback_names.extend(["q", "search", "query", "comment", "name"])
        elif any(w in path_lower for w in ("redirect", "login", "logout", "auth", "callback", "goto")):
            fallback_names.extend(["next", "url", "redirect"])
        elif any(w in path_lower for w in ("file", "download", "export", "doc", "invoice", "template", "view")):
            fallback_names.extend(["file", "path", "template"])
        elif any(w in path_lower for w in ("ping", "diag", "health", "cmd", "exec", "check", "network")):
            fallback_names.extend(["host", "ip", "cmd"])
        else:
            fallback_names.extend(["id", "q"])

        for fn in fallback_names:
            if fn not in seen:
                candidates.append((fn, default_src))
                seen.add(fn)
        return candidates

    @staticmethod
    def _default_param_value(param_name: str) -> str:
        pl = param_name.lower()
        if any(k in pl for k in ("id", "num", "page", "limit", "qty", "count", "price")):
            return "1"
        if any(k in pl for k in REDIRECT_PARAM_HINTS):
            return "/home"
        if any(k in pl for k in FILE_PARAM_HINTS):
            return "readme.txt"
        if any(k in pl for k in CMD_PARAM_HINTS):
            return "127.0.0.1"
        return "test"

    async def _send_probe(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        payload_value: str,
        semaphore: asyncio.Semaphore,
    ) -> Tuple[Optional[httpx.Response], str]:
        """
        Send a single diagnostic probe for `(route, param_name, payload_value)` and
        return `(response, full_request_url_with_query)`.
        """
        baseline_map = {
            p: self._default_param_value(p)
            for p in route.params
            if route.param_sources.get(p) != "path"
        }
        baseline_map[param_name] = payload_value

        if param_source == "path":
            concrete_path = route.concrete_path({param_name: payload_value})
            query_params = {k: v for k, v in baseline_map.items() if k != param_name}
        else:
            concrete_path = route.concrete_path()
            query_params = baseline_map

        target_url = urljoin(self.base_url + "/", concrete_path.lstrip("/"))

        async with semaphore:
            try:
                if route.method == "GET" or param_source in ("query", "path"):
                    q_dict = query_params if param_source != "path" else (query_params or None)
                    resp = await client.request(route.method, target_url, params=q_dict)
                    full_url = str(resp.request.url)
                    return resp, full_url
                elif param_source == "json":
                    resp = await client.request(route.method, target_url, json=query_params)
                    return resp, target_url
                else:
                    resp = await client.request(route.method, target_url, data=query_params)
                    return resp, target_url
            except Exception:
                return None, target_url

    async def _probe_route_active(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        baseline_resp: Optional[httpx.Response],
        semaphore: asyncio.Semaphore,
        active_plan: Optional[ScopeReductionReport] = None,
    ) -> List[CanonicalFinding]:
        """
        Run Phase A active diagnostic probes on a single `RouteEntry`.
        When `active_plan` (`ScopeReductionReport`) is provided:
          - `PRUNED_SAFE` routes skip Phase-A active fuzzing completely (0 active probes).
          - `TARGETED_REDUCTION` (`EXACT_REPLICA` tainted) routes only execute the
            specific `(param, CWE)` probe pairs flagged by SAST.
          - `FULL_PROBE_DRIFT` (`RUNTIME_DRIFT_EXTRA`) routes execute all 5 CWE probes.
        """
        findings: List[CanonicalFinding] = []
        plan_entry = None
        is_targeted_reduction = False

        if active_plan is not None:
            # Synthetic root `/` added purely for Phase B passive header audit is never actively fuzzed under a plan
            if route.file == "__runtime__":
                return findings

            norm_method = route.method.upper()
            norm_path = route.canonical_path
            for entry in getattr(active_plan, "route_entries", []):
                if entry.method.upper() == norm_method and entry.canonical_path == norm_path:
                    plan_entry = entry
                    break

            if plan_entry is not None:
                strategy = str(plan_entry.scope_strategy)
                if strategy == "PRUNED_SAFE" or not getattr(plan_entry, "should_fuzz_active", True):
                    return findings
                if strategy == "TARGETED_REDUCTION":
                    is_targeted_reduction = True

        candidate_params = self._infer_candidate_params(route)
        if is_targeted_reduction and plan_entry is not None:
            default_src = "query" if route.method == "GET" else "form"
            seen_params = {p for p, _ in candidate_params}
            for tp in getattr(plan_entry, "targeted_probes", []):
                t_param = tp[0] if isinstance(tp, (tuple, list)) else getattr(tp, "param", None)
                if t_param and t_param != "*" and t_param not in seen_params:
                    candidate_params.append((t_param, route.param_sources.get(t_param, default_src)))
                    seen_params.add(t_param)
            for t_param in getattr(plan_entry, "tainted_params", []):
                if t_param and t_param != "*" and t_param not in seen_params:
                    candidate_params.append((t_param, route.param_sources.get(t_param, default_src)))
                    seen_params.add(t_param)

        if not candidate_params:
            return findings

        baseline_text = baseline_resp.text if baseline_resp is not None else ""
        baseline_status = baseline_resp.status_code if baseline_resp is not None else 200

        for param_name, param_source in candidate_params:
            p_lower = param_name.lower()

            def _should_run_cwe(cwe_id: str, default_heuristic: bool = True) -> bool:
                if active_plan is None:
                    return default_heuristic
                allowed = ScopeReducer.should_probe(
                    active_plan,
                    route.method,
                    route.canonical_path,
                    param_name,
                    cwe_id,
                )
                if not allowed:
                    return False
                # If SAST explicitly targeted this (param, CWE), run even if param name is non-standard
                if is_targeted_reduction:
                    return True
                return default_heuristic

            # 1. CWE-89: SQL Injection Diagnostic Probe
            if _should_run_cwe("CWE-89", True):
                sqli_finding = await self._check_sqli_cwe89(
                    client, route, param_name, param_source, baseline_text, baseline_status, semaphore
                )
                if sqli_finding is not None:
                    findings.append(sqli_finding)

            # 2. CWE-79: Cross-Site Scripting (XSS) Canary Reflection Probe
            if _should_run_cwe("CWE-79", True):
                xss_finding = await self._check_xss_cwe79(
                    client, route, param_name, param_source, baseline_text, semaphore
                )
                if xss_finding is not None:
                    findings.append(xss_finding)

            # 3. CWE-601: Open Redirect Probe (when param or route suggests redirect, or SAST targeted CWE-601)
            redir_heuristic = (
                p_lower in REDIRECT_PARAM_HINTS
                or "redirect" in route.canonical_path.lower()
                or "login" in route.canonical_path.lower()
            )
            if _should_run_cwe("CWE-601", redir_heuristic):
                redir_finding = await self._check_open_redirect_cwe601(
                    client, route, param_name, param_source, semaphore
                )
                if redir_finding is not None:
                    findings.append(redir_finding)

            # 4. CWE-22: Path Traversal Probe (when param or route suggests file/path, or SAST targeted CWE-22)
            pt_heuristic = (
                p_lower in FILE_PARAM_HINTS
                or any(k in route.canonical_path.lower() for k in ("file", "download", "export", "doc", "template"))
            )
            if _should_run_cwe("CWE-22", pt_heuristic):
                pt_finding = await self._check_path_traversal_cwe22(
                    client, route, param_name, param_source, baseline_text, semaphore
                )
                if pt_finding is not None:
                    findings.append(pt_finding)

            # 5. CWE-78: Command Injection Echo Canary Probe (when param or route suggests cmd/host, or SAST targeted CWE-78)
            cmd_heuristic = (
                p_lower in CMD_PARAM_HINTS
                or any(k in route.canonical_path.lower() for k in ("ping", "diag", "cmd", "exec", "network", "tool"))
            )
            if _should_run_cwe("CWE-78", cmd_heuristic):
                cmd_finding = await self._check_cmd_injection_cwe78(
                    client, route, param_name, param_source, baseline_text, semaphore
                )
                if cmd_finding is not None:
                    findings.append(cmd_finding)

        return findings

    async def _check_sqli_cwe89(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        baseline_text: str,
        baseline_status: int,
        semaphore: asyncio.Semaphore,
    ) -> Optional[CanonicalFinding]:
        """
        Phase A Check for CWE-89 (SQL Injection):
          1. Send quote probe (`1'`) to check for DBMS syntax error signatures not in baseline.
          2. Send boolean differential probes (`1' OR '1'='1` vs `1' AND '1'='2`) to detect
             boolean-based SQL injection when error messages are suppressed.
        """
        quote_payload = "1'"
        resp_quote, req_url = await self._send_probe(
            client, route, param_name, param_source, quote_payload, semaphore
        )
        if resp_quote is None:
            return None

        # Signal A: DBMS Error Signature in response (and NOT in clean baseline)
        for pattern in SQL_ERROR_PATTERNS:
            m = pattern.search(resp_quote.text)
            if m and not pattern.search(baseline_text):
                matched_err = m.group(0)
                return CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-a",
                    cwe="CWE-89",
                    title="SQL Injection (Database Error Confirmed)",
                    severity="Critical",
                    confidence="High",
                    url=req_url,
                    canonical_path=route.canonical_path,
                    method=route.method,
                    param=param_name,
                    payload=quote_payload,
                    evidence=f"HTTP {resp_quote.status_code}: DBMS syntax error signature `{matched_err}` triggered by quote probe `{quote_payload}`.",
                    status_code=resp_quote.status_code,
                    phase="Phase-A-Active",
                )

        # Signal B: Boolean Tautology vs Contradiction Differential
        true_payload = "1' OR '1'='1"
        false_payload = "1' AND '1'='2"
        resp_true, true_url = await self._send_probe(
            client, route, param_name, param_source, true_payload, semaphore
        )
        resp_false, _ = await self._send_probe(
            client, route, param_name, param_source, false_payload, semaphore
        )
        if resp_true is not None and resp_false is not None:
            # Check if quote caused a 500 error while tautology succeeded with 200 OK
            if (
                resp_quote.status_code >= 500
                and baseline_status < 400
                and resp_true.status_code == 200
            ):
                return CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-a",
                    cwe="CWE-89",
                    title="SQL Injection (500 Syntax Break + Tautology Recovery)",
                    severity="Critical",
                    confidence="High",
                    url=req_url,
                    canonical_path=route.canonical_path,
                    method=route.method,
                    param=param_name,
                    payload=quote_payload,
                    evidence=(
                        f"Quote probe `{quote_payload}` caused HTTP {resp_quote.status_code} while "
                        f"boolean tautology `{true_payload}` restored HTTP 200 OK."
                    ),
                    status_code=resp_quote.status_code,
                    phase="Phase-A-Active",
                )

            # Check if TRUE condition returns HTTP 200 while FALSE condition returns 4xx/5xx (e.g. 404 Not Found on .fetchone())
            if resp_true.status_code == 200 and resp_false.status_code >= 400:
                return CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-a",
                    cwe="CWE-89",
                    title="SQL Injection (Boolean Status Differential Confirmed)",
                    severity="Critical",
                    confidence="High",
                    url=true_url,
                    canonical_path=route.canonical_path,
                    method=route.method,
                    param=param_name,
                    payload=true_payload,
                    evidence=(
                        f"Boolean tautology `{true_payload}` returned HTTP 200 OK while "
                        f"contradiction `{false_payload}` returned HTTP {resp_false.status_code}."
                    ),
                    status_code=resp_true.status_code,
                    phase="Phase-A-Active",
                )

            # Check if TRUE condition returns a substantially larger response body than FALSE condition
            # after stripping raw, HTML-escaped, and URL-encoded reflections of the payload itself.
            if resp_true.status_code == 200 and resp_false.status_code == 200:
                def _strip_reflections(body: str, pld: str) -> str:
                    for variant in (
                        pld,
                        html.escape(pld, quote=True),
                        html.escape(pld, quote=False),
                        quote(pld),
                        quote_plus(pld),
                    ):
                        body = body.replace(variant, "")
                    return body

                true_stripped = _strip_reflections(resp_true.text, true_payload)
                false_stripped = _strip_reflections(resp_false.text, false_payload)
                len_diff = len(true_stripped) - len(false_stripped)
                if len_diff >= 15 and (
                    len(true_stripped) > len(baseline_text) * 1.10
                    or len(false_stripped) < len(baseline_text) * 0.85
                ):
                    return CanonicalFinding(
                        source="DAST",
                        scanner_name="cyberforge-dast-phase-a",
                        cwe="CWE-89",
                        title="SQL Injection (Boolean Differential Confirmed)",
                        severity="Critical",
                        confidence="High",
                        url=true_url,
                        canonical_path=route.canonical_path,
                        method=route.method,
                        param=param_name,
                        payload=true_payload,
                        evidence=(
                            f"Boolean tautology `{true_payload}` returned {len(resp_true.text)} bytes "
                            f"vs contradiction `{false_payload}` returning {len(resp_false.text)} bytes (delta +{len_diff} bytes)."
                        ),
                        status_code=resp_true.status_code,
                        phase="Phase-A-Active",
                    )

        return None

    async def _check_xss_cwe79(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        baseline_text: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[CanonicalFinding]:
        """
        Phase A Check for CWE-79 (Cross-Site Scripting):
          Sends `<script>cyberforge_canary_79</script>` and verifies that it reflects
          UNESCAPED inside an HTML response body (ignoring JSON responses and
          HTML-escaped `&lt;script&gt;` decoys).
        """
        resp, req_url = await self._send_probe(
            client, route, param_name, param_source, XSS_SCRIPT_CANARY, semaphore
        )
        if resp is None:
            return None

        ctype = resp.headers.get("content-type", "").lower()
        # Do not flag pure JSON API responses as reflected HTML XSS
        if "application/json" in ctype:
            return None

        if XSS_SCRIPT_CANARY in resp.text and XSS_SCRIPT_CANARY not in baseline_text:
            return CanonicalFinding(
                source="DAST",
                scanner_name="cyberforge-dast-phase-a",
                cwe="CWE-79",
                title="Reflected Cross-Site Scripting (Unescaped Script Canary)",
                severity="High",
                confidence="High",
                url=req_url,
                canonical_path=route.canonical_path,
                method=route.method,
                param=param_name,
                payload=XSS_SCRIPT_CANARY,
                evidence=f"Unescaped canary `{XSS_SCRIPT_CANARY}` reflected verbatim in HTTP {resp.status_code} HTML response.",
                status_code=resp.status_code,
                phase="Phase-A-Active",
            )

        # Also check attribute-context breakout (`" autofocus onfocus="cyberforge_canary_79`)
        resp_attr, attr_url = await self._send_probe(
            client, route, param_name, param_source, XSS_ATTR_CANARY, semaphore
        )
        if resp_attr is not None and "application/json" not in resp_attr.headers.get("content-type", "").lower():
            if XSS_ATTR_CANARY in resp_attr.text and XSS_ATTR_CANARY not in baseline_text:
                return CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-a",
                    cwe="CWE-79",
                    title="Reflected Cross-Site Scripting (Unescaped Attribute Breakout)",
                    severity="High",
                    confidence="High",
                    url=attr_url,
                    canonical_path=route.canonical_path,
                    method=route.method,
                    param=param_name,
                    payload=XSS_ATTR_CANARY,
                    evidence=f"Unescaped attribute breakout `{XSS_ATTR_CANARY}` reflected in HTTP {resp_attr.status_code} HTML response.",
                    status_code=resp_attr.status_code,
                    phase="Phase-A-Active",
                )

        return None

    async def _check_open_redirect_cwe601(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[CanonicalFinding]:
        """
        Phase A Check for CWE-601 (Open Redirect):
          Uses `SAFE_OPEN_REDIRECT_CANARY_URL` (`https://cyberforge-redirect-canary.invalid/verify`)
          with `follow_redirects=False` so no external request is ever made.
        """
        resp, req_url = await self._send_probe(
            client,
            route,
            param_name,
            param_source,
            SAFE_OPEN_REDIRECT_CANARY_URL,
            semaphore,
        )
        if resp is None:
            return None

        location = resp.headers.get("location", "").strip()
        if resp.status_code in (301, 302, 303, 307, 308) and any(
            location.startswith(prefix)
            for prefix in (
                "https://cyberforge-redirect-canary.invalid",
                "http://cyberforge-redirect-canary.invalid",
                "//cyberforge-redirect-canary.invalid",
            )
        ):
            return CanonicalFinding(
                source="DAST",
                scanner_name="cyberforge-dast-phase-a",
                cwe="CWE-601",
                title="Open Redirect to External Domain",
                severity="Medium",
                confidence="High",
                url=req_url,
                canonical_path=route.canonical_path,
                method=route.method,
                param=param_name,
                payload=SAFE_OPEN_REDIRECT_CANARY_URL,
                evidence=f"HTTP {resp.status_code} Redirect with `Location: {location}` (captured safely with follow_redirects=False).",
                status_code=resp.status_code,
                phase="Phase-A-Active",
            )
        return None

    async def _check_path_traversal_cwe22(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        baseline_text: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[CanonicalFinding]:
        """Phase A Check for CWE-22 (Path Traversal)."""
        for probe in ("../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"):
            resp, req_url = await self._send_probe(
                client, route, param_name, param_source, probe, semaphore
            )
            if resp is None:
                continue
            for sig in PATH_TRAVERSAL_SIGNATURES:
                if sig.search(resp.text) and not sig.search(baseline_text):
                    return CanonicalFinding(
                        source="DAST",
                        scanner_name="cyberforge-dast-phase-a",
                        cwe="CWE-22",
                        title="Path Traversal / Arbitrary File Read",
                        severity="High",
                        confidence="High",
                        url=req_url,
                        canonical_path=route.canonical_path,
                        method=route.method,
                        param=param_name,
                        payload=probe,
                        evidence=f"HTTP {resp.status_code} returned traversal file content matching `{sig.pattern}`.",
                        status_code=resp.status_code,
                        phase="Phase-A-Active",
                    )
        return None

    async def _check_cmd_injection_cwe78(
        self,
        client: httpx.AsyncClient,
        route: RouteEntry,
        param_name: str,
        param_source: str,
        baseline_text: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[CanonicalFinding]:
        """Phase A Check for CWE-78 (OS Command Injection via benign echo token)."""
        for probe in (f"127.0.0.1; echo {CMD_ECHO_CANARY_TOKEN}", f"127.0.0.1 && echo {CMD_ECHO_CANARY_TOKEN}"):
            resp, req_url = await self._send_probe(
                client, route, param_name, param_source, probe, semaphore
            )
            if resp is None:
                continue
            # Ensure the response reflected the executed output (not just the raw input command string)
            if CMD_ECHO_CANARY_TOKEN in resp.text and CMD_ECHO_CANARY_TOKEN not in baseline_text:
                if f"echo {CMD_ECHO_CANARY_TOKEN}" not in resp.text:
                    return CanonicalFinding(
                        source="DAST",
                        scanner_name="cyberforge-dast-phase-a",
                        cwe="CWE-78",
                        title="OS Command Injection (Canary Output Confirmed)",
                        severity="Critical",
                        confidence="High",
                        url=req_url,
                        canonical_path=route.canonical_path,
                        method=route.method,
                        param=param_name,
                        payload=probe,
                        evidence=f"Executed shell command output `{CMD_ECHO_CANARY_TOKEN}` present in HTTP {resp.status_code} response.",
                        status_code=resp.status_code,
                        phase="Phase-A-Active",
                    )
        return None

    # -----------------------------------------------------------------------
    # Phase B: Passive Runtime Header / Cookie / CORS / Banner Auditor (FR-7)
    # -----------------------------------------------------------------------

    def _audit_passive_runtime_responses(
        self, baseline_responses: Dict[Tuple[str, str], httpx.Response]
    ) -> List[CanonicalFinding]:
        """
        Phase B: Inspect HTTP responses to capture the 6 `Runtime only` (`FR-7`)
        misconfigurations that exist only at runtime (e.g. missing security headers,
        insecure session cookies, wildcard CORS, server version disclosure).

        App-wide header checks are anchored to the primary representative endpoint
        (preferring `/` or the first 200 OK endpoint) so we report exactly 1 clean
        `Runtime only` issue per distinct runtime flaw rather than duplicating across
        all 30 URLs (`FR-6`).
        """
        passive_findings: List[CanonicalFinding] = []
        if not baseline_responses:
            return passive_findings

        # Select primary representative response (preferring ("GET", "/") if available)
        primary_key = ("GET", "/") if ("GET", "/") in baseline_responses else next(iter(baseline_responses.keys()))
        primary_resp = baseline_responses[primary_key]
        primary_method, primary_path = primary_key
        primary_url = str(primary_resp.request.url) if primary_resp.request else urljoin(self.base_url + "/", primary_path.lstrip("/"))
        headers = primary_resp.headers

        # 1. Missing Content-Security-Policy (CSP) Header
        if "content-security-policy" not in headers:
            passive_findings.append(
                CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-b",
                    cwe="CWE-693",
                    title="Missing Content-Security-Policy (CSP) Header",
                    severity="Medium",
                    confidence="High",
                    url=primary_url,
                    canonical_path=primary_path,
                    method=primary_method,
                    param="header:Content-Security-Policy",
                    payload="Passive HTTP Header Audit",
                    evidence=f"HTTP {primary_resp.status_code} response from `{primary_path}` omits `Content-Security-Policy` header.",
                    status_code=primary_resp.status_code,
                    phase="Phase-B-Passive",
                )
            )

        # 2. Missing Anti-Clickjacking Header (X-Frame-Options / CSP frame-ancestors)
        csp_val = headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in headers and "frame-ancestors" not in csp_val:
            passive_findings.append(
                CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-b",
                    cwe="CWE-1021",
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    severity="Medium",
                    confidence="High",
                    url=primary_url,
                    canonical_path=primary_path,
                    method=primary_method,
                    param="header:X-Frame-Options",
                    payload="Passive HTTP Header Audit",
                    evidence=f"HTTP {primary_resp.status_code} response from `{primary_path}` omits `X-Frame-Options` (`DENY`/`SAMEORIGIN`).",
                    status_code=primary_resp.status_code,
                    phase="Phase-B-Passive",
                )
            )

        # 3. Missing X-Content-Type-Options: nosniff
        if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
            passive_findings.append(
                CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-b",
                    cwe="CWE-693",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    severity="Low",
                    confidence="High",
                    url=primary_url,
                    canonical_path=primary_path,
                    method=primary_method,
                    param="header:X-Content-Type-Options",
                    payload="Passive HTTP Header Audit",
                    evidence=f"HTTP {primary_resp.status_code} response from `{primary_path}` is missing `X-Content-Type-Options: nosniff`.",
                    status_code=primary_resp.status_code,
                    phase="Phase-B-Passive",
                )
            )

        # 4. Missing Strict-Transport-Security (HSTS) Header
        if "strict-transport-security" not in headers:
            passive_findings.append(
                CanonicalFinding(
                    source="DAST",
                    scanner_name="cyberforge-dast-phase-b",
                    cwe="CWE-693",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity="Low",
                    confidence="High",
                    url=primary_url,
                    canonical_path=primary_path,
                    method=primary_method,
                    param="header:Strict-Transport-Security",
                    payload="Passive HTTP Header Audit",
                    evidence=f"HTTP {primary_resp.status_code} response from `{primary_path}` omits `Strict-Transport-Security` header.",
                    status_code=primary_resp.status_code,
                    phase="Phase-B-Passive",
                )
            )

        # 5. Inspect all responses for Insecure Cookie Flags, Wildcard CORS, and Server/Version Disclosure
        cookie_flagged = False
        cors_flagged = False
        banner_flagged = False

        for (method, path), resp in baseline_responses.items():
            resp_url = str(resp.request.url) if resp.request else urljoin(self.base_url + "/", path.lstrip("/"))
            r_headers = resp.headers

            # Check 5a: Insecure Set-Cookie missing HttpOnly or Secure/SameSite
            if not cookie_flagged:
                set_cookies = r_headers.get_list("set-cookie") if hasattr(r_headers, "get_list") else [r_headers.get("set-cookie", "")]
                for raw_cookie in set_cookies:
                    if not raw_cookie:
                        continue
                    cl = raw_cookie.lower()
                    cookie_name = raw_cookie.split("=", 1)[0].strip()
                    missing_attrs: List[str] = []
                    if "httponly" not in cl:
                        missing_attrs.append("HttpOnly")
                    if "samesite" not in cl:
                        missing_attrs.append("SameSite")
                    if "secure" not in cl:
                        missing_attrs.append("Secure")
                    if missing_attrs:
                        cookie_flagged = True
                        passive_findings.append(
                            CanonicalFinding(
                                source="DAST",
                                scanner_name="cyberforge-dast-phase-b",
                                cwe="CWE-614",
                                title=f"Session Cookie `{cookie_name}` Missing Security Flags ({', '.join(missing_attrs)})",
                                severity="Medium",
                                confidence="High",
                                url=resp_url,
                                canonical_path=path,
                                method=method,
                                param=f"cookie:{cookie_name}",
                                payload="Passive Set-Cookie Audit",
                                evidence=f"`Set-Cookie: {raw_cookie}` omits {', '.join(missing_attrs)}.",
                                status_code=resp.status_code,
                                phase="Phase-B-Passive",
                            )
                        )
                        break

            # Check 5b: Permissive Wildcard CORS (Access-Control-Allow-Origin: *)
            if not cors_flagged:
                acao = r_headers.get("access-control-allow-origin", "").strip()
                if acao == "*":
                    cors_flagged = True
                    passive_findings.append(
                        CanonicalFinding(
                            source="DAST",
                            scanner_name="cyberforge-dast-phase-b",
                            cwe="CWE-942",
                            title="Overly Permissive Cross-Origin Resource Sharing (CORS Wildcard `*`)",
                            severity="Medium",
                            confidence="High",
                            url=resp_url,
                            canonical_path=path,
                            method=method,
                            param="header:Access-Control-Allow-Origin",
                            payload="Passive CORS Audit",
                            evidence=f"Endpoint `{path}` responds with `Access-Control-Allow-Origin: *`.",
                            status_code=resp.status_code,
                            phase="Phase-B-Passive",
                        )
                    )

            # Check 5c: Verbose Server / X-Powered-By Version Banner Disclosure
            if not banner_flagged:
                server_hdr = r_headers.get("server", "").strip()
                powered_by = r_headers.get("x-powered-by", "").strip()
                banner_val = powered_by or (server_hdr if any(ch.isdigit() for ch in server_hdr) or "werkzeug" in server_hdr.lower() else "")
                if banner_val:
                    banner_flagged = True
                    hdr_name = "X-Powered-By" if powered_by else "Server"
                    passive_findings.append(
                        CanonicalFinding(
                            source="DAST",
                            scanner_name="cyberforge-dast-phase-b",
                            cwe="CWE-200",
                            title=f"Verbose Server / Framework Version Disclosure (`{hdr_name}`)",
                            severity="Low",
                            confidence="High",
                            url=resp_url,
                            canonical_path=path,
                            method=method,
                            param=f"header:{hdr_name}",
                            payload="Passive Server Banner Audit",
                            evidence=f"Response header `{hdr_name}: {banner_val}` exposes underlying server/framework version.",
                            status_code=resp.status_code,
                            phase="Phase-B-Passive",
                        )
                    )

        return passive_findings

    # Method aliases matching Task B2.1 naming conventions
    _probe_sqli = _check_sqli_cwe89
    _probe_xss = _check_xss_cwe79
    _probe_cmdi = _check_cmd_injection_cwe78
    _probe_path_traversal = _check_path_traversal_cwe22
    _probe_open_redirect = _check_open_redirect_cwe601


# ---------------------------------------------------------------------------
# Convenience Functional Entrypoints (Async & Sync)
# ---------------------------------------------------------------------------


async def run_dast_scan(
    base_url: str,
    routes: Optional[List[RouteEntry]] = None,
    timeout_seconds: float = 6.0,
    max_concurrency: int = 10,
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    enable_crawl: bool = True,
    enable_passive_checks: bool = True,
    sast_findings: Optional[List[CanonicalFinding]] = None,
    probe_plan: Optional[ScopeReductionReport] = None,
    route_mapper: Optional[Any] = None,
) -> List[CanonicalFinding]:
    """Async entrypoint for running the 2-Phase DAST scanner."""
    scanner = DASTScanner(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        max_concurrency=max_concurrency,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        transport=transport,
        enable_crawl=enable_crawl,
        enable_passive_checks=enable_passive_checks,
    )
    return await scanner.scan(
        routes=routes,
        sast_findings=sast_findings,
        probe_plan=probe_plan,
        route_mapper=route_mapper,
    )


def run_dast_scan_sync(
    base_url: str,
    routes: Optional[List[RouteEntry]] = None,
    **kwargs: Any,
) -> List[CanonicalFinding]:
    """Synchronous convenience wrapper for CLI / script callers."""
    return asyncio.run(run_dast_scan(base_url=base_url, routes=routes, **kwargs))
