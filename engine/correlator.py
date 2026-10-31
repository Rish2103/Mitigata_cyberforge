"""
Deterministic Multi-Signal Correlation and Deduplication Engine.
Implements:
- FR-5: Link DAST finding to SAST finding based on (CWE match + Route/Handler match + Parameter/Sink line)
- FR-6: Deterministic Deduplication (merging multiple scanner findings on the same bug, idempotent scans)
- FR-7: 3-Bucket Categorisation (Confirmed, Code only, Runtime only)
- FR-8: Consolidated Issue Detail
- FR-9: Prioritised Risk Scoring (Confirmed first, then Exploitability Risk Score 0-100)
- B-3: Plain-English Link Explanation Badges
- B-4: Remediation / Fix Suggestions

Enforces Charlie Munger's Zero Wrong Links rule (<5% target):
Strict hard negative vetoes prevent joining two different bugs.
"""

import hashlib
import re
from typing import List, Dict, Optional, Tuple, Set
from core.schemas import (
    CanonicalFinding,
    CorrelatedIssue,
    IssueStatus,
    Severity,
    RouteEntry,
    ScopeReductionReport,
)
from core.config import CWE_NAMES, CWE_BASE_SEVERITY
from engine.route_mapper import RouteMapper
from engine.scope_reducer import compute_scope_reduction


def _generate_issue_id(prefix: str, cwe: str, primary_key: str) -> str:
    """
    Generates a deterministic 12-char hex hash ID ensuring idempotency (FR-6).
    """
    data = f"{prefix}:{cwe}:{primary_key}"
    return f"ISSUE-{hashlib.sha256(data.encode('utf-8')).hexdigest()[:10].upper()}"


def _get_fix_suggestion(
    cwe: str,
    param: Optional[str] = None,
    code_snippet: Optional[str] = None,
) -> str:
    """
    B-4: Context-Aware Remediation Generator.
    Produces plain-English remediation advice plus concrete Before (Vulnerable) / After (Fixed)
    code diff lines tailored to the actual sink snippet and tainted parameter.
    """
    p = param or "user_input"
    snippet_clean = (code_snippet or "").strip()

    if cwe == "CWE-89":
        before_line = snippet_clean or f'cursor.execute(f"SELECT * FROM records WHERE {p} = \'{{{p}}}\'")'
        after_line = f'cursor.execute("SELECT * FROM records WHERE {p} = ?", ({p},))'
        if "express" in before_line.lower() or "db.query" in before_line:
            after_line = f'db.query("SELECT * FROM records WHERE {p} = ?", [{p}])'
        return (
            f"Use parameterized queries with bound variables instead of string concatenation/f-strings. "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-79":
        before_line = snippet_clean or f'return render_template_string(f"<div>{{{p}}}</div>")'
        after_line = f'return render_template("view.html", {p}=markupsafe.escape({p}))'
        if "res.send" in before_line:
            after_line = f"res.send(`<div>${{escapeHtml({p})}}</div>`)"
        return (
            f"HTML-encode all untrusted input before rendering in templates or responses. "
            f"Avoid render_template_string or markupsafe.Markup on unvalidated input '{p}'. "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-78":
        before_line = snippet_clean or f'subprocess.check_output(f"cmd {{{p}}}", shell=True)'
        after_line = f'subprocess.run(["cmd", {p}], shell=False, check=True, capture_output=True, text=True)'
        if "exec(" in before_line:
            after_line = f'execFile("cmd", [{p}], callback)'
        return (
            f"Pass arguments as an argument list with shell=False instead of shell command strings. "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-22":
        before_line = snippet_clean or f'open(os.path.join(BASE_DIR, {p}), "r").read()'
        after_line = (
            f'safe_path = os.path.realpath(os.path.join(BASE_DIR, secure_filename({p}))); '
            f'assert safe_path.startswith(os.path.realpath(BASE_DIR))'
        )
        return (
            f"Sanitize filenames using werkzeug.utils.secure_filename({p}) or os.path.basename({p}), and verify that "
            f"os.path.realpath(target_path).startswith(os.path.realpath(BASE_DIR)). "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-601":
        before_line = snippet_clean or f"return redirect({p})"
        after_line = (
            f'parsed = urlparse({p}); '
            f'return redirect({p} if (not parsed.scheme and not parsed.netloc and {p}.startswith("/")) else "/")'
        )
        return (
            f"Validate redirect targets against an explicit allowlist of trusted domains or "
            f"ensure the path is strictly relative (starts with '/' and not '//'). "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-798":
        before_line = snippet_clean or 'SECRET_KEY = "sk_live_hardcoded_secret"'
        var_name = before_line.split("=")[0].strip() if "=" in before_line else "SECRET_KEY"
        after_line = f'{var_name} = os.environ["{var_name}"]'
        return (
            "Never commit secrets or credentials directly in source code. "
            "Load sensitive keys from environment variables (os.environ) or a secrets manager. "
            f"Before: `{before_line}` -> After: `{after_line}`"
        )
    if cwe == "CWE-693":
        return (
            "Add Content-Security-Policy and X-Content-Type-Options: nosniff response headers via middleware. "
            "Before: `response.headers (missing CSP)` -> "
            "After: `response.headers['Content-Security-Policy'] = \"default-src 'self'\"`"
        )
    if cwe == "CWE-614":
        return (
            "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all session cookies. "
            "Before: `response.set_cookie('session_id', token)` -> "
            "After: `response.set_cookie('session_id', token, httponly=True, secure=True, samesite='Lax')`"
        )
    if cwe == "CWE-1021":
        return (
            "Prevent clickjacking by setting X-Frame-Options: DENY or CSP frame-ancestors 'none'. "
            "Before: `response.headers (missing X-Frame-Options)` -> "
            "After: `response.headers['X-Frame-Options'] = 'DENY'`"
        )
    if cwe == "CWE-942":
        return (
            "Replace wildcard Access-Control-Allow-Origin: * with an explicit origin allowlist. "
            "Before: `Access-Control-Allow-Origin: *` -> "
            "After: `Access-Control-Allow-Origin: https://trusted.example.com`"
        )
    return "Apply principle of least privilege, strict input validation, and context-aware output encoding."


def _generate_contextual_remediation_diff(
    cwe: str,
    param: Optional[str] = None,
    code_snippet: Optional[str] = None,
    file_path: Optional[str] = None,
    line: Optional[int] = None,
) -> str:
    """
    Generates a unified diff (`--- a/...` / `+++ b/...`) using the actual file path,
    line number, parameter name, and vulnerable code snippet.
    """
    target_file = (file_path or "app.py").replace("\\", "/").lstrip("./")
    line_no = line or 1
    p = param or "user_input"
    snippet_clean = (code_snippet or "").strip().splitlines()[0].strip() if code_snippet else ""

    if cwe == "CWE-89":
        before = snippet_clean or f'cursor.execute(f"SELECT * FROM table WHERE {p} = \'{{{p}}}\'")'
        after = f'cursor.execute("SELECT * FROM table WHERE {p} = ?", ({p},))'
    elif cwe == "CWE-79":
        before = snippet_clean or f'return render_template_string(f"<div>{{{p}}}</div>")'
        after = f'return render_template_string("<div>{{{{ {p} }}}}</div>", {p}={p})'
    elif cwe == "CWE-78":
        before = snippet_clean or f'subprocess.check_output(f"cmd {{{p}}}", shell=True)'
        after = f'subprocess.run(["cmd", {p}], shell=False, check=True, capture_output=True, text=True)'
    elif cwe == "CWE-22":
        before = snippet_clean or f'send_file(f"{{UPLOAD_DIR}}/{{{p}}}")'
        after = f'send_file(os.path.realpath(os.path.join(UPLOAD_DIR, secure_filename({p}))))'
    elif cwe == "CWE-601":
        before = snippet_clean or f"return redirect({p})"
        after = f'return redirect({p} if ({p}.startswith("/") and not {p}.startswith("//")) else "/")'
    elif cwe == "CWE-798":
        before = snippet_clean or 'SECRET_KEY = "sk_live_hardcoded_secret"'
        var_name = before.split("=")[0].strip() if "=" in before else "SECRET_KEY"
        after = f'{var_name} = os.environ["{var_name}"]'
    else:
        before = snippet_clean or "# missing security control"
        after = _get_fix_suggestion(cwe, param, code_snippet)

    return (
        f"--- a/{target_file}\n"
        f"+++ b/{target_file}\n"
        f"@@ -{line_no},1 +{line_no},1 @@\n"
        f"-    {before}\n"
        f"+    {after}"
    )


def _attach_bridge_attributes(
    issue: CorrelatedIssue,
    *,
    confidence: str,
    signals_matched: List[str],
    sast_finding_ids: List[str],
    dast_finding_ids: List[str],
) -> CorrelatedIssue:
    """
    Populates both Person A and Person B bridge attributes on `CorrelatedIssue`
    without modifying the frozen `core/schemas.py` model definition.
    """
    rem_diff = _generate_contextual_remediation_diff(
        cwe=issue.cwe,
        param=issue.param,
        code_snippet=issue.code_snippet,
        file_path=issue.file_path,
        line=issue.line,
    )
    issue.__dict__.update(
        {
            "remediation": issue.fix_suggestion,
            "remediation_text": issue.fix_suggestion,
            "remediation_code_diff": rem_diff,
            "correlation_reason": issue.link_reason,
            "confidence": confidence,
            "signals_matched": list(signals_matched),
            "sast_finding_ids": list(sast_finding_ids),
            "dast_finding_ids": list(dast_finding_ids),
            "sast_findings": list(issue.sast_evidence),
            "dast_findings": list(issue.dast_evidence),
        }
    )
    return issue


def _compute_risk_score(status: IssueStatus, cwe: str, severity: Severity) -> float:
    """
    Computes exploitability risk score (0-100) per FR-9:
    - Confirmed issues rank highest (proven at runtime + code located)
    - Runtime only issues next (proven attack surface)
    - Code only issues third (static warning, unproven exploit)
    """
    base_sev, base_score = CWE_BASE_SEVERITY.get(cwe, (severity.value, 60.0))

    status_multiplier = {
        IssueStatus.CONFIRMED: 1.0,      # Proven exploitable in running environment
        IssueStatus.RUNTIME_ONLY: 0.85,  # Proven running weakness, no line of code located yet
        IssueStatus.CODE_ONLY: 0.70,     # Unproven static warning
    }.get(status, 0.70)

    score = round(base_score * status_multiplier, 1)
    return min(100.0, max(0.0, score))


class Correlator:
    """
    Correlates SAST findings with DAST findings via AST Route Map,
    and computes Runtime-Verified Adaptive DAST Scope Reduction (Checkpoint 1 Judge Feedback).
    """

    def __init__(
        self,
        route_mapper: Optional[RouteMapper] = None,
        source_dir: Optional[str] = None,
        routes: Optional[List[RouteEntry]] = None,
    ):
        if route_mapper is not None:
            self.route_mapper = route_mapper
        elif source_dir:
            self.route_mapper = RouteMapper(source_dir)
            self.route_mapper.scan()
            if routes and not self.route_mapper.routes:
                self.route_mapper = RouteMapper.from_routes(routes, root_dir=source_dir)
        elif routes is not None:
            self.route_mapper = RouteMapper.from_routes(routes)
        else:
            self.route_mapper = RouteMapper.from_routes([])
        self.last_scope_reduction: Optional[ScopeReductionReport] = None

    def compute_dast_scope(
        self,
        sast_findings: List[CanonicalFinding],
        live_endpoints: Optional[List[Tuple[str, str]]] = None,
    ) -> ScopeReductionReport:
        """
        Computes the Runtime-Verified Adaptive DAST Scope Reduction report
        from the current AST Route Map, SAST findings, and discovered runtime endpoints.
        """
        self.last_scope_reduction = compute_scope_reduction(
            routes=self.route_mapper.routes,
            sast_findings=sast_findings,
            live_endpoints=live_endpoints,
            route_mapper=self.route_mapper,
        )
        return self.last_scope_reduction

    @staticmethod
    def _deduplicate_sast_findings(sast_findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        FR-6: Merge multiple SAST findings pointing to the exact same (CWE, file_path, line)
        (e.g. from AST scanner + Bandit/Semgrep or repeated runs) into one canonical finding
        with all evidence attached.
        """
        grouped: Dict[Tuple[str, str, int, str], CanonicalFinding] = {}
        for f in sast_findings:
            if f.is_protected_decoy:
                continue
            norm_file = (f.file_path or f.file or "").replace("\\", "/").lstrip("./")
            norm_param = (f.param or "").strip().lower()
            # Group by (cwe, norm_file, line) when param is empty or matches existing group
            base_key = (f.cwe, norm_file, f.line or 0, norm_param)
            fallback_key = (f.cwe, norm_file, f.line or 0, "")
            target_key = base_key
            if base_key not in grouped and fallback_key in grouped:
                target_key = fallback_key
            elif norm_param == "":
                for gk in grouped:
                    if gk[0] == f.cwe and gk[1] == norm_file and gk[2] == (f.line or 0):
                        target_key = gk
                        break

            if target_key not in grouped:
                cloned = f.model_copy(deep=True)
                cloned.raw_details.setdefault("merged_finding_ids", [f.id])
                grouped[target_key] = cloned
            else:
                existing = grouped[target_key]
                merged_ids = existing.raw_details.setdefault("merged_finding_ids", [existing.id])
                if f.id not in merged_ids:
                    merged_ids.append(f.id)
                if not existing.code_snippet and f.code_snippet:
                    existing.code_snippet = f.code_snippet
                    existing.snippet = f.code_snippet
                if not existing.param and f.param:
                    existing.param = f.param
        return list(grouped.values())

    def _deduplicate_dast_findings(self, dast_findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        FR-6: Merge multiple DAST findings targeting the exact same (CWE, route/path, method, param)
        into one canonical DAST finding with all payloads/evidence attached.
        """
        grouped: Dict[Tuple[str, str, str, str], CanonicalFinding] = {}
        for d in dast_findings:
            raw_url = (d.url or d.canonical_path or "").strip()
            clean_url = raw_url.split("?")[0].rstrip("/") or "/"
            matched_route = self.route_mapper.match_url(d.method or "GET", raw_url) if raw_url else None
            route_key = matched_route.path_pattern if matched_route else clean_url
            norm_method = (d.method or "GET").upper()
            norm_param = (d.param or "").strip().lower()
            key = (d.cwe, route_key, norm_method, norm_param)

            if key not in grouped:
                cloned = d.model_copy(deep=True)
                cloned.raw_details.setdefault("merged_finding_ids", [d.id])
                if d.evidence:
                    cloned.raw_details.setdefault("all_evidence", [d.evidence])
                if d.payload:
                    cloned.raw_details.setdefault("all_payloads", [d.payload])
                grouped[key] = cloned
            else:
                existing = grouped[key]
                merged_ids = existing.raw_details.setdefault("merged_finding_ids", [existing.id])
                if d.id not in merged_ids:
                    merged_ids.append(d.id)
                if d.evidence:
                    ev_list = existing.raw_details.setdefault("all_evidence", [])
                    if d.evidence not in ev_list:
                        ev_list.append(d.evidence)
                if d.payload:
                    pl_list = existing.raw_details.setdefault("all_payloads", [])
                    if d.payload not in pl_list:
                        pl_list.append(d.payload)
        return list(grouped.values())

    @staticmethod
    def _has_parameter_conflict(
        sast_snippet: str,
        dast_param: Optional[str],
        route_params: List[str],
        sast_param: Optional[str] = None,
    ) -> bool:
        """
        Hard Negative Veto 3:
        If a route handler accepts multiple parameters (e.g. 'user' and 'role'),
        and the SAST sink (either via inferred `sast_param` or `sast_snippet`) explicitly uses
        one route parameter ('user') while NOT matching the DAST parameter ('role'),
        veto the link so we never cross-link two different parameters.
        """
        if not dast_param or len(route_params) <= 1:
            return False

        d_param_lower = dast_param.strip().lower()
        route_params_lower = {rp.lower() for rp in route_params if rp}

        if sast_param:
            s_param_lower = sast_param.strip().lower()
            if s_param_lower == d_param_lower:
                return False
            if s_param_lower in route_params_lower and s_param_lower != d_param_lower:
                return True

        if not sast_snippet:
            return False

        snippet_lower = sast_snippet.lower()

        # If the DAST parameter itself appears in the snippet, there is no conflict
        if d_param_lower in snippet_lower:
            return False

        # Check if any OTHER route parameter explicitly appears as a whole identifier in the sink snippet
        for rp in route_params:
            rp_lower = rp.lower()
            if rp_lower != d_param_lower and len(rp_lower) >= 2:
                if re.search(rf"\b{re.escape(rp_lower)}\b", snippet_lower):
                    return True
        return False

    def correlate(
        self,
        sast_findings: List[CanonicalFinding],
        dast_findings: List[CanonicalFinding],
        live_endpoints: Optional[List[Tuple[str, str]]] = None,
    ) -> List[CorrelatedIssue]:
        """
        Main correlation algorithm:
        0. Compute Runtime-Verified Adaptive DAST Scope Reduction report (Checkpoint 1 Judge Feedback).
        1. Suppress B-2 decoys and deduplicate multi-scanner SAST & DAST findings (FR-6).
        2. Match each DAST finding against SAST findings using AST Route Map + 3-hop Call Graph
           with hard negative vetoes (CWE veto, Route/Handler veto, Multi-Parameter conflict veto).
        3. Package matched pairs as 'Confirmed' (FR-7).
        4. Package remaining unlinked SAST findings as 'Code only' (FR-7).
        5. Package remaining unlinked DAST findings as 'Runtime only' (FR-7).
        6. Deduplicate identical issues (FR-6).
        7. Sort by Confirmed first, then risk_score descending (FR-9).
        """
        self.compute_dast_scope(sast_findings, live_endpoints=live_endpoints)

        correlated_issues: List[CorrelatedIssue] = []
        matched_sast_ids: Set[str] = set()
        matched_dast_ids: Set[str] = set()

        # Build lookup maps from finding ID -> CanonicalFinding for full multi-scanner evidence lists
        raw_sast_by_id: Dict[str, CanonicalFinding] = {
            f.id: f for f in sast_findings if not f.is_protected_decoy
        }
        raw_dast_by_id: Dict[str, CanonicalFinding] = {d.id: d for d in dast_findings}

        # Step 1: Filter out protected decoys (B-2) and deduplicate findings on the same bug (FR-6)
        active_sast = self._deduplicate_sast_findings(sast_findings)
        active_dast = self._deduplicate_dast_findings(dast_findings)

        # Sort DAST findings so concrete parameter probes are matched before parameterless findings
        active_dast_sorted = sorted(
            active_dast,
            key=lambda df: (0 if df.param else 1),
        )

        # Step 2: Correlate DAST findings with SAST findings
        for d in active_dast_sorted:
            target_url = d.url or d.canonical_path or ""
            if not target_url:
                continue

            dast_route = self.route_mapper.match_url(d.method or "GET", target_url)
            if not dast_route:
                continue

            candidates = []
            for s in active_sast:
                if s.id in matched_sast_ids:
                    continue

                # VETO 1: CWE must match exactly
                if s.cwe != d.cwe:
                    continue

                # VETO 3: Code location (file + line) must be inside the route handler or its called helpers
                if s.file_path and s.line:
                    if self.route_mapper.is_line_in_route(s.file_path, s.line, dast_route):
                        # VETO 4: Multi-parameter snippet & inferred param conflict check
                        if self._has_parameter_conflict(
                            s.code_snippet or "",
                            d.param,
                            dast_route.parameters,
                            sast_param=s.param,
                        ):
                            continue

                        score = 10  # base match for route + CWE
                        param_match_note = ""
                        if d.param:
                            if s.param and d.param.lower() == s.param.lower():
                                score += 25
                                param_match_note = f" + Parameter '{d.param}' verified in sink call"
                            elif s.code_snippet and d.param.lower() in s.code_snippet.lower():
                                score += 20
                                param_match_note = f" + Parameter '{d.param}' verified in sink call"
                            elif dast_route.parameters and d.param.lower() in [p.lower() for p in dast_route.parameters]:
                                score += 10
                                param_match_note = f" + Parameter '{d.param}' verified in handler"

                        link_reason = (
                            f"Matched {s.cwe} on Route {dast_route.path_pattern} ({dast_route.method}) "
                            f"handled by {dast_route.func_name}() lines {dast_route.start_line}-{dast_route.end_line} "
                            f"calling sink at {s.file_path}:{s.line}{param_match_note}"
                        )
                        candidates.append((score, s, link_reason))

            best_sast = None
            best_link_reason = ""
            if candidates:
                candidates.sort(key=lambda c: c[0], reverse=True)
                _, best_sast, best_link_reason = candidates[0]

            if best_sast:
                matched_sast_ids.add(best_sast.id)
                matched_dast_ids.add(d.id)

                sast_merged_ids = best_sast.raw_details.get("merged_finding_ids", [best_sast.id])
                dast_merged_ids = d.raw_details.get("merged_finding_ids", [d.id])
                sast_ev = [raw_sast_by_id[fid] for fid in sast_merged_ids if fid in raw_sast_by_id] or [best_sast]
                dast_ev = [raw_dast_by_id[fid] for fid in dast_merged_ids if fid in raw_dast_by_id] or [d]
                effective_param = d.param or best_sast.param
                effective_sev = (
                    Severity.CRITICAL
                    if (d.severity == Severity.CRITICAL or best_sast.severity == Severity.CRITICAL)
                    else best_sast.severity
                )
                route_desc = (
                    f"{dast_route.method} {dast_route.path_pattern} -> "
                    f"{dast_route.func_name}(), {dast_route.file_path}:{dast_route.start_line}-{dast_route.end_line}"
                )

                issue_id = _generate_issue_id(
                    "CONF",
                    best_sast.cwe,
                    f"{dast_route.path_pattern}:{best_sast.file_path}:{best_sast.line}:{effective_param or ''}",
                )
                issue = CorrelatedIssue(
                    id=issue_id,
                    status=IssueStatus.CONFIRMED,
                    cwe=best_sast.cwe,
                    cwe_name=CWE_NAMES.get(best_sast.cwe, best_sast.cwe),
                    severity=effective_sev,
                    risk_score=_compute_risk_score(IssueStatus.CONFIRMED, best_sast.cwe, effective_sev),
                    url=d.url,
                    canonical_path=dast_route.canonical_path,
                    method=d.method or dast_route.method,
                    param=effective_param,
                    payload=d.payload,
                    evidence=d.evidence,
                    file_path=best_sast.file_path,
                    line=best_sast.line,
                    func_name=best_sast.func_name or dast_route.func_name,
                    code_snippet=best_sast.code_snippet,
                    matched_route=route_desc,
                    link_reason=best_link_reason,
                    fix_suggestion=_get_fix_suggestion(
                        best_sast.cwe,
                        d.param or best_sast.param,
                        best_sast.code_snippet,
                    ),
                    sast_finding=best_sast,
                    dast_finding=d,
                    sast_evidence=sast_ev,
                    dast_evidence=dast_ev,
                    finding_count=len(sast_ev) + len(dast_ev),
                    estimated_exposure_inr=5000000.0 if best_sast.cwe in ("CWE-89", "CWE-78") else 1500000.0,
                    sebi_sla_days=7 if effective_sev == Severity.CRITICAL else 30,
                )
                _attach_bridge_attributes(
                    issue,
                    confidence="HIGH",
                    signals_matched=["route", "cwe", "parameter"] if effective_param else ["route", "cwe"],
                    sast_finding_ids=[f.id for f in sast_ev],
                    dast_finding_ids=[f.id for f in dast_ev],
                )
                correlated_issues.append(issue)

        # Step 3: Remaining SAST findings become 'Code only' (FR-7)
        for s in active_sast:
            if s.id not in matched_sast_ids:
                sast_merged_ids = s.raw_details.get("merged_finding_ids", [s.id])
                sast_ev = [raw_sast_by_id[fid] for fid in sast_merged_ids if fid in raw_sast_by_id] or [s]
                issue_id = _generate_issue_id("CODE", s.cwe, f"{s.file_path}:{s.line}:{s.param or ''}")
                issue = CorrelatedIssue(
                    id=issue_id,
                    status=IssueStatus.CODE_ONLY,
                    cwe=s.cwe,
                    cwe_name=CWE_NAMES.get(s.cwe, s.cwe),
                    severity=s.severity,
                    risk_score=_compute_risk_score(IssueStatus.CODE_ONLY, s.cwe, s.severity),
                    file_path=s.file_path,
                    line=s.line,
                    func_name=s.func_name,
                    param=s.param,
                    code_snippet=s.code_snippet,
                    link_reason="Code only: Vulnerable code pattern detected by SAST, not yet proven at runtime",
                    fix_suggestion=_get_fix_suggestion(s.cwe, s.param, s.code_snippet),
                    sast_finding=s,
                    dast_finding=None,
                    sast_evidence=sast_ev,
                    dast_evidence=[],
                    finding_count=len(sast_ev),
                    estimated_exposure_inr=500000.0,
                    sebi_sla_days=90,
                )
                _attach_bridge_attributes(
                    issue,
                    confidence="MEDIUM",
                    signals_matched=["sast_sink", "cwe"],
                    sast_finding_ids=[f.id for f in sast_ev],
                    dast_finding_ids=[],
                )
                correlated_issues.append(issue)

        # Step 4: Remaining DAST findings become 'Runtime only' (FR-7)
        for d in active_dast:
            if d.id not in matched_dast_ids:
                dast_merged_ids = d.raw_details.get("merged_finding_ids", [d.id])
                dast_ev = [raw_dast_by_id[fid] for fid in dast_merged_ids if fid in raw_dast_by_id] or [d]
                target_url = d.url or d.canonical_path or ""
                matched_r = self.route_mapper.match_url(d.method or "GET", target_url) if target_url else None
                resolved_canonical = matched_r.canonical_path if matched_r else d.canonical_path
                key = f"{d.url}:{d.param or 'header'}:{d.cwe}"
                issue_id = _generate_issue_id("RUNTIME", d.cwe, key)
                issue = CorrelatedIssue(
                    id=issue_id,
                    status=IssueStatus.RUNTIME_ONLY,
                    cwe=d.cwe,
                    cwe_name=CWE_NAMES.get(d.cwe, d.cwe),
                    severity=d.severity,
                    risk_score=_compute_risk_score(IssueStatus.RUNTIME_ONLY, d.cwe, d.severity),
                    url=d.url,
                    canonical_path=resolved_canonical,
                    method=d.method,
                    param=d.param,
                    payload=d.payload,
                    evidence=d.evidence,
                    code_snippet=None,
                    link_reason="Runtime only: Exploit proven at runtime, but no corresponding AST sink located",
                    fix_suggestion=_get_fix_suggestion(d.cwe, d.param),
                    sast_finding=None,
                    dast_finding=d,
                    sast_evidence=[],
                    dast_evidence=dast_ev,
                    finding_count=len(dast_ev),
                    estimated_exposure_inr=1000000.0,
                    sebi_sla_days=30,
                )
                _attach_bridge_attributes(
                    issue,
                    confidence="MEDIUM",
                    signals_matched=["runtime_probe", "cwe"],
                    sast_finding_ids=[],
                    dast_finding_ids=[f.id for f in dast_ev],
                )
                correlated_issues.append(issue)

        # Step 5: FR-6 Deduplication: ensure unique issue IDs
        unique_issues: Dict[str, CorrelatedIssue] = {}
        for item in correlated_issues:
            if item.id not in unique_issues:
                unique_issues[item.id] = item

        # Step 6: FR-9 Prioritised list:
        # Sort Confirmed first, then by risk_score descending
        status_priority = {
            IssueStatus.CONFIRMED: 0,
            IssueStatus.RUNTIME_ONLY: 1,
            IssueStatus.CODE_ONLY: 2,
        }

        sorted_issues = sorted(
            unique_issues.values(),
            key=lambda x: (status_priority.get(x.status, 3), -x.risk_score),
        )

        return sorted_issues


def correlate_findings(
    routes: List[RouteEntry],
    sast_findings: List[CanonicalFinding],
    dast_findings: List[CanonicalFinding],
    source_dir: Optional[str] = None,
    live_endpoints: Optional[List[Tuple[str, str]]] = None,
    route_mapper: Optional[RouteMapper] = None,
) -> List[CorrelatedIssue]:
    """
    Module-level correlation entrypoint invoked by api/main.py.
    Uses an existing RouteMapper (with full 3-hop call graph) when provided,
    or constructs a RouteMapper from `source_dir` or `routes`.
    """
    if route_mapper is not None:
        mapper = route_mapper
    elif source_dir:
        mapper = RouteMapper(source_dir)
        mapper.scan()
        if routes and not mapper.routes:
            mapper = RouteMapper.from_routes(routes, root_dir=source_dir)
    else:
        mapper = RouteMapper.from_routes(routes)

    if routes and not mapper.routes:
        mapper = RouteMapper.from_routes(routes, root_dir=getattr(mapper, "root_dir", "."))

    engine = Correlator(route_mapper=mapper, source_dir=source_dir, routes=routes)
    return engine.correlate(sast_findings, dast_findings, live_endpoints=live_endpoints)



