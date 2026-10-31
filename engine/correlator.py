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
)
from core.config import CWE_NAMES, CWE_BASE_SEVERITY
from engine.route_mapper import RouteMapper


def _generate_issue_id(prefix: str, cwe: str, primary_key: str) -> str:
    """
    Generates a deterministic 12-char hex hash ID ensuring idempotency (FR-6).
    """
    data = f"{prefix}:{cwe}:{primary_key}"
    return f"ISSUE-{hashlib.sha256(data.encode('utf-8')).hexdigest()[:10].upper()}"


def _get_fix_suggestion(cwe: str, param: Optional[str] = None) -> str:
    p = param or "input"
    if cwe == "CWE-89":
        return (
            f"Use parameterized queries with bound variables instead of string concatenation/f-strings. "
            f"Example: cursor.execute('SELECT * FROM items WHERE {p} = ?', ({p},)) or use ORM parameter binding."
        )
    if cwe == "CWE-79":
        return (
            f"HTML-encode all untrusted input before rendering in templates or responses. "
            f"Avoid render_template_string or markupsafe.Markup on unvalidated user input '{p}'; use html.escape({p})."
        )
    if cwe == "CWE-78":
        return (
            f"Pass arguments as a list with shell=False instead of string commands. "
            f"Example: subprocess.run(['cmd', {p}], shell=False, check=True). Avoid os.system / child_process.exec."
        )
    if cwe == "CWE-22":
        return (
            f"Sanitize filenames using werkzeug.utils.secure_filename({p}) or os.path.basename({p}), and verify that "
            f"os.path.realpath(target_path).startswith(os.path.realpath(BASE_DIR))."
        )
    if cwe == "CWE-601":
        return (
            f"Validate redirect targets against an explicit allowlist of trusted domains or "
            f"ensure the path begins with a single '/' and does not start with '//' or contain external schemes."
        )
    if cwe == "CWE-798":
        return (
            "Never commit secrets or credentials directly in source code. "
            "Load sensitive keys from environment variables (os.environ.get) or a dedicated secrets manager."
        )
    return "Apply principle of least privilege, strict input validation, and context-aware output encoding."


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
    Correlates SAST findings with DAST findings via AST Route Map.
    """

    def __init__(self, route_mapper: RouteMapper):
        self.route_mapper = route_mapper

    @staticmethod
    def _deduplicate_sast_findings(sast_findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        FR-6: Merge multiple SAST findings pointing to the exact same (CWE, file_path, line)
        (e.g. from AST scanner + Bandit/Semgrep or repeated runs) into one canonical finding
        with all evidence attached.
        """
        grouped: Dict[Tuple[str, str, int], CanonicalFinding] = {}
        for f in sast_findings:
            if f.is_protected_decoy:
                continue
            norm_file = (f.file_path or "").replace("\\", "/").lstrip("./")
            key = (f.cwe, norm_file, f.line or 0)
            if key not in grouped:
                cloned = f.model_copy(deep=True)
                cloned.raw_details.setdefault("merged_finding_ids", [f.id])
                grouped[key] = cloned
            else:
                existing = grouped[key]
                merged_ids = existing.raw_details.setdefault("merged_finding_ids", [existing.id])
                if f.id not in merged_ids:
                    merged_ids.append(f.id)
                if not existing.code_snippet and f.code_snippet:
                    existing.code_snippet = f.code_snippet
        return list(grouped.values())

    def _deduplicate_dast_findings(self, dast_findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """
        FR-6: Merge multiple DAST findings targeting the exact same (CWE, route/path, method, param)
        into one canonical DAST finding with all payloads/evidence attached.
        """
        grouped: Dict[Tuple[str, str, str, str], CanonicalFinding] = {}
        for d in dast_findings:
            raw_url = (d.url or "").strip()
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
    def _has_parameter_conflict(sast_snippet: str, dast_param: Optional[str], route_params: List[str]) -> bool:
        """
        Hard Negative Veto 3:
        If a route handler accepts multiple parameters (e.g. 'user' and 'role'),
        and the SAST sink snippet explicitly uses one route parameter ('user') while NOT containing
        the DAST parameter ('role'), veto the link so we never cross-link two different parameters.
        """
        if not dast_param or not sast_snippet or len(route_params) <= 1:
            return False

        snippet_lower = sast_snippet.lower()
        d_param_lower = dast_param.lower()

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
    ) -> List[CorrelatedIssue]:
        """
        Main correlation algorithm:
        1. Suppress B-2 decoys and deduplicate multi-scanner SAST & DAST findings (FR-6).
        2. Match each DAST finding against SAST findings using AST Route Map + 3-hop Call Graph
           with hard negative vetoes (CWE veto, Route/Handler veto, Multi-Parameter conflict veto).
        3. Package matched pairs as 'Confirmed' (FR-7).
        4. Package remaining unlinked SAST findings as 'Code only' (FR-7).
        5. Package remaining unlinked DAST findings as 'Runtime only' (FR-7).
        6. Deduplicate identical issues (FR-6).
        7. Sort by Confirmed first, then risk_score descending (FR-9).
        """
        correlated_issues: List[CorrelatedIssue] = []
        matched_sast_ids: Set[str] = set()
        matched_dast_ids: Set[str] = set()

        # Step 1: Filter out protected decoys (B-2) and deduplicate findings on the same bug (FR-6)
        active_sast = self._deduplicate_sast_findings(sast_findings)
        active_dast = self._deduplicate_dast_findings(dast_findings)

        # Step 2: Correlate DAST findings with SAST findings
        for d in active_dast:
            if not d.url:
                continue

            dast_route = self.route_mapper.match_url(d.method or "GET", d.url)
            if not dast_route:
                continue

            candidates = []
            for s in active_sast:
                if s.id in matched_sast_ids:
                    continue

                # VETO 1: CWE must match exactly
                if s.cwe != d.cwe:
                    continue

                # VETO 2: Code location (file + line) must be inside the route handler or its called helpers
                if s.file_path and s.line:
                    if self.route_mapper.is_line_in_route(s.file_path, s.line, dast_route):
                        # VETO 3: Multi-parameter conflict check
                        if self._has_parameter_conflict(s.code_snippet or "", d.param, dast_route.parameters):
                            continue

                        score = 10  # base match for route + CWE
                        param_match_note = ""
                        if d.param:
                            if s.code_snippet and d.param.lower() in s.code_snippet.lower():
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

                issue_id = _generate_issue_id(
                    "CONF",
                    best_sast.cwe,
                    f"{dast_route.path_pattern}:{best_sast.file_path}:{best_sast.line}",
                )
                issue = CorrelatedIssue(
                    id=issue_id,
                    status=IssueStatus.CONFIRMED,
                    cwe=best_sast.cwe,
                    cwe_name=CWE_NAMES.get(best_sast.cwe, best_sast.cwe),
                    severity=best_sast.severity,
                    risk_score=_compute_risk_score(IssueStatus.CONFIRMED, best_sast.cwe, best_sast.severity),
                    url=d.url,
                    method=d.method,
                    param=d.param,
                    payload=d.payload,
                    file_path=best_sast.file_path,
                    line=best_sast.line,
                    code_snippet=best_sast.code_snippet,
                    link_reason=best_link_reason,
                    fix_suggestion=_get_fix_suggestion(best_sast.cwe, d.param),
                    sast_finding=best_sast,
                    dast_finding=d,
                    estimated_exposure_inr=5000000.0 if best_sast.cwe in ("CWE-89", "CWE-78") else 1500000.0,
                    sebi_sla_days=7 if best_sast.severity == Severity.CRITICAL else 30,
                )
                correlated_issues.append(issue)

        # Step 3: Remaining SAST findings become 'Code only' (FR-7)
        for s in active_sast:
            if s.id not in matched_sast_ids:
                issue_id = _generate_issue_id("CODE", s.cwe, f"{s.file_path}:{s.line}")
                issue = CorrelatedIssue(
                    id=issue_id,
                    status=IssueStatus.CODE_ONLY,
                    cwe=s.cwe,
                    cwe_name=CWE_NAMES.get(s.cwe, s.cwe),
                    severity=s.severity,
                    risk_score=_compute_risk_score(IssueStatus.CODE_ONLY, s.cwe, s.severity),
                    file_path=s.file_path,
                    line=s.line,
                    code_snippet=s.code_snippet,
                    link_reason="Code only: Vulnerable code pattern detected by SAST, not yet proven at runtime",
                    fix_suggestion=_get_fix_suggestion(s.cwe),
                    sast_finding=s,
                    dast_finding=None,
                    estimated_exposure_inr=500000.0,
                    sebi_sla_days=90,
                )
                correlated_issues.append(issue)

        # Step 4: Remaining DAST findings become 'Runtime only' (FR-7)
        for d in active_dast:
            if d.id not in matched_dast_ids:
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
                    method=d.method,
                    param=d.param,
                    payload=d.payload,
                    code_snippet=None,
                    link_reason="Runtime only: Exploit proven at runtime, but no corresponding AST sink located",
                    fix_suggestion=_get_fix_suggestion(d.cwe, d.param),
                    sast_finding=None,
                    dast_finding=d,
                    estimated_exposure_inr=1000000.0,
                    sebi_sla_days=30,
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
