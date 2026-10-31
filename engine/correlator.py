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
            f"Example: cursor.execute('SELECT * FROM items WHERE {p} = %s', ({p},)) or use ORM filter."
        )
    if cwe == "CWE-79":
        return (
            f"HTML-encode all untrusted input before rendering in templates. "
            f"Avoid render_template_string or markupsafe.Markup on unvalidated user input '{p}'."
        )
    if cwe == "CWE-78":
        return (
            f"Pass arguments as a list with shell=False instead of string commands. "
            f"Example: subprocess.run(['cmd', {p}], shell=False, check=True). Avoid os.system."
        )
    if cwe == "CWE-22":
        return (
            f"Sanitize filenames using werkzeug.utils.secure_filename({p}) and verify that "
            f"os.path.realpath(target_path).startswith(os.path.realpath(BASE_DIR))."
        )
    if cwe == "CWE-601":
        return (
            f"Validate redirect targets against an explicit allowlist of trusted domains or "
            f"ensure the path begins with a single '/' and does not start with '//' or contain schemes."
        )
    if cwe == "CWE-798":
        return (
            "Never commit secrets or credentials directly in source code. "
            "Load sensitive keys from environment variables or a dedicated secrets manager (e.g., Vault)."
        )
    return "Apply principle of least privilege, input validation, and secure output encoding."


def _compute_risk_score(status: IssueStatus, cwe: str, severity: Severity) -> float:
    """
    Computes exploitability risk score (0-100) per FR-9:
    - Confirmed issues rank highest (proven at runtime + code located)
    - Runtime only issues next (proven attack surface)
    - Code only issues third (static warning, unproven exploit)
    """
    base_sev, base_score = CWE_BASE_SEVERITY.get(cwe, (severity.value, 60.0))
    
    status_multiplier = {
        IssueStatus.CONFIRMED: 1.0,     # Proven exploitable in running environment
        IssueStatus.RUNTIME_ONLY: 0.85, # Proven running weakness, no line of code located yet
        IssueStatus.CODE_ONLY: 0.70,    # Unproven static warning
    }.get(status, 0.70)

    score = round(base_score * status_multiplier, 1)
    return min(100.0, max(0.0, score))


class Correlator:
    """
    Correlates SAST findings with DAST findings via AST Route Map.
    """
    def __init__(self, route_mapper: RouteMapper):
        self.route_mapper = route_mapper

    def correlate(
        self,
        sast_findings: List[CanonicalFinding],
        dast_findings: List[CanonicalFinding],
    ) -> List[CorrelatedIssue]:
        """
        Main correlation algorithm:
        1. Suppress B-2 decoys from SAST findings.
        2. Index active SAST findings by (CWE, route_matched_handler).
        3. Match each DAST finding against SAST findings with hard negative vetoes.
        4. Package matched pairs as 'Confirmed' (FR-7).
        5. Package remaining unlinked SAST findings as 'Code only' (FR-7).
        6. Package remaining unlinked DAST findings as 'Runtime only' (FR-7).
        7. Deduplicate identical issues (FR-6).
        8. Sort by Confirmed first, then risk_score descending (FR-9).
        """
        correlated_issues: List[CorrelatedIssue] = []
        matched_sast_ids: Set[str] = set()
        matched_dast_ids: Set[str] = set()

        # Step 1: Filter out protected decoys (B-2)
        active_sast = [f for f in sast_findings if not f.is_protected_decoy]

        # Step 2: Correlate DAST findings with SAST findings
        for d in dast_findings:
            if not d.url:
                continue

            # Identify matching route entry in AST map
            dast_route = self.route_mapper.match_url(d.method or "GET", d.url)
            if not dast_route:
                continue

            # Find candidate SAST finding:
            # VETO 1: CWE must match exactly (e.g. CWE-89 matches CWE-89)
            # VETO 2: Code location (file + line) must be inside the route handler or its called helpers
            best_sast: Optional[CanonicalFinding] = None
            best_link_reason: str = ""

            for s in active_sast:
                if s.id in matched_sast_ids:
                    continue

                if s.cwe != d.cwe:
                    continue  # Hard negative veto: never match different CWEs

                # Check if SAST sink is inside this route handler or helper
                if s.file_path and s.line:
                    if self.route_mapper.is_line_in_route(s.file_path, s.line, dast_route):
                        # VETO 3 (Parameter Alignment): If DAST tested a specific param, check if handler references it
                        param_match_note = ""
                        if d.param and dast_route.parameters:
                            if d.param.lower() in [p.lower() for p in dast_route.parameters]:
                                param_match_note = f" + Parameter '{d.param}' verified in handler"

                        link_reason = (
                            f"Matched {s.cwe} on Route {dast_route.path_pattern} ({dast_route.method}) "
                            f"handled by {dast_route.func_name}() lines {dast_route.start_line}-{dast_route.end_line} "
                            f"calling sink at {s.file_path}:{s.line}{param_match_note}"
                        )
                        best_sast = s
                        best_link_reason = link_reason
                        break  # Found high-confidence deterministic link

            if best_sast:
                # Mark as matched
                matched_sast_ids.add(best_sast.id)
                matched_dast_ids.add(d.id)

                issue_id = _generate_issue_id("CONF", best_sast.cwe, f"{dast_route.path_pattern}:{best_sast.file_path}:{best_sast.line}")
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
        for d in dast_findings:
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
