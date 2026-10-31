"""
api/sarif_exporter.py - OASIS SARIF v2.1.0 Exporter and CI/CD Gate Evaluator (Task B3.1, B-6).

Exports correlated SAST+DAST issues (`CorrelatedIssue`) and Reachability-Aware SCA
advisories (`SCAFinding`) into a GitHub Code Scanning / DefectDojo compatible
SARIF v2.1.0 JSON report, and evaluates the deterministic CI/CD security gate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from core.schemas import CorrelatedIssue, SCAFinding, ScanSummary

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}

SEVERITY_TO_SECURITY_SCORE: Dict[str, str] = {
    "Critical": "9.5",
    "High": "8.0",
    "Medium": "5.5",
    "Low": "3.0",
    "Info": "1.0",
}


def _enum_str(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value or "")


def build_sarif_report(
    issues: List[CorrelatedIssue],
    sca_findings: Optional[List[SCAFinding]] = None,
    scan_summary: Optional[ScanSummary] = None,
) -> Dict[str, Any]:
    """
    Build an OASIS SARIF v2.1.0 document containing correlated SAST+DAST issues
    and reachability-evaluated SCA findings.
    """
    sca_list = list(sca_findings or [])
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for issue in issues:
        cwe_id = _enum_str(issue.cwe) or "CWE-000"
        sev_str = _enum_str(issue.severity) or "High"
        status_str = _enum_str(issue.status) or "Code only"
        title_str = issue.title or issue.cwe_name or f"Security Issue ({cwe_id})"
        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(sev_str, "warning")
        sec_score = SEVERITY_TO_SECURITY_SCORE.get(sev_str, "7.0")

        if cwe_id not in rules_by_id:
            rules_by_id[cwe_id] = {
                "id": cwe_id,
                "name": title_str.replace(" ", ""),
                "shortDescription": {"text": title_str},
                "fullDescription": {
                    "text": (
                        f"{title_str} ({cwe_id}) correlated across static AST analysis "
                        f"and 2-phase runtime DAST verification."
                    )
                },
                "help": {
                    "text": issue.fix_suggestion
                    or "Apply parameterized queries, context-aware output encoding, or strict allowlists.",
                },
                "defaultConfiguration": {"level": sarif_level},
                "properties": {
                    "tags": ["security", cwe_id.lower(), "cyberforge-correlate"],
                    "security-severity": sec_score,
                },
            }

        file_uri = issue.file or issue.file_path or (issue.canonical_path or "/").lstrip("/") or "runtime-endpoint"
        line_num = int(issue.line) if issue.line and issue.line > 0 else 1

        location_entry: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_uri,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": line_num,
                },
            }
        }
        if issue.snippet or issue.code_snippet:
            location_entry["physicalLocation"]["region"]["snippet"] = {
                "text": issue.snippet or issue.code_snippet
            }

        msg_parts = [f"[{status_str}] {title_str} ({cwe_id})"]
        if issue.canonical_path or issue.url:
            msg_parts.append(f"Route/URL: {issue.method or 'GET'} {issue.canonical_path or issue.url}")
        if issue.param:
            msg_parts.append(f"Param: {issue.param}")
        if issue.link_reason:
            msg_parts.append(f"Reason: {issue.link_reason}")

        results.append(
            {
                "ruleId": cwe_id,
                "level": sarif_level,
                "message": {"text": " | ".join(msg_parts)},
                "locations": [location_entry],
                "partialFingerprints": {
                    "primaryLocationLineHash": issue.fingerprint,
                },
                "properties": {
                    "id": issue.id,
                    "fingerprint": issue.fingerprint,
                    "status": status_str,
                    "severity": sev_str,
                    "cwe": cwe_id,
                    "url": issue.url,
                    "canonical_path": issue.canonical_path,
                    "method": issue.method,
                    "param": issue.param,
                    "payload": issue.payload,
                    "evidence": issue.evidence,
                    "file": issue.file or issue.file_path,
                    "line": issue.line,
                    "func_name": issue.func_name,
                    "auto_verified": bool(issue.auto_verified),
                    "finding_count": int(issue.finding_count or 1),
                    "risk_score": float(issue.risk_score or 0.0),
                    "fair_exposure_inr_lakhs": float(issue.fair_exposure_inr_lakhs or 0.0),
                    "sebi_cscrf_sla_days": int(issue.sebi_cscrf_sla_days or 90),
                    "link_reason": issue.link_reason,
                    "fix_suggestion": issue.fix_suggestion,
                },
            }
        )

    for sca in sca_list:
        rule_id = sca.cve_id or sca.advisory_id or "SCA-ADVISORY"
        eff_sev = _enum_str(sca.effective_severity) or "High"
        orig_sev = _enum_str(sca.original_severity) or eff_sev
        reach_status = _enum_str(sca.reachability_status) or "Unknown"
        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(eff_sev, "warning")

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": f"SCA_{sca.package_name}_{rule_id}".replace("-", "_"),
                "shortDescription": {
                    "text": f"SCA Advisory {rule_id} in {sca.package_name}=={sca.installed_version}"
                },
                "fullDescription": {
                    "text": (
                        f"Reachability-Aware SCA finding for {sca.package_name}=={sca.installed_version} "
                        f"({rule_id}, status={reach_status})."
                    )
                },
                "defaultConfiguration": {"level": sarif_level},
                "properties": {
                    "tags": ["security", "sca", sca.ecosystem.lower()],
                    "security-severity": str(round(float(sca.cvss_score or 7.5), 1)),
                },
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": (
                        f"[SCA {reach_status}] {sca.package_name}=={sca.installed_version} "
                        f"({rule_id}, effective_severity={eff_sev}, in_cisa_kev={sca.in_cisa_kev})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "requirements.txt" if sca.ecosystem.lower() == "pypi" else "package.json",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "status": f"SCA:{reach_status}",
                    "reachability_status": reach_status,
                    "package_name": sca.package_name,
                    "installed_version": sca.installed_version,
                    "advisory_id": sca.advisory_id,
                    "cve_id": sca.cve_id,
                    "original_severity": orig_sev,
                    "effective_severity": eff_sev,
                    "cvss_score": float(sca.cvss_score or 0.0),
                    "epss_score": float(sca.epss_score or 0.0),
                    "in_cisa_kev": bool(sca.in_cisa_kev),
                    "call_chain": list(sca.call_chain or []),
                    "supply_chain_flags": list(sca.supply_chain_flags or []),
                },
            }
        )

    run_properties: Dict[str, Any] = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_correlated_issues": len(issues),
        "total_sca_findings": len(sca_list),
    }
    if scan_summary is not None:
        run_properties["scan_id"] = scan_summary.scan_id
        run_properties["app_name"] = scan_summary.app_name
        run_properties["confirmed_count"] = scan_summary.confirmed_count
        run_properties["code_only_count"] = scan_summary.code_only_count
        run_properties["runtime_only_count"] = scan_summary.runtime_only_count
        run_properties["safe_decoys_suppressed"] = scan_summary.safe_decoys_suppressed
        if scan_summary.scope_reduction is not None:
            run_properties["scope_reduction"] = scan_summary.scope_reduction.model_dump()

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberForge Correlate",
                        "organization": "Mitigata CyberForge",
                        "semanticVersion": "1.0.0",
                        "informationUri": "http://localhost:8000",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": run_properties,
            }
        ],
    }


def evaluate_ci_gate(
    issues: List[CorrelatedIssue],
    sca_findings: Optional[List[SCAFinding]] = None,
    scan_summary: Optional[ScanSummary] = None,
) -> Dict[str, Any]:
    """
    Task B3.1: Evaluate deterministic CI/CD security gate.
    Returns `status: "FAIL"` and `exit_code: 1` if ANY of the following exist:
      1. A `Confirmed` issue with `Critical` or `High` severity, OR
      2. A `Reachable` SCA finding listed in CISA KEV (`in_cisa_kev=True`).
    Otherwise returns `status: "PASS"` and `exit_code: 0`.
    """
    sca_list = list(sca_findings or [])

    blocking_issues: List[Dict[str, Any]] = []
    for issue in issues:
        status_str = _enum_str(issue.status)
        sev_str = _enum_str(issue.severity)
        if status_str == "Confirmed" and sev_str in ("Critical", "High"):
            blocking_issues.append(
                {
                    "id": issue.id,
                    "fingerprint": issue.fingerprint,
                    "cwe": _enum_str(issue.cwe),
                    "severity": sev_str,
                    "status": status_str,
                    "canonical_path": issue.canonical_path or issue.url,
                    "file": issue.file or issue.file_path,
                    "line": issue.line,
                    "param": issue.param,
                    "risk_score": issue.risk_score,
                }
            )

    blocking_sca: List[Dict[str, Any]] = []
    for sca in sca_list:
        reach_str = _enum_str(sca.reachability_status)
        if reach_str == "Reachable" and bool(sca.in_cisa_kev):
            blocking_sca.append(
                {
                    "id": sca.id,
                    "package_name": sca.package_name,
                    "installed_version": sca.installed_version,
                    "cve_id": sca.cve_id or sca.advisory_id,
                    "reachability_status": reach_str,
                    "in_cisa_kev": True,
                    "call_chain": list(sca.call_chain or []),
                }
            )

    failed = bool(blocking_issues or blocking_sca)
    reasons: List[str] = []
    if blocking_issues:
        reasons.append(f"{len(blocking_issues)} Confirmed Critical/High SAST+DAST issue(s)")
    if blocking_sca:
        reasons.append(f"{len(blocking_sca)} Reachable CISA KEV SCA vulnerability(ies)")
    if not reasons:
        reasons.append("0 Confirmed Critical/High issues and 0 Reachable KEV SCA advisories")

    return {
        "scan_id": scan_summary.scan_id if scan_summary is not None else None,
        "app_name": scan_summary.app_name if scan_summary is not None else "workspace",
        "status": "FAIL" if failed else "PASS",
        "passed": not failed,
        "exit_code": 1 if failed else 0,
        "reason": "; ".join(reasons),
        "blocking_confirmed_count": len(blocking_issues),
        "blocking_reachable_kev_sca_count": len(blocking_sca),
        "blocking_confirmed_issues": blocking_issues,
        "blocking_reachable_kev_sca": blocking_sca,
    }
