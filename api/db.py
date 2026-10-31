"""
api/db.py — SQLite Persistence & FR-6 Idempotent Deduplication Store.

Covers PRD Requirements:
  - FR-6: "Merge duplicates: one issue per real bug with all its evidence attached;
           running a scan twice does not create copies."
  - FR-8: Store and retrieve full issue detail (`GET /issues/{id}`).
  - FR-9: Return issues ordered by `Confirmed` first, then by `risk_score` descending.
  - FR-10: Persist scans, route maps, raw findings, and correlated issues.
  - B-5: Track scan-to-issue membership (`scan_issue_links`) so any two scans can be
         compared into `NEW`, `FIXED`, and `STILL-OPEN` issues.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from core.schemas import (
    CanonicalFinding,
    CorrelatedIssue,
    RouteEntry,
    SCAFinding,
    ScanSummary,
    compute_issue_risk_score,
)

DEFAULT_DB_PATH = os.getenv("CYBERFORGE_DB_PATH", os.getenv("GORDON_DB_PATH", os.path.join(os.getcwd(), "cyberforge_correlate.db")))

STATUS_SORT_ORDER_SQL = """
CASE status
    WHEN 'Confirmed' THEN 1
    WHEN 'Runtime only' THEN 2
    WHEN 'Code only' THEN 3
    ELSE 4
END
"""


class DatabaseStore:
    """
    Thread-safe SQLite store implementing FR-6 idempotent fingerprint upserts
    for findings and correlated issues.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create SQLite tables (`scans`, `routes`, `findings`, `issues`, `scan_issue_links`, `sca_findings`)."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    source_dir TEXT,
                    target_url TEXT,
                    started_at TEXT NOT NULL,
                    duration_seconds REAL DEFAULT 0.0,
                    routes_discovered INTEGER DEFAULT 0,
                    raw_sast_findings INTEGER DEFAULT 0,
                    raw_dast_findings INTEGER DEFAULT 0,
                    safe_decoys_suppressed INTEGER DEFAULT 0,
                    total_issues INTEGER DEFAULT 0,
                    confirmed_count INTEGER DEFAULT 0,
                    code_only_count INTEGER DEFAULT 0,
                    runtime_only_count INTEGER DEFAULT 0,
                    auto_verified_count INTEGER DEFAULT 0,
                    sca_findings_count INTEGER DEFAULT 0,
                    total_fair_exposure_inr_lakhs REAL DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    app_name TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path_pattern TEXT NOT NULL,
                    canonical_path TEXT NOT NULL,
                    file TEXT NOT NULL,
                    func_name TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    route_json TEXT NOT NULL,
                    UNIQUE(app_name, method, canonical_path, file, func_name),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    app_name TEXT NOT NULL,
                    first_scan_id INTEGER NOT NULL,
                    last_scan_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    scanner_name TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    is_protected_decoy INTEGER DEFAULT 0,
                    finding_json TEXT NOT NULL,
                    UNIQUE(app_name, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    app_name TEXT NOT NULL,
                    first_scan_id INTEGER NOT NULL,
                    last_scan_id INTEGER NOT NULL,
                    is_open INTEGER DEFAULT 1,
                    status TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    url TEXT,
                    canonical_path TEXT,
                    method TEXT,
                    param TEXT,
                    payload TEXT,
                    evidence TEXT,
                    file TEXT,
                    line INTEGER,
                    func_name TEXT,
                    snippet TEXT,
                    matched_route TEXT,
                    link_reason TEXT,
                    auto_verified INTEGER DEFAULT 0,
                    fix_suggestion TEXT,
                    finding_count INTEGER DEFAULT 1,
                    fair_exposure_inr_lakhs REAL DEFAULT 0.0,
                    sebi_cscrf_sla_days INTEGER DEFAULT 90,
                    sast_evidence_json TEXT NOT NULL,
                    dast_evidence_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(app_name, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS scan_issue_links (
                    scan_id INTEGER NOT NULL,
                    issue_id INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    PRIMARY KEY (scan_id, issue_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS sca_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    app_name TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    advisory_id TEXT NOT NULL,
                    reachability_status TEXT NOT NULL,
                    effective_severity TEXT NOT NULL,
                    sca_json TEXT NOT NULL,
                    UNIQUE(app_name, package_name, advisory_id)
                );
                """
            )

    def create_scan(
        self,
        app_name: str = "target-web-shop",
        source_dir: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> int:
        """Create a new scan record and return its integer `scan_id`."""
        started_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (app_name, source_dir, target_url, started_at)
                VALUES (?, ?, ?, ?)
                """,
                (app_name, source_dir, target_url, started_at),
            )
            return int(cursor.lastrowid)

    def save_routes(
        self, scan_id: int, routes: List[RouteEntry], app_name: str = "target-web-shop"
    ) -> int:
        """Idempotently upsert discovered FR-4 RouteEntry items."""
        with self._connect() as conn:
            for r in routes:
                conn.execute(
                    """
                    INSERT INTO routes (
                        scan_id, app_name, method, path_pattern, canonical_path,
                        file, func_name, start_line, end_line, route_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(app_name, method, canonical_path, file, func_name)
                    DO UPDATE SET
                        scan_id = excluded.scan_id,
                        path_pattern = excluded.path_pattern,
                        start_line = excluded.start_line,
                        end_line = excluded.end_line,
                        route_json = excluded.route_json
                    """,
                    (
                        scan_id,
                        app_name,
                        r.method,
                        r.path_pattern,
                        r.canonical_path,
                        r.file,
                        r.func_name,
                        r.start_line,
                        r.end_line,
                        r.model_dump_json(),
                    ),
                )
        return len(routes)

    def save_findings(
        self, scan_id: int, findings: List[CanonicalFinding], app_name: str = "target-web-shop"
    ) -> Tuple[int, int]:
        """
        Idempotently upsert raw SAST and DAST findings by deterministic `fingerprint`.
        Returns `(active_findings_count, decoys_suppressed_count)`.
        """
        active_count = 0
        decoy_count = 0
        with self._connect() as conn:
            for f in findings:
                fp = f.fingerprint or f.compute_fingerprint()
                if f.is_protected_decoy:
                    decoy_count += 1
                else:
                    active_count += 1
                conn.execute(
                    """
                    INSERT INTO findings (
                        fingerprint, app_name, first_scan_id, last_scan_id,
                        source, scanner_name, cwe, severity, is_protected_decoy, finding_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(app_name, fingerprint) DO UPDATE SET
                        last_scan_id = excluded.last_scan_id,
                        severity = excluded.severity,
                        is_protected_decoy = excluded.is_protected_decoy,
                        finding_json = excluded.finding_json
                    """,
                    (
                        fp,
                        app_name,
                        scan_id,
                        scan_id,
                        f.source,
                        f.scanner_name,
                        f.cwe,
                        f.severity,
                        1 if f.is_protected_decoy else 0,
                        f.model_dump_json(),
                    ),
                )
        return active_count, decoy_count

    @staticmethod
    def _merge_finding_lists(
        existing_json: str, incoming_list: List[CanonicalFinding]
    ) -> List[CanonicalFinding]:
        """
        FR-6: Merge incoming findings with existing stored findings by deterministic
        fingerprint so re-running a scan never creates duplicate evidence entries.
        """
        merged_by_fp: Dict[str, CanonicalFinding] = {}
        try:
            raw_items = json.loads(existing_json) if existing_json else []
            for item in raw_items:
                f_obj = CanonicalFinding.model_validate(item)
                merged_by_fp[f_obj.fingerprint] = f_obj
        except Exception:
            pass

        for inc in incoming_list:
            fp = inc.fingerprint or inc.compute_fingerprint()
            merged_by_fp[fp] = inc

        return list(merged_by_fp.values())

    def upsert_issues(
        self,
        scan_id: int,
        issues: List[CorrelatedIssue],
        app_name: str = "target-web-shop",
        mark_unseen_closed: bool = True,
    ) -> List[CorrelatedIssue]:
        """
        FR-6 Idempotent Issue Upsert:
          1. Deduplicate any incoming issues that share the same deterministic `fingerprint`
             within the same scan run (e.g. 3 scanner hits on the same bug -> 1 issue).
          2. Upsert into SQLite `issues` by `(app_name, fingerprint)` so running a scan twice updates
             the existing row in-place and NEVER creates duplicate rows or collides across apps.
          3. Record scan membership in `scan_issue_links` for B-5 Scan Diffing.
        """
        # Step 1: Collapse any same-fingerprint issues within the incoming batch itself
        deduped_batch: Dict[str, CorrelatedIssue] = {}
        for issue in issues:
            fp = issue.fingerprint or issue.compute_fingerprint()
            issue.fingerprint = fp
            if fp not in deduped_batch:
                deduped_batch[fp] = issue
            else:
                existing = deduped_batch[fp]
                # Upgrade status if either side is Confirmed
                if issue.status == "Confirmed" or (
                    existing.status != "Confirmed"
                    and (existing.sast_evidence or issue.sast_evidence)
                    and (existing.dast_evidence or issue.dast_evidence)
                ):
                    existing.status = "Confirmed"
                existing.sast_evidence = self._merge_finding_lists(
                    json.dumps([f.model_dump() for f in existing.sast_evidence]),
                    issue.sast_evidence,
                )
                existing.dast_evidence = self._merge_finding_lists(
                    json.dumps([f.model_dump() for f in existing.dast_evidence]),
                    issue.dast_evidence,
                )
                existing.finding_count = len(existing.sast_evidence) + len(existing.dast_evidence)
                existing.auto_verified = existing.auto_verified or issue.auto_verified
                existing.url = existing.url or issue.url
                existing.param = existing.param or issue.param
                existing.parameter = existing.param
                existing.payload = existing.payload or issue.payload
                existing.evidence = existing.evidence or issue.evidence
                existing.file = existing.file or issue.file
                existing.line = existing.line if existing.line is not None else issue.line
                existing.snippet = existing.snippet or issue.snippet
                existing.code_snippet = existing.snippet
                existing.link_reason = existing.link_reason or issue.link_reason
                existing.fix_suggestion = existing.fix_suggestion or issue.fix_suggestion
                existing.risk_score = compute_issue_risk_score(
                    existing.status, existing.severity, existing.cwe, existing.auto_verified
                )

        now_iso = datetime.now(timezone.utc).isoformat()
        persisted_issues: List[CorrelatedIssue] = []
        seen_issue_ids: List[int] = []

        with self._connect() as conn:
            for fp, issue in deduped_batch.items():
                row = conn.execute(
                    "SELECT * FROM issues WHERE app_name = ? AND fingerprint = ?",
                    (app_name, fp),
                ).fetchone()

                if row is not None:
                    issue_id = int(row["id"])
                    merged_sast = self._merge_finding_lists(
                        row["sast_evidence_json"], issue.sast_evidence
                    )
                    merged_dast = self._merge_finding_lists(
                        row["dast_evidence_json"], issue.dast_evidence
                    )
                    # If previous scan had SAST and current had DAST (or vice versa), upgrade status
                    effective_status = issue.status
                    if row["status"] == "Confirmed" or (merged_sast and merged_dast):
                        effective_status = "Confirmed"

                    effective_auto_verified = bool(row["auto_verified"]) or issue.auto_verified
                    effective_score = compute_issue_risk_score(
                        effective_status, issue.severity, issue.cwe, effective_auto_verified
                    )
                    finding_count = max(1, len(merged_sast) + len(merged_dast))

                    conn.execute(
                        """
                        UPDATE issues SET
                            last_scan_id = ?,
                            is_open = 1,
                            status = ?,
                            cwe = ?,
                            title = ?,
                            severity = ?,
                            risk_score = ?,
                            url = COALESCE(?, url),
                            canonical_path = COALESCE(?, canonical_path),
                            method = COALESCE(?, method),
                            param = COALESCE(?, param),
                            payload = COALESCE(?, payload),
                            evidence = COALESCE(?, evidence),
                            file = COALESCE(?, file),
                            line = COALESCE(?, line),
                            func_name = COALESCE(?, func_name),
                            snippet = COALESCE(?, snippet),
                            matched_route = COALESCE(?, matched_route),
                            link_reason = COALESCE(?, link_reason),
                            auto_verified = ?,
                            fix_suggestion = COALESCE(?, fix_suggestion),
                            finding_count = ?,
                            fair_exposure_inr_lakhs = ?,
                            sebi_cscrf_sla_days = ?,
                            sast_evidence_json = ?,
                            dast_evidence_json = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            scan_id,
                            effective_status,
                            issue.cwe,
                            issue.title,
                            issue.severity,
                            effective_score,
                            issue.url,
                            issue.canonical_path,
                            issue.method,
                            issue.param,
                            issue.payload,
                            issue.evidence,
                            issue.file,
                            issue.line,
                            issue.func_name,
                            issue.snippet,
                            issue.matched_route,
                            issue.link_reason,
                            1 if effective_auto_verified else 0,
                            issue.fix_suggestion,
                            finding_count,
                            issue.fair_exposure_inr_lakhs,
                            issue.sebi_cscrf_sla_days,
                            json.dumps([f.model_dump() for f in merged_sast]),
                            json.dumps([f.model_dump() for f in merged_dast]),
                            now_iso,
                            issue_id,
                        ),
                    )
                    issue.id = issue_id
                    issue.status = effective_status
                    issue.risk_score = effective_score
                    issue.sast_evidence = merged_sast
                    issue.dast_evidence = merged_dast
                    issue.finding_count = finding_count
                else:
                    finding_count = max(1, len(issue.sast_evidence) + len(issue.dast_evidence))
                    cursor = conn.execute(
                        """
                        INSERT INTO issues (
                            fingerprint, app_name, first_scan_id, last_scan_id, is_open,
                            status, cwe, title, severity, risk_score,
                            url, canonical_path, method, param, payload, evidence,
                            file, line, func_name, snippet,
                            matched_route, link_reason, auto_verified, fix_suggestion,
                            finding_count, fair_exposure_inr_lakhs, sebi_cscrf_sla_days,
                            sast_evidence_json, dast_evidence_json, updated_at
                        )
                        VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            fp,
                            app_name,
                            scan_id,
                            scan_id,
                            issue.status,
                            issue.cwe,
                            issue.title,
                            issue.severity,
                            issue.risk_score,
                            issue.url,
                            issue.canonical_path,
                            issue.method,
                            issue.param,
                            issue.payload,
                            issue.evidence,
                            issue.file,
                            issue.line,
                            issue.func_name,
                            issue.snippet,
                            issue.matched_route,
                            issue.link_reason,
                            1 if issue.auto_verified else 0,
                            issue.fix_suggestion,
                            finding_count,
                            issue.fair_exposure_inr_lakhs,
                            issue.sebi_cscrf_sla_days,
                            json.dumps([f.model_dump() for f in issue.sast_evidence]),
                            json.dumps([f.model_dump() for f in issue.dast_evidence]),
                            now_iso,
                        ),
                    )
                    issue_id = int(cursor.lastrowid)
                    issue.id = issue_id
                    issue.finding_count = finding_count

                seen_issue_ids.append(issue_id)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scan_issue_links (
                        scan_id, issue_id, fingerprint, status, severity, risk_score
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        issue_id,
                        fp,
                        issue.status,
                        issue.severity,
                        issue.risk_score,
                    ),
                )
                persisted_issues.append(issue)

            if mark_unseen_closed:
                if seen_issue_ids:
                    placeholders = ",".join("?" for _ in seen_issue_ids)
                    conn.execute(
                        f"UPDATE issues SET is_open = 0 WHERE app_name = ? AND id NOT IN ({placeholders})",
                        [app_name, *seen_issue_ids],
                    )
                else:
                    conn.execute(
                        "UPDATE issues SET is_open = 0 WHERE app_name = ?",
                        (app_name,),
                    )

        # Sort FR-9: Confirmed first, then by risk_score descending
        status_rank = {"Confirmed": 1, "Runtime only": 2, "Code only": 3}
        persisted_issues.sort(
            key=lambda x: (status_rank.get(x.status, 4), -x.risk_score, x.id or 0)
        )
        return persisted_issues

    def save_sca_findings(
        self, scan_id: int, sca_findings: List[SCAFinding], app_name: str = "target-web-shop"
    ) -> int:
        """Persist Page 4 Reachability-Aware SCA findings."""
        with self._connect() as conn:
            for sf in sca_findings:
                conn.execute(
                    """
                    INSERT INTO sca_findings (
                        scan_id, app_name, package_name, advisory_id,
                        reachability_status, effective_severity, sca_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(app_name, package_name, advisory_id)
                    DO UPDATE SET
                        scan_id = excluded.scan_id,
                        reachability_status = excluded.reachability_status,
                        effective_severity = excluded.effective_severity,
                        sca_json = excluded.sca_json
                    """,
                    (
                        scan_id,
                        app_name,
                        sf.package_name,
                        sf.advisory_id,
                        sf.reachability_status,
                        sf.effective_severity,
                        sf.model_dump_json(),
                    ),
                )
        return len(sca_findings)

    def finalize_scan(
        self,
        scan_id: int,
        duration_seconds: float,
        routes_discovered: int = 0,
        raw_sast_findings: int = 0,
        raw_dast_findings: int = 0,
        safe_decoys_suppressed: int = 0,
        issues: Optional[List[CorrelatedIssue]] = None,
        sca_findings_count: int = 0,
    ) -> ScanSummary:
        """Update scan summary statistics and return a `ScanSummary` object."""
        issues_list = issues or []
        confirmed_count = sum(1 for i in issues_list if i.status == "Confirmed")
        code_only_count = sum(1 for i in issues_list if i.status == "Code only")
        runtime_only_count = sum(1 for i in issues_list if i.status == "Runtime only")
        auto_verified_count = sum(1 for i in issues_list if i.auto_verified)
        total_fair = round(sum(i.fair_exposure_inr_lakhs for i in issues_list), 2)

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE scans SET
                    duration_seconds = ?,
                    routes_discovered = ?,
                    raw_sast_findings = ?,
                    raw_dast_findings = ?,
                    safe_decoys_suppressed = ?,
                    total_issues = ?,
                    confirmed_count = ?,
                    code_only_count = ?,
                    runtime_only_count = ?,
                    auto_verified_count = ?,
                    sca_findings_count = ?,
                    total_fair_exposure_inr_lakhs = ?
                WHERE id = ?
                """,
                (
                    round(duration_seconds, 3),
                    routes_discovered,
                    raw_sast_findings,
                    raw_dast_findings,
                    safe_decoys_suppressed,
                    len(issues_list),
                    confirmed_count,
                    code_only_count,
                    runtime_only_count,
                    auto_verified_count,
                    sca_findings_count,
                    total_fair,
                    scan_id,
                ),
            )
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

        return ScanSummary(
            scan_id=scan_id,
            app_name=row["app_name"] if row else "target-web-shop",
            source_dir=row["source_dir"] if row else None,
            target_url=row["target_url"] if row else None,
            started_at=row["started_at"] if row else datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration_seconds, 3),
            routes_discovered=routes_discovered,
            raw_sast_findings=raw_sast_findings,
            raw_dast_findings=raw_dast_findings,
            safe_decoys_suppressed=safe_decoys_suppressed,
            total_issues=len(issues_list),
            confirmed_count=confirmed_count,
            code_only_count=code_only_count,
            runtime_only_count=runtime_only_count,
            auto_verified_count=auto_verified_count,
            sca_findings_count=sca_findings_count,
            total_fair_exposure_inr_lakhs=total_fair,
        )

    @staticmethod
    def _row_to_issue(row: sqlite3.Row) -> CorrelatedIssue:
        sast_list = [
            CanonicalFinding.model_validate(item)
            for item in json.loads(row["sast_evidence_json"] or "[]")
        ]
        dast_list = [
            CanonicalFinding.model_validate(item)
            for item in json.loads(row["dast_evidence_json"] or "[]")
        ]
        return CorrelatedIssue(
            id=int(row["id"]),
            fingerprint=row["fingerprint"],
            status=row["status"],
            cwe=row["cwe"],
            title=row["title"],
            severity=row["severity"],
            risk_score=float(row["risk_score"]),
            url=row["url"],
            canonical_path=row["canonical_path"],
            method=row["method"],
            param=row["param"],
            payload=row["payload"],
            evidence=row["evidence"],
            file=row["file"],
            line=row["line"],
            func_name=row["func_name"],
            snippet=row["snippet"],
            sast_evidence=sast_list,
            dast_evidence=dast_list,
            finding_count=int(row["finding_count"]),
            matched_route=row["matched_route"],
            link_reason=row["link_reason"],
            auto_verified=bool(row["auto_verified"]),
            fix_suggestion=row["fix_suggestion"],
            fair_exposure_inr_lakhs=float(row["fair_exposure_inr_lakhs"] or 0.0),
            sebi_cscrf_sla_days=int(row["sebi_cscrf_sla_days"] or 90),
        )

    def get_issues(
        self,
        status: Optional[str] = None,
        cwe: Optional[str] = None,
        app_name: Optional[str] = None,
        scan_id: Optional[int] = None,
        only_open: bool = True,
    ) -> List[CorrelatedIssue]:
        """
        FR-9 / FR-10: Retrieve correlated issues sorted with `Confirmed` issues first,
        then by `risk_score` descending.
        """
        clauses: List[str] = []
        params: List[Any] = []

        if scan_id is not None:
            clauses.append(
                "id IN (SELECT issue_id FROM scan_issue_links WHERE scan_id = ?)"
            )
            params.append(scan_id)
        elif only_open:
            clauses.append("is_open = 1")

        if status:
            clauses.append("status = ?")
            params.append(status)
        if cwe:
            clauses.append("UPPER(cwe) = UPPER(?)")
            params.append(cwe)
        if app_name:
            clauses.append("app_name = ?")
            params.append(app_name)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"""
            SELECT * FROM issues
            {where_sql}
            ORDER BY {STATUS_SORT_ORDER_SQL} ASC, risk_score DESC, id ASC
        """
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_issue(r) for r in rows]

    def get_issue_by_id(self, issue_id: int) -> Optional[CorrelatedIssue]:
        """FR-8 / FR-10: Retrieve a single issue with all evidence by numeric ID (`GET /issues/7`)."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM issues WHERE id = ?", (issue_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_issue(row)

    def get_routes(self, app_name: Optional[str] = None) -> List[RouteEntry]:
        """Retrieve discovered FR-4 route entries."""
        with self._connect() as conn:
            if app_name:
                rows = conn.execute(
                    "SELECT route_json FROM routes WHERE app_name = ? ORDER BY canonical_path, method",
                    (app_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT route_json FROM routes ORDER BY canonical_path, method"
                ).fetchall()
        return [RouteEntry.model_validate_json(r["route_json"]) for r in rows]

    def get_suppressed_decoys(self, app_name: Optional[str] = None) -> List[CanonicalFinding]:
        """B-2: Retrieve findings marked as protected decoys (`is_protected_decoy = 1`)."""
        with self._connect() as conn:
            if app_name:
                rows = conn.execute(
                    "SELECT finding_json FROM findings WHERE is_protected_decoy = 1 AND app_name = ?",
                    (app_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT finding_json FROM findings WHERE is_protected_decoy = 1"
                ).fetchall()
        return [CanonicalFinding.model_validate_json(r["finding_json"]) for r in rows]

    def get_sca_findings(self, app_name: Optional[str] = None) -> List[SCAFinding]:
        """Retrieve Page 4 Reachability-Aware SCA findings."""
        with self._connect() as conn:
            if app_name:
                rows = conn.execute(
                    "SELECT sca_json FROM sca_findings WHERE app_name = ? ORDER BY reachability_status, package_name",
                    (app_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT sca_json FROM sca_findings ORDER BY reachability_status, package_name"
                ).fetchall()
        return [SCAFinding.model_validate_json(r["sca_json"]) for r in rows]

    def get_scans(self) -> List[ScanSummary]:
        """List all executed scans ordered most-recent first."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        return [
            ScanSummary(
                scan_id=int(r["id"]),
                app_name=r["app_name"],
                source_dir=r["source_dir"],
                target_url=r["target_url"],
                started_at=r["started_at"],
                duration_seconds=float(r["duration_seconds"] or 0.0),
                routes_discovered=int(r["routes_discovered"] or 0),
                raw_sast_findings=int(r["raw_sast_findings"] or 0),
                raw_dast_findings=int(r["raw_dast_findings"] or 0),
                safe_decoys_suppressed=int(r["safe_decoys_suppressed"] or 0),
                total_issues=int(r["total_issues"] or 0),
                confirmed_count=int(r["confirmed_count"] or 0),
                code_only_count=int(r["code_only_count"] or 0),
                runtime_only_count=int(r["runtime_only_count"] or 0),
                auto_verified_count=int(r["auto_verified_count"] or 0),
                sca_findings_count=int(r["sca_findings_count"] or 0),
                total_fair_exposure_inr_lakhs=float(r["total_fair_exposure_inr_lakhs"] or 0.0),
            )
            for r in rows
        ]

    def compare_scans(self, base_scan_id: int, target_scan_id: int) -> Dict[str, Any]:
        """
        Bonus B-5: Compare two scans by deterministic issue fingerprint and classify
        every issue as `NEW`, `FIXED`, or `STILL-OPEN`.
        """
        base_issues = {
            i.fingerprint: i for i in self.get_issues(scan_id=base_scan_id, only_open=False)
        }
        target_issues = {
            i.fingerprint: i for i in self.get_issues(scan_id=target_scan_id, only_open=False)
        }

        new_list: List[CorrelatedIssue] = []
        fixed_list: List[CorrelatedIssue] = []
        still_open_list: List[CorrelatedIssue] = []

        for fp, issue in target_issues.items():
            issue_copy = issue.model_copy(deep=True)
            if fp not in base_issues:
                issue_copy.diff_status = "NEW"
                new_list.append(issue_copy)
            else:
                issue_copy.diff_status = "STILL-OPEN"
                still_open_list.append(issue_copy)

        for fp, issue in base_issues.items():
            if fp not in target_issues:
                issue_copy = issue.model_copy(deep=True)
                issue_copy.diff_status = "FIXED"
                fixed_list.append(issue_copy)

        return {
            "base_scan_id": base_scan_id,
            "target_scan_id": target_scan_id,
            "summary": {
                "new_count": len(new_list),
                "fixed_count": len(fixed_list),
                "still_open_count": len(still_open_list),
            },
            "new_issues": new_list,
            "fixed_issues": fixed_list,
            "still_open_issues": still_open_list,
        }
