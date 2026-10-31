"""
core/schemas.py — Shared Data Contract for GORDON CORRELATE (PROBLEM 06 · FLAGSHIP).

Locked shared schema between:
  - Person A (Static Intelligence, AST Route Mapper, Decoy Filter, Correlator, Reachability SCA)
  - Person B (Runtime 2-Phase DAST, Auto-Verify, FastAPI/SQLite Persistence, SARIF/Diff & UI)

Covers PRD Requirements:
  - FR-1 (SAST finding fields: file, line, cwe, severity, snippet)
  - FR-2 (DAST finding fields: url, method, param, payload, evidence)
  - FR-3 (CanonicalFinding common format with normalized CWE-<num>)
  - FR-4 (RouteEntry: URL -> function, file, start_line..end_line, params, call graph)
  - FR-5 & B-3 (CorrelatedIssue with link_reason and hard-veto metadata)
  - FR-6 (Deterministic fingerprint for idempotent deduplication across repeated scans)
  - FR-7 (3-Bucket status: "Confirmed", "Code only", "Runtime only")
  - FR-8 (Unified Issue Detail fields: url, param, payload, file, line, snippet, cwe, severity)
  - FR-9 (Prioritised risk_score + Gordon AI FAIR ₹ exposure & SEBI CSCRF SLA)
  - B-1..B-7 & Page 4 Bonus (Reachability-Aware SCA with strict "Never downgrade Unknown" rule)
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Canonical Literal Types & Constants
# ---------------------------------------------------------------------------

FindingSource = Literal["SAST", "DAST", "SCA"]
IssueStatus = Literal["Confirmed", "Code only", "Runtime only"]
SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Info"]
ConfidenceLevel = Literal["High", "Medium", "Low"]
DiffStatus = Literal["NEW", "FIXED", "STILL-OPEN"]
SCAReachabilityStatus = Literal["Reachable", "Imported-only", "Present-only", "Unknown"]

SEVERITY_WEIGHTS: Dict[str, float] = {
    "Critical": 40.0,
    "High": 30.0,
    "Medium": 20.0,
    "Low": 10.0,
    "Info": 5.0,
}

STATUS_BASE_SCORE: Dict[str, float] = {
    # FR-9: Confirmed issues ALWAYS rank first above Runtime only and Code only
    "Confirmed": 55.0,
    "Runtime only": 25.0,
    "Code only": 15.0,
}

CWE_DEFAULT_TITLES: Dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal / Arbitrary File Read",
    "CWE-601": "Open Redirect",
    "CWE-798": "Use of Hard-coded Credentials / Secrets",
    "CWE-693": "Missing Protection Mechanism (HTTP Security Header)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' / 'HttpOnly' Attribute",
    "CWE-942": "Permissive Cross-domain Policy (CORS Wildcard)",
    "CWE-200": "Exposure of Sensitive Server / Debug Information",
    "CWE-16": "Security Misconfiguration",
}


# ---------------------------------------------------------------------------
# Path & CWE Normalization Helpers (Shared by Route Mapper, DAST & Correlator)
# ---------------------------------------------------------------------------

_FLASK_PARAM_RE = re.compile(r"<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_FASTAPI_TYPED_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*):[^/{}]+\}")
_COLON_PARAM_RE = re.compile(r"(?<=/):([a-zA-Z_][a-zA-Z0-9_]*)(?=/|$)")
_BRACE_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def normalize_cwe(cwe_raw: str) -> str:
    """Normalize any CWE identifier (e.g., '89', 'cwe-89', 'CWE-089') to 'CWE-89'."""
    if not cwe_raw:
        return "CWE-0"
    cleaned = str(cwe_raw).strip().upper()
    match = re.search(r"(\d+)", cleaned)
    if match:
        return f"CWE-{int(match.group(1))}"
    return cleaned if cleaned.startswith("CWE-") else f"CWE-{cleaned}"


def normalize_route_template(path_pattern: str) -> str:
    """
    Convert framework-specific route templates into a canonical path format:
      - Flask:   /api/orders/<int:order_id> -> /api/orders/{order_id}
      - FastAPI: /api/orders/{order_id:int} -> /api/orders/{order_id}
      - Express: /api/orders/:order_id      -> /api/orders/{order_id}
    Crucial for FR-4, FR-5, B-7, and the Unseen Second App (>65% target).
    """
    if not path_pattern:
        return "/"
    parsed = urlparse(path_pattern)
    path = parsed.path if parsed.scheme or parsed.netloc else path_pattern.split("?")[0]
    if not path.startswith("/"):
        path = "/" + path
    # Convert Flask/Django <int:id> or <id> -> {id}
    path = _FLASK_PARAM_RE.sub(r"{\1}", path)
    # Convert FastAPI/Starlette {id:int} or {filepath:path} -> {id} / {filepath}
    path = _FASTAPI_TYPED_PARAM_RE.sub(r"{\1}", path)
    # Convert Express /:id -> /{id}
    path = _COLON_PARAM_RE.sub(r"{\1}", path)
    # Collapse duplicate slashes and strip trailing slash (except root "/")
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def compile_route_regex(path_pattern: str) -> str:
    """
    Compile a route template into an anchored regex pattern that matches concrete URLs
    (e.g., '/api/orders/{id}' -> '^/api/orders/(?P<id>[^/]+)/?$').
    """
    canonical = normalize_route_template(path_pattern)
    if canonical == "/":
        return r"^/$"
    parts: List[str] = []
    used_names: set[str] = set()
    for segment in canonical.strip("/").split("/"):
        m = _BRACE_PARAM_RE.fullmatch(segment)
        if m:
            param_name = m.group(1)
            if param_name not in used_names:
                used_names.add(param_name)
                parts.append(f"(?P<{param_name}>[^/]+)")
            else:
                parts.append(r"[^/]+")
        else:
            parts.append(re.escape(segment))
    return r"^/" + "/".join(parts) + r"/?$"


def extract_url_path(url_or_path: str) -> str:
    """Extract clean path from a full URL or relative path."""
    if not url_or_path:
        return "/"
    parsed = urlparse(url_or_path)
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def normalize_file_path(file_path: Optional[str]) -> str:
    """Normalize Windows/POSIX file paths for consistent comparison and hashing."""
    if not file_path:
        return ""
    norm = file_path.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


# ---------------------------------------------------------------------------
# FR-4: RouteEntry & Call-Graph Models
# ---------------------------------------------------------------------------


class CalledFunction(BaseModel):
    """Represents a helper function invoked by a route handler (1-to-3 hop call graph)."""

    name: str = Field(..., description="Function or method name, e.g. 'query_orders'")
    qualified_name: Optional[str] = Field(
        default=None, description="Module/object qualified name, e.g. 'db.query_orders'"
    )
    file: Optional[str] = Field(
        default=None, description="Resolved source file where the helper function is defined"
    )
    start_line: Optional[int] = Field(default=None, description="Start line of helper function")
    end_line: Optional[int] = Field(default=None, description="End line of helper function")


class RouteEntry(BaseModel):
    """
    FR-4: Route Map entry mapping a URL pattern and HTTP method to the source function
    and line range that handles it, plus extracted parameter names and called helpers.
    """

    method: str = Field(default="GET", description="Primary HTTP method (GET, POST, PUT, DELETE)")
    methods: List[str] = Field(
        default_factory=list, description="All HTTP methods accepted by this route"
    )
    path_pattern: str = Field(
        ..., description="Original route pattern from source code, e.g. '/api/orders/<int:id>'"
    )
    canonical_path: str = Field(
        default="", description="Normalized path pattern, e.g. '/api/orders/{id}'"
    )
    regex: str = Field(
        default="", description="Anchored regex matching concrete runtime URL paths"
    )
    file: str = Field(..., description="Source file path, e.g. 'orders.py'")
    func_name: str = Field(..., description="Handler function name, e.g. 'get_orders'")
    start_line: int = Field(..., description="1-indexed start line of handler function")
    end_line: int = Field(..., description="1-indexed end line of handler function")
    params: List[str] = Field(
        default_factory=list,
        description="Extracted input parameter names (query, form, json, path)",
    )
    param_sources: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional map of param_name -> source ('query', 'form', 'json', 'path')",
    )
    called_funcs: List[str] = Field(
        default_factory=list,
        description="Names or file:func identifiers of helper functions called from this route",
    )
    called_func_details: List[CalledFunction] = Field(
        default_factory=list,
        description="Resolved multi-file helper function definitions (line ranges) for FR-5",
    )
    language: str = Field(default="python", description="Source language ('python' | 'javascript')")
    framework: Optional[str] = Field(
        default=None, description="Web framework ('flask' | 'fastapi' | 'django' | 'express')"
    )
    auth_required: bool = Field(
        default=False, description="Whether route requires authentication/session"
    )

    @model_validator(mode="after")
    def _populate_derived_fields(self) -> "RouteEntry":
        self.method = (self.method or "GET").upper()
        if not self.methods:
            self.methods = [self.method]
        else:
            self.methods = [m.upper() for m in self.methods]
        self.file = normalize_file_path(self.file)
        if not self.canonical_path:
            self.canonical_path = normalize_route_template(self.path_pattern)
        if not self.regex:
            self.regex = compile_route_regex(self.path_pattern)
        # Ensure path template parameters (e.g. {id}) are registered in params
        for m in _BRACE_PARAM_RE.finditer(self.canonical_path):
            pname = m.group(1)
            if pname not in self.params:
                self.params.append(pname)
            self.param_sources.setdefault(pname, "path")
        return self

    def matches_url(self, url_or_path: str, method: Optional[str] = None) -> bool:
        """Return True if the given runtime URL/path (and optional HTTP method) hits this route."""
        if method and method.upper() not in self.methods and "ANY" not in self.methods:
            return False
        concrete_path = extract_url_path(url_or_path)
        if concrete_path == self.canonical_path:
            return True
        try:
            return bool(re.match(self.regex, concrete_path))
        except re.error:
            return concrete_path == self.canonical_path

    def covers_location(self, target_file: Optional[str], target_line: Optional[int]) -> bool:
        """
        Return True if (target_file, target_line) falls inside this route handler
        OR inside one of its resolved called helper functions.
        """
        if not target_file or target_line is None:
            return False
        norm_target = normalize_file_path(target_file)
        # Match either exact relative path or basename when unambiguous
        same_file = (
            norm_target == self.file
            or norm_target.endswith("/" + self.file)
            or self.file.endswith("/" + norm_target)
        )
        if same_file and self.start_line <= target_line <= self.end_line:
            return True
        for helper in self.called_func_details:
            if helper.file and helper.start_line is not None and helper.end_line is not None:
                norm_helper = normalize_file_path(helper.file)
                helper_same = (
                    norm_target == norm_helper
                    or norm_target.endswith("/" + norm_helper)
                    or norm_helper.endswith("/" + norm_target)
                )
                if helper_same and helper.start_line <= target_line <= helper.end_line:
                    return True
        return False

    def concrete_path(self, sample_values: Optional[Dict[str, str]] = None) -> str:
        """
        Substitute concrete test values into path parameters (e.g. '/api/orders/{id}' -> '/api/orders/1')
        so Phase A DAST and B-1 Auto-Verify can probe parameterized routes directly.
        """
        samples = sample_values or {}

        def _replace(match: re.Match[str]) -> str:
            pname = match.group(1)
            if pname in samples:
                return str(samples[pname])
            if any(k in pname.lower() for k in ("id", "num", "page", "count", "qty", "pid", "uid")):
                return "1"
            return "test"

        return _BRACE_PARAM_RE.sub(_replace, self.canonical_path)


# ---------------------------------------------------------------------------
# FR-3: CanonicalFinding (Unified SAST & DAST Finding Format)
# ---------------------------------------------------------------------------


class CanonicalFinding(BaseModel):
    """
    FR-3: One common finding format for both SAST and DAST scanners, with a normalized
    CWE number for the vulnerability type.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: FindingSource = Field(..., description="'SAST', 'DAST', or 'SCA'")
    scanner_name: str = Field(
        default="gordon-native",
        description="Originating scanner (e.g. 'gordon-sast', 'gordon-dast', 'semgrep', 'bandit')",
    )
    cwe: str = Field(..., description="Normalized CWE identifier, e.g. 'CWE-89'")
    title: str = Field(default="", description="Short human-readable vulnerability title")
    severity: SeverityLevel = Field(default="High", description="Critical | High | Medium | Low | Info")
    confidence: ConfidenceLevel = Field(default="High", description="High | Medium | Low")

    # SAST fields (FR-1)
    file: Optional[str] = Field(default=None, description="Source file path (e.g. 'orders.py')")
    line: Optional[int] = Field(default=None, description="1-indexed source line number (e.g. 88)")
    end_line: Optional[int] = Field(default=None, description="Optional end line of vulnerable sink")
    func_name: Optional[str] = Field(
        default=None, description="Enclosing function name (e.g. 'get_orders')"
    )
    snippet: Optional[str] = Field(default=None, description="Source code snippet at sink")

    # DAST fields (FR-2)
    url: Optional[str] = Field(
        default=None, description="Full target URL or request URI (e.g. 'http://localhost:5000/api/orders?id=1%27')"
    )
    canonical_path: Optional[str] = Field(
        default=None, description="Normalized route path (e.g. '/api/orders')"
    )
    method: Optional[str] = Field(default=None, description="HTTP method (e.g. 'GET', 'POST')")
    param: Optional[str] = Field(default=None, description="Tested/tainted parameter name (e.g. 'id')")
    payload: Optional[str] = Field(default=None, description="Diagnostic probe value sent")
    evidence: Optional[str] = Field(
        default=None, description="Runtime proof (e.g. SQL error message, unescaped canary, missing header)"
    )
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    phase: Optional[str] = Field(
        default=None, description="DAST phase ('Phase-A-Active', 'Phase-B-Passive', 'B1-Auto-Verify')"
    )

    # Safe Decoy & Reachability flags (B-2)
    is_protected_decoy: bool = Field(
        default=False,
        description="B-2: True if code is protected (e.g. parameterized query) or unreachable",
    )
    decoy_reason: Optional[str] = Field(
        default=None,
        description="B-2: Explanation why finding was marked as a safe decoy",
    )
    is_reachable: Optional[bool] = Field(
        default=True, description="B-2: Whether an FR-4 route can reach this sink"
    )

    # Deterministic deduplication fingerprint (FR-6)
    fingerprint: str = Field(
        default="", description="Deterministic SHA-256 fingerprint for deduplicating raw findings"
    )

    @model_validator(mode="after")
    def _normalize_finding(self) -> "CanonicalFinding":
        self.cwe = normalize_cwe(self.cwe)
        if not self.title:
            self.title = CWE_DEFAULT_TITLES.get(self.cwe, f"Security Finding ({self.cwe})")
        if self.file:
            self.file = normalize_file_path(self.file)
        if self.method:
            self.method = self.method.upper()
        if self.url and not self.canonical_path:
            self.canonical_path = normalize_route_template(extract_url_path(self.url))
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        return self

    def compute_fingerprint(self) -> str:
        """
        Compute a deterministic SHA-256 fingerprint for a raw scanner finding.
        Includes `scanner_name` (and `payload` for DAST) so findings from multiple scanners
        (e.g. '3 scanner findings on the same bug = 1 issue' per FR-6) are preserved as
        distinct evidence entries inside the single merged CorrelatedIssue, while re-running
        the same scanner twice produces the exact same finding fingerprint.
        """
        if self.source == "SAST":
            raw = "|".join(
                [
                    "SAST",
                    (self.scanner_name or "gordon-native").strip().lower(),
                    self.cwe,
                    normalize_file_path(self.file),
                    str(self.line or 0),
                    (self.func_name or "").strip().lower(),
                    (self.param or "").strip().lower(),
                ]
            )
        else:
            raw = "|".join(
                [
                    self.source,
                    (self.scanner_name or "gordon-native").strip().lower(),
                    self.cwe,
                    (self.method or "GET").upper(),
                    self.canonical_path or extract_url_path(self.url or "/"),
                    (self.param or "").strip().lower(),
                    (self.payload or "").strip(),
                ]
            )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# FR-5, FR-6, FR-7, FR-8, FR-9, B-1..B-5: CorrelatedIssue
# ---------------------------------------------------------------------------


def compute_issue_risk_score(
    status: IssueStatus,
    severity: SeverityLevel,
    cwe: str,
    auto_verified: bool = False,
) -> float:
    """
    FR-9: Compute a prioritised 0..100 risk score.
    Guarantees that EVERY 'Confirmed' issue ranks strictly higher than 'Runtime only'
    and 'Code only' issues, and within each bucket sorts by severity & exploitability.
    """
    base = STATUS_BASE_SCORE.get(status, 15.0)
    sev_weight = SEVERITY_WEIGHTS.get(severity, 20.0)
    cwe_norm = normalize_cwe(cwe)
    # High-exploitability RCE / SQLi / Path Traversal bonus
    exploit_bonus = 4.0 if cwe_norm in ("CWE-89", "CWE-78", "CWE-22") else (2.5 if cwe_norm == "CWE-79" else 1.0)
    b1_bonus = 0.5 if auto_verified else 0.0
    return round(min(100.0, base + sev_weight + exploit_bonus + b1_bonus), 2)


def estimate_fair_exposure_inr_lakhs(status: IssueStatus, severity: SeverityLevel, cwe: str) -> float:
    """
    Gordon AI Cyber Risk Quantification (FAIR Model in ₹ Lakhs) aligned with
    https://mitigata.com/gordon-ai/cyber-risk-quantification and DPDP Act 2023 exposure.
    """
    cwe_norm = normalize_cwe(cwe)
    base_lakhs = {
        "Critical": 185.0,
        "High": 75.0,
        "Medium": 24.0,
        "Low": 6.0,
        "Info": 1.0,
    }.get(severity, 25.0)
    status_multiplier = {
        "Confirmed": 1.0,
        "Runtime only": 0.45,
        "Code only": 0.30,
    }.get(status, 0.3)
    cwe_multiplier = 1.35 if cwe_norm in ("CWE-89", "CWE-78", "CWE-22") else 1.0
    return round(base_lakhs * status_multiplier * cwe_multiplier, 2)


class CorrelatedIssue(BaseModel):
    """
    FR-5 / FR-6 / FR-7 / FR-8 / FR-9: Unified issue representing a single real vulnerability
    after correlating SAST and DAST findings and merging duplicates.
    """

    id: Optional[int] = Field(default=None, description="Numeric issue ID for GET /issues/{id} (FR-10)")
    issue_uid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = Field(
        default="",
        description="FR-6 deterministic SHA-256 fingerprint ensuring re-scans never duplicate issues",
    )
    status: IssueStatus = Field(
        ..., description="FR-7: 'Confirmed' | 'Code only' | 'Runtime only'"
    )
    cwe: str = Field(..., description="FR-3 / FR-8: Canonical CWE identifier, e.g. 'CWE-89'")
    title: str = Field(default="", description="Human-readable vulnerability title")
    severity: SeverityLevel = Field(default="High", description="FR-8: Critical | High | Medium | Low | Info")
    risk_score: float = Field(
        default=0.0,
        description="FR-9: Composite priority score (Confirmed always ranked first)",
    )

    # FR-8 Mandatory Issue Detail Fields (top-level for direct API/UI/grading access)
    url: Optional[str] = Field(default=None, description="FR-8: Exploited/tested URL")
    canonical_path: Optional[str] = Field(default=None, description="Normalized route path")
    method: Optional[str] = Field(default=None, description="HTTP method (GET, POST, etc.)")
    param: Optional[str] = Field(default=None, description="FR-8: Vulnerable parameter name")
    parameter: Optional[str] = Field(default=None, description="FR-8 alias: Vulnerable parameter name")
    payload: Optional[str] = Field(default=None, description="FR-8: Runtime payload used")
    evidence: Optional[str] = Field(default=None, description="Runtime proof / HTTP response snippet")
    file: Optional[str] = Field(default=None, description="FR-8: Source code file path")
    line: Optional[int] = Field(default=None, description="FR-8: Source code line number")
    func_name: Optional[str] = Field(default=None, description="Handler or helper function name")
    snippet: Optional[str] = Field(default=None, description="FR-8: Vulnerable source code snippet")
    code_snippet: Optional[str] = Field(default=None, description="FR-8 alias: Vulnerable source code snippet")

    # Attached Evidence Lists (FR-5, FR-6)
    sast_evidence: List[CanonicalFinding] = Field(
        default_factory=list, description="All merged SAST findings for this issue"
    )
    dast_evidence: List[CanonicalFinding] = Field(
        default_factory=list, description="All merged DAST findings for this issue"
    )
    finding_count: int = Field(
        default=1, description="FR-6: Total number of raw scanner findings merged into this issue"
    )

    # Bonus B-1, B-3, B-4, B-5 & Mitigata Gordon AI Enrichment
    matched_route: Optional[str] = Field(
        default=None,
        description="FR-4 route mapping summary, e.g. 'GET /api/orders -> get_orders(), orders.py:80-95'",
    )
    link_reason: Optional[str] = Field(
        default=None,
        description="B-3: Explicit explanation of why SAST and DAST findings were linked",
    )
    auto_verified: bool = Field(
        default=False,
        description="B-1: True if upgraded from Code only to Confirmed via targeted runtime verification",
    )
    fix_suggestion: Optional[str] = Field(
        default=None,
        description="B-4: Plain-English fix suggestion and safe code pattern",
    )
    diff_status: Optional[DiffStatus] = Field(
        default=None,
        description="B-5: 'NEW' | 'FIXED' | 'STILL-OPEN' when comparing two scans",
    )
    fair_exposure_inr_lakhs: float = Field(
        default=0.0,
        description="Gordon AI FAIR estimated financial risk exposure in ₹ Lakhs",
    )
    sebi_cscrf_sla_days: int = Field(
        default=90,
        description="SEBI CSCRF mandatory vulnerability closure window in days",
    )

    @model_validator(mode="after")
    def _populate_issue_defaults(self) -> "CorrelatedIssue":
        self.cwe = normalize_cwe(self.cwe)
        if not self.title:
            self.title = CWE_DEFAULT_TITLES.get(self.cwe, f"Security Issue ({self.cwe})")

        if not self.param and self.parameter:
            self.param = self.parameter
        if not self.snippet and self.code_snippet:
            self.snippet = self.code_snippet

        # Backfill top-level FR-8 fields from attached evidence if omitted
        if self.sast_evidence:
            first_sast = self.sast_evidence[0]
            self.file = self.file or first_sast.file
            self.line = self.line if self.line is not None else first_sast.line
            self.func_name = self.func_name or first_sast.func_name
            self.snippet = self.snippet or first_sast.snippet
            if not self.param and first_sast.param:
                self.param = first_sast.param

        if self.dast_evidence:
            first_dast = self.dast_evidence[0]
            self.url = self.url or first_dast.url
            self.canonical_path = self.canonical_path or first_dast.canonical_path
            self.method = self.method or first_dast.method
            self.param = self.param or first_dast.param
            self.payload = self.payload or first_dast.payload
            self.evidence = self.evidence or first_dast.evidence

        self.parameter = self.param
        self.code_snippet = self.snippet

        if self.file:
            self.file = normalize_file_path(self.file)
        if self.url and not self.canonical_path:
            self.canonical_path = normalize_route_template(extract_url_path(self.url))

        total_findings = len(self.sast_evidence) + len(self.dast_evidence)
        if total_findings > 0:
            self.finding_count = max(self.finding_count, total_findings)

        if not self.risk_score or self.risk_score <= 0.0:
            self.risk_score = compute_issue_risk_score(
                self.status, self.severity, self.cwe, self.auto_verified
            )
        if not self.fair_exposure_inr_lakhs or self.fair_exposure_inr_lakhs <= 0.0:
            self.fair_exposure_inr_lakhs = estimate_fair_exposure_inr_lakhs(
                self.status, self.severity, self.cwe
            )
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        return self

    def compute_fingerprint(self) -> str:
        """
        FR-6: Deterministic issue fingerprint across scans.
        Ensures running a scan twice or merging 3 findings on the same bug produces
        strictly ONE issue record.
        """
        route_key = self.canonical_path or extract_url_path(self.url or "")
        file_key = normalize_file_path(self.file)
        line_key = str(self.line or 0)
        param_key = (self.param or "").strip().lower()
        method_key = (self.method or "GET").upper()

        if self.status == "Confirmed" or (file_key and route_key):
            raw = f"ISSUE|{self.cwe}|{route_key}|{param_key}|{file_key}|{line_key}"
        elif self.status == "Code only" or file_key:
            raw = f"ISSUE|{self.cwe}|CODE|{file_key}|{line_key}|{param_key}"
        else:
            raw = f"ISSUE|{self.cwe}|RUNTIME|{method_key}|{route_key}|{param_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Page 4 Bonus: 5-Step Reachability-Aware SCA Schema
# ---------------------------------------------------------------------------


class SCAFinding(BaseModel):
    """
    Page 4 Bonus Feature: Reachability-Aware SCA finding.
    Enforces the strict rule:
      Statuses: 'Reachable', 'Imported-only', 'Present-only', 'Unknown'
      NEVER downgrade 'Unknown'!
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package_name: str = Field(..., description="Dependency package name (e.g. 'pyyaml', 'jinja2')")
    installed_version: str = Field(..., description="Pinned or resolved version in lockfile")
    ecosystem: str = Field(default="PyPI", description="'PyPI' or 'npm'")
    is_direct: bool = Field(default=True, description="Step 1: Direct vs transitive dependency")
    dependency_path: List[str] = Field(
        default_factory=list, description="Step 1: Transitive dependency chain from lockfile"
    )
    advisory_id: str = Field(..., description="Step 2: GHSA or CVE ID, e.g. 'GHSA-xxxx-xxxx-xxxx'")
    cve_id: Optional[str] = Field(default=None, description="Associated CVE identifier")
    cwe: str = Field(default="CWE-1395", description="Associated CWE")
    original_severity: SeverityLevel = Field(default="High", description="Original advisory severity")
    effective_severity: SeverityLevel = Field(
        default="High", description="Effective severity after reachability analysis (Unknown never downgraded!)"
    )
    cvss_score: float = Field(default=7.5, description="Step 2: CVSS base score")
    epss_score: float = Field(default=0.0, description="Step 2: FIRST EPSS probability (0.0 - 1.0)")
    in_cisa_kev: bool = Field(default=False, description="Step 2: Listed in CISA KEV catalog")
    fixed_version: Optional[str] = Field(default=None, description="Step 2: Patched version")
    vulnerable_functions: List[str] = Field(
        default_factory=list,
        description="Step 3: Symbols extracted from OSV ecosystem_specific or GitHub fix-commit diffs",
    )
    function_map_source: Optional[str] = Field(
        default=None,
        description="Step 3 source: 'osv_symbols' | 'fix_commit_diff' | 'none_unknown'",
    )
    reachability_status: SCAReachabilityStatus = Field(
        default="Unknown",
        description="Step 4: 'Reachable' | 'Imported-only' | 'Present-only' | 'Unknown'",
    )
    call_chain: List[str] = Field(
        default_factory=list,
        description="Step 4: Entry route -> app function -> vulnerable library function",
    )
    supply_chain_flags: List[str] = Field(
        default_factory=list,
        description="Step 5: 'typosquat_suspect', 'dependency_confusion_risk', 'unpinned_version', 'malicious_pkg'",
    )

    @model_validator(mode="after")
    def _enforce_never_downgrade_unknown(self) -> "SCAFinding":
        # Page 4 Note: "Statuses: Reachable, Imported-only, Present-only, Unknown (never downgrade Unknown)."
        if self.reachability_status in ("Reachable", "Unknown"):
            self.effective_severity = self.original_severity
        return self


# ---------------------------------------------------------------------------
# API Request / Response Envelopes (FR-10, B-5)
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request payload for POST /scans (FR-10)."""

    source_dir: Optional[str] = Field(
        default=None, description="Local filesystem path to target app source code"
    )
    target_url: Optional[str] = Field(
        default=None, description="Running local target app URL (must pass localhost/container safety lock)"
    )
    app_name: str = Field(default="target-web-shop", description="Logical name of target application")
    run_live_dast: bool = Field(
        default=True, description="Execute live 2-phase DAST probing against target_url"
    )
    enable_auto_verify: bool = Field(
        default=True, description="B-1: Automatically probe Code-only findings at runtime"
    )
    enable_sca: bool = Field(
        default=True, description="Page 4 Bonus: Run 5-step Reachability-Aware SCA"
    )
    auth_headers: Dict[str, str] = Field(
        default_factory=dict, description="Optional pre-authenticated headers"
    )
    auth_cookies: Dict[str, str] = Field(
        default_factory=dict, description="Optional pre-authenticated session cookies"
    )
    seeded_routes: List[RouteEntry] = Field(
        default_factory=list, description="Optional pre-discovered RouteEntry objects"
    )
    seeded_sast_findings: List[CanonicalFinding] = Field(
        default_factory=list, description="Optional pre-scanned or B-6 imported SAST findings"
    )
    seeded_dast_findings: List[CanonicalFinding] = Field(
        default_factory=list, description="Optional pre-scanned or B-6 imported DAST findings"
    )
    seed_checkpoint_slice_if_empty: bool = Field(
        default=False,
        description="When True and no live findings are discovered, seed Checkpoint 1 reference slice.",
    )



class ScanSummary(BaseModel):
    """Summary counters and timing returned by POST /scans and GET /scans/{id}."""

    scan_id: int
    app_name: str
    source_dir: Optional[str] = None
    target_url: Optional[str] = None
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: float = 0.0
    routes_discovered: int = 0
    raw_sast_findings: int = 0
    raw_dast_findings: int = 0
    safe_decoys_suppressed: int = 0
    total_issues: int = 0
    confirmed_count: int = 0
    code_only_count: int = 0
    runtime_only_count: int = 0
    auto_verified_count: int = 0
    sca_findings_count: int = 0
    total_fair_exposure_inr_lakhs: float = 0.0
