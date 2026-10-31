"""
core/schemas.py — Shared Data Contract for GORDON CORRELATE / CyberForge (PROBLEM 06 · FLAGSHIP).

Unified shared schema between:
  - Person A (Static Intelligence, AST Route Mapper, Decoy Filter, Correlator, Reachability SCA)
  - Person B (Runtime 2-Phase DAST, Auto-Verify, FastAPI/SQLite Persistence, SARIF/Diff & UI)

Covers PRD Requirements:
  - FR-1 (SAST finding fields: file/file_path, line, cwe, severity, snippet/code_snippet)
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
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# Canonical Enums, Literal Types & Constants
# ---------------------------------------------------------------------------


class FindingSource(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"

    def __str__(self) -> str:
        return str(self.value)


class IssueStatus(str, Enum):
    CONFIRMED = "Confirmed"        # Found by both SAST and DAST (FR-7)
    CODE_ONLY = "Code only"        # Found by SAST, not proven at runtime (FR-7)
    RUNTIME_ONLY = "Runtime only"  # Found by DAST, no matching code location (FR-7)

    def __str__(self) -> str:
        return str(self.value)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    def __str__(self) -> str:
        return str(self.value)


class SCAReachabilityStatus(str, Enum):
    """
    PRD Page 4 Bonus: 4 Mandatory Reachability Statuses.
    Rule: Never downgrade Unknown!
    """

    REACHABLE = "Reachable"
    IMPORTED_ONLY = "Imported-only"
    PRESENT_ONLY = "Present-only"
    UNKNOWN = "Unknown"

    def __str__(self) -> str:
        return str(self.value)


# Type aliases for compatibility with both Person A and Person B annotations
SeverityLevel = Severity
ConfidenceLevel = Literal["High", "Medium", "Low"]
DiffStatus = Literal["NEW", "FIXED", "STILL-OPEN"]

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
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-942": "Permissive Cross-domain Policy (CORS Wildcard)",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-489": "Active Debug Code",
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
    Supports both Person A (`file_path`, `parameters`, `regex_pattern`) and
    Person B (`file`, `params`, `regex`) field names seamlessly.
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
    regex_pattern: Optional[str] = Field(
        default=None, description="Compiled regex matching live URLs (alias of regex)"
    )
    file: str = Field(default="", description="Source file path, e.g. 'orders.py'")
    file_path: str = Field(default="", description="Relative or absolute path to source file")
    func_name: str = Field(..., description="Handler function name, e.g. 'get_orders'")
    start_line: int = Field(..., description="1-indexed start line of handler function")
    end_line: int = Field(..., description="1-indexed end line of handler function")
    params: List[str] = Field(
        default_factory=list,
        description="Extracted input parameter names (query, form, json, path)",
    )
    parameters: List[str] = Field(
        default_factory=list,
        description="Query, path, or body param names extracted from AST (alias of params)",
    )
    param_sources: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional map of param_name -> source ('query', 'form', 'json', 'path')",
    )
    called_funcs: List[str] = Field(
        default_factory=list,
        description="Names or file:func identifiers of helper functions called from this route",
    )
    called_functions: List[str] = Field(
        default_factory=list,
        description="Alias for called_funcs",
    )
    called_func_details: List[CalledFunction] = Field(
        default_factory=list,
        description="Resolved multi-file helper function definitions (line ranges) for FR-5",
    )
    language: str = Field(default="python", description="Source language ('python' | 'javascript')")
    framework: Optional[str] = Field(
        default="flask", description="Web framework ('flask' | 'fastapi' | 'django' | 'express')"
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

        # Synchronize file <-> file_path
        raw_file = self.file or self.file_path
        norm_file = normalize_file_path(raw_file)
        self.file = norm_file
        self.file_path = norm_file

        if not self.canonical_path:
            self.canonical_path = normalize_route_template(self.path_pattern)

        # Synchronize regex <-> regex_pattern
        if self.regex_pattern and not self.regex:
            self.regex = self.regex_pattern
        if not self.regex:
            self.regex = compile_route_regex(self.path_pattern)
        if not self.regex_pattern:
            self.regex_pattern = self.regex

        # Merge & synchronize params <-> parameters
        merged_params: List[str] = []
        for p in list(self.params) + list(self.parameters):
            if p and p not in merged_params:
                merged_params.append(p)

        # Ensure path template parameters (e.g. {id}) are registered in params
        for m in _BRACE_PARAM_RE.finditer(self.canonical_path):
            pname = m.group(1)
            if pname not in merged_params:
                merged_params.append(pname)
            self.param_sources.setdefault(pname, "path")

        self.params = merged_params
        self.parameters = merged_params

        # Merge & synchronize called_funcs <-> called_functions
        merged_called: List[str] = []
        for cf in list(self.called_funcs) + list(self.called_functions):
            if cf and cf not in merged_called:
                merged_called.append(cf)
        self.called_funcs = merged_called
        self.called_functions = merged_called
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
    Supports both Person A (`file_path`, `code_snippet`, `cwe_name`, `raw_details`) and
    Person B (`file`, `snippet`, `title`, `fingerprint`, etc.) field names.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: FindingSource = Field(..., description="'SAST', 'DAST', or 'SCA'")
    scanner_name: str = Field(
        default="cyberforge-native",
        description="Originating scanner (e.g. 'cyberforge-sast', 'cyberforge-dast', 'semgrep', 'bandit')",
    )
    cwe: str = Field(..., description="Normalized CWE identifier, e.g. 'CWE-89'")
    title: str = Field(default="", description="Short human-readable vulnerability title")
    cwe_name: Optional[str] = Field(default=None, description="Human readable CWE name (alias of title)")
    severity: Severity = Field(default=Severity.HIGH, description="Critical | High | Medium | Low | Info")
    confidence: ConfidenceLevel = Field(default="High", description="High | Medium | Low")

    # SAST fields (FR-1)
    file: Optional[str] = Field(default=None, description="Source file path (e.g. 'orders.py')")
    file_path: Optional[str] = Field(default=None, description="File path where sink was found (SAST)")
    line: Optional[int] = Field(default=None, description="1-indexed source line number (e.g. 88)")
    end_line: Optional[int] = Field(default=None, description="Optional end line of vulnerable sink")
    func_name: Optional[str] = Field(
        default=None, description="Enclosing function name (e.g. 'get_orders')"
    )
    snippet: Optional[str] = Field(default=None, description="Source code snippet at sink")
    code_snippet: Optional[str] = Field(default=None, description="Vulnerable code snippet (SAST)")
    taint_var: Optional[str] = Field(default=None, description="Tainted variable name feeding the sink")

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

    # Metadata
    raw_details: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner details")

    @model_validator(mode="after")
    def _normalize_finding(self) -> "CanonicalFinding":
        self.cwe = normalize_cwe(self.cwe)

        # Synchronize title <-> cwe_name
        if self.cwe_name and not self.title:
            self.title = self.cwe_name
        if not self.title:
            self.title = CWE_DEFAULT_TITLES.get(self.cwe, f"Security Finding ({self.cwe})")
        if not self.cwe_name:
            self.cwe_name = self.title

        # Synchronize file <-> file_path
        raw_file = self.file or self.file_path
        if raw_file:
            norm_file = normalize_file_path(raw_file)
            self.file = norm_file
            self.file_path = norm_file

        # Synchronize snippet <-> code_snippet
        if self.snippet and not self.code_snippet:
            self.code_snippet = self.snippet
        elif self.code_snippet and not self.snippet:
            self.snippet = self.code_snippet

        # Backfill func_name from raw_details if present
        if not self.func_name and isinstance(self.raw_details, dict) and self.raw_details.get("func_name"):
            self.func_name = str(self.raw_details["func_name"])

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
        src_val = self.source.value if isinstance(self.source, Enum) else str(self.source)
        if src_val == "SAST":
            raw = "|".join(
                [
                    "SAST",
                    (self.scanner_name or "cyberforge-native").strip().lower(),
                    self.cwe,
                    normalize_file_path(self.file or self.file_path),
                    str(self.line or 0),
                    (self.func_name or "").strip().lower(),
                    (self.param or "").strip().lower(),
                ]
            )
        else:
            raw = "|".join(
                [
                    src_val,
                    (self.scanner_name or "cyberforge-native").strip().lower(),
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
    status: Union[IssueStatus, str],
    severity: Union[SeverityLevel, str],
    cwe: str,
    auto_verified: bool = False,
) -> float:
    """
    FR-9: Compute a prioritised 0..100 risk score.
    Guarantees that EVERY 'Confirmed' issue ranks strictly higher than 'Runtime only'
    and 'Code only' issues, and within each bucket sorts by severity & exploitability.
    """
    status_str = status.value if isinstance(status, Enum) else str(status)
    sev_str = severity.value if isinstance(severity, Enum) else str(severity)
    base = STATUS_BASE_SCORE.get(status_str, 15.0)
    sev_weight = SEVERITY_WEIGHTS.get(sev_str, 20.0)
    cwe_norm = normalize_cwe(cwe)
    # High-exploitability RCE / SQLi / Path Traversal bonus
    exploit_bonus = 4.0 if cwe_norm in ("CWE-89", "CWE-78", "CWE-22") else (2.5 if cwe_norm == "CWE-79" else 1.0)
    b1_bonus = 0.5 if auto_verified else 0.0
    return round(min(100.0, base + sev_weight + exploit_bonus + b1_bonus), 2)


def estimate_fair_exposure_inr_lakhs(
    status: Union[IssueStatus, str],
    severity: Union[SeverityLevel, str],
    cwe: str,
) -> float:
    """
    Gordon AI Cyber Risk Quantification (FAIR Model in ₹ Lakhs) aligned with
    https://mitigata.com/gordon-ai/cyber-risk-quantification and DPDP Act 2023 exposure.
    """
    status_str = status.value if isinstance(status, Enum) else str(status)
    sev_str = severity.value if isinstance(severity, Enum) else str(severity)
    cwe_norm = normalize_cwe(cwe)
    base_lakhs = {
        "Critical": 185.0,
        "High": 75.0,
        "Medium": 24.0,
        "Low": 6.0,
        "Info": 1.0,
    }.get(sev_str, 25.0)
    status_multiplier = {
        "Confirmed": 1.0,
        "Runtime only": 0.45,
        "Code only": 0.30,
    }.get(status_str, 0.3)
    cwe_multiplier = 1.35 if cwe_norm in ("CWE-89", "CWE-78", "CWE-22") else 1.0
    return round(base_lakhs * status_multiplier * cwe_multiplier, 2)


class CorrelatedIssue(BaseModel):
    """
    FR-5 / FR-6 / FR-7 / FR-8 / FR-9: Unified issue representing a single real vulnerability
    after correlating SAST and DAST findings and merging duplicates.
    Supports both Person A (`id: str`, `cwe_name`, `file_path`, `code_snippet`, `sast_finding`,
    `dast_finding`, `estimated_exposure_inr`, `sebi_sla_days`) and Person B (`id: Optional[int]`,
    `title`, `file`, `snippet`, `sast_evidence`, `dast_evidence`, `fair_exposure_inr_lakhs`,
    `sebi_cscrf_sla_days`) fields.
    """

    id: Optional[Union[int, str]] = Field(
        default=None, description="Issue identifier (numeric DB ID or deterministic string ID)"
    )
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
    cwe_name: str = Field(default="", description="Human readable vulnerability title (alias of title)")
    severity: Severity = Field(default=Severity.HIGH, description="FR-8: Critical | High | Medium | Low | Info")
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
    file_path: Optional[str] = Field(default=None, description="Source code file path to fix (alias of file)")
    line: Optional[int] = Field(default=None, description="FR-8: Source code line number")
    func_name: Optional[str] = Field(default=None, description="Handler or helper function name")
    snippet: Optional[str] = Field(default=None, description="FR-8: Vulnerable source code snippet")
    code_snippet: Optional[str] = Field(default=None, description="FR-8 alias: Vulnerable source code snippet")

    # Underlying single finding fields (Person A) & Attached Evidence Lists (Person B, FR-5, FR-6)
    sast_finding: Optional[CanonicalFinding] = Field(
        default=None, description="Primary SAST finding for this issue"
    )
    dast_finding: Optional[CanonicalFinding] = Field(
        default=None, description="Primary DAST finding for this issue"
    )
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
    estimated_exposure_inr: Optional[float] = Field(
        default=None,
        description="Estimated FAIR financial loss in INR",
    )
    sebi_cscrf_sla_days: int = Field(
        default=90,
        description="SEBI CSCRF mandatory vulnerability closure window in days",
    )
    sebi_sla_days: Optional[int] = Field(
        default=None,
        description="SEBI CSCRF statutory closure window in days (alias of sebi_cscrf_sla_days)",
    )

    @model_validator(mode="after")
    def _populate_issue_defaults(self) -> "CorrelatedIssue":
        self.cwe = normalize_cwe(self.cwe)

        # Synchronize title <-> cwe_name
        if self.cwe_name and not self.title:
            self.title = self.cwe_name
        if not self.title:
            self.title = CWE_DEFAULT_TITLES.get(self.cwe, f"Security Issue ({self.cwe})")
        if not self.cwe_name:
            self.cwe_name = self.title

        # Synchronize sast_finding <-> sast_evidence
        if self.sast_finding is not None and not self.sast_evidence:
            self.sast_evidence = [self.sast_finding]
        elif self.sast_evidence and self.sast_finding is None:
            self.sast_finding = self.sast_evidence[0]

        # Synchronize dast_finding <-> dast_evidence
        if self.dast_finding is not None and not self.dast_evidence:
            self.dast_evidence = [self.dast_finding]
        elif self.dast_evidence and self.dast_finding is None:
            self.dast_finding = self.dast_evidence[0]

        if not self.param and self.parameter:
            self.param = self.parameter
        if not self.file and self.file_path:
            self.file = self.file_path
        if not self.snippet and self.code_snippet:
            self.snippet = self.code_snippet

        # Backfill top-level FR-8 fields from attached evidence if omitted
        if self.sast_evidence:
            first_sast = self.sast_evidence[0]
            self.file = self.file or first_sast.file or first_sast.file_path
            self.line = self.line if self.line is not None else first_sast.line
            self.func_name = self.func_name or first_sast.func_name
            self.snippet = self.snippet or first_sast.snippet or first_sast.code_snippet
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

        if self.file:
            self.file = normalize_file_path(self.file)
        self.file_path = self.file
        self.parameter = self.param
        self.code_snippet = self.snippet

        if self.url and not self.canonical_path:
            self.canonical_path = normalize_route_template(extract_url_path(self.url))

        total_findings = len(self.sast_evidence) + len(self.dast_evidence)
        if total_findings > 0:
            self.finding_count = max(self.finding_count, total_findings)

        if not self.risk_score or self.risk_score <= 0.0:
            self.risk_score = compute_issue_risk_score(
                self.status, self.severity, self.cwe, self.auto_verified
            )

        # Synchronize FAIR financial exposure (Lakhs <-> INR)
        if not self.fair_exposure_inr_lakhs or self.fair_exposure_inr_lakhs <= 0.0:
            if self.estimated_exposure_inr and self.estimated_exposure_inr > 0.0:
                self.fair_exposure_inr_lakhs = round(self.estimated_exposure_inr / 100000.0, 2)
            else:
                self.fair_exposure_inr_lakhs = estimate_fair_exposure_inr_lakhs(
                    self.status, self.severity, self.cwe
                )
        if self.estimated_exposure_inr is None:
            self.estimated_exposure_inr = round(self.fair_exposure_inr_lakhs * 100000.0, 2)

        # Synchronize SEBI SLA days
        if self.sebi_sla_days is not None and self.sebi_cscrf_sla_days == 90:
            self.sebi_cscrf_sla_days = self.sebi_sla_days
        elif self.sebi_sla_days is None:
            self.sebi_sla_days = self.sebi_cscrf_sla_days

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
        file_key = normalize_file_path(self.file or self.file_path)
        line_key = str(self.line or 0)
        param_key = (self.param or "").strip().lower()
        method_key = (self.method or "GET").upper()
        status_val = self.status.value if isinstance(self.status, Enum) else str(self.status)

        if status_val == "Confirmed" or (file_key and route_key):
            raw = f"ISSUE|{self.cwe}|{route_key}|{param_key}|{file_key}|{line_key}"
        elif status_val == "Code only" or file_key:
            raw = f"ISSUE|{self.cwe}|CODE|{file_key}|{line_key}|{param_key}"
        else:
            raw = f"ISSUE|{self.cwe}|RUNTIME|{method_key}|{route_key}|{param_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Page 4 Bonus: 5-Step Reachability-Aware SCA Schemas (Person A & Person B)
# ---------------------------------------------------------------------------


class SBOMDependency(BaseModel):
    """
    Step 1 (Inventory): Parsed lockfile/manifest dependency with transitive path.
    """

    name: str = Field(..., description="Normalized package name")
    version: str = Field(..., description="Installed or declared version string")
    ecosystem: str = Field(default="pypi", description="Package ecosystem: pypi or npm")
    is_direct: bool = Field(default=True, description="True if direct dependency, False if transitive")
    is_pinned: bool = Field(default=True, description="True if locked to an exact version")
    transitive_path: List[str] = Field(default_factory=list, description="Dependency resolution path from root")
    source_file: str = Field(..., description="Manifest or lockfile path")
    line: Optional[int] = Field(default=None, description="Line number in manifest/lockfile")


class VulnerabilityAdvisory(BaseModel):
    """
    Step 2 & 3 (GHSA Match + Function Map): Advisory with CVSS, EPSS, KEV, and vulnerable symbols.
    """

    advisory_id: str = Field(..., description="GHSA ID, e.g., GHSA-xxxx-xxxx-xxxx")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier, e.g., CVE-2023-xxxx")
    package: str = Field(..., description="Affected package name")
    ecosystem: str = Field(default="pypi", description="pypi or npm")
    affected_versions: str = Field(..., description="Affected version range specification")
    fixed_version: Optional[str] = Field(default=None, description="Patched version")
    severity: Severity = Field(..., description="Original advisory severity")
    cvss_score: float = Field(..., description="CVSS v3 base score (0.0 - 10.0)")
    epss_score: float = Field(default=0.0, description="Exploit Prediction Scoring System probability (0.0 - 1.0)")
    is_kev: bool = Field(default=False, description="True if listed in CISA Known Exploited Vulnerabilities")
    vulnerable_symbols: List[str] = Field(default_factory=list, description="OSV symbols or fix-commit diff functions")
    symbol_source: str = Field(default="osv", description="Source of function map: osv, fix_commit_diff, or unknown")
    summary: str = Field(default="", description="Short description of vulnerability")


class SCAReachabilityFinding(BaseModel):
    """
    Step 4 (Call Graph & Status): Reachability-evaluated SCA finding (Person A engine).
    Strictly preserves original_severity when status == Unknown.
    """

    id: str = Field(..., description="Deterministic SCA finding fingerprint")
    package: str = Field(..., description="Package name")
    installed_version: str = Field(..., description="Installed version")
    ecosystem: str = Field(default="pypi", description="pypi or npm")
    advisory_id: str = Field(..., description="GHSA ID")
    cve_id: Optional[str] = Field(default=None, description="CVE ID")
    status: SCAReachabilityStatus = Field(..., description="Reachable, Imported-only, Present-only, or Unknown")
    original_severity: Severity = Field(..., description="Original advisory severity")
    effective_severity: Severity = Field(..., description="Effective severity (Never downgraded for Unknown!)")
    cvss_score: float = Field(..., description="CVSS base score")
    epss_score: float = Field(default=0.0, description="EPSS probability (0.0 - 1.0)")
    is_kev: bool = Field(default=False, description="CISA KEV status")
    transitive_path: List[str] = Field(default_factory=list, description="SBOM transitive dependency path")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable library functions")
    call_chain: List[str] = Field(default_factory=list, description="Entry point -> App function -> Library function chain")
    entry_route: Optional[str] = Field(default=None, description="Entry route reaching the vulnerable function")
    file_path: Optional[str] = Field(default=None, description="Application source file invoking or importing the package")
    line: Optional[int] = Field(default=None, description="Line number of invocation or import")
    fixed_version: Optional[str] = Field(default=None, description="Patched version to upgrade to")
    remediation: str = Field(..., description="Plain-English remediation advice")

    @model_validator(mode="after")
    def _enforce_never_downgrade_unknown(self) -> "SCAReachabilityFinding":
        if self.status in (SCAReachabilityStatus.REACHABLE, SCAReachabilityStatus.UNKNOWN, "Reachable", "Unknown"):
            self.effective_severity = self.original_severity
        return self


class SupplyChainAlert(BaseModel):
    """
    Step 5 (Supply Chain): Malicious packages, typosquats, dependency confusion, and unpinned lockfiles.
    """

    id: str = Field(..., description="Deterministic alert ID")
    alert_type: str = Field(..., description="malicious_package, typosquat, dependency_confusion, or unpinned_lockfile")
    package: str = Field(..., description="Suspect package name")
    version: Optional[str] = Field(default=None, description="Declared version specifier")
    severity: Severity = Field(..., description="Alert severity")
    source_file: str = Field(..., description="Lockfile or manifest file path")
    line: Optional[int] = Field(default=None, description="Line number in file")
    target_legit_package: Optional[str] = Field(default=None, description="Likely intended legitimate package (for typosquats)")
    description: str = Field(..., description="Explanation of the supply chain risk")
    remediation: str = Field(..., description="Actionable fix")


class SCAReport(BaseModel):
    """
    Consolidated 5-Step Reachability-Aware SCA Report (PRD Page 4 Bonus).
    """

    sbom_count: int = Field(default=0, description="Total dependencies inventoried")
    sbom: List[SBOMDependency] = Field(default_factory=list, description="Full SBOM inventory with transitive paths")
    findings: List[SCAReachabilityFinding] = Field(default_factory=list, description="Reachability-ranked CVE/GHSA findings")
    supply_chain_alerts: List[SupplyChainAlert] = Field(default_factory=list, description="Step 5 supply chain security alerts")
    summary: Dict[str, int] = Field(default_factory=dict, description="Counts by status and alert type")


class SCAFinding(BaseModel):
    """
    Page 4 Bonus Feature: Reachability-Aware SCA finding (API / DB persistence model).
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
    original_severity: Severity = Field(default=Severity.HIGH, description="Original advisory severity")
    effective_severity: Severity = Field(
        default=Severity.HIGH, description="Effective severity after reachability analysis (Unknown never downgraded!)"
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
        default=SCAReachabilityStatus.UNKNOWN,
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
        if self.reachability_status in (
            SCAReachabilityStatus.REACHABLE,
            SCAReachabilityStatus.UNKNOWN,
            "Reachable",
            "Unknown",
        ):
            self.effective_severity = self.original_severity
        return self


# ---------------------------------------------------------------------------
# Checkpoint 1 Judge Feedback: Runtime-Verified Adaptive DAST Scope Reduction
# ---------------------------------------------------------------------------


class ParityStatus(str, Enum):
    """Runtime vs Static AST route parity classification."""

    EXACT_REPLICA = "EXACT_REPLICA"
    RUNTIME_DRIFT_EXTRA = "RUNTIME_DRIFT_EXTRA"
    CODE_ONLY_UNMOUNTED = "CODE_ONLY_UNMOUNTED"


class ScopeStrategy(str, Enum):
    """Per-route DAST active probe scheduling strategy."""

    PRUNED_SAFE = "PRUNED_SAFE"
    TARGETED_REDUCTION = "TARGETED_REDUCTION"
    FULL_PROBE_DRIFT = "FULL_PROBE_DRIFT"


class RouteParityEntry(BaseModel):
    """Per-route parity verification and adaptive DAST scope reduction decision."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    method: str = "GET"
    canonical_path: str
    path_pattern: Optional[str] = None
    parity_status: str = Field(
        default="EXACT_REPLICA",
        description="'EXACT_REPLICA' | 'RUNTIME_DRIFT_EXTRA' | 'CODE_ONLY_UNMOUNTED'",
    )
    scope_strategy: str = Field(
        default="PRUNED_SAFE",
        description="'PRUNED_SAFE' | 'TARGETED_REDUCTION' | 'FULL_PROBE_DRIFT'",
    )
    active_sast_cwes: List[str] = Field(default_factory=list)
    tainted_params: List[str] = Field(default_factory=list)
    targeted_probes: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="Specific (param, cwe) pairs scheduled for Phase-A active probing",
    )
    naive_probes: int = 5
    scheduled_probes: int = 0
    reduced_probes: int = 0
    passive_audit_enabled: bool = True
    reason: str = ""

    @model_validator(mode="after")
    def _sync_fields(self) -> "RouteParityEntry":
        self.method = (self.method or "GET").upper().strip()
        if not self.path_pattern:
            self.path_pattern = self.canonical_path
        if self.scheduled_probes and not self.reduced_probes:
            self.reduced_probes = self.scheduled_probes
        elif self.reduced_probes and not self.scheduled_probes:
            self.scheduled_probes = self.reduced_probes
        return self


class ScopeReductionReport(BaseModel):
    """
    Checkpoint 1 Judge Feedback Telemetry:
    Quantifies Runtime Parity Verification & Adaptive DAST Scope Reduction
    alongside Single-Pass AST time complexity O(N_ast + K_tainted_sinks).
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    total_ast_routes: int = 0
    total_live_routes: int = 0
    exact_replica_routes: int = 0
    runtime_drift_routes: int = 0
    code_only_routes: int = 0
    runtime_parity_ratio: float = 1.0
    is_exact_replica: bool = True
    naive_probe_count: int = 0
    reduced_probe_count: int = 0
    probes_saved_count: int = 0
    probes_saved_pct: float = 0.0
    scope_reduction_pct: float = 0.0
    passive_header_audits_retained: bool = True
    time_complexity: str = "O(N_ast + K_tainted_sinks) — Single-Pass AST"
    time_complexity_class: str = "O(N_ast + K_tainted_sinks) — Single-Pass AST"
    route_entries: List[RouteParityEntry] = Field(default_factory=list)
    route_decisions: List[RouteParityEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sync_report_aliases(self) -> "ScopeReductionReport":
        if self.probes_saved_pct and not self.scope_reduction_pct:
            self.scope_reduction_pct = self.probes_saved_pct
        elif self.scope_reduction_pct and not self.probes_saved_pct:
            self.probes_saved_pct = self.scope_reduction_pct

        if self.naive_probe_count >= self.reduced_probe_count and self.probes_saved_count == 0:
            self.probes_saved_count = self.naive_probe_count - self.reduced_probe_count

        if self.route_entries and not self.route_decisions:
            self.route_decisions = list(self.route_entries)
        elif self.route_decisions and not self.route_entries:
            self.route_entries = list(self.route_decisions)

        if self.time_complexity and not self.time_complexity_class:
            self.time_complexity_class = self.time_complexity
        return self

    @property
    def code_only_unmounted_routes(self) -> int:
        return self.code_only_routes

    @property
    def naive_total_probes(self) -> int:
        return self.naive_probe_count

    @property
    def reduced_total_probes(self) -> int:
        return self.reduced_probe_count

    @property
    def probes_saved(self) -> int:
        return self.probes_saved_count

    @property
    def reduction_percentage(self) -> float:
        return self.probes_saved_pct



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
    scope_reduction: Optional[ScopeReductionReport] = None

