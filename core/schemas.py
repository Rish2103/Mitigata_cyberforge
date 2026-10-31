"""
CyberForge Core Shared Schemas.
Implements FR-3 (Canonical Finding Format), FR-4 (Route Entry), and FR-7/FR-8/FR-9 (Correlated Issue).
Zero-Merge Conflict boundary agreed between Person A and Person B.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingSource(str, Enum):
    SAST = "SAST"
    DAST = "DAST"


class IssueStatus(str, Enum):
    CONFIRMED = "Confirmed"      # Found by both SAST and DAST (FR-7)
    CODE_ONLY = "Code only"      # Found by SAST, not proven at runtime (FR-7)
    RUNTIME_ONLY = "Runtime only"# Found by DAST, no matching code location (FR-7)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class RouteEntry(BaseModel):
    """
    FR-4 Route Entry: AST-extracted routing map.
    Links a public URL pattern to the exact controller function, code lines,
    handler parameters, and 1-hop helper calls.
    """
    method: str = Field(..., description="HTTP Method: GET, POST, PUT, DELETE, etc.")
    path_pattern: str = Field(..., description="Route pattern: e.g. /api/orders or /orders/<id>")
    regex_pattern: Optional[str] = Field(None, description="Compiled regex matching live URLs")
    file_path: str = Field(..., description="Relative or absolute path to source file")
    func_name: str = Field(..., description="Name of the handler function")
    start_line: int = Field(..., description="Starting line number of the handler")
    end_line: int = Field(..., description="Ending line number of the handler")
    parameters: List[str] = Field(default_factory=list, description="Query, path, or body param names extracted from AST")
    called_funcs: List[str] = Field(default_factory=list, description="1-hop helper functions called by this handler")
    framework: str = Field(default="flask", description="Detected framework: flask, fastapi, django, express")


class CanonicalFinding(BaseModel):
    """
    FR-3 Canonical Finding: Uniform schema for both SAST and DAST reports.
    """
    id: str = Field(..., description="Deterministic unique fingerprint hash of finding")
    source: FindingSource = Field(..., description="SAST or DAST")
    cwe: str = Field(..., description="CWE identifier: e.g. CWE-89")
    cwe_name: Optional[str] = Field(None, description="Human readable CWE name")
    severity: Severity = Field(..., description="Severity rating")
    
    # SAST specific fields
    file_path: Optional[str] = Field(None, description="File path where sink was found (SAST)")
    line: Optional[int] = Field(None, description="Line number where sink was found (SAST)")
    code_snippet: Optional[str] = Field(None, description="Vulnerable code snippet (SAST)")
    is_protected_decoy: bool = Field(default=False, description="True if marked safe by decoy filter (B-2)")
    decoy_reason: Optional[str] = Field(None, description="Reason for decoy suppression (B-2)")
    
    # DAST specific fields
    url: Optional[str] = Field(None, description="Target URL probed (DAST)")
    method: Optional[str] = Field(None, description="HTTP method used (DAST)")
    param: Optional[str] = Field(None, description="Vulnerable parameter probed (DAST)")
    payload: Optional[str] = Field(None, description="Exploit test payload used (DAST)")
    evidence: Optional[str] = Field(None, description="Runtime proof: e.g. SQL error, canary reflection (DAST)")
    
    # Metadata
    raw_details: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner details")


class CorrelatedIssue(BaseModel):
    """
    FR-5, FR-6, FR-7, FR-8, FR-9 Correlated Issue:
    Unifies SAST code location with DAST runtime proof.
    """
    id: str = Field(..., description="Unique deterministic issue identifier")
    status: IssueStatus = Field(..., description="Confirmed, Code only, or Runtime only (FR-7)")
    cwe: str = Field(..., description="CWE identifier: e.g. CWE-89")
    cwe_name: str = Field(..., description="Human readable vulnerability title")
    severity: Severity = Field(..., description="Overall severity")
    risk_score: float = Field(..., description="Exploitability risk score 0.0 - 100.0 (FR-9)")
    
    # Consolidated Evidence (FR-8)
    url: Optional[str] = Field(None, description="Probed URL or associated route")
    method: Optional[str] = Field(None, description="HTTP method")
    param: Optional[str] = Field(None, description="Vulnerable parameter name")
    payload: Optional[str] = Field(None, description="Exploit test payload proving runtime weakness")
    file_path: Optional[str] = Field(None, description="Source code file path to fix")
    line: Optional[int] = Field(None, description="Exact line of code to change")
    code_snippet: Optional[str] = Field(None, description="Source code snippet showing the sink")
    
    # B-3 Link explanation
    link_reason: Optional[str] = Field(None, description="Deterministic link explanation badge (B-3)")
    
    # B-4 Plain English remediation
    fix_suggestion: Optional[str] = Field(None, description="Remediation advice and code replacement (B-4)")
    
    # Underlying finding objects
    sast_finding: Optional[CanonicalFinding] = None
    dast_finding: Optional[CanonicalFinding] = None
    
    # Financial / Compliance context (Mitigata InsurTech alignment)
    estimated_exposure_inr: Optional[float] = Field(None, description="Estimated FAIR financial loss in INR")
    sebi_sla_days: Optional[int] = Field(None, description="SEBI CSCRF statutory closure window in days")


class SCAReachabilityStatus(str, Enum):
    """
    PRD Page 4 Bonus: 4 Mandatory Reachability Statuses.
    Rule: Never downgrade Unknown!
    """
    REACHABLE = "Reachable"
    IMPORTED_ONLY = "Imported-only"
    PRESENT_ONLY = "Present-only"
    UNKNOWN = "Unknown"


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
    line: Optional[int] = Field(None, description="Line number in manifest/lockfile")


class VulnerabilityAdvisory(BaseModel):
    """
    Step 2 & 3 (GHSA Match + Function Map): Advisory with CVSS, EPSS, KEV, and vulnerable symbols.
    """
    advisory_id: str = Field(..., description="GHSA ID, e.g., GHSA-xxxx-xxxx-xxxx")
    cve_id: Optional[str] = Field(None, description="CVE identifier, e.g., CVE-2023-xxxx")
    package: str = Field(..., description="Affected package name")
    ecosystem: str = Field(default="pypi", description="pypi or npm")
    affected_versions: str = Field(..., description="Affected version range specification")
    fixed_version: Optional[str] = Field(None, description="Patched version")
    severity: Severity = Field(..., description="Original advisory severity")
    cvss_score: float = Field(..., description="CVSS v3 base score (0.0 - 10.0)")
    epss_score: float = Field(default=0.0, description="Exploit Prediction Scoring System probability (0.0 - 1.0)")
    is_kev: bool = Field(default=False, description="True if listed in CISA Known Exploited Vulnerabilities")
    vulnerable_symbols: List[str] = Field(default_factory=list, description="OSV symbols or fix-commit diff functions")
    symbol_source: str = Field(default="osv", description="Source of function map: osv, fix_commit_diff, or unknown")
    summary: str = Field(default="", description="Short description of vulnerability")


class SCAReachabilityFinding(BaseModel):
    """
    Step 4 (Call Graph & Status): Reachability-evaluated SCA finding.
    Strictly preserves original_severity when status == Unknown.
    """
    id: str = Field(..., description="Deterministic SCA finding fingerprint")
    package: str = Field(..., description="Package name")
    installed_version: str = Field(..., description="Installed version")
    ecosystem: str = Field(default="pypi", description="pypi or npm")
    advisory_id: str = Field(..., description="GHSA ID")
    cve_id: Optional[str] = Field(None, description="CVE ID")
    status: SCAReachabilityStatus = Field(..., description="Reachable, Imported-only, Present-only, or Unknown")
    original_severity: Severity = Field(..., description="Original advisory severity")
    effective_severity: Severity = Field(..., description="Effective severity (Never downgraded for Unknown!)")
    cvss_score: float = Field(..., description="CVSS base score")
    epss_score: float = Field(default=0.0, description="EPSS probability (0.0 - 1.0)")
    is_kev: bool = Field(default=False, description="CISA KEV status")
    transitive_path: List[str] = Field(default_factory=list, description="SBOM transitive dependency path")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable library functions")
    call_chain: List[str] = Field(default_factory=list, description="Entry point -> App function -> Library function chain")
    entry_route: Optional[str] = Field(None, description="Entry route reaching the vulnerable function")
    file_path: Optional[str] = Field(None, description="Application source file invoking or importing the package")
    line: Optional[int] = Field(None, description="Line number of invocation or import")
    fixed_version: Optional[str] = Field(None, description="Patched version to upgrade to")
    remediation: str = Field(..., description="Plain-English remediation advice")


class SupplyChainAlert(BaseModel):
    """
    Step 5 (Supply Chain): Malicious packages, typosquats, dependency confusion, and unpinned lockfiles.
    """
    id: str = Field(..., description="Deterministic alert ID")
    alert_type: str = Field(..., description="malicious_package, typosquat, dependency_confusion, or unpinned_lockfile")
    package: str = Field(..., description="Suspect package name")
    version: Optional[str] = Field(None, description="Declared version specifier")
    severity: Severity = Field(..., description="Alert severity")
    source_file: str = Field(..., description="Lockfile or manifest file path")
    line: Optional[int] = Field(None, description="Line number in file")
    target_legit_package: Optional[str] = Field(None, description="Likely intended legitimate package (for typosquats)")
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

