"""
5-Step Reachability-Aware SCA Engine (PRD Page 4 Bonus).

Report whether the app can actually reach a vulnerable library function, not just that a CVE exists:
1. Inventory: Parse lockfiles (requirements.txt, Pipfile.lock, poetry.lock, package-lock.json, package.json)
   into an SBOM keeping transitive dependency paths.
2. GHSA Match: Pull affected versions, fixes, CVSS, EPSS, and CISA KEV.
3. Function Map: Build it from OSV symbols and GitHub fix-commit unified diffs, since GHSA rarely lists functions.
4. Call Graph: Link FR-4 route entry points -> app functions -> library functions.
5. Supply Chain: Check for malicious packages, typosquats (Levenshtein distance), dependency confusion,
   and unpinned lockfiles.

Statuses: Reachable, Imported-only, Present-only, Unknown (STRICT RULE: NEVER downgrade Unknown!).
"""

import ast
import hashlib
import json
import os
import re
from typing import List, Dict, Optional, Set, Tuple, Any
from core.schemas import (
    SCAReachabilityStatus,
    SBOMDependency,
    VulnerabilityAdvisory,
    SCAReachabilityFinding,
    SCAFinding,
    SupplyChainAlert,
    SCAReport,
    Severity,
    RouteEntry,
)
from engine.route_mapper import RouteMapper


# Package name -> Python import module name mapping where PyPI name != import name
PYPI_TO_IMPORT_MAP: Dict[str, str] = {
    "pyyaml": "yaml",
    "pillow": "pil",
    "pyjwt": "jwt",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "python-jose": "jose",
    "pycryptodome": "crypto",
    "opencv-python": "cv2",
}


# Known transitive relationships for flat requirements.txt enrichment when # via is absent
KNOWN_TRANSITIVE_PARENTS: Dict[str, str] = {
    "werkzeug": "flask",
    "jinja2": "flask",
    "markupsafe": "jinja2",
    "itsdangerous": "flask",
    "urllib3": "requests",
    "certifi": "requests",
    "idna": "requests",
    "charset-normalizer": "requests",
    "starlette": "fastapi",
    "pydantic": "fastapi",
    "sqlparse": "django",
    "asgiref": "django",
}


# Curated Offline GHSA / OSV Knowledge Base with CVSS, EPSS, KEV, OSV symbols, and Fix-Commit Diffs
BUNDLED_ADVISORIES: List[Dict[str, Any]] = [
    {
        "advisory_id": "GHSA-8q59-q68h-6hv4",
        "cve_id": "CVE-2020-14343",
        "package": "pyyaml",
        "ecosystem": "pypi",
        "affected_versions": "<5.4",
        "fixed_version": "5.4",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "epss_score": 0.94,
        "is_kev": True,
        "vulnerable_symbols": ["load", "unsafe_load", "full_load", "FullLoader", "UnsafeLoader"],
        "symbol_source": "osv",
        "summary": "Arbitrary code execution in PyYAML via untrusted yaml.load() / FullLoader",
    },
    {
        "advisory_id": "GHSA-h5c8-rqwp-cp95",
        "cve_id": "CVE-2024-34069",
        "package": "werkzeug",
        "ecosystem": "pypi",
        "affected_versions": "<3.0.3",
        "fixed_version": "3.0.3",
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "epss_score": 0.62,
        "is_kev": False,
        "vulnerable_symbols": ["DebuggedApplication", "run_simple"],
        "symbol_source": "fix_commit_diff",
        "fix_commit_diff": "@@ -112,7 +112,9 @@ def run_simple(hostname, port, application, use_debugger=False):\n@@ -45,6 +45,8 @@ class DebuggedApplication:",
        "summary": "Werkzeug debugger remote code execution when interacting with attacker-controlled domain",
    },
    {
        "advisory_id": "GHSA-h75v-3vvj-5mfj",
        "cve_id": "CVE-2024-22195",
        "package": "jinja2",
        "ecosystem": "pypi",
        "affected_versions": "<3.1.3",
        "fixed_version": "3.1.3",
        "severity": Severity.MEDIUM,
        "cvss_score": 6.1,
        "epss_score": 0.18,
        "is_kev": False,
        "vulnerable_symbols": ["xmlattr", "do_xmlattr"],
        "symbol_source": "osv",
        "summary": "Cross-site scripting in Jinja2 xmlattr filter via attribute injection",
    },
    {
        "advisory_id": "GHSA-j8r2-6x86-q33q",
        "cve_id": "CVE-2023-32681",
        "package": "requests",
        "ecosystem": "pypi",
        "affected_versions": "<2.31.0",
        "fixed_version": "2.31.0",
        "severity": Severity.MEDIUM,
        "cvss_score": 6.1,
        "epss_score": 0.25,
        "is_kev": False,
        "vulnerable_symbols": ["get", "post", "request", "Session", "rebuild_proxies"],
        "symbol_source": "fix_commit_diff",
        "fix_commit_diff": "@@ -280,6 +280,10 @@ def rebuild_proxies(self, prepared_request, proxies):",
        "summary": "Unintended leak of Proxy-Authorization header in requests upon cross-origin redirect",
    },
    {
        "advisory_id": "GHSA-v845-jxx5-vc9f",
        "cve_id": "CVE-2023-45803",
        "package": "urllib3",
        "ecosystem": "pypi",
        "affected_versions": "<2.0.7",
        "fixed_version": "2.0.7",
        "severity": Severity.MEDIUM,
        "cvss_score": 4.2,
        "epss_score": 0.09,
        "is_kev": False,
        "vulnerable_symbols": ["request", "urlopen", "PoolManager", "HTTPConnectionPool"],
        "symbol_source": "osv",
        "summary": "Request body not stripped after redirect from 303 status in urllib3",
    },
    {
        "advisory_id": "GHSA-m2vv-5vj5-2hm7",
        "cve_id": "CVE-2023-30861",
        "package": "flask",
        "ecosystem": "pypi",
        "affected_versions": "<2.3.2",
        "fixed_version": "2.3.2",
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "epss_score": 0.41,
        "is_kev": False,
        "vulnerable_symbols": [],  # Advisory affects general session cookie caching without a specific function symbol -> Unknown!
        "symbol_source": "unknown",
        "summary": "Session cookie disclosure due to missing Vary: Cookie header in Flask",
    },
    {
        "advisory_id": "GHSA-j4m5-q23w-478r",
        "cve_id": "CVE-2022-29217",
        "package": "pyjwt",
        "ecosystem": "pypi",
        "affected_versions": "<2.4.0",
        "fixed_version": "2.4.0",
        "severity": Severity.HIGH,
        "cvss_score": 7.4,
        "epss_score": 0.52,
        "is_kev": False,
        "vulnerable_symbols": ["decode", "encode", "get_unverified_header"],
        "symbol_source": "osv",
        "summary": "Key confusion through non-blocklisted public key formats in PyJWT",
    },
    {
        "advisory_id": "GHSA-35jh-r3h4-6jhm",
        "cve_id": "CVE-2021-23337",
        "package": "lodash",
        "ecosystem": "npm",
        "affected_versions": "<4.17.21",
        "fixed_version": "4.17.21",
        "severity": Severity.HIGH,
        "cvss_score": 7.2,
        "epss_score": 0.78,
        "is_kev": False,
        "vulnerable_symbols": ["template", "zipObjectDeep", "merge"],
        "symbol_source": "osv",
        "summary": "Command Injection in lodash via template function",
    },
    {
        "advisory_id": "GHSA-qwcr-r2fm-qrc7",
        "cve_id": "CVE-2024-29041",
        "package": "express",
        "ecosystem": "npm",
        "affected_versions": "<4.19.2",
        "fixed_version": "4.19.2",
        "severity": Severity.MEDIUM,
        "cvss_score": 6.1,
        "epss_score": 0.14,
        "is_kev": False,
        "vulnerable_symbols": ["redirect", "location"],
        "symbol_source": "osv",
        "summary": "Open redirect allowlist bypass in Express res.location / res.redirect",
    },
    {
        "advisory_id": "GHSA-8cf7-32gw-wr33",
        "cve_id": "CVE-2022-23529",
        "package": "jsonwebtoken",
        "ecosystem": "npm",
        "affected_versions": "<9.0.0",
        "fixed_version": "9.0.0",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "epss_score": 0.88,
        "is_kev": True,
        "vulnerable_symbols": ["verify", "sign"],
        "symbol_source": "osv",
        "summary": "Remote code execution via malicious secretOrPublicKey in jsonwebtoken.verify()",
    },
]


# Top popular PyPI & npm packages for Levenshtein typosquat detection (Step 5)
POPULAR_PACKAGES: Dict[str, Set[str]] = {
    "pypi": {
        "requests",
        "urllib3",
        "flask",
        "fastapi",
        "django",
        "uvicorn",
        "pydantic",
        "sqlalchemy",
        "pyyaml",
        "cryptography",
        "pillow",
        "numpy",
        "pandas",
        "pytest",
        "boto3",
        "celery",
        "redis",
        "psycopg2",
        "pyjwt",
        "werkzeug",
        "jinja2",
        "httpx",
        "paramiko",
        "beautifulsoup4",
    },
    "npm": {
        "express",
        "lodash",
        "axios",
        "react",
        "jsonwebtoken",
        "moment",
        "chalk",
        "commander",
        "dotenv",
        "mongoose",
        "sequelize",
        "webpack",
        "typescript",
        "next",
        "cors",
        "helmet",
    },
}


KNOWN_MALICIOUS_PACKAGES: Set[str] = {
    "colourama",
    "python-sqlite",
    "urllib4",
    "setup-tools",
    "ctx-malicious",
    "event-stream-malicious",
    "discord-color",
    "pycrypto-env",
    "request-sync",
}


def _parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", v_str or "0")
    return tuple(int(n) for n in nums[:4]) if nums else (0,)


def _is_version_affected(installed_ver: str, affected_spec: str) -> bool:
    """
    Evaluates simple semantic version ranges such as '<5.4', '<=2.3.1', '<3.0.3'.
    """
    if not installed_ver or installed_ver in ("*", "latest", "unknown"):
        return True
    inst = _parse_version_tuple(installed_ver)
    for part in affected_spec.split(","):
        p = part.strip()
        if p.startswith("<="):
            target = _parse_version_tuple(p[2:])
            if not (inst <= target):
                return False
        elif p.startswith("<"):
            target = _parse_version_tuple(p[1:])
            if not (inst < target):
                return False
        elif p.startswith(">="):
            target = _parse_version_tuple(p[2:])
            if not (inst >= target):
                return False
        elif p.startswith("=="):
            target = _parse_version_tuple(p[2:])
            if not (inst == target):
                return False
    return True


def _levenshtein_distance(a: str, b: str) -> int:
    """
    Computes Optimal String Alignment (Damerau-Levenshtein) distance so both
    single-character edits (insertion, deletion, substitution) and single
    adjacent transpositions (e.g., 'reqeusts' -> 'requests') have distance 1.
    """
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    if len_a == 0:
        return len_b
    if len_b == 0:
        return len_a

    d = [[0] * (len_b + 1) for _ in range(len_a + 1)]
    for i in range(len_a + 1):
        d[i][0] = i
    for j in range(len_b + 1):
        d[0][j] = j

    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,      # deletion
                d[i][j - 1] + 1,      # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # adjacent transposition
    return d[len_a][len_b]


class _PythonImportAndCallAnalyzer(ast.NodeVisitor):
    """
    Extracts module imports, symbol aliases, and library function calls inside each Python file and function.
    """

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        # imported_modules: canonical_module_lower -> first_import_line
        self.imported_modules: Dict[str, int] = {}
        # alias_to_module: alias_name -> canonical_module_lower
        self.alias_to_module: Dict[str, str] = {}
        # symbol_to_module_func: local_func_alias -> (canonical_module_lower, symbol_name)
        self.symbol_to_module_func: Dict[str, Tuple[str, str]] = {}
        # calls: list of (enclosing_func_or_module, canonical_module_lower, symbol_name, line)
        self.lib_calls: List[Tuple[str, str, str, int]] = []
        self.has_dynamic_import: bool = False
        self._func_stack: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            root_mod = alias.name.split(".")[0].lower()
            as_name = alias.asname or alias.name.split(".")[0]
            self.imported_modules.setdefault(root_mod, node.lineno)
            self.alias_to_module[as_name] = root_mod
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            root_mod = node.module.split(".")[0].lower()
            self.imported_modules.setdefault(root_mod, node.lineno)
            for alias in node.names:
                sym = alias.name
                as_name = alias.asname or sym
                self.symbol_to_module_func[as_name] = (root_mod, sym)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_Call(self, node: ast.Call):
        enclosing = self._func_stack[-1] if self._func_stack else "<module>"

        # Check dynamic imports or reflection: importlib.import_module(...), __import__(...), or getattr(...)
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            self.has_dynamic_import = True
        elif isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if node.args and isinstance(node.args[0], ast.Name):
                target_id = node.args[0].id
                if target_id in self.alias_to_module or target_id not in ("self", "cls", "request", "app"):
                    self.has_dynamic_import = True
            else:
                self.has_dynamic_import = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
            self.has_dynamic_import = True

        # Case 1: module_alias.func_name(...) e.g. yaml.load(...)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            recv = node.func.value.id
            sym = node.func.attr
            if recv in self.alias_to_module:
                mod = self.alias_to_module[recv]
                self.lib_calls.append((enclosing, mod, sym, node.lineno))

        # Case 2: directly imported symbol e.g. from yaml import unsafe_load -> unsafe_load(...)
        elif isinstance(node.func, ast.Name):
            fn_id = node.func.id
            if fn_id in self.symbol_to_module_func:
                mod, sym = self.symbol_to_module_func[fn_id]
                self.lib_calls.append((enclosing, mod, sym, node.lineno))

        # Also check keyword arguments passing vulnerable classes like Loader=yaml.FullLoader or Loader=FullLoader
        for kw in node.keywords:
            if isinstance(kw.value, ast.Attribute) and isinstance(kw.value.value, ast.Name):
                recv = kw.value.value.id
                sym = kw.value.attr
                if recv in self.alias_to_module:
                    self.lib_calls.append((enclosing, self.alias_to_module[recv], sym, node.lineno))
            elif isinstance(kw.value, ast.Name) and kw.value.id in self.symbol_to_module_func:
                mod, sym = self.symbol_to_module_func[kw.value.id]
                self.lib_calls.append((enclosing, mod, sym, node.lineno))

        self.generic_visit(node)


class SCAReachabilityEngine:
    """
    Implements the 5-Step Reachability-Aware SCA Engine (PRD Page 4 Bonus).
    """

    def __init__(
        self,
        root_dir: str,
        route_mapper: Optional[RouteMapper] = None,
        custom_advisories: Optional[List[Dict[str, Any]]] = None,
    ):
        self.root_dir = os.path.abspath(root_dir)
        self.route_mapper = route_mapper or RouteMapper(self.root_dir)
        if not self.route_mapper.routes:
            self.route_mapper.scan()
        self.advisory_db: List[Dict[str, Any]] = list(BUNDLED_ADVISORIES)
        if custom_advisories:
            self.advisory_db.extend(custom_advisories)

    # =========================================================================
    # STEP 1: Inventory — Parse lockfiles into an SBOM keeping transitive paths
    # =========================================================================
    def parse_lockfiles(self) -> Tuple[List[SBOMDependency], bool]:
        """
        Scans root_dir for requirements.txt, Pipfile.lock, poetry.lock, package-lock.json, and package.json.
        Returns (sbom_dependencies, has_private_registry_config).
        """
        sbom: List[SBOMDependency] = []
        has_private_registry = False

        for dirpath, _, filenames in os.walk(self.root_dir):
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules") for p in parts):
                continue

            for fname in sorted(filenames):
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")

                if fname == "requirements.txt" or (fname.startswith("requirements") and fname.endswith(".txt")):
                    deps, priv = self._parse_requirements_txt(full_path, rel_path)
                    sbom.extend(deps)
                    has_private_registry = has_private_registry or priv
                elif fname == "Pipfile.lock":
                    sbom.extend(self._parse_pipfile_lock(full_path, rel_path))
                elif fname == "poetry.lock":
                    sbom.extend(self._parse_poetry_lock(full_path, rel_path))
                elif fname == "package-lock.json":
                    sbom.extend(self._parse_package_lock_json(full_path, rel_path))
                elif fname == "package.json":
                    # Only add package.json entries if package-lock.json wasn't in the same folder
                    if "package-lock.json" not in filenames:
                        sbom.extend(self._parse_package_json(full_path, rel_path))
                elif fname in (".npmrc", "pip.conf"):
                    has_private_registry = True

        # Enrich transitive paths for flat requirements.txt when parent package is also present
        present_names = {d.name.lower() for d in sbom}
        for dep in sbom:
            if len(dep.transitive_path) <= 2 and dep.name.lower() in KNOWN_TRANSITIVE_PARENTS:
                parent = KNOWN_TRANSITIVE_PARENTS[dep.name.lower()]
                if parent in present_names and dep.transitive_path == ["root", dep.name.lower()]:
                    dep.is_direct = False
                    dep.transitive_path = ["root", parent, dep.name.lower()]

        return sbom, has_private_registry

    def _parse_requirements_txt(self, full_path: str, rel_path: str) -> Tuple[List[SBOMDependency], bool]:
        deps: List[SBOMDependency] = []
        has_private_index = False
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, raw_line in enumerate(lines):
                lineno = idx + 1
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith(("--index-url", "--extra-index-url", "-i ")):
                    has_private_index = True
                    continue

                # Check inline "# via parent_pkg" comment from pip-compile
                via_parent = None
                if "#" in stripped:
                    code_part, comment_part = stripped.split("#", 1)
                    stripped = code_part.strip()
                    via_m = re.search(r"\bvia\s+([a-zA-Z0-9_.-]+)", comment_part)
                    if via_m:
                        via_parent = via_m.group(1).lower()

                m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:(==|>=|<=|~=|!=|>|<)\s*([a-zA-Z0-9_.*+-]+))?", stripped)
                if m:
                    pkg_name = m.group(1).lower()
                    op = m.group(2) or ""
                    ver = m.group(3) or "unpinned"
                    is_pinned = op == "==" and "*" not in ver and ver != "unpinned"
                    t_path = ["root", via_parent, pkg_name] if via_parent else ["root", pkg_name]
                    deps.append(
                        SBOMDependency(
                            name=pkg_name,
                            version=ver,
                            ecosystem="pypi",
                            is_direct=via_parent is None,
                            is_pinned=is_pinned,
                            transitive_path=t_path,
                            source_file=rel_path,
                            line=lineno,
                        )
                    )
        except Exception:
            pass
        return deps, has_private_index

    def _parse_pipfile_lock(self, full_path: str, rel_path: str) -> List[SBOMDependency]:
        deps: List[SBOMDependency] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                sec_dict = data.get(section, {})
                if isinstance(sec_dict, dict):
                    for pkg_name, meta in sec_dict.items():
                        raw_ver = str(meta.get("version", "")).lstrip("=")
                        is_pinned = str(meta.get("version", "")).startswith("==")
                        via = meta.get("via", [])
                        t_path = ["root"] + [str(v).lower() for v in via] + [pkg_name.lower()] if via else ["root", pkg_name.lower()]
                        deps.append(
                            SBOMDependency(
                                name=pkg_name.lower(),
                                version=raw_ver or "unknown",
                                ecosystem="pypi",
                                is_direct=not bool(via),
                                is_pinned=is_pinned,
                                transitive_path=t_path,
                                source_file=rel_path,
                            )
                        )
        except Exception:
            pass
        return deps

    def _parse_poetry_lock(self, full_path: str, rel_path: str) -> List[SBOMDependency]:
        deps: List[SBOMDependency] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            blocks = content.split("[[package]]")
            pkg_parents: Dict[str, str] = {}
            parsed_blocks: List[Tuple[str, str, List[str]]] = []

            for b in blocks[1:]:
                name_m = re.search(r'name\s*=\s*"([^"]+)"', b)
                ver_m = re.search(r'version\s*=\s*"([^"]+)"', b)
                if name_m and ver_m:
                    p_name = name_m.group(1).lower()
                    p_ver = ver_m.group(1)
                    child_deps: List[str] = []
                    if "[package.dependencies]" in b:
                        dep_sec = b.split("[package.dependencies]", 1)[1].split("\n[", 1)[0]
                        for dm in re.finditer(r"^([a-zA-Z0-9_.-]+)\s*=", dep_sec, re.MULTILINE):
                            c_name = dm.group(1).lower()
                            child_deps.append(c_name)
                            pkg_parents.setdefault(c_name, p_name)
                    parsed_blocks.append((p_name, p_ver, child_deps))

            for p_name, p_ver, _ in parsed_blocks:
                parent = pkg_parents.get(p_name)
                t_path = ["root", parent, p_name] if parent else ["root", p_name]
                deps.append(
                    SBOMDependency(
                        name=p_name,
                        version=p_ver,
                        ecosystem="pypi",
                        is_direct=parent is None,
                        is_pinned=True,
                        transitive_path=t_path,
                        source_file=rel_path,
                    )
                )
        except Exception:
            pass
        return deps

    def _parse_package_lock_json(self, full_path: str, rel_path: str) -> List[SBOMDependency]:
        deps: List[SBOMDependency] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            # npm v2/v3 "packages" format or v1 "dependencies" format
            dependencies = data.get("dependencies", {})
            if isinstance(dependencies, dict) and dependencies:
                # Build parent map from "requires"
                parent_map: Dict[str, str] = {}
                for pkg_name, meta in dependencies.items():
                    if isinstance(meta, dict):
                        for req_child in (meta.get("requires") or {}).keys():
                            parent_map.setdefault(req_child.lower(), pkg_name.lower())

                for pkg_name, meta in dependencies.items():
                    if isinstance(meta, dict):
                        ver = str(meta.get("version", "unknown"))
                        parent = parent_map.get(pkg_name.lower())
                        t_path = ["root", parent, pkg_name.lower()] if parent else ["root", pkg_name.lower()]
                        deps.append(
                            SBOMDependency(
                                name=pkg_name.lower(),
                                version=ver,
                                ecosystem="npm",
                                is_direct=parent is None,
                                is_pinned=not ver.startswith(("^", "~", "*", ">")),
                                transitive_path=t_path,
                                source_file=rel_path,
                            )
                        )
        except Exception:
            pass
        return deps

    def _parse_package_json(self, full_path: str, rel_path: str) -> List[SBOMDependency]:
        deps: List[SBOMDependency] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                sec = data.get(section, {})
                if isinstance(sec, dict):
                    for pkg_name, ver_spec in sec.items():
                        raw_spec = str(ver_spec).strip()
                        is_pinned = bool(re.match(r"^\d+\.\d+\.\d+$", raw_spec))
                        clean_ver = raw_spec.lstrip("^~>=<") or raw_spec
                        deps.append(
                            SBOMDependency(
                                name=pkg_name.lower(),
                                version=clean_ver,
                                ecosystem="npm",
                                is_direct=True,
                                is_pinned=is_pinned,
                                transitive_path=["root", pkg_name.lower()],
                                source_file=rel_path,
                            )
                        )
        except Exception:
            pass
        return deps

    # =========================================================================
    # STEP 2 & 3: GHSA Match + Function Map (OSV Symbols & Fix-Commit Diffs)
    # =========================================================================
    @staticmethod
    def parse_fix_commit_diff(diff_text: str) -> List[str]:
        """
        Step 3 Helper: Extracts modified function or class names from a GitHub fix-commit unified diff
        when GHSA/OSV omits explicit vulnerable symbols.
        """
        symbols: Set[str] = set()
        if not diff_text:
            return []

        # Match hunk header context or modified lines:
        # e.g. @@ -10,7 +10,9 @@ def parse_token(token):
        # or +def validate_url(url): or function verifyToken(
        patterns = [
            r"@@[^@]+@@\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)",
            r"@@[^@]+@@\s*class\s+([a-zA-Z_]\w*)",
            r"^[+-]\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(",
            r"@@[^@]+@@\s*(?:async\s+)?function\s+([a-zA-Z_]\w*)",
            r"^[+-]\s*(?:async\s+)?function\s+([a-zA-Z_]\w*)\s*\(",
        ]
        for pat in patterns:
            for m in re.finditer(pat, diff_text, re.MULTILINE):
                sym = m.group(1)
                if not sym.startswith("test_"):
                    symbols.add(sym)

        return sorted(list(symbols))

    def match_advisories(self, sbom: List[SBOMDependency]) -> List[ Tuple[SBOMDependency, VulnerabilityAdvisory] ]:
        """
        Step 2 & Step 3: Matches SBOM dependencies against GHSA advisories, pulling CVSS, EPSS, KEV,
        and building the vulnerable function map from OSV symbols or fix-commit diffs.
        """
        matches: List[Tuple[SBOMDependency, VulnerabilityAdvisory]] = []

        for dep in sbom:
            for adv in self.advisory_db:
                if adv.get("package", "").lower() != dep.name.lower():
                    continue
                if adv.get("ecosystem", "pypi").lower() != dep.ecosystem.lower():
                    continue
                if not _is_version_affected(dep.version, adv.get("affected_versions", "")):
                    continue

                # Step 3: Function Map from OSV symbols or fix-commit diff
                symbols = list(adv.get("vulnerable_symbols") or [])
                symbol_source = adv.get("symbol_source", "osv" if symbols else "unknown")

                if not symbols and adv.get("fix_commit_diff"):
                    symbols = self.parse_fix_commit_diff(adv["fix_commit_diff"])
                    if symbols:
                        symbol_source = "fix_commit_diff"

                if not symbols:
                    symbol_source = "unknown"

                advisory_model = VulnerabilityAdvisory(
                    advisory_id=adv["advisory_id"],
                    cve_id=adv.get("cve_id"),
                    package=dep.name.lower(),
                    ecosystem=dep.ecosystem,
                    affected_versions=adv.get("affected_versions", ""),
                    fixed_version=adv.get("fixed_version"),
                    severity=adv.get("severity", Severity.HIGH),
                    cvss_score=float(adv.get("cvss_score", 7.5)),
                    epss_score=float(adv.get("epss_score", 0.1)),
                    is_kev=bool(adv.get("is_kev", False)),
                    vulnerable_symbols=symbols,
                    symbol_source=symbol_source,
                    summary=adv.get("summary", ""),
                )
                matches.append((dep, advisory_model))

        return matches

    # =========================================================================
    # STEP 4: Call Graph & 4-Status Reachability Classification
    # =========================================================================
    def _collect_codebase_library_usage(
        self,
    ) -> Tuple[
        Dict[str, Tuple[str, int]],
        List[Tuple[str, str, str, str, int]],
        bool,
    ]:
        """
        Scans Python and JS/TS source files to collect:
        1. imported_packages: canonical_import_mod -> (rel_path, line)
        2. library_calls: list of (rel_path, enclosing_func, canonical_import_mod, symbol_name, line)
        3. has_dynamic_import: bool
        """
        imported_packages: Dict[str, Tuple[str, int]] = {}
        library_calls: List[Tuple[str, str, str, str, int]] = []
        any_dynamic_import = False

        for dirpath, _, filenames in os.walk(self.root_dir):
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules") for p in parts):
                continue

            for fname in sorted(filenames):
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")

                if fname.endswith(".py"):
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        tree = ast.parse(content, filename=rel_path)
                        analyzer = _PythonImportAndCallAnalyzer(rel_path)
                        analyzer.visit(tree)
                        any_dynamic_import = any_dynamic_import or analyzer.has_dynamic_import
                        for mod, line in analyzer.imported_modules.items():
                            imported_packages.setdefault(mod, (rel_path, line))
                        for enc_func, mod, sym, line in analyzer.lib_calls:
                            library_calls.append((rel_path, enc_func, mod, sym, line))
                    except Exception:
                        pass

                elif fname.endswith((".js", ".ts")) and not fname.endswith(".min.js"):
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.read().splitlines()
                        alias_map: Dict[str, str] = {}
                        for idx, line_s in enumerate(lines):
                            lineno = idx + 1
                            # const _ = require('lodash') or import jwt from 'jsonwebtoken'
                            req_m = re.search(
                                r"""(?:const|let|var)\s+([a-zA-Z_$]\w*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""",
                                line_s,
                            )
                            if req_m:
                                alias, pkg = req_m.group(1), req_m.group(2).lower()
                                imported_packages.setdefault(pkg, (rel_path, lineno))
                                alias_map[alias] = pkg
                            imp_m = re.search(r"""import\s+([a-zA-Z_$]\w*)\s+from\s+['"]([^'"]+)['"]""", line_s)
                            if imp_m:
                                alias, pkg = imp_m.group(1), imp_m.group(2).lower()
                                imported_packages.setdefault(pkg, (rel_path, lineno))
                                alias_map[alias] = pkg

                            for alias, pkg in alias_map.items():
                                for call_m in re.finditer(rf"\b{re.escape(alias)}\s*\.\s*([a-zA-Z_]\w*)\s*\(", line_s):
                                    sym = call_m.group(1)
                                    library_calls.append((rel_path, "<js_handler>", pkg, sym, lineno))
                    except Exception:
                        pass

        return imported_packages, library_calls, any_dynamic_import

    def _trace_route_to_function(self, file_path: str, func_name: str, line: int) -> Tuple[Optional[RouteEntry], List[str]]:
        """
        Traces whether (file_path, func_name, line) is reachable from an FR-4 route entry point
        and returns (RouteEntry, call_chain_steps).
        """
        for r in self.route_mapper.routes:
            if self.route_mapper.is_line_in_route(file_path, line, r, max_hops=3):
                chain = [
                    f"{r.method} {r.path_pattern}",
                    f"{r.file_path}:{r.func_name}() [line {r.start_line}]",
                ]
                if func_name not in (r.func_name, "<module>", "<js_handler>"):
                    chain.append(f"{file_path}:{func_name}() [line {line}]")
                return r, chain
        return None, []

    def analyze_reachability(self) -> SCAReport:
        """
        Executes all 5 steps of Reachability-Aware SCA and returns a consolidated SCAReport.
        """
        # Step 1: Inventory
        sbom, has_private_registry = self.parse_lockfiles()

        # Step 2 & 3: GHSA Match + Function Map
        matched_advisories = self.match_advisories(sbom)

        # Step 4: Call Graph & Reachability Status Classification
        imported_packages, library_calls, has_dynamic_import = self._collect_codebase_library_usage()
        findings: List[SCAReachabilityFinding] = []

        for dep, adv in matched_advisories:
            pkg_lower = dep.name.lower()
            import_mod_name = PYPI_TO_IMPORT_MAP.get(pkg_lower, pkg_lower.replace("-", "_"))
            candidate_mod_names = {pkg_lower, import_mod_name}

            # RULE (PRD Page 4 Note):
            # If advisory has NO vulnerable symbols (neither OSV nor fix-commit diff),
            # status MUST be Unknown and we MUST NEVER downgrade Unknown!
            if not adv.vulnerable_symbols:
                status = SCAReachabilityStatus.UNKNOWN
                effective_severity = adv.severity  # Never downgrade Unknown!
                imp_info = None
                for m_name in candidate_mod_names:
                    if m_name in imported_packages:
                        imp_info = imported_packages[m_name]
                        break
                f_path = imp_info[0] if imp_info else dep.source_file
                f_line = imp_info[1] if imp_info else dep.line
                call_chain: List[str] = []
                entry_route = None
            else:
                # Check if package is imported at all
                imp_info = None
                for m_name in candidate_mod_names:
                    if m_name in imported_packages:
                        imp_info = imported_packages[m_name]
                        break

                if not imp_info:
                    if has_dynamic_import:
                        status = SCAReachabilityStatus.UNKNOWN
                        effective_severity = adv.severity  # Never downgrade Unknown!
                    else:
                        status = SCAReachabilityStatus.PRESENT_ONLY
                        effective_severity = Severity.LOW
                    f_path = dep.source_file
                    f_line = dep.line
                    call_chain = []
                    entry_route = None
                else:
                    # Package is imported; check if any vulnerable symbol is invoked in a reachable path
                    vuln_sym_set = {s.lower() for s in adv.vulnerable_symbols}
                    reachable_hit = None
                    for call_file, enc_func, call_mod, call_sym, call_line in library_calls:
                        if call_mod in candidate_mod_names and call_sym.lower() in vuln_sym_set:
                            # Check if this call line is reachable from routes (or if app has no routes, module-level)
                            if self.route_mapper.is_line_reachable(call_file, call_line):
                                route_obj, route_chain = self._trace_route_to_function(call_file, enc_func, call_line)
                                full_chain = route_chain + [f"{call_mod}.{call_sym}() [line {call_line}]"]
                                reachable_hit = (
                                    call_file,
                                    call_line,
                                    full_chain,
                                    f"{route_obj.method} {route_obj.path_pattern}" if route_obj else "module_entrypoint",
                                )
                                break

                    if reachable_hit:
                        status = SCAReachabilityStatus.REACHABLE
                        effective_severity = adv.severity
                        f_path, f_line, call_chain, entry_route = reachable_hit
                    elif has_dynamic_import:
                        status = SCAReachabilityStatus.UNKNOWN
                        effective_severity = adv.severity  # Never downgrade Unknown!
                        f_path, f_line = imp_info
                        call_chain = []
                        entry_route = None
                    else:
                        status = SCAReachabilityStatus.IMPORTED_ONLY
                        effective_severity = Severity.MEDIUM if adv.severity in (Severity.CRITICAL, Severity.HIGH) else Severity.LOW
                        f_path, f_line = imp_info
                        call_chain = []
                        entry_route = None

            finding_id = f"SCA-{hashlib.sha256(f'{dep.name}:{dep.version}:{adv.advisory_id}'.encode('utf-8')).hexdigest()[:10].upper()}"
            fix_note = f"Upgrade {dep.name} from {dep.version} to >= {adv.fixed_version}." if adv.fixed_version else f"Review {dep.name} advisory {adv.advisory_id}."
            if status == SCAReachabilityStatus.REACHABLE and adv.vulnerable_symbols:
                fix_note += f" Replace vulnerable call(s) ({', '.join(adv.vulnerable_symbols[:3])}) with safe equivalents."
            elif status == SCAReachabilityStatus.UNKNOWN:
                fix_note += " Advisory does not specify function-level symbols; original severity preserved (Unknown status never downgraded)."

            findings.append(
                SCAReachabilityFinding(
                    id=finding_id,
                    package=dep.name,
                    installed_version=dep.version,
                    ecosystem=dep.ecosystem,
                    advisory_id=adv.advisory_id,
                    cve_id=adv.cve_id,
                    status=status,
                    original_severity=adv.severity,
                    effective_severity=effective_severity,
                    cvss_score=adv.cvss_score,
                    epss_score=adv.epss_score,
                    is_kev=adv.is_kev,
                    transitive_path=dep.transitive_path,
                    vulnerable_functions=adv.vulnerable_symbols,
                    call_chain=call_chain,
                    entry_route=entry_route,
                    file_path=f_path,
                    line=f_line,
                    fixed_version=adv.fixed_version,
                    remediation=fix_note,
                )
            )

        # Sort findings: Reachable first, then Unknown (never downgraded!), then Imported-only, then Present-only
        status_order = {
            SCAReachabilityStatus.REACHABLE: 0,
            SCAReachabilityStatus.UNKNOWN: 1,
            SCAReachabilityStatus.IMPORTED_ONLY: 2,
            SCAReachabilityStatus.PRESENT_ONLY: 3,
        }
        findings.sort(key=lambda x: (status_order.get(x.status, 4), -x.cvss_score))

        # Step 5: Supply Chain Checks
        supply_chain_alerts = self.check_supply_chain(sbom, has_private_registry)

        summary = {
            "total_dependencies": len(sbom),
            "total_vulnerabilities": len(findings),
            "reachable": sum(1 for f in findings if f.status == SCAReachabilityStatus.REACHABLE),
            "unknown": sum(1 for f in findings if f.status == SCAReachabilityStatus.UNKNOWN),
            "imported_only": sum(1 for f in findings if f.status == SCAReachabilityStatus.IMPORTED_ONLY),
            "present_only": sum(1 for f in findings if f.status == SCAReachabilityStatus.PRESENT_ONLY),
            "supply_chain_alerts": len(supply_chain_alerts),
        }

        return SCAReport(
            sbom_count=len(sbom),
            sbom=sbom,
            findings=findings,
            supply_chain_alerts=supply_chain_alerts,
            summary=summary,
        )

    # =========================================================================
    # STEP 5: Supply Chain Checks (Malicious, Typosquats, Confusion, Unpinned)
    # =========================================================================
    def check_supply_chain(
        self,
        sbom: List[SBOMDependency],
        has_private_registry: bool = False,
    ) -> List[SupplyChainAlert]:
        """
        Checks SBOM entries for:
        1. Known malicious packages
        2. Typosquats (Levenshtein edit distance == 1 against top PyPI/npm packages)
        3. Dependency confusion (internal/corporate package names without private index configuration)
        4. Unpinned lockfiles / manifests
        """
        alerts: List[SupplyChainAlert] = []

        confusion_re = re.compile(
            r"(?:^internal[-_]|[-_]internal$|^corp[-_]|[-_]corp$|^private[-_]|[-_]private$|^mitigata[-_]|^company[-_])",
            re.IGNORECASE,
        )

        for dep in sbom:
            pkg = dep.name.lower()

            # 1. Malicious package check
            if pkg in KNOWN_MALICIOUS_PACKAGES:
                alert_id = f"SC-MAL-{hashlib.sha256(f'{pkg}:{dep.source_file}'.encode()).hexdigest()[:8].upper()}"
                alerts.append(
                    SupplyChainAlert(
                        id=alert_id,
                        alert_type="malicious_package",
                        package=dep.name,
                        version=dep.version,
                        severity=Severity.CRITICAL,
                        source_file=dep.source_file,
                        line=dep.line,
                        description=f"Package '{dep.name}' matches known malicious package signature.",
                        remediation=f"Immediately remove '{dep.name}' from {dep.source_file} and rotate exposed credentials.",
                    )
                )
                continue

            # 2. Typosquatting check (Levenshtein distance == 1 against top packages in ecosystem)
            popular_set = POPULAR_PACKAGES.get(dep.ecosystem.lower(), POPULAR_PACKAGES["pypi"])
            if pkg not in popular_set and len(pkg) >= 4:
                for legit in sorted(popular_set):
                    if _levenshtein_distance(pkg, legit) == 1:
                        alert_id = f"SC-TYPO-{hashlib.sha256(f'{pkg}:{legit}'.encode()).hexdigest()[:8].upper()}"
                        alerts.append(
                            SupplyChainAlert(
                                id=alert_id,
                                alert_type="typosquat",
                                package=dep.name,
                                version=dep.version,
                                severity=Severity.CRITICAL,
                                source_file=dep.source_file,
                                line=dep.line,
                                target_legit_package=legit,
                                description=(
                                    f"Suspected typosquat: '{dep.name}' is edit-distance 1 from popular {dep.ecosystem} package '{legit}'."
                                ),
                                remediation=f"Replace '{dep.name}' with legitimate package '{legit}' in {dep.source_file}.",
                            )
                        )
                        break

            # 3. Dependency confusion check
            if confusion_re.search(pkg) and not has_private_registry:
                alert_id = f"SC-CONF-{hashlib.sha256(f'{pkg}:{dep.source_file}'.encode()).hexdigest()[:8].upper()}"
                alerts.append(
                    SupplyChainAlert(
                        id=alert_id,
                        alert_type="dependency_confusion",
                        package=dep.name,
                        version=dep.version,
                        severity=Severity.HIGH,
                        source_file=dep.source_file,
                        line=dep.line,
                        description=(
                            f"Potential dependency confusion: internal-scoped package '{dep.name}' declared without a pinned private registry."
                        ),
                        remediation="Configure an explicit --index-url / scoped private registry and reserve the package namespace.",
                    )
                )

            # 4. Unpinned lockfile / manifest check
            if not dep.is_pinned:
                alert_id = f"SC-UNPIN-{hashlib.sha256(f'{pkg}:{dep.source_file}'.encode()).hexdigest()[:8].upper()}"
                alerts.append(
                    SupplyChainAlert(
                        id=alert_id,
                        alert_type="unpinned_lockfile",
                        package=dep.name,
                        version=dep.version,
                        severity=Severity.MEDIUM,
                        source_file=dep.source_file,
                        line=dep.line,
                        description=(
                            f"Unpinned dependency '{dep.name}' ({dep.version}) in {dep.source_file} allows non-deterministic or compromised upstream releases."
                        ),
                        remediation=f"Pin '{dep.name}' to an exact version (e.g. ==x.y.z) and commit a deterministic lockfile with hashes.",
                    )
                )

        return alerts


SCAReachabilityScanner = SCAReachabilityEngine


def _format_supply_chain_flag(alert: SupplyChainAlert) -> str:
    if alert.alert_type == "typosquat":
        return f"TYPOSQUAT_SUSPECT: {alert.package} -> {alert.target_legit_package} (distance=1)"
    if alert.alert_type == "dependency_confusion":
        return f"DEPENDENCY_CONFUSION: {alert.package} ({alert.source_file})"
    if alert.alert_type == "unpinned_lockfile":
        return f"UNPINNED_VERSION: {alert.package} ({alert.version})"
    if alert.alert_type == "malicious_package":
        return f"MALICIOUS_PACKAGE: {alert.package} ({alert.source_file})"
    return f"{alert.alert_type.upper()}: {alert.package}"


def run_sca_reachability(
    source_dir: str,
    routes: Optional[List[RouteEntry]] = None,
    route_mapper: Optional[RouteMapper] = None,
) -> List[SCAFinding]:
    """
    Top-level bridge function invoked by `api/main.py` and CLI runners.
    Executes the 5-Step Reachability-Aware SCA Engine and returns `List[SCAFinding]`
    with human-readable `call_chain` and `supply_chain_flags`.
    """
    mapper = route_mapper
    if mapper is None:
        mapper = RouteMapper(source_dir)
        mapper.scan()
    elif routes and not mapper.routes:
        mapper.routes = list(routes)

    engine = SCAReachabilityEngine(source_dir, route_mapper=mapper)
    report = engine.analyze_reachability()

    alert_flags_by_pkg: Dict[str, List[str]] = {}
    alerts_by_pkg: Dict[str, List[SupplyChainAlert]] = {}
    for alert in report.supply_chain_alerts:
        pkg_key = alert.package.lower()
        alerts_by_pkg.setdefault(pkg_key, []).append(alert)
        flags = alert_flags_by_pkg.setdefault(pkg_key, [])
        formatted = _format_supply_chain_flag(alert)
        if formatted not in flags:
            flags.append(formatted)
        if alert.alert_type not in flags:
            flags.append(alert.alert_type)

    sca_findings: List[SCAFinding] = []
    seen_pkgs: Set[str] = set()

    for rf in report.findings:
        pkg_key = rf.package.lower()
        seen_pkgs.add(pkg_key)
        fn_source = "osv_symbols" if rf.vulnerable_functions else "none_unknown"
        sca_findings.append(
            SCAFinding(
                id=rf.id,
                package_name=rf.package,
                installed_version=rf.installed_version,
                ecosystem="PyPI" if rf.ecosystem.lower() == "pypi" else rf.ecosystem,
                is_direct=len(rf.transitive_path) <= 2,
                dependency_path=rf.transitive_path,
                advisory_id=rf.advisory_id,
                cve_id=rf.cve_id,
                original_severity=rf.original_severity,
                effective_severity=rf.effective_severity,
                cvss_score=rf.cvss_score,
                epss_score=rf.epss_score,
                in_cisa_kev=rf.is_kev,
                fixed_version=rf.fixed_version,
                vulnerable_functions=rf.vulnerable_functions,
                function_map_source=fn_source,
                reachability_status=rf.status,
                call_chain=rf.call_chain,
                supply_chain_flags=alert_flags_by_pkg.get(pkg_key, []),
            )
        )

    # Also surface standalone supply-chain alerts (typosquats, dependency confusion, malicious packages)
    sbom_by_pkg = {d.name.lower(): d for d in report.sbom}
    for pkg_key, pkg_alerts in alerts_by_pkg.items():
        if pkg_key in seen_pkgs:
            continue
        primary_alert = pkg_alerts[0]
        dep = sbom_by_pkg.get(pkg_key)
        sca_findings.append(
            SCAFinding(
                id=primary_alert.id,
                package_name=primary_alert.package,
                installed_version=primary_alert.version or (dep.version if dep else "unpinned"),
                ecosystem="PyPI" if (dep is None or dep.ecosystem.lower() == "pypi") else dep.ecosystem,
                is_direct=dep.is_direct if dep else True,
                dependency_path=dep.transitive_path if dep else ["root", pkg_key],
                advisory_id=primary_alert.id,
                cve_id=None,
                original_severity=primary_alert.severity,
                effective_severity=primary_alert.severity,
                cvss_score=9.0 if primary_alert.severity == Severity.CRITICAL else (7.5 if primary_alert.severity == Severity.HIGH else 5.0),
                epss_score=0.0,
                in_cisa_kev=False,
                fixed_version=primary_alert.target_legit_package,
                vulnerable_functions=[],
                function_map_source="none_unknown",
                reachability_status=SCAReachabilityStatus.UNKNOWN,
                call_chain=[],
                supply_chain_flags=alert_flags_by_pkg.get(pkg_key, []),
            )
        )

    for sf in sca_findings:
        sf.__dict__.update({"package": sf.package_name, "status": sf.reachability_status})

    return sca_findings

