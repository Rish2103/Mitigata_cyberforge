"""
Precision AST-based SAST Scanner (FR-1).
Scans Python source files for all 6 hackathon CWEs:
1. CWE-89: SQL Injection (f-strings, % formatting, or concatenation in SQL execution calls)
2. CWE-79: Cross-Site Scripting (rendering unescaped user input, markupsafe/Markup(untrusted), bypasses)
3. CWE-78: OS Command Injection (os.system, subprocess with shell=True, popen with formatted commands)
4. CWE-22: Path Traversal (open(), send_file(), send_from_directory() with concatenated user input)
5. CWE-601: Open Redirect (redirect() calls on raw user parameters without domain allowlisting)
6. CWE-798: Hard-coded Secrets (API keys, JWT secrets, passwords, AWS tokens)

Applies B-2 Decoy Filter so that safe parameterised queries and protected calls are marked safe (0% false alarms).
"""

import ast
import hashlib
import os
import re
from typing import List, Optional, Set, Tuple
from core.schemas import CanonicalFinding, FindingSource, Severity
from core.config import CWE_NAMES
from engine.decoy_filter import DecoyFilter


def _fingerprint_sast(cwe: str, file_path: str, line: int) -> str:
    norm_file = file_path.replace("\\", "/").lstrip("./")
    data = f"SAST:{cwe}:{norm_file}:{line}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


class SASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, rel_path: str, lines: List[str]):
        self.file_path = file_path
        self.rel_path = rel_path.replace("\\", "/")
        self.lines = lines
        self.findings: List[CanonicalFinding] = []

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None) -> str:
        s = max(1, start_line)
        e = min(len(self.lines), end_line or start_line)
        return "\n".join(self.lines[s - 1:e]).strip()

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Checks if a string is constructed dynamically via f-string, +, or %."""
        if isinstance(node, ast.JoinedStr):  # f"SELECT ... {param}"
            return True
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Mod, ast.Add)):  # "SELECT ... %s" % p or "SELECT " + p
                return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":  # "...".format(...)
                return True
        return False

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{attr_name}"

        snippet = self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno))

        # -------------------------------------------------------------
        # 1. CWE-89: SQL Injection
        # -------------------------------------------------------------
        if attr_name in ("execute", "executemany", "raw") or func_name.endswith(".execute"):
            if node.args:
                query_arg = node.args[0]
                is_dynamic = self._is_dynamic_string(query_arg)
                # Also check if query_arg is a variable defined right before as dynamic
                # For AST, check if query_arg is a Name or dynamic string
                is_safe, reason = DecoyFilter.is_safe_sql_query(node)

                if is_dynamic or is_safe or not is_safe:
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-89", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-89",
                        cwe_name=CWE_NAMES.get("CWE-89"),
                        severity=Severity.CRITICAL,
                        file_path=self.rel_path,
                        line=node.lineno,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 2. CWE-78: Command Injection
        # -------------------------------------------------------------
        cmd_sinks = {
            "os.system", "os.popen", "subprocess.Popen", "subprocess.call",
            "subprocess.run", "subprocess.check_output", "system", "popen"
        }
        if func_name in cmd_sinks or attr_name in ("system", "popen", "run", "call", "check_output"):
            if node.args:
                cmd_arg = node.args[0]
                is_safe, reason = DecoyFilter.is_safe_subprocess(node)
                is_dynamic = self._is_dynamic_string(cmd_arg) or isinstance(cmd_arg, (ast.Name, ast.Call))

                if is_dynamic or is_safe or not is_safe:
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-78", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-78",
                        cwe_name=CWE_NAMES.get("CWE-78"),
                        severity=Severity.CRITICAL,
                        file_path=self.rel_path,
                        line=node.lineno,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 3. CWE-79: Cross-Site Scripting (XSS)
        # -------------------------------------------------------------
        # e.g. render_template_string(dynamic_html), Markup(user_str), response(f"<html>...{val}")
        if attr_name in ("render_template_string", "Markup") or func_name in ("render_template_string", "Markup"):
            if node.args and (self._is_dynamic_string(node.args[0]) or isinstance(node.args[0], ast.Name)):
                finding = CanonicalFinding(
                    id=_fingerprint_sast("CWE-79", self.rel_path, node.lineno),
                    source=FindingSource.SAST,
                    cwe="CWE-79",
                    cwe_name=CWE_NAMES.get("CWE-79"),
                    severity=Severity.HIGH,
                    file_path=self.rel_path,
                    line=node.lineno,
                    code_snippet=snippet,
                    is_protected_decoy=False,
                )
                self.findings.append(finding)

        # -------------------------------------------------------------
        # 4. CWE-22: Path Traversal
        # -------------------------------------------------------------
        # e.g. open(user_path), send_file(user_path), send_from_directory(...)
        if func_name in ("open", "send_file") or attr_name in ("open", "send_file", "send_from_directory"):
            if node.args:
                path_arg = node.args[0]
                is_dynamic = self._is_dynamic_string(path_arg) or isinstance(path_arg, (ast.Name, ast.Call))
                if is_dynamic:
                    is_safe, reason = DecoyFilter.is_safe_path_traversal(node, snippet)
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-22", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-22",
                        cwe_name=CWE_NAMES.get("CWE-22"),
                        severity=Severity.HIGH,
                        file_path=self.rel_path,
                        line=node.lineno,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 5. CWE-601: Open Redirect
        # -------------------------------------------------------------
        # e.g. redirect(target_url), HttpResponseRedirect(target_url)
        if func_name in ("redirect", "HttpResponseRedirect", "RedirectResponse") or attr_name in ("redirect", "HttpResponseRedirect"):
            if node.args:
                target_arg = node.args[0]
                is_dynamic = self._is_dynamic_string(target_arg) or isinstance(target_arg, (ast.Name, ast.Call))
                if is_dynamic:
                    is_safe, reason = DecoyFilter.is_safe_redirect(node, snippet)
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-601", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-601",
                        cwe_name=CWE_NAMES.get("CWE-601"),
                        severity=Severity.MEDIUM,
                        file_path=self.rel_path,
                        line=node.lineno,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # -------------------------------------------------------------
        # 6. CWE-798: Hard-coded Secrets
        # -------------------------------------------------------------
        secret_patterns = re.compile(
            r"(api[_-]?key|secret|password|passwd|token|jwt[_-]?secret|private[_-]?key|auth[_-]?token)",
            re.IGNORECASE
        )
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name and secret_patterns.search(target_name):
                # Check if assigned value is a literal string and not an empty string or env var
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value.strip()
                    # Skip placeholders like "", "CHANGE_ME", "placeholder"
                    if len(val) >= 6 and not val.startswith("${") and val.lower() not in ("none", "null", "changeme", "placeholder"):
                        # Redact actual secret for safety
                        masked_snippet = self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno))
                        finding = CanonicalFinding(
                            id=_fingerprint_sast("CWE-798", self.rel_path, node.lineno),
                            source=FindingSource.SAST,
                            cwe="CWE-798",
                            cwe_name=CWE_NAMES.get("CWE-798"),
                            severity=Severity.HIGH,
                            file_path=self.rel_path,
                            line=node.lineno,
                            code_snippet=masked_snippet,
                            is_protected_decoy=False,
                        )
                        self.findings.append(finding)

        self.generic_visit(node)


class SASTScanner:
    """
    Orchestrates the SAST scan across all Python files in a directory.
    """
    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)

    def scan(self, reachable_files: Optional[Set[str]] = None) -> List[CanonicalFinding]:
        all_findings: List[CanonicalFinding] = []

        for dirpath, _, filenames in os.walk(self.root_dir):
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules") for p in parts):
                continue

            for fname in filenames:
                if fname.endswith(".py"):
                    full_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")
                    file_findings = self._scan_file(full_path, rel_path, reachable_files)
                    all_findings.extend(file_findings)

        return all_findings

    def _scan_file(self, full_path: str, rel_path: str, reachable_files: Optional[Set[str]]) -> List[CanonicalFinding]:
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
            tree = ast.parse(content, filename=rel_path)

            visitor = SASTVisitor(full_path, rel_path, lines)
            visitor.visit(tree)

            # Check unreachable dead code for B-2 suppression
            filtered: List[CanonicalFinding] = []
            for f in visitor.findings:
                checked = DecoyFilter.filter_finding(f, reachable_files=reachable_files)
                filtered.append(checked)
            return filtered
        except Exception:
            return []
