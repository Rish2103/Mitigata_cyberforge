"""
Decoy and False Positive Filter (B-2).
Suppresses safe decoys (e.g. parameterised SQL queries, shell=False commands,
path traversals guarded by safe prefixes, dead code unreachable from any route).
Enforces 0% false alarms on the 8 planted safe decoys.
"""

import ast
from typing import Optional, Tuple, Set
from core.schemas import CanonicalFinding, RouteEntry


class DecoyFilter:
    """
    Analyzes candidate SAST findings and AST nodes to distinguish real vulnerabilities
    from safe decoys (PRD B-2).
    """

    @staticmethod
    def is_safe_sql_query(call_node: ast.Call) -> Tuple[bool, str]:
        """
        Detects parameterized SQL queries:
        cursor.execute(sql, (param,))
        cursor.execute(sql, [param])
        cursor.execute(sql, {'param': val})
        db.session.execute(text(sql), params)
        """
        # If cursor.execute or conn.execute has 2 or more arguments:
        if len(call_node.args) >= 2:
            arg2 = call_node.args[1]
            # If the second argument is a tuple, list, dict, or variable name passing parameters
            if isinstance(arg2, (ast.Tuple, ast.List, ast.Dict, ast.Name, ast.Call)):
                # Ensure the first argument is not itself an f-string / formatted string
                arg1 = call_node.args[0]
                if not isinstance(arg1, ast.JoinedStr):
                    # Check if arg1 is BinOp with % or +
                    if isinstance(arg1, ast.BinOp) and isinstance(arg1.op, (ast.Mod, ast.Add)):
                        # If first arg uses % or +, it is still string formatting!
                        return False, ""
                    return True, "Safe parameterized SQL query: query and bound parameters passed separately"

        # Check keyword arguments e.g. params=(...)
        for kw in call_node.keywords:
            if kw.arg in ("params", "parameters", "args"):
                return True, "Safe parameterized SQL query with explicit parameters keyword argument"

        return False, ""

    @staticmethod
    def is_safe_subprocess(call_node: ast.Call) -> Tuple[bool, str]:
        """
        Detects safe command execution:
        subprocess.run(['ls', '-l'], shell=False)
        """
        # Check if shell=True is explicitly passed or omitted
        has_shell_true = False
        for kw in call_node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True
                elif isinstance(kw.value, ast.Name) and kw.value.id == "True":
                    has_shell_true = True

        # If args[0] is a list/tuple of strings and shell is not True, it's safe
        if call_node.args and isinstance(call_node.args[0], (ast.List, ast.Tuple)):
            if not has_shell_true:
                return True, "Safe command execution: argument vector array used with shell=False"

        return False, ""

    @staticmethod
    def is_safe_path_traversal(call_node: ast.Call, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe file access protected by secure_filename, os.path.realpath prefix check,
        or abspath check.
        """
        code_lower = enclosing_code.lower()
        if "secure_filename(" in code_lower:
            return True, "Safe file operation: input sanitized via werkzeug.utils.secure_filename"
        if "os.path.realpath" in code_lower and ("startswith" in code_lower or "commonpath" in code_lower):
            return True, "Safe file operation: canonicalized path validated with prefix/startswith guard"
        if "os.path.abspath" in code_lower and "startswith" in code_lower:
            return True, "Safe file operation: path verified with abspath prefix check"
        if "os.path.basename" in code_lower:
            return True, "Safe file operation: directory components stripped via os.path.basename"

        return False, ""

    @staticmethod
    def is_safe_redirect(call_node: ast.Call, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe redirect guarded by host allowlist, url_has_allowed_host_and_scheme,
        or startswith('/').
        """
        code_lower = enclosing_code.lower()
        if "url_has_allowed_host_and_scheme" in code_lower or "is_safe_url" in code_lower:
            return True, "Safe open redirect: target URL validated against host allowlist"
        if "startswith('/')" in code_lower or 'startswith("/")' in code_lower:
            return True, "Safe open redirect: target restricted strictly to local relative paths"

        return False, ""

    @classmethod
    def filter_finding(
        cls,
        finding: CanonicalFinding,
        call_node: Optional[ast.Call] = None,
        enclosing_snippet: str = "",
        reachable_files: Optional[Set[str]] = None,
    ) -> CanonicalFinding:
        """
        Evaluates finding against decoy rules. If protected or unreachable, sets:
        finding.is_protected_decoy = True
        finding.decoy_reason = explanation
        """
        if finding.is_protected_decoy:
            return finding

        # 1. SQL Injection (CWE-89)
        if finding.cwe == "CWE-89" and call_node:
            is_safe, reason = cls.is_safe_sql_query(call_node)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 2. Command Injection (CWE-78)
        if finding.cwe == "CWE-78" and call_node:
            is_safe, reason = cls.is_safe_subprocess(call_node)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 3. Path Traversal (CWE-22)
        if finding.cwe == "CWE-22":
            is_safe, reason = cls.is_safe_path_traversal(call_node, enclosing_snippet)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 4. Open Redirect (CWE-601)
        if finding.cwe == "CWE-601":
            is_safe, reason = cls.is_safe_redirect(call_node, enclosing_snippet)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 5. Dead Code / Unreachable Sink (B-2):
        # If finding is inside a file that is completely unreachable from any public route
        # (and not a CWE-798 Hard-coded Secret which matters regardless of route reachability)
        if reachable_files is not None and finding.file_path and finding.cwe != "CWE-798":
            norm_path = finding.file_path.replace("\\", "/").lstrip("./")
            if norm_path not in reachable_files and not any(r.endswith(norm_path) for r in reachable_files):
                # Candidate for dead-code suppression
                finding.is_protected_decoy = True
                finding.decoy_reason = f"Unreachable dead code: file {norm_path} is never called by any active route"
                return finding

        return finding
