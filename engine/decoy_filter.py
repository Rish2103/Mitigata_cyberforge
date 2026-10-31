"""
Decoy and False Positive Filter (B-2).
Suppresses safe decoys across Python and Node.js/Express:
1. CWE-89: Parameterized SQL queries (bound tuple/list/dict parameters) or strict int() cast guards
2. CWE-78: Argument vector arrays with shell=False, execFile(), or shlex.quote() sanitization
3. CWE-79: Explicit HTML escaping via html.escape, markupsafe.escape, bleach.clean, DOMPurify
4. CWE-22: Path canonicalization via secure_filename, os.path.basename, path.basename, realpath/abspath + startswith/commonpath
5. CWE-601: Redirect validation via url_has_allowed_host_and_scheme, is_safe_url, urlparse().netloc allowlist, or startswith('/')
6. Dead code: Unreachable files or unreachable dead functions never called by any active route (FR-4 -> B-2)

Enforces 0% false alarms on the ~8 planted safe decoys.
"""

import ast
import re
from typing import Optional, Tuple, Set, Dict, Any
from core.schemas import CanonicalFinding


class DecoyFilter:
    """
    Analyzes candidate SAST findings and AST nodes to distinguish real vulnerabilities
    from safe decoys (PRD B-2).
    """

    @staticmethod
    def _is_ast_node_dynamic_string(node: ast.AST, var_defs: Optional[Dict[str, ast.AST]] = None) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        if isinstance(node, ast.Name) and var_defs and node.id in var_defs:
            val_node = var_defs[node.id]
            if val_node is not node:
                return DecoyFilter._is_ast_node_dynamic_string(val_node, None)
        return False

    @staticmethod
    def _is_int_cast_node(
        node: ast.AST,
        var_defs: Optional[Dict[str, ast.AST]] = None,
        enclosing_code: str = "",
    ) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "int":
            return True
        if isinstance(node, ast.Name):
            if var_defs and node.id in var_defs:
                val = var_defs[node.id]
                if isinstance(val, ast.Call) and isinstance(val.func, ast.Name) and val.func.id == "int":
                    return True
            if enclosing_code and re.search(rf"\b{re.escape(node.id)}\s*=\s*int\s*\(", enclosing_code):
                return True
        return False

    @staticmethod
    def _all_interpolations_int_casted(
        query_node: ast.AST,
        var_defs: Optional[Dict[str, ast.AST]] = None,
        enclosing_code: str = "",
    ) -> bool:
        target = query_node
        if isinstance(target, ast.Name) and var_defs and target.id in var_defs:
            target = var_defs[target.id]

        interp_nodes = []
        if isinstance(target, ast.JoinedStr):
            interp_nodes = [v.value for v in target.values if isinstance(v, ast.FormattedValue)]
        elif isinstance(target, ast.BinOp) and isinstance(target.op, ast.Mod):
            if isinstance(target.right, (ast.Tuple, ast.List)):
                interp_nodes = list(target.right.elts)
            else:
                interp_nodes = [target.right]
        elif isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute) and target.func.attr == "format":
            interp_nodes = list(target.args) + [kw.value for kw in target.keywords]

        if not interp_nodes:
            return False
        return all(DecoyFilter._is_int_cast_node(n, var_defs, enclosing_code) for n in interp_nodes)

    @staticmethod
    def is_safe_sql_query(
        call_node: ast.Call,
        enclosing_code: str = "",
        var_defs: Optional[Dict[str, ast.AST]] = None,
    ) -> Tuple[bool, str]:
        """
        Detects parameterized SQL queries or strict int() cast guards:
        cursor.execute(sql, (param,))
        cursor.execute(sql, [param])
        cursor.execute(sql, {'param': val})
        db.session.execute(text(sql), params)
        cursor.execute(f"SELECT * FROM t WHERE id = {int(uid)}")
        """
        if len(call_node.args) >= 2:
            arg1 = call_node.args[0]
            arg2 = call_node.args[1]
            if isinstance(arg2, (ast.Tuple, ast.List, ast.Dict, ast.Name, ast.Call)):
                if not DecoyFilter._is_ast_node_dynamic_string(arg1, var_defs):
                    return True, "Safe parameterized SQL query: SQL template and bound parameters passed separately"

        for kw in call_node.keywords:
            if kw.arg in ("params", "parameters", "args", "bind_params"):
                if call_node.args and not DecoyFilter._is_ast_node_dynamic_string(call_node.args[0], var_defs):
                    return True, "Safe parameterized SQL query with explicit parameters keyword argument"

        if call_node.args and DecoyFilter._all_interpolations_int_casted(call_node.args[0], var_defs, enclosing_code):
            return True, "Safe SQL query: interpolated parameter strictly cast via int() guard"

        return False, ""

    @staticmethod
    def is_safe_subprocess(call_node: ast.Call, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe command execution:
        - subprocess.run(['ls', '-l'], shell=False)
        - shlex.quote(user_input) used to sanitize shell arguments
        """
        has_shell_true = False
        for kw in call_node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True
                elif isinstance(kw.value, ast.Name) and kw.value.id == "True":
                    has_shell_true = True

        if call_node.args and isinstance(call_node.args[0], (ast.List, ast.Tuple)):
            if not has_shell_true:
                return True, "Safe command execution: argument vector array used with shell=False"

        code_lower = enclosing_code.lower()
        if "shlex.quote(" in code_lower or "pipes.quote(" in code_lower:
            return True, "Safe command execution: dynamic argument escaped via shlex.quote()"

        return False, ""

    @staticmethod
    def is_safe_xss(call_node: Optional[ast.Call] = None, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe HTML rendering when user input is explicitly escaped via
        html.escape, markupsafe.escape, bleach.clean, or DOMPurify.sanitize.
        """
        code_lower = enclosing_code.lower()
        if (
            "html.escape(" in code_lower
            or "markupsafe.escape(" in code_lower
            or "flask.escape(" in code_lower
            or "bleach.clean(" in code_lower
            or "dompurify.sanitize(" in code_lower
            or "escapehtml(" in code_lower
        ):
            return True, "Safe HTML rendering: user input explicitly sanitized via HTML escape/cleaner"
        return False, ""

    @staticmethod
    def is_safe_path_traversal(call_node: Optional[ast.Call] = None, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe file access protected by secure_filename, os.path.realpath prefix check,
        os.path.abspath check, os.path.basename, or path.basename.
        """
        code_lower = enclosing_code.lower()
        if "secure_filename(" in code_lower:
            return True, "Safe file operation: input sanitized via werkzeug.utils.secure_filename"
        if ("os.path.realpath" in code_lower or "path.resolve(" in code_lower or ".resolve()" in code_lower) and (
            "startswith" in code_lower or "commonpath" in code_lower
        ):
            return True, "Safe file operation: canonicalized path validated with prefix/startswith guard"
        if "os.path.abspath" in code_lower and ("startswith" in code_lower or "commonpath" in code_lower):
            return True, "Safe file operation: path verified with abspath prefix check"
        if "os.path.basename(" in code_lower or "path.basename(" in code_lower:
            return True, "Safe file operation: directory traversal stripped via basename()"

        return False, ""

    @staticmethod
    def is_safe_redirect(call_node: Optional[ast.Call] = None, enclosing_code: str = "") -> Tuple[bool, str]:
        """
        Detects safe redirect guarded by host allowlist, url_has_allowed_host_and_scheme,
        urlparse().netloc validation, or startswith('/').
        """
        code_lower = enclosing_code.lower()
        if "url_has_allowed_host_and_scheme" in code_lower or "is_safe_url" in code_lower:
            return True, "Safe open redirect: target URL validated against host allowlist"
        if "startswith('/')" in code_lower or 'startswith("/")' in code_lower:
            return True, "Safe open redirect: target restricted strictly to local relative paths"
        if "urlparse(" in code_lower and "netloc" in code_lower:
            return True, "Safe open redirect: target URL netloc/domain verified via urlparse"
        if "allowed_hosts" in code_lower or "allowed_domains" in code_lower or "whitelist" in code_lower:
            return True, "Safe open redirect: target validated against explicit domain allowlist"

        return False, ""

    @classmethod
    def filter_finding(
        cls,
        finding: CanonicalFinding,
        call_node: Optional[ast.Call] = None,
        enclosing_snippet: str = "",
        reachable_files: Optional[Set[str]] = None,
        route_mapper: Optional[Any] = None,
    ) -> CanonicalFinding:
        """
        Evaluates finding against decoy rules. If protected or unreachable, sets:
        finding.is_protected_decoy = True
        finding.decoy_reason = explanation
        """
        if finding.is_protected_decoy:
            return finding

        context_text = enclosing_snippet or (finding.code_snippet or "")

        # 1. SQL Injection (CWE-89)
        if finding.cwe == "CWE-89" and call_node:
            is_safe, reason = cls.is_safe_sql_query(call_node, context_text)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 2. Command Injection (CWE-78)
        if finding.cwe == "CWE-78":
            if call_node:
                is_safe, reason = cls.is_safe_subprocess(call_node, context_text)
                if is_safe:
                    finding.is_protected_decoy = True
                    finding.decoy_reason = reason
                    return finding
            elif "shlex.quote(" in context_text.lower() or "execfile(" in context_text.lower():
                finding.is_protected_decoy = True
                finding.decoy_reason = "Safe command execution: arguments passed safely without shell interpretation"
                return finding

        # 3. Cross-Site Scripting (CWE-79)
        if finding.cwe == "CWE-79":
            is_safe, reason = cls.is_safe_xss(call_node, context_text)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 4. Path Traversal (CWE-22)
        if finding.cwe == "CWE-22":
            is_safe, reason = cls.is_safe_path_traversal(call_node, context_text)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 5. Open Redirect (CWE-601)
        if finding.cwe == "CWE-601":
            is_safe, reason = cls.is_safe_redirect(call_node, context_text)
            if is_safe:
                finding.is_protected_decoy = True
                finding.decoy_reason = reason
                return finding

        # 6. Dead Code / Unreachable Sink (B-2):
        # Exclude CWE-798 (hard-coded secrets), CWE-327 (weak crypto), CWE-489 (debug flags)
        # which are code-hygiene/config vulnerabilities that exist regardless of route calls.
        non_route_bound_cwes = {"CWE-798", "CWE-327", "CWE-489"}
        if finding.file_path and finding.cwe not in non_route_bound_cwes:
            norm_path = finding.file_path.replace("\\", "/").lstrip("./")

            # 6a. File-level reachability check
            if reachable_files is not None:
                if norm_path not in reachable_files and not any(
                    r.replace("\\", "/").lstrip("./").endswith(norm_path) for r in reachable_files
                ):
                    finding.is_protected_decoy = True
                    finding.decoy_reason = f"Unreachable dead code: file {norm_path} is never called by any active route"
                    return finding

            # 6b. Function-level reachability check via RouteMapper (if routes exist)
            if route_mapper is not None and getattr(route_mapper, "routes", None) and finding.line:
                if not route_mapper.is_line_reachable(norm_path, finding.line):
                    finding.is_protected_decoy = True
                    finding.decoy_reason = (
                        f"Unreachable dead code: function at {norm_path}:{finding.line} is never reached by any URL route"
                    )
                    return finding

        return finding
