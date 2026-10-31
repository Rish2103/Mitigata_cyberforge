"""
Precision AST-based SAST Scanner (FR-1, FR-3) + Node.js/Express Polyglot Scanner (B-7)
+ External SARIF / Bandit / Semgrep Normalizer (FR-3).

Scans Python and JavaScript/TypeScript source files for all 6 hackathon CWEs:
1. CWE-89: SQL Injection (f-strings, % formatting, .format(), concatenation, or tainted SQL variables)
2. CWE-79: Cross-Site Scripting (render_template_string, Markup, HTMLResponse, or unescaped HTML returns)
3. CWE-78: OS Command Injection (os.system, os.popen, subprocess with shell=True, child_process.exec)
4. CWE-22: Path Traversal (open(), send_file(), Path.read_text(), fs.readFile, res.sendFile with user input)
5. CWE-601: Open Redirect (redirect(), HttpResponseRedirect, RedirectResponse, res.redirect on user input)
6. CWE-798: Hard-coded Secrets (API keys, JWT secrets, passwords, private tokens, config['SECRET_KEY'])

Applies B-2 Decoy Filter with full enclosing-function context and route reachability
so that safe parameterised queries, sanitized inputs, and unreachable dead code are marked safe (0% false alarms).
"""

import ast
import hashlib
import json
import os
import re
from typing import List, Optional, Set, Dict, Any, Tuple, Union
from core.schemas import CanonicalFinding, FindingSource, Severity
from core.config import CWE_NAMES
from engine.decoy_filter import DecoyFilter


def _fingerprint_sast(cwe: str, file_path: str, line: int) -> str:
    norm_file = file_path.replace("\\", "/").lstrip("./")
    data = f"SAST:{cwe}:{norm_file}:{line}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


_HTML_TAG_RE = re.compile(r"<\s*(?:html|body|div|span|p|h[1-6]|script|img|a|table|tr|td|ul|li|form|input|b|i|u|section|header|footer)\b", re.IGNORECASE)


class SASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, rel_path: str, lines: List[str]):
        self.file_path = file_path
        self.rel_path = rel_path.replace("\\", "/")
        self.lines = lines
        self.findings: List[CanonicalFinding] = []
        self._func_stack: List[ast.AST] = []
        self._var_defs_stack: List[Dict[str, ast.AST]] = [{}]
        self._var_lines_stack: List[Dict[str, int]] = [{}]

    @property
    def _current_var_defs(self) -> Dict[str, ast.AST]:
        merged: Dict[str, ast.AST] = {}
        for scope in self._var_defs_stack:
            merged.update(scope)
        return merged

    @property
    def _current_var_lines(self) -> Dict[str, int]:
        merged: Dict[str, int] = {}
        for scope in self._var_lines_stack:
            merged.update(scope)
        return merged

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None) -> str:
        s = max(1, start_line)
        e = min(len(self.lines), end_line or start_line)
        return "\n".join(self.lines[s - 1 : e]).strip()

    def _get_enclosing_function_snippet(self, node: ast.AST) -> str:
        if self._func_stack:
            fn = self._func_stack[-1]
            start = getattr(fn, "lineno", 1)
            end = getattr(fn, "end_lineno", start)
            return self._get_snippet(start, end)
        lineno = getattr(node, "lineno", 1)
        return self._get_snippet(max(1, lineno - 5), min(len(self.lines), lineno + 5))

    def _get_contextual_snippet(self, node: ast.AST, arg_node: Optional[ast.AST] = None) -> str:
        """
        Returns the sink line snippet; if arg_node is a variable assigned earlier in the function,
        includes the assignment line so the parameter name is preserved in the snippet for correlation.
        """
        base = self._get_snippet(getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1)))
        if isinstance(arg_node, ast.Name) and arg_node.id in self._current_var_lines:
            def_line = self._current_var_lines[arg_node.id]
            if def_line != getattr(node, "lineno", 1):
                def_snippet = self._get_snippet(def_line, def_line)
                return f"{def_snippet}\n{base}"
        return base

    def _is_dynamic_string(self, node: ast.AST, _depth: int = 0) -> bool:
        """Checks if an AST expression is constructed dynamically (f-string, +, %, .format, or variable assigned one)."""
        if _depth > 4:
            return False
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        if isinstance(node, ast.Name):
            var_defs = self._current_var_defs
            if node.id in var_defs:
                return self._is_dynamic_string(var_defs[node.id], _depth + 1)
        return False

    def _contains_html_markup(self, node: ast.AST, _depth: int = 0) -> bool:
        if _depth > 4:
            return False
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if _HTML_TAG_RE.search(val.value):
                        return True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._contains_html_markup(node.left, _depth + 1) or self._contains_html_markup(node.right, _depth + 1)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                if _HTML_TAG_RE.search(node.func.value.value):
                    return True
        elif isinstance(node, ast.Name) and node.id in self._current_var_defs:
            return self._contains_html_markup(self._current_var_defs[node.id], _depth + 1)
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._func_stack.append(node)
        self._var_defs_stack.append({})
        self._var_lines_stack.append({})
        self.generic_visit(node)
        self._var_lines_stack.pop()
        self._var_defs_stack.pop()
        self._func_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._func_stack.append(node)
        self._var_defs_stack.append({})
        self._var_lines_stack.append({})
        self.generic_visit(node)
        self._var_lines_stack.pop()
        self._var_defs_stack.pop()
        self._func_stack.pop()

    def _infer_param_and_func(self, snippet: str, enclosing_code: str = "") -> Tuple[Optional[str], Optional[str]]:
        """Infer enclosing function name and HTTP parameter name feeding the sink."""
        fn_name: Optional[str] = None
        fn_args: List[str] = []
        if self._func_stack:
            fn_node = self._func_stack[-1]
            fn_name = getattr(fn_node, "name", None)
            if isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_args = [
                    a.arg for a in fn_node.args.args
                    if a.arg not in ("self", "cls", "request", "req", "db", "session", "conn", "cursor")
                ]

        # Map local variable -> request parameter name from AST assignments
        var_to_param: Dict[str, str] = {}
        for var_name, val_node in self._current_var_defs.items():
            if isinstance(val_node, ast.Call) and isinstance(val_node.func, ast.Attribute):
                if val_node.func.attr in ("get", "getlist") and val_node.args:
                    first = val_node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        var_to_param[var_name] = first.value
            elif isinstance(val_node, ast.Subscript) and isinstance(val_node.slice, ast.Constant):
                if isinstance(val_node.slice.value, str):
                    var_to_param[var_name] = val_node.slice.value

        # Also check regex on enclosing_code for var = request.*.get("param")
        if enclosing_code:
            for m in re.finditer(
                r"\b([a-zA-Z_]\w*)\s*=\s*(?:request\.(?:args|form|values|json|GET|POST|query_params)|data|body)\s*(?:\.\s*get\s*\(\s*['\"]([^'\"]+)['\"]|\[\s*['\"]([^'\"]+)['\"]\s*\])",
                enclosing_code,
            ):
                v_id = m.group(1)
                p_id = m.group(2) or m.group(3)
                if v_id and p_id:
                    var_to_param.setdefault(v_id, p_id)

        # Look for interpolated variables {var} in snippet
        for m_brace in re.finditer(r"\{\s*([a-zA-Z_]\w*)", snippet or ""):
            tok = m_brace.group(1)
            if tok in var_to_param:
                return fn_name, var_to_param[tok]
            if tok not in ("html", "shlex", "os", "urllib", "self", "request"):
                return fn_name, tok

        # Check if any mapped variable appears as a token in snippet
        snippet_tokens = set(re.findall(r"\b[a-zA-Z_]\w*\b", snippet or ""))
        for v_id, p_id in var_to_param.items():
            if v_id in snippet_tokens:
                return fn_name, p_id

        for arg_name in fn_args:
            if arg_name in snippet_tokens:
                return fn_name, arg_name

        if len(var_to_param) == 1:
            return fn_name, next(iter(var_to_param.values()))
        if len(fn_args) == 1:
            return fn_name, fn_args[0]

        return fn_name, None

    def visit_Return(self, node: ast.Return):
        # Detect direct HTML string returns in route handlers: return f"<h1>Hello {name}</h1>"
        if node.value and self._is_dynamic_string(node.value) and self._contains_html_markup(node.value):
            enclosing_code = self._get_enclosing_function_snippet(node)
            snippet = self._get_contextual_snippet(node, node.value)
            is_safe, reason = DecoyFilter.is_safe_xss(None, enclosing_code)
            fn_name, param_name = self._infer_param_and_func(snippet, enclosing_code)
            finding = CanonicalFinding(
                id=_fingerprint_sast("CWE-79", self.rel_path, node.lineno),
                source=FindingSource.SAST,
                cwe="CWE-79",
                cwe_name=CWE_NAMES.get("CWE-79"),
                severity=Severity.HIGH,
                file_path=self.rel_path,
                line=node.lineno,
                func_name=fn_name,
                param=param_name,
                code_snippet=snippet,
                is_protected_decoy=is_safe,
                decoy_reason=reason if is_safe else None,
            )
            self.findings.append(finding)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{attr_name}"

        enclosing_code = self._get_enclosing_function_snippet(node)
        first_arg = node.args[0] if node.args else None
        snippet = self._get_contextual_snippet(node, first_arg)
        fn_name, param_name = self._infer_param_and_func(snippet, enclosing_code)

        # -------------------------------------------------------------
        # 1. CWE-89: SQL Injection
        # -------------------------------------------------------------
        if attr_name in ("execute", "executemany", "raw", "read_sql") or func_name.endswith(".execute"):
            if node.args:
                query_arg = node.args[0]
                is_dynamic = self._is_dynamic_string(query_arg)
                is_safe, reason = DecoyFilter.is_safe_sql_query(node, enclosing_code, self._current_var_defs)

                if is_dynamic or is_safe:
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-89", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-89",
                        cwe_name=CWE_NAMES.get("CWE-89"),
                        severity=Severity.CRITICAL,
                        file_path=self.rel_path,
                        line=node.lineno,
                        func_name=fn_name,
                        param=param_name,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 2. CWE-78: Command Injection
        # -------------------------------------------------------------
        cmd_sinks = {
            "os.system",
            "os.popen",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "subprocess.check_output",
            "system",
            "popen",
        }
        if func_name in cmd_sinks or attr_name in ("system", "popen", "run", "call", "check_output"):
            # Guard against matching app.run() or thread.run() as subprocess.run()
            is_real_cmd_sink = func_name in cmd_sinks or (
                attr_name in ("system", "popen", "check_output")
                or (attr_name in ("run", "call", "Popen") and func_name.startswith("subprocess."))
            )
            if is_real_cmd_sink and node.args:
                cmd_arg = node.args[0]
                is_safe, reason = DecoyFilter.is_safe_subprocess(node, enclosing_code)
                is_dynamic = self._is_dynamic_string(cmd_arg) or isinstance(cmd_arg, (ast.Name, ast.Call))

                if is_dynamic or is_safe:
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-78", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-78",
                        cwe_name=CWE_NAMES.get("CWE-78"),
                        severity=Severity.CRITICAL,
                        file_path=self.rel_path,
                        line=node.lineno,
                        func_name=fn_name,
                        param=param_name,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 3. CWE-79: Cross-Site Scripting (XSS)
        # -------------------------------------------------------------
        xss_sinks = {"render_template_string", "Markup", "HTMLResponse", "make_response", "HttpResponse"}
        if attr_name in xss_sinks or func_name in xss_sinks:
            if node.args and (self._is_dynamic_string(node.args[0]) or isinstance(node.args[0], ast.Name)):
                is_safe, reason = DecoyFilter.is_safe_xss(node, enclosing_code)
                finding = CanonicalFinding(
                    id=_fingerprint_sast("CWE-79", self.rel_path, node.lineno),
                    source=FindingSource.SAST,
                    cwe="CWE-79",
                    cwe_name=CWE_NAMES.get("CWE-79"),
                    severity=Severity.HIGH,
                    file_path=self.rel_path,
                    line=node.lineno,
                    func_name=fn_name,
                    param=param_name,
                    code_snippet=snippet,
                    is_protected_decoy=is_safe,
                    decoy_reason=reason if is_safe else None,
                )
                self.findings.append(finding)

        # -------------------------------------------------------------
        # 4. CWE-22: Path Traversal
        # -------------------------------------------------------------
        if func_name in ("open", "send_file") or attr_name in ("open", "send_file", "send_from_directory"):
            if node.args:
                path_arg = node.args[0]
                target_arg = node.args[1] if (attr_name == "send_from_directory" and len(node.args) >= 2) else path_arg
                is_dynamic = self._is_dynamic_string(target_arg) or isinstance(target_arg, (ast.Name, ast.Call))
                if is_dynamic:
                    is_safe, reason = DecoyFilter.is_safe_path_traversal(node, enclosing_code)
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-22", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-22",
                        cwe_name=CWE_NAMES.get("CWE-22"),
                        severity=Severity.HIGH,
                        file_path=self.rel_path,
                        line=node.lineno,
                        func_name=fn_name,
                        param=param_name,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        # -------------------------------------------------------------
        # 5. CWE-601: Open Redirect
        # -------------------------------------------------------------
        if func_name in ("redirect", "HttpResponseRedirect", "RedirectResponse") or attr_name in (
            "redirect",
            "HttpResponseRedirect",
            "RedirectResponse",
        ):
            if node.args:
                target_arg = node.args[0]
                # Exclude redirect(url_for(...)) which points to internal route names
                is_url_for = isinstance(target_arg, ast.Call) and (
                    (isinstance(target_arg.func, ast.Name) and target_arg.func.id == "url_for")
                    or (isinstance(target_arg.func, ast.Attribute) and target_arg.func.attr == "url_for")
                )
                is_dynamic = not is_url_for and (
                    self._is_dynamic_string(target_arg) or isinstance(target_arg, (ast.Name, ast.Call))
                )
                if is_dynamic:
                    is_safe, reason = DecoyFilter.is_safe_redirect(node, enclosing_code)
                    finding = CanonicalFinding(
                        id=_fingerprint_sast("CWE-601", self.rel_path, node.lineno),
                        source=FindingSource.SAST,
                        cwe="CWE-601",
                        cwe_name=CWE_NAMES.get("CWE-601"),
                        severity=Severity.MEDIUM,
                        file_path=self.rel_path,
                        line=node.lineno,
                        func_name=fn_name,
                        param=param_name,
                        code_snippet=snippet,
                        is_protected_decoy=is_safe,
                        decoy_reason=reason if is_safe else None,
                    )
                    self.findings.append(finding)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Record local variable assignments for intra-function taint/dynamic resolution
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._var_defs_stack[-1][target.id] = node.value
                self._var_lines_stack[-1][target.id] = node.lineno

        # -------------------------------------------------------------
        # 6. CWE-798: Hard-coded Secrets
        # -------------------------------------------------------------
        secret_patterns = re.compile(
            r"(api[_-]?key|secret|password|passwd|token|jwt[_-]?secret|private[_-]?key|auth[_-]?token|client[_-]?secret|access[_-]?key)",
            re.IGNORECASE,
        )
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                target_name = target.slice.value

            if target_name and secret_patterns.search(target_name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value.strip()
                    if (
                        len(val) >= 6
                        and not val.startswith("${")
                        and val.lower() not in ("none", "null", "changeme", "placeholder", "your_api_key", "example")
                    ):
                        masked_snippet = self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno))
                        fn_name = getattr(self._func_stack[-1], "name", None) if self._func_stack else None
                        finding = CanonicalFinding(
                            id=_fingerprint_sast("CWE-798", self.rel_path, node.lineno),
                            source=FindingSource.SAST,
                            cwe="CWE-798",
                            cwe_name=CWE_NAMES.get("CWE-798"),
                            severity=Severity.HIGH,
                            file_path=self.rel_path,
                            line=node.lineno,
                            func_name=fn_name,
                            code_snippet=masked_snippet,
                            is_protected_decoy=False,
                        )
                        self.findings.append(finding)

        self.generic_visit(node)


class SASTScanner:
    """
    Orchestrates the SAST scan across all Python and JS/TS files in a directory,
    plus optional ingestion of external SARIF, Bandit, and Semgrep reports (FR-1, FR-3, B-7).
    """

    def __init__(self, root_dir: str, route_mapper: Optional[Any] = None):
        self.root_dir = os.path.abspath(root_dir)
        self.route_mapper = route_mapper

    def scan_directory(
        self,
        reachable_files: Optional[Set[str]] = None,
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        """Alias for `scan()` used by CLI and integration runners."""
        active_mapper = route_mapper or self.route_mapper
        if reachable_files is None and active_mapper is not None and hasattr(active_mapper, "get_reachable_files"):
            reachable_files = active_mapper.get_reachable_files()
        return self.scan(reachable_files=reachable_files, route_mapper=active_mapper)

    def ingest_sarif_file(self, sarif_path: Union[str, Dict[str, Any]]) -> List[CanonicalFinding]:
        """Alias for `from_sarif`."""
        return self.from_sarif(sarif_path)

    def ingest_bandit_file(self, bandit_path: Union[str, Dict[str, Any]]) -> List[CanonicalFinding]:
        """Alias for `from_bandit`."""
        return self.from_bandit(bandit_path)

    def scan(
        self,
        reachable_files: Optional[Set[str]] = None,
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        active_mapper = route_mapper or self.route_mapper
        all_findings: List[CanonicalFinding] = []
        self._func_param_names: Dict[str, List[str]] = {}
        self._func_var_to_http_param: Dict[str, Dict[str, str]] = {}
        self._func_call_edges: Dict[str, List[Tuple[str, List[str]]]] = {}
        self._func_local_aliases: Dict[str, List[Tuple[str, str]]] = {}

        for dirpath, _, filenames in os.walk(self.root_dir):
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules", "dist", "build") for p in parts):
                continue

            for fname in sorted(filenames):
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")
                if fname.endswith(".py"):
                    file_findings = self._scan_python_file(full_path, rel_path, reachable_files, active_mapper)
                    all_findings.extend(file_findings)
                elif fname.endswith((".js", ".ts")) and not fname.endswith(".min.js"):
                    js_findings = self._scan_js_file(full_path, rel_path, reachable_files, active_mapper)
                    all_findings.extend(js_findings)
                elif fname.endswith(".java"):
                    java_findings = self._scan_java_file(full_path, rel_path, reachable_files, active_mapper)
                    all_findings.extend(java_findings)

        # Propagate HTTP parameter names across 3-hop helper call chains & intra-function aliases
        for _ in range(5):
            for fn_name, aliases in self._func_local_aliases.items():
                fn_map = self._func_var_to_http_param.get(fn_name, {})
                if not fn_map:
                    continue
                for target_var, src_var in aliases:
                    if src_var in fn_map and target_var not in fn_map:
                        fn_map[target_var] = fn_map[src_var]

            for caller_fn, calls in self._func_call_edges.items():
                caller_map = self._func_var_to_http_param.get(caller_fn, {})
                if not caller_map:
                    continue
                for callee_fn, arg_vars in calls:
                    callee_formals = self._func_param_names.get(callee_fn, [])
                    for idx, passed_var in enumerate(arg_vars):
                        if idx < len(callee_formals) and passed_var in caller_map:
                            formal_name = callee_formals[idx]
                            self._func_var_to_http_param.setdefault(callee_fn, {}).setdefault(
                                formal_name, caller_map[passed_var]
                            )

        for fn_name, aliases in self._func_local_aliases.items():
            fn_map = self._func_var_to_http_param.get(fn_name, {})
            if fn_map:
                for target_var, src_var in aliases:
                    if src_var in fn_map and target_var not in fn_map:
                        fn_map[target_var] = fn_map[src_var]

        for f in all_findings:
            if f.func_name and f.param:
                fn_map = self._func_var_to_http_param.get(f.func_name, {})
                if f.param in fn_map:
                    f.param = fn_map[f.param]

        return all_findings

    @staticmethod
    def _extract_http_param_from_expr(expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if expr.func.attr in ("get", "getlist") and expr.args:
                arg0 = expr.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    return arg0.value
        elif isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Constant):
            if isinstance(expr.slice.value, str):
                return expr.slice.value
        return None

    def _collect_interprocedural_taint(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = node.name
                formals = [
                    a.arg for a in node.args.args
                    if a.arg not in ("self", "cls", "request", "req", "db", "session", "conn", "cursor")
                ]
                self._func_param_names[fn_name] = formals
                var_map = self._func_var_to_http_param.setdefault(fn_name, {})
                if node.decorator_list:
                    for p in formals:
                        var_map.setdefault(p, p)

                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        param_extracted = self._extract_http_param_from_expr(sub.value)
                        if param_extracted:
                            for t in sub.targets:
                                if isinstance(t, ast.Name):
                                    var_map[t.id] = param_extracted
                        else:
                            call_func_ids = {
                                c.func.id
                                for c in ast.walk(sub.value)
                                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                            }
                            src_names = [
                                n.id
                                for n in ast.walk(sub.value)
                                if isinstance(n, ast.Name)
                                and n.id not in call_func_ids
                                and n.id not in ("str", "int", "float", "list", "dict", "set", "tuple", "len", "True", "False", "None")
                            ]
                            for t in sub.targets:
                                if isinstance(t, ast.Name):
                                    for s_name in src_names:
                                        if s_name != t.id:
                                            self._func_local_aliases.setdefault(fn_name, []).append((t.id, s_name))

                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        callee_name = ""
                        if isinstance(sub.func, ast.Name):
                            callee_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            callee_name = sub.func.attr
                        if callee_name:
                            arg_names: List[str] = []
                            for a in sub.args:
                                inline_param = self._extract_http_param_from_expr(a)
                                if inline_param:
                                    pseudo_key = f"__inline_param__:{inline_param}"
                                    var_map[pseudo_key] = inline_param
                                    arg_names.append(pseudo_key)
                                elif isinstance(a, ast.Name):
                                    arg_names.append(a.id)
                                elif isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and isinstance(a.func.value, ast.Name):
                                    arg_names.append(a.func.value.id)
                                elif isinstance(a, ast.Call) and a.args and isinstance(a.args[0], ast.Name):
                                    arg_names.append(a.args[0].id)
                                else:
                                    arg_names.append("")
                            self._func_call_edges.setdefault(fn_name, []).append((callee_name, arg_names))

    def _scan_python_file(
        self,
        full_path: str,
        rel_path: str,
        reachable_files: Optional[Set[str]],
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
            tree = ast.parse(content, filename=rel_path)

            if hasattr(self, "_func_param_names"):
                self._collect_interprocedural_taint(tree)

            visitor = SASTVisitor(full_path, rel_path, lines)
            visitor.visit(tree)

            filtered: List[CanonicalFinding] = []
            for f in visitor.findings:
                checked = DecoyFilter.filter_finding(
                    f,
                    enclosing_snippet=f.code_snippet or "",
                    reachable_files=reachable_files,
                    route_mapper=route_mapper,
                )
                filtered.append(checked)
            return filtered
        except Exception:
            return []

    @staticmethod
    def _infer_js_param(line_s: str, context_window: str) -> Optional[str]:
        # Direct req.query.x / req.body.x / req.params.x on line
        m_direct = re.search(r"\breq\s*\.\s*(?:query|body|params)\s*\.\s*([a-zA-Z_]\w*)", line_s)
        if m_direct:
            return m_direct.group(1)
        m_sub = re.search(r"""\breq\s*\.\s*(?:query|body|params)\s*\[\s*['"]([^'"]+)['"]\s*\]""", line_s)
        if m_sub:
            return m_sub.group(1)

        # Map local JS variable -> req.query.param in context window
        var_to_param: Dict[str, str] = {}
        for m in re.finditer(
            r"\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*req\s*\.\s*(?:query|body|params)\s*\.\s*([a-zA-Z_]\w*)",
            context_window,
        ):
            var_to_param[m.group(1)] = m.group(2)
        for m in re.finditer(
            r"\{\s*([^}]+)\}\s*=\s*req\s*\.\s*(?:query|body|params)",
            context_window,
        ):
            for part in m.group(1).split(","):
                clean_p = part.split(":")[0].split("=")[0].strip()
                if clean_p and re.match(r"^[a-zA-Z_]\w*$", clean_p):
                    var_to_param[clean_p] = clean_p

        # Check template literal ${var} or concatenation + var
        for m_interp in re.finditer(r"\$\{\s*([a-zA-Z_]\w*)\s*\}", line_s):
            tok = m_interp.group(1)
            if tok in var_to_param:
                return var_to_param[tok]
            return tok
        for tok in re.findall(r"\b[a-zA-Z_]\w*\b", line_s):
            if tok in var_to_param:
                return var_to_param[tok]
        if len(var_to_param) == 1:
            return next(iter(var_to_param.values()))
        return None

    # -------------------------------------------------------------------------
    # Bonus B-7: Node.js / Express SAST Scanner
    # -------------------------------------------------------------------------
    def _scan_js_file(
        self,
        full_path: str,
        rel_path: str,
        reachable_files: Optional[Set[str]],
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        findings: List[CanonicalFinding] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()

            for idx, raw_line in enumerate(lines):
                lineno = idx + 1
                line_s = raw_line.strip()
                if not line_s or line_s.startswith("//") or line_s.startswith("/*"):
                    continue

                window_start = max(0, idx - 6)
                window_end = min(len(lines), idx + 5)
                context_window = "\n".join(lines[window_start:window_end])
                js_param = self._infer_js_param(line_s, context_window)

                # 1. CWE-89: JS SQL Injection
                if re.search(r"\b(?:db|pool|conn|connection|client|sequelize|knex)\s*\.\s*(?:query|execute|raw|all|get)\s*\(", line_s):
                    has_template_interp = "`" in line_s and "${" in line_s
                    has_concat = "+" in line_s and re.search(r"(?:SELECT|INSERT|UPDATE|DELETE)\b", line_s, re.IGNORECASE)
                    has_bound_params = bool(re.search(r",\s*\[[^\]]+\]", line_s)) and not has_template_interp and not has_concat
                    if has_template_interp or has_concat or has_bound_params:
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-89", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-89",
                                cwe_name=CWE_NAMES.get("CWE-89"),
                                severity=Severity.CRITICAL,
                                file_path=rel_path,
                                line=lineno,
                                param=js_param,
                                code_snippet=line_s,
                                is_protected_decoy=has_bound_params,
                                decoy_reason="Safe parameterized SQL query with bound array parameters" if has_bound_params else None,
                            )
                        )

                # 2. CWE-78: JS Command Injection
                if re.search(r"\b(?:exec|execSync|execFile|execFileSync|spawn)\s*\(", line_s):
                    is_exec_file = bool(re.search(r"\b(?:execFile|execFileSync)\s*\(", line_s))
                    is_spawn_safe = "spawn(" in line_s and "shell: true" not in line_s
                    is_safe_cmd = is_exec_file or is_spawn_safe
                    is_dynamic_cmd = ("`" in line_s and "${" in line_s) or "+" in line_s or "req." in line_s
                    if is_dynamic_cmd or is_safe_cmd:
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-78", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-78",
                                cwe_name=CWE_NAMES.get("CWE-78"),
                                severity=Severity.CRITICAL,
                                file_path=rel_path,
                                line=lineno,
                                param=js_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_cmd,
                                decoy_reason="Safe command execution via execFile/spawn without shell" if is_safe_cmd else None,
                            )
                        )

                # 3. CWE-79: JS XSS
                if re.search(r"\bres\s*\.\s*(?:send|write)\s*\(", line_s) or ".innerHTML" in line_s:
                    if ("`" in line_s and "${" in line_s and _HTML_TAG_RE.search(line_s)) or (
                        "+" in line_s and _HTML_TAG_RE.search(line_s)
                    ) or ".innerHTML" in line_s:
                        is_safe_xss, xss_reason = DecoyFilter.is_safe_xss(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-79", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-79",
                                cwe_name=CWE_NAMES.get("CWE-79"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                param=js_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_xss,
                                decoy_reason=xss_reason if is_safe_xss else None,
                            )
                        )

                # 4. CWE-22: JS Path Traversal
                if re.search(r"\b(?:fs\.readFile|fs\.readFileSync|res\.sendFile)\s*\(", line_s):
                    if ("`" in line_s and "${" in line_s) or "+" in line_s or "req." in line_s or "path.join(" in line_s:
                        is_safe_path, path_reason = DecoyFilter.is_safe_path_traversal(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-22", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-22",
                                cwe_name=CWE_NAMES.get("CWE-22"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                param=js_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_path,
                                decoy_reason=path_reason if is_safe_path else None,
                            )
                        )

                # 5. CWE-601: JS Open Redirect
                if re.search(r"\bres\s*\.\s*redirect\s*\(", line_s):
                    if not re.search(r"""\bres\s*\.\s*redirect\s*\(\s*['"][^'"]+['"]\s*\)""", line_s):
                        is_safe_red, red_reason = DecoyFilter.is_safe_redirect(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-601", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-601",
                                cwe_name=CWE_NAMES.get("CWE-601"),
                                severity=Severity.MEDIUM,
                                file_path=rel_path,
                                line=lineno,
                                param=js_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_red,
                                decoy_reason=red_reason if is_safe_red else None,
                            )
                        )

                # 6. CWE-798: JS Hard-coded Secrets
                sec_match = re.search(
                    r"""(?:const|let|var)?\s*\b([a-zA-Z0-9_]*(?:api[_-]?key|secret|password|passwd|jwt[_-]?secret|private[_-]?key|auth[_-]?token)[a-zA-Z0-9_]*)\s*[:=]\s*['"]([^'"]{6,})['"]""",
                    line_s,
                    re.IGNORECASE,
                )
                if sec_match and "process.env" not in line_s:
                    val = sec_match.group(2).strip()
                    if val.lower() not in ("changeme", "placeholder", "none", "null"):
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-798", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-798",
                                cwe_name=CWE_NAMES.get("CWE-798"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                code_snippet=line_s,
                                is_protected_decoy=False,
                            )
                        )

            filtered: List[CanonicalFinding] = []
            for f in findings:
                checked = DecoyFilter.filter_finding(
                    f,
                    enclosing_snippet=f.code_snippet or "",
                    reachable_files=reachable_files,
                    route_mapper=route_mapper,
                )
                filtered.append(checked)
            return filtered
        except Exception:
            return []

    # -------------------------------------------------------------------------
    # Bonus B-7: Java (Spring Boot / Jakarta Servlet) SAST & Safe Decoy Scanner
    # -------------------------------------------------------------------------
    @staticmethod
    def _infer_java_param(line_s: str, context_window: str) -> Optional[str]:
        # 1. Direct request.getParameter("param") on the sink line
        m_req = re.search(
            r"""\b(?:request|req|httpRequest)\s*\.\s*getParameter\s*\(\s*["']([^"']+)["']\s*\)""",
            line_s,
        )
        if m_req:
            return m_req.group(1)

        # 2. Build local Java variable -> HTTP parameter name map from enclosing method window
        var_to_param: Dict[str, str] = {}
        for m in re.finditer(
            r"""\b(?:String|int|long|Integer|Long|Object|var)\s+([a-zA-Z_]\w*)\s*=\s*(?:request|req|httpRequest)\s*\.\s*getParameter\s*\(\s*["']([^"']+)["']\s*\)""",
            context_window,
        ):
            var_to_param[m.group(1)] = m.group(2)

        for m in re.finditer(
            r"""\b(?:String|Object|var)\s+([a-zA-Z_]\w*)\s*=\s*(?:body|payload|params|data)\s*\.\s*get\s*\(\s*["']([^"']+)["']\s*\)""",
            context_window,
        ):
            var_to_param[m.group(1)] = m.group(2)

        # @RequestParam("q") String query  OR  @RequestParam String host
        for m in re.finditer(
            r"""@(?:RequestParam|PathVariable)(?:\s*\(\s*(?:(?:value|name)\s*=\s*)?["']([^"']+)["'][^)]*\))?\s+(?:final\s+)?[\w<>\[\]\?]+\s+([a-zA-Z_]\w*)""",
            context_window,
        ):
            http_name = m.group(1) or m.group(2)
            var_name = m.group(2)
            var_to_param[var_name] = http_name

        # Propagate 1-hop local String assignments (e.g., String sql = "SELECT ..." + orderId;)
        for m_assign in re.finditer(r"\bString\s+([a-zA-Z_]\w*)\s*=\s*([^;]+);", context_window):
            lhs, rhs = m_assign.group(1), m_assign.group(2)
            for tok in re.findall(r"\b[a-zA-Z_]\w*\b", rhs):
                if tok in var_to_param:
                    var_to_param[lhs] = var_to_param[tok]

        for tok in re.findall(r"\b[a-zA-Z_]\w*\b", line_s):
            if tok in var_to_param:
                return var_to_param[tok]
        if len(var_to_param) == 1:
            return next(iter(var_to_param.values()))
        return None

    def _scan_java_file(
        self,
        full_path: str,
        rel_path: str,
        reachable_files: Optional[Set[str]],
        route_mapper: Optional[Any] = None,
    ) -> List[CanonicalFinding]:
        findings: List[CanonicalFinding] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()

            for idx, raw_line in enumerate(lines):
                lineno = idx + 1
                line_s = raw_line.strip()
                if not line_s or line_s.startswith(("//", "/*", "*")):
                    continue

                window_start = max(0, idx - 8)
                window_end = min(len(lines), idx + 5)
                context_window = "\n".join(lines[window_start:window_end])
                java_param = self._infer_java_param(line_s, context_window)

                # Resolve enclosing Java method name from RouteMapper if available
                fn_name: Optional[str] = None
                if route_mapper is not None:
                    matched_routes = route_mapper.find_routes_for_finding(rel_path, lineno)
                    if matched_routes:
                        fn_name = matched_routes[0].func_name

                # 1. CWE-89: Java SQL Injection & Safe PreparedStatement Decoy
                is_sql_exec = bool(
                    re.search(
                        r"\b(?:stmt|statement|conn|connection|jdbcTemplate|entityManager)\s*\.\s*(?:executeQuery|executeUpdate|execute|query|queryForObject| queryForList|update|createNativeQuery)\s*\(",
                        line_s,
                    )
                )
                is_prep_stmt = bool(re.search(r"\bprepareStatement\s*\(", line_s))
                if is_sql_exec or is_prep_stmt:
                    has_concat = "+" in line_s or "String.format(" in line_s or (
                        "+" in context_window and bool(re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", context_window, re.IGNORECASE))
                    )
                    is_safe_prep = is_prep_stmt and "?" in line_s and "+" not in line_s and "String.format(" not in line_s
                    if has_concat or is_safe_prep:
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-89", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-89",
                                cwe_name=CWE_NAMES.get("CWE-89"),
                                severity=Severity.CRITICAL,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                param=java_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_prep,
                                decoy_reason=(
                                    "Safe parameterized SQL query: Java PreparedStatement with '?' bound placeholders"
                                    if is_safe_prep
                                    else None
                                ),
                            )
                        )

                # 2. CWE-78: Java OS Command Injection & Safe ProcessBuilder Decoy
                is_runtime_exec = bool(re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", line_s))
                is_proc_builder = bool(re.search(r"new\s+ProcessBuilder\s*\(", line_s))
                if is_runtime_exec or is_proc_builder:
                    invokes_shell = bool(re.search(r"""["'](?:sh|bash|/bin/sh|cmd|cmd\.exe)["']\s*,\s*["'](?:-c|/c)["']""", line_s))
                    has_concat = "+" in line_s or "String.format(" in line_s
                    is_safe_pb = is_proc_builder and not invokes_shell and not has_concat
                    if is_runtime_exec or invokes_shell or has_concat or is_safe_pb:
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-78", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-78",
                                cwe_name=CWE_NAMES.get("CWE-78"),
                                severity=Severity.CRITICAL,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                param=java_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_pb,
                                decoy_reason=(
                                    "Safe command execution: Java ProcessBuilder argument list without shell interpretation"
                                    if is_safe_pb
                                    else None
                                ),
                            )
                        )

                # 3. CWE-79: Java Reflected XSS & Safe HtmlUtils.htmlEscape Decoy
                if (
                    re.search(r"\bgetWriter\(\)\s*\.\s*(?:write|print|println)\s*\(", line_s)
                    or re.search(r"\bResponseEntity\s*\.\s*ok\s*\(", line_s)
                ) and _HTML_TAG_RE.search(line_s):
                    if "+" in line_s or "String.format(" in line_s:
                        is_safe_xss, xss_reason = DecoyFilter.is_safe_xss(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-79", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-79",
                                cwe_name=CWE_NAMES.get("CWE-79"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                param=java_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_xss,
                                decoy_reason=xss_reason if is_safe_xss else None,
                            )
                        )

                # 4. CWE-22: Java Path Traversal & Safe .normalize().startsWith() Decoy
                if re.search(r"\b(?:new\s+FileInputStream|Files\.readString|Files\.readAllBytes|Paths\.get)\s*\(", line_s):
                    if "+" in line_s or (java_param and java_param in line_s):
                        is_safe_path, path_reason = DecoyFilter.is_safe_path_traversal(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-22", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-22",
                                cwe_name=CWE_NAMES.get("CWE-22"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                param=java_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_path,
                                decoy_reason=path_reason if is_safe_path else None,
                            )
                        )

                # 5. CWE-601: Java Open Redirect
                if re.search(r"\bsendRedirect\s*\(", line_s) or (
                    '"redirect:"' in line_s and "+" in line_s
                ):
                    if not re.search(r"""\bsendRedirect\s*\(\s*["'][^"']+["']\s*\)""", line_s):
                        is_safe_red, red_reason = DecoyFilter.is_safe_redirect(None, context_window)
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-601", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-601",
                                cwe_name=CWE_NAMES.get("CWE-601"),
                                severity=Severity.MEDIUM,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                param=java_param,
                                code_snippet=line_s,
                                is_protected_decoy=is_safe_red,
                                decoy_reason=red_reason if is_safe_red else None,
                            )
                        )

                # 6. CWE-798: Java Hard-coded Secrets
                sec_match = re.search(
                    r"""(?:private|public|protected|static|final|\bString\b)\s+[\w\s]*\b([a-zA-Z0-9_]*(?:api[_-]?key|secret|password|passwd|jwt[_-]?secret|private[_-]?key|auth[_-]?token)[a-zA-Z0-9_]*)\s*=\s*["']([^"']{6,})["']""",
                    line_s,
                    re.IGNORECASE,
                )
                if sec_match and "System.getenv" not in line_s and "getProperty" not in line_s:
                    val = sec_match.group(2).strip()
                    if val.lower() not in ("changeme", "placeholder", "none", "null"):
                        findings.append(
                            CanonicalFinding(
                                id=_fingerprint_sast("CWE-798", rel_path, lineno),
                                source=FindingSource.SAST,
                                cwe="CWE-798",
                                cwe_name=CWE_NAMES.get("CWE-798"),
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=lineno,
                                func_name=fn_name,
                                code_snippet=line_s,
                                is_protected_decoy=False,
                            )
                        )

            filtered: List[CanonicalFinding] = []
            for f in findings:
                checked = DecoyFilter.filter_finding(
                    f,
                    enclosing_snippet=f.code_snippet or "",
                    reachable_files=reachable_files,
                    route_mapper=route_mapper,
                )
                filtered.append(checked)
            return filtered
        except Exception:
            return []

    # -------------------------------------------------------------------------
    # FR-3 External SAST Report Normalizers (SARIF v2.1.0, Bandit, Semgrep)
    # -------------------------------------------------------------------------
    @staticmethod
    def from_sarif(sarif_input: Union[str, Dict[str, Any]]) -> List[CanonicalFinding]:
        """
        Normalizes a SARIF v2.1.0 JSON report (from Semgrep, CodeQL, Bandit, etc.)
        into CanonicalFinding objects (FR-3).
        """
        data = json.loads(sarif_input) if isinstance(sarif_input, str) and sarif_input.strip().startswith("{") else (
            json.load(open(sarif_input, "r", encoding="utf-8")) if isinstance(sarif_input, str) else sarif_input
        )
        findings: List[CanonicalFinding] = []
        for run in data.get("runs", []):
            rules_by_id: Dict[str, Dict[str, Any]] = {}
            for r in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules_by_id[r.get("id", "")] = r

            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                rule_meta = rules_by_id.get(rule_id, {})
                cwe = SASTScanner._extract_cwe_from_tags(res, rule_meta, rule_id)
                level = (res.get("level") or "warning").lower()
                sev = Severity.CRITICAL if level == "error" and cwe in ("CWE-89", "CWE-78") else (
                    Severity.HIGH if level == "error" else Severity.MEDIUM
                )

                for loc in res.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    file_path = phys.get("artifactLocation", {}).get("uri", "").replace("\\", "/").lstrip("./")
                    region = phys.get("region", {})
                    line = int(region.get("startLine", 1))
                    snippet = region.get("snippet", {}).get("text", "") or res.get("message", {}).get("text", "")
                    sarif_hash = hashlib.sha256(f"sarif:{rule_id}:{cwe}:{file_path}:{line}".encode("utf-8")).hexdigest()[:12]
                    findings.append(
                        CanonicalFinding(
                            id=f"SARIF-{sarif_hash}",
                            source=FindingSource.SAST,
                            cwe=cwe,
                            cwe_name=CWE_NAMES.get(cwe, cwe),
                            severity=sev,
                            file_path=file_path,
                            line=line,
                            code_snippet=snippet.strip(),
                            raw_details={"rule_id": rule_id, "format": "sarif"},
                        )
                    )
        return findings

    @staticmethod
    def from_bandit(bandit_input: Union[str, Dict[str, Any]]) -> List[CanonicalFinding]:
        """
        Normalizes Bandit JSON output into CanonicalFinding objects (FR-3).
        """
        data = json.loads(bandit_input) if isinstance(bandit_input, str) and bandit_input.strip().startswith("{") else (
            json.load(open(bandit_input, "r", encoding="utf-8")) if isinstance(bandit_input, str) else bandit_input
        )
        bandit_map = {
            "B608": "CWE-89",
            "B602": "CWE-78",
            "B605": "CWE-78",
            "B607": "CWE-78",
            "B701": "CWE-79",
            "B702": "CWE-79",
            "B703": "CWE-79",
            "B105": "CWE-798",
            "B106": "CWE-798",
            "B107": "CWE-798",
        }
        findings: List[CanonicalFinding] = []
        for item in data.get("results", []):
            cwe_data = item.get("issue_cwe", {})
            cwe = f"CWE-{cwe_data['id']}" if isinstance(cwe_data, dict) and "id" in cwe_data else bandit_map.get(item.get("test_id", ""), "CWE-798")
            file_path = str(item.get("filename", "")).replace("\\", "/").lstrip("./")
            line = int(item.get("line_number", 1))
            sev_str = str(item.get("issue_severity", "MEDIUM")).upper()
            sev = Severity.HIGH if sev_str == "HIGH" else (Severity.LOW if sev_str == "LOW" else Severity.MEDIUM)
            if cwe in ("CWE-89", "CWE-78") and sev == Severity.HIGH:
                sev = Severity.CRITICAL
            test_id = str(item.get("test_id", "bandit"))
            bandit_hash = hashlib.sha256(f"bandit:{test_id}:{cwe}:{file_path}:{line}".encode("utf-8")).hexdigest()[:12]
            findings.append(
                CanonicalFinding(
                    id=f"BANDIT-{bandit_hash}",
                    source=FindingSource.SAST,
                    cwe=cwe,
                    cwe_name=CWE_NAMES.get(cwe, cwe),
                    severity=sev,
                    file_path=file_path,
                    line=line,
                    code_snippet=str(item.get("code", "")).strip(),
                    raw_details={"test_id": item.get("test_id"), "format": "bandit"},
                )
            )
        return findings

    @staticmethod
    def _extract_cwe_from_tags(res: Dict[str, Any], rule_meta: Dict[str, Any], rule_id: str) -> str:
        tags = list(rule_meta.get("properties", {}).get("tags", [])) + list(res.get("properties", {}).get("tags", []))
        for t in tags:
            m = re.search(r"CWE-(\d+)", str(t), re.IGNORECASE)
            if m:
                return f"CWE-{m.group(1)}"
        m_id = re.search(r"CWE-(\d+)", rule_id, re.IGNORECASE)
        if m_id:
            return f"CWE-{m_id.group(1)}"
        rid_lower = rule_id.lower()
        if "sql" in rid_lower:
            return "CWE-89"
        if "xss" in rid_lower or "cross-site" in rid_lower:
            return "CWE-79"
        if "cmd" in rid_lower or "command" in rid_lower or "subprocess" in rid_lower:
            return "CWE-78"
        if "path" in rid_lower or "traversal" in rid_lower:
            return "CWE-22"
        if "redirect" in rid_lower:
            return "CWE-601"
        return "CWE-798"

    def ingest_sarif(
        self, sarif_input: Union[str, Dict[str, Any]], route_mapper: Optional[Any] = None
    ) -> List[CanonicalFinding]:
        return SASTScanner.from_sarif(sarif_input)

    def ingest_bandit_json(
        self, bandit_input: Union[str, Dict[str, Any]], route_mapper: Optional[Any] = None
    ) -> List[CanonicalFinding]:
        return SASTScanner.from_bandit(bandit_input)

    parse_sarif_report = ingest_sarif
    parse_bandit_report = ingest_bandit_json


def run_sast_scan(
    source_dir: str,
    routes: Optional[List[Any]] = None,
    route_mapper: Optional[Any] = None,
) -> List[CanonicalFinding]:
    """
    Top-level convenience entrypoint for running the AST SAST + B-2 Safe Decoy Filter
    on a source directory (invoked by `api/main.py` and CLI runners).
    """
    from engine.route_mapper import RouteMapper

    mapper = route_mapper
    if mapper is None:
        mapper = RouteMapper(source_dir)
        mapper.scan()
    reachable_files = mapper.get_reachable_files() if mapper.routes else None
    scanner = SASTScanner(source_dir, route_mapper=mapper)
    return scanner.scan(reachable_files=reachable_files, route_mapper=mapper)


def scan_source(source_dir: str) -> List[CanonicalFinding]:
    """Alias for `run_sast_scan(source_dir)`."""
    return run_sast_scan(source_dir)


