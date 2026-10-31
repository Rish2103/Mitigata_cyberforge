"""
AST-based Route Mapper (FR-4) + Polyglot Express Adapter (B-7).
Parses:
- Python: Flask (@app.route, Blueprint, add_url_rule), FastAPI (@app.get, APIRouter), Django (path, re_path)
- Node.js / Express (B-7): app.get/post/put/delete/patch, router.get/post, app.use('/prefix', router)

Extracts:
- URL patterns and normalizes them to regex matchers
- HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
- Controller handler functions with exact start_line and end_line
- Handler parameters (from function signature and request parameter accesses)
- Multi-hop (up to 3 hops) helper function call graph across files
- Function-level and file-level reachability for B-2 dead-code suppression
"""

import ast
import os
import re
from typing import List, Dict, Optional, Set, Tuple
from core.schemas import CalledFunction, RouteEntry


def _normalize_route_pattern_to_regex(pattern: str) -> str:
    """
    Converts framework route patterns like:
      - Flask: /api/orders/<id> or /api/orders/<int:order_id> or /files/<path:subpath>
      - FastAPI: /api/orders/{order_id} or /files/{file_path:path}
      - Django: orders/<int:id>/ or ^orders/(?P<id>[0-9]+)/$
      - Express (B-7): /api/orders/:id or /files/:subpath*
    into a standard regex pattern anchored with ^ and $.
    """
    clean = pattern.strip()
    # If already a Django raw regex starting with ^
    if clean.startswith("^"):
        clean_regex = clean.rstrip("$").rstrip("/")
        if not clean_regex.startswith("^/"):
            clean_regex = "^/" + clean_regex.lstrip("^").lstrip("/")
        return f"{clean_regex}/?$"

    if not clean.startswith("/"):
        clean = "/" + clean
    clean_no_trail = clean.rstrip("/")
    if not clean_no_trail:
        clean_no_trail = "/"

    # 1. Flask / Django converter patterns: <converter:name> or <name>
    def _flask_param(match):
        conv, name = match.group(1), match.group(2)
        if conv == "path":
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"

    regex = re.sub(r"<(?:(\w+):)?(\w+)>", _flask_param, clean_no_trail)

    # 2. FastAPI style: {param} or {param:path} or {param:int}
    def _fastapi_param(match):
        name = match.group(1)
        conv = match.group(2) if match.group(2) else ""
        if conv == "path":
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"

    regex = re.sub(r"\{(\w+)(?::(\w+))?\}", _fastapi_param, regex)

    # 3. Express style (B-7): :param or :param*
    def _express_param(match):
        name = match.group(1)
        wildcard = match.group(2)
        if wildcard:
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"

    regex = re.sub(r":([a-zA-Z_]\w*)(\*)?", _express_param, regex)

    return f"^{regex}/?$"


class FunctionVisitor(ast.NodeVisitor):
    """
    Inspects a Python function AST node to extract parameter accesses and called helper functions.
    """

    def __init__(self, func_node: ast.AST):
        self.func_node = func_node
        self.parameters: Set[str] = set()
        self.called_funcs: Set[str] = set()

        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in func_node.args.args:
                if arg.arg not in ("self", "cls", "request", "req", "db", "session"):
                    self.parameters.add(arg.arg)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            self.called_funcs.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.called_funcs.add(node.func.attr)

        # Detect request parameter accesses:
        # Flask/Django: request.args.get('param'), request.form.get('param'),
        # request.values.get('param'), request.json.get('param'), request.GET.get('param'), request.POST.get('param')
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                # Check if receiver is request.<bag> or similar
                self.parameters.add(node.args[0].value)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Detect request.args['param'], request.form['param'], request.GET['param'], request.POST['param'], data['param']
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if isinstance(node.value, ast.Attribute):
                if node.value.attr in ("args", "form", "values", "json", "headers", "cookies", "GET", "POST", "query_params"):
                    self.parameters.add(node.slice.value)
        self.generic_visit(node)


class RouteExtractor(ast.NodeVisitor):
    """
    Extracts Flask, FastAPI, and Django routes from a Python AST.
    """

    def __init__(
        self,
        file_path: str,
        rel_path: str,
        global_prefixes: Optional[Dict[str, str]] = None,
    ):
        self.file_path = file_path
        self.rel_path = rel_path.replace("\\", "/")
        self.routes: List[RouteEntry] = []
        self.blueprint_prefixes: Dict[str, str] = dict(global_prefixes or {})
        self.django_Pending_routes: List[Tuple[str, str, str]] = []  # (path, target_func_name, rel_path)

    def visit_Assign(self, node: ast.Assign):
        # Detect Flask Blueprint or FastAPI APIRouter definitions:
        # bp = Blueprint('orders', __name__, url_prefix='/api')
        # router = APIRouter(prefix='/api')
        if isinstance(node.value, ast.Call):
            func_name = ""
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr

            if func_name in ("Blueprint", "APIRouter"):
                prefix = ""
                for kw in node.value.keywords:
                    if kw.arg in ("url_prefix", "prefix") and isinstance(kw.value, ast.Constant):
                        prefix = str(kw.value.value).rstrip("/")
                for target in node.targets:
                    if isinstance(target, ast.Name) and prefix:
                        self.blueprint_prefixes[target.id] = prefix

        # Detect Django urlpatterns = [path('orders/<int:id>/', views.get_order), ...]
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "urlpatterns":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        self._extract_django_urlpattern(elt)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Detect Flask app.add_url_rule('/orders', 'orders', get_orders, methods=['GET'])
        if isinstance(node.func, ast.Attribute) and node.func.attr == "add_url_rule":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                path = node.args[0].value
                view_func = None
                if len(node.args) >= 3 and isinstance(node.args[2], ast.Name):
                    view_func = node.args[2].id
                for kw in node.keywords:
                    if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                        view_func = kw.value.id
                if view_func:
                    self.django_Pending_routes.append((path, view_func, "flask"))
        self.generic_visit(node)

    def _extract_django_urlpattern(self, elt: ast.AST):
        if not isinstance(elt, ast.Call):
            return
        func_name = ""
        if isinstance(elt.func, ast.Name):
            func_name = elt.func.id
        elif isinstance(elt.func, ast.Attribute):
            func_name = elt.func.attr

        if func_name in ("path", "re_path", "url") and len(elt.args) >= 2:
            if isinstance(elt.args[0], ast.Constant) and isinstance(elt.args[0].value, str):
                raw_path = elt.args[0].value
                view_arg = elt.args[1]
                target_func = ""
                if isinstance(view_arg, ast.Name):
                    target_func = view_arg.id
                elif isinstance(view_arg, ast.Attribute):
                    target_func = view_arg.attr
                if target_func:
                    self.django_Pending_routes.append((raw_path, target_func, "django"))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node):
        for decorator in node.decorator_list:
            route_info = self._parse_decorator(decorator)
            if route_info:
                path_pattern, methods, framework = route_info
                visitor = FunctionVisitor(node)
                visitor.visit(node)
                end_line = getattr(node, "end_lineno", node.lineno)

                for m in methods:
                    self.routes.append(
                        RouteEntry(
                            method=m.upper(),
                            path_pattern=path_pattern,
                            regex_pattern=_normalize_route_pattern_to_regex(path_pattern),
                            file_path=self.rel_path,
                            func_name=node.name,
                            start_line=node.lineno,
                            end_line=end_line,
                            parameters=sorted(list(visitor.parameters)),
                            called_funcs=sorted(list(visitor.called_funcs)),
                            framework=framework,
                        )
                    )

    def _parse_decorator(self, dec) -> Optional[Tuple[str, List[str], str]]:
        if not isinstance(dec, ast.Call):
            return None

        call = dec
        func = call.func

        attr_name = ""
        obj_name = ""
        if isinstance(func, ast.Attribute):
            attr_name = func.attr
            if isinstance(func.value, ast.Name):
                obj_name = func.value.id
        elif isinstance(func, ast.Name):
            attr_name = func.id

        path = ""
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            path = call.args[0].value
        else:
            for kw in call.keywords:
                if kw.arg in ("rule", "path") and isinstance(kw.value, ast.Constant):
                    path = str(kw.value.value)

        if not path:
            return None

        # Apply Blueprint / APIRouter prefix if applicable
        if obj_name in self.blueprint_prefixes and self.blueprint_prefixes[obj_name]:
            bp_prefix = self.blueprint_prefixes[obj_name].rstrip("/")
            if not path.startswith(bp_prefix + "/") and path != bp_prefix:
                path = f"{bp_prefix}/{path.lstrip('/')}"

        methods = []
        framework = "flask"

        if attr_name.lower() in ("get", "post", "put", "delete", "patch"):
            methods = [attr_name.upper()]
            framework = "fastapi" if "router" in obj_name.lower() or "app" in obj_name.lower() else "flask"
        elif attr_name in ("route", "api_route"):
            for kw in call.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            methods.append(elt.value.upper())
            if not methods:
                methods = ["GET"]
            framework = "fastapi" if attr_name == "api_route" else "flask"

        if methods:
            return (path, methods, framework)
        return None


class RouteMapper:
    """
    Engine that traverses a source directory, extracts all routes (Python & Node.js/Express),
    builds a multi-hop call graph, and resolves live URL/method requests to RouteEntries.
    """

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.routes: List[RouteEntry] = []
        self._compiled_matchers: List[Tuple[RouteEntry, re.Pattern]] = []
        self.call_graph: Dict[str, Set[str]] = {}  # func_name -> set of called_funcs
        self.func_to_file_lines: Dict[str, Tuple[str, int, int]] = {}  # func_name -> (file, start, end)
        # Multi-definition safe store: func_name -> list of (file, start, end, called_funcs, parameters)
        self.func_defs: Dict[str, List[Tuple[str, int, int, Set[str], Set[str]]]] = {}
        self._global_router_prefixes: Dict[str, str] = {}
        self._pending_view_routes: List[Tuple[str, str, str]] = []

    def scan(self) -> List[RouteEntry]:
        self.routes = []
        self._compiled_matchers = []
        self.call_graph = {}
        self.func_to_file_lines = {}
        self.func_defs = {}
        self._global_router_prefixes = {}
        self._pending_view_routes = []

        py_files: List[Tuple[str, str]] = []
        js_files: List[Tuple[str, str]] = []

        for dirpath, _, filenames in os.walk(self.root_dir):
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules", "dist", "build") for p in parts):
                continue

            for fname in sorted(filenames):
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")
                if fname.endswith(".py"):
                    py_files.append((full_path, rel_path))
                elif fname.endswith((".js", ".ts")) and not fname.endswith(".min.js"):
                    js_files.append((full_path, rel_path))

        # Pass 1 on Python files: collect cross-file Blueprint / APIRouter prefixes & function defs
        for full_path, rel_path in py_files:
            self._precollect_python_prefixes(full_path, rel_path)

        # Pass 2 on Python files: extract routes and call graphs
        for full_path, rel_path in py_files:
            self._parse_python_file(full_path, rel_path)

        # Resolve Django path() / Flask add_url_rule() deferred view functions
        self._resolve_pending_view_routes()

        # Pass 3 on JS/TS files (Bonus B-7: Node.js / Express support)
        if js_files:
            self._scan_express_files(js_files)

        # Populate called_func_details and compile regex matchers
        for r in self.routes:
            expanded = self._expand_called_functions(set(r.called_funcs), max_hops=3)
            details = list(r.called_func_details)
            seen_defs = {(d.name, d.file, d.start_line) for d in details}
            for h_name in sorted(expanded):
                for h_file, h_start, h_end, _, _ in self.func_defs.get(h_name, []):
                    key = (h_name, h_file, h_start)
                    if key not in seen_defs:
                        seen_defs.add(key)
                        details.append(
                            CalledFunction(
                                name=h_name,
                                file=h_file,
                                start_line=h_start,
                                end_line=h_end,
                            )
                        )
            r.called_func_details = details

            pat = r.regex_pattern or _normalize_route_pattern_to_regex(r.path_pattern)
            try:
                comp = re.compile(pat, re.IGNORECASE)
                self._compiled_matchers.append((r, comp))
            except Exception:
                pass

        return self.routes

    def _precollect_python_prefixes(self, full_path: str, rel_path: str):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=rel_path)

            for node in ast.walk(tree):
                # 1. bp = Blueprint('orders', __name__, url_prefix='/api')
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    func_name = ""
                    if isinstance(node.value.func, ast.Name):
                        func_name = node.value.func.id
                    elif isinstance(node.value.func, ast.Attribute):
                        func_name = node.value.func.attr
                    if func_name in ("Blueprint", "APIRouter"):
                        for kw in node.value.keywords:
                            if kw.arg in ("url_prefix", "prefix") and isinstance(kw.value, ast.Constant):
                                prefix = str(kw.value.value).rstrip("/")
                                for target in node.targets:
                                    if isinstance(target, ast.Name) and prefix:
                                        self._global_router_prefixes[target.id] = prefix

                # 2. app.register_blueprint(orders_bp, url_prefix='/api')
                #    app.include_router(orders_router, prefix='/api')
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("register_blueprint", "include_router") and node.args:
                        router_arg = node.args[0]
                        router_var = router_arg.id if isinstance(router_arg, ast.Name) else ""
                        if router_var:
                            for kw in node.keywords:
                                if kw.arg in ("url_prefix", "prefix") and isinstance(kw.value, ast.Constant):
                                    prefix = str(kw.value.value).rstrip("/")
                                    if prefix:
                                        self._global_router_prefixes[router_var] = prefix
        except Exception:
            pass

    def _parse_python_file(self, full_path: str, rel_path: str):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=rel_path)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end_line = getattr(node, "end_lineno", node.lineno)
                    vis = FunctionVisitor(node)
                    vis.visit(node)
                    self.func_to_file_lines[node.name] = (rel_path, node.lineno, end_line)
                    self.call_graph.setdefault(node.name, set()).update(vis.called_funcs)
                    self.func_defs.setdefault(node.name, []).append(
                        (rel_path, node.lineno, end_line, set(vis.called_funcs), set(vis.parameters))
                    )

            extractor = RouteExtractor(full_path, rel_path, global_prefixes=self._global_router_prefixes)
            extractor.visit(tree)
            self.routes.extend(extractor.routes)
            self._pending_view_routes.extend(extractor.django_Pending_routes)
        except Exception:
            pass

    def _resolve_pending_view_routes(self):
        for raw_path, target_func, framework in self._pending_view_routes:
            defs = self.func_defs.get(target_func, [])
            if defs:
                rel_path, start_line, end_line, called_funcs, params = defs[0]
                norm_path = raw_path if raw_path.startswith("/") or raw_path.startswith("^") else "/" + raw_path
                # Extract path converter params like <int:id>
                for m in re.finditer(r"<(?:\w+:)?(\w+)>", norm_path):
                    params.add(m.group(1))
                for m in re.finditer(r"\(\?P<(\w+)>", norm_path):
                    params.add(m.group(1))

                for method in ("GET", "POST"):
                    self.routes.append(
                        RouteEntry(
                            method=method,
                            path_pattern=norm_path,
                            regex_pattern=_normalize_route_pattern_to_regex(norm_path),
                            file_path=rel_path,
                            func_name=target_func,
                            start_line=start_line,
                            end_line=end_line,
                            parameters=sorted(list(params)),
                            called_funcs=sorted(list(called_funcs)),
                            framework=framework,
                        )
                    )

    # -------------------------------------------------------------------------
    # Bonus B-7: Node.js / Express Route & Call Graph Parser
    # -------------------------------------------------------------------------
    def _scan_express_files(self, js_files: List[Tuple[str, str]]):
        router_prefixes: Dict[str, str] = {}

        # First pass: collect app.use('/prefix', routerName) and helper functions
        for full_path, rel_path in js_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                lines = content.splitlines()

                # Detect app.use('/api', apiRouter)
                for m in re.finditer(r"""\b(?:app|router)\s*\.\s*use\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z_]\w*)""", content):
                    router_prefixes[m.group(2)] = m.group(1).rstrip("/")

                # Detect named JS functions: function myHelper(a, b) { ... } or const myHelper = (a, b) => { ... }
                func_pattern = re.compile(
                    r"""(?:(?:async\s+)?function\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)|(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>)\s*\{"""
                )
                for idx, line_str in enumerate(lines):
                    fm = func_pattern.search(line_str)
                    if fm:
                        fname = fm.group(1) or fm.group(3)
                        raw_args = fm.group(2) if fm.group(1) else fm.group(4)
                        start_line = idx + 1
                        end_line = self._find_js_block_end(lines, idx)
                        block_text = "\n".join(lines[idx:end_line])
                        params = self._extract_js_params(block_text, raw_args)
                        called = self._extract_js_calls(block_text, exclude_name=fname)
                        self.func_to_file_lines[fname] = (rel_path, start_line, end_line)
                        self.call_graph.setdefault(fname, set()).update(called)
                        self.func_defs.setdefault(fname, []).append((rel_path, start_line, end_line, called, params))
            except Exception:
                pass

        # Second pass: extract Express routes
        route_regex = re.compile(
            r"""\b([a-zA-Z_]\w*)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^\n]+)"""
        )
        for full_path, rel_path in js_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                lines = content.splitlines()

                for idx, line_str in enumerate(lines):
                    rm = route_regex.search(line_str)
                    if not rm:
                        continue
                    obj_name, method_str, raw_path, handler_part = (
                        rm.group(1),
                        rm.group(2).upper(),
                        rm.group(3),
                        rm.group(4).strip(),
                    )
                    prefix = router_prefixes.get(obj_name, "")
                    full_route_path = f"{prefix}/{raw_path.lstrip('/')}" if prefix else raw_path
                    if not full_route_path.startswith("/"):
                        full_route_path = "/" + full_route_path

                    start_line = idx + 1
                    end_line = self._find_js_block_end(lines, idx)
                    block_text = "\n".join(lines[idx:end_line])

                    # Check if handler_part references a named function vs inline callback
                    named_match = re.match(r"^([a-zA-Z_]\w*)\s*\)", handler_part)
                    if named_match and named_match.group(1) in self.func_defs:
                        target_fn = named_match.group(1)
                        fn_file, fn_start, fn_end, fn_called, fn_params = self.func_defs[target_fn][0]
                        for pm in re.finditer(r":([a-zA-Z_]\w*)", full_route_path):
                            fn_params.add(pm.group(1))
                        self.routes.append(
                            RouteEntry(
                                method=method_str,
                                path_pattern=full_route_path,
                                regex_pattern=_normalize_route_pattern_to_regex(full_route_path),
                                file_path=fn_file,
                                func_name=target_fn,
                                start_line=fn_start,
                                end_line=fn_end,
                                parameters=sorted(list(fn_params)),
                                called_funcs=sorted(list(fn_called)),
                                framework="express",
                            )
                        )
                    else:
                        func_name = f"express_{method_str.lower()}_{re.sub(r'[^a-zA-Z0-9_]', '_', full_route_path).strip('_') or 'root'}"
                        params = self._extract_js_params(block_text, "")
                        for pm in re.finditer(r":([a-zA-Z_]\w*)", full_route_path):
                            params.add(pm.group(1))
                        called = self._extract_js_calls(block_text)
                        self.func_to_file_lines[func_name] = (rel_path, start_line, end_line)
                        self.call_graph.setdefault(func_name, set()).update(called)
                        self.func_defs.setdefault(func_name, []).append((rel_path, start_line, end_line, called, params))
                        self.routes.append(
                            RouteEntry(
                                method=method_str,
                                path_pattern=full_route_path,
                                regex_pattern=_normalize_route_pattern_to_regex(full_route_path),
                                file_path=rel_path,
                                func_name=func_name,
                                start_line=start_line,
                                end_line=end_line,
                                parameters=sorted(list(params)),
                                called_funcs=sorted(list(called)),
                                framework="express",
                            )
                        )
            except Exception:
                pass

    @staticmethod
    def _find_js_block_end(lines: List[str], start_idx: int) -> int:
        brace_depth = 0
        opened = False
        for i in range(start_idx, len(lines)):
            for ch in lines[i]:
                if ch == "{":
                    brace_depth += 1
                    opened = True
                elif ch == "}":
                    brace_depth -= 1
                    if opened and brace_depth <= 0:
                        return i + 1
        return min(len(lines), start_idx + 15)

    @staticmethod
    def _extract_js_params(block_text: str, raw_args: str) -> Set[str]:
        params: Set[str] = set()
        # req.query.id, req.body.username, req.params.orderId
        for m in re.finditer(r"\breq\s*\.\s*(?:query|body|params)\s*\.\s*([a-zA-Z_]\w*)", block_text):
            params.add(m.group(1))
        # req.query['id'], req.body['id']
        for m in re.finditer(r"""\breq\s*\.\s*(?:query|body|params|headers)\s*\[\s*['"]([^'"]+)['"]\s*\]""", block_text):
            params.add(m.group(1))
        # Destructuring: const { id, sort } = req.query
        for m in re.finditer(r"\{\s*([^}]+)\}\s*=\s*req\s*\.\s*(?:query|body|params)", block_text):
            for part in m.group(1).split(","):
                clean_p = part.split(":")[0].split("=")[0].strip()
                if clean_p and re.match(r"^[a-zA-Z_]\w*$", clean_p):
                    params.add(clean_p)
        for arg in (raw_args or "").split(","):
            a = arg.strip()
            if a and a not in ("req", "res", "next", "err"):
                params.add(a)
        return params

    @staticmethod
    def _extract_js_calls(block_text: str, exclude_name: str = "") -> Set[str]:
        called: Set[str] = set()
        for m in re.finditer(r"\b([a-zA-Z_]\w*)\s*\(", block_text):
            name = m.group(1)
            if name not in ("if", "for", "while", "switch", "catch", "function", "return", "require", exclude_name):
                called.add(name)
        return called

    # -------------------------------------------------------------------------
    # Route Resolution & Multi-Hop Call Graph Queries
    # -------------------------------------------------------------------------
    def match_url(self, method: str, url_path: str) -> Optional[RouteEntry]:
        """
        Given an HTTP method (e.g. GET) and URL or path (e.g. http://localhost:5000/api/orders/42?id=1 or /api/orders/42),
        matches against the AST route map.
        """
        raw = url_path.strip()
        if "://" in raw:
            from urllib.parse import urlparse
            parsed = urlparse(raw)
            clean_path = parsed.path or "/"
        else:
            clean_path = raw.split("?")[0].strip()

        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        norm_method = (method or "GET").upper()

        # 1. Exact method + static/specific path match first
        for route, comp in self._compiled_matchers:
            if route.method == norm_method and comp.match(clean_path):
                return route

        # 2. Fallback: match path if method differs (e.g. HEAD/GET or unspecified)
        for route, comp in self._compiled_matchers:
            if comp.match(clean_path):
                return route

        return None

    def _expand_called_functions(self, initial_funcs: Set[str], max_hops: int = 3) -> Set[str]:
        """
        Expands called helper functions up to `max_hops` across the project call graph.
        """
        visited: Set[str] = set(initial_funcs)
        frontier: Set[str] = set(initial_funcs)
        for _ in range(max(0, max_hops - 1)):
            next_frontier: Set[str] = set()
            for fn in frontier:
                for callee in self.call_graph.get(fn, set()):
                    if callee not in visited:
                        visited.add(callee)
                        next_frontier.add(callee)
            if not next_frontier:
                break
            frontier = next_frontier
        return visited

    def is_line_in_route(self, file_path: str, line: int, route: RouteEntry, max_hops: int = 3) -> bool:
        """
        Checks whether a given file_path and line number falls within the route's handler
        or any 1-hop / 2-hop / 3-hop helper function called by that handler.
        """
        norm_target_file = file_path.replace("\\", "/").lstrip("./")
        norm_route_file = route.file_path.replace("\\", "/").lstrip("./")

        # 1. Direct handler match
        if norm_target_file == norm_route_file:
            if route.start_line <= line <= route.end_line:
                return True

        # 2. Check multi-hop called helpers across all definitions
        expanded_helpers = self._expand_called_functions(set(route.called_funcs), max_hops=max_hops)

        for helper_name in expanded_helpers:
            # Check multi-def store first
            for h_file, h_start, h_end, _, _ in self.func_defs.get(helper_name, []):
                if h_file.replace("\\", "/").lstrip("./") == norm_target_file:
                    if h_start <= line <= h_end:
                        return True
            # Fallback to single-def dict
            if helper_name in self.func_to_file_lines:
                h_file, h_start, h_end = self.func_to_file_lines[helper_name]
                if h_file.replace("\\", "/").lstrip("./") == norm_target_file:
                    if h_start <= line <= h_end:
                        return True

        return False

    def get_reachable_files(self, max_hops: int = 3) -> Set[str]:
        """
        Returns the set of all relative file paths reachable from at least one registered route.
        """
        reachable: Set[str] = set()
        for r in self.routes:
            reachable.add(r.file_path.replace("\\", "/").lstrip("./"))
            for helper_name in self._expand_called_functions(set(r.called_funcs), max_hops=max_hops):
                for h_file, _, _, _, _ in self.func_defs.get(helper_name, []):
                    reachable.add(h_file.replace("\\", "/").lstrip("./"))
                if helper_name in self.func_to_file_lines:
                    h_file, _, _ = self.func_to_file_lines[helper_name]
                    reachable.add(h_file.replace("\\", "/").lstrip("./"))
        return reachable

    def is_line_reachable(self, file_path: str, line: int, max_hops: int = 3) -> bool:
        """
        Checks whether (file_path, line) is reachable from ANY route in the application.
        Used by B-2 Decoy Filter to suppress dead functions even when they reside inside an active file.
        """
        if not self.routes:
            return True  # If no routes exist in snippet/unit test, assume code is under test

        norm_target = file_path.replace("\\", "/").lstrip("./")
        for r in self.routes:
            if self.is_line_in_route(norm_target, line, r, max_hops=max_hops):
                return True

        # Check if the line is outside any function definition (module-level code in a reachable file)
        in_any_func = False
        for defs in self.func_defs.values():
            for f_file, f_start, f_end, _, _ in defs:
                if f_file.replace("\\", "/").lstrip("./") == norm_target and f_start <= line <= f_end:
                    in_any_func = True
                    break
        if not in_any_func and norm_target in self.get_reachable_files(max_hops=max_hops):
            return True

        return False
