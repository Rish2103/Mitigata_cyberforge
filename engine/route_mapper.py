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
from typing import List, Dict, Optional, Pattern, Set, Tuple
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
    clean_no_trail = clean.rstrip("$").rstrip("/")
    if not clean_no_trail:
        clean_no_trail = "/"

    # 1. Flask / Django converter patterns: <converter:name> or <name>
    def _flask_param(match):
        conv, name = match.group(1), match.group(2)
        if conv == "path":
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"

    regex = re.sub(r"(?<!\?P)<(?:(\w+):)?(\w+)>", _flask_param, clean_no_trail)

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
    Inspects a Python function AST node to extract parameter accesses, parameter sources,
    and called helper functions.
    """

    def __init__(self, func_node: ast.AST, pydantic_models: Optional[Dict[str, List[str]]] = None):
        self.func_node = func_node
        self.parameters: Set[str] = set()
        self.param_sources: Dict[str, str] = {}
        self.called_funcs: Set[str] = set()
        self._json_vars: Set[str] = {"data", "body", "payload", "json_data", "req_json"}
        self._pydantic_models: Dict[str, List[str]] = pydantic_models or {}

        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            all_args = list(func_node.args.args)
            defaults = list(func_node.args.defaults)
            num_no_default = len(all_args) - len(defaults)

            for idx, arg in enumerate(all_args):
                if arg.arg in ("self", "cls", "request", "req", "db", "session", "background_tasks"):
                    continue

                default_node = defaults[idx - num_no_default] if idx >= num_no_default else None
                if isinstance(default_node, ast.Call):
                    def_fn = ""
                    if isinstance(default_node.func, ast.Name):
                        def_fn = default_node.func.id
                    elif isinstance(default_node.func, ast.Attribute):
                        def_fn = default_node.func.attr

                    # FastAPI Depends(helper_fn) / Security(helper_fn): register helper in call graph, skip as HTTP param
                    if def_fn in ("Depends", "Security"):
                        if default_node.args:
                            dep_target = default_node.args[0]
                            if isinstance(dep_target, ast.Name):
                                self.called_funcs.add(dep_target.id)
                            elif isinstance(dep_target, ast.Attribute):
                                self.called_funcs.add(dep_target.attr)
                        continue
                    elif def_fn == "Query":
                        self.param_sources[arg.arg] = "query"
                    elif def_fn == "Path":
                        self.param_sources[arg.arg] = "path"
                    elif def_fn == "Form":
                        self.param_sources[arg.arg] = "form"
                    elif def_fn == "Body":
                        self.param_sources[arg.arg] = "json"

                # If parameter has a Pydantic model type annotation, extract its fields as JSON body params
                ann_name = ""
                if isinstance(arg.annotation, ast.Name):
                    ann_name = arg.annotation.id
                elif isinstance(arg.annotation, ast.Attribute):
                    ann_name = arg.annotation.attr
                if ann_name and ann_name in self._pydantic_models:
                    self._json_vars.add(arg.arg)
                    for field_name in self._pydantic_models[ann_name]:
                        self.parameters.add(field_name)
                        self.param_sources.setdefault(field_name, "json")
                else:
                    self.parameters.add(arg.arg)

    def visit_Assign(self, node: ast.Assign):
        # Track variables assigned from request.get_json() or request.json
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
            if node.value.func.attr == "get_json":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._json_vars.add(target.id)
        elif isinstance(node.value, ast.Attribute) and node.value.attr in ("json", "body", "data"):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._json_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            self.called_funcs.add(node.func.id)
            if node.func.id in ("Depends", "Security") and node.args:
                dep_arg = node.args[0]
                if isinstance(dep_arg, ast.Name):
                    self.called_funcs.add(dep_arg.id)
                elif isinstance(dep_arg, ast.Attribute):
                    self.called_funcs.add(dep_arg.attr)
        elif isinstance(node.func, ast.Attribute):
            self.called_funcs.add(node.func.attr)

        # Detect request parameter accesses:
        # Flask/Django: request.args.get('param'), request.form.get('param'),
        # request.values.get('param'), request.json.get('param'), request.get_json().get('param')
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                param_name = node.args[0].value
                self.parameters.add(param_name)
                receiver = node.func.value
                if isinstance(receiver, ast.Attribute):
                    bag = receiver.attr
                    if bag in ("args", "GET", "query_params"):
                        self.param_sources[param_name] = "query"
                    elif bag in ("form", "POST", "files"):
                        self.param_sources[param_name] = "form"
                    elif bag == "json":
                        self.param_sources[param_name] = "json"
                elif isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
                    if receiver.func.attr == "get_json":
                        self.param_sources[param_name] = "json"
                elif isinstance(receiver, ast.Name) and receiver.id in self._json_vars:
                    self.param_sources[param_name] = "json"

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Detect request.args['param'], request.form['param'], request.json['param'], data['param']
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            param_name = node.slice.value
            if isinstance(node.value, ast.Attribute):
                bag = node.value.attr
                if bag in ("args", "form", "values", "json", "headers", "cookies", "GET", "POST", "query_params"):
                    self.parameters.add(param_name)
                    if bag in ("args", "GET", "query_params"):
                        self.param_sources[param_name] = "query"
                    elif bag in ("form", "POST"):
                        self.param_sources[param_name] = "form"
                    elif bag == "json":
                        self.param_sources[param_name] = "json"
            elif isinstance(node.value, ast.Name) and node.value.id in self._json_vars:
                self.parameters.add(param_name)
                self.param_sources.setdefault(param_name, "json")
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
        pydantic_models: Optional[Dict[str, List[str]]] = None,
        django_file_prefix: str = "",
    ):
        self.file_path = file_path
        self.rel_path = rel_path.replace("\\", "/")
        self.routes: List[RouteEntry] = []
        self.blueprint_prefixes: Dict[str, str] = dict(global_prefixes or {})
        self.pydantic_models: Dict[str, List[str]] = pydantic_models or {}
        self.django_file_prefix: str = (django_file_prefix or "").strip()
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
                        # Only set local prefix if a combined global prefix wasn't already precomputed
                        if target.id not in self.blueprint_prefixes:
                            self.blueprint_prefixes[target.id] = prefix

        # Detect Django urlpatterns = [path('orders/<int:id>/', views.get_order), ...]
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "urlpatterns":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        self._extract_django_urlpattern(elt)
                elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    for side in (node.value.left, node.value.right):
                        if isinstance(side, (ast.List, ast.Tuple)):
                            for elt in side.elts:
                                self._extract_django_urlpattern(elt)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name) and node.target.id == "urlpatterns":
            if isinstance(node.value, (ast.List, ast.Tuple)):
                for elt in node.value.elts:
                    self._extract_django_urlpattern(elt)
        self.generic_visit(node)

    @staticmethod
    def _extract_view_target(expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "as_view":
            receiver = expr.func.value
            if isinstance(receiver, ast.Name):
                return f"ClassView:{receiver.id}"
            if isinstance(receiver, ast.Attribute):
                return f"ClassView:{receiver.attr}"
        return None

    def visit_Call(self, node: ast.Call):
        # Detect Flask app.add_url_rule('/orders', 'orders', get_orders, methods=['GET'])
        # or app.add_url_rule('/users', view_func=UserAPI.as_view('user_api'))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "add_url_rule":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                path = node.args[0].value
                if isinstance(node.func.value, ast.Name):
                    bp_name = node.func.value.id
                    if bp_name in self.blueprint_prefixes and self.blueprint_prefixes[bp_name]:
                        bp_prefix = self.blueprint_prefixes[bp_name].rstrip("/")
                        if not path.startswith(bp_prefix + "/") and path != bp_prefix:
                            path = f"{bp_prefix}/{path.lstrip('/')}"
                view_func = None
                if len(node.args) >= 3:
                    view_func = self._extract_view_target(node.args[2])
                explicit_methods: List[str] = []
                for kw in node.keywords:
                    if kw.arg == "view_func":
                        view_func = self._extract_view_target(kw.value) or view_func
                    elif kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                explicit_methods.append(elt.value.upper())
                if view_func:
                    fw_tag = f"flask:{','.join(explicit_methods)}" if explicit_methods else "flask"
                    self.django_Pending_routes.append((path, view_func, fw_tag))
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
                if self.django_file_prefix:
                    clean_prefix = self.django_file_prefix.strip("^$").strip("/")
                    clean_sub = raw_path.lstrip("^").rstrip("$").lstrip("/")
                    if clean_prefix:
                        raw_path = f"/{clean_prefix}/{clean_sub}" if clean_sub else f"/{clean_prefix}/"
                view_arg = elt.args[1]
                target_func = self._extract_view_target(view_arg) or ""
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
                visitor = FunctionVisitor(node, pydantic_models=self.pydantic_models)
                visitor.visit(node)
                end_line = getattr(node, "end_lineno", node.lineno)

                # Extract path parameters from path_pattern and mark them as 'path' source
                params = set(visitor.parameters)
                param_sources = dict(visitor.param_sources)
                for m_conv in re.finditer(r"<(?:\w+:)?(\w+)>", path_pattern):
                    p_name = m_conv.group(1)
                    params.add(p_name)
                    param_sources[p_name] = "path"
                for m_brace in re.finditer(r"\{(\w+)(?::\w+)?\}", path_pattern):
                    p_name = m_brace.group(1)
                    params.add(p_name)
                    param_sources[p_name] = "path"

                for m in methods:
                    default_src = "form" if m.upper() in ("POST", "PUT", "PATCH") else "query"
                    route_param_sources = {
                        p: param_sources.get(p, default_src) for p in sorted(params)
                    }
                    self.routes.append(
                        RouteEntry(
                            method=m.upper(),
                            path_pattern=path_pattern,
                            regex_pattern=_normalize_route_pattern_to_regex(path_pattern),
                            file_path=self.rel_path,
                            func_name=node.name,
                            start_line=node.lineno,
                            end_line=end_line,
                            parameters=sorted(list(params)),
                            param_sources=route_param_sources,
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
        self._router_def_prefixes: Dict[str, str] = {}
        self._router_mount_prefixes: Dict[str, str] = {}
        self._router_def_files: Dict[str, Set[str]] = {}
        self._router_parent_edges: List[Tuple[str, str, str]] = []
        self._django_include_prefixes: Dict[str, str] = {}
        self._django_include_edges: List[Tuple[str, str, str]] = []
        self._pydantic_models: Dict[str, List[str]] = {}
        self._pending_view_routes: List[Tuple[str, str, str]] = []
        self._class_views: Dict[str, List[Tuple[str, str, str, int, int, Set[str], Set[str]]]] = {}
        self._has_scanned_files: bool = False

    @classmethod
    def from_routes(cls, routes: List[RouteEntry], root_dir: str = ".") -> "RouteMapper":
        """
        Constructs a RouteMapper instance from pre-seeded RouteEntry objects
        (e.g. from ScanPipelineRequest.seeded_routes or fallback route lists).
        """
        mapper = cls(root_dir)
        mapper.routes = list(routes or [])
        for r in mapper.routes:
            if r.func_name and r.file_path:
                mapper.func_to_file_lines[r.func_name] = (r.file_path, r.start_line, r.end_line)
                mapper.func_defs.setdefault(r.func_name, []).append(
                    (r.file_path, r.start_line, r.end_line, set(r.called_funcs or []), set(r.parameters or []))
                )
            if r.func_name and r.called_funcs:
                mapper.call_graph.setdefault(r.func_name, set()).update(r.called_funcs)
            for cf in getattr(r, "called_func_details", None) or []:
                if cf.name and cf.file:
                    mapper.func_to_file_lines[cf.name] = (cf.file, cf.start_line, cf.end_line)
                    mapper.func_defs.setdefault(cf.name, []).append(
                        (cf.file, cf.start_line, cf.end_line, set(), set())
                    )
            pat = r.regex_pattern or _normalize_route_pattern_to_regex(r.path_pattern)
            try:
                comp = re.compile(pat, re.IGNORECASE)
                mapper._compiled_matchers.append((r, comp))
            except Exception:
                pass
        return mapper

    def scan_directory(self) -> List[RouteEntry]:
        """Alias for `scan()` used by CLI and integration runners."""
        return self.scan()

    @staticmethod
    def _join_prefixes(*parts: str) -> str:
        segments: List[str] = []
        for p in parts:
            clean = (p or "").strip().strip("/")
            if clean:
                if not segments or not clean.startswith(segments[-1] + "/"):
                    segments.append(clean)
        return "/" + "/".join(segments) if segments else ""

    def scan(self) -> List[RouteEntry]:
        self._has_scanned_files = True
        self.routes = []
        self._compiled_matchers = []
        self.call_graph = {}
        self.func_to_file_lines = {}
        self.func_defs = {}
        self._global_router_prefixes = {}
        self._router_def_prefixes = {}
        self._router_mount_prefixes = {}
        self._router_def_files = {}
        self._router_parent_edges = []
        self._django_include_prefixes = {}
        self._django_include_edges = []
        self._pydantic_models = {}
        self._pending_view_routes = []
        self._class_views = {}

        py_files: List[Tuple[str, str]] = []
        js_files: List[Tuple[str, str]] = []
        java_files: List[Tuple[str, str]] = []
        polyglot_files: List[Tuple[str, str]] = []
        polyglot_exts = (
            ".go", ".php", ".cs", ".rb", ".kt", ".rs",
            ".scala", ".swift", ".ex", ".exs", ".cpp", ".c", ".cc",
        )

        skip_dirs = {
            "venv", ".venv", "__pycache__", "env", "node_modules", "dist", "build",
            "target", "out", "bin", "gradle", ".gradle", ".mvn", ".git", ".idea",
            ".vscode", "vendor", "coverage", "logs", ".tox", ".mypy_cache", ".pytest_cache",
        }

        if os.path.isfile(self.root_dir):
            fname = os.path.basename(self.root_dir)
            if fname.endswith(".py"):
                py_files.append((self.root_dir, fname))
            elif fname.endswith((".js", ".ts")) and not fname.endswith(".min.js"):
                js_files.append((self.root_dir, fname))
            elif fname.endswith(".java"):
                java_files.append((self.root_dir, fname))
            elif fname.endswith(polyglot_exts):
                polyglot_files.append((self.root_dir, fname))
        else:
            for dirpath, dirnames, filenames in os.walk(self.root_dir):
                # Prune build/artifact/vendor directories in-place so os.walk never descends into them
                dirnames[:] = [
                    d for d in sorted(dirnames)
                    if not d.startswith(".") and d.lower() not in skip_dirs
                ]
                rel_dir = os.path.relpath(dirpath, self.root_dir)
                if rel_dir != ".":
                    rel_parts = rel_dir.split(os.sep)
                    if any(p.startswith(".") or p.lower() in skip_dirs for p in rel_parts):
                        continue

                for fname in sorted(filenames):
                    full_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")
                    if fname.endswith(".py"):
                        py_files.append((full_path, rel_path))
                    elif fname.endswith((".js", ".ts")) and not fname.endswith(".min.js"):
                        js_files.append((full_path, rel_path))
                    elif fname.endswith(".java"):
                        java_files.append((full_path, rel_path))
                    elif fname.endswith(polyglot_exts):
                        polyglot_files.append((full_path, rel_path))

        # Pass 1 on Python files: collect cross-file Blueprint / APIRouter prefixes & Pydantic models
        for full_path, rel_path in py_files:
            self._precollect_python_prefixes(full_path, rel_path)

        # Prune bare router variable names that collide across multiple files so only module-qualified keys apply
        for r_var, mod_stems in self._router_def_files.items():
            if len(mod_stems) > 1:
                self._router_def_prefixes.pop(r_var, None)
                self._router_mount_prefixes.pop(r_var, None)

        # Combine router definition prefixes and mount (register_blueprint / include_router) prefixes
        all_router_vars = set(self._router_def_prefixes.keys()) | set(self._router_mount_prefixes.keys())
        for r_var in all_router_vars:
            def_p = self._router_def_prefixes.get(r_var, "").rstrip("/")
            mount_p = self._router_mount_prefixes.get(r_var, "").rstrip("/")
            if mount_p and def_p and mount_p != def_p and not def_p.startswith(mount_p + "/"):
                combined = f"{mount_p}/{def_p.lstrip('/')}"
            else:
                combined = mount_p or def_p
            if combined:
                self._global_router_prefixes[r_var] = combined

        # Propagate nested router chains (e.g. app.include_router(api, prefix="/api") -> api.include_router(v1, prefix="/v1"))
        for _ in range(4):
            for parent_var, child_var, edge_prefix in self._router_parent_edges:
                if len(self._router_def_files.get(child_var, set())) > 1:
                    continue
                parent_p = self._global_router_prefixes.get(parent_var, "")
                child_def_p = self._router_def_prefixes.get(child_var, "")
                candidate = self._join_prefixes(parent_p, edge_prefix, child_def_p)
                if candidate:
                    self._global_router_prefixes[child_var] = candidate

        # Propagate nested Django include('app.urls') prefix chains across modular urls.py files
        for _ in range(4):
            for parent_rel, target_mod, edge_prefix in self._django_include_edges:
                parent_p = self._django_include_prefixes.get(parent_rel, "")
                candidate = self._join_prefixes(parent_p, edge_prefix)
                if candidate:
                    self._django_include_prefixes[target_mod] = candidate
                    mod_as_path = target_mod.replace(".", "/") + ".py"
                    self._django_include_prefixes[mod_as_path] = candidate
                    mod_underscore = target_mod.replace(".", "_") + ".py"
                    self._django_include_prefixes[mod_underscore] = candidate

        # Pass 2 on Python files: extract routes and call graphs
        for full_path, rel_path in py_files:
            self._parse_python_file(full_path, rel_path)

        # Resolve Django path() / Flask add_url_rule() deferred view functions
        self._resolve_pending_view_routes()

        # Pass 3 on JS/TS files (Bonus B-7: Node.js / Express support)
        if js_files:
            self._scan_express_files(js_files)

        # Pass 4 on Java files (Bonus B-7: Java Spring Boot / Jakarta Servlet support)
        if java_files:
            self._scan_java_files(java_files)

        # Pass 5 on Universal Polyglot files (Go, PHP, C#/.NET, Ruby, Kotlin, Rust, Scala, Swift, C/C++)
        if polyglot_files:
            self._scan_polyglot_files(polyglot_files)

        # Populate multi-hop called_func_details, called_functions, and compile regex matchers
        for r in self.routes:
            expanded = self._expand_called_functions(set(r.called_funcs), max_hops=3)
            r.called_funcs = sorted(list(expanded))
            r.called_functions = list(r.called_funcs)
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
            mod_stem = os.path.splitext(os.path.basename(rel_path))[0]

            local_import_aliases: Dict[str, str] = {}
            local_qual_import_aliases: Dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    src_mod_stem = (node.module or "").split(".")[-1]
                    for alias in node.names:
                        bound_name = alias.asname or alias.name
                        if alias.asname:
                            local_import_aliases[alias.asname] = alias.name
                        if src_mod_stem:
                            local_qual_import_aliases[bound_name] = f"{src_mod_stem}.{alias.name}"

            for node in ast.walk(tree):
                # 0. Collect Pydantic BaseModel class fields for FastAPI JSON body inspection
                if isinstance(node, ast.ClassDef):
                    is_model = any(
                        (isinstance(b, ast.Name) and b.id in ("BaseModel", "Schema"))
                        or (isinstance(b, ast.Attribute) and b.attr in ("BaseModel", "Schema"))
                        for b in node.bases
                    )
                    if is_model:
                        fields: List[str] = []
                        for item in node.body:
                            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                                fields.append(item.target.id)
                        if fields:
                            self._pydantic_models[node.name] = fields

                # 1. bp = Blueprint('orders', __name__, url_prefix='/api')
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
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
                            if isinstance(target, ast.Name):
                                self._router_def_files.setdefault(target.id, set()).add(mod_stem)
                                if prefix:
                                    self._router_def_prefixes[target.id] = prefix
                                    self._router_def_prefixes[f"{mod_stem}.{target.id}"] = prefix

                # 2. app.register_blueprint(orders_bp, url_prefix='/api')
                #    app.include_router(orders_router, prefix='/api')
                #    api_router.include_router(v1_router, prefix='/v1')
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("register_blueprint", "include_router") and node.args:
                        parent_var = ""
                        if isinstance(node.func.value, ast.Name):
                            parent_var = node.func.value.id
                        elif isinstance(node.func.value, ast.Attribute):
                            parent_var = node.func.value.attr
                        parent_orig = local_import_aliases.get(parent_var, parent_var)

                        router_arg = node.args[0]
                        router_var = ""
                        qual_router_var = ""
                        if isinstance(router_arg, ast.Name):
                            router_var = router_arg.id
                            qual_router_var = local_qual_import_aliases.get(router_var, f"{mod_stem}.{router_var}")
                        elif isinstance(router_arg, ast.Attribute):
                            router_var = router_arg.attr
                            if isinstance(router_arg.value, ast.Name):
                                attr_mod = local_import_aliases.get(router_arg.value.id, router_arg.value.id)
                                qual_router_var = f"{attr_mod}.{router_arg.attr}"
                        if router_var:
                            prefix = ""
                            for kw in node.keywords:
                                if kw.arg in ("url_prefix", "prefix") and isinstance(kw.value, ast.Constant):
                                    prefix = str(kw.value.value).rstrip("/")
                            orig_name = local_import_aliases.get(router_var)
                            if prefix:
                                self._router_mount_prefixes[router_var] = prefix
                                if orig_name:
                                    self._router_mount_prefixes[orig_name] = prefix
                                if qual_router_var:
                                    self._router_mount_prefixes[qual_router_var] = prefix
                            self._router_parent_edges.append((parent_orig, router_var, prefix))
                            if orig_name:
                                self._router_parent_edges.append((parent_orig, orig_name, prefix))
                            if qual_router_var:
                                self._router_parent_edges.append((parent_orig, qual_router_var, prefix))

                # 3. Django path('api/v1/billing/', include('billing.urls')) cross-file prefix collection
                elif isinstance(node, ast.Call):
                    fn_name = ""
                    if isinstance(node.func, ast.Name):
                        fn_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        fn_name = node.func.attr
                    if fn_name in ("path", "re_path", "url") and len(node.args) >= 2:
                        if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            inc_prefix = str(node.args[0].value).strip("^$")
                            second_arg = node.args[1]
                            if isinstance(second_arg, ast.Call):
                                inc_fn = ""
                                if isinstance(second_arg.func, ast.Name):
                                    inc_fn = second_arg.func.id
                                elif isinstance(second_arg.func, ast.Attribute):
                                    inc_fn = second_arg.func.attr
                                if inc_fn == "include" and second_arg.args:
                                    inc_target = second_arg.args[0]
                                    target_mod = ""
                                    if isinstance(inc_target, ast.Constant) and isinstance(inc_target.value, str):
                                        target_mod = inc_target.value
                                    elif isinstance(inc_target, (ast.Tuple, ast.List)) and inc_target.elts:
                                        first_elt = inc_target.elts[0]
                                        if isinstance(first_elt, ast.Constant) and isinstance(first_elt.value, str):
                                            target_mod = first_elt.value
                                    if target_mod:
                                        norm_inc = self._join_prefixes(inc_prefix)
                                        if norm_inc:
                                            self._django_include_prefixes[target_mod] = norm_inc
                                            self._django_include_prefixes[target_mod.replace(".", "/") + ".py"] = norm_inc
                                            self._django_include_prefixes[target_mod.replace(".", "_") + ".py"] = norm_inc
                                        self._django_include_edges.append((rel_path, target_mod, inc_prefix))
        except Exception:
            pass

    def _parse_python_file(self, full_path: str, rel_path: str):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=rel_path)

            # Collect class-based views (MethodView / View)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    is_view_cls = any(
                        (isinstance(b, ast.Name) and b.id in ("MethodView", "View", "APIView"))
                        or (isinstance(b, ast.Attribute) and b.attr in ("MethodView", "View", "APIView"))
                        for b in node.bases
                    )
                    if is_view_cls:
                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                m_lower = item.name.lower()
                                if m_lower in ("get", "post", "put", "delete", "patch"):
                                    end_line = getattr(item, "end_lineno", item.lineno)
                                    vis = FunctionVisitor(item, pydantic_models=self._pydantic_models)
                                    vis.visit(item)
                                    qual_name = f"{node.name}.{item.name}"
                                    self.func_to_file_lines[qual_name] = (rel_path, item.lineno, end_line)
                                    self.call_graph.setdefault(qual_name, set()).update(vis.called_funcs)
                                    self.func_defs.setdefault(qual_name, []).append(
                                        (rel_path, item.lineno, end_line, set(vis.called_funcs), set(vis.parameters))
                                    )
                                    self._class_views.setdefault(node.name, []).append(
                                        (
                                            m_lower.upper(),
                                            qual_name,
                                            rel_path,
                                            item.lineno,
                                            end_line,
                                            set(vis.called_funcs),
                                            set(vis.parameters),
                                        )
                                    )

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end_line = getattr(node, "end_lineno", node.lineno)
                    vis = FunctionVisitor(node, pydantic_models=self._pydantic_models)
                    vis.visit(node)
                    self.func_to_file_lines[node.name] = (rel_path, node.lineno, end_line)
                    self.call_graph.setdefault(node.name, set()).update(vis.called_funcs)
                    self.func_defs.setdefault(node.name, []).append(
                        (rel_path, node.lineno, end_line, set(vis.called_funcs), set(vis.parameters))
                    )

            mod_stem = os.path.splitext(os.path.basename(rel_path))[0]
            file_prefixes = dict(self._global_router_prefixes)
            for r_var, mod_stems in self._router_def_files.items():
                if mod_stem in mod_stems:
                    qual_key = f"{mod_stem}.{r_var}"
                    if qual_key in self._global_router_prefixes:
                        file_prefixes[r_var] = self._global_router_prefixes[qual_key]
                    elif len(mod_stems) > 1:
                        file_prefixes.pop(r_var, None)

            django_prefix = (
                self._django_include_prefixes.get(rel_path)
                or self._django_include_prefixes.get(os.path.basename(rel_path))
                or self._django_include_prefixes.get(rel_path[:-3].replace("/", ".") if rel_path.endswith(".py") else "")
                or ""
            )

            extractor = RouteExtractor(
                full_path,
                rel_path,
                global_prefixes=file_prefixes,
                pydantic_models=self._pydantic_models,
                django_file_prefix=django_prefix,
            )
            extractor.visit(tree)
            self.routes.extend(extractor.routes)
            self._pending_view_routes.extend(extractor.django_Pending_routes)
        except Exception:
            pass

    def _resolve_pending_view_routes(self):
        for raw_path, target_func, framework_spec in self._pending_view_routes:
            if ":" in framework_spec:
                framework, methods_csv = framework_spec.split(":", 1)
                explicit_methods = [m.strip().upper() for m in methods_csv.split(",") if m.strip()]
            else:
                framework = framework_spec
                explicit_methods = []

            norm_path = raw_path if raw_path.startswith("/") or raw_path.startswith("^") else "/" + raw_path
            if target_func.startswith("ClassView:"):
                cls_name = target_func.split(":", 1)[1]
                for http_method, qual_name, rel_path, start_line, end_line, called_funcs, params in self._class_views.get(cls_name, []):
                    if explicit_methods and http_method.upper() not in explicit_methods:
                        continue
                    route_params = set(params)
                    param_sources: Dict[str, str] = {}
                    for m in re.finditer(r"<(?:\w+:)?(\w+)>", norm_path):
                        route_params.add(m.group(1))
                        param_sources[m.group(1)] = "path"
                    for m in re.finditer(r"\(\?P<(\w+)>", norm_path):
                        route_params.add(m.group(1))
                        param_sources[m.group(1)] = "path"
                    self.routes.append(
                        RouteEntry(
                            method=http_method,
                            path_pattern=norm_path,
                            regex_pattern=_normalize_route_pattern_to_regex(norm_path),
                            file_path=rel_path,
                            func_name=qual_name,
                            start_line=start_line,
                            end_line=end_line,
                            parameters=sorted(list(route_params)),
                            param_sources=param_sources,
                            called_funcs=sorted(list(called_funcs)),
                            framework=framework,
                        )
                    )
                continue

            defs = self.func_defs.get(target_func, [])
            if defs:
                rel_path, start_line, end_line, called_funcs, params = defs[0]
                route_params = set(params)
                param_sources = {}
                # Extract path converter params like <int:id>
                for m in re.finditer(r"<(?:\w+:)?(\w+)>", norm_path):
                    route_params.add(m.group(1))
                    param_sources[m.group(1)] = "path"
                for m in re.finditer(r"\(\?P<(\w+)>", norm_path):
                    route_params.add(m.group(1))
                    param_sources[m.group(1)] = "path"

                methods_to_use = tuple(explicit_methods) if explicit_methods else ("GET", "POST")
                for method in methods_to_use:
                    self.routes.append(
                        RouteEntry(
                            method=method,
                            path_pattern=norm_path,
                            regex_pattern=_normalize_route_pattern_to_regex(norm_path),
                            file_path=rel_path,
                            func_name=target_func,
                            start_line=start_line,
                            end_line=end_line,
                            parameters=sorted(list(route_params)),
                            param_sources=param_sources,
                            called_funcs=sorted(list(called_funcs)),
                            framework=framework,
                        )
                    )

    # -------------------------------------------------------------------------
    # Bonus B-7: Node.js / Express Route & Call Graph Parser
    # -------------------------------------------------------------------------
    def _scan_express_files(self, js_files: List[Tuple[str, str]]):
        router_prefixes: Dict[str, str] = {}
        file_router_prefixes: Dict[str, str] = {}

        # First pass: collect app.use('/prefix', routerName), cross-file require() mounts, and helper functions
        for full_path, rel_path in js_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                lines = content.splitlines()
                cur_dir = os.path.dirname(rel_path).replace("\\", "/")

                # Track const ordersRouter = require('./routes/orders') or import ordersRouter from './routes/orders'
                local_requires: Dict[str, str] = {}
                for req_m in re.finditer(
                    r"""(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s+([a-zA-Z_]\w*)\s+from\s+['"]([^'"]+)['"]""",
                    content,
                ):
                    var_name = req_m.group(1) or req_m.group(3)
                    req_path = req_m.group(2) or req_m.group(4)
                    if var_name and req_path:
                        local_requires[var_name] = req_path

                def _register_file_prefix(req_target: str, mount_prefix: str):
                    clean_p = mount_prefix.rstrip("/")
                    if not clean_p:
                        return
                    joined = os.path.normpath(os.path.join(cur_dir, req_target)).replace("\\", "/").lstrip("./")
                    for cand in (joined, f"{joined}.js", f"{joined}.ts", f"{joined}/index.js", os.path.basename(joined) + ".js"):
                        file_router_prefixes[cand] = clean_p

                # Detect app.use('/api', apiRouter)
                for m in re.finditer(r"""\b(?:app|router)\s*\.\s*use\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z_]\w*)""", content):
                    mount_p = m.group(1).rstrip("/")
                    r_var = m.group(2)
                    router_prefixes[r_var] = mount_p
                    if r_var in local_requires:
                        _register_file_prefix(local_requires[r_var], mount_p)

                # Detect inline app.use('/api/orders', require('./routes/orders'))
                for m_in in re.finditer(
                    r"""\b(?:app|router)\s*\.\s*use\s*\(\s*['"]([^'"]+)['"]\s*,\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
                    content,
                ):
                    _register_file_prefix(m_in.group(2), m_in.group(1))

                # Detect named JS functions: function myHelper(a, b) { ... }, const myHelper = (a, b) => { ... }, or exports.myHelper = function(a, b) { ... }
                func_pattern = re.compile(
                    r"""(?:(?:async\s+)?function\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)|(?:(?:const|let|var)\s+|(?:module\.)?exports\.)([a-zA-Z_]\w*)\s*=\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)\s*(?:=>)?)\s*\{"""
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

        # Second pass: extract Express routes (direct obj.get('/path', ...) AND chained obj.route('/path').get(...).post(...))
        route_regex = re.compile(
            r"""\b([a-zA-Z_]\w*)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^\n]+)"""
        )
        chain_route_start_regex = re.compile(
            r"""\b([a-zA-Z_]\w*)\s*\.\s*route\s*\(\s*['"]([^'"]+)['"]\s*\)"""
        )
        chain_method_regex = re.compile(
            r"""\.\s*(get|post|put|delete|patch)\s*\("""
        )
        for full_path, rel_path in js_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                lines = content.splitlines()
                file_mount_prefix = (
                    file_router_prefixes.get(rel_path)
                    or file_router_prefixes.get(os.path.basename(rel_path))
                    or ""
                )

                # 2a. Direct obj.get('/path', handler)
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
                    prefix = router_prefixes.get(obj_name) or file_mount_prefix
                    full_route_path = f"{prefix}/{raw_path.lstrip('/')}" if prefix else raw_path
                    if len(full_route_path) > 1 and full_route_path.endswith("/"):
                        full_route_path = full_route_path.rstrip("/")
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

                # 2b. Chained router.route('/items/:id').get(...).post(...)
                for idx, line_str in enumerate(lines):
                    cm = chain_route_start_regex.search(line_str)
                    if not cm:
                        continue
                    obj_name, raw_path = cm.group(1), cm.group(2)
                    prefix = router_prefixes.get(obj_name) or file_mount_prefix
                    full_route_path = f"{prefix}/{raw_path.lstrip('/')}" if prefix else raw_path
                    if len(full_route_path) > 1 and full_route_path.endswith("/"):
                        full_route_path = full_route_path.rstrip("/")
                    if not full_route_path.startswith("/"):
                        full_route_path = "/" + full_route_path

                    # Scan lines from idx until end of chained statement
                    chain_end_idx = min(len(lines), idx + 30)
                    for scan_idx in range(idx, chain_end_idx):
                        scan_line = lines[scan_idx]
                        for mm in chain_method_regex.finditer(scan_line):
                            # Avoid matching obj.get('/path', ...) which has a string literal first arg
                            after_paren = scan_line[mm.end():].lstrip()
                            if after_paren.startswith(("'", '"')):
                                continue
                            method_str = mm.group(1).upper()
                            m_start_line = scan_idx + 1
                            m_end_line = self._find_js_block_end(lines, scan_idx)
                            block_text = "\n".join(lines[scan_idx:m_end_line])
                            func_name = f"express_{method_str.lower()}_{re.sub(r'[^a-zA-Z0-9_]', '_', full_route_path).strip('_') or 'root'}"
                            params = self._extract_js_params(block_text, "")
                            for pm in re.finditer(r":([a-zA-Z_]\w*)", full_route_path):
                                params.add(pm.group(1))
                            called = self._extract_js_calls(block_text)
                            self.func_to_file_lines[func_name] = (rel_path, m_start_line, m_end_line)
                            self.call_graph.setdefault(func_name, set()).update(called)
                            self.func_defs.setdefault(func_name, []).append((rel_path, m_start_line, m_end_line, called, params))
                            self.routes.append(
                                RouteEntry(
                                    method=method_str,
                                    path_pattern=full_route_path,
                                    regex_pattern=_normalize_route_pattern_to_regex(full_route_path),
                                    file_path=rel_path,
                                    func_name=func_name,
                                    start_line=m_start_line,
                                    end_line=m_end_line,
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
    # Bonus B-7: Java (Spring Boot / Jakarta Servlet) Route & Method Extraction
    # -------------------------------------------------------------------------
    def _scan_java_files(self, java_files: List[Tuple[str, str]]) -> None:
        spring_verb_map = {
            "GetMapping": "GET",
            "PostMapping": "POST",
            "PutMapping": "PUT",
            "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH",
        }
        method_sig_re = re.compile(
            r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\],\s\?]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)"
        )
        max_in_memory_bytes = 2 * 1024 * 1024  # 2 MB threshold; stream larger files in constant RAM

        for full_path, rel_path in java_files:
            try:
                file_size = os.path.getsize(full_path)
                if file_size > max_in_memory_bytes:
                    self._scan_large_java_file_stream(full_path, rel_path, spring_verb_map, method_sig_re)
                    continue

                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if "(" not in content:
                    continue
                lines = content.splitlines()

                # Detect class-level @RequestMapping or @WebServlet prefix
                class_prefix = ""
                web_servlet_path = ""
                for idx, raw_line in enumerate(lines):
                    s_line = raw_line.strip()
                    if re.search(r"\bclass\s+[A-Z]\w*", s_line):
                        break
                    m_cls_req = re.search(
                        r"""@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""",
                        s_line,
                    )
                    if m_cls_req:
                        class_prefix = m_cls_req.group(1).strip()
                    m_servlet = re.search(
                        r"""@WebServlet\s*\(\s*(?:(?:value|urlPatterns)\s*=\s*)?["']([^"']+)["']""",
                        s_line,
                    )
                    if m_servlet:
                        web_servlet_path = m_servlet.group(1).strip()

                # Pass 1: Register all Java methods (for call-graph & dead-code reachability)
                idx = 0
                while idx < len(lines):
                    raw_line = lines[idx]
                    # Support multi-line method declarations up to 3 lines
                    sig_window = " ".join(ln.strip() for ln in lines[idx : min(len(lines), idx + 3)])
                    m_sig = method_sig_re.match(sig_window) if "(" in raw_line and not raw_line.strip().startswith(("@", "//", "/*", "*")) else None
                    if m_sig and ("{" in sig_window):
                        func_name = m_sig.group(1)
                        raw_args = m_sig.group(2)
                        if func_name not in ("if", "for", "while", "switch", "catch"):
                            start_line = idx + 1
                            end_line = self._find_js_block_end(lines, idx)
                            block_text = "\n".join(lines[idx:end_line])
                            params = self._extract_java_params(block_text, raw_args, "")
                            called = self._extract_js_calls(block_text, exclude_name=func_name)
                            self.func_to_file_lines[func_name] = (rel_path, start_line, end_line)
                            self.call_graph.setdefault(func_name, set()).update(called)
                            self.func_defs.setdefault(func_name, []).append(
                                (rel_path, start_line, end_line, called, params)
                            )
                    idx += 1

                # Pass 2: Scan for Spring Boot route annotations and Servlet handlers
                has_route_markers = any(
                    k in content
                    for k in ("Mapping", "@WebServlet", "doGet", "doPost", "doPut", "doDelete")
                )
                if not has_route_markers:
                    continue

                for idx, raw_line in enumerate(lines):
                    s_line = raw_line.strip()
                    if "@" not in s_line and "void do" not in s_line:
                        continue
                    route_methods: List[str] = []
                    sub_path = ""
                    matched_annotation = False

                    for ann_name, http_verb in spring_verb_map.items():
                        m_ann = re.search(rf"@{ann_name}\b(?:\s*\((.*)\))?", s_line)
                        if m_ann:
                            matched_annotation = True
                            route_methods = [http_verb]
                            ann_args = m_ann.group(1) or ""
                            m_p = re.search(r"""(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", ann_args)
                            if m_p:
                                sub_path = m_p.group(1).strip()
                            break

                    if not matched_annotation and s_line.startswith("@RequestMapping"):
                        # Ignore class-level @RequestMapping (followed by 'public class ...')
                        lookahead = "\n".join(lines[idx : min(len(lines), idx + 5)])
                        if not re.search(r"\bclass\s+[A-Z]\w*", lookahead):
                            matched_annotation = True
                            m_p = re.search(r"""(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", s_line)
                            if m_p:
                                sub_path = m_p.group(1).strip()
                            m_verb = re.findall(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", s_line)
                            route_methods = m_verb if m_verb else ["GET"]

                    # Check Jakarta/Java Servlet doGet / doPost inside @WebServlet class
                    servlet_verb = None
                    if not matched_annotation and web_servlet_path:
                        m_do = re.search(r"\bprotected\s+void\s+do(Get|Post|Put|Delete)\s*\(", s_line)
                        if m_do:
                            servlet_verb = m_do.group(1).upper()
                            matched_annotation = True
                            route_methods = [servlet_verb]
                            sub_path = web_servlet_path

                    if not matched_annotation:
                        continue

                    # Locate the annotated Java method declaration within the next 1..6 lines
                    method_idx = idx
                    func_name = f"java_handler_{idx + 1}"
                    raw_args = ""
                    for scan_i in range(idx, min(len(lines), idx + 6)):
                        cand_sig = " ".join(ln.strip() for ln in lines[scan_i : min(len(lines), scan_i + 3)])
                        if cand_sig.startswith("@"):
                            continue
                        m_decl = method_sig_re.match(cand_sig)
                        if m_decl:
                            method_idx = scan_i
                            func_name = m_decl.group(1)
                            raw_args = m_decl.group(2)
                            break

                    start_line = idx + 1
                    end_line = self._find_js_block_end(lines, method_idx)
                    block_text = "\n".join(lines[idx:end_line])

                    if servlet_verb:
                        full_route_path = web_servlet_path
                    else:
                        full_route_path = self._join_prefixes(class_prefix, sub_path) or "/"

                    params = self._extract_java_params(block_text, raw_args, full_route_path)
                    called = self._extract_js_calls(block_text, exclude_name=func_name)
                    auth_ctx = "none"
                    if re.search(r"@(?:PreAuthorize|Secured|RolesAllowed)\b", block_text) or (
                        'getHeader("Authorization")' in block_text or "SecurityContextHolder" in block_text
                    ):
                        auth_ctx = "spring_security"

                    self.func_to_file_lines[func_name] = (rel_path, start_line, end_line)
                    self.call_graph.setdefault(func_name, set()).update(called)
                    self.func_defs.setdefault(func_name, []).append(
                        (rel_path, start_line, end_line, called, params)
                    )

                    for m_verb in route_methods:
                        self.routes.append(
                            RouteEntry(
                                method=m_verb,
                                path_pattern=full_route_path,
                                regex_pattern=_normalize_route_pattern_to_regex(full_route_path),
                                file_path=rel_path,
                                func_name=func_name,
                                start_line=start_line,
                                end_line=end_line,
                                parameters=sorted(list(params)),
                                called_funcs=sorted(list(called)),
                                auth_context=auth_ctx,
                                framework="spring",
                            )
                        )
            except Exception:
                pass

    def _scan_large_java_file_stream(
        self,
        full_path: str,
        rel_path: str,
        spring_verb_map: Dict[str, str],
        method_sig_re: Pattern[str],
    ) -> None:
        """
        Streaming O(1)-RAM Java route & method scanner for huge monolithic files (> 2 MB up to 13+ GB).
        Never loads the full file into memory; inspects lines via an 8 MB buffered stream.
        """
        class_prefix = ""
        web_servlet_path = ""
        seen_class_decl = False
        pending_route: Optional[Tuple[int, List[str], str, Optional[str]]] = None

        with open(full_path, "r", encoding="utf-8", errors="ignore", buffering=8 * 1024 * 1024) as f:
            lineno = 0
            while True:
                raw_line = f.readline()
                if not raw_line:
                    break
                lineno += 1
                s_line = raw_line.strip()
                if not s_line or s_line.startswith(("//", "/*", "*")):
                    continue

                if not seen_class_decl:
                    if "class " in s_line and re.search(r"\bclass\s+[A-Z]\w*", s_line):
                        seen_class_decl = True
                    else:
                        if "@RequestMapping" in s_line:
                            m_cls_req = re.search(
                                r"""@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""",
                                s_line,
                            )
                            if m_cls_req:
                                class_prefix = m_cls_req.group(1).strip()
                        if "@WebServlet" in s_line:
                            m_servlet = re.search(
                                r"""@WebServlet\s*\(\s*(?:(?:value|urlPatterns)\s*=\s*)?["']([^"']+)["']""",
                                s_line,
                            )
                            if m_servlet:
                                web_servlet_path = m_servlet.group(1).strip()
                        continue

                # Check route annotations inside class body
                if s_line.startswith("@"):
                    for ann_name, http_verb in spring_verb_map.items():
                        m_ann = re.search(rf"@{ann_name}\b(?:\s*\((.*)\))?", s_line)
                        if m_ann:
                            ann_args = m_ann.group(1) or ""
                            m_p = re.search(r"""(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", ann_args)
                            sub_p = m_p.group(1).strip() if m_p else ""
                            pending_route = (lineno, [http_verb], sub_p, None)
                            break
                    else:
                        if s_line.startswith("@RequestMapping"):
                            m_p = re.search(r"""(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", s_line)
                            sub_p = m_p.group(1).strip() if m_p else ""
                            m_verb = re.findall(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", s_line)
                            pending_route = (lineno, m_verb if m_verb else ["GET"], sub_p, None)
                    continue

                # Check Servlet doGet / doPost
                if web_servlet_path and "void do" in s_line:
                    m_do = re.search(r"\bprotected\s+void\s+do(Get|Post|Put|Delete)\s*\(", s_line)
                    if m_do:
                        s_verb = m_do.group(1).upper()
                        pending_route = (lineno, [s_verb], web_servlet_path, s_verb)

                # Check method signature line
                if "(" in s_line and any(mod in s_line for mod in ("public ", "protected ", "private ")):
                    m_sig = method_sig_re.match(s_line)
                    if m_sig:
                        func_name = m_sig.group(1)
                        raw_args = m_sig.group(2)
                        start_line = pending_route[0] if pending_route else lineno
                        block_lines = [raw_line]
                        brace_depth = raw_line.count("{") - raw_line.count("}")
                        opened = "{" in raw_line
                        for _ in range(60):
                            if opened and brace_depth <= 0:
                                break
                            nxt = f.readline()
                            if not nxt:
                                break
                            lineno += 1
                            block_lines.append(nxt)
                            if "{" in nxt:
                                opened = True
                            brace_depth += nxt.count("{") - nxt.count("}")
                        end_line = lineno
                        block_text = "".join(block_lines)
                        full_route_path = ""
                        if pending_route:
                            _, r_methods, sub_p, servlet_v = pending_route
                            full_route_path = web_servlet_path if servlet_v else (self._join_prefixes(class_prefix, sub_p) or "/")
                        params = self._extract_java_params(block_text, raw_args, full_route_path)
                        called = self._extract_js_calls(block_text, exclude_name=func_name)
                        self.func_to_file_lines[func_name] = (rel_path, start_line, end_line)
                        self.call_graph.setdefault(func_name, set()).update(called)
                        self.func_defs.setdefault(func_name, []).append(
                            (rel_path, start_line, end_line, called, params)
                        )
                        if pending_route:
                            _, r_methods, _, _ = pending_route
                            auth_ctx = "none"
                            if re.search(r"@(?:PreAuthorize|Secured|RolesAllowed)\b", block_text) or (
                                'getHeader("Authorization")' in block_text or "SecurityContextHolder" in block_text
                            ):
                                auth_ctx = "spring_security"
                            for m_verb in r_methods:
                                self.routes.append(
                                    RouteEntry(
                                        method=m_verb,
                                        path_pattern=full_route_path,
                                        regex_pattern=_normalize_route_pattern_to_regex(full_route_path),
                                        file_path=rel_path,
                                        func_name=func_name,
                                        start_line=start_line,
                                        end_line=end_line,
                                        parameters=sorted(list(params)),
                                        called_funcs=sorted(list(called)),
                                        auth_context=auth_ctx,
                                        framework="spring",
                                    )
                                )
                            pending_route = None

    @staticmethod
    def _extract_java_params(block_text: str, raw_args: str, route_path: str) -> Set[str]:
        params: Set[str] = set()
        # Path variables in route pattern: /api/orders/{id}
        for m in re.finditer(r"\{([a-zA-Z_]\w*)\}", route_path or ""):
            params.add(m.group(1))
        # @RequestParam("q") or @RequestParam(value = "q", ...) or @PathVariable("id")
        for m in re.finditer(
            r"""@(?:RequestParam|PathVariable|RequestHeader)\s*\(\s*(?:(?:value|name)\s*=\s*)?["']([^"']+)["']""",
            block_text,
        ):
            params.add(m.group(1))
        # @RequestParam String host or @PathVariable Long orderId
        for m in re.finditer(
            r"@(?:RequestParam|PathVariable|RequestBody)(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w<>\[\]\?]+\s+([a-zA-Z_]\w*)",
            block_text,
        ):
            params.add(m.group(1))
        # HttpServletRequest: request.getParameter("username") / req.getParameter("id")
        for m in re.finditer(r"""\b(?:request|req|httpRequest)\s*\.\s*getParameter\s*\(\s*["']([^"']+)["']\s*\)""", block_text):
            params.add(m.group(1))
        # Map.get("host") on @RequestBody Map<String, String> body
        for m in re.finditer(r"""\b(?:body|payload|params|data)\s*\.\s*get\s*\(\s*["']([^"']+)["']\s*\)""", block_text):
            params.add(m.group(1))
        # Plain method arguments (excluding servlet/spring framework objects)
        ignored_types = {
            "HttpServletRequest",
            "HttpServletResponse",
            "HttpSession",
            "Model",
            "ModelMap",
            "RedirectAttributes",
            "BindingResult",
            "Principal",
            "Authentication",
        }
        for part in (raw_args or "").split(","):
            tokens = re.sub(r"@\w+(?:\s*\([^)]*\))?", "", part).strip().split()
            if len(tokens) >= 2:
                param_type = tokens[-2].split("<")[0].strip()
                param_name = tokens[-1].strip()
                if param_type not in ignored_types and re.match(r"^[a-zA-Z_]\w*$", param_name):
                    params.add(param_name)
        return params

    # -------------------------------------------------------------------------
    # Universal Polyglot Route Extractor (Go, PHP, C#/.NET, Ruby, Kotlin, Rust, etc.)
    # -------------------------------------------------------------------------
    def _scan_polyglot_files(self, polyglot_files: List[Tuple[str, str]]) -> None:
        """
        2-Tier Universal Polyglot Route Extractor:
          - Tier 1: Framework-aware parsers for Go (Gin/Echo/Fiber/net/http), PHP (Laravel/Slim/Native),
            C# ASP.NET Core ([Route]/[HttpGet]/MapGet), Ruby (Sinatra/Rails), Rust (Actix/Axum), Kotlin.
          - Tier 2: Universal HTTP route string fallback for any other backend language.
          - Caps per-file memory by reading at most 2 MB so large files stay fast and bounded.
        """
        MAX_POLYGLOT_READ_BYTES = 2 * 1024 * 1024

        for full_path, rel_path in polyglot_files:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(MAX_POLYGLOT_READ_BYTES)
            except Exception:
                continue

            if not content:
                continue

            lines = content.splitlines()
            total_lines = max(1, len(lines))
            ext = os.path.splitext(rel_path)[1].lower()
            routes_before = len(self.routes)

            # 1. Pre-index named functions/methods in this file so route tables (e.g. r.GET("/x", myHandler))
            #    map directly to the handler function's start_line..end_line.
            local_funcs: Dict[str, Tuple[int, int, str, str]] = {}
            func_sig_patterns = [
                # Go: func searchOrders(w http.ResponseWriter, r *http.Request) {
                r"^\s*func\s+(?:\([^)]+\)\s*)?([a-zA-Z_]\w*)\s*\(([^)]*)\)",
                # PHP / JS: public function searchOrders($req) {
                r"^\s*(?:public\s+|protected\s+|private\s+|static\s+)*function\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)",
                # Rust: pub async fn search_orders(...) {
                r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)",
                # Kotlin / Scala: fun searchOrders(...) {
                r"^\s*(?:suspend\s+|override\s+|public\s+|private\s+)*fun\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)",
                # Ruby: def search_orders(...)
                r"^\s*def\s+([a-zA-Z_]\w*)(?:\s*\(([^)]*)\))?",
                # C#: public IActionResult SearchOrders(string q)
                r"^\s*(?:public|protected|private)\s+(?:async\s+)?[\w<>\[\],\s\?]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)",
            ]

            for idx, line_s in enumerate(lines):
                s_strip = line_s.strip()
                if not s_strip or s_strip.startswith(("//", "#", "/*", "*")):
                    continue
                for f_pat in func_sig_patterns:
                    m_fn = re.match(f_pat, line_s)
                    if m_fn:
                        fn_name = m_fn.group(1)
                        if fn_name in ("if", "for", "while", "switch", "catch", "main"):
                            continue
                        raw_args = m_fn.group(2) or ""
                        start_l = idx + 1
                        if ext == ".rb":
                            end_l = self._find_ruby_end_line(lines, idx)
                        else:
                            end_l = self._find_brace_end_line(lines, idx)
                        block_t = "\n".join(lines[start_l - 1 : end_l])
                        local_funcs[fn_name] = (start_l, end_l, raw_args, block_t)
                        p_set = self._extract_polyglot_params(block_t, raw_args, "")
                        c_set = self._extract_js_calls(block_t, exclude_name=fn_name)
                        self.func_to_file_lines[fn_name] = (rel_path, start_l, end_l)
                        self.call_graph.setdefault(fn_name, set()).update(c_set)
                        self.func_defs.setdefault(fn_name, []).append((rel_path, start_l, end_l, c_set, p_set))
                        break

            # -----------------------------------------------------------------
            # Language A: Go (.go) — Gin, Echo, Fiber, Chi, Gorilla Mux, net/http
            # -----------------------------------------------------------------
            if ext == ".go":
                group_prefixes: Dict[str, str] = {}
                for gm in re.finditer(
                    r"""(\b[a-zA-Z_]\w*)\s*:?=\s*([a-zA-Z_]\w*)\s*\.\s*(?:Group|Route)\s*\(\s*["']([^"']+)["']""",
                    content,
                ):
                    child_var, parent_var, g_pref = gm.group(1), gm.group(2), gm.group(3)
                    parent_pref = group_prefixes.get(parent_var, "")
                    group_prefixes[child_var] = self._join_prefixes(parent_pref, g_pref)

                # Match r.GET("/path", handler), app.Post("/path", ...), http.HandleFunc("/path", handler)
                go_route_re = re.compile(
                    r"""\b([a-zA-Z_]\w*)\s*\.\s*(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch|HandleFunc|Handle)\s*\(\s*["']([^"']+)["']\s*,\s*([a-zA-Z_][\w.]*|func\s*\()""",
                )
                for rm in go_route_re.finditer(content):
                    router_var = rm.group(1)
                    raw_verb = rm.group(2).upper()
                    http_verb = "GET" if raw_verb in ("HANDLEFUNC", "HANDLE") else raw_verb
                    sub_path = rm.group(3).strip()
                    handler_tok = rm.group(4).strip()
                    reg_line = content[: rm.start()].count("\n") + 1
                    full_path_pat = self._join_prefixes(group_prefixes.get(router_var, ""), sub_path) or "/"

                    if handler_tok.startswith("func"):
                        end_l = self._find_brace_end_line(lines, reg_line - 1)
                        block_t = "\n".join(lines[reg_line - 1 : end_l])
                        fn_name = f"go_handler_L{reg_line}"
                        params = self._extract_polyglot_params(block_t, "", full_path_pat)
                        called = self._extract_js_calls(block_t, exclude_name=fn_name)
                        start_l = reg_line
                    else:
                        fn_name = handler_tok.split(".")[-1]
                        if fn_name in local_funcs:
                            start_l, end_l, raw_args, block_t = local_funcs[fn_name]
                            params = self._extract_polyglot_params(block_t, raw_args, full_path_pat)
                            called = self._extract_js_calls(block_t, exclude_name=fn_name)
                        else:
                            start_l, end_l = reg_line, min(total_lines, reg_line + 25)
                            block_t = "\n".join(lines[start_l - 1 : end_l])
                            params = self._extract_polyglot_params(block_t, "", full_path_pat)
                            called = set()

                    self.routes.append(
                        RouteEntry(
                            method=http_verb,
                            path_pattern=full_path_pat,
                            regex_pattern=_normalize_route_pattern_to_regex(full_path_pat),
                            file_path=rel_path,
                            func_name=fn_name,
                            start_line=start_l,
                            end_line=end_l,
                            parameters=sorted(list(params)),
                            called_funcs=sorted(list(called)),
                            auth_context="none",
                            framework="go",
                        )
                    )

            # -----------------------------------------------------------------
            # Language B: PHP (.php) — Laravel, Slim, Symfony, or Native PHP
            # -----------------------------------------------------------------
            elif ext == ".php":
                php_route_re = re.compile(
                    r"""(?:Route\s*::\s*|\$[a-zA-Z_]\w*\s*->\s*)(get|post|put|delete|patch|any)\s*\(\s*["']([^"']+)["']([^\n;]*)""",
                    re.IGNORECASE,
                )
                for rm in php_route_re.finditer(content):
                    raw_v = rm.group(1).upper()
                    verbs = ["GET", "POST"] if raw_v == "ANY" else [raw_v]
                    r_path = self._join_prefixes("", rm.group(2).strip()) or "/"
                    rest_line = rm.group(3) or ""
                    reg_line = content[: rm.start()].count("\n") + 1

                    # Check if handler points to a controller method e.g. [OrderController::class, 'search'] or 'OrderController@search'
                    target_fn = None
                    m_arr = re.search(r"""['"]([a-zA-Z_]\w*)['"]\s*\]""", rest_line)
                    m_at = re.search(r"""@([a-zA-Z_]\w*)['"]""", rest_line)
                    if m_at:
                        target_fn = m_at.group(1)
                    elif m_arr:
                        target_fn = m_arr.group(1)

                    if target_fn and target_fn in local_funcs:
                        start_l, end_l, raw_args, block_t = local_funcs[target_fn]
                        fn_name = target_fn
                    else:
                        start_l = reg_line
                        end_l = self._find_brace_end_line(lines, reg_line - 1)
                        block_t = "\n".join(lines[start_l - 1 : end_l])
                        fn_name = target_fn or f"php_route_L{reg_line}"

                    params = self._extract_polyglot_params(block_t, "", r_path)
                    called = self._extract_js_calls(block_t, exclude_name=fn_name)
                    for v in verbs:
                        self.routes.append(
                            RouteEntry(
                                method=v,
                                path_pattern=r_path,
                                regex_pattern=_normalize_route_pattern_to_regex(r_path),
                                file_path=rel_path,
                                func_name=fn_name,
                                start_line=start_l,
                                end_line=end_l,
                                parameters=sorted(list(params)),
                                called_funcs=sorted(list(called)),
                                auth_context="none",
                                framework="php",
                            )
                        )

                # Native standalone PHP script fallback (e.g., orders.php using $_GET / $_POST)
                if len(self.routes) == routes_before and any(k in content for k in ("$_GET", "$_POST", "$_REQUEST")):
                    script_path = "/" + rel_path.lstrip("/")
                    params = self._extract_polyglot_params(content, "", script_path)
                    verbs = []
                    if "$_GET" in content or "$_REQUEST" in content:
                        verbs.append("GET")
                    if "$_POST" in content or "$_REQUEST" in content:
                        verbs.append("POST")
                    for v in (verbs or ["GET"]):
                        self.routes.append(
                            RouteEntry(
                                method=v,
                                path_pattern=script_path,
                                regex_pattern=_normalize_route_pattern_to_regex(script_path),
                                file_path=rel_path,
                                func_name=os.path.splitext(os.path.basename(rel_path))[0],
                                start_line=1,
                                end_line=total_lines,
                                parameters=sorted(list(params)),
                                called_funcs=[],
                                auth_context="none",
                                framework="php",
                            )
                        )

            # -----------------------------------------------------------------
            # Language C: C# / ASP.NET Core (.cs) — Controllers & Minimal APIs
            # -----------------------------------------------------------------
            elif ext == ".cs":
                ctrl_name_m = re.search(r"\bclass\s+([a-zA-Z_]\w*)Controller\b", content)
                ctrl_slug = ctrl_name_m.group(1).lower() if ctrl_name_m else "api"
                class_route_m = re.search(r"""\[\s*Route\s*\(\s*["']([^"']+)["']\s*\)\s*\]""", content)
                class_prefix = ""
                if class_route_m:
                    class_prefix = class_route_m.group(1).replace("[controller]", ctrl_slug)

                # Attribute-routed controller methods: [HttpGet("search")]
                cs_attr_re = re.compile(
                    r"""\[\s*Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*["']([^"']*)["']\s*\))?\s*\]""",
                    re.IGNORECASE,
                )
                for am in cs_attr_re.finditer(content):
                    http_verb = am.group(1).upper()
                    sub_p = (am.group(2) or "").strip()
                    attr_line = content[: am.start()].count("\n") + 1
                    full_r_path = self._join_prefixes(class_prefix, sub_p) or "/"

                    # Find the method immediately following the attribute
                    fn_name = f"cs_action_L{attr_line}"
                    start_l, end_l, raw_args = attr_line, min(total_lines, attr_line + 25), ""
                    for look_idx in range(attr_line - 1, min(total_lines, attr_line + 8)):
                        m_cs = re.search(
                            r"\b(?:public|protected|private)\s+(?:async\s+)?[\w<>\[\],\s\?]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)",
                            lines[look_idx],
                        )
                        if m_cs:
                            fn_name = m_cs.group(1)
                            raw_args = m_cs.group(2) or ""
                            end_l = self._find_brace_end_line(lines, look_idx)
                            break

                    block_t = "\n".join(lines[start_l - 1 : end_l])
                    params = self._extract_polyglot_params(block_t, raw_args, full_r_path)
                    called = self._extract_js_calls(block_t, exclude_name=fn_name)
                    self.routes.append(
                        RouteEntry(
                            method=http_verb,
                            path_pattern=full_r_path,
                            regex_pattern=_normalize_route_pattern_to_regex(full_r_path),
                            file_path=rel_path,
                            func_name=fn_name,
                            start_line=start_l,
                            end_line=end_l,
                            parameters=sorted(list(params)),
                            called_funcs=sorted(list(called)),
                            auth_context="aspnet_authorize" if "[Authorize" in block_t else "none",
                            framework="aspnet",
                        )
                    )

                # ASP.NET Minimal APIs: app.MapGet("/api/orders", ...)
                for mm in re.finditer(
                    r"""\bMap(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']""",
                    content,
                ):
                    http_verb = mm.group(1).upper()
                    r_path = self._join_prefixes("", mm.group(2).strip()) or "/"
                    reg_line = content[: mm.start()].count("\n") + 1
                    end_l = self._find_brace_end_line(lines, reg_line - 1)
                    block_t = "\n".join(lines[reg_line - 1 : end_l])
                    params = self._extract_polyglot_params(block_t, "", r_path)
                    self.routes.append(
                        RouteEntry(
                            method=http_verb,
                            path_pattern=r_path,
                            regex_pattern=_normalize_route_pattern_to_regex(r_path),
                            file_path=rel_path,
                            func_name=f"map_{http_verb.lower()}_L{reg_line}",
                            start_line=reg_line,
                            end_line=end_l,
                            parameters=sorted(list(params)),
                            called_funcs=[],
                            auth_context="none",
                            framework="aspnet",
                        )
                    )

            # -----------------------------------------------------------------
            # Language D: Ruby (.rb) — Sinatra / Rails
            # -----------------------------------------------------------------
            elif ext == ".rb":
                for rm in re.finditer(
                    r"""^\s*(get|post|put|delete|patch)\s+["']([^"']+)["']""",
                    content,
                    re.MULTILINE | re.IGNORECASE,
                ):
                    http_verb = rm.group(1).upper()
                    r_path = self._join_prefixes("", rm.group(2).strip()) or "/"
                    start_l = content[: rm.start()].count("\n") + 1
                    end_l = self._find_ruby_end_line(lines, start_l - 1)
                    block_t = "\n".join(lines[start_l - 1 : end_l])
                    params = self._extract_polyglot_params(block_t, "", r_path)
                    self.routes.append(
                        RouteEntry(
                            method=http_verb,
                            path_pattern=r_path,
                            regex_pattern=_normalize_route_pattern_to_regex(r_path),
                            file_path=rel_path,
                            func_name=f"ruby_{http_verb.lower()}_L{start_l}",
                            start_line=start_l,
                            end_line=end_l,
                            parameters=sorted(list(params)),
                            called_funcs=[],
                            auth_context="none",
                            framework="ruby",
                        )
                    )

            # -----------------------------------------------------------------
            # Language E: Rust (.rs) — Actix-web & Axum
            # -----------------------------------------------------------------
            elif ext == ".rs":
                for rm in re.finditer(
                    r"""#\[\s*(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*\)\s*\]""",
                    content,
                    re.IGNORECASE,
                ):
                    http_verb = rm.group(1).upper()
                    r_path = self._join_prefixes("", rm.group(2).strip()) or "/"
                    start_l = content[: rm.start()].count("\n") + 1
                    end_l = self._find_brace_end_line(lines, start_l - 1)
                    fn_name = f"rust_{http_verb.lower()}_L{start_l}"
                    raw_args = ""
                    for look_idx in range(start_l - 1, min(total_lines, start_l + 6)):
                        m_rs = re.search(r"\bfn\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)", lines[look_idx])
                        if m_rs:
                            fn_name = m_rs.group(1)
                            raw_args = m_rs.group(2) or ""
                            end_l = self._find_brace_end_line(lines, look_idx)
                            break
                    block_t = "\n".join(lines[start_l - 1 : end_l])
                    params = self._extract_polyglot_params(block_t, raw_args, r_path)
                    self.routes.append(
                        RouteEntry(
                            method=http_verb,
                            path_pattern=r_path,
                            regex_pattern=_normalize_route_pattern_to_regex(r_path),
                            file_path=rel_path,
                            func_name=fn_name,
                            start_line=start_l,
                            end_line=end_l,
                            parameters=sorted(list(params)),
                            called_funcs=[],
                            auth_context="none",
                            framework="rust",
                        )
                    )

            # -----------------------------------------------------------------
            # Tier 2 Universal Fallback (Kotlin, Scala, Swift, Elixir, C/C++, or custom routers)
            # -----------------------------------------------------------------
            if len(self.routes) == routes_before:
                # Check Spring-style annotations (e.g. Kotlin @GetMapping) or Ktor/generic verb("/path")
                if "@GetMapping" in content or "@PostMapping" in content or "@RequestMapping" in content:
                    self._scan_java_files([(full_path, rel_path)])
                else:
                    univ_re = re.compile(
                        r"""\b(GET|POST|PUT|DELETE|PATCH|get|post|put|delete|patch)\b[^\n"']*["'](/[a-zA-Z0-9_./:{}-]+)["']"""
                    )
                    for um in univ_re.finditer(content):
                        http_verb = um.group(1).upper()
                        r_path = self._join_prefixes("", um.group(2).strip()) or "/"
                        start_l = content[: um.start()].count("\n") + 1
                        end_l = self._find_brace_end_line(lines, start_l - 1)
                        block_t = "\n".join(lines[start_l - 1 : end_l])
                        params = self._extract_polyglot_params(block_t, "", r_path)
                        self.routes.append(
                            RouteEntry(
                                method=http_verb,
                                path_pattern=r_path,
                                regex_pattern=_normalize_route_pattern_to_regex(r_path),
                                file_path=rel_path,
                                func_name=f"polyglot_{http_verb.lower()}_L{start_l}",
                                start_line=start_l,
                                end_line=end_l,
                                parameters=sorted(list(params)),
                                called_funcs=[],
                                auth_context="none",
                                framework=ext.lstrip(".") or "polyglot",
                            )
                        )

    @staticmethod
    def _find_brace_end_line(lines: List[str], start_idx: int) -> int:
        brace_depth = 0
        opened = False
        for idx in range(start_idx, len(lines)):
            line_s = lines[idx]
            if "{" in line_s:
                opened = True
            brace_depth += line_s.count("{") - line_s.count("}")
            if opened and brace_depth <= 0:
                return idx + 1
        return min(len(lines), start_idx + 25)

    @staticmethod
    def _find_ruby_end_line(lines: List[str], start_idx: int) -> int:
        depth = 0
        for idx in range(start_idx, len(lines)):
            s = lines[idx].strip()
            if not s or s.startswith("#"):
                continue
            if re.search(r"\b(?:def|do|class|module|if|case|begin)\b", s):
                depth += 1
            if re.search(r"\bend\b", s):
                depth -= 1
                if depth <= 0 and idx > start_idx:
                    return idx + 1
        return min(len(lines), start_idx + 25)

    @staticmethod
    def _extract_polyglot_params(block_text: str, raw_args: str, route_path: str) -> Set[str]:
        params: Set[str] = set()
        # Path variables: /orders/{id} or /orders/:id
        for m in re.finditer(r"\{([a-zA-Z_]\w*)\}|:([a-zA-Z_]\w*)", route_path or ""):
            params.add(m.group(1) or m.group(2))
        # Go: c.Query("q"), c.DefaultQuery("q", ...), c.Param("id"), c.PostForm("cmd"), r.URL.Query().Get("q"), r.FormValue("q")
        for m in re.finditer(
            r"""\b(?:Query|DefaultQuery|Param|PostForm|FormValue|Get)\s*\(\s*["']([a-zA-Z_]\w*)["']""",
            block_text,
        ):
            params.add(m.group(1))
        # PHP: $_GET['q'], $_POST['cmd'], $_REQUEST['id'], $request->input('q'), $request->query('q')
        for m in re.finditer(
            r"""(?:\$_(?:GET|POST|REQUEST)\s*\[\s*["']([a-zA-Z_]\w*)["']\s*\]|->\s*(?:input|query|get|post|route)\s*\(\s*["']([a-zA-Z_]\w*)["'])""",
            block_text,
        ):
            params.add(m.group(1) or m.group(2))
        # Ruby: params[:q] or params['q']
        for m in re.finditer(r"""\bparams\s*\[\s*(?::([a-zA-Z_]\w*)|["']([a-zA-Z_]\w*)["'])\s*\]""", block_text):
            params.add(m.group(1) or m.group(2))
        # C#: Request.Query["q"] or [FromQuery] string q / plain typed parameters
        for m in re.finditer(r"""\bQuery\s*\[\s*["']([a-zA-Z_]\w*)["']\s*\]""", block_text):
            params.add(m.group(1))
        for m in re.finditer(r"""\[\s*From(?:Query|Route|Form|Header)\s*(?:\([^)]*\))?\s*\]\s*[\w<>\?]+\s+([a-zA-Z_]\w*)""", raw_args or ""):
            params.add(m.group(1))
        # Plain C# / Rust / Kotlin typed arguments (excluding framework context types)
        for part in (raw_args or "").split(","):
            clean_p = re.sub(r"\[[^\]]*\]", "", part).strip()
            # C# style: string q, int id
            m_cs_arg = re.match(r"^(?:string|int|long|bool|double|decimal|Guid)\??\s+([a-zA-Z_]\w*)$", clean_p, re.IGNORECASE)
            if m_cs_arg:
                params.add(m_cs_arg.group(1))
        return params

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

        # 3. Fallback for pre-seeded routes when _compiled_matchers was not built via scan()
        for route in self.routes:
            if route.matches_url(clean_path, norm_method):
                return route
        for route in self.routes:
            if route.matches_url(clean_path, None):
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
        if route.covers_location(file_path, line):
            return True

        norm_target_file = file_path.replace("\\", "/").lstrip("./")
        norm_route_file = route.file_path.replace("\\", "/").lstrip("./")

        # 1. Direct handler match or explicit called_func_details coverage
        if norm_target_file == norm_route_file:
            if route.start_line <= line <= route.end_line:
                return True
        if hasattr(route, "covers_location") and route.covers_location(file_path, line):
            return True

        # 2. Check multi-hop called helpers across all definitions
        expanded_helpers = self._expand_called_functions(set(route.called_funcs), max_hops=max_hops)

        for helper_name in expanded_helpers:
            # Check multi-def store first
            for h_file, h_start, h_end, _, _ in self.func_defs.get(helper_name, []):
                norm_h = h_file.replace("\\", "/").lstrip("./")
                if norm_h == norm_target_file or norm_target_file.endswith("/" + norm_h) or norm_h.endswith("/" + norm_target_file):
                    if h_start <= line <= h_end:
                        return True
            # Fallback to single-def dict
            if helper_name in self.func_to_file_lines:
                h_file, h_start, h_end = self.func_to_file_lines[helper_name]
                norm_h = h_file.replace("\\", "/").lstrip("./")
                if norm_h == norm_target_file or norm_target_file.endswith("/" + norm_h) or norm_h.endswith("/" + norm_target_file):
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

    def find_routes_for_finding(self, file_path: str, line: int, max_hops: int = 3) -> List[RouteEntry]:
        """Return all RouteEntries whose handler or 1..3 hop helper covers `(file_path, line)`."""
        if not file_path or not line:
            return []
        matched: List[RouteEntry] = []
        for r in self.routes:
            if self.is_line_in_route(file_path, line, r, max_hops=max_hops):
                matched.append(r)
        return matched

    def resolve_dast_url(self, url_path: str, method: Optional[str] = None) -> List[RouteEntry]:
        """Return all RouteEntries matching `url_path` and optional HTTP `method`."""
        raw = (url_path or "").strip()
        if "://" in raw:
            from urllib.parse import urlparse
            clean_path = urlparse(raw).path or "/"
        else:
            clean_path = raw.split("?")[0].strip() or "/"
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        norm_method = method.upper().strip() if method else None
        exact: List[RouteEntry] = []
        fallback: List[RouteEntry] = []
        for route, comp in self._compiled_matchers:
            if comp.match(clean_path):
                if norm_method is None or route.method == norm_method:
                    exact.append(route)
                else:
                    fallback.append(route)
        return exact if exact else fallback


def build_route_map(source_dir: str) -> List[RouteEntry]:
    """Module-level entry point used by `api/main.py` to build the AST route map."""
    mapper = RouteMapper(source_dir)
    return mapper.scan()


def map_routes(source_dir: str) -> List[RouteEntry]:
    """Alias for `build_route_map`."""
    return build_route_map(source_dir)

