"""
AST-based Route Mapper (FR-4).
Parses Flask, FastAPI, and Django applications using Python's standard `ast` module.
Extracts:
- URL patterns and normalizes them to regex matchers
- HTTP methods (GET, POST, PUT, DELETE, etc.)
- Controller handler functions with exact start_line and end_line
- Handler parameters (from function signature and request parameter accesses)
- 1-hop and multi-hop helper function calls
"""

import ast
import os
import re
from typing import List, Dict, Optional, Set, Tuple
from core.schemas import RouteEntry


def _normalize_route_pattern_to_regex(pattern: str) -> str:
    """
    Converts framework route patterns like:
      - Flask: /api/orders/<id> or /api/orders/<int:order_id>
      - FastAPI: /api/orders/{order_id}
      - Django: orders/<int:id>/
    into a standard regex pattern anchored with ^ and $.
    """
    # Remove leading/trailing slash inconsistencies for pattern matching
    clean = pattern.strip()
    if not clean.startswith("/"):
        clean = "/" + clean
    # Remove trailing slash for flexible matching
    clean_no_trail = clean.rstrip("/")
    if not clean_no_trail:
        clean_no_trail = "/"

    # Replace Flask converter patterns <converter:name> or <name>
    # e.g. <path:subpath> -> (?P<subpath>.*), <int:id> -> (?P<id>[^/]+), <id> -> (?P<id>[^/]+)
    def _flask_param(match):
        conv, name = match.group(1), match.group(2)
        if conv == "path":
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"
    regex = re.sub(r'<(?:(\w+):)?(\w+)>', _flask_param, clean_no_trail)

    # Replace FastAPI style {param} or {param:path} or {param:int}
    def _fastapi_param(match):
        name = match.group(1)
        conv = match.group(2) if match.group(2) else ""
        if conv == "path":
            return f"(?P<{name}>.*)"
        return f"(?P<{name}>[^/]+)"
    regex = re.sub(r'\{(\w+)(?::(\w+))?\}', _fastapi_param, regex)

    # Allow optional trailing slash
    return f"^{regex}/?$"


class FunctionVisitor(ast.NodeVisitor):
    """
    Inspects a function AST node to extract parameter accesses and called helper functions.
    """
    def __init__(self, func_node: ast.FunctionDef):
        self.func_node = func_node
        self.parameters: Set[str] = set()
        self.called_funcs: Set[str] = set()
        
        # Add function argument names (excluding self, cls)
        for arg in func_node.args.args:
            if arg.arg not in ("self", "cls", "request"):
                self.parameters.add(arg.arg)

    def visit_Call(self, node: ast.Call):
        # Detect helper function calls: func() or module.func() or self.func()
        if isinstance(node.func, ast.Name):
            self.called_funcs.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.called_funcs.add(node.func.attr)

        # Detect request parameter accesses:
        # Flask: request.args.get('param'), request.form.get('param'), request.values.get('param')
        # request.args['param'], request.json.get('param')
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.parameters.add(node.args[0].value)
                
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Detect request.args['param'], request.form['param']
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            # check if value is request.args or similar
            if isinstance(node.value, ast.Attribute):
                if node.value.attr in ("args", "form", "values", "json", "headers", "cookies"):
                    self.parameters.add(node.slice.value)
        self.generic_visit(node)


class RouteExtractor(ast.NodeVisitor):
    def __init__(self, file_path: str, rel_path: str):
        self.file_path = file_path
        self.rel_path = rel_path.replace("\\", "/")
        self.routes: List[RouteEntry] = []
        self.blueprint_prefixes: Dict[str, str] = {}  # blueprint var name -> url_prefix

    def visit_Assign(self, node: ast.Assign):
        # Detect Flask Blueprint definitions: bp = Blueprint('name', __name__, url_prefix='/api')
        if isinstance(node.value, ast.Call):
            func_name = ""
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            if func_name == "Blueprint":
                prefix = ""
                for kw in node.value.keywords:
                    if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant):
                        prefix = str(kw.value.value).rstrip("/")
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.blueprint_prefixes[target.id] = prefix
        self.generic_visit(node)

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
                
                # Extract parameters and called helpers from the function body
                visitor = FunctionVisitor(node)
                visitor.visit(node)

                # End lineno support
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
        """
        Parses decorator nodes and extracts (path_pattern, methods, framework).
        Supports:
        - Flask: @app.route('/path', methods=['GET', 'POST']), @bp.route('/path')
        - Flask shortcuts: @app.get('/path'), @bp.post('/path')
        - FastAPI: @app.get('/path'), @router.post('/path'), @app.api_route('/path', methods=['GET'])
        """
        if not isinstance(dec, ast.Call):
            return None

        call = dec
        func = call.func
        
        # Check call method name
        attr_name = ""
        obj_name = ""
        if isinstance(func, ast.Attribute):
            attr_name = func.attr
            if isinstance(func.value, ast.Name):
                obj_name = func.value.id
        elif isinstance(func, ast.Name):
            attr_name = func.id

        # Determine path
        path = ""
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            path = call.args[0].value
        else:
            # check keyword path
            for kw in call.keywords:
                if kw.arg in ("rule", "path") and isinstance(kw.value, ast.Constant):
                    path = str(kw.value.value)

        if not path:
            return None

        # Apply Blueprint prefix if applicable
        if obj_name in self.blueprint_prefixes and self.blueprint_prefixes[obj_name]:
            bp_prefix = self.blueprint_prefixes[obj_name]
            path = f"{bp_prefix}/{path.lstrip('/')}"

        # Determine HTTP methods
        methods = []
        framework = "flask"

        # Direct HTTP method shortcuts: .get, .post, .put, .delete, .patch
        if attr_name.lower() in ("get", "post", "put", "delete", "patch"):
            methods = [attr_name.upper()]
            framework = "fastapi" if "router" in obj_name.lower() or "app" in obj_name.lower() else "flask"
        elif attr_name in ("route", "api_route"):
            # Check methods kwarg: methods=['GET', 'POST']
            for kw in call.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            methods.append(elt.value.upper())
            if not methods:
                methods = ["GET"]  # Default Flask/FastAPI method if omitted
            framework = "fastapi" if attr_name == "api_route" else "flask"

        if methods:
            return (path, methods, framework)
        return None


class RouteMapper:
    """
    Engine that traverses a source directory, extracts all routes,
    and resolves live URL/method requests to corresponding RouteEntries.
    """
    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.routes: List[RouteEntry] = []
        self._compiled_matchers: List[Tuple[RouteEntry, re.Pattern]] = []
        self.call_graph: Dict[str, Set[str]] = {}  # func_name -> set of called_funcs
        self.func_to_file_lines: Dict[str, Tuple[str, int, int]] = {} # func_name -> (file, start, end)

    def scan(self) -> List[RouteEntry]:
        self.routes = []
        self._compiled_matchers = []
        self.call_graph = {}
        self.func_to_file_lines = {}

        for dirpath, _, filenames in os.walk(self.root_dir):
            # Skip hidden / venv / test / git folders
            parts = os.path.normpath(dirpath).split(os.sep)
            if any(p.startswith(".") or p in ("venv", ".venv", "__pycache__", "env", "node_modules") for p in parts):
                continue

            for fname in filenames:
                if fname.endswith(".py"):
                    full_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(full_path, self.root_dir).replace("\\", "/")
                    self._parse_python_file(full_path, rel_path)

        # Compile regex matchers
        for r in self.routes:
            pat = r.regex_pattern or _normalize_route_pattern_to_regex(r.path_pattern)
            try:
                comp = re.compile(pat, re.IGNORECASE)
                self._compiled_matchers.append((r, comp))
            except Exception:
                pass

        return self.routes

    def _parse_python_file(self, full_path: str, rel_path: str):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=rel_path)
            
            # Map top-level and class functions for call-graph resolution
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end_line = getattr(node, "end_lineno", node.lineno)
                    self.func_to_file_lines[node.name] = (rel_path, node.lineno, end_line)
                    vis = FunctionVisitor(node)
                    vis.visit(node)
                    self.call_graph[node.name] = vis.called_funcs

            # Extract routes
            extractor = RouteExtractor(full_path, rel_path)
            extractor.visit(tree)
            self.routes.extend(extractor.routes)
        except Exception:
            # Tolerant parsing: ignore non-python or malformed files
            pass

    def match_url(self, method: str, url_path: str) -> Optional[RouteEntry]:
        """
        Given an HTTP method (e.g. GET) and url path (e.g. /api/orders/42 or /api/orders?id=1),
        matches against the AST route map.
        """
        # Strip query string if provided
        clean_path = url_path.split("?")[0].strip()
        norm_method = method.upper()

        for route, comp in self._compiled_matchers:
            if route.method == norm_method and comp.match(clean_path):
                return route

        # Fallback: check without strict method if only path matches
        for route, comp in self._compiled_matchers:
            if comp.match(clean_path):
                return route

        return None

    def is_line_in_route(self, file_path: str, line: int, route: RouteEntry) -> bool:
        """
        Checks whether a given file_path and line number falls within the route's handler
        or any 1-hop / 2-hop helper function called by that handler.
        """
        norm_target_file = file_path.replace("\\", "/").lstrip("./")
        norm_route_file = route.file_path.replace("\\", "/").lstrip("./")

        # 1. Direct handler match
        if norm_target_file == norm_route_file:
            if route.start_line <= line <= route.end_line:
                return True

        # 2. Check 1-hop / 2-hop called helpers
        helpers_to_check = set(route.called_funcs)
        # expand 1 hop further
        expanded_helpers = set(helpers_to_check)
        for h in helpers_to_check:
            if h in self.call_graph:
                expanded_helpers.update(self.call_graph[h])

        for helper_name in expanded_helpers:
            if helper_name in self.func_to_file_lines:
                h_file, h_start, h_end = self.func_to_file_lines[helper_name]
                if h_file.replace("\\", "/").lstrip("./") == norm_target_file:
                    if h_start <= line <= h_end:
                        return True

        return False
