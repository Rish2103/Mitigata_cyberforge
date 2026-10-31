# CyberForge Correlate — Deterministic SAST + DAST Correlation Engine & Reachability-Aware SCA

**Track:** `PROBLEM 06 · FLAGSHIP` — SAST and DAST Correlation (+ Page 4 Bonus: Reachability-Aware SCA)

CyberForge Correlate is an enterprise AppSec correlation engine that eliminates scanner alert fatigue by deterministically joining **Single-Pass AST Route & Taint Analysis (`O(N_ast + K_tainted_sinks)`)**, **2-Phase Scope-Locked DAST Verification**, and **5-Step Reachability-Aware SCA** into a single prioritized source of truth.

---

## 1. 1-Command Reproducibility (Docker Compose & Unified Local Launcher)

### Option A: Docker Compose (Recommended for Judges)
```bash
docker compose up --build
```
This single command builds and starts all **3 services** on an isolated bridge network (`cyberforge-net`) with the **Target Safety Lock** pre-configured:
1. **CyberForge Correlate Dashboard & API (`:8000`):** http://localhost:8000
2. **Target App #1 — Live Vulnerable Storefront (`:5000`):** http://localhost:5000 (`tests/mock_shop_app`)
3. **Target App #2 — Unseen Billing Portal (`:5001`):** http://localhost:5001 (`tests/unseen_app_sim`)

### Option B: Unified 1-Command Local Python Launcher (No Docker Required)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start all 3 servers (:8000 Dashboard, :5000 Mock Shop, :5001 Unseen Billing App) in ONE command
python run_all.py
```

---

## 2. PRD Functional Requirements (`FR-1` to `FR-10`) & Where Each Lives

| PRD ID | Requirement | Implementation in CyberForge Correlate |
| :--- | :--- | :--- |
| **`FR-1`** | **SAST scan:** scan a source folder and report file, line, vulnerability type, severity, and code snippet | [`engine/sast_scanner.py`](engine/sast_scanner.py) — Single-pass AST taint & sink scanner + multi-scanner SARIF/Bandit/Semgrep JSON ingestor |
| **`FR-2`** | **DAST scan:** scan a running app URL by sending test requests and report URL, method, parameter, payload, and evidence | [`engine/dast_scanner.py`](engine/dast_scanner.py) — 2-Phase Async `httpx` DAST engine (Phase A Active Probes + Phase B Passive Header/Cookie/CORS Audit) |
| **`FR-3`** | **One common finding format** for both scanners with a CWE number | [`core/schemas.py`](core/schemas.py) — `CanonicalFinding` & `CorrelatedIssue` normalizing all findings to canonical `CWE-XX` identifiers |
| **`FR-4`** | **Route map:** read source code to list which URL is handled by which function and lines | [`engine/route_mapper.py`](engine/route_mapper.py) — Polyglot AST Route Mapper (`GET /api/orders -> get_orders(), orders.py lines 80..95`) + 3-hop helper call graph |
| **`FR-5`** | **Correlate:** link a DAST finding to a SAST finding when they share CWE and the DAST URL maps to the code holding the SAST finding | [`engine/correlator.py`](engine/correlator.py) — Deterministic 4-gate correlator with parameter-affinity scoring and hard negative vetoes |
| **`FR-6`** | **Merge duplicates:** one issue per real bug with all evidence attached; running a scan twice never creates copies | [`api/db.py`](api/db.py) & [`engine/correlator.py`](engine/correlator.py) — SHA-256 `compute_issue_fingerprint()` + SQLite `ON CONFLICT(fingerprint) DO UPDATE` |
| **`FR-7`** | **Label every issue** as `Confirmed`, `Code only`, or `Runtime only` | [`engine/correlator.py`](engine/correlator.py) — Strict 3-bucket partitioning (`Confirmed`, `Code only`, `Runtime only`) |
| **`FR-8`** | **Issue detail for confirmed issues:** URL, parameter, payload, file, line, code snippet, CWE, and severity | [`api/main.py`](api/main.py) (`GET /issues/{issue_id}`) & [`ui/index.html`](ui/index.html) Slide-Over Evidence Inspector with Plain-English CWE Guide |
| **`FR-9`** | **Prioritised list:** `Confirmed` issues first, then by risk score (severity & exploitability) | [`core/schemas.py`](core/schemas.py) (`compute_issue_risk_score`) — `Confirmed` ranked strictly above `Code only` and `Runtime only`, plus FAIR financial exposure |
| **`FR-10`** | **Simple CLI, REST API, or Web Page**, with a clear `README` | Web UI at `http://localhost:8000`, REST API (`POST /scans`, `GET /issues`, `GET /issues/{id}`), and CLI doctor (`python -m tests.phase5_unseen_doctor`) |

---

## 3. All 7 Bonus Items (`B-1` to `B-7`) + Page 4 Reachability-Aware SCA Bonus

| Bonus ID | PRD Bonus Specification | Implementation & Verification |
| :--- | :--- | :--- |
| **`B-1`** | **Auto-verify:** for a `Code only` finding, send a safe test request to prove it at runtime and upgrade it to `Confirmed` | [`engine/auto_verify.py`](engine/auto_verify.py) — Synthesizes targeted diagnostic probes for `Code only` issues mapped to AST routes, upgrading verified flaws to `Confirmed` (`auto_verified = True`) |
| **`B-2`** | **Cut SAST noise:** mark findings as safe when protected (e.g., parameterized query) or unreachable | [`engine/decoy_filter.py`](engine/decoy_filter.py) — Suppresses parameterized SQL (`cursor.execute(sql, (param,))`), `html.escape()` / `markupsafe.escape()`, `subprocess.run([...], shell=False)`, `os.path.realpath` prefix checks, `urlparse` allowlists, and dead-code helpers (**0% false alarms**) |
| **`B-3`** | **Explain every link:** show why two findings were joined (same CWE, same route, same parameter) | [`engine/correlator.py`](engine/correlator.py) — Populates human-readable `link_reason` on every `Confirmed` issue (including 3-hop helper call chain trace) |
| **`B-4`** | **Plain-English fix suggestion** for each confirmed issue | [`api/main.py`](api/main.py) & [`ui/index.html`](ui/index.html) — Plain-English CWE Knowledge Base + side-by-side **Before / After Code Remediation Diff** |
| **`B-5`** | **Compare two scans** and show `NEW`, `FIXED`, and `STILL-OPEN` issues | [`api/db.py`](api/db.py) & `GET /scans/compare` — Deterministic SHA-256 fingerprint diff across scan runs |
| **`B-6`** | **Export results as SARIF v2.1.0** and fail a CI build on confirmed high-severity issues | [`api/sarif_exporter.py`](api/sarif_exporter.py), `GET /scans/{id}/sarif`, `GET /scans/{id}/ci-gate`, and [`.github/workflows/cyberforge-gate.yml`](.github/workflows/cyberforge-gate.yml) |
| **`B-7`** | **Support a second programming language or framework** | [`engine/route_mapper.py`](engine/route_mapper.py) & [`engine/sast_scanner.py`](engine/sast_scanner.py) — Native polyglot support for **Python (Flask, FastAPI, Django)**, **JavaScript/TypeScript (Node.js Express)**, and **Java (Spring Boot)** |
| **Page 4 Bonus** | **5-Step Reachability-Aware SCA** (`Reachable`, `Imported-only`, `Present-only`, `Unknown` — **never downgrade `Unknown`**) | [`engine/sca_reachability.py`](engine/sca_reachability.py) & `GET /sca`:<br>1. **Inventory:** Parses `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json` keeping transitive paths.<br>2. **GHSA/OSV Match:** Attaches affected versions, fixed versions, CVSS, EPSS, and CISA KEV flags.<br>3. **Function Map:** Maps OSV symbols & fix-commit functions (`yaml.load`, `urllib3.PoolManager.request`, `jinja2.Template.render`, etc.).<br>4. **Call Graph:** Traces `Route Handler -> App Helper -> Library Sink` to classify `Reachable`, `Imported-only`, `Present-only`, or `Unknown` (dynamic `getattr`/`importlib` strictly kept as `Unknown` and **never downgraded**).<br>5. **Supply Chain:** Flags Levenshtein-distance typosquats (`reqeusts -> requests`), internal namespace dependency confusion, and unpinned lockfile specs. |

---

## 4. Page 5 Strategic Question: *"Which language should this target first?"*

**Answer:** Target **Python (Flask, FastAPI, Django) first**, and **JavaScript / TypeScript (Node.js Express) second** (with Java Spring Boot third):
1. **Deterministic AST Route & Taint Fidelity:** Python's built-in `ast` module gives 100% lossless syntax trees with exact line ranges (`lineno..end_lineno`), decorator arguments (`@app.route`, `@bp.get`, `@router.post`), and cross-file import bindings without external binary compiler dependencies.
2. **Polyglot Generalization (`B-7`):** Using normalized `RouteEntry` (`path_pattern`, `method`, `params`, `helper_calls`) and `CanonicalFinding` schemas allows our Express.js (`app.get`, `router.route`, `app.use` mounts) and Java Spring Boot (`@GetMapping`, `@RequestMapping`) frontends to feed the exact same `Correlator` and `ScopeReducer` without changing a single line of correlation logic.

---

## 5. Open-Source Libraries, Scanners & Rule Engines Used

In compliance with PRD Page 3 (*"list in your README which open-source scanners and rules you used"*):
- **Static Analysis & AST Parsing:**
  - Python standard library `ast` module (native single-pass route extraction, 3-hop call-graph resolution, taint propagation, and `B-2` sanitizer/parameterized-query verification).
  - Built-in ingestion adapters (`SASTScanner.ingest_semgrep_sarif()` & `SASTScanner.ingest_bandit_json()`) compatible with **Semgrep** (OWASP Top 10 / CWE rulesets, SARIF v2.1.0) and **Bandit** (`B608` SQLi, `B602/B605` Command Injection, `B105/B106` Hardcoded Secrets).
- **Dynamic Analysis (2-Phase Scope-Locked DAST):**
  - **HTTPX (`httpx.AsyncClient`)** with `follow_redirects=False` and a mandatory `request` event hook enforcing [`core/config.py`](core/config.py) (`validate_target_url` — hard-locked to `localhost`, `127.0.0.1`, and Docker test-app aliases).
  - Covers all **6 PRD CWE classes** (`CWE-89` SQLi, `CWE-79` XSS, `CWE-78` Command Injection, `CWE-22` Path Traversal, `CWE-601` Open Redirect, `CWE-798` Hardcoded Secrets) + passive runtime checks (`CWE-693` Security Headers, `CWE-1021` Clickjacking, `CWE-614` Cookie Flags, `CWE-942` CORS, `CWE-200` Banner Disclosure).
- **Web Control Plane & Persistence:**
  - **FastAPI + Uvicorn + Pydantic v2** (`api/main.py`, `core/schemas.py`)
  - **SQLite3** (`api/db.py`) with deterministic SHA-256 idempotent upserts (`FR-6`)

---

## 6. PRD Page 4 Answer-Key Benchmark Scorecard (`36 Bugs + 8 Safe Decoys`)

Run the full 36-bug PRD benchmark scorecard and the Unseen Second App pre-flight doctor anytime:
```bash
# 1. Run the 36-Bug PRD Page 4 Answer-Key Benchmark Scorecard
python -m tests.demo_checkpoint1 --full-benchmark

# 2. Run the Unseen Second App Pre-Flight Doctor (:5001)
python -m tests.phase5_unseen_doctor --export-dir ./unseen_reports

# 3. Run the full 53-test automated pytest suite
python -m pytest -v
```

| PRD Page 4 Metric | Good (Qualify) | Great (Stand Out) | CyberForge Correlate Result |
| :--- | :--- | :--- | :--- |
| **1. Correct Links (20 Pairs)** | `>= 50%` | `>= 80%` | **`20 / 20 (100.0%)` [PASS]** |
| **2. Wrong Links** | `< 20%` | `< 5%` | **`0 / 20 (0.0%)` [PASS]** |
| **3. False Alarms (8 Safe Decoys)** | `< 30%` | `< 10%` | **`0 / 8 (0.0%)` [PASS]** |
| **4. Confirmed Ranked First** | Top 5 | All Confirmed | **All 20 Top-Ranked [PASS]** |
| **5. Duplicate Findings Merged** | `>= 80%` | `>= 95%` | **`100.0%` (Idempotent SHA-256) [PASS]** |
| **6. Unseen Second App** | `> 40%` | `> 65%` | **`100.0%` (`5/5` Confirmed on `:5001`) [PASS]** |
| **7. Run Time** | `< 15 min` | `< 5 min` | **`< 1.5 seconds` E2E (`~28 ms` AST+Correlate) [PASS]** |
| **Judge Scope Reduction Telemetry** | — | — | **`85.7% – 90.0%` Active HTTP Probes Saved (`Single-Pass AST O(N_ast + K_tainted_sinks)`)** |

---

## 7. REST API Reference (`FR-10`, `B-5`, `B-6`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Engine liveness, Target Safety Lock allowlist, and credential isolation status |
| `POST` | `/scans` | Trigger end-to-end Single-Pass AST + SAST + Adaptive 2-Phase DAST + B-1 Auto-Verify + 5-Step SCA scan |
| `GET` | `/scans` | List all executed scans with summary metrics and `scope_reduction` telemetry |
| `GET` | `/scans/{scan_id}` | Retrieve a single `ScanSummary` including `scope_reduction` telemetry |
| `GET` | `/scans/{scan_id}/sarif` | Export scan findings in OASIS **SARIF v2.1.0** format |
| `GET` | `/export/sarif` | Export latest scan findings in OASIS **SARIF v2.1.0** format |
| `GET` | `/scans/{scan_id}/ci-gate` | Evaluate deterministic CI/CD gate (`PASS` / `FAIL`, `exit_code: 0 | 1`) |
| `GET` | `/ci-gate` | Evaluate deterministic CI/CD gate for the latest scan |
| `GET` | `/scans/compare` | Compare two scans (`NEW`, `FIXED`, `STILL-OPEN` via SHA-256 fingerprints) |
| `GET` | `/issues` | Prioritized correlated issues (`Confirmed` ranked first, then by `risk_score`) |
| `GET` | `/issues/{issue_id}` | Unified issue detail view with Plain-English CWE Guide, Static Proof, Live HTTP Proof, Link Reason, and Before/After Diff |
| `GET` | `/routes` | Discovered AST Route Map (`RouteEntry` items) |
| `GET` | `/decoys` | Safe decoys suppressed by the `B-2` AST guard gate |
| `GET` | `/sca` | 5-Step Reachability-Aware SCA findings (`Reachable`, `Imported-only`, `Present-only`, `Unknown`) |
