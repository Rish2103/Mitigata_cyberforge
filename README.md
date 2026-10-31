# CyberForge Correlate - SAST, 2-Phase DAST & Reachability-Aware SCA Correlation Engine

**Problem Statement 06: SAST + DAST Correlation Engine (Mitigata CyberForge Hackathon)**

CyberForge Correlate is an enterprise AppSec correlation engine that eliminates scanner alert fatigue by deterministically joining **Single-Pass AST Route & Taint Analysis (`O(N_ast + K_tainted_sinks)`)**, **2-Phase Scope-Locked DAST Verification**, and **5-Step Reachability-Aware SCA** into a single prioritized source of truth.

---

## Key Capabilities

1. **Deterministic AST Route-to-Sink Mapping (`FR-1`, `FR-4`):**
   - Extracts Flask, FastAPI, and Express route templates (`/orders/<int:order_id>` -> `/orders/{order_id}`), HTTP methods, parameters, and 3-hop cross-file helper call graphs (`services/order_service.py`) in a single AST pass (`O(N_ast + K_tainted_sinks)`).
2. **Safe Decoy Suppression Gate (`B-2`):**
   - Suppresses parameterized SQL queries (`cursor.execute(sql, (param,))`), `markupsafe.escape()` / `html.escape()` XSS guards, `subprocess.run([...], shell=False)` arrays, `os.path.realpath` prefix checks, and `urlparse` redirect allowlists before DAST probing.
3. **Runtime-Verified Adaptive DAST Scope Reduction (`FR-2`, Checkpoint 1 Judge Feedback):**
   - Compares static AST routes against live discovered endpoints (`EXACT_REPLICA` vs `RUNTIME_DRIFT_EXTRA`).
   - Skips active fuzzing on provably safe routes (`PRUNED_SAFE`), restricts tainted routes to only flagged `(param, CWE)` pairs (`TARGETED_REDUCTION`), and runs full 5-CWE active probing on unmapped runtime drift routes (`FULL_PROBE_DRIFT`), saving **>80% of active HTTP fuzzing traffic**.
4. **Zero-Wrong-Link Correlator & Idempotent SQLite Upserts (`FR-5`, `FR-6`, `FR-7`, `FR-9`):**
   - Enforces 4 hard vetoes (CWE mismatch, route mismatch, parameter conflict, and protected decoy status) to guarantee **0% wrong links**.
   - Computes deterministic SHA-256 fingerprints so running a scan twice produces **0 duplicate issues** and merges multi-scanner hits on the same bug into **1 `CorrelatedIssue`**.
5. **`B-1` Code-Only -> Confirmed Active Auto-Verifier:**
   - Synthesizes targeted diagnostic probes for `Code only` SAST findings mapped to AST routes and automatically upgrades verified bugs to `Confirmed` (`auto_verified = True`).
6. **5-Step Reachability-Aware SCA (`Page 4 Bonus`):**
   - Evaluates lockfiles (`requirements.txt`, `package.json`), OSV/GHSA advisories, vulnerable symbols, and AST import/call chains (`Reachable`, `Imported-only`, `Present-only`, `Unknown` - **never downgrading `Unknown`**) plus supply-chain typosquatting and dependency confusion flags.
7. **OASIS SARIF v2.1.0 Exporter & CI/CD Security Gate (`B-5`, `B-6`):**
   - Exports correlated findings and SCA reachability traces as standard **SARIF v2.1.0** (`GET /scans/{scan_id}/sarif`, `GET /export/sarif`).
   - Provides a deterministic CI/CD gate (`GET /scans/{scan_id}/ci-gate`, `GET /ci-gate`) returning `exit_code: 1` (`FAIL`) when any `Confirmed` Critical/High issue or `Reachable` CISA KEV SCA vulnerability is present.

---

## Quickstart (Local Python)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the Live Vulnerable Storefront (:5000) in Terminal 1
cd tests/mock_shop_app
python app.py

# 3. Start the CyberForge Correlate Control Plane & UI (:8000) in Terminal 2
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

- **CyberForge Correlate Dashboard:** http://localhost:8000
- **Live Vulnerable Storefront:** http://localhost:5000

---

## 1-Command Reproducibility (Docker Compose)

```bash
docker compose up --build
```

 This launches both `web-shop` (`http://localhost:5000`) and `cyberforge-correlate` (`http://localhost:8000`) on an isolated bridge network with the Target Safety Lock pre-configured.

---

## API Reference (`FR-10`, `B-5`, `B-6`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Engine liveness, Target Safety Lock allowlist, and credential isolation status |
| `POST` | `/scans` | Trigger end-to-end AST + SAST + Adaptive 2-Phase DAST + B-1 Auto-Verify + SCA scan |
| `GET` | `/scans` | List all executed scans with summary metrics and `scope_reduction` telemetry |
| `GET` | `/scans/{scan_id}` | Retrieve a single `ScanSummary` including `scope_reduction` telemetry |
| `GET` | `/scans/{scan_id}/sarif` | Export scan findings in OASIS **SARIF v2.1.0** format |
| `GET` | `/export/sarif` | Export latest scan findings in OASIS **SARIF v2.1.0** format |
| `GET` | `/scans/{scan_id}/ci-gate` | Evaluate deterministic CI/CD gate (`PASS` / `FAIL`, `exit_code: 0 | 1`) |
| `GET` | `/ci-gate` | Evaluate deterministic CI/CD gate for the latest scan |
| `GET` | `/scans/compare` | Compare two scans (`NEW`, `FIXED`, `STILL-OPEN` via SHA-256 fingerprints) |
| `GET` | `/issues` | Prioritized correlated issues (`Confirmed` ranked first, then by `risk_score`) |
| `GET` | `/issues/{issue_id}` | Unified issue detail view with Static Proof, Live HTTP Proof, Link Reason, and Fix |
| `GET` | `/routes` | Discovered AST Route Map (`RouteEntry` items) |
| `GET` | `/decoys` | Safe decoys suppressed by the `B-2` AST guard gate |
| `GET` | `/sca` | 5-Step Reachability-Aware SCA findings (`Reachable`, `Imported-only`, `Present-only`, `Unknown`) |

---

## Running Verification & Torture Tests

```bash
pytest -v
```
