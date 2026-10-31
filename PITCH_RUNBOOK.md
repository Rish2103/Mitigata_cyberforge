# CyberForge Correlate - Phase 5 Checkpoint 2 & Final Jury Pitch Runbook

This runbook covers the **7:00 AM Unseen App Drop**, **8:30 AM Checkpoint 2 Evaluation**, and **11:00 AM Final Jury Pitch**.

---

## 1. Pre-Demo Terminal Setup (3 Terminals)

Run these commands from `d:\Mitigata` before going on stage or entering Checkpoint 2:

### Terminal 1: App 1 - Vulnerable Mock Shop (`:5000`)
```powershell
python -m tests.mock_shop_app.app
```

### Terminal 2: App 2 - Unseen Billing & Invoice Portal Simulator (`:5001`)
```powershell
python -m tests.unseen_app_sim.app
```

### Terminal 3: CyberForge Correlate Main Server & Dashboard (`:8000`)
```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000/` in your browser.

---

## 2. 7:00 AM Unseen App Drop Workflow (< 60 Seconds)

The moment the organizers drop the **Unseen Second Application** at `7:00 AM`:

1. **Run the Phase 5 Unseen-App Pre-Flight Doctor:**
   ```powershell
   python -m tests.phase5_unseen_doctor --source-dir <path_to_unseen_app> --target-url http://127.0.0.1:5001 --export-dir ./reports
   ```
2. **Verify the 4 Automated Checks in Console Output:**
   - **Routes Discovered:** Confirm `Unmapped Decorators: 0`. If the unseen app uses a non-standard decorator alias, add it to `engine/ast_route_extractor.py`.
   - **SAST & B-2 Decoy Gate:** Confirm `0% False Alarms` on safe decoys (parameterized SQL, `markupsafe.escape`, `yaml.safe_load`, `shell=False`, `realpath` prefix checks).
   - **Unseen App Metric #6:** Confirm `Correlation Rate >= 65%` (`100.0%` on both `mock_shop_app` and `unseen_app_sim`).
   - **Execution Time:** Confirm total runtime is well under the `60,000 ms` (`60s`) ceiling (`~25 ms` static+simulated, `<2s` live HTTP).
3. **Switch Target in Live UI (`http://127.0.0.1:8000/`):**
   - Click **`App 2: Unseen Billing (:5001)`** in the Target Configuration bar (or enter the unseen app's URL and source path) and click **`Run Correlation Scan`**.

---

## 3. 3-Minute Stage Script (Person A + Person B)

### 0:00 - 0:45 | Person A: Problem & Single-Pass AST Architecture
- **Hook:** "Traditional AppSec pipelines run SAST and DAST in silos. SAST floods developers with false positives on sanitized code, while DAST blindly fires thousands of payloads at every endpoint."
- **Architecture:** "CyberForge Correlate bridges both worlds in a **Single-Pass AST Walk** with complexity $\mathcal{O}(N_{\text{ast}} + K_{\text{tainted\_sinks}})$. Before firing a single HTTP packet, we extract canonical routes, handler parameters, taint sinks, and import graphs. That lets our **Adaptive Scope Reducer** skip safe routes and cut **90% of active DAST HTTP traffic**."

### 0:45 - 2:15 | Person B: Live Multi-App Demo (`:5000` -> `:5001`)
1. **Scan App 1 (`:5000` Mock Shop):**
   - Click **`App 1: Mock Shop (:5000)`** -> **`Run Correlation Scan`**.
   - Point to the **Judge Complexity & Scope Reduction Banner**: `Naive: 70 -> Reduced: 7 (90.0% Active HTTP Traffic Saved)` and `CI Gate: FAIL`.
   - Point to the **KPI Cards**: `5 Confirmed`, `1 Code Only`, `1 Runtime Only`, and `5 Safe Decoys (0% False Alarms)`.
   - Click **`Verify Idempotency (2x)`** to prove running the same scan twice produces **zero duplicate rows** via deterministic SHA-256 fingerprinting.
2. **Switch Live to App 2 (`:5001` Unseen Billing App):**
   - Click **`App 2: Unseen Billing (:5001)`** -> **`Run Correlation Scan`**.
   - Show that with **zero hardcoded paths or rules**, CyberForge discovers all `12` multi-file Blueprint routes (`/api/v1/billing/...`), suppresses all `5` safe decoys, and achieves a **100% Correlation Rate** in under 1 second.
3. **Open Slide-Over Evidence Inspector & Remediation Diff (`B-4`):**
   - Click a **Confirmed `CWE-89` SQL Injection** row.
   - Show side-by-side **Static AST Proof** (`file:line`), **Live DAST HTTP Proof** (baseline vs attack differential), **B-3 Natural-Language Link Reason**, and the **B-4 Before/After Code Remediation Diff**.
4. **Show 5-Step SCA Call-Graph Reachability & SARIF Export:**
   - Switch to **SCA Reachability** tab: show `pyyaml==5.3.1` flagged as **Reachable** (because `yaml.load` is called in route handlers), `urllib3==1.26.4` downgraded by `-3.0` CVSS as **Unreachable**, and `reqeusts` caught as a **Typosquat** (`Levenshtein = 1`).
   - Click **`Export SARIF v2.1.0`** to download a GitHub Code Scanning compliant report.

### 2:15 - 3:00 | Person A: Bonus Hooks (`B-1` to `B-4`) & Verification Benchmark
- Switch to Terminal and run:
  ```powershell
  python -m tests.demo_checkpoint1 --full-benchmark
  python -m tests.phase5_unseen_doctor
  ```
- Highlight all **7/7 Great Thresholds PASS**:
  - **B-1 Auto-Verification:** Targeted DAST probes automatically promote static sinks to `Confirmed`.
  - **B-2 False-Positive Filter:** `0%` false alarms across all safe decoys.
  - **B-3 Link Explanation:** Deterministic route + parameter + CWE explanation on every finding.
  - **B-4 Remediation Guidance:** Copy-pasteable `Before -> After` code diffs.

---

## 4. Judge Q&A Quick Cheat Sheet

| Judge Question | Winning Answer |
| :--- | :--- |
| **"How do you avoid DAST blindly fuzzing everything?"** | "Our `engine/scope_reducer.py` uses SAST taint sinks to compute `ScopeReductionReport`: instead of `12 routes x 5 CWE probes = 60 requests`, we only probe the exact `(route, param, CWE)` tuples flagged by AST taint analysis (`6 requests`), saving **90.0% of active HTTP traffic**." |
| **"What happens if someone enters a public IP like `8.8.8.8` or `192.168.x.x`?"** | "`core/safety.py` enforces `validate_target_url()` before any socket opens. Only loopback (`127.0.0.1`, `localhost`, `::1`) and Docker-internal ranges (`172.16.0.0/12`, `10.0.0.0/8`) are allowed; LAN and WAN targets immediately return `HTTP 403 TargetOutOfScopeError`." |
| **"How does your SCA avoid alerting on unused dependencies?"** | "`scanners/sca_scanner.py` performs a **5-step AST reachability pipeline**: (1) dependency parse, (2) OSV/CISA KEV match, (3) AST import detection, (4) call-graph sink verification (`yaml.load`), and (5) Levenshtein typosquatting check (`reqeusts` vs `requests`). Unimported packages get a `-3.0` CVSS reduction." |
| **"How do you prevent duplicate issues across repeated CI runs?"** | "Every correlated issue gets a deterministic SHA-256 fingerprint over `(cwe, canonical_path, file_path, param)`. SQLite `ON CONFLICT(fingerprint) DO UPDATE` guarantees idempotent upserts and powers `/scans/compare` (`NEW`, `FIXED`, `STILL-OPEN`)." |
