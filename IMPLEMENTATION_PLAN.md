# CyberForge (Mitigata Hackathon) — 24-Hour Phase-Wise Implementation Plan
**Track:** `PROBLEM 06 · FLAGSHIP` — SAST and DAST Correlation (`GORDON CORRELATE`)  
**Format:** 24-Hour Overnight Sprint · Team of 2 (`Person A` + `Person B`)  
**Current Time:** `1:30 PM (Day 1)` → **1st Checkpoint:** `4:00 PM (Day 1)` → **2nd Checkpoint:** `9:00 AM (Day 2)` → **Build Clock Closes:** `11:00 AM (Day 2)`

---

## 1. Team of 2 Role Split (Zero Merge-Conflict Boundary)

To move at maximum speed without stepping on each other's files, split the system along a **single JSON/Python data contract (`schemas.py`)** agreed upon in the first 15 minutes:

| Role | Owner | Core Ownership (Files You Touch) | PRD Requirements Owned |
| :--- | :--- | :--- | :--- |
| **Person A — Static Intelligence, AST & Correlation Engine Lead** | **Member 1** | `engine/route_mapper.py`, `engine/sast_scanner.py`, `engine/decoy_filter.py`, `engine/correlator.py`, `engine/sca_reachability.py` | **`FR-1`** (SAST Scan), **`FR-4`** (AST Route Map + Call Graph), **`FR-5`** (Multi-Signal Correlator), **`FR-6`** (Duplicate Merger), **`B-2`** (Safe Decoy Killer), **`B-3`** (Link Explanation), **`B-7`** (2nd Language Adapter), **Page 4 Bonus** (5-Step Reachability-Aware SCA) |
| **Person B — Runtime DAST Engine, API/Storage & Dashboard Lead** | **Member 2** | `engine/dast_scanner.py`, `engine/auto_verify.py`, `api/main.py`, `api/db.py`, `api/exporters.py`, `ui/`, `docker-compose.yml`, `README.md` | **`FR-2`** (2-Phase DAST Scan: Active + Passive Runtime-Only), **`FR-3`** (Common Finding Schema), **`FR-7`** (3-Bucket Labels), **`FR-8`** (Issue Detail View), **`FR-9`** (Prioritised Risk Score), **`FR-10`** (FastAPI + UI + CLI), **`B-1`** (Auto-Verify), **`B-4`** (Fix Suggestions), **`B-5`** (Scan Diffing), **`B-6`** (SARIF Export & CI Gate) |

---

## 2. Git Repository Structure & Branching Workflow

### 2.1 Recommended Repository Layout

```text
gordon-correlate/
├── README.md                        # Setup, architecture, open-source disclosure (PRD Rule 2)
├── docker-compose.yml               # 1-command startup for judges (PRD Page 4 "Must run easily")
├── requirements.txt                 # FastAPI, uvicorn, httpx, tree-sitter, semgrep/bandit, pydantic
├── cli.py                           # CLI entrypoint + CI exit-code gate (FR-10, B-6)
│
├── core/                            # LOCKED AT 1:45 PM (Shared by Person A & Person B)
│   ├── __init__.py
│   ├── schemas.py                   # FR-3 Canonical Finding, RouteEntry, CorrelatedIssue models
│   └── config.py                    # Localhost/Test-App Scope Guard (PRD Rule 1 safety lock)
│
├── engine/                          # PERSON A's Folder (except dast_scanner.py & auto_verify.py)
│   ├── __init__.py
│   ├── route_mapper.py              # [Person A] FR-4: AST Route Map + function call graph
│   ├── sast_scanner.py              # [Person A] FR-1: SAST (CWE-89,79,78,22,601,798) + SARIF/Bandit
│   ├── decoy_filter.py              # [Person A] B-2: Marks parameterised queries & dead code as safe
│   ├── dast_scanner.py              # [Person B] FR-2: Async httpx active prober + passive header audit
│   ├── auto_verify.py               # [Person B] B-1: Targeted runtime probe to upgrade Code-only
│   ├── correlator.py                # [Person A] FR-5, FR-6, FR-7, FR-9, B-3: Linker & Deduplicator
│   └── sca_reachability.py          # [Person A] Page 4 Bonus: 5-step Reachability-Aware SCA
│
├── api/                             # PERSON B's Folder
│   ├── __init__.py
│   ├── db.py                        # [Person B] SQLite persistence + FR-6 idempotent scan storage
│   ├── main.py                      # [Person B] FR-10: POST /scans, GET /issues, GET /issues/{id}
│   ├── diff_engine.py               # [Person B] B-5: Compare two scans (new, fixed, still-open)
│   └── sarif_exporter.py            # [Person B] B-6: Export SARIF v2.1.0
│
├── ui/                              # PERSON B's Folder
│   └── index.html                   # [Person B] FR-8, FR-9: Single-page dark dashboard (Tailwind)
│
└── tests/
    ├── mock_shop_app/               # Mini test app for pre-kickoff / unit testing
    └── test_correlation.py          # Automated verification of 0% wrong links & 0% false alarms
```

### 2.2 Git Branching & Merge Rules (For a 2-Person Team)

1. **`main` branch:** Always working, always demoable. Never push broken code directly to `main`.
2. **Feature branches by owner:**
   - **Person A branches:** `feat/a-route-map`, `feat/a-sast-core`, `feat/a-correlator`, `feat/a-decoy-filter`, `feat/a-sca-bonus`, `feat/a-second-lang`
   - **Person B branches:** `feat/b-dast-core`, `feat/b-api-ui`, `feat/b-auto-verify`, `feat/b-scan-diff-sarif`, `feat/b-docker-polish`
3. **The 15-Minute Contract Lock (`1:30 PM – 1:45 PM`):**
   - Sit together for 15 minutes, write `core/schemas.py` (`RouteEntry`, `CanonicalFinding`, `CorrelatedIssue`), commit it to `main`, and both pull `main`.
   - Because Person A works inside `engine/{route_mapper,sast_scanner,decoy_filter,correlator,sca_reachability}.py` and Person B works inside `engine/{dast_scanner,auto_verify}.py`, `api/`, and `ui/`, **you will have 0 merge conflicts for the entire 24 hours**.
4. **Sync Cadence:** Merge to `main` via fast PRs every **90 minutes** (at `3:15 PM`, `6:30 PM`, `9:00 PM`, `12:00 AM`, `4:00 AM`, `8:00 AM`).

---

## 3. Phase-by-Phase Schedule Mapped to the Official CyberForge Agenda

### PHASE 1: `1:30 PM – 4:00 PM` (2.5 Hours) — **Sprint to 1st Checkpoint (Working End-to-End Prototype Without Compromising Architecture)**

> **Goal for 4:00 PM Mentor Checkpoint:** Show mentors a **real, non-faked vertical slice** running end-to-end on the organisers' test app (or a 6-route replica if the test app is still spinning up):
> 1. Reads the source code to build a real **AST Route Map (`FR-4`)** (`GET /api/orders -> get_orders(), orders.py:80–95`).
> 2. Runs real **SAST (`FR-1`)** + **Safe Decoy Suppression (`B-2`)** on SQLi (`CWE-89`), XSS (`CWE-79`), and Hard-coded Secrets (`CWE-798`).
> 3. Runs real **DAST (`FR-2`)** sending live HTTP requests (`GET /api/orders?id=1'`) + passive header checks.
> 4. Links them via the **Deterministic Correlator (`FR-5`, `FR-6`, `FR-7`, `FR-9`)** into `Confirmed`, `Code only`, and `Runtime only` buckets and displays them on `POST /scans` & `GET /issues` (`FR-10`).

#### Minute-by-Minute Breakdown (`1:30 PM – 4:00 PM`)

| Time Window | Person A (Static, AST & Correlation) | Person B (Runtime DAST, API & UI) |
| :--- | :--- | :--- |
| **`1:30 – 1:45 PM`**<br>*(15 mins — Together)* | **Lock `core/schemas.py` & `core/config.py` on `main`:**<br>• Define `RouteEntry(method, path_pattern, regex, file, func_name, start_line, end_line, params, called_funcs)`<br>• Define `CanonicalFinding(source="SAST"\|"DAST", cwe="CWE-89", severity, file, line, snippet, url, method, param, payload, evidence, is_protected_decoy)`<br>• Define `CorrelatedIssue(id, status="Confirmed"\|"Code only"\|"Runtime only", cwe, severity, risk_score, sast_evidence, dast_evidence, link_reason, fix_suggestion)` | **Initialize Repo + FastAPI Skeleton (`api/main.py`, `api/db.py`):**<br>• Set up SQLite tables (`scans`, `findings`, `issues`)<br>• Enforce **Target Safety Lock (`core/config.py`)**: DAST refuses any URL not matching `localhost`, `127.0.0.1`, or the local Docker test-app container. |
| **`1:45 – 2:35 PM`**<br>*(50 mins — Hack Hours)* | **Build `engine/route_mapper.py` (`FR-4`):**<br>• Use Python's built-in `ast` module to parse all `.py` files in the target folder.<br>• Extract Flask (`@app.route`, `@bp.get/post`), FastAPI (`@app.get/post`), and Django (`path()`) routes.<br>• Record `file`, `function_name`, `lineno`, `end_lineno`, parameter names (`request.args.get('id')`), and 1-hop helper calls (`db.query_orders()`). | **Build `engine/dast_scanner.py` (`FR-2` Core):**<br>• Build async `httpx` scanner that takes the target base URL + `RouteEntry` list.<br>• Implement **SQLi (`CWE-89`)** probe (`' OR '1'='1`, `1'`) checking for DB error signatures / boolean diffs.<br>• Implement **XSS (`CWE-79`)** probe (`<script>gordon_canary_79</script>`) checking unescaped reflection.<br>• Implement **Phase B Passive Header Check** (`Missing CSP / X-Frame-Options / HttpOnly cookie`) so `Runtime only` (`FR-7`) works at Checkpoint 1! |
| **`2:35 – 3:15 PM`**<br>*(40 mins — Hack Hours)* | **Build `engine/sast_scanner.py` (`FR-1`) + `engine/decoy_filter.py` (`B-2`) + `engine/correlator.py` (`FR-5`–`FR-9`):**<br>• AST detector for `CWE-89` (f-string / `%` / `+` SQL queries), `CWE-79` (unescaped template/HTML return), `CWE-798` (hard-coded API keys/passwords).<br>• **`B-2` Decoy Filter:** If `cursor.execute(query, (param,))` has a 2nd tuple/list argument, mark `is_protected_decoy=True` and suppress!<br>• **`FR-5` Correlator:** Join `DAST` and `SAST` when `dast.cwe == sast.cwe` AND `dast.url` matches `RouteEntry` covering `sast.file:sast.line` (or its called helper). Populate `B-3` `link_reason`. | **Build `api/main.py` (`FR-10`) + `ui/index.html` (`FR-8`, `FR-9`):**<br>• Implement `POST /scans` (runs `route_mapper` → `sast_scanner` → `dast_scanner` → `correlator`, saves to SQLite).<br>• Implement `GET /issues` (returns prioritised list: `Confirmed` first, then by risk score `FR-9`) and `GET /issues/{id}` (`FR-8` detail).<br>• Build clean 1-page UI showing: Summary counters (`Confirmed`, `Code only`, `Runtime only`, `Safe Decoys Suppressed`), the Route Map table (`FR-4`), and expandable Issue Detail cards (`FR-8`). |
| **`3:15 – 3:30 PM`**<br>*(15 mins — Integration)* | **Merge `feat/a-*` and `feat/b-*` into `main`:**<br>• Run end-to-end scan on the test app.<br>• Verify `FR-6` idempotency: click "Run Scan" twice and prove issue count does NOT double! | **Prep 3-Minute Mentor Demo Script:**<br>• Keep browser tab open on `http://localhost:8000` + terminal ready to run `POST /scans`. |
| **`3:30 – 4:00 PM`**<br>*(Hi-Tea & Snacks)* | Quick refresh + sanity-check demo before mentors arrive at `4:00 PM`. | Quick refresh + verify Docker / local ports are stable. |

#### What You Show Mentors at `4:00 PM` (1st Checkpoint)
1. *"Correlation is what the PRD judges most, so we built the **AST Route-to-Sink Mapper (`FR-4`)** and **Deterministic Correlator (`FR-5`)** first instead of a hard-coded wrapper."*
2. Live click **Scan**: show a **`Confirmed` SQL Injection (`CWE-89`)** linking `GET /api/orders?id=1'` directly to `orders.py:88` with the `B-3` explanation badge (`Same CWE-89 + Route /api/orders handled by get_orders() lines 80-95 + Param id`).
3. Show a **`Code only` Hard-coded Secret (`CWE-798`)**, a **`Runtime only` Missing Security Header**, and a **Suppressed Safe Decoy (`B-2` parameterised query)**—proving all 3 buckets (`FR-7`) and decoy suppression work at 4:00 PM!

---

### PHASE 2: `4:00 PM – 9:00 PM` (Day 1 Evening) — **Full 6-CWE Coverage, Auth Handling & `B-1` Auto-Verify**

*Agenda Context: `4:00–7:00 PM` Hack Hours & 1st Checkpoint · `7:00–7:30 PM` Icebreaker 1 · `7:30–9:00 PM` Hack Hours · `9:00–10:00 PM` Dinner.*

**Goal by 9:00 PM Dinner:** Hit the **"Great"** column on **Code Detection (`>85%` of 30 code bugs)**, **Runtime Detection (`>80%` of 26 runtime bugs)**, **Correct Links (`>80%` of 20 pairs)**, **Wrong Links (`<5%` = strictly `0` wrong links)**, and **False Alarms (`<10%` on the 8 safe decoys)**.

| Time Window | Person A (Static, AST & Correlation) | Person B (Runtime DAST, API & UI) |
| :--- | :--- | :--- |
| **`4:00 – 6:00 PM`** | **Expand SAST (`FR-1`) to All 6 CWEs + External Scanner Adapter:**<br>• Add AST taint rules + optional Semgrep/Bandit JSON/SARIF ingestion for:<br>  1. `CWE-89` (SQLi)<br>  2. `CWE-79` (Reflected & Stored XSS)<br>  3. `CWE-78` (Command Injection: `os.system`, `subprocess(..., shell=True)`)<br>  4. `CWE-22` (Path Traversal: `open()`, `send_file()` with user input)<br>  5. `CWE-601` (Open Redirect: `redirect(request.args.get('next'))`)<br>  6. `CWE-798` (Hard-coded secrets, weak MD5/SHA1 hashes, `debug=True`). | **Expand DAST (`FR-2`) to All 5 Runtime CWEs + Session Auth:**<br>• Add **Auto-Login / Session Jar**: automatically log into the test web shop so authenticated routes (`/orders`, `/checkout`, `/admin`, `/profile`) don't return `401/302`.<br>• Add safe deterministic probes for:<br>  - `CWE-78` (Command Injection: `; echo gordon_cmd_78` / differential output)<br>  - `CWE-22` (Path Traversal: `../../etc/passwd` or known local file read signature)<br>  - `CWE-601` (Open Redirect: `next=https://example.invalid` with `follow_redirects=False` checking `301/302 Location` header). |
| **`6:00 – 7:00 PM`** | **Harden `B-2` Safe Decoy Filter & Multi-File Call Graph:**<br>• Inspect all ~8 decoys in the test app: ensure parameterised SQL queries, `shlex.quote` / `shell=False`, `os.path.realpath` prefix guards, URL host allowlists, and **dead functions unreachable from any `FR-4` route** are flagged as `Protected / Unreachable (B-2 Suppressed)`.<br>• Extend `route_mapper.py` to trace 2–3 hops across imported helper files (`routes/orders.py` → `services/order_svc.py` → `db/repo.py`). | **Build `engine/auto_verify.py` (Bonus `B-1` — Huge Score Booster):**<br>• For every remaining reachable `Code only` finding (`CWE-89, 79, 78, 22, 601`) that Phase A DAST didn't catch:<br>  1. Read the exact route, HTTP method, parameter name, and expected content-type (`JSON` vs `form` vs `query`) from Person A's `RouteEntry`.<br>  2. Craft a targeted safe verification request and fire it against the running app.<br>  3. If proven, automatically upgrade the issue from `Code only` → **`Confirmed (Auto-Verified via B-1)`**! |
| **`7:00 – 7:30 PM`** | *Icebreaker Session 1 (30-min refresh)* | *Icebreaker Session 1 (30-min refresh)* |
| **`7:30 – 9:00 PM`** | **Enforce Zero Wrong Links (`<5%` Target) in `correlator.py`:**<br>• Add hard negative vetoes:<br>  - Never join two findings on different routes (`/cart` vs `/orders`) even if both are `CWE-89`.<br>  - Never join two different parameters (`?id=` vs `?sort=`) unless AST proves both flow to the exact same `file:line` sink.<br>• Run full evaluation against the test app's 36-bug answer key and verify `Wrong links == 0%`. | **Add Bonus `B-4` (Plain-English Fix Suggestions) & Polish `FR-8` Issue Detail Page:**<br>• Generate clear, copy-pasteable code remediation + plain-English explanation for each CWE (`B-4`).<br>• Ensure `GET /issues/{id}` and the UI detail drawer show all 8 mandatory `FR-8` fields: `URL`, `parameter`, `payload`, `file`, `line`, `code snippet`, `CWE`, and `severity` + the `B-3` correlation badge. |

---

### PHASE 3: `10:00 PM – 3:00 AM` (Overnight Sprint Part 1) — **Bonus `B-5`, `B-6`, `B-7` & Page 4 Reachability-Aware SCA Bonus**

*Agenda Context: `9:00–10:00 PM` Dinner · `10:00 PM–12:00 AM` Hack Hours · `12:00–12:30 AM` Icebreaker 2 · `12:30–8:00 AM` Overnight Build.*

**Goal by 3:00 AM:** Capture the **Flagship Bonus Points** that no other team will finish—specifically **Page 4's 5-Step Reachability-Aware SCA**, **Bonus `B-7` (2nd Language/Framework for the Unseen App)**, **Bonus `B-5` (Scan Diffing)**, and **Bonus `B-6` (SARIF Export + CI Build Breaker)**.

| Time Window | Person A (Static, AST & Correlation) | Person B (Runtime DAST, API & UI) |
| :--- | :--- | :--- |
| **`10:00 PM – 12:00 AM`** | **Build `engine/sca_reachability.py` (Page 4 Bonus — Steps 1 to 3):**<br>1. **Inventory:** Parse `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package-lock.json` into an SBOM keeping transitive dependency paths.<br>2. **GHSA Match:** Query OSV/GHSA (plus a bundled offline JSON fallback so it works even if venue Wi-Fi drops!) to pull affected versions, fixes, `CVSS`, `EPSS`, and `KEV`.<br>3. **Function Map:** Extract vulnerable symbols from OSV `ecosystem_specific.imports/symbols` AND parse GitHub `fix-commit` diffs (`@@ def func_name`) when GHSA omits functions! | **Build `api/diff_engine.py` (Bonus `B-5`) & `api/sarif_exporter.py` (Bonus `B-6`):**<br>• **`B-5` Scan Comparison:** Endpoint `GET /scans/compare?base=1&target=2` + UI toggle that compares two scans by deterministic issue fingerprint and badges every issue as **`NEW`**, **`FIXED`**, or **`STILL-OPEN`**.<br>• **`B-6` SARIF v2.1.0 + CI Gate:** Endpoint `GET /scans/{id}/sarif` + CLI flag `python cli.py scan --fail-on-confirmed-high` that exits with code `1` (failing a GitHub Actions / CI build) when any `Confirmed` High/Critical issue exists. |
| **`12:00 – 12:30 AM`** | *Icebreaker Session 2* | *Icebreaker Session 2* |
| **`12:30 – 3:00 AM`** | **Finish `engine/sca_reachability.py` (Steps 4 & 5) + Bonus `B-7` (2nd Language):**<br>4. **Call Graph:** Link `FR-4` route entry points → app functions → imported library functions.<br>5. **Supply Chain:** Flag typosquats (Levenshtein distance against top PyPI/npm packages), dependency confusion, and unpinned lockfile entries.<br>• **4 Status Labels:** `Reachable`, `Imported-only`, `Present-only`, `Unknown` (**strictly enforce: never downgrade `Unknown`!**).<br>• **Bonus `B-7`:** Add a lightweight **Node.js / Express (`app.get('/api/...', handler)`)** route + sink adapter in `route_mapper.py` & `sast_scanner.py` so you support 2 languages/frameworks! | **Add SCA Reachability & Mitigata Gordon AI Tab to UI:**<br>• Add the **Reachability-Aware SCA** view to `ui/index.html` showing the 4 statuses (`Reachable`, `Imported-only`, `Present-only`, `Unknown`), the visual call path (`Route -> App Function -> Library Symbol`), and supply-chain alerts.<br>• Add a compact **Mitigata Gordon AI Risk Summary bar** (`0 False Positives` decoy filter badge + estimated `₹` exposure on `Confirmed` issues) to align directly with `mitigata.com`. |

---

### PHASE 4: `3:00 AM – 8:00 AM` (Overnight Sprint Part 2) — **Shift Rest + Unseen-App Generalisation Torture Test**

*Agenda Context: `12:30 – 8:00 AM` Overnight Build & Snacks ("teams may rest in shifts").*

- **`3:00 AM – 4:30 AM`:** **Person A rests (90 mins)** while **Person B** packages `docker-compose.yml`, writes the CLI (`cli.py`), and tests scan speed (`Great target: < 5 minutes`; aim for `< 45 seconds`).
- **`4:30 AM – 6:00 AM`:** **Person B rests (90 mins)** while **Person A** builds a small **10-endpoint "Unseen Second App" test harness** (using different filenames, Blueprints/APIRouters, and path parameters like `/products/<int:pid>`) and tests `route_mapper.py` + `correlator.py` on it to guarantee **`> 65%` (Great target) on the judges' unseen app**.
- **`6:00 AM – 8:00 AM` (Together):**
  - Fix any edge cases where route parameters (`/orders/<id>` vs `/orders?id=1`), Blueprint prefixes (`url_prefix='/api'`), or multi-file imports missed a link.
  - Double-check all 7 metrics on Page 4 of the PRD against the organiser's answer key.

---

### PHASE 5: `8:00 AM – 11:00 AM` (Day 2 Morning) — **2nd Checkpoint, Feature Freeze & Submission**

*Agenda Context: `8:00–9:00 AM` Breakfast · `9:00–11:00 AM` Hack Hours & 2nd Checkpoint ("Final mentor check-ins; bug fixes only, no new features") · `11:00 AM` Build Clock Closes · `11:00–11:30 AM` Submission & Refining.*

| Time Window | Person A | Person B |
| :--- | :--- | :--- |
| **`8:00 – 9:00 AM`** | *Breakfast* | *Breakfast* |
| **`9:00 – 10:15 AM`**<br>*(2nd Checkpoint — Feature Freeze)* | **Answer-Key & Unseen-App Verification:**<br>• Run the full benchmark suite twice in a row to verify:<br>  - `Code detection > 85%`<br>  - `Runtime detection > 80%`<br>  - `Correct links > 80%`<br>  - `Wrong links < 5%` (`0%`)<br>  - `False alarms < 10%` (`0%`)<br>  - `Run time < 5 min` (`< 45s`)<br>  - Running scan twice creates `0` duplicates (`FR-6`). | **Write `README.md` & Verify Clean Docker Compose Boot:**<br>• Per PRD Page 4 Rules:<br>  1. Clearly list every open-source tool/ruleset used (`Semgrep/Bandit`, `ast`, `tree-sitter`, `httpx`, `OSV API`) and explain that the correlation, route-map, decoy-filter, and auto-verify engines are 100% your original work.<br>  2. Document 1-command startup (`docker compose up --build`) + API examples (`POST /scans`, `GET /issues`, `GET /issues/7`). |
| **`10:15 – 11:00 AM`** | Freeze `main` branch, tag release `v1.0-submission`, record a 90-second backup video of a live scan in case of projector glitches. | Prepare the 5-slide jury pitch deck highlighting the Answer-Key Scorecard, Live Demo flow, and Reachability-Aware SCA Bonus. |
| **`11:00 – 11:30 AM`** | **Submit code, prototype, and presentation** before the `11:30 AM` cutoff; rehearse the 3-minute Final Jury pitch for the `12:30 PM` Final Round. | Rehearse live demo handoff with Person A. |

---

## 4. Non-Negotiable Rules Checklist (Keep Next to Your Laptop)

1. **Disqualification Guard (PRD Page 4 Rule 1):** Point the DAST scanner **ONLY** at the organisers' test app running on your own machine (`localhost` / local Docker network). Set `follow_redirects=False` on `httpx` so an Open Redirect (`CWE-601`) test payload never follows a redirect out to the public internet.
2. **README Disclosure (PRD Page 4 Rule 2):** Explicitly list all open-source libraries/scanners used in `README.md`.
3. **Math of `Wrong links < 5%`:** With 20 planted pairs, **1 wrong link = 5.0%**, which fails `"Under 5%"`. Only mark an issue `Confirmed` when `CWE` + `Route/Handler` + `Parameter/Sink` match. If unsure, leave them as separate `Code only` and `Runtime only` items!
4. **Never Downgrade `Unknown` in SCA (PRD Page 4 Note):** In the Reachability-Aware SCA bonus, if an advisory does not list specific vulnerable functions, label it `Unknown` and **keep its original severity**.
