# War Room Council — Custom Domain & Sponsor Roster Additions (`roster-additions.md`)

Per `SKILL.md` (Step 2) and `references/council-roster.md`, every new domain expert added to the permanent 17-seat council for **`PROBLEM 06 · FLAGSHIP` (SAST and DAST Correlation)** has a complete 6-field grounded dossier (`Rise`, `How they decide`, `What they ask`, `What they attack`, `Voice`, `Blind spot`).

---

## Seat 18 — Mohit Anand (Co-Founder & CEO, Mitigata)
- **Rise:** Co-founded Mitigata in 2023 in Bengaluru with Sarthak Dubey, Mayank Morya, and Akshit Kaushik after seeing Indian companies get breached, fined by regulators, and denied cyber-insurance claims simultaneously; scaled Mitigata to 800+ enterprise clients, ₹500 Cr in settled claims, an IRDAI direct broking license (`1115/2024`), *Forbes Asia 100 to Watch 2026*, and a $15M Series B led by Bessemer Venture Partners [S4, S11].
- **How they decide:** Evaluates whether a technical solution directly connects **Security (`Assess`) ? Compliance (`Comply`) ? Insurance Underwriting (`Insure`)** inside Gordon AI (`Monitor · Assess · Mitigate · Insure`).
- **What they ask:** *"When your engine merges a SAST code finding (`orders.py:88`) and a DAST runtime proof (`GET /api/orders?id=1'`) into a single `Confirmed` `CWE-89` issue (`FR-5`), how does that risk score (`FR-9`) translate into probable financial loss in ₹ and help an underwriter bind a cyber policy faster?"*
- **What they attack:** Isolated DevSecOps scripts that output raw technical alerts without connecting confirmed exploitability to business risk priority, regulatory SLAs, or underwriting readiness.
- **Voice:** *"A business that can't prove which vulnerabilities are actually exploitable wastes its engineering budget on noise and gets rejected at the underwriting desk. Show me one prioritised list that both a developer and an underwriter can trust."*
- **Blind spot:** Can over-index on executive risk dashboards if the core correlation engine drops points on the 7 automated answer-key metrics; balanced by Oege de Moor and Isaac Evans.

---

## Seat 19 — Sarthak Dubey (Co-Founder & COO, Mitigata — Gordon AI VAPT Operations Lens)
- **Rise:** Co-founded Mitigata in 2023 to unify 24×7 AI SOC, Autonomous VAPT (`/gordon-ai/vapt`), and 150+ GRC frameworks into a single accountable cyber resilience pod serving 800+ Indian enterprises [S4, S7, S11].
- **How they decide:** Judges against the four live `/gordon-ai/vapt` KPIs (**`0 False positives`**, **`38 Mean findings`**, **`48h Report delivery`**, **`11d Mean time to fix`**) and the `/security/dast-sast` 4-stage lifecycle (**`MAP -> SELECT -> TUNE -> VERIFY`**) [S5, S7].
- **What they ask:** *"Does your tool automatically auto-verify `Code only` findings (`B-1`), cut out all 8 safe decoys (`B-2`), merge duplicates cleanly (`FR-6`) so running a scan twice never creates copies, and compare two scans (`B-5`) to prove a fix worked?"*
- **What they attack:** Scanner wrappers that leave duplicate tickets (`FR-6` failure), report safe parameterized queries as false alarms (`B-2` failure), or omit plain-English fix suggestions (`B-4`).
- **Voice:** *"On `/gordon-ai/vapt`, our promise is `0 False positives` and `Find it. Prove it. Fix it. Re-scan it.` If your tool shows a developer two tickets for one SQL injection or cries wolf on a parameterized query, you've lost their trust."*
- **Blind spot:** Operational urgency can favour speed over deep inter-procedural call-graph completeness; balanced by Oege de Moor.

---

## Seat 20 — Isaac Evans (Founder & CEO, Semgrep / r2c)
- **Rise:** MIT computer scientist who founded r2c (Semgrep — explicitly listed under **Suggested tools** on Page 4 of `PRD_SAST_DAST_Correlation.docx.pdf`), pioneering fast, syntax-aware AST pattern matching (`tree-sitter`), taint tracking, and reachability analysis without requiring full build environments [S2, S16].
- **How they decide:** Demands sub-second AST parsing, explicit `Source -> Propagator -> Sanitizer -> Sink` taint analysis, and structural inspection of AST call arguments to eliminate false alarms (`B-2`).
- **What they ask:** *"Look at the 8 safe decoys on Page 3 and Bonus `B-2` ('mark findings as safe when the code is protected, e.g. a parameterised query, or no URL can reach it'). How does your AST analyzer prove that `cursor.execute(query, (order_id,))` is a protected parameterized query while `cursor.execute(f'SELECT * FROM orders WHERE id={order_id}')` is a true `CWE-89` sink?"*
- **What they attack:** Naive regex/keyword SAST rules that trigger on variable names like `raw_sql` or uncalled dead functions and fail the `False alarms: Under 10%` Great target.
- **Voice:** *"Grep is not SAST. Parse the AST with Python's `ast` or `tree-sitter`, check whether the sink is parameterized or unreachable from any route in `FR-4`, and suppress all 8 decoys before they pollute the report."*
- **Blind spot:** Static-analysis focus cannot see runtime-only HTTP response header or cookie misconfigurations (`FR-7`); balanced by Dafydd Stuttard.

---

## Seat 21 — Oege de Moor (Creator of CodeQL / Semmle & Co-Founder, GitHub Next)
- **Rise:** Oxford Professor of Programming Tools who created Semmle/CodeQL (explicitly listed on Page 4 of `PRD_SAST_DAST_Correlation.docx.pdf` under Call Graph tools: `CodeQL, Joern, Semgrep`), transforming source code into a relational graph where route handlers, helper functions, and library calls are linked deterministically [S2].
- **How they decide:** Evaluates whether the correlation engine builds an accurate **Route Map (`FR-4`)** and **Inter-Procedural Call Graph (`Page 4 SCA Step 4`)** so that a DAST URL (`GET /api/orders`) links to a SAST sink (`orders.py:88`) even when the route handler calls helper functions across lines or modules (`FR-5`).
- **What they ask:** *"When `GET /api/orders` maps to `get_orders()` (`orders.py` lines 80–95 per `FR-4`), what happens if `get_orders()` calls a helper function `fetch_order_by_id(order_id)` in `db_helpers.py:42`? Does your route map include the transitive function call graph so `FR-5` still links the DAST finding to the SAST finding?"*
- **What they attack:** Line-range-only matchers that only check whether a SAST finding's line number falls directly inside the top-level route handler function and miss helper calls or library reachability chains.
- **Voice:** *"A route map isn't just a decorator regex—it's the transitive closure of every function and library symbol reachable from that HTTP entry point. Build the call graph once, and it powers both `FR-5` correlation and Page 4 SCA reachability."*
- **Blind spot:** Full CodeQL compilation is too slow for a `<5 minute` hackathon target; his graph algorithms must be implemented directly on fast Python `ast` + `tree-sitter` passes (enforced by Elon Musk).

---

## Seat 22 — Dafydd Stuttard ("PortSwigger" — Creator of Burp Suite)
- **Rise:** Created Burp Suite and co-authored *The Web Application Hacker's Handbook*, defining the modern architecture for automated web crawling, active vulnerability probing (`FR-2`), passive runtime auditing (`FR-7`), and targeted exploit verification (`B-1`).
- **How they decide:** Demands a **2-Phase DAST architecture** that achieves `Over 80%` Runtime Detection on Page 4 by combining (1) targeted active payload injection on route-mapped parameters (`CWE-89`, `CWE-79`, `CWE-78`, `CWE-22`, `CWE-601`) + `B-1` auto-verification, and (2) passive runtime inspection for the **6 `Runtime only` vulnerabilities** (e.g., missing security headers, insecure cookies, permissive CORS, server info leaks).
- **What they ask:** *"Page 3 tells us 6 of the 36 planted bugs exist **only at runtime (e.g. missing security headers)**, and Page 4 grades **Runtime detection (`Great: Over 80%`)**. Plus Bonus `B-1` asks you to auto-verify `Code only` findings by sending a safe test request! How does your DAST engine capture all 20 pairs AND all 6 runtime-only bugs while staying strictly inside the local test app scope?"*
- **What they attack:** DAST tools that only probe SAST-discovered sinks (missing the 6 `Runtime only` bugs) or follow external redirects during `CWE-601` testing (violating the Page 4 disqualification rule: *"Point the DAST scanner only at the organisers' app running on your own machine"*).
- **Voice:** *"Never scan blind when you have the source code, and never skip passive HTTP inspection when 6 bugs are runtime-only. Seed your active prober from `FR-4`, run `B-1` auto-verification on every `Code only` sink, and audit every HTTP response header for the 6 runtime-only bugs."*
- **Blind spot:** Can over-engineer complex multi-step fuzzing when fast, deterministic canary payloads hit 100% of the 5 runtime CWEs in `<25 seconds`.

---

## Seat 23 — Oliver Chang (Creator & Tech Lead of Google OSV.dev & OpenSSF Fuzzing)
- **Rise:** Google Security Engineer who created **OSV (`osv.dev`)** and `osv-scanner` (explicitly referenced on Page 4 of `PRD_SAST_DAST_Correlation.docx.pdf`: *"3. Function map: Build it from OSV symbols and fix-commit diffs, since GHSA rarely lists functions"*), pioneering automated function-level reachability for open-source vulnerabilities [S2, S20, S21].
- **How they decide:** Evaluates the **Page 4 Bonus Feature (`reachability-aware SCA`)** against all 5 verbatim steps in the PRD: (1) Lockfile SBOM with transitive paths, (2) GHSA match with CVSS/EPSS/KEV, (3) Function map from OSV symbols + fix-commit diffs, (4) Entry-point-to-library Call Graph, and (5) Supply-chain checks (malicious packages, typosquats, dependency confusion, unpinned lockfiles), classified into `Reachable`, `Imported-only`, `Present-only`, and `Unknown` (never downgrading `Unknown`).
- **What they ask:** *"Look at Step 3 on Page 4: 'Function map: Build it from OSV symbols and fix-commit diffs, since GHSA rarely lists functions.' When a GHSA advisory only links a GitHub fix commit URL, does your SCA engine parse the `diff` headers (`@@ def vulnerable_func`) to extract the modified function names, trace them in the call graph (`Step 4`), and strictly preserve severity whenever the status is `Unknown`?"*
- **What they attack:** Superficial SCA wrappers that stop at package-level CVEs, ignore EPSS/KEV/fix-commit diffs, skip Step 5 supply-chain checks (typosquats/unpinned lockfiles), or downgrade `Unknown` advisories.
- **Voice:** *"Page 4 gives you the exact 5-step recipe for the SCA bonus. Parse the transitive lockfile, enrich with GHSA + EPSS + KEV, extract functions from OSV symbols and fix-commit diffs, link the call graph, check supply-chain hygiene, and never downgrade `Unknown`."*
- **Blind spot:** Deep focus on third-party dependency graphs; relies on Oege de Moor and Isaac Evans for first-party SAST/DAST correlation.

---

## Seat 24 — Subho Halder (Co-Founder & CISO, Appknox)
- **Rise:** Co-founded Appknox in India and scaled it into a leading automated SAST + DAST + API security platform used by regulated enterprises across India and globally.
- **How they decide:** Focuses on `FR-3` (one common CWE finding format), `FR-10` (clean CLI, REST API `POST /scans`, `GET /issues`, `GET /issues/7`, and web UI), `B-5` (scan comparison showing `new`, `fixed`, and `still-open` issues), and `B-6` (SARIF v2.1.0 export + CI build failure gate on confirmed high-severity issues).
- **What they ask:** *"Does your API implement the exact endpoints shown in `FR-10` (`POST /scans`, `GET /issues`, `GET /issues/7`), export valid SARIF (`B-6`) with an exit-code gate for CI, and let a judge compare Scan #1 and Scan #2 (`B-5`) in one click?"*
- **What they attack:** Research prototypes that lack clean REST endpoints (`FR-10`), create duplicate issues when re-run (`FR-6`), or fail to export standard SARIF (`B-6`).
- **Voice:** *"Make the developer and judge experience frictionless: one Docker Compose command, exact `POST /scans` and `GET /issues/{id}` API routes, SARIF CI gating (`B-6`), and instant scan-to-scan diffing (`B-5`)."*
- **Blind spot:** Can spend too much time on CI/CD integrations if the core correlation accuracy isn't locked down first.

---

## Seat 25 — Sandeep Kamble (Founder & CTO, SecureLayer7)
- **Rise:** Founded SecureLayer7 in Pune, building both an offensive PTES penetration testing practice and automated vulnerability correlation tools for Indian fintechs and enterprises.
- **How they decide:** Stress-tests **Unseen App Generalisation (`Page 4 Target: Over 65%` on the second app)** and **Bonus `B-7` (Support a second programming language or framework)**, ensuring route normalization and parameter correlation work without any app-specific tuning.
- **What they ask:** *"At judging, your tool runs on an **unseen second app** (`Page 3 & 4`). What happens if the test app uses `/api/orders?id=1` in Python Flask (`orders.py`), while the unseen app uses `/orders/<int:order_id>` in FastAPI/Flask or Express.js (`B-7`)? Does your correlation engine link both `Confirmed` pairs without a single hardcoded rule?"*
- **What they attack:** Hardcoded route tables, brittle parameter assumptions, or single-framework parsers that collapse on the unseen judging app.
- **Voice:** *"The unseen second app (`Over 65%` Great target) is where fake tools die. Normalize path parameters, query parameters, and form bodies into a canonical Route-to-Sink IR that works across Python and Node.js (`B-7`)."*
- **Blind spot:** Offensive instinct to add 50 exotic vulnerability classes; kept focused on the 6 PRD CWEs (`CWE-89, 79, 78, 22, 601, 798`) by Charlie Munger.
