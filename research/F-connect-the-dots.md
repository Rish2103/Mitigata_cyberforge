# Phase 3 Synthesis — Patrick Jane's "Connect the Dots" Session (`F-connect-the-dots.md`)

> **Chair:** Patrick Jane ◇ · **Co-Chairs:** Charlie Munger †, Paul Graham, Mohit Anand, Mayank Morya (lens), Isaac Evans, Oege de Moor, Dafydd Stuttard, Oliver Chang

---

## 1. Ten Dots Nobody Else Will Connect

### Dot 1 — Every Hackathon Problem Statement Is an Active R&D Epic Inside `GORDON-V3`
When we overlay `Hackathon Problem Statements.pdf` (`PROBLEM 01` to `PROBLEM 06`) onto `https://mitigata.com/gordon-ai`, a 1-to-1 structural isomorphism emerges:
- **`PROBLEM 01` (Kill chain & attack paths, 15–50 GB logs)** = Gordon AI's **AI SOC (`01/12` & `05/12`)** + **Risk Narratives (`01/06`)** (`12.4k events/s`, `4.2 min MTTD`, MITRE ATT&CK story builder).
- **`PROBLEM 02` (Multi-tenant aggregation layer, 10M rows, 100 tenants)** = Gordon AI's **Multi-Tenant Posture Console** (`800+ clients`, live `<1s` rollups without cross-tenant cache bleed after the 2023 ChatGPT Redis incident `INC-02`).
- **`PROBLEM 03` (Community scam map)** = Mitigata's **`/personal` Cyber Protection + Brand & Dark Web Monitoring (`06/12` & `07/12`)** built for India's `INC-03` Digital Arrest wave.
- **`PROBLEM 04` (Autonomous pentest engine — CART)** = Gordon AI's **ReLIQ / Offensive VAPT agent** (`/gordon-ai/vapt`).
- **`PROBLEM 05` (Config-driven integration platform)** = Gordon AI's **200+ GRC & 60+ Security OEM Connectors** (`84/84 evidence synced`).
- **`PROBLEM 06 · FLAGSHIP` (SAST and DAST correlation)** = The **Crown Jewel of Gordon AI's `Assess` Pillar**: on `https://mitigata.com/gordon-ai`, the very first finding rendered in the `CONSOLE · GORDON-V3` UI mockup is `01 · SQL injection · /api/v2/users · Critical · CWE-89 · public endpoint · CVSS 9.8`, paired with the complaint under *"Old Stack STATUS QUO"*:
  - `01 · Monitor: Alerts pile up. False positives eat the day. Important signals get buried.`
  - `02 · Assess: VAPT reports arrive as PDFs. Findings lose owners. Fixes are hard to verify.`

### Dot 2 — Why `PROBLEM 06` Alone Is Badged `FLAGSHIP · Solve it for bonus points`
Out of all 6 challenges in `Hackathon Problem Statements.pdf`, **only Problem 06** has the gold **`FLAGSHIP`** badge, the pill **`Solve it for bonus points`**, and a dedicated 5-page quantitative PRD (`PRD_SAST_DAST_Correlation.docx.pdf`, authored by **`Anuj`** on **`30 October 2026`**). Why? Because correlating static code (`orders.py:88`) with dynamic HTTP proof (`GET /api/orders?id=1'`) and reachability-aware SCA is the hardest unsolved engineering bottleneck in Mitigata's `/security/dast-sast` and `/gordon-ai/vapt` product lines—where human analysts currently spend hours manually deduplicating Semgrep/Bandit alerts against ZAP/Nuclei/Burp findings to deliver on Mitigata's **`0 False positives`** and **`48h Report delivery`** SLA.

### Dot 3 — The `38 Mean Findings` Fingerprint on `/gordon-ai/vapt` vs. `36 Planted Bugs` in the PRD
Look at `https://mitigata.com/gordon-ai/vapt`: the page advertises **`0 False positives`** and **`38 Mean findings`** per web-shop VAPT engagement. Look at Page 3 of `PRD_SAST_DAST_Correlation.docx.pdf`: the kickoff test application is *"a small web shop with about 30 URLs"* containing **`36 planted vulnerabilities`** (`20 pairs + 10 code-only + 6 runtime-only`) plus **`8 safe decoys`**. The benchmark app was literally modeled on Mitigata's internal reference VAPT testbench!

### Dot 4 — Charlie Munger's Math Catch on `Wrong links: Under 5%`
Look closely at the Page 4 Targets table in `PRD_SAST_DAST_Correlation.docx.pdf`:
- **`Wrong links`**: *"Share of your Confirmed issues that join two different bugs"* ? Good: `Under 20%`, Great: **`Under 5%`**.
- Notice the denominator: it is **your reported `Confirmed` issues**, of which there are at most `20` true pairs in the test app!
- If your tool reports `20` Confirmed issues and **even ONE (`1`)** of them joins two different bugs (e.g. joining a SQLi on `/api/orders?id=` with a SQLi on `/api/orders?sort=`, or joining a XSS on `/search` with a XSS on `/reviews`), your wrong-link rate is 1/20 = 5.0% (or 1/18 = 5.56%), which **FAILS** `"Under 5%"`!
- **Implication:** To hit the `Great` column on `Wrong links`, our correlation engine must have **strictly ZERO (`0`) wrong links ($0.0\%$)**—enforced via hard negative vetoes on `(Canonical_URL_Template, HTTP_Method, Parameter_or_Shared_Sink_Line, CWE_Number)`.

### Dot 5 — The `Runtime detection: Over 80%` + `6 Runtime only` Trap
Page 3 states that of the 36 planted bugs:
- `20` are in both code and runtime (`Confirmed` pairs),
- `10` are only in the code (`Code only`, e.g., `CWE-798` hard-coded secrets),
- **`6` are only at runtime (`Runtime only`, e.g., missing security headers)**.
And Page 4 measures **`Runtime detection`** as *"Share of planted runtime vulnerabilities your DAST finds"* (`Great: Over 80%`, i.e., ? 21/26).
- If a team builds a DAST scanner that *only* tests parameters extracted from SAST route handlers (`FR-4`), it will completely miss the **6 `Runtime only` vulnerabilities** (missing `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, insecure `Set-Cookie` flags, permissive CORS, server version leaks)!
- Even worse, if DAST misses 2 active endpoints AND misses all 6 runtime-only bugs, it only finds $18/26 = 69.2\%$, failing the `Over 80%` Great target!
- **Implication:** Our DAST scanner MUST run in **Two Phases**:
  - **Phase A (AST-Route-Seeded Active Prober + `B-1` Auto-Verifier)** to nail $20/20$ injectable pairs.
  - **Phase B (Live HTTP Crawler + Passive Header/Cookie/CORS/Config Auditor)** to nail $6/6$ `Runtime only` bugs (`FR-7`).

### Dot 6 — The `8 Safe Decoys` Trap (`False alarms: Under 10%` & Bonus `B-2`)
Page 3 explicitly warns:
- *"Safe decoys: about 8 pieces of code that look dangerous but are safe, such as a properly parameterised database query. Reporting one is a false alarm."*
- And Bonus `B-2` states: *"Cut SAST noise: mark findings as safe when the code is protected (e.g. a parameterised query) or no URL can reach it."*
- Teams that simply run stock Bandit or naive regex rules (or fail to filter Semgrep output through an AST parameterization/reachability verifier) will report all 8 decoys. If a tool reports 30 real bugs + 8 decoys, its false alarm rate is 8/38 = 21.1%, failing `Great: Under 10%`!
- **Implication:** We implement an **AST Protection & Reachability Verifier (`B-2`)** that inspects every candidate SAST sink:
  1. Is it a parameterized SQL query (`cursor.execute(sql, (param,))` with tuple/list/dict bound args)? ? Mark **`Protected / Safe Decoy (Suppressed)`**.
  2. Is `subprocess.run([...], shell=False)` using a list argument without shell invocation? ? Mark **`Protected / Safe Decoy (Suppressed)`**.
  3. Is file access guarded by `os.path.realpath`/`abspath` prefix check or `secure_filename`? ? Mark **`Protected / Safe Decoy (Suppressed)`**.
  4. Is redirect guarded by domain allowlist / relative-path check? ? Mark **`Protected / Safe Decoy (Suppressed)`**.
  5. Is the function dead code that **no URL route in `FR-4` can ever reach** (and not a `CWE-798` secret)? ? Mark **`Unreachable / Safe Decoy (Suppressed)`** per `B-2`!

### Dot 7 — Page 4's Reachability-Aware SCA Bonus Is an Exact 5-Step Blueprint
Look at the bottom of Page 4 in `PRD_SAST_DAST_Correlation.docx.pdf`. Author `Anuj` didn't write a vague wish—he wrote the exact 5-step architecture he wants to see:
1. **Inventory:** Parse lockfiles into an SBOM, keeping transitive paths.
2. **GHSA match:** Pull affected versions, fixes, CVSS, EPSS and KEV.
3. **Function map:** Build it from OSV symbols and fix-commit diffs, since GHSA rarely lists functions.
4. **Call graph:** Link entry points, app functions and library functions (CodeQL, Joern, Semgrep).
5. **Supply chain:** Check for malicious packages, typosquats, dependency confusion and unpinned lockfiles.
- **Statuses:** `Reachable`, `Imported-only`, `Present-only`, `Unknown` (**never downgrade `Unknown`**).
Most teams will either ignore this note at the bottom of Page 4 or wrap `pip-audit` (which only does Step 1–2 at the package level). By implementing all 5 steps—including **OSV symbols + GitHub fix-commit diff AST function extraction (Step 3)**, **Entry-Point-to-Library Call Graph (Step 4)**, and **Typosquat/Levenshtein + Dependency Confusion + Unpinned Lockfile supply-chain checks (Step 5)**—we lock in the full Flagship bonus points.

### Dot 8 — Page 5's Single Sentence (`"Which language should this target first?"`) Is a Design Clue
Page 5 of `PRD_SAST_DAST_Correlation.docx.pdf` contains a single line: `"Which language should this target first?"`.
- Combined with Page 1–2 (`orders.py, line 88`, `GET /api/orders -> get_orders(), orders.py lines 80 to 95`) and Page 4 (`Python's ast module or tree-sitter for the route map`), the kickoff web-shop test app is written in **Python** (Flask / FastAPI), while Bonus `B-7` explicitly awards bonus points for **`"Support a second programming language or framework"`**.
- By answering Page 5 explicitly in our README & UI—targeting **Python (Flask / FastAPI / Django) first** via Python's `ast` + `tree-sitter`, and supporting **JavaScript/TypeScript (Node.js Express) second** (`B-7`) via `tree-sitter-javascript` normalized into the same Route-to-Sink Intermediate Representation (IR)—we prove we read all 5 pages down to the final line.

### Dot 9 — `INC-06` (The 2017 Equifax Breach) Frames the Entire Pitch Narrative
Slide `07 / 07` of `Hackathon Problem Statements.pdf` anchors PS-06 to:
- **`REAL INCIDENT · INC-06`:** *"A 2017 credit bureau breach: a known web flaw that scans missed, about 145 million people."*
- In March 2017, Equifax ran vulnerability scans looking for Apache Struts `CVE-2017-5638`, but their network/dynamic scanner missed the vulnerable `/struts2-rest-showcase` route context while their static/asset inventory couldn't tell which public web endpoint actually reached the vulnerable `JakartaMultipartParser` class.
- Framing our 3-minute pitch around **how our SAST + DAST + Reachability-Aware SCA engine would have caught `INC-06` in 28 seconds** connects our demo directly to the slide deck the judges themselves wrote.

### Dot 10 — Connecting `FR-9` Risk Score to Mitigata's InsurTech Moat (`₹` FAIR Exposure + SEBI CSCRF)
`FR-9` requires: *"Prioritised list: confirmed issues first, then by risk score (severity and how easy it is to exploit)."*
While other teams compute a toy `CVSS * 1.2` number, we compute a **Dual-Layer Risk Score**:
1. **Technical Exploitability Risk Score (`0–100`)** combining Confirmation status (`Confirmed` > `Runtime only` > `Code only`), CWE severity, auth requirement (public vs authenticated route), and EPSS/KEV (for SCA).
2. **Mitigata Gordon AI Business & Regulatory Impact Badge**: Probable financial exposure in `₹ Lakhs/Crores` (FAIR model from `/gordon-ai/cyber-risk-quantification`), **SEBI CSCRF 3-month mandatory closure clock**, **DPDP Act 2023 PII sink impact**, and **IRDAI cyber insurance underwriting status**.

---

## 2. Hidden Evaluation Criteria & Landmines

### Hidden Criteria the Jury Will Actually Grade On
1. **Zero Hardcoding (The Unseen Second App Test):** On Page 3 & 4, the judges run your tool against an **unseen second app** (`Great: Over 65%` of planted pairs linked). Any hardcoded URL paths (`/api/orders`) or filenames (`orders.py`) results in an instant `0%` on the unseen app.
2. **Idempotency (`FR-6`):** *"running a scan twice does not create copies."* The SQLite/PostgreSQL storage layer must upsert by a deterministic canonical fingerprint so running `--scan` twice in a row produces the exact same issue count.
3. **Sub-5-Minute Wall-Clock Speed (`Page 4 Run time`):** Running heavy Java/Scala tools (CodeQL database build or full headless OWASP ZAP spidering) can easily take 6–12 minutes on a 30-URL app. A fast Python `ast` + `tree-sitter` static pass (`<1.5s`) paired with an async `httpx` AST-guided + passive DAST engine (`<25s`) finishes the entire 30-URL shop in **~25–35 seconds**.
4. **Strict Sandbox Scope Safety (`Page 2 & Page 4 Rules`):** *"Point the DAST scanner only at the organisers' app running on your own machine. Scanning any other site or system is not allowed and leads to disqualification."* We enforce a hard loopback/target-host allowlist lock in the HTTP client so even an Open Redirect (`CWE-601`) test never follows an external redirect over the internet (`follow_redirects=False`).

### The 80% Trap (What Most Teams Will Build and Why It Loses)
- **Trap A:** Running Semgrep + OWASP ZAP CLI blindly and asking an LLM (`GPT-4o`) to "match the two JSON outputs."
  - *Why it fails:* ZAP's blind crawler misses unlinked API routes (`POST /api/orders/checkout`) and takes `>8 minutes`; LLM matching hallucinates links across different endpoints/params (`Wrong links > 20%`) and cannot build a deterministic route map (`FR-4`).
- **Trap B:** Naive regex SAST + simple URL string matching (`if filename in url`).
  - *Why it fails:* Flags all **8 safe decoys** (`False alarms > 25%`), fails whenever `routes.py` calls a helper in `db/orders_repo.py` (`FR-5` multi-file failure), and fails on URL path parameters (`/api/orders/42` vs `/api/orders/<int:id>`).
