# Phase 1 Recon — Hard Facts from Official Hackathon PDFs, DOCX & Mitigata.com

## 1. Hackathon Overview & Source Documents

- **Event Name:** Mitigata Hackathon 2026 (`MITIGATA HACKATHON — Six challenges across security, data and product engineering`) [S1]
- **Organiser:** Mitigata (`https://mitigata.com/`) — legally registered as **Mitigata Insurance Brokers Pvt. Ltd.** (a wholly owned subsidiary of **Alphawave Technologies Private Limited**), IRDAI Direct Broker Registration No. `IRDAI/INT/BRK/DB 1115/2024`, License No. `1013` (valid Nov 27, 2024 to Nov 26, 2027), CIN `U66220KA2024PTC186580`, headquartered in Bellandur, Bengaluru with offices in BKC Mumbai, Udyog Vihar Gurugram, and Dover, Delaware (USA) [S4, S11].
- **Primary Source Documents Inspected in `d:\Mitigata\`:**
  1. **`d:\Mitigata\Hackathon Problem Statements.pdf`** (7 slides, `01 / 07` to `07 / 07`, marked *"Confidential to Mitigata"*): Defines the 6 official hackathon challenges (`PROBLEM 01` to `PROBLEM 06 · FLAGSHIP`), their scale/scope constraints, 3 numbered deliverables per problem statement, and a real-world historical breach anchor (`REAL INCIDENT · INC-01` to `INC-06`) [S1].
  2. **`d:\Mitigata\PRD_SAST_DAST_Correlation.docx.pdf`** (identical to user-uploaded `media_1793427809899_793e9247.pdf`, 5 pages, titled **`PRD: SAST and DAST Correlation — Problem, Goals and Requirements`**, dated **`30 October 2026 · Anuj`**): The exhaustive specification and grading rubric for `PROBLEM 06 · FLAGSHIP` [S2].
  3. **User-uploaded `media_1793427832701_51b87539.png`**: High-resolution slide image of Slide `07 / 07` (`PROBLEM 06 · FLAGSHIP — SAST and DAST correlation`) [S1].
  4. **`d:\Mitigata\Problem Statements.docx`** (internal timestamp `2026-10-29`): Early 6-line draft of the problem statements prior to the 7-slide deck [S3].

---

## 2. All 6 Official Problem Statements (`Hackathon Problem Statements.pdf`)

| Official ID & Slide | Title | Scope / Constraint Badge | Three Required Deliverables (01, 02, 03) | Real Incident Trigger (INC-01 to INC-06) | Draft Title in Problem Statements.docx |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`PROBLEM 01`**<br>*(Slide 02/07)* | **Kill chain and attack path analysis** | `Data tiers: 15, 30 or 50 GB of logs` | **01 Detect and label:** Find suspicious events and tag each with a MITRE ATT&CK technique and kill chain stage.<br>**02 Connect the steps:** Link events across hosts, users, IPs and time into one attack path, without running out of memory.<br>**03 Explain and look ahead:** Show a timeline and a graph of hosts and users, plus what the attacker could reach next. | **`INC-01`:** *"A 2013 retail breach: one stolen vendor login, weeks of ignored alerts, up to 110 million customers."* (2013 Target breach) | PS 2: *Kill Chain Attack Path Reconstruction: Turn raw logs into attack stories* |
| **`PROBLEM 02`**<br>*(Slide 03/07)* | **Multi-tenant aggregation layer** | `Scale: 10M records, 100 tenants` | **01 Fast and fresh:** Dashboard queries return in under a second, and new or updated orders show up within minutes.<br>**02 Four dashboard queries:** Counts and totals, trends over time, top-N lists and breakdowns by category, through a simple API.<br>**03 Separate and correct:** Each tenant sees only its own data, and the numbers match a direct database query. | **`INC-02`:** *"A 2023 cache bug that showed some users other users' chat titles and payment details."* (March 2023 OpenAI ChatGPT Redis bug) | PS 1: *Fast Multi-Tenant Data Aggregation: Live rollups at scale without database overload* |
| **`PROBLEM 03`**<br>*(Slide 04/07)* | **Community scam map** | `Reporters stay anonymous` | **01 Report and look up:** Report a scam in under 60 seconds. Lookups answer in under half a second.<br>**02 Map and alerts:** Show the last 7 days of reports by area, and alert only when something is unusual.<br>**03 Beat fake reports:** Trust rules must stop report-bombing, fake accounts, spam and junk, without missing real scams. | **`INC-03`:** *"India's 'digital arrest' scams: over 83,000 WhatsApp accounts blocked by March 2025."* (I4C / MHA crackdown) | PS 4: *Community Scam Map for India: Report and verify scams in seconds, anonymously* |
| **`PROBLEM 04`**<br>*(Slide 05/07)* | **Autonomous pentest engine (CART)** | `Test only inside the given scope` | **01 Discover all three surfaces:** Find live hosts, ports and services, then crawl web apps and inspect the binaries.<br>**02 Coordinate agents:** Agents share findings and hand work to each other, so no host is tested twice.<br>**03 Verify and report:** Prove each weakness, tag it with a PTES phase, and deliver one report with the attack path. | **`INC-04`:** *"A 2019 bank breach: a misconfigured web firewall led to cloud data on about 100 million people."* (2019 Capital One AWS WAF SSRF breach) | Upgraded from PS 6 (*Network Asset Discovery and Mapping*) |
| **`PROBLEM 05`**<br>*(Slide 06/07)* | **Config-driven integration platform** | `Prove it with 3 different sources` | **01 Config describes the source:** Login, endpoints, pagination, schedule, and a mapping into one common format.<br>**02 Platform handles the rest:** Safe secrets, retries with backoff, rate limits and bad data, the same for every connector.<br>**03 Health stays visible:** A simple page shows each connection's status, last run and errors. | **`INC-05`:** *"A 2025 breach where stolen integration tokens exposed many companies' CRM data."* (2025 Salesloft Drift OAuth token breach) | PS 3: *Config-Driven Generic Integration Platform: Add new tool integrations without writing code* |
| **`PROBLEM 06 · FLAGSHIP`**<br>*(Slide 07/07)* | **SAST and DAST correlation** | `Solve it for bonus points` | **01 Scan code and app:** Cover at least four of six vulnerability types, including SQL injection and XSS, in one common format with CWE numbers.<br>**02 Correlate and merge:** Link a runtime finding to the code behind it and merge duplicates. This is what we judge most.<br>**03 Prioritise what to fix:** Label each issue Confirmed, Code only or Runtime only, and rank confirmed issues first. | **`INC-06`:** *"A 2017 credit bureau breach: a known web flaw that scans missed, about 145 million people."* (2017 Equifax Apache Struts CVE-2017-5638 breach) | PS 5: *SAST and DAST Correlation Engine: Link code flaws to proven runtime exploits* |

---

## 3. Verbatim Requirements & Rubric for `PROBLEM 06 · FLAGSHIP` (`PRD_SAST_DAST_Correlation.docx.pdf`)

### 3.1 Overview, Setting & Core Problem (Page 1)
- **Author & Date:** `30 October 2026 · Anuj` [S2].
- **Mission:** *"Build a tool that scans an application's source code and its running version, then connects the two sets of results, so each real vulnerability appears once, with the line of code that causes it and the proof that it can be exploited."* [S2]
- **The 4 Pain Points Stated in PRD:**
  1. **Same bug, two tickets:** SAST says `"SQL injection in orders.py, line 88"`. DAST says `"SQL injection at /api/orders, parameter id"`. It is one bug, but nobody can see that, so it gets fixed twice or not at all.
  2. **Too much noise:** SAST reports hundreds of findings, many of them safe or in code that can never be reached. Developers stop trusting the list.
  3. **No place to fix:** A DAST finding proves the app can be attacked but does not say which code to change.
  4. **No clear priority:** A bug found in the code and proven exploitable matters more than a guess, but no report shows the difference.
- **Flagship Bonus:** *"Flagship Challenge. Any team that solves this problem earns bonus points on top of its normal score."* [S2]

### 3.2 Must-Have Functional Requirements (`FR-1` to `FR-10`, Pages 2–3)

| ID | Feature (Verbatim from PRD) | Example (Verbatim from PRD) |
| :--- | :--- | :--- |
| **`FR-1`** | **SAST scan:** scan a source folder and report findings with file, line, vulnerability type, severity and the code snippet | `SQL injection, orders.py line 88, CWE-89` |
| **`FR-2`** | **DAST scan:** scan a running app URL by sending test requests and report findings with URL, method, parameter, payload and evidence | `GET /api/orders?id=1' returns a database error` |
| **`FR-3`** | **One common finding format** for both scanners, with a CWE number for the type | `Both sides report SQL injection as CWE-89` |
| **`FR-4`** | **Route map:** read the source code to list which URL is handled by which function and lines | `GET /api/orders → get_orders(), orders.py lines 80 to 95` |
| **`FR-5`** | **Correlate:** link a DAST finding to a SAST finding when they have the same CWE and the DAST URL is handled by the code that holds the SAST finding | `DAST SQL injection on /api/orders + SAST SQL injection at orders.py:88 = one confirmed issue` |
| **`FR-6`** | **Merge duplicates:** one issue per real bug with all its evidence attached; running a scan twice does not create copies | `3 scanner findings on the same bug = 1 issue` |
| **`FR-7`** | **Label every issue** as `Confirmed` (found by both), `Code only` (SAST, not proven) or `Runtime only` (DAST, no code location found) | `Hard-coded secret = Code only` |
| **`FR-8`** | **Issue detail for confirmed issues:** URL, parameter, payload, file, line, code snippet, CWE and severity | `One page that tells a developer where to look` |
| **`FR-9`** | **Prioritised list:** confirmed issues first, then by risk score (severity and how easy it is to exploit) | `Confirmed SQL injection above a Code only weak hash` |
| **`FR-10`** | **Simple command line, API or page, with a short README** | `POST /scans, GET /issues, GET /issues/7` |

### 3.3 Official Bonus Items (`B-1` to `B-7`, Page 3)

| ID | Bonus Feature (Verbatim from PRD) |
| :--- | :--- |
| **`B-1`** | **Auto-verify:** for a `Code only` finding, send a safe test request to try to prove it at runtime and upgrade it to `Confirmed` |
| **`B-2`** | **Cut SAST noise:** mark findings as safe when the code is protected (e.g. a parameterised query) or no URL can reach it |
| **`B-3`** | **Explain every link:** show why two findings were joined (same CWE, same route, same parameter) |
| **`B-4`** | **Plain-English fix suggestion** for each confirmed issue |
| **`B-5`** | **Compare two scans** and show new, fixed and still-open issues |
| **`B-6`** | **Export results as SARIF** and fail a CI build on confirmed high-severity issues |
| **`B-7`** | **Support a second programming language or framework** |

### 3.4 Test Application, Planted Bugs, Decoys & 6 CWE Types (Page 3)
- **One test app (provided at kickoff):** A small web shop with about **30 URLs**, its source code, and a Docker Compose file to run it on your own machine [S2].
- **Planted vulnerabilities with an answer key (36 in total):**
  - **20 pairs** can be found in both the code and the running app (the pairs to link into `Confirmed`).
  - **10 `Code only`** (e.g. hard-coded secrets).
  - **6 `Runtime only`** (e.g. missing security headers).
- **Safe decoys (~8 pieces of code):** Code that looks dangerous (e.g. a properly parameterised database query) but is safe. **Reporting one is a false alarm** [S2].
- **Unseen second app (at judging):** Tool runs on a second app with the same kinds of bugs to verify it is not tuned only to the test app [S2].
- **6 Vulnerability Types (must cover at least 4, including SQLi and XSS):**
  1. **SQL injection (`CWE-89`)** — Code and runtime
  2. **Cross-site scripting (XSS) (`CWE-79`)** — Code and runtime
  3. **Command injection (`CWE-78`)** — Code and runtime
  4. **Path traversal (`CWE-22`)** — Code and runtime
  5. **Open redirect (`CWE-601`)** — Code and runtime
  6. **Hard-coded secrets (`CWE-798`)** — Code only

### 3.5 Quantitative Judging Targets (Page 4)

| What we measure | How (Verbatim from PRD) | Good (to qualify) | Great (to stand out) |
| :--- | :--- | :--- | :--- |
| **Code detection** | Share of planted code vulnerabilities your SAST finds (out of 30 code bugs: 20 pairs + 10 code-only) | `Over 60%` (`>= 19/30`) | **`Over 85%`** (`>= 26/30`) |
| **Runtime detection** | Share of planted runtime vulnerabilities your DAST finds (out of 26 runtime bugs: 20 pairs + 6 runtime-only) | `Over 50%` (`>= 14/26`) | **`Over 80%`** (`>= 21/26`) |
| **Correct links** | Share of the 20 planted pairs linked into one `Confirmed` issue | `Over 50%` (`>= 11/20`) | **`Over 80%`** (`>= 17/20`) |
| **Wrong links** | Share of your `Confirmed` issues that join two different bugs | `Under 20%` | **`Under 5%`** *(Strict `0` wrong links required when reporting `<= 20` Confirmed)* |
| **False alarms** | Share of reported issues that are safe decoys | `Under 30%` | **`Under 10%`** |
| **Unseen app** | Share of planted pairs linked on the second app | `Over 40%` | **`Over 65%`** |
| **Run time** | Time to scan, correlate and produce the report on the test app | `Under 15 minutes` | **`Under 5 minutes`** |

### 3.6 Page 4 Special Bonus Feature: Reachability-Aware SCA
Verbatim 5-step architecture required on Page 4 of `PRD_SAST_DAST_Correlation.docx.pdf` [S2]:
> **NOTE : Bonus feature: reachability-aware SCA**
> Report whether the app can actually reach a vulnerable library function, not just that a CVE exists.
> 1. **Inventory:** Parse lockfiles into an SBOM, keeping transitive paths.
> 2. **GHSA match:** Pull affected versions, fixes, CVSS, EPSS and KEV.
> 3. **Function map:** Build it from OSV symbols and fix-commit diffs, since GHSA rarely lists functions.
> 4. **Call graph:** Link entry points, app functions and library functions (CodeQL, Joern, Semgrep).
> 5. **Supply chain:** Check for malicious packages, typosquats, dependency confusion and unpinned lockfiles.
> **Statuses:** `Reachable`, `Imported-only`, `Present-only`, `Unknown` (never downgrade `Unknown`).

### 3.7 Page 5 Strategic Prompt
- Verbatim text on Page 5: **`"Which language should this target first?"`** [S2]
- **Evidence in PRD:** Page 1 (`orders.py, line 88`), Page 2 (`orders.py line 88`, `GET /api/orders -> get_orders(), orders.py lines 80 to 95`), and Page 4 Suggested Tools (`Semgrep or Bandit for code scanning; OWASP ZAP or Nuclei for runtime scanning; Python's ast module or tree-sitter for the route map; SARIF as a common results format; SQLite or PostgreSQL to store findings`) prove the primary test app is **Python** (Flask / FastAPI), while `B-7` rewards supporting a second language/framework (**JavaScript / Node.js Express** via `tree-sitter`).

---

## 4. Live Recon of `https://mitigata.com/`

- **Founders & Executive Leadership (`/company/about-us`):**
  - **Mohit Anand** — Co-founder & CEO
  - **Sarthak Dubey** — Co-founder & COO
  - **Mayank Morya** — Co-founder & CTO (Architect of `Gordon AI · GORDON-V3`)
  - **Akshit Kaushik** — Co-founder & CBO
  - **Lt Cdr Dheeraj Yadav** — CISO (ex-Deputy Director, Indian Navy)
  - **Dr. Lalit Gupta** — Senior Partner & Chief Delivery Officer (Founding Member, CERT-In India) [S11]
- **Funding & Recognition:**
  - **$15 Million Series B** led by **Bessemer Venture Partners (BVP)**, with **Nexus Venture Partners**, **Titan Capital**, and **WEH Ventures** [S4, S11].
  - Named to **Forbes Asia 100 to Watch 2026** [S4].
- **Traction & Scale Metrics:**
  - `800+` enterprise clients across `25+` industries, `1M+` systems secured, `18+` IRDAI cyber insurance carrier partners (ICICI Lombard, HDFC ERGO, Tata AIG, Bajaj Allianz, SBI General, Zurich Kotak, etc.), `500+` OEM partnerships, `1,000+` ethical hackers, `₹500 Cr` claims settled in 24 months [S4, S11].
- **Product Pages Directly Aligned with PS-06:**
  1. **`https://mitigata.com/security/dast-sast` (`Application Security Testing: DAST + SAST`)**:
     - Tagline: *"Find code flaws before attackers do."*
     - 4-Stage Pipeline: **`MAP`** (inventory repos, routes, APIs, dependencies) ? **`SELECT`** (right SAST/DAST/SCA rules) ? **`TUNE`** (strip out safe decoys and false positives) ? **`VERIFY`** (prove exploitability at runtime and re-scan fixes) [S5].
  2. **`https://mitigata.com/gordon-ai/vapt` (`Gordon AI Autonomous VAPT`)**:
     - Hero KPIs: **`0 False positives`**, **`38 Mean findings`** (matching the 36 planted bugs in PS-06!), **`48h Report delivery`**, **`11d Mean time to fix`**.
     - Workflow: *"Find it. Prove it. Fix it. Re-scan it."* [S7].
  3. **`https://mitigata.com/gordon-ai` (`CONSOLE · GORDON-V3`)**:
     - Four pillars: **`Monitor · Assess · Mitigate · Insure`**.
     - The #1 vulnerability displayed in the live `GORDON-V3` hero console on `/gordon-ai` is literally:
       `01 · SQL injection · /api/v2/users · Critical · CWE-89 · public endpoint · CVSS 9.8` [S6].
  4. **`https://mitigata.com/gordon-ai/cyber-risk-quantification`**:
     - Translates confirmed technical vulnerabilities into **FAIR (Factor Analysis of Information Risk) financial exposure in ₹ Crores**, **DPDP Act 2023 penalty risk (up to ₹250 Cr)**, **SEBI CSCRF compliance status**, and **cyber insurance underwriting bindability** [S8, S9].
