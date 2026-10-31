# Mitigata Hackathon — War Room Council State

- **Hackathon Name:** Mitigata Hackathon 2026
- **Sponsor / Organiser:** Mitigata (`https://mitigata.com/`) — Mitigata Insurance Brokers Pvt. Ltd. (Subsidiary of Alphawave Technologies Private Limited; IRDAI Registration No. `1115/2024`, License `1013`, CIN `U66220KA2024PTC186580`)
- **Date:** October 31, 2026 (PRD dated `30 October 2026 · Anuj`)
- **Primary Problem Statement Selected:** `PROBLEM 06 · FLAGSHIP` — **SAST and DAST Correlation** (*"Scan an app's source code and its running version, then connect the results so each real vulnerability appears once, with the line of code and proof it can be exploited. Solve it for bonus points."*)
- **Source Artefacts Analysed:**
  1. `d:\Mitigata\Hackathon Problem Statements.pdf` (7-slide official deck: `PROBLEM 01` to `PROBLEM 06 · FLAGSHIP`, with real incident anchors `INC-01` to `INC-06`)
  2. `d:\Mitigata\PRD_SAST_DAST_Correlation.docx.pdf` & user-uploaded `media_1793427809899_793e9247.pdf` (5-page Flagship PRD authored by `Anuj`, dated `30 October 2026`, covering `FR-1` to `FR-10`, `B-1` to `B-7`, 36 planted vulnerabilities = 20 pairs + 10 code-only + 6 runtime-only, 8 safe decoys, unseen second app, 7 quantitative answer-key targets, Reachability-Aware SCA bonus feature, and Page 5 language strategy)
  3. User-uploaded `media_1793427832701_51b87539.png` (Slide `07 / 07` — `PROBLEM 06 · FLAGSHIP`)
  4. `d:\Mitigata\Problem Statements.docx` (initial 6-problem-statement summary draft)
  5. Live crawl of `https://mitigata.com/` (`/`, `/security/dast-sast`, `/gordon-ai`, `/gordon-ai/vapt`, `/gordon-ai/cyber-risk-quantification`, `/compliance/sebi-cscrf`, `/resources/apis`, `/personal`, `/company/about-us`, `/company/careers`)

---

## Approved 25-Seat War-Room Council Roster

| Seat # | Person | Role / Credentials | Jurisdiction in War Room | Mode on PS-06 |
| :--- | :--- | :--- | :--- | :--- |
| **01** | **Peter Thiel** | Co-founder PayPal, Palantir, Founders Fund | Contrarian secret, 0-to-1 monopoly vs crowded ASPM tarpit | **LEAD** |
| **02** | **Alex Karp** | Co-founder & CEO, Palantir | Ontology-first architecture pitch (*Code-to-Runtime-to-Rupee Ontology*) | **LEAD** |
| **03** | **Patrick Jane ◇** | Consultant (*The Mentalist*) | Reads PRD author (`Anuj`), Mitigata founders, hidden rubric & decoy traps | **LEAD (Chair — Recon)** |
| **04** | **Warren Buffett** | CEO, Berkshire Hathaway | Cyber insurance float, underwriting pricing power, ₹ ROI for CFOs | **LEAD** |
| **05** | **Harvey Specter ◇** | Senior Partner (*Suits*) | Scope-lock legality, safe-harbour active probing, insurance policy wording | **LEAD (Veto)** |
| **06** | **Mike Ross ◇** | Legal & Human Conscience (*Suits*) | Developer/AppSec burnout empathy + DPDP Act / SEBI CSCRF / CERT-In law | **LEAD (Veto)** |
| **07** | **Steve Jobs †** | Co-founder, Apple | 45-second live demo theatre (`36 bugs -> 20 Confirmed -> 0 false alarms`) | **LEAD** |
| **08** | **Elon Musk** | Founder, SpaceX, Tesla, xAI | First-principles `<35s` execution speed vs 5-minute Great ceiling | **LEAD** |
| **09** | **Andrej Karpathy** | Founding Member OpenAI, ex-Director AI Tesla | Deterministic AST/CFG + 2-phase DAST first; zero-hallucination AI fix suggestions | **LEAD (Veto)** |
| **10** | **Dr. S. Jaishankar** | External Affairs Minister, India | Sovereign Indian cyber resilience (*Atmanirbhar* AppSec, CERT-In & NCIIPC) | **LEAD** |
| **11** | **Dr. R.S. Sharma** | Ex-DG UIDAI, Ex-Chair TRAI, Ex-CEO NHA | Population-scale DPI, CERT-In 6-hour directions, SEBI CSCRF, DPDP Rules 2025 | **LEAD (Veto)** |
| **12** | **Charlie Munger †** | Vice Chairman, Berkshire Hathaway | Inversion pre-mortem (`Wrong links < 5%` math trap, 8 safe decoys, `Unknown` SCA) | **LEAD (Veto)** |
| **13** | **Seth Godin** | Author (*Purple Cow*, *This Is Marketing*) | Remarkable positioning: *The Equifax (`INC-06`) Prevention Graph* | **LEAD** |
| **14** | **Gary Vaynerchuk** | CEO, VaynerMedia | Developer distribution, SARIF CI/CD PR gate (`B-6`), GitHub/GitLab adoption | **LEAD** |
| **15** | **Tim Cook** | CEO, Apple | Operational discipline, Docker Compose 1-command reproducibility, unseen-app reliability | **LEAD** |
| **16** | **Jony Ive** | Founder, LoveFrom; ex-CDO Apple | 3-screen high-craft dark console matching `GORDON-V3` (`/gordon-ai`) | **LEAD** |
| **17** | **Paul Graham** | Co-founder, Y Combinator | Schlep filter & Hackathon Judge Simulator (chairs 9-criterion scoring) | **LEAD (Chair — Scoring)** |
| **18** | **Mohit Anand** | Co-founder & CEO, Mitigata | Buyer-judge lens: unifying Security (`Assess`), Compliance, and Insurance (`Insure`) | **LEAD** |
| **19** | **Sarthak Dubey** | Co-founder & COO, Mitigata | Gordon AI VAPT pod ops (`0 False positives`, `38 Mean findings`, `48h delivery`) | **LEAD** |
| **20** | **Isaac Evans** | Founder & CEO, Semgrep (r2c) | Fast `tree-sitter` / Python `ast` rules, taint tracking & `B-2` safe-decoy suppression | **LEAD** |
| **21** | **Oege de Moor** | Creator of CodeQL (Semmle), GitHub Next | Inter-procedural call graphs, route-to-sink mapping (`FR-4`, `FR-5`), SCA call chains | **LEAD** |
| **22** | **Dafydd Stuttard** | Creator of Burp Suite (PortSwigger) | 2-Phase DAST (`FR-2`), `B-1` auto-verify probing, and 6 `Runtime only` bug capture | **LEAD** |
| **23** | **Oliver Chang** | Creator of Google OSV.dev & OpenSSF Fuzzing | Page 4 Bonus: Reachability-Aware SCA (SBOM, GHSA/EPSS/KEV, OSV diff symbols) | **LEAD** |
| **24** | **Subho Halder** | Co-founder & CISO, Appknox | Multi-scanner normalization (`FR-3`), SARIF CI/CD gating (`B-6`), scan diffing (`B-5`) | **LEAD** |
| **25** | **Sandeep Kamble** | Founder & CTO, SecureLayer7 | Offensive exploit verification, route parameter normalization, unseen-app generalisation | **LEAD** |

---

## Summary of Winnability & Top 5 Ideas for `PROBLEM 06 · FLAGSHIP`

### Domain Winnability Ranking (All 6 Hackathon Challenges)
1. **`PROBLEM 06 · FLAGSHIP`: SAST and DAST Correlation (+ Reachability-Aware SCA)** — **9.55 / 10** *(Explicitly badged `FLAGSHIP` + `Solve it for bonus points`; backed by 5-page quantitative PRD; 100% aligned with Mitigata's `/security/dast-sast` and `/gordon-ai/vapt`)*
2. **`PROBLEM 04`: Autonomous Pentest Engine (CART)** — **8.59 / 10** *(Strong alignment with `/gordon-ai/vapt`, but coordinating network + web + binary agents live in 24–48h has high demo-failure risk)*
3. **`PROBLEM 01`: Kill Chain and Attack Path Analysis (15–50 GB logs)** — **8.23 / 10** *(Core to Mitigata's AI SOC, but 50 GB out-of-core streaming is heavy backend plumbing)*
4. **`PROBLEM 03`: Community Scam Map for India** — **7.53 / 10** *(High visual appeal and `INC-03` relevance, but overcrowded beginner CRUD tarpit)*
5. **`PROBLEM 02`: Multi-Tenant Aggregation Layer (10M records, 100 tenants)** — **7.50 / 10** *(Crucial for Gordon AI console scale, but low 3-minute stage theatrics)*
6. **`PROBLEM 05`: Config-Driven Integration Platform** — **7.29 / 10** *(Essential internal GRC connector plumbing, lowest hackathon demo excitement)*

### Top 5 Ranked Ideas for `PROBLEM 06 · FLAGSHIP` (SAST and DAST Correlation)
1. **Idea 1 — `GORDON CORRELATE` (Recommended #1 Pick):** Deterministic AST Route-to-Sink Call-Graph + 2-Phase Authenticated DAST Correlator + `B-1` Auto-Verifier + `B-2` Decoy Killer + 5-Step Reachability-Aware SCA — **Score: 9.60 / 10** (`Doesn't exist`)
2. **Idea 2 — `GORDON SARIF-DIFF & AUTO-VERIFY HUB`:** Universal Multi-Scanner Normalizer (`FR-3`), `B-1` Code-Only-to-Confirmed Active Auto-Verifier, `B-5` Differential Scan Engine & `B-6` SARIF CI Gate — **Score: 9.34 / 10** (`Doesn't exist`)
3. **Idea 3 — `GORDON UNDERWRITE-BRIDGE`:** Confirmed-Exploit-to-FAIR Financial Risk Quantifier (`₹ Cr`), SEBI CSCRF 3-Month Closure Tracker & IRDAI Cyber Insurance Underwriting Binder — **Score: 9.33 / 10** (`Exists abroad, not in India`)
4. **Idea 4 — `GORDON REACH-SCA` (Dark Horse Pick):** 5-Step Reachability-Aware SCA Engine (Lockfile Transitive SBOM + GHSA/CVSS/EPSS/KEV + OSV/Fix-Commit Diff Function Map + Entry-to-Library Call Graph + Supply-Chain Typosquat/Confusion Detector) — **Score: 9.29 / 10** (`Exists-but-weak`)
5. **Idea 5 — `GORDON SHADOW-SURFACE`:** AST-vs-Runtime Differential Route Auditor & Polyglot Dual-Framework (`Python + Node.js/Express`) Engine (`B-7`) — **Score: 8.99 / 10** (`Exists-but-weak`)

- **Council Recommendation:** Build **Idea 1 (`GORDON CORRELATE`)** as the unified flagship platform incorporating the `B-1..B-7` bonus modules from Ideas 2 & 5, the **5-step Reachability-Aware SCA** engine from Idea 4, and the **Gordon AI FAIR ₹ Risk & SEBI CSCRF panel** from Idea 3.
