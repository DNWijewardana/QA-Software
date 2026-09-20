# 12 — UI/UX Information Architecture

> Spec ref: PART IX.5 (key screens), IX.6 (finding detail), IX.7 (dashboard/search/filter/notifications),
> IX.8 (UI quality bar), IX.10 (no fake data), §VII.13 (traceability), Rule 10 (never hide limitations).
> Phase 0 document #12. This is a living document. Section 3 describes what is **implemented today**; section 6
> is the **planned** full information architecture, honestly separated — the UI is not claimed to be complete.

## 1. Design principles (the UI bar, §IX.8)

The interface must feel like a serious engineering product, not a marketing dashboard:

- **Evidence-first.** Every score, status, and decision drills down to the evidence that produced it; nothing is
  asserted without a "why?" and a linkable artifact (§VII.6, §51).
- **Honesty is visible, not buried.** `NOT TESTED` / `INSUFFICIENT EVIDENCE`, manual-review items, and
  limitations are first-class UI, not footnotes (§I.4, Rule 10). No fake progress, no decorative charts, no
  invented counts (§IX.10, §VI.6).
- **Severity hierarchy + text, never color alone.** Severity and release decisions are conveyed by text/mark
  *and* color, for accessibility and print (§IX.8).
- **Clarity and information density** over gradients, huge type, and empty space.
- **Accessible to its own standard.** The platform's own UI targets **WCAG 2.2 AA** (§IX.8) — it must not fail
  the checks it runs on others.

## 2. Architecture of the web tier (how the IA is delivered)

`apps/web` is a **Next.js 14 App-Router BFF** that proxies to the API via same-origin route handlers
(`app/api/*/route.ts`). It bundles **no** `@qa/*` packages, so no Node-only code reaches the browser and there
is no CORS surface. A server-side `QA_API_KEY` is attached by the proxy and never exposed to the client. This
keeps the UI a thin, secure presentation layer over the same canonical result contract (§IX.4) that the CLI and
API emit — one source of truth, many views.

## 3. Implemented screens & components (today)

| Screen / route | Purpose | Key components |
|---|---|---|
| **Home** (`/`) | Submit a scan (project dropdown from `GET /targets`, or a public git URL) + list recent scans | `SubmitForm`, recent-scans list |
| **Scan detail** (`/scans/[id]`) | Live status → full result once COMPLETED | `ScanLive` (1s polling, accessible `role="progressbar"`) |

The **scan detail** page renders the full evidence-first result via these panels (`QualityPanels.tsx`,
`FindingsTable.tsx`, `Badges.tsx`):

- **Overall** — score, evidence coverage, critical blockers, high-risk, manual-verification (KPIs).
- **Quality dimensions** — accessible score **meters** (`role="meter"`), each with its "why" explanation.
- **Compliance** — control-coverage table (SATISFIED / GAPS / NOT_ASSESSED as text+mark, never color alone).
- **Supply-chain (SBOM)** — CycloneDX components with the honest `NOT_TESTED` vulnerability status called out.
- **SEO** — issues, labeled "separate from software quality" (§V.24).
- **Manual review required** — the human-judgment queue (§IX.5).
- **Limitations (never hidden)** — what was not tested and why (Rule 10).
- **Findings table** — severity filter, with report/export links (human/JSON/SARIF/JUnit/CSV/CycloneDX/HTML).

**Accessibility measures already in place (WCAG 2.2 AA target):** semantic landmarks, a skip link, visible
focus (`:focus-visible`), severity/decision conveyed by text+color, reduced-motion support, light/dark themes,
and a phone-width responsive layout.

## 4. Navigation model

```
Landing → Dashboard → Project → Scan (new / detail) → Finding detail
                          └→ Trends · Compliance · Supply-chain · Reports · Policies · Audit log
```

The spine is **Project → Scan → Finding → Evidence**, mirroring the traceability chain
`Requirement → Test → Evidence → Defect → Release Decision` (§VII.13). Today the implemented slice is the
**Scan → Findings/panels → Evidence** portion; the Project/Dashboard shell above it is planned (§6).

## 5. The finding detail view (§IX.6) — target shape

A dedicated finding page (planned as its own route; today findings render inline in the table + panels) shows:
Title · Severity · Confidence · Status · Risk · Affected component · **Evidence** · Why it matters · How it was
detected · Reproduction · Expected · Actual · Root-cause hypothesis · Recommended fix · Related requirement ·
Related test · Related standard · Retest · History. Every dynamic value is escaped (findings come from untrusted
scanned code — the HTML report already enforces this; the React UI escapes by default).

## 6. Planned information architecture (§IX.5) — not yet built

The full screen inventory the IA is designed toward (honestly marked planned):

- **Auth & shell:** Landing · Login · Registration · global nav · global **Search** (projects/scans/findings/
  files/endpoints/components) · **Filters** (severity/confidence/status/category/component/standard/date/owner).
- **Dashboard** (§IX.7): projects · recent scans · quality/risk **trends** · open & critical findings · release
  readiness · per-area health (test/security/perf/a11y/dependency/**compliance**).
- **Project view** (§60): overview · environments · repositories · scans · findings · requirements · coverage ·
  security · performance · accessibility · dependencies · architecture · reports · trends · settings.
- **Scan configuration** (§IX.9): scan tiers (QUICK/STANDARD/DEEP/CUSTOM) with expected engines/duration/impact
  shown, and a **scan-plan preview** whose counts appear only after the plan is generated (never invented).
- **Dedicated pages:** Finding detail · Requirements & traceability · Coverage · Trends · **Compliance** ·
  **Supply-chain** · **AI/LLM quality** (only if AI features exist) · **Manual review queue** workflow ·
  Policies (weights/gates editor) · Suppressions (scoped/auditable editor) · Integrations · **Audit log** viewer.
- **Differential view:** a "compare to baseline" screen over the existing `GET /scans/:id/diff` endpoint.

## 7. Deferred / notes

- The dashboard, project shell, dedicated finding page, requirements/coverage/trends, and the policy/suppression
  editors are **planned**; the backend for several already exists (diff endpoint, policy/suppression inputs,
  audit endpoint, compliance/SBOM/SEO exports), so these are primarily front-end work.
- **AI/LLM quality** screens are gated on AI features being enabled (see the — deliberately unwritten until then
  — AI/LLM Governance model, doc #17).
- The implemented UI has been verified by `next build` (types + routes) and live runs through the proxy; a
  browser-automation E2E suite is future work (see `docs/09` §10).
