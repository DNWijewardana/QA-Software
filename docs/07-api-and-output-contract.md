# 07 — API & Machine-Readable Output Contract

> Spec ref: PART IX (Reporting & Output Contracts), IX.4 (canonical JSON), VI.9 (platform APIs), IX.3 (exports).

## 1. Dual output is mandatory (spec Rule 36, §0.6)

Whenever results are structured, the platform emits **both**:
1. a **machine-readable** object conforming to the canonical contract (§3 below), and
2. a **human-readable** report (IX.1 report types).

## 2. Platform REST API (spec VI.9)

Versioned (`/api/v1`), with validation · pagination (cursor) · filtering · sorting · consistent errors ·
authorization · rate limiting · idempotency keys.

### Authentication & multi-tenancy (§VIII.8) — implemented

API-key auth: requests carry `Authorization: Bearer <key>` (or `x-api-key`). A key maps to a principal
`{orgId, role}`. Auth is **opt-in**: enforced when keys are configured (`QA_API_KEYS`, a JSON array of
`{key, orgId, role, keyId}`), otherwise the API runs open in single-tenant dev mode. Keys are compared in
constant time and never logged. **RBAC:** only Owner/Admin/QAManager/SecurityAnalyst/Developer may submit
scans (write); any authenticated role may read. **Tenant isolation:** every scan record is scoped to one
`orgId`; a principal may only read/list records in its own org, and a cross-org record is reported as `404`
(never disclosed) — this is a first-class, tested security control (`tests/auth.test.ts`). `GET /health`
is public.

| Resource | Endpoints (representative) |
|---|---|
| Auth | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout` |
| Projects | `GET/POST /projects`, `GET /projects/:id` |
| Scans | `POST /projects/:id/scans` (returns job), `GET /scans/:id`, `GET /scans/:id/stream` (progress, SSE) |
| Findings | `GET /scans/:id/findings` (filter: severity/status/category/confidence…) , `GET /findings/:id` |
| Reports | `GET /scans/:id/report?format=json|human|sarif|cyclonedx|junit|csv` |
| Suppressions | `GET/POST /projects/:id/suppressions` (scoped, expiring — VII.17) |
| Baselines | `GET/POST /projects/:id/baselines`, diff at `GET /scans/:id/diff?base=…` |
| Audit | `GET /audit` (org-scoped, role-gated; append-only hash-chained log + integrity status) |

**Progress is real (spec VI.6):** the scan stream reports actual stage + completed engines + counts. No fake
percentages; "estimated remaining" is shown only when reliably computable.

## 3. Canonical output contract (spec IX.4)

Authored once in `packages/contracts` as a **Zod** schema, from which a **JSON Schema** is generated (single
source of truth). Shape (fields may extend; required ones never silently dropped):

```jsonc
{
  "schemaVersion": "2.0",
  "scan": { "id", "startedAt", "completedAt|null", "mode", "manifest": {…} },
  "projectProfile": { /* detected stack + detection confidence */ },
  "assumptions": [ { "id", "statement", "impactIfWrong" } ],
  "authorization": { "confirmed", "scope": [], "excluded": [] },
  "coverage": { "byDimension": { "security": 0.62 }, "overall": 0.71 },
  "scores": [ { "dimension", "score", "confidence", "coverage", "weight", "why": [], "unknowns": [] } ],
  "overall": { "score", "confidence", "evidenceCoverage", "criticalBlockers",
               "highRiskFindings", "untestedAreas": [], "manualVerificationRequired" },
  "findings": [ { /* full Finding record — spec VII.1 / IX.4 */ } ],
  "releaseDecision": { "decision", "conditions": [], "gatesEvaluated": [], "rationale" },
  "manualReviewQueue": [ { "item", "reason" } ],
  "limitations": [ "what was not tested and why" ]
}
```

`decision ∈ {GO, GO_WITH_CONDITIONS, NO_GO, INSUFFICIENT_EVIDENCE}`. `mode ∈ ExecutionMode`.
The full per-finding shape (status/evidenceClass/severity/cvss/cwe/traceability/…) is the spec IX.4 finding
object, mirrored exactly by the Zod schema.

## 4. Export formats (spec IX.3)

`PDF · HTML · JSON · CSV · SARIF · CycloneDX/SPDX · JUnit XML`. SARIF maps findings for code-scanning
integration; JUnit XML surfaces test results in CI; CycloneDX/SPDX carry the SBOM.

## 5. Contract stability rules

- `schemaVersion` is bumped on any breaking change; consumers pin it.
- Required fields are additive-only within a major version.
- The contract is validated in CI against golden example outputs so drift is caught (spec X.4).

## 6. Report language (spec IX.2)

Professional, precise, evidence-based. Never "Your software looks good." Instead: state what was tested, what
was not, and the confidence — e.g. "Authentication tests passed for the tested flows. Dynamic authorization
testing was not executed; authorization confidence is limited."
