# 11 — Compliance & Privacy Model

> Spec ref: PART IV.3 (compliance mapping engine), PART V.15 (data governance), V.16 (privacy engineering),
> V.30 (license/legal), PART VIII.7–VIII.10 (auditability, data security, redaction), PART I.5 (honesty — no
> false certification claims). Phase 0 document #16.
> This is a living design document. Every capability described here exists in the repository today; anything
> not yet built is listed under **Deferred**, never implied.

## 1. The honesty stance (read this first)

The platform produces **technical evidence relevant to a control**. It does **not** certify compliance and does
**not** give legal advice. Two hard rules from the spec govern everything below:

- **Never claim certification** (§I.5). The platform says *"aligned with"* / *"assessed against controls inspired
  by"*, never *"SOC 2 / ISO 27001 / PCI certified."* Certification requires an accredited human/legal process.
- **No legal-compliance claims without jurisdiction + requirements** (§IV.3, §V.16). A statement like "GDPR
  compliant" is out of scope; the platform reports *technical signals* (e.g., "PII written to logs at X") and
  leaves the legal conclusion to a human with the jurisdiction in hand.

The compliance output therefore separates **"technical evidence for control X"** from **"compliant with
regulation Y"** — only the former is produced automatically.

## 2. Compliance mapping engine (`mapCompliance`, §IV.3)

`packages/core/src/compliance.ts` maps deterministic findings onto a **control-coverage matrix**. The ground
truth is a curated `CONTROL_CATALOG` of **14 controls** across five frameworks:

| Framework | Example controls (controlId → check) |
|---|---|
| SOC 2 (illustrative) | CC6.1 no hardcoded secrets · CC7.1 dependency hygiene · CC7.2 no sensitive data in logs |
| OWASP Top 10 2025 | A05 security misconfiguration (secrets) · A06 vulnerable & outdated components |
| OWASP API Security Top 10 2023 | API2 endpoints require authentication |
| CIS Docker Benchmark | 4.1 non-root · 4.6 HEALTHCHECK · 4.10 no baked secrets · 5.31 no Docker-socket mount |
| CIS Kubernetes Benchmark | 5.2.1 no privileged · 5.2.4 no host namespaces/hostPath · 5.2.5 no privilege-escalation · 5.2.6 non-root |

Each control declares the rule IDs that evidence it and the engine that provides them (`providedByEngine`). "SOC
2 (illustrative)" is named to make clear these are *illustrative* control mappings, not an audited SOC 2 scope.

### 2.1 Honest statuses (the core design)

Every control resolves to exactly one status — and the distinctions are the whole point:

- **`SATISFIED`** — the providing check **ran** and found no violation on the mapped rules. This means *"no
  violating evidence was found by an executed check"* — **not** "compliant."
- **`GAPS`** — the check ran and found violations; the offending **finding IDs** are attached as evidence.
- **`NOT_ASSESSED`** — the providing check **did not run** for this project, so the control is honestly
  unassessed. It is **never** silently upgraded to satisfied — this is the compliance-layer expression of the
  platform-wide invariant `NOT TESTED ↛ PASS` (§I.4).

A prominent disclaimer travels with the matrix ("technical evidence only, not a certification"), and the result
is exportable as `?format=compliance` (API/web) and shown on the dashboard's compliance panel. The
`ComplianceReadiness` dimension carries weight 0 by design — compliance coverage is *reported*, never blended
into the quality score as if it were a correctness measure.

## 3. Privacy engineering (`PrivacyScanner`, §V.16)

`packages/engines/src/privacy-scanner.ts` performs **PII discovery** in source and data files, feeding the
**Privacy** dimension:

- `PRIV-PII-CARD-001` — credit-card numbers, **Luhn-validated** to suppress false positives (High, CWE-312).
- `PRIV-PII-SSN-001` — US SSNs in valid ranges, excluding obvious placeholders (Medium, CWE-359).
- `PRIV-PII-EMAIL-001` — personal emails, excluding placeholder domains (`example.*`, `test`, `localhost`, …).

**Every detected PII value is redacted before it reaches evidence** (§VIII.10) — verified by a dedicated
no-leak test, and by the fix (roadmap 2.25) that made a finding mask *all* PII on a line, not just its own
trigger (an email finding used to leave a card number visible on the same line). Adjacent signals come from the
logging engine (`OBS-LOG-SENSITIVE-001`, `OBS-LOG-PII-OBJECT-001` — personal data written to logs, mapped to
SOC 2 CC7.2) and the secret scanner (credentials).

## 4. Redaction discipline (§VIII.10) — platform-wide

Redaction is not per-engine politeness; it is a cross-cutting guarantee. Engine evidence is redacted *by the
engine* before it leaves (`EngineArtifact.content` is already redacted, with `redactedClasses` recording *counts*
of what was masked, never the values), and the orchestrator verifies each artifact's content hash before
persisting. The self-contained HTML report additionally HTML-escapes every dynamic value (untrusted scanned
code) to prevent stored XSS. The test suite includes explicit **no-leak assertions** that grep the on-disk
evidence for known secret/PII values and fail if any appears.

## 5. Data security of the platform itself (§VIII.4, §VIII.8)

The platform handles sensitive third-party source, so it protects that data as a first-class concern (see
`docs/06` for the full security model). Compliance-relevant controls already implemented:

- **Tenant isolation (§VIII.8)** — every scan record is scoped to an `orgId`; cross-org reads return 404 (never
  disclosed) and are audited. Tested as a first-class security test (`tests/auth.test.ts`).
- **Tamper-evident audit log (§VIII.7)** — append-only, **hash-chained** (each event's hash covers the previous),
  with a durable Postgres adapter that production configures to revoke UPDATE/DELETE. `verify()` detects any
  mutation. This is the evidentiary backbone auditors need.
- **AuthN/AuthZ + rate limiting** — API-key auth, RBAC (incl. an **Auditor** and **Compliance Officer** role for
  the audit endpoint), constant-time key comparison, keys never logged, per-key rate limiting.

## 6. Versioned framework registry (§IV.2, §118)

Every rule and control carries its framework **and version** (e.g., `OWASP Top 10 2025`, `WCAG 2.2`,
`CIS Kubernetes Benchmark`), so a rule's meaning never changes silently. Per-framework implementation status is
tracked as `implemented` / `partially implemented` / `planned` / `not applicable`. Current posture:

| Framework | Status |
|---|---|
| OWASP Top 10 2025, OWASP API Security Top 10 2023 | partially implemented (mapped controls above) |
| CIS Docker / CIS Kubernetes Benchmarks | partially implemented |
| SOC 2 Trust Services Criteria | *illustrative* mappings only — not an audited scope |
| GDPR · CCPA/CPRA · HIPAA · PCI-DSS v4.0 · ISO 27001/27701 | reference only — **planned**; no automated legal claims |

## 7. License / legal technical checks (§V.30)

`LicenseScanner` reports **facts only** (declared license metadata) and draws no legal conclusions — see
`docs/10` §4. It never asserts license compatibility.

## 8. Deferred (not yet built — stated, not implied)

- **Jurisdiction-aware compliance** — accepting a jurisdiction + requirement set and producing a scoped
  control-coverage package; audit-export **evidence bundles per control** for SOC 2 / ISO 27001 readiness reviews.
- **Privacy depth (§V.16)** — DSAR / right-to-erasure verification, consent-flow analysis, purpose-limitation,
  cross-border-transfer flags, third-party-processor inventory, **LINDDUN** privacy threat modeling, and
  dark-pattern detection in consent UX.
- **Data governance (§V.15)** — data lineage, classification/labeling, data-contract validation.
- **More frameworks** — expanding the catalog toward ISO 27001/27701, PCI-DSS v4.0, and HIPAA control sets.
- **Human sign-off workflow** — routing `GAPS`/`NOT_ASSESSED` controls to a Compliance Officer for attestation
  (the roles exist; the workflow does not yet).
