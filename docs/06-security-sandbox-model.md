# 06 — Security & Sandbox Model (incl. Threat Model)

> Spec ref: PART VIII (Security, Authorization, Sandboxing & Safe Execution), VIII.1–VIII.10, V.8 (threat modeling).

## 1. Execution modes (spec VIII.1)

| Mode | Meaning | Default |
|---|---|---|
| `SAFE_STATIC` | Analyze uploaded code/config only | **Current build runs here** |
| `SAFE_DYNAMIC` | Test a controlled environment | Requires Definition of Ready |
| `AUTHORIZED_SECURITY` | Security tests vs explicitly authorized targets only | Requires written authorization |
| `DESTRUCTIVE` | Disabled by default; explicit auth + safeguards | Off |
| `PRODUCTION` | READ-ONLY / LOW-RISK; never destructive automatically | Read-only |

## 2. Pre-dynamic authorization gate (spec VIII.2, §0.3.1 Definition of Ready)

Before ANY dynamic/security/outward-facing action, ALL must be captured or the job stays in `SAFE_STATIC`:
target identity & environment · **written authorization for the exact scope** · allowed & excluded scope ·
test intensity/rate limits/allowed hours · data-sensitivity classification · rollback/abort procedure.
Missing any item ⇒ **do not proceed** (Appendix B pre-flight checklist).

## 3. Payload safety (spec VIII.3)

Non-destructive payloads only. Never delete production data · modify financial transactions · exfiltrate real
secrets · damage systems · persist unauthorized access. Verify vulnerabilities **without unnecessary exploitation**.

## 4. Sandbox for untrusted project execution (spec VIII.5) — treat ALL uploads as untrusted

Uploaded source is untrusted input. Execution (dependency install, tests, browser runs) happens in an
**ephemeral, per-job container** destroyed after use, with:

- **default-deny egress** + explicit allowlist (e.g., package registries only when needed);
- CPU / memory / disk quotas · execution timeouts · process (pid) limits;
- filesystem isolation (no host FS access) · no privilege escalation · no container escape surface;
- seccomp/AppArmor-style syscall profiles;
- guards against fork bombs, infinite loops, malicious build scripts, resource exhaustion.

Phase 1 (SAFE_STATIC) does **not execute** untrusted code — static analysis reads files only. Any future stage
that *executes* code MUST run in the sandbox above; this is a Definition-of-Done gate for those engines.

## 5. Platform data security (spec VIII.4, VIII.10)

Authentication · authorization · RBAC · secure sessions · encryption in transit & at rest · secure file
storage · tenant isolation · audit logging · secret management (KMS) · secure deletion · upload validation ·
malware-safe handling · resource limits · network isolation. **Secrets are never logged. Reports never expose
secrets or PII** (redaction — see doc 04).

## 6. Multi-tenancy (spec VIII.8) — a first-class, tested control

Org A must **never** access Org B's projects/scans/source/reports/findings/credentials. Enforced by: tenant
scoping on every query (row-level, `org_id` guard in NestJS) + RBAC. **Tenant isolation is an explicit security
test in the platform's own test suite, not an afterthought** (spec VIII.8, X.7).

Roles: Owner · Admin · QA Manager · Security Analyst · Developer · Viewer · Auditor · Compliance Officer.

## 7. Threat model (STRIDE) — the platform itself (spec V.8)

| Threat | Vector | Mitigation |
|---|---|---|
| **S**poofing | Stolen session/token | Short-lived tokens, secure cookies, (later) SSO/OIDC + MFA |
| **T**ampering | Malicious upload alters host / poisons results | Sandbox isolation; content-hashed evidence; hash-chained audit log |
| **R**epudiation | User denies an action | Append-only, hash-chained `AuditEvent` (VIII.7) |
| **I**nfo disclosure | Secrets/PII in reports or cross-tenant leak | Mandatory redaction; tenant row-scoping; encryption at rest |
| **D**oS | Fork bomb / huge upload / scan flood | Sandbox quotas; upload size limits; queue backpressure & rate limits |
| **E**levation | Container escape; RBAC bypass | Seccomp profiles, non-root containers; deny-by-default authz guards |

LINDDUN (privacy) and MITRE ATT&CK mapping are added when privacy/security engines land (spec V.8, V.16).

## 8. Auditability & reproducibility (spec VIII.6, VIII.7)

Every scan records who initiated it, target, config, versions, tools, rules, timestamps, environment, results,
overrides, suppressions. The execution manifest (doc 04 §5) makes results reproducible; the audit log is
tamper-evident.
