# sus — Agent Instructions

## Project Overview

sus (Secure Package Gateway for AI Agents) is a security layer that sits in front of npm/yarn/pnpm/bun. It scans packages before installation using CVE databases, AI-powered threat detection, and static capability analysis.

## Architecture

```
crates/
├── api/        → REST API serving scan results from database
├── cli/        → User-facing CLI (sus add, sus scan, etc.)
├── common/     → Shared models, database, queue
├── cve/        → CVE enrichment worker (OSV, GitHub Advisory)
├── seed/       → Database seeding
├── watcher/    → npm registry change feed monitor
└── worker/     → Package scanning (CVE + agentic + capabilities)
```

## Key Files

- `worker/src/scanner/agentic.rs` — AI threat detection prompts
- `worker/src/scanner/mod.rs` — Main scanning orchestration
- `common/src/models.rs` — Data models and threat types
- `api/src/handlers.rs` — API response formatting

---

## Legal & Communication Guidelines

Apply to ALL security assessments, reports, marketing copy, SKILL.md generation, and public-facing content.

### CVE/GHSA Data (from OSV, GitHub Advisory, NVD)

Authoritative third-party data. State as fact.
- Include CVE/GHSA ID for traceability
- Cite source: "per GitHub Advisory GHSA-xxxx" or "CVE-2024-xxxxx (OSV)"
- OK: "lodash 4.17.20 has CVE-2021-23337 (GitHub Advisory)"

### sus-Detected Issues (agentic threats, capability analysis)

Automated assessment. Use cautious language.
- USE: "detected," "patterns consistent with," "risk indicators," "flagged," "assessed as"
- AVOID: "vulnerability," "malicious," "dangerous," "compromised," "contains"
- Include confidence scores when available
- Frame as input to human judgment, not verdict

### Risk Levels

- "assessed as high-risk" not "is high-risk"
- "indicators suggest" not "package does X"
- Never imply maintainer negligence or malice

### Required Context

Imply or include:
- Assessments are automated, may contain errors
- Findings are risk indicators, not confirmed threats
- Point-in-time assessment; security posture changes
- Dispute process exists for maintainers

### Examples

BAD: "contains malicious code that steals data"
GOOD: "detected patterns consistent with data exfiltration"

BAD: "dangerous, should never be used"
GOOD: "assessed as high-risk due to [indicators]; review flagged concerns"

BAD: "maintainer included a backdoor"
GOOD: "detected code patterns warranting manual review; reported to maintainer"

BAD: "has prompt injection vulnerability"
GOOD: "flagged for potential prompt injection patterns (confidence: 0.82)"

### Default Behavior

- Understate rather than overstate severity
- Err toward caution on language
- False positive published confidently causes more harm than true positive published cautiously
