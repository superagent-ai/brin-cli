# brin — Agent Instructions

## Project Overview

brin is a secure package gateway for agents. It wraps npm/yarn/pnpm/bun. Before installing any package, it checks a database of pre-scanned results (CVE lookups, static analysis, threat detection). No scanning happens at install time, so there's no slowdown. If the package passes, brin hands off to your actual package manager.

## Legal & Communication Guidelines

Apply to ALL security assessments, reports, marketing copy, SKILL.md generation, and public-facing content.

### CVE/GHSA Data (from OSV, GitHub Advisory, NVD)

Authoritative third-party data. State as fact.
- Include CVE/GHSA ID for traceability
- Cite source: "per GitHub Advisory GHSA-xxxx" or "CVE-2024-xxxxx (OSV)"
- OK: "lodash 4.17.20 has CVE-2021-23337 (GitHub Advisory)"

### brin-Detected Issues (agentic threats, capability analysis)

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
