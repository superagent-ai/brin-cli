<p align="center">
  <img src="assets/brin-logo.png" alt="brin" height="120">
</p>

<h1 align="center">brin cli</h1>
<p align="center">
  the credit score for context
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  &nbsp;
  <a href="https://www.ycombinator.com"><img src="https://img.shields.io/badge/Backed%20by-Y%20Combinator-orange" alt="Backed by Y Combinator"></a>
  &nbsp;
  <a href="https://discord.gg/spZ7MnqFT4"><img src="https://img.shields.io/badge/Discord-Join-7289da?logo=discord&logoColor=white" alt="Discord"></a>
  &nbsp;
  <a href="https://x.com/superagent_ai"><img src="https://img.shields.io/badge/X-Follow-000000?logo=x&logoColor=white" alt="X"></a>
  &nbsp;
  <a href="https://www.linkedin.com/company/superagent-sh/"><img src="https://img.shields.io/badge/LinkedIn-Follow-0077b5?logo=linkedin&logoColor=white" alt="LinkedIn"></a>
</p>

---

your agents are at risk every time they use external context. brin pre-scans packages, skills, and web pages to detect malware, prompt injection, and supply chain attacks.

this repo contains the **brin cli** — a thin Rust client over the [brin API](https://api.brin.sh). no sdk, no auth, no signup. a single command returns a score, verdict, and threat data.

---

## install

### via npm

```bash
npm install -g brin
```

### via shell script

```bash
curl -fsSL https://brin.sh/install.sh | sh
```

---

## usage

```
brin check <origin>/<identifier>
```

before your agent acts on any external context, make a single call. brin returns a score, verdict, and any detected threats.

### packages

```bash
brin check npm/express
brin check npm/lodash@4.17.21
brin check pypi/requests
brin check crate/serde
```

```json
{
  "origin": "npm",
  "name": "express",
  "score": 81,
  "confidence": "medium",
  "verdict": "safe",
  "tolerance": "conservative",
  "scanned_at": "2026-02-25T09:00:00Z",
  "url": "https://api.brin.sh/npm/express"
}
```

### repositories

```bash
brin check repo/expressjs/express
```

### MCP servers

```bash
brin check mcp/modelcontextprotocol/servers
```

### agent skills

```bash
brin check skill/owner/repo
```

### domains and pages

```bash
brin check domain/example.com
brin check page/example.com/login
```

### commits

```bash
brin check commit/owner/repo@abc123def
```

---

## flags

| flag | description |
|------|-------------|
| `--details` | include sub-scores (identity, behavior, content, graph) |
| `--webhook <url>` | receive tier-completion events as the deep scan progresses |
| `--headers` | print only the `X-Brin-*` response headers instead of the JSON body |

### --details

```bash
brin check npm/express --details
```

```json
{
  "origin": "npm",
  "name": "express",
  "score": 81,
  "verdict": "safe",
  "sub_scores": {
    "identity": 95.0,
    "behavior": 40.0,
    "content": 100.0,
    "graph": 30.0
  }
}
```

### --webhook

brin runs a 3-tier analysis — the LLM tier takes 20–30s. pass a webhook url to receive results as each tier completes rather than waiting:

```bash
brin check npm/express --webhook https://your-server.com/brin-callback
```

events posted to your endpoint:

| event | description |
|-------|-------------|
| `tier1_complete` | identity + registry metadata done |
| `tier2_complete` | static analysis done |
| `tier3_complete` | LLM threat analysis done |
| `scan_complete` | final score with graph analysis |

### --headers

for fast, scriptable checks without JSON parsing:

```bash
brin check npm/express --headers
```

```
X-Brin-Score: 81
X-Brin-Verdict: safe
X-Brin-Confidence: medium
X-Brin-Tolerance: conservative
```

flags can be combined:

```bash
brin check npm/express --details --webhook https://your-server.com/cb
```

---

## what we score

six types of external context that agents consume autonomously — each with a distinct threat model and scoring methodology.

| origin | example | threats detected |
|--------|---------|-----------------|
| `npm` / `pypi` / `crate` | `npm/express` | install-time attacks, credential harvesting, typosquatting |
| `domain` / `page` | `domain/example.com` | prompt injection, phishing, cloaking, exfiltration via hidden content |
| `repo` | `repo/owner/repo` | agent config injection, malicious commits, compromised dependencies |
| `skill` | `skill/owner/repo` | description injection, output poisoning, instruction override |
| `mcp` | `mcp/owner/server` | tool shadowing, schema abuse, silent capability escalation |
| `commit` | `commit/owner/repo@sha` | PR injection, security sabotage, backdoor introduction |

---

## how it works

before your agent acts on any external context, make a single GET request. brin returns a score, verdict, and any detected threats. pre-scanned results return in under 10ms — fast enough to sit in the critical path of every agent action, no queues, no cold starts.

```
brin check npm/express
      |
      v
GET https://api.brin.sh/npm/express
      |
      v
  score · verdict · threats
```

if brin is unreachable, the agent continues as normal — zero risk to your existing workflow.

---

## for ai agents

- **[Cursor](https://www.brin.sh/docs/guides/cursor)**
- **[Claude Code](https://www.brin.sh/docs/guides/claude-code)**
- **[OpenCode](https://www.brin.sh/docs/guides/opencode)**
- **[Gemini CLI](https://www.brin.sh/docs/guides/gemini-cli)**
- **[Codex CLI](https://www.brin.sh/docs/guides/codex-cli)**

---

## environment variables

| variable | default | description |
|----------|---------|-------------|
| `BRIN_API_URL` | `https://api.brin.sh` | override the API endpoint |

---

## local development

```bash
git clone https://github.com/superagent-ai/brin
cd brin
cargo build
cargo test
```

---

## contributing

see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## license

MIT

---

<p align="center">
  <sub>built by <a href="https://superagent.sh">superagent</a> — ai security for the agentic era</sub>
</p>
