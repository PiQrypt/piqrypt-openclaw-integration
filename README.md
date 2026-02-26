# piqrypt-openclaw-integration

**Verifiable AI Agent Memory_Cryptographic audit trail for OpenClaw autonomous agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain-integration/)
[![Downloads](https://img.shields.io/pypi/dm/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain-integration/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-blue)](https://github.com/piqrypt/piqrypt)

Every reasoning step, tool execution (bash, Python, file ops), and task result — signed, hash-chained, tamper-proof.

```bash
pip install piqrypt-openclaw
```

---

## The problem

OpenClaw has OS-level access — it can run bash, write files, execute Python. When an autonomous agent has this much power, you need to know exactly what it did and when. PiQrypt makes every action cryptographically irrefutable.

---

## Quickstart

```python
from openclaw import Agent
from piqrypt_openclaw import AuditableOpenClaw

# Wrap your existing OpenClaw agent
base_agent = Agent(config)
agent = AuditableOpenClaw(base_agent, identity_file="openclaw.json")

# Execute tasks — every step is stamped automatically
result = agent.execute_task(task)

# Export tamper-proof audit trail
agent.export_audit("openclaw-audit.json")
# $ piqrypt verify openclaw-audit.json
```

---

## Granular tool stamping

```python
# Stamp each tool call individually for full traceability
agent = AuditableOpenClaw(base_agent, identity_file="openclaw.json")

# After planning
prev = agent.stamp_reasoning(task.description, plan, model="llama-3.2")

# After each tool call
prev = agent.stamp_tool_call("bash", "ls -la /reports", output, prev)
prev = agent.stamp_tool_call("python", analysis_code, result, prev)
prev = agent.stamp_tool_call("file_write", "report.pdf", "written", prev)
```

---

## Security monitoring

```python
# Detect suspicious bash patterns (rm -rf, curl | bash, etc.)
suspicious = agent.get_suspicious_events()

for event in suspicious:
    print(f"⚠️  Suspicious action stamped:")
    print(f"   Tool: {event['payload']['tool']}")
    print(f"   Hash: {event['payload']['input_hash'][:16]}...")
    print(f"   Timestamp: {event['timestamp']}")
```

Suspicious patterns are **stamped and flagged**, not blocked — the audit trail proves what happened.

---

## Decorator pattern

```python
from piqrypt_openclaw import stamp_action

@stamp_action("file_analysis", identity_file="my-agent.json")
def analyze_sales_data(path: str) -> dict:
    return your_analysis_logic(path)

@stamp_action("report_generation", identity_file="my-agent.json")
def generate_report(data: dict) -> str:
    return your_report_logic(data)
```

---

## What gets stamped

| Event | When |
|---|---|
| `agent_initialized` | Agent creation |
| `task_start` | Before task execution |
| `task_reasoning` | After LLM planning phase |
| `tool_execution` | Each tool call (bash, Python, file ops) |
| `task_complete` | After task finishes |
| `task_failed` | On exception (with error hash) |

All events are Ed25519-signed, SHA-256 hash-chained.  
Raw commands and outputs are **never stored** — only their SHA-256 hashes.

---

## Verify

```bash
piqrypt verify openclaw-audit.json
# ✅ Chain integrity verified — 24 events, 0 forks

piqrypt search --type tool_execution --limit 10
# Lists last 10 tool calls with timestamps
```

---

## Full integration guide

→ [docs/OPENCLAW_INTEGRATION.md](https://github.com/piqrypt/piqrypt/blob/main/docs/OPENCLAW_INTEGRATION.md)

---

## Links

- **PiQrypt core:** [github.com/piqrypt/piqrypt](https://github.com/piqrypt/piqrypt)
- **Issues:** [github.com/piqrypt/piqrypt/issues](https://github.com/piqrypt/piqrypt/issues)
- **Support:** piqrypt@gmail.com

---


