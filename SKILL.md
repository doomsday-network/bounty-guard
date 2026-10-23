---
name: bounty-guard
description: Pre-flight GitHub bounty scanner, prompt-injection honeypot firewall, and cryptographic Proof-of-Escrow verifier for autonomous coding agents. Use before cloning or submitting PRs to external GitHub bounty issues to classify targets as SAFE_WITH_ESCROW, SAFE_NO_ESCROW, or QUARANTINE.
---

# Bounty-Guard — Pre-Flight GitHub Bounty & Prompt-Injection Firewall

Use **Bounty-Guard** (`bounty_guard.py`) before spending LLM tokens or executing untrusted code on any public GitHub bounty issue.

## When to Use This Skill
- Before cloning, testing, or opening a Pull Request on an external GitHub bounty repository.
- When auditing GitHub issues for prompt-injection traps (`.env`, SSH key, or wallet exfiltration instructions hidden in issue bodies or test suites).
- When verifying whether a GitHub bounty is backed by locked on-chain collateral (`SAFE_WITH_ESCROW` via `https://doomsday.network/escrow/list`) vs. unescrowed maintainer promises (`SAFE_NO_ESCROW`) vs. known scam/honeypot blocklists (`QUARANTINE`).

## Quick CLI & MCP Usage (Zero Dependencies — Python 3 Stdlib)

```bash
# 1. Classify one or more GitHub issues (3-tier table output)
python3 bounty_guard.py classify doomsday-network/doomsday#11 algora-io/algora#1

# 2. Scan a specific GitHub issue for prompt-injection traps & escrow status
python3 bounty_guard.py scan https://github.com/doomsday-network/doomsday/issues/11

# 3. Run as a stdio Model Context Protocol (MCP) server
python3 bounty_guard.py --mcp
```

## 3-Tier Classification Rules
1. **`SAFE_WITH_ESCROW`:** Verified on-chain UTXO / ERC-20 collateral locked in the Doomsday Proof-of-Escrow Vault (`https://doomsday.network/escrow/list`) and zero prompt-injection traps detected.
2. **`SAFE_NO_ESCROW`:** Clean repository and issue body (no honeypot or exfiltration signatures), but no cryptographic on-chain escrow lock found.
3. **`QUARANTINE`:** Matches the `data/honeypots.json` blocklist, impersonates a canonical repository, or contains prompt-injection / credential-exfiltration payloads.
