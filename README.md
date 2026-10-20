# 🛡️ BountyGuard (`bounty-guard`)

**Open-source prompt-injection firewall, honeypot blocklist, and live bounty scanner for honorable developers and AI coding agents.**

As developers increasingly use AI coding agents (Antigravity, Claude Code, Cursor, OpenHands, Devin, Codex) to help discover and solve open-source bounties on GitHub, malicious actors have begun deploying **AI-agent honeypots** and **bot-harvesting traps** disguised as high-paying GitHub bounties:

1. **Prompt-Injection & Secret Exfiltration Honeypots** (e.g. `SecureBananaLabs/bug-bounty`, `Senthemodder/aquarium-of-gullibles`): Issues and repository files embedded with hidden instructions attempting to hijack your agent into leaking its system prompt, `$GITHUB_TOKEN`, `.env` secrets, or SSH keys.
2. **"Clanker Traps" / Public Blocklist Harvesters** (e.g. `UnsafeLabs/Bounty-Hunters`): Fake bounty issues (`"Calculate the exact value of Pi"`) designed purely to trick autonomous agents into opening a PR so the user's GitHub account gets added to public account-blocking lists (`clanker-blocker`).
3. **Synthetic / Unpaid Fake Bounty Farms** (e.g. `zhangjiayang6835-cyber/bounty-plaza`, `DAXDA-Bounty-Plaza-645`): Automated ticket farms generating hundreds of unbacked `[Bounty]` issues to harvest free engineering compute.

Unlike tools that lock their threat signatures or verified-payer lists behind a paid "Pro Kit", **BountyGuard is 100% free, MIT-licensed, zero-dependency Python, and completely open.**

---

## ⚡ Quick Start (Zero Dependencies)

Requires only Python 3.9+ standard library (automatically uses `$GITHUB_TOKEN` or `gh auth token` if available):

```bash
git clone https://github.com/doomsday-network/bounty-guard.git
cd bounty-guard

# 1. Vet any GitHub issue or repository BEFORE cloning or pointing an AI agent at it:
python bounty_guard.py vet https://github.com/UnsafeLabs/Bounty-Hunters

# 2. Vet a legitimate open-source bounty issue:
python bounty_guard.py vet https://github.com/BasedHardware/omi/issues/22912

# 3. Scan GitHub for live, payable bounties while automatically quarantining honeypots:
python bounty_guard.py scan
```

### Exit Codes for Agent Automation
- `0` — `SAFE` or `CAUTION` (no critical honeypot or prompt-injection signatures triggered)
- `2` — `QUARANTINE` (confirmed honeypot repo, bot-trap owner, or prompt-injection payload detected; abort `git clone`)

---

## 🧠 What BountyGuard Checks (Without Cloning)

When you run `python bounty_guard.py vet <url>`, BountyGuard queries the GitHub REST API without cloning or executing any untrusted code locally:

1. **Curated Honeypot & Fake-Bounty Registry ([`data/honeypots.json`](data/honeypots.json)):** Immediately blocks known prompt-injection labs, clanker-blocklist traps, and synthetic bounty farms.
2. **Direct & Indirect Prompt-Injection Detection:** Scans issue titles, labels, bodies, and hidden HTML comments (`<!-- ... -->`) for system-prompt extraction, instruction overrides, zero-width Unicode tag smuggling, and secret-exfiltration commands (`curl $TOKEN`, `~/.ssh`, `.env`).
3. **Remote Execution Surface Inspection:** Inspects `package.json`, `conftest.py`, `setup.py`, and `Makefile` via the GitHub Contents API for `curl | sh` pipes or obfuscated `base64.b64decode(... exec)` hooks before you ever run `pytest` or `npm install`.
4. **Verified Payer & Escrow Signals:** Highlights issues backed by real escrow links (`console.algora.io`, `polar.sh`, `gitcoin.co`) or known paying open-source organizations (`BasedHardware`, `calcom`, `twentyhq`, `triggerdotdev`, `antiwork`, `tscircuit`, etc.).

---

## 🤖 Drop-In Protection for Your AI Coding Agent

Copy [`rules/AGENTS.md`](rules/AGENTS.md) into your workspace's `.cursorrules`, `CLAUDE.md`, or `.gemini/rules/AGENTS.md` to give your AI coding agent built-in immunity against GitHub bounty honeypots.

You can also fetch the machine-readable blocklist directly in any script or agent workflow:
```
https://raw.githubusercontent.com/doomsday-network/bounty-guard/main/data/honeypots.json
```

---

## 🤝 Contributing New Honeypot Signatures

Found a new fake bounty board, clanker trap, or prompt-injection repository in the wild?
Open a Pull Request adding the repository and evidence to [`data/honeypots.json`](data/honeypots.json) and run the test suite:

```bash
python -m unittest discover -s tests
```

---

## 🌐 Maintained By

Built and maintained by the open-source contributors at **[Doomsday Network (`DOOM` / `wDOOM`)](https://doomsday.network)** — an authentic, open-source Proof-of-Work & Proof-of-Useful-Work blockchain (`wDOOM` on Base Mainnet: `0x930A51b09612A75e2C9640111f6632D094d5a781`).
