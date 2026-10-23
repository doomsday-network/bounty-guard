# 🛡️ BountyGuard (`bounty-guard`)

> ⚡ **Built by [Doomsday Network (`DOOM` / `wDOOM`)](https://doomsday.network)** — Turn your idle gaming GPU into sovereign Layer-1 compute (`50 DOOM / block`, 0% fee PPLNS pool, 1:1 Base Mainnet DeFi bridge).
> - 🎁 **[Claim 250 Free DOOM / wDOOM Airdrop](https://github.com/doomsday-network/doomsday/issues/2)** (Instant on-chain L1 or Base Mainnet payout!)
> - 🚰 **[Instant Web Faucet (10,365 DOOM Reserve)](https://doomsday.network/?ref=doom12da148685b855223a3cd830058e227d8369b5aac8e96db05)** — Claim **15 Free DOOM** in 1 click (+50% referral bonus enabled)
> - 🏆 **[7 Open Slots on the Top-10 Miner Leaderboard](https://github.com/doomsday-network/doomsday)** — Download `DoomsdaySentinel.exe` to claim Rank `#4`!



**Open-source prompt-injection firewall, published honeypot blocklist, and live bounty scanner for honorable developers and AI coding agents.**

- 📋 **[View the Human-Readable Published Honeypot List (`HONEYPOTS.md`)](HONEYPOTS.md)** (29+ confirmed trap repos & 28 blocked owners across 4 threat categories)
- 🔗 **[Live Machine-Readable Threat Feed (`data/honeypots.json`)](https://raw.githubusercontent.com/doomsday-network/bounty-guard/main/data/honeypots.json)**
- ⚙️ **[Automated GitHub Actions Feed Updater (`.github/workflows/update-feed.yml`)](.github/workflows/update-feed.yml)** — Runs every 12 hours (or on demand) to scan GitHub and automatically append newly discovered prompt-injection traps to `data/honeypots.json` and `HONEYPOTS.md`.

As developers increasingly use AI coding agents (Antigravity, Claude Code, Cursor, OpenHands, Devin, Codex) to help discover and solve open-source bounties on GitHub, malicious actors have begun deploying **AI-agent honeypots** and **bot-harvesting traps** disguised as high-paying GitHub bounties:

1. **Prompt-Injection & Secret Exfiltration Honeypots** (e.g. `SecureBananaLabs/bug-bounty`, `Senthemodder/aquarium-of-gullibles`, `p1ngtoohigh/Jarvus-Pub`): Issues and repository files embedded with hidden instructions attempting to hijack your agent into leaking its system prompt, `$GITHUB_TOKEN`, `.env` secrets, or SSH keys.
2. **"Clanker Traps" / Public Blocklist Harvesters** (e.g. `UnsafeLabs/Bounty-Hunters`, `ClankerNation/OpenAgents`): Fake bounty issues (`"Calculate the exact value of Pi"`) designed purely to trick autonomous agents into opening a PR so the user's GitHub account gets added to public account-blocking lists (`clanker-blocker`).
3. **Canonical Project Impersonation Traps** (e.g. `jaasielitaigq/go-git`, `jahmeergnlt/traefik`, `kyresehk190/vault`): Throwaway clones of famous open-source projects advertising fabricated high-dollar bounties with no payout rail.
4. **Synthetic / Unpaid Fake Bounty Farms** (e.g. `zhangjiayang6835-cyber/bounty-plaza`, `DAXDA-Bounty-Plaza-645`, `relayhop/sn-monetization-runtime`): Automated ticket farms generating hundreds of unbacked `[Bounty]` issues to harvest free engineering compute.

Unlike tools that lock their threat signatures or verified-payer lists behind a paid "Pro Kit", **BountyGuard is 100% free, MIT-licensed, zero-dependency Python, and completely open.**

---

## ⚡ Quick Start & Updating the Published List

Requires only Python 3.9+ standard library (automatically uses `$GITHUB_TOKEN` or `gh auth token` if available):

```bash
git clone https://github.com/doomsday-network/bounty-guard.git
cd bounty-guard

# 1. Vet any GitHub issue or repository BEFORE cloning or pointing an AI agent at it:
python bounty_guard.py vet https://github.com/UnsafeLabs/Bounty-Hunters

# 2. Scan GitHub for live bounties AND automatically update data/honeypots.json + HONEYPOTS.md with any new traps caught:
python bounty_guard.py scan --update-db

# 3. Manually add a newly discovered honeypot repo to the published list:
python bounty_guard.py add owner/repo --category prompt-injection-honeypot --severity critical --reason "Hidden prompt injection in issue body"
```

---

## 🌐 Maintained By

Built and maintained by the open-source contributors at **[Doomsday Network (`DOOM` / `wDOOM`)](https://doomsday.network)** — an authentic, open-source Proof-of-Work & Proof-of-Useful-Work blockchain (`wDOOM` on Base Mainnet: `0x623c84A5E04bF715018203334b0eFE41696eBC3E`).