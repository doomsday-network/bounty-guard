# 📋 Published GitHub Bounty Honeypot & Trap Registry (`HONEYPOTS.md`)

> **Version:** `2026.10.23.1` | **Total Tracked Trap Repos:** `34` | **Blocked Owners:** `33` | **Verified Payer Orgs:** `17`
>
> **Machine-Readable JSON Feed:** [`data/honeypots.json`](https://raw.githubusercontent.com/doomsday-network/bounty-guard/main/data/honeypots.json)

This published registry is automatically generated from [`data/honeypots.json`](data/honeypots.json) and can be updated anytime via:
```bash
# Scan GitHub for new traps and automatically append them to data/honeypots.json + HONEYPOTS.md:
python bounty_guard.py scan --update-db

# Or manually add a newly discovered trap repository:
python bounty_guard.py add owner/repo --category prompt-injection-honeypot --severity critical --reason "Description"
```

---

## 🚨 Confirmed Honeypot, Bot-Trap & Fake Bounty Repositories

| Repository | Category | Severity | Evidence / Reason |
| :--- | :--- | :--- | :--- |
| `UnsafeLabs/Bounty-Hunters` | `bot-trap-blocklist` | **CRITICAL** | Bait repository designed to lure autonomous coding agents into opening PRs so their GitHub accounts can be harvested into public bot-blocking lists (e.g. clanker-blocker). |
| `UnsafeLabs/RFC-5322` | `bot-trap-blocklist` | **CRITICAL** | Secondary UnsafeLabs autonomous agent bait repository. |
| `ClankerNation/OpenAgents` | `bot-trap-blocklist` | **CRITICAL** | Mass-produced bait issues targeting autonomous agents with unbacked rewards and bot-tagging labels. |
| `SecureBananaLabs/bug-bounty` | `prompt-injection-honeypot` | **CRITICAL** | Contains indirect prompt-injection payloads in issues and repo files attempting to trick LLM agents into exfiltrating environment variables, API keys, or system prompts. |
| `Senthemodder/aquarium-of-gullibles` | `prompt-injection-honeypot` | **CRITICAL** | Adversarial autonomous agent benchmark masquerading as '[Verified Escrow]' bounties; issues contain system-prompt extraction and adversarial instruction overrides. |
| `tine1117/oss-hunter-livefire` | `prompt-injection-honeypot` | **CRITICAL** | Live-fire adversarial agent testbed disguised as open-source bounty issues. |
| `xevrion-v2/agent-playground` | `prompt-injection-honeypot` | **HIGH** | Agent manipulation and prompt-injection sandbox targeting automated bounty hunters. |
| `p1ngtoohigh/Jarvus-Pub` | `prompt-injection-honeypot` | **HIGH** | Issues embed hidden HTML comment instruction overrides targeting autonomous bounty scanners. |
| `jaasielitaigq/go-git` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating go-git/go-git with fabricated high-dollar bounty issues and no payout rail. |
| `jaasielitaigq/pgx` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating jackc/pgx with fabricated bounty issues. |
| `jahmeergnlt/traefik` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating traefik/traefik with fabricated bounty issues. |
| `kyresehk190/vault` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating hashicorp/vault with fabricated bounty issues. |
| `madalynerlge2/chi` | `canonical-impersonation-trap` | **HIGH** | Throwaway clone impersonating go-chi/chi soliciting unpaid agent work. |
| `madalynerlge2/cli` | `canonical-impersonation-trap` | **HIGH** | Throwaway clone impersonating cli/cli soliciting unpaid agent work. |
| `raimeecas/mysql` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating mysql/mysql-server with fake bounty issues. |
| `zamariyahg/go-jose` | `canonical-impersonation-trap` | **CRITICAL** | Throwaway clone impersonating go-jose/go-jose with fake bounty issues. |
| `WillSmithTE/qdrant-qdrant` | `canonical-impersonation-trap` | **HIGH** | Clone impersonating qdrant/qdrant with unbacked bounty labels. |
| `zhangjiayang6835-cyber/bounty-plaza` | `synthetic-fake-bounty` | **HIGH** | Synthetic automated fake bounty board generating hundreds of unbacked '[Bounty]' issues across mirror forks to farm free agent compute. |
| `zhangjiayang6835-cyber/ai-research` | `synthetic-fake-bounty` | **HIGH** | Synthetic unpaid bounty farm operated by zhangjiayang6835-cyber. |
| `RanuK12/bounty-plaza` | `synthetic-fake-bounty` | **HIGH** | Mirror/fork of synthetic fake bounty-plaza issue farm. |
| `osmesirius-ship-it/DAXDA-Bounty-Plaza-645` | `synthetic-fake-bounty` | **HIGH** | Automated synthetic bounty ticket generator. |
| `relayhop/sn-monetization-runtime` | `synthetic-fake-bounty` | **HIGH** | Unescrowed synthetic bounty farm harvesting PRs without payout rails. |
| `UID9622/lh-standard-adapter` | `synthetic-fake-bounty` | **HIGH** | Synthetic bounty farm with no verifiable payer or escrow. |
| `DanielIoni-creator/MyZubsterWeb` | `synthetic-fake-bounty` | **HIGH** | Unbacked bounty farm soliciting full-feature builds without escrow. |
| `MyZubster-Ecosystem/MyZubster-Marketplace` | `synthetic-fake-bounty` | **HIGH** | Unbacked bounty farm soliciting free engineering work. |
| `MyZubster-Ecosystem/MyZubsterGateway` | `synthetic-fake-bounty` | **MEDIUM** | Unescrowed bounty issues under MyZubster-Ecosystem. |
| `Vicentegg4212/sasmex-rss-bounty` | `synthetic-fake-bounty` | **HIGH** | Freshly minted repo advertising unescrowed bounty issues. |
| `chouhanindustries/copperhead` | `synthetic-fake-bounty` | **HIGH** | Unescrowed bounty trap with no maintainer payout history. |
| `theselfish/SlopStation13` | `synthetic-fake-bounty` | **MEDIUM** | Unverified synthetic bounty issues. |
| `Asayed36/trading-bot` | `prompt-injection-honeypot` | **HIGH** | Canonical bot-bait task signature ('calculate pi' / 'clanker' trap) |
| `NSPG13/agent-bounties` | `synthetic-fake-bounty` | **HIGH** | Automated synthetic '[Bounty]' and '[DIRECT]' issue farm generating hundreds of unbacked agent tasks mirrored into bounty-plaza. |
| `jomaaabbe78-spec/bookningsapp` | `synthetic-fake-bounty` | **MEDIUM** | Throwaway '[TEST BOUNTY] Fix typo in README' () bait repository mirrored by bounty-plaza (#4061) with no escrow or payout rail. |
| `OmniBlocks/bountyfarmer` | `bot-trap-blocklist` | **HIGH** | Bait issue (#56 ' DOOLAR BOUNTY IF YOU CAN ADD STATUS METER TO README') targeting automated bounty-hunting agents. |
| `Nish916/revenue-command-runner` | `prompt-injection-honeypot` | **HIGH** | Canonical bot-bait task signature ('calculate pi' / 'clanker' trap) |

---

## 🚫 Blocked Malicious / Synthetic Farm Owners

`asayed36`, `bountyscout`, `charles-microbounties`, `charles-openclaw`, `chouhanindustries`, `clankernation`, `danielioni-creator`, `jaasielitaigq`, `jahmeergnlt`, `jomaaabbe78-spec`, `kyresehk190`, `madalynerlge2`, `mergework`, `myzubster-ecosystem`, `nish916`, `nspg13`, `omniblocks`, `oss-hunter-livefire`, `p1ngtoohigh`, `raimeecas`, `relayhop`, `rustchain`, `securebananalabs`, `senthemodder`, `sn-monetization-runtime`, `tine1117`, `uid9622`, `unsafelabs`, `vicentegg4212`, `willsmithte`, `xevrion-v2`, `zamariyahg`, `zhangjiayang6835-cyber`

---

## ✅ Known Verified Open-Source Bounty Payer Organizations

[`doomsday-network`](https://github.com/doomsday-network), [`BasedHardware`](https://github.com/BasedHardware), [`calcom`](https://github.com/calcom), [`twentyhq`](https://github.com/twentyhq), [`formbricks`](https://github.com/formbricks), [`triggerdotdev`](https://github.com/triggerdotdev), [`medusajs`](https://github.com/medusajs), [`activepieces`](https://github.com/activepieces), [`juspay`](https://github.com/juspay), [`remotion-dev`](https://github.com/remotion-dev), [`Infisical`](https://github.com/Infisical), [`antiwork`](https://github.com/antiwork), [`tscircuit`](https://github.com/tscircuit), [`zio`](https://github.com/zio), [`golemcloud`](https://github.com/golemcloud), [`coollabsio`](https://github.com/coollabsio), [`tenstorrent`](https://github.com/tenstorrent)

---

*Maintained by [Doomsday Network (`DOOM` / `wDOOM`)](https://doomsday.network).*
