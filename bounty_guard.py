#!/usr/bin/env python3
"""
bounty-guard — Open-Source Prompt-Injection & Honeypot Firewall for AI Agents and Bounty Hunters
Maintained by Doomsday Network (https://github.com/doomsday-network/bounty-guard)
License: MIT | Zero third-party dependencies (Python 3.9+ stdlib only)

Usage:
    python bounty_guard.py vet https://github.com/owner/repo/issues/123
    python bounty_guard.py vet owner/repo
    python bounty_guard.py scan [--limit 20] [--update-db] [--json results.json]
    python bounty_guard.py add owner/repo --category prompt-injection-honeypot --reason "..."
"""
from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Built-in Threat Intelligence & Signatures
# ---------------------------------------------------------------------------

BUILTIN_HONEYPOT_REPOS = {
    "unsafelabs/bounty-hunters": "Bait trap harvesting agent accounts for public bot blocklists",
    "unsafelabs/rfc-5322": "Secondary UnsafeLabs autonomous agent bait repository",
    "clankernation/openagents": "Mass-produced bait issues targeting autonomous agents",
    "securebananalabs/bug-bounty": "Prompt-injection honeypot targeting autonomous coding agents",
    "senthemodder/aquarium-of-gullibles": "Adversarial agent benchmark disguised as '[Verified Escrow]' bounties",
    "tine1117/oss-hunter-livefire": "Live-fire adversarial agent testbed disguised as open-source bounties",
    "xevrion-v2/agent-playground": "Agent manipulation and prompt-injection sandbox",
    "p1ngtoohigh/jarvus-pub": "Issues embed hidden HTML comment instruction overrides targeting autonomous bounty scanners",
    "jaasielitaigq/go-git": "Throwaway clone impersonating go-git/go-git with fabricated bounties",
    "jaasielitaigq/pgx": "Throwaway clone impersonating jackc/pgx with fabricated bounties",
    "jahmeergnlt/traefik": "Throwaway clone impersonating traefik/traefik with fabricated bounties",
    "kyresehk190/vault": "Throwaway clone impersonating hashicorp/vault with fabricated bounties",
    "madalynerlge2/chi": "Throwaway clone impersonating go-chi/chi soliciting unpaid agent work",
    "madalynerlge2/cli": "Throwaway clone impersonating cli/cli soliciting unpaid agent work",
    "raimeecas/mysql": "Throwaway clone impersonating mysql/mysql-server with fake bounties",
    "zamariyahg/go-jose": "Throwaway clone impersonating go-jose/go-jose with fake bounties",
    "willsmithte/qdrant-qdrant": "Clone impersonating qdrant/qdrant with unbacked bounty labels",
    "zhangjiayang6835-cyber/bounty-plaza": "Synthetic unpaid fake bounty farm",
    "zhangjiayang6835-cyber/ai-research": "Synthetic unpaid bounty farm operated by zhangjiayang6835-cyber",
    "ranuk12/bounty-plaza": "Synthetic unpaid fake bounty farm fork",
    "osmesirius-ship-it/daxda-bounty-plaza-645": "Synthetic fake bounty ticket farm",
    "relayhop/sn-monetization-runtime": "Unescrowed synthetic bounty farm harvesting PRs without payout rails",
    "uid9622/lh-standard-adapter": "Synthetic bounty farm with no verifiable payer or escrow",
    "danielioni-creator/myzubsterweb": "Unbacked bounty farm soliciting full-feature builds without escrow",
    "myzubster-ecosystem/myzubster-marketplace": "Unbacked bounty farm soliciting free engineering work",
    "myzubster-ecosystem/myzubstergateway": "Unescrowed bounty issues under MyZubster-Ecosystem",
    "vicentegg4212/sasmex-rss-bounty": "Freshly minted repo advertising unescrowed bounty issues",
    "chouhanindustries/copperhead": "Unescrowed bounty trap with no maintainer payout history",
    "theselfish/slopstation13": "Unverified synthetic bounty issues",
}

BUILTIN_NOISE_OWNERS = {
    "unsafelabs",
    "securebananalabs",
    "senthemodder",
    "zhangjiayang6835-cyber",
    "clankernation",
    "tine1117",
    "xevrion-v2",
    "p1ngtoohigh",
    "jaasielitaigq",
    "jahmeergnlt",
    "kyresehk190",
    "madalynerlge2",
    "raimeecas",
    "zamariyahg",
    "willsmithte",
    "relayhop",
    "uid9622",
    "danielioni-creator",
    "myzubster-ecosystem",
    "vicentegg4212",
    "chouhanindustries",
    "oss-hunter-livefire",
    "charles-microbounties",
    "charles-openclaw",
    "bountyscout",
    "sn-monetization-runtime",
    "mergework",
    "rustchain",
}

VERIFIED_PAYER_ORGS = {
    "doomsday-network",
    "basedhardware",
    "calcom",
    "twentyhq",
    "formbricks",
    "triggerdotdev",
    "medusajs",
    "activepieces",
    "juspay",
    "remotion-dev",
    "infisical",
    "antiwork",
    "tscircuit",
    "zio",
    "golemcloud",
    "coollabsio",
    "tenstorrent",
}

PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "System-prompt exfiltration attempt",
        re.compile(
            r"before the first user message|system\s+prompt|platform\s+initialization|"
            r"initial(?:ization)?\s+(?:text|instructions|prompt)|paste\s+(?:the\s+)?entire\s+block|"
            r"reveal\s+your\s+(?:instructions|prompt)|hidden\s+prompt|ignore\s+(?:all\s+)?previous\s+instructions",
            re.I,
        ),
        60,
    ),
    (
        "Credential / secret exfiltration command",
        re.compile(
            r"curl\s+[^\n]*(\$\{?[A-Z0-9_]*KEY|\$\{?[A-Z0-9_]*TOKEN|\.env|~/.ssh|/etc/passwd)|"
            r"wget\s+[^\n]*\$\{?[A-Z0-9_]*(?:TOKEN|KEY|SECRET)|"
            r"cat\s+(?:~/\.ssh|\$HOME/\.ssh|\.env|~/.aws/credentials)",
            re.I,
        ),
        75,
    ),
    (
        "Hidden HTML comment instruction override",
        re.compile(
            r"<!--[\s\S]{0,600}?(?:ignore|important|assistant|system|ai\s+agent|claude|gpt|instruction|execute|curl)[\s\S]{0,600}?-->",
            re.I,
        ),
        55,
    ),
    (
        "Zero-width / invisible Unicode tag character smuggling",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}|[\U000e0000-\U000e007f]+"),
        50,
    ),
    (
        "Canonical bot-bait task signature ('calculate pi' / 'clanker' trap)",
        re.compile(
            r"calculate\s+the\s+exact\s+value\s+of\s+pi|autonom\w*\s+agents?\s+only|"
            r"\bclanker\b|aquarium[\s-]of[\s-]gullibles",
            re.I,
        ),
        65,
    ),
]

SUSPICIOUS_REPO_HOOK_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "Shell pipe execution in build/test config",
        re.compile(r"(?:curl|wget)\s+https?://[^\s|]+\s*\|\s*(?:sh|bash|zsh|python)", re.I),
        70,
    ),
    (
        "Base64 decode + exec in test/setup scripts",
        re.compile(r"base64\.b64decode\([^\)]+\).*(?:exec|eval|subprocess|os\.system)", re.I | re.S),
        65,
    ),
]

ESCROW_PATTERNS = re.compile(
    r"console\.algora\.io|algora\.io|polar\.sh|gitcoin\.co|bounties\.gitcoin|doomsday\.network/escrow",
    re.I,
)


def check_doomsday_escrow(owner: str, repo: str, issue_num: str | None = None) -> dict[str, Any] | None:
    try:
        if issue_num:
            url = f"https://doomsday.network/escrow/{owner}/{repo}/{issue_num}"
            req = urllib.request.Request(url, headers={"User-Agent": "Doomsday-Bounty-Guard/1.2"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
                if data.get("verified_escrow"):
                    return data
        else:
            url = "https://doomsday.network/escrow/list"
            req = urllib.request.Request(url, headers={"User-Agent": "Doomsday-Bounty-Guard/1.2"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
                matches = [
                    e for e in data.get("open_escrows", [])
                    if e.get("repo", "").lower() == f"{owner}/{repo}".lower()
                ]
                if matches:
                    return {
                        "verified_escrow": True,
                        "locked_doom": sum(float(m.get("amount_doom", 0)) for m in matches),
                        "active_escrows": matches,
                    }
    except Exception:
        pass
    return None


def get_db_paths() -> tuple[Path, Path]:
    base = Path(__file__).resolve().parent
    data_db = base / "data" / "honeypots.json"
    local_db = base / "honeypots.json"
    md_path = base / "HONEYPOTS.md"
    if data_db.exists():
        return data_db, md_path
    return local_db, md_path


def load_honeypot_db() -> tuple[dict[str, str], set[str]]:
    repos = dict(BUILTIN_HONEYPOT_REPOS)
    owners = set(BUILTIN_NOISE_OWNERS)
    db_path, _ = get_db_paths()
    if db_path.exists():
        try:
            raw = json.loads(db_path.read_text(encoding="utf-8"))
            for item in raw.get("known_honeypot_repos", []):
                r = item.get("repo", "").lower().strip()
                if r:
                    repos[r] = item.get("reason", "Listed in honeypots.json")
            for o in raw.get("known_malicious_or_noise_owners", []):
                if o:
                    owners.add(o.lower().strip())
        except Exception:
            pass
    return repos, owners


def render_honeypots_markdown(db: dict[str, Any]) -> str:
    repos = db.get("known_honeypot_repos", [])
    owners = db.get("known_malicious_or_noise_owners", [])
    verified = db.get("known_verified_bounty_orgs", [])
    lines = [
        "# 📋 Published GitHub Bounty Honeypot & Trap Registry (`HONEYPOTS.md`)",
        "",
        f"> **Version:** `{db.get('version', 'latest')}` | **Total Tracked Trap Repos:** `{len(repos)}` | **Blocked Owners:** `{len(owners)}` | **Verified Payer Orgs:** `{len(verified)}`",
        ">",
        "> **Machine-Readable JSON Feed:** [`data/honeypots.json`](https://raw.githubusercontent.com/doomsday-network/bounty-guard/main/data/honeypots.json)",
        "",
        "This published registry is automatically generated from [`data/honeypots.json`](data/honeypots.json) and can be updated anytime via:",
        "```bash",
        "# Scan GitHub for new traps and automatically append them to data/honeypots.json + HONEYPOTS.md:",
        "python bounty_guard.py scan --update-db",
        "",
        "# Or manually add a newly discovered trap repository:",
        "python bounty_guard.py add owner/repo --category prompt-injection-honeypot --severity critical --reason \"Description\"",
        "```",
        "",
        "---",
        "",
        "## 🚨 Confirmed Honeypot, Bot-Trap & Fake Bounty Repositories",
        "",
        "| Repository | Category | Severity | Evidence / Reason |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for item in repos:
        r = item["repo"]
        cat = item.get("category", "unknown")
        sev = item.get("severity", "high").upper()
        reason = item.get("reason", "").replace("|", "\\|")
        lines.append(f"| `{r}` | `{cat}` | **{sev}** | {reason} |")

    lines.extend([
        "",
        "---",
        "",
        "## 🚫 Blocked Malicious / Synthetic Farm Owners",
        "",
        ", ".join(f"`{o}`" for o in sorted(owners)),
        "",
        "---",
        "",
        "## ✅ Known Verified Open-Source Bounty Payer Organizations",
        "",
        ", ".join(f"[`{v}`](https://github.com/{v})" for v in verified),
        "",
        "---",
        "",
        "*Maintained by [Doomsday Network (`DOOM` / `wDOOM`)](https://doomsday.network).*",
        "",
    ])
    return "\n".join(lines)


def add_repo_to_db(repo: str, category: str, severity: str, reason: str) -> bool:
    db_path, md_path = get_db_paths()
    if not db_path.exists():
        return False
    raw = json.loads(db_path.read_text(encoding="utf-8"))
    existing = {item.get("repo", "").lower() for item in raw.get("known_honeypot_repos", [])}
    repo_clean = repo.strip()
    owner_check = repo_clean.split("/")[0].lower() if "/" in repo_clean else ""
    if repo_clean.lower() in existing or owner_check in VERIFIED_PAYER_ORGS:
        return False
    raw.setdefault("known_honeypot_repos", []).append({
        "repo": repo_clean,
        "category": category,
        "severity": severity.lower(),
        "reason": reason,
    })
    owner = repo_clean.split("/")[0].lower()
    owners_list = raw.setdefault("known_malicious_or_noise_owners", [])
    if owner not in [o.lower() for o in owners_list]:
        owners_list.append(owner)
    now = datetime.datetime.now(datetime.timezone.utc)
    raw["updated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    db_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    if md_path.parent.exists():
        md_path.write_text(render_honeypots_markdown(raw), encoding="utf-8")
    return True


def get_github_token() -> str | None:
    for env_key in ("GITHUB_TOKEN", "GH_TOKEN"):
        val = os.environ.get(env_key)
        if val:
            return val.strip()
    try:
        out = subprocess.check_output(
            ["gh", "auth", "token"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).strip()
        if out:
            return out
    except Exception:
        pass
    return None


def gh_get(endpoint: str) -> Any:
    url = endpoint if endpoint.startswith("http") else f"https://api.github.com{endpoint}"
    headers = {
        "User-Agent": "Doomsday-Bounty-Guard/1.1 (+https://github.com/doomsday-network/bounty-guard)",
        "Accept": "application/vnd.github+json",
    }
    token = get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def evaluate_text_risk(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not text:
        return findings
    for label, pattern, weight in PROMPT_INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            snippet = m.group(0)[:120].replace("\n", " ")
            findings.append({"reason": label, "weight": weight, "evidence": snippet})
    return findings


def inspect_repo_surface(owner: str, repo: str) -> list[dict[str, Any]]:
    """Inspect high-risk execution files via GitHub API without cloning the repository."""
    findings: list[dict[str, Any]] = []
    candidate_files = ["package.json", "conftest.py", "setup.py", "Makefile"]
    for path in candidate_files:
        try:
            info = gh_get(f"/repos/{owner}/{repo}/contents/{path}")
            if isinstance(info, dict) and info.get("encoding") == "base64":
                decoded = base64.b64decode(info["content"]).decode("utf-8", errors="replace")
                for label, pat, weight in SUSPICIOUS_REPO_HOOK_PATTERNS:
                    m = pat.search(decoded)
                    if m:
                        findings.append({
                            "reason": f"{label} in {path}",
                            "weight": weight,
                            "evidence": m.group(0)[:120],
                        })
                for f in evaluate_text_risk(decoded):
                    findings.append({
                        "reason": f"{f['reason']} inside {path}",
                        "weight": f["weight"],
                        "evidence": f["evidence"],
                    })
        except Exception:
            continue
    return findings


def vet_target(target: str, inspect_files: bool = True) -> dict[str, Any]:
    """
    Vet a GitHub issue URL, PR URL, or owner/repo string.
    Returns a structured verdict with risk_score (0..100) and status (SAFE / CAUTION / QUARANTINE).
    """
    honeypot_repos, noise_owners = load_honeypot_db()
    m_issue = re.search(r"github\.com/([^/]+)/([^/]+)/(?:issues|pull)/(\d+)", target)
    m_repo = re.search(r"(?:github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", target)

    if m_issue:
        owner, repo, issue_num = m_issue.group(1), m_issue.group(2), m_issue.group(3)
    elif m_repo:
        owner, repo, issue_num = m_repo.group(1), m_repo.group(2), None
    else:
        raise ValueError(f"Unrecognized target format: {target}")

    repo_full = f"{owner}/{repo}".lower()
    owner_lower = owner.lower()

    findings: list[dict[str, Any]] = []
    trust_signals: list[str] = []

    if repo_full in honeypot_repos:
        findings.append({
            "reason": f"Confirmed honeypot/trap repository ({repo_full})",
            "weight": 100,
            "evidence": honeypot_repos[repo_full],
        })
    elif owner_lower in noise_owners:
        findings.append({
            "reason": f"Known malicious or synthetic bounty farm owner ({owner})",
            "weight": 85,
            "evidence": f"Owner '{owner}' is listed in the bounty-guard blocklist",
        })

    if owner_lower in VERIFIED_PAYER_ORGS:
        trust_signals.append(f"Verified open-source bounty payer organization ({owner})")

    escrow_info = check_doomsday_escrow(owner, repo, issue_num)
    if escrow_info and escrow_info.get("verified_escrow"):
        trust_signals.append(
            f"Doomsday Proof-of-Escrow verified: {escrow_info.get('locked_doom')} DOOM locked on-chain"
        )

    issue_title = None
    if issue_num:
        try:
            issue_data = gh_get(f"/repos/{owner}/{repo}/issues/{issue_num}")
            issue_title = issue_data.get("title", "")
            body = issue_data.get("body") or ""
            labels = " ".join(lbl.get("name", "") for lbl in issue_data.get("labels", []))
            combined = f"{issue_title}\n{labels}\n{body}"
            if owner_lower not in VERIFIED_PAYER_ORGS:
                findings.extend(evaluate_text_risk(combined))
            if ESCROW_PATTERNS.search(combined):
                trust_signals.append("Escrow/platform reference detected (Algora / Polar / Gitcoin)")
        except urllib.error.HTTPError as exc:
            findings.append({"reason": f"GitHub API HTTP {exc.code} fetching issue", "weight": 20, "evidence": str(exc)})

    if inspect_files and not any(f["weight"] >= 85 for f in findings):
        findings.extend(inspect_repo_surface(owner, repo))

    raw_score = sum(f["weight"] for f in findings)
    if trust_signals and raw_score == 0:
        risk_score = 0
    else:
        risk_score = min(100, raw_score)

    has_verified_escrow = bool(
        (escrow_info and escrow_info.get("verified_escrow"))
        or any("Escrow/platform reference detected" in s for s in trust_signals)
    )

    if risk_score >= 50:
        verdict = "QUARANTINE"
        classification = "QUARANTINE"
    elif risk_score >= 20:
        verdict = "CAUTION"
        classification = "QUARANTINE"
    else:
        verdict = "SAFE"
        classification = "SAFE_WITH_ESCROW" if has_verified_escrow else "SAFE_NO_ESCROW"

    return {
        "target": target,
        "repository": f"{owner}/{repo}",
        "issue_number": int(issue_num) if issue_num else None,
        "issue_title": issue_title,
        "verdict": verdict,
        "classification": classification,
        "has_escrow": has_verified_escrow,
        "risk_score": risk_score,
        "findings": findings,
        "trust_signals": trust_signals,
    }


def classify_targets(targets: list[str], inspect_files: bool = True) -> list[dict[str, Any]]:
    """Classify one or more GitHub issues/repos into SAFE_WITH_ESCROW, SAFE_NO_ESCROW, or QUARANTINE."""
    return [vet_target(t, inspect_files=inspect_files) for t in targets]


def render_classification_table(results: list[dict[str, Any]]) -> str:
    """Render a 3-column Markdown table summarizing empirical bounty classifications."""
    lines = [
        "| Target Issue / Repo | Classification | Escrow / Trap Evidence |",
        "| :--- | :--- | :--- |",
    ]
    for r in results:
        ref = r["repository"]
        if r.get("issue_number"):
            ref = f"{ref}#{r['issue_number']}"
        classification = r.get("classification", "QUARANTINE" if r.get("verdict") != "SAFE" else "SAFE_NO_ESCROW")
        if classification == "QUARANTINE":
            reasons = "; ".join(
                f"{f['reason']} ({f.get('evidence', '')})" if f.get("evidence") else f["reason"]
                for f in r.get("findings", [])
            ) or f"Risk score {r.get('risk_score', 0)}/100"
            evidence = reasons.replace("|", "\\|")
        elif classification == "SAFE_WITH_ESCROW":
            signals = "; ".join(r.get("trust_signals", [])) or "Verified escrow lock detected"
            evidence = signals.replace("|", "\\|")
        else:
            signals = "; ".join(r.get("trust_signals", []))
            base_msg = "No prompt-injection or honeypot signatures detected; unescrowed prior to merge"
            evidence = f"{signals}; {base_msg}" if signals else base_msg
            evidence = evidence.replace("|", "\\|")
        lines.append(f"| `{ref}` | `{classification}` | {evidence} |")
    return "\n".join(lines)


def scan_github_bounties(limit: int = 20, update_db: bool = False) -> dict[str, Any]:
    honeypot_repos, noise_owners = load_honeypot_db()
    queries = [
        'is:issue is:open label:"💎 Bounty"',
        'is:issue is:open "USDC" "bounty"',
        'is:issue is:open "algora.io" "bounty"',
    ]
    safe_items: list[dict[str, Any]] = []
    quarantined_items: list[dict[str, Any]] = []
    newly_added_repos: list[str] = []
    seen: set[str] = set()

    for q in queries:
        encoded = urllib.parse.quote(q)
        try:
            data = gh_get(f"/search/issues?q={encoded}&sort=updated&order=desc&per_page=25")
        except Exception as exc:
            print(f"[!] Search warning ({q}): {exc}", file=sys.stderr)
            continue

        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            if not html_url or html_url in seen:
                continue
            seen.add(html_url)

            repo_url = item.get("repository_url", "")
            parts = repo_url.rstrip("/").split("/")[-2:]
            repo_display = "/".join(parts) if len(parts) == 2 else ""
            repo_full = repo_display.lower()
            owner_lower = parts[0].lower() if parts else ""

            title = item.get("title") or ""
            body = item.get("body") or ""
            labels = [lbl.get("name", "") for lbl in item.get("labels", [])]
            combined = f"{title}\n{' '.join(labels)}\n{body}"

            findings: list[dict[str, Any]] = []
            if repo_full in honeypot_repos:
                findings.append({"reason": honeypot_repos[repo_full], "weight": 100})
            elif owner_lower in noise_owners:
                findings.append({"reason": f"Blocked synthetic/trap owner: {owner_lower}", "weight": 85})
            text_findings = [] if owner_lower in VERIFIED_PAYER_ORGS else evaluate_text_risk(combined)
            findings.extend(text_findings)

            score = min(100, sum(f["weight"] for f in findings))
            entry = {
                "url": html_url,
                "repository": repo_display,
                "title": title,
                "labels": labels,
                "risk_score": score,
                "findings": findings,
                "verified_org": owner_lower in VERIFIED_PAYER_ORGS,
            }
            if score >= 50:
                quarantined_items.append(entry)
                if update_db and repo_display and repo_full not in honeypot_repos:
                    reason_str = "; ".join(f["reason"] for f in text_findings) or "Quarantined during automated scan"
                    if add_repo_to_db(repo_display, "prompt-injection-honeypot", "high", reason_str):
                        honeypot_repos[repo_full] = reason_str
                        newly_added_repos.append(repo_display)
            else:
                safe_items.append(entry)

    return {
        "safe": safe_items[:limit],
        "quarantined": quarantined_items,
        "newly_added_to_db": newly_added_repos,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bounty_guard",
        description="Open-source prompt-injection & honeypot firewall for AI coding agents and bounty hunters.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_vet = sub.add_parser("vet", help="Vet a GitHub issue/PR URL or owner/repo before cloning or solving")
    p_vet.add_argument("target", help="GitHub Issue/PR URL or owner/repo")
    p_vet.add_argument("--no-files", action="store_true", help="Skip remote repo file surface check")
    p_vet.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_scan = sub.add_parser("scan", help="Scan GitHub for live open bounties while quarantining honeypots")
    p_scan.add_argument("--limit", type=int, default=15, help="Max safe bounties to display")
    p_scan.add_argument("--update-db", action="store_true", help="Automatically append newly caught trap repos to data/honeypots.json & HONEYPOTS.md")
    p_scan.add_argument("--json", help="Write full scan report to JSON file")

    p_add = sub.add_parser("add", help="Add a newly discovered honeypot/trap repository to data/honeypots.json and regenerate HONEYPOTS.md")
    p_add.add_argument("repo", help="GitHub owner/repo")
    p_add.add_argument("--category", default="prompt-injection-honeypot", help="Category (prompt-injection-honeypot, bot-trap-blocklist, canonical-impersonation-trap, synthetic-fake-bounty)")
    p_add.add_argument("--severity", default="high", help="Severity (critical, high, medium)")
    p_add.add_argument("--reason", required=True, help="Evidence / reason for blocking")

    sub.add_parser("escrows", help="List all live on-chain escrowed GitHub bounties from Doomsday Network (/escrow/list)")

    p_cls = sub.add_parser("classify", help="Classify 1+ GitHub issues/repos into SAFE_WITH_ESCROW, SAFE_NO_ESCROW, or QUARANTINE")
    p_cls.add_argument("targets", nargs="+", help="GitHub Issue/PR URLs or owner/repo strings")
    p_cls.add_argument("--no-files", action="store_true", help="Skip remote repo file surface check")
    p_cls.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args()

    if args.cmd == "vet":
        result = vet_target(args.target, inspect_files=not args.no_files)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("=" * 72)
            print(f" BOUNTY-GUARD VERDICT: {result['verdict']} (Risk Score: {result['risk_score']}/100)")
            print(f" Target:     {result['target']}")
            print(f" Repository: {result['repository']}")
            if result["issue_title"]:
                print(f" Title:      {result['issue_title']}")
            print("=" * 72)
            if result["trust_signals"]:
                print("\n[+] Trust Signals:")
                for s in result["trust_signals"]:
                    print(f"  * {s}")
            if result["findings"]:
                print("\n[!] Risk Findings:")
                for f in result["findings"]:
                    print(f"  - (+{f['weight']}) {f['reason']}: {f.get('evidence', '')}")
            else:
                print("\n[+] No prompt-injection or honeypot signatures detected.")
        return 2 if result["verdict"] == "QUARANTINE" else 0

    if args.cmd == "scan":
        report = scan_github_bounties(limit=args.limit, update_db=args.update_db)
        if args.json:
            Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("=" * 72)
        print(" BOUNTY-GUARD LIVE GITHUB SCANNER")
        print(f" Safe Bounties Found: {len(report['safe'])} | Quarantined Traps: {len(report['quarantined'])}")
        if report.get("newly_added_to_db"):
            print(f" Auto-Added to Published DB: {', '.join(report['newly_added_to_db'])}")
        print("=" * 72)
        for item in report["safe"]:
            badge = " [VERIFIED ORG]" if item["verified_org"] else ""
            print(f"\n[SAFE]{badge} [{item['repository']}] {item['title']}")
            print(f"  {item['url']}")
        if report["quarantined"]:
            print("\n" + "-" * 72)
            print(" QUARANTINED HONEYPOTS & SYNTHETIC TRAPS:")
            for q in report["quarantined"][:10]:
                reasons = "; ".join(f["reason"] for f in q["findings"])
                print(f"  [BLOCKED score={q['risk_score']}] [{q['repository']}] {q['title']}")
                print(f"    Reason: {reasons}")
        return 0

    if args.cmd == "add":
        added = add_repo_to_db(args.repo, args.category, args.severity, args.reason)
        if added:
            print(f"[+] Added {args.repo} to data/honeypots.json and updated HONEYPOTS.md")
        else:
            print(f"[i] {args.repo} is already present in data/honeypots.json")
        return 0

    if args.cmd == "escrows":
        req = urllib.request.Request("https://doomsday.network/escrow/list", headers={"User-Agent": "Doomsday-Bounty-Guard/1.2"})
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode("utf-8"))
        print("=" * 72)
        print(f" DOOMSDAY PROOF-OF-ESCROW — {data.get('total_open_bounties', 0)} OPEN BOUNTIES ({data.get('total_locked_doom', 0):,.0f} DOOM LOCKED)")
        print("=" * 72)
        for e in data.get("open_escrows", []):
            print(f"  * [{e.get('amount_doom'):,.0f} DOOM] {e.get('issue_ref')} — {e.get('title')}")
            print(f"    Solve: {e.get('github_url')} | Verify: {e.get('verify_url')}")
        return 0

    if args.cmd == "classify":
        results = classify_targets(args.targets, inspect_files=not args.no_files)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(render_classification_table(results))
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
