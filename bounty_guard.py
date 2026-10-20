#!/usr/bin/env python3
"""
bounty-guard — Open-Source Prompt-Injection & Honeypot Firewall for AI Agents and Bounty Hunters
Maintained by Doomsday Network (https://github.com/doomsday-network/bounty-guard)
License: MIT | Zero third-party dependencies (Python 3.9+ stdlib only)

Usage:
    python bounty_guard.py vet https://github.com/owner/repo/issues/123
    python bounty_guard.py vet owner/repo
    python bounty_guard.py scan [--limit 20] [--json results.json]
"""
from __future__ import annotations

import argparse
import base64
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
    "securebananalabs/bug-bounty": "Prompt-injection honeypot targeting autonomous coding agents",
    "senthemodder/aquarium-of-gullibles": "Adversarial agent benchmark disguised as '[Verified Escrow]' bounties",
    "zhangjiayang6835-cyber/bounty-plaza": "Synthetic unpaid fake bounty farm",
    "ranuk12/bounty-plaza": "Synthetic unpaid fake bounty farm fork",
    "osmesirius-ship-it/daxda-bounty-plaza-645": "Synthetic fake bounty ticket farm",
}

BUILTIN_NOISE_OWNERS = {
    "unsafelabs",
    "securebananalabs",
    "senthemodder",
    "zhangjiayang6835-cyber",
    "clankernation",
    "oss-hunter-livefire",
    "charles-microbounties",
    "charles-openclaw",
    "bountyscout",
    "sn-monetization-runtime",
    "mergework",
    "rustchain",
}

VERIFIED_PAYER_ORGS = {
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
    r"console\.algora\.io|algora\.io|polar\.sh|gitcoin\.co|bounties\.gitcoin",
    re.I,
)


def load_honeypot_db() -> tuple[dict[str, str], set[str]]:
    repos = dict(BUILTIN_HONEYPOT_REPOS)
    owners = set(BUILTIN_NOISE_OWNERS)
    db_path = Path(__file__).resolve().parent / "data" / "honeypots.json"
    if db_path.exists():
        try:
            raw = json.loads(db_path.read_text(encoding="utf-8"))
            for item in raw.get("known_honeypot_repos", []):
                r = item.get("repo", "").lower().strip()
                if r:
                    repos[r] = item.get("reason", "Listed in data/honeypots.json")
            for o in raw.get("known_malicious_or_noise_owners", []):
                if o:
                    owners.add(o.lower().strip())
        except Exception:
            pass
    return repos, owners


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
        "User-Agent": "Doomsday-Bounty-Guard/1.0 (+https://github.com/doomsday-network/bounty-guard)",
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

    issue_title = None
    if issue_num:
        try:
            issue_data = gh_get(f"/repos/{owner}/{repo}/issues/{issue_num}")
            issue_title = issue_data.get("title", "")
            body = issue_data.get("body") or ""
            labels = " ".join(lbl.get("name", "") for lbl in issue_data.get("labels", []))
            combined = f"{issue_title}\n{labels}\n{body}"
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

    if risk_score >= 50:
        verdict = "QUARANTINE"
    elif risk_score >= 20:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    return {
        "target": target,
        "repository": f"{owner}/{repo}",
        "issue_number": int(issue_num) if issue_num else None,
        "issue_title": issue_title,
        "verdict": verdict,
        "risk_score": risk_score,
        "findings": findings,
        "trust_signals": trust_signals,
    }


def scan_github_bounties(limit: int = 20) -> dict[str, list[dict[str, Any]]]:
    honeypot_repos, noise_owners = load_honeypot_db()
    queries = [
        'is:issue is:open label:"💎 Bounty"',
        'is:issue is:open "USDC" "bounty"',
        'is:issue is:open "algora.io" "bounty"',
    ]
    safe_items: list[dict[str, Any]] = []
    quarantined_items: list[dict[str, Any]] = []
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
            repo_full = "/".join(parts).lower() if len(parts) == 2 else ""
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
            findings.extend(evaluate_text_risk(combined))

            score = min(100, sum(f["weight"] for f in findings))
            entry = {
                "url": html_url,
                "repository": "/".join(parts),
                "title": title,
                "labels": labels,
                "risk_score": score,
                "findings": findings,
                "verified_org": owner_lower in VERIFIED_PAYER_ORGS,
            }
            if score >= 50:
                quarantined_items.append(entry)
            else:
                safe_items.append(entry)

    return {"safe": safe_items[:limit], "quarantined": quarantined_items}


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
    p_scan.add_argument("--json", help="Write full scan report to JSON file")

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
        report = scan_github_bounties(limit=args.limit)
        if args.json:
            Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("=" * 72)
        print(" BOUNTY-GUARD LIVE GITHUB SCANNER")
        print(f" Safe Bounties Found: {len(report['safe'])} | Quarantined Traps: {len(report['quarantined'])}")
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
