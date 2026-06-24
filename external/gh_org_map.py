#!/usr/bin/env python3
"""
gh_org_map.py — enumerate org members, map forks/repos/gists, score for triage

Usage:
    python gh_org_map.py <org> [--output-dir DIR] [--min-score N] [--workers N]

Auth (in order of precedence):
    1. GITHUB_TOKEN env var
    2. `gh auth token` CLI
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("requests not installed — run: pip install requests")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API = "https://api.github.com"
CUTOFF_DAYS = 90
NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, timeout=5
        )
        token = result.stdout.strip()
        if token:
            return token
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    sys.exit(
        "No GitHub token found.\n"
        "Set GITHUB_TOKEN env var or authenticate with: gh auth login"
    )


# ---------------------------------------------------------------------------
# GitHub client
# ---------------------------------------------------------------------------

class GitHubClient:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        retry = Retry(
            total=5,
            backoff_factor=1.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _get(self, url: str, params: dict = None) -> requests.Response:
        while True:
            r = self.session.get(url, params=params, timeout=20)
            if r.status_code == 403 and "rate limit" in r.text.lower():
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - int(time.time()), 1) + 2
                print(f"\n  [rate limit] sleeping {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            return r

    def paginate(self, path: str, params: dict = None) -> list:
        url = f"{API}{path}"
        results = []
        p = {"per_page": 100, **(params or {})}
        while url:
            r = self._get(url, p)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                return data  # single object endpoint
            url = r.links.get("next", {}).get("url")
            p = {}  # params already in next URL
        return results

    def get(self, path: str) -> Optional[dict]:
        r = self._get(f"{API}{path}")
        if r.status_code in (404, 403):
            return None
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

SENSITIVE_NAMES = (
    "internal", "infra", "corp", "prod", "staging", "deploy", "secret",
    "config", "cred", "vault", "k8s", "terraform", "ansible", "aws",
    "gcp", "azure", "vpn", "bastion", "jumpbox", "ci", "pipeline",
    "helm", "password", "token", "key", "private",
)

SENSITIVE_EXTENSIONS = (
    ".pem", ".key", ".env", ".cfg", ".conf", ".tf", ".sh",
)

SENSITIVE_GIST_KEYWORDS = (
    "password", "token", "secret", "key", "cred", ".env",
    "config", "aws", "ssh", "vpn", "prod", "internal",
)


def days_since(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (NOW - dt).days
    except ValueError:
        return None


def score_repo(name: str, desc: str, is_org_fork: bool,
               pushed_at: Optional[str], org: str) -> int:
    score = 0
    name_lower = (name or "").lower()
    desc_lower = (desc or "").lower()

    if is_org_fork:
        score += 40

    if any(kw in name_lower for kw in SENSITIVE_NAMES):
        score += 25

    if any(kw in desc_lower for kw in SENSITIVE_NAMES) or org.lower() in desc_lower:
        score += 20

    age = days_since(pushed_at)
    if age is not None and age <= CUTOFF_DAYS:
        score += 15

    return score


def score_gist(desc: str, filenames: list[str], updated_at: Optional[str]) -> int:
    score = 0
    combined = ((desc or "") + " " + " ".join(filenames)).lower()

    if any(kw in combined for kw in SENSITIVE_GIST_KEYWORDS):
        score += 35

    if any(f.endswith(ext) for f in filenames for ext in SENSITIVE_EXTENSIONS):
        score += 20

    age = days_since(updated_at)
    if age is not None and age <= CUTOFF_DAYS:
        score += 10

    return score


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    type: str           # repo | gist
    user: str
    name: str
    url: str
    score: int
    desc: str = ""
    fork: bool = False
    org_fork: bool = False
    pushed: str = ""
    private: bool = False
    files: str = ""     # gist only


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def process_member(login: str, org: str, org_repo_names: set,
                   client: GitHubClient, min_score: int) -> list[Finding]:
    findings = []

    # -- Repos --
    repos = client.paginate(f"/users/{login}/repos")
    for repo in repos:
        name        = repo.get("name", "")
        full_name   = repo.get("full_name", "")
        desc        = repo.get("description") or ""
        is_fork     = repo.get("fork", False)
        pushed_at   = repo.get("pushed_at")
        html_url    = repo.get("html_url", "")
        is_private  = repo.get("private", False)

        is_org_fork = False
        if is_fork:
            parent = repo.get("parent", {})
            if parent:
                parent_org  = parent.get("owner", {}).get("login", "")
                parent_name = parent.get("name", "")
                is_org_fork = parent_org == org or parent_name in org_repo_names
            else:
                # parent not embedded — check if name matches an org repo
                is_org_fork = name in org_repo_names

        s = score_repo(name, desc, is_org_fork, pushed_at, org)
        if s >= min_score:
            findings.append(Finding(
                type="repo", user=login, name=full_name,
                url=html_url, score=s, desc=desc,
                fork=is_fork, org_fork=is_org_fork,
                pushed=pushed_at or "", private=is_private,
            ))

    # -- Gists --
    gists = client.paginate(f"/users/{login}/gists")
    for gist in gists:
        gist_id   = gist.get("id", "")
        gist_url  = gist.get("html_url", "")
        gist_desc = gist.get("description") or ""
        updated   = gist.get("updated_at")
        filenames = list(gist.get("files", {}).keys())

        s = score_gist(gist_desc, filenames, updated)
        if s >= min_score:
            findings.append(Finding(
                type="gist", user=login, name=gist_id,
                url=gist_url, score=s, desc=gist_desc,
                pushed=updated or "", files=" ".join(filenames),
            ))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Map GitHub org member repos/gists")
    parser.add_argument("org",          help="GitHub org name")
    parser.add_argument("--output-dir", default="", help="Output directory (default: gh-map-<timestamp>)")
    parser.add_argument("--min-score",  type=int, default=1, help="Minimum score to include (default: 1)")
    parser.add_argument("--workers",    type=int, default=10, help="Concurrent workers (default: 10)")
    args = parser.parse_args()

    org      = args.org
    out_dir  = Path(args.output_dir or f"gh-map-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)

    token  = get_token()
    client = GitHubClient(token)

    print(f"[*] Target org : {org}")
    print(f"[*] Output     : {out_dir}")
    print()

    # -- Org members --
    print("[1/4] Enumerating org members...")
    members = client.paginate(f"/orgs/{org}/members")
    if not members:
        sys.exit(
            f"No members returned for '{org}'.\n"
            "Org may be private, name may be wrong, or your token lacks org:read scope."
        )
    logins = [m["login"] for m in members]
    print(f"      Found {len(logins)} members")

    with open(out_dir / "members.json", "w") as f:
        json.dump(members, f, indent=2)

    # -- Org repos --
    print("\n[2/4] Fetching org repo list...")
    org_repos = client.paginate(f"/orgs/{org}/repos")
    org_repo_names = {r["name"] for r in org_repos}
    print(f"      Found {len(org_repo_names)} org repos")

    with open(out_dir / "org_repos.json", "w") as f:
        json.dump(org_repos, f, indent=2)

    # -- Per-member enumeration --
    print(f"\n[3/4] Mapping member repos and gists ({args.workers} workers)...")
    all_findings: list[Finding] = []

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(process_member, login, org, org_repo_names,
                        client, args.min_score): login
            for login in logins
        }
        for future in as_completed(futures):
            login = futures[future]
            done += 1
            try:
                results = future.result()
                all_findings.extend(results)
                print(f"  [{done:>4}/{len(logins)}] {login:<30} interesting={len(results)}")
            except Exception as e:
                print(f"  [{done:>4}/{len(logins)}] {login:<30} ERROR: {e}", file=sys.stderr)

    # -- Sort and write output --
    print("\n[4/4] Writing output...")
    all_findings.sort(key=lambda f: f.score, reverse=True)

    # JSONL
    jsonl_path = out_dir / "report.jsonl"
    with open(jsonl_path, "w") as f:
        for finding in all_findings:
            f.write(json.dumps(asdict(finding)) + "\n")

    # TSV
    tsv_path = out_dir / "summary.tsv"
    tsv_fields = ["score", "type", "user", "name", "org_fork", "pushed", "url"]
    with open(tsv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=tsv_fields, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        for finding in all_findings:
            row = asdict(finding)
            row["url"] = row.pop("url", "")
            w.writerow({k: row.get(k, "") for k in tsv_fields})

    # -- Summary --
    high   = sum(1 for f in all_findings if f.score >= 50)
    medium = sum(1 for f in all_findings if 25 <= f.score < 50)
    org_forks = [f for f in all_findings if f.org_fork]

    print()
    print("=" * 68)
    print(f" Results: {out_dir}")
    print("-" * 68)
    print(f" Total interesting findings : {len(all_findings)}")
    print(f" High priority (score >=50) : {high}")
    print(f" Medium priority  (25-49)   : {medium}")
    print(f" Org forks found            : {len(org_forks)}")
    print("=" * 68)
    print()
    print(f" {'SCORE':<7} {'TYPE':<7} {'USER':<22} {'ORG_FORK':<10} URL")
    print(f" {'-'*6:<7} {'-'*6:<7} {'-'*21:<22} {'-'*8:<10} ---")

    for f in all_findings[:20]:
        print(f" {f.score:<7} {f.type:<7} {f.user:<22} {str(f.org_fork):<10} {f.url}")

    print()
    for f in all_findings:
        print(f.url)


if __name__ == "__main__":
    main()
