#!/usr/bin/env python3
"""Collect SOC 2 evidence for one GitHub repository.

Reads the repository's settings and history through the GitHub API, saves
every raw response with a timestamp and a SHA-256 manifest, and writes a
summary of which controls the evidence supports, which it contradicts, and
which still need a person.

Usage:
    python3 collect.py OWNER/REPO [--days 90] [--sla-days 30] [--out evidence]

Needs a token in GITHUB_TOKEN (or a logged-in `gh`) that can read the
repository's settings, collaborators and security alerts (admin on the repo).
Standard library only.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"


class GitHub:
    def __init__(self, token):
        self.token = token
        self.calls = 0

    def get(self, path, allow=(404,)):
        """GET one page. Returns (status, json or None)."""
        req = urllib.request.Request(
            API + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "soc2-evidence-collector",
            },
        )
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                body = res.read()
                return res.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            if e.code in allow:
                return e.code, None
            raise SystemExit(f"GET {path}: HTTP {e.code} {e.read()[:200]!r}")

    def pages(self, path, limit=1000, stop=None):
        """GET every page of a list endpoint (100 per page) up to `limit` items."""
        items, page = [], 1
        sep = "&" if "?" in path else "?"
        while len(items) < limit:
            status, data = self.get(f"{path}{sep}per_page=100&page={page}")
            if status != 200 or not data:
                break
            items.extend(data)
            if len(data) < 100 or (stop and stop(data[-1])):
                break
            page += 1
        return items[:limit]


def token():
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit("Set GITHUB_TOKEN or log in with `gh auth login`.")


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --- Classification: pure functions, covered by tests/test_collect.py ---


def approval_state(pr, reviews):
    """'independent', 'stale' or 'none'.

    Independent: someone other than the author approved the exact commit that
    was merged, before the merge. Stale: such an approval exists, but for an
    earlier commit, so the merged code was not the code that was approved.
    """
    merged = parse_time(pr["merged_at"])
    author = pr["user"]["login"]
    head = pr["head"]["sha"]
    others = [
        r for r in reviews
        if r["state"] == "APPROVED" and r["user"] and r["user"]["login"] != author
        and parse_time(r["submitted_at"]) <= merged
    ]
    if any(r.get("commit_id") == head for r in others):
        return "independent"
    return "stale" if others else "none"


def independent_approval(pr, reviews):
    return approval_state(pr, reviews) == "independent"


def checks_state(check_runs):
    """'passed', 'failed', 'pending' or 'none' for the check runs on one commit."""
    if not check_runs:
        return "none"
    if any(c["status"] != "completed" for c in check_runs):
        return "pending"
    ok = {"success", "neutral", "skipped"}
    return "passed" if all(c["conclusion"] in ok for c in check_runs) else "failed"


def checks_at_merge(pr, check_runs):
    """The checks' state when the PR was merged: a run that finished after the merge did not gate it."""
    merged = parse_time(pr["merged_at"])
    finished_before = [
        c for c in check_runs if c.get("completed_at") and parse_time(c["completed_at"]) <= merged
    ]
    if check_runs and len(finished_before) < len(check_runs):
        return "not finished"
    return checks_state(finished_before)


def open_alerts_past_sla(alerts, now, sla_days, severities=("critical", "high")):
    """Open alerts of the given severities that are older than the SLA."""
    late = []
    for a in alerts:
        sev = (a.get("security_advisory") or {}).get("severity") or (a.get("security_vulnerability") or {}).get("severity")
        age = (now - parse_time(a["created_at"])).days
        if sev in severities and age > sla_days:
            late.append({"number": a["number"], "severity": sev, "age_days": age,
                         "package": a["dependency"]["package"]["name"]})
    return late


def linked_to_merged_pr(prs, branch, merged_numbers):
    """A default-branch commit counts as reviewed only through a PR that was
    merged into that branch and is one of the merged PRs we evaluated."""
    return any(
        p.get("merged_at") and (p.get("base") or {}).get("ref") == branch and p["number"] in merged_numbers
        for p in prs or []
    )


def sla_control(status, alerts, now, sla_days):
    """(result, detail) for the alert SLA. Missing data never passes."""
    if status != 200:
        return "incomplete", f"could not read Dependabot alerts (HTTP {status}); check the token's access"
    late = open_alerts_past_sla(alerts, now, sla_days)
    return ("pass" if not late else "fail"), (
        f"{len(alerts)} open alerts, {len(late)} critical or high past {sla_days} days")


def direct_push_control(direct, commits, limit, branch):
    """(result, detail). A truncated commit list cannot prove the absence of direct pushes."""
    if len(commits) >= limit:
        return "incomplete", f"stopped at {limit} commits on {branch}; narrow --days or raise the limit"
    return ("pass" if not direct else "fail"), (
        f"{len(direct)} of {len(commits)} commits on {branch} in the window are not linked to a merged PR")


def rule_types(rules):
    return {r["type"]: r.get("parameters", {}) for r in rules or []}


# --- Collection ---


def collect(gh, repo, days, sla_days, out_root):
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(out_root, repo.replace("/", "__"), stamp)
    raw_dir = os.path.join(out, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    saved = []

    def save(name, data):
        path = os.path.join(raw_dir, name + ".json")
        with open(path, "w") as f:
            json.dump({"collected_at": now.isoformat(), "source": f"GitHub API, {repo}", "data": data}, f, indent=1)
        saved.append(path)

    started = time.monotonic()
    _, meta = gh.get(f"/repos/{repo}")
    save("repository", meta)
    branch = meta["default_branch"]

    _, rules = gh.get(f"/repos/{repo}/rules/branches/{branch}")
    save("branch-rules", rules)
    status, protection = gh.get(f"/repos/{repo}/branches/{branch}/protection")
    save("branch-protection-classic", protection if status == 200 else {"status": status})

    pulls = gh.pages(
        f"/repos/{repo}/pulls?state=closed&base={branch}&sort=updated&direction=desc",
        stop=lambda p: parse_time(p["updated_at"]) < since,
    )
    merged = [p for p in pulls if p.get("merged_at") and parse_time(p["merged_at"]) >= since]
    pr_rows = []
    for p in merged:
        reviews = gh.pages(f"/repos/{repo}/pulls/{p['number']}/reviews")
        _, runs = gh.get(f"/repos/{repo}/commits/{p['head']['sha']}/check-runs?per_page=100")
        runs = (runs or {}).get("check_runs", [])
        pr_rows.append({
            "number": p["number"],
            "merged_at": p["merged_at"],
            "approval": approval_state(p, reviews),
            "checks_at_merge": checks_at_merge(p, runs),
            "checks_now": checks_state(runs),
        })
        save(f"pr-{p['number']}", {"pull": {k: p[k] for k in ("number", "title", "merged_at", "html_url")},
                                   "head_sha": p["head"]["sha"],
                                   "reviews": [{k: r.get(k) for k in ("state", "submitted_at", "commit_id")} for r in reviews],
                                   "check_runs": [{k: c.get(k) for k in ("name", "status", "conclusion", "completed_at")} for c in runs]})

    commit_limit = 300
    commits = gh.pages(f"/repos/{repo}/commits?sha={branch}&since={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                       limit=commit_limit)
    merged_numbers = {p["number"] for p in merged}
    direct = []
    for c in commits:
        _, prs = gh.get(f"/repos/{repo}/commits/{c['sha']}/pulls")
        if not linked_to_merged_pr(prs, branch, merged_numbers):
            direct.append({"sha": c["sha"][:12], "date": c["commit"]["committer"]["date"],
                           "message": c["commit"]["message"].splitlines()[0][:80]})
    save("default-branch-commits-without-pr", direct)

    alerts_on, _ = gh.get(f"/repos/{repo}/vulnerability-alerts")
    alerts_status, _ = gh.get(f"/repos/{repo}/dependabot/alerts?state=open&per_page=1", allow=(403, 404))
    alerts = gh.pages(f"/repos/{repo}/dependabot/alerts?state=open", limit=10000) if alerts_status == 200 else []
    save("dependabot-alerts-open", [{"number": a["number"], "created_at": a["created_at"],
                                      "package": a["dependency"]["package"]["name"],
                                      "severity": a["security_advisory"]["severity"],
                                      "ghsa": a["security_advisory"]["ghsa_id"]} for a in alerts])

    sec = meta.get("security_and_analysis") or {}
    status, secrets = gh.get(f"/repos/{repo}/secret-scanning/alerts?state=open&per_page=100", allow=(403, 404))
    save("secret-scanning", {"settings": sec, "open_alerts": len(secrets) if status == 200 else None})

    collaborators = gh.pages(f"/repos/{repo}/collaborators?affiliation=all")
    outside = gh.pages(f"/repos/{repo}/collaborators?affiliation=outside")
    roles = {}
    for c in collaborators:
        roles[c["role_name"]] = roles.get(c["role_name"], 0) + 1
    # Logins stay in the raw file for the auditor; the summary only counts roles.
    save("collaborators", {"by_role": roles, "outside_collaborators": len(outside),
                           "people": [{"login": c["login"], "role": c["role_name"]} for c in collaborators]})
    elapsed = time.monotonic() - started

    # --- Evaluate ---
    r = rule_types(rules)
    pr_rule = r.get("pull_request")
    classic_reviews = (protection or {}).get("required_pull_request_reviews") if isinstance(protection, dict) else None
    required_checks = r.get("required_status_checks", {}).get("required_status_checks") or (
        ((protection or {}).get("required_status_checks") or {}).get("contexts") if isinstance(protection, dict) else None)
    n = len(pr_rows)
    approved = sum(p["approval"] == "independent" for p in pr_rows)
    stale = sum(p["approval"] == "stale" for p in pr_rows)
    tested = sum(p["checks_at_merge"] == "passed" for p in pr_rows)
    sla_result, sla_detail = sla_control(alerts_status, alerts, now, sla_days)
    push_result, push_detail = direct_push_control(direct, commits, commit_limit, branch)

    def control(cid, name, ok, detail, evidence):
        result = ok if isinstance(ok, str) else ("pass" if ok else "fail")
        return {"id": cid, "control": name, "result": result, "detail": detail, "evidence": evidence}

    controls = [
        control("CC8.1", "Changes to the default branch go through a pull request",
                bool(pr_rule or classic_reviews),
                f"rule on {branch}: {'pull_request' if pr_rule else 'none'}"
                + (f", {pr_rule.get('required_approving_review_count', 0)} approval(s) required" if pr_rule else ""),
                ["branch-rules.json", "branch-protection-classic.json"]),
        control("CC8.1", "Every merged change was tested before the merge",
                bool(required_checks) and n > 0 and tested == n,
                f"required checks: {len(required_checks or [])}; {tested} of {n} merged PRs had passing checks at merge time",
                ["branch-rules.json", "pr-*.json"]),
        control("CC8.1", "Every merged change was approved by someone other than its author",
                n > 0 and approved == n,
                f"{approved} of {n} merged PRs had an independent approval of the merged commit"
                + (f" ({stale} approved an earlier commit only)" if stale else ""),
                ["pr-*.json"]),
        control("CC8.1", "Nothing reached the default branch without a pull request",
                push_result, push_detail, ["default-branch-commits-without-pr.json"]),
        control("CC7.1", "Dependency vulnerability alerts are on",
                alerts_on == 204, "Dependabot alerts " + ("on" if alerts_on == 204 else "off"),
                ["dependabot-alerts-open.json"]),
        control("CC7.1", f"No critical or high alert is open past {sla_days} days",
                sla_result, sla_detail, ["dependabot-alerts-open.json"]),
        control("CC6.1", "Secret scanning and push protection are on",
                (sec.get("secret_scanning") or {}).get("status") == "enabled"
                and (sec.get("secret_scanning_push_protection") or {}).get("status") == "enabled",
                f"secret scanning {(sec.get('secret_scanning') or {}).get('status')}, "
                f"push protection {(sec.get('secret_scanning_push_protection') or {}).get('status')}",
                ["secret-scanning.json"]),
        {"id": "CC6.3", "control": "Repository access follows least privilege",
         "result": "needs a person",
         "detail": f"roles: {roles}, outside collaborators: {len(outside)}; the list is evidence, the judgement is not",
         "evidence": ["collaborators.json"]},
    ]

    manifest = []
    for path in sorted(saved):
        with open(path, "rb") as f:
            manifest.append(f"{hashlib.sha256(f.read()).hexdigest()}  raw/{os.path.basename(path)}")
    with open(os.path.join(out, "manifest.sha256"), "w") as f:
        f.write("\n".join(manifest) + "\n")

    summary = {
        "repository": repo, "collected_at": now.isoformat(), "window_days": days,
        "api_calls": gh.calls, "seconds": round(elapsed, 1), "evidence_files": len(saved),
        "merged_prs": pr_rows, "commits_without_pr": direct, "controls": controls,
    }
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    return out, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="OWNER/REPO")
    ap.add_argument("--days", type=int, default=90, help="evidence window in days (default 90)")
    ap.add_argument("--sla-days", type=int, default=30, help="days a critical/high alert may stay open (default 30)")
    ap.add_argument("--out", default="evidence", help="output folder (default evidence/)")
    args = ap.parse_args()

    out, s = collect(GitHub(token()), args.repo, args.days, args.sla_days, args.out)
    print(f"{s['repository']}, last {s['window_days']} days: {s['evidence_files']} evidence files, "
          f"{s['api_calls']} API calls, {s['seconds']} s")
    for c in s["controls"]:
        print(f"  {c['id']:6} {c['result']:15} {c['control']}\n         {c['detail']}")
    print(f"evidence: {out}")
    return 0 if all(c["result"] not in ("fail", "incomplete") for c in s["controls"]) else 1


if __name__ == "__main__":
    sys.exit(main())
