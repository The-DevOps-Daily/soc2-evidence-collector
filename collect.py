#!/usr/bin/env python3
"""Collect SOC 2 evidence for one GitHub repository.

Reads the repository's settings and history through the GitHub API, saves
the fields each control uses with a timestamp and a SHA-256 manifest, and
writes a summary of which controls the evidence supports, which it
contradicts, and which still need a person.

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
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
SEVERITIES = ("low", "medium", "high", "critical")


class GitHub:
    def __init__(self, token):
        self.token = token
        self.calls = 0

    def request(self, url):
        """One GET. Returns (status, json or error text, Link header)."""
        req = urllib.request.Request(
            url,
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
                return res.status, (json.loads(body) if body else None), res.headers.get("Link") or ""
        except urllib.error.HTTPError as e:
            return e.code, e.read()[:200], ""

    def get(self, path, allow=(404,)):
        """GET one object. Returns (status, json or None); a status outside `allow` stops the run."""
        status, data, _ = self.request(API + path)
        if status < 400:
            return status, data
        if status in allow:
            return status, None
        raise SystemExit(f"GET {path}: HTTP {status} {data!r}")

    def follow(self, path, limit=1000, stop=None, key=None):
        """GET every page of a list through the Link header's next URL.

        Returns (items, complete). `complete` is False when the list was cut at
        `limit` with pages left. `stop(item)` ends early once the rest of a
        sorted list is outside the window. Any error stops the run: a list that
        failed half way is not a short list.
        """
        url = API + path + ("&" if "?" in path else "?") + "per_page=100"
        items = []
        while url:
            status, data, links = self.request(url)
            if status != 200:
                raise SystemExit(f"GET {url}: HTTP {status} {data!r}")
            page = data[key] if key else data
            items.extend(page)
            if stop and page and stop(page[-1]):
                return items, True
            url = next((part.split(";")[0].strip(" <>") for part in links.split(",") if 'rel="next"' in part), None)
            if url and len(items) >= limit:
                return items, False
        return items, True


def token():
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit("Set GITHUB_TOKEN or log in with `gh auth login`.")


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def seg(value):
    """One URL path segment. Branch names can hold '/', '?', '#' or '&'."""
    return urllib.parse.quote(str(value), safe="")


def query(path, **params):
    return path + "?" + urllib.parse.urlencode(params)


def only_ref(items, ref_of, expected):
    """(items on the expected ref, whether all were). An item for another ref
    means the API did not answer the question we asked."""
    kept = [i for i in items if ref_of(i) == expected]
    return kept, len(kept) == len(items)


# --- Classification: pure functions, covered by tests/test_collect.py ---


def approval_state(pr, reviews):
    """'independent', 'stale', 'changes requested' or 'none'.

    Only each reviewer's last decision before the merge counts, as on GitHub:
    a later change request or a dismissal replaces an approval. Independent:
    someone other than the author approved the exact commit that was merged.
    Stale: the approval was for an earlier commit, so the merged code was not
    the code that was approved.
    """
    merged = parse_time(pr["merged_at"])
    author = pr["user"]["login"]
    head = pr["head"]["sha"]
    last = {}
    for r in sorted(reviews, key=lambda r: r.get("submitted_at") or ""):
        login = (r.get("user") or {}).get("login")
        if (login and login != author and r.get("submitted_at") and parse_time(r["submitted_at"]) <= merged
                and r["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")):
            last[login] = r
    if any(r["state"] == "CHANGES_REQUESTED" for r in last.values()):
        return "changes requested"
    approvals = [r for r in last.values() if r["state"] == "APPROVED"]
    if any(r.get("commit_id") == head for r in approvals):
        return "independent"
    return "stale" if approvals else "none"


def independent_approval(pr, reviews):
    return approval_state(pr, reviews) == "independent"


def required_contexts(rules, protection):
    """[(check name, app id or None)] required by any ruleset rule or classic protection."""
    required = []
    for r in rules or []:
        if r["type"] == "required_status_checks":
            for c in r.get("parameters", {}).get("required_status_checks") or []:
                required.append((c["context"], c.get("integration_id")))
    classic = (protection or {}).get("required_status_checks") or {}
    for c in classic.get("checks") or [{"context": name} for name in classic.get("contexts") or []]:
        required.append((c["context"], c.get("app_id")))
    return list(dict.fromkeys(required))


def checks_at_merge(pr, check_runs, required):
    """'passed', 'failed', 'skipped', 'not finished' or 'missing' for the required checks when the PR was merged.

    Each required check is judged by its latest run on the PR's head commit
    (with the check's name, and app when the rule names one) that started at
    or before the merge: that run is the check's state at the merge. If it had
    not finished by then, the check did not gate the merge, even when an
    earlier run passed. Runs started after the merge are re-runs and do not
    count. Only `success` passes: a skipped or neutral check ran no tests, and
    a passing run of some other check does not stand in for a required one.
    """
    merged = parse_time(pr["merged_at"])
    states = []
    for name, app in required:
        runs = [c for c in check_runs
                if c["name"] == name and (app is None or (c.get("app") or {}).get("id") == app)]
        # A run with no start time is treated as the latest, so it can only hold a check back.
        started = sorted((c for c in runs if not c.get("started_at") or parse_time(c["started_at"]) <= merged),
                         key=lambda c: c.get("started_at") or "9999")
        if not started:
            states.append("not finished" if runs else "missing")
            continue
        last = started[-1]
        if not last.get("completed_at") or parse_time(last["completed_at"]) > merged:
            states.append("not finished")
        elif last["conclusion"] == "success":
            states.append("passed")
        else:
            states.append("skipped" if last["conclusion"] in ("skipped", "neutral") else "failed")
    return next((s for s in ("missing", "failed", "skipped", "not finished") if s in states), "passed")


def alert_severity(a):
    return (a.get("security_advisory") or {}).get("severity") or (a.get("security_vulnerability") or {}).get("severity")


def open_alerts_past_sla(alerts, now, sla_days, severities=("critical", "high")):
    """Open alerts of the given severities that have been open longer than the SLA."""
    late = []
    for a in alerts:
        sev = alert_severity(a)
        age = now - parse_time(a["created_at"])
        if sev in severities and age > timedelta(days=sla_days):
            late.append({"number": a["number"], "severity": sev, "age_days": age.days,
                         "package": a["dependency"]["package"]["name"]})
    return late


def linked_to_merged_pr(prs, branch, merged_numbers):
    """A default-branch commit counts as reviewed only through a PR that was
    merged into that branch and is one of the merged PRs we evaluated."""
    return any(
        p.get("merged_at") and (p.get("base") or {}).get("ref") == branch and p["number"] in merged_numbers
        for p in prs or []
    )


def ref_updates_outside_prs(activities, since):
    """Updates to the branch in the window that were not pull request merges:
    direct pushes, force pushes, and the branch being created or deleted."""
    return [a for a in activities if parse_time(a["timestamp"]) >= since
            and a["activity_type"] not in ("pr_merge", "merge_queue_merge")]


def activity_covers(activities, since):
    """The branch's activity log reaches back to the window start, or to the branch's creation."""
    return any(parse_time(a["timestamp"]) < since or a["activity_type"] == "branch_creation" for a in activities)


# Partial data can still prove a failure, but it can never prove a pass.


def pr_control(rows, key, good, complete):
    if any(p[key] not in (good, "incomplete") for p in rows):
        return "fail"
    if not complete or any(p[key] == "incomplete" for p in rows):
        return "incomplete"
    return "pass" if rows else "fail"


def sla_control(status, alerts, complete, now, sla_days):
    """(result, detail) for the alert SLA. Missing data never passes."""
    if status != 200:
        return "incomplete", f"could not read Dependabot alerts (HTTP {status}); check the token's access"
    late = open_alerts_past_sla(alerts, now, sla_days)
    unknown = [a for a in alerts if alert_severity(a) not in SEVERITIES]
    detail = f"{len(alerts)} open alerts, {len(late)} critical or high open longer than {sla_days} days"
    if late:
        return "fail", detail
    if not complete:
        return "incomplete", detail + f"; stopped at {len(alerts)} alerts"
    if unknown:
        return "incomplete", detail + f"; {len(unknown)} without a known severity"
    return "pass", detail


def direct_push_control(direct, commits, commits_complete, updates, log_covers, branch):
    """(result, detail) from two sources: commits with no merged PR, and branch
    updates that were not PR merges (which also catches force pushes)."""
    detail = (f"commits not linked to a merged PR: {len(direct)} of {len(commits)}; "
              f"branch updates that were not PR merges: {len(updates)}")
    if updates:
        detail += " (" + ", ".join(sorted({u["activity_type"] for u in updates})) + ")"
    if direct or updates:
        return "fail", detail
    if not commits_complete:
        return "incomplete", f"stopped at {len(commits)} commits on {branch}; narrow --days"
    if not log_covers:
        return "incomplete", f"the activity log for {branch} does not reach back to the window start"
    return "pass", detail


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
    base = f"/repos/{repo}"
    _, meta = gh.get(base, allow=())
    save("repository", meta)
    branch = meta["default_branch"]

    rules, rules_complete = gh.follow(f"{base}/rules/branches/{seg(branch)}")
    save("branch-rules", rules)
    status, protection = gh.get(f"{base}/branches/{seg(branch)}/protection")
    save("branch-protection-classic", protection if status == 200 else {"status": status})
    required = required_contexts(rules, protection)

    pulls, prs_complete = gh.follow(
        query(f"{base}/pulls", state="closed", base=branch, sort="updated", direction="desc"),
        stop=lambda p: parse_time(p["updated_at"]) < since,
    )
    pulls, on_branch = only_ref(pulls, lambda p: (p.get("base") or {}).get("ref"), branch)
    prs_complete = prs_complete and on_branch
    merged = [p for p in pulls if p.get("merged_at") and parse_time(p["merged_at"]) >= since]
    pr_rows = []
    for p in merged:
        reviews, reviews_complete = gh.follow(f"{base}/pulls/{seg(p['number'])}/reviews")
        # filter=all keeps runs that a later re-run replaced, so the run that gated the merge is still visible.
        runs, runs_complete = gh.follow(query(f"{base}/commits/{seg(p['head']['sha'])}/check-runs", filter="all"),
                                        key="check_runs")
        runs, on_head = only_ref(runs, lambda c: c.get("head_sha"), p["head"]["sha"])
        pr_rows.append({
            "number": p["number"],
            "merged_at": p["merged_at"],
            "approval": approval_state(p, reviews) if reviews_complete else "incomplete",
            "checks_at_merge": checks_at_merge(p, runs, required) if runs_complete and on_head else "incomplete",
        })
        save(f"pr-{p['number']}", {
            "pull": {"number": p["number"], "title": p["title"], "author": p["user"]["login"],
                     "base": p["base"]["ref"], "merged_at": p["merged_at"], "html_url": p["html_url"]},
            "head_sha": p["head"]["sha"],
            "reviews": [{"reviewer": (r.get("user") or {}).get("login"),
                         **{k: r.get(k) for k in ("state", "submitted_at", "commit_id")}} for r in reviews],
            "check_runs": [{"name": c["name"], "app_id": (c.get("app") or {}).get("id"),
                            **{k: c.get(k) for k in ("head_sha", "status", "conclusion", "started_at", "completed_at")}}
                           for c in runs],
        })

    commits, commits_complete = gh.follow(
        query(f"{base}/commits", sha=branch, since=since.strftime("%Y-%m-%dT%H:%M:%SZ")), limit=300)
    merged_numbers = {p["number"] for p in merged}
    direct, linked = [], []
    for c in commits:
        prs, _ = gh.follow(f"{base}/commits/{seg(c['sha'])}/pulls")
        row = {"sha": c["sha"][:12], "date": c["commit"]["committer"]["date"],
               "message": c["commit"]["message"].splitlines()[0][:80],
               "pulls": [{"number": p["number"], "base": (p.get("base") or {}).get("ref"),
                          "merged_at": p.get("merged_at")} for p in prs]}
        (linked if linked_to_merged_pr(prs, branch, merged_numbers) else direct).append(row)
    save("default-branch-commits", {"without_pr": direct, "linked": linked})

    # Every update to the branch ref, including force pushes that left no commit behind.
    activity, activity_complete = gh.follow(query(f"{base}/activity", ref=f"refs/heads/{branch}"),
                                            stop=lambda a: parse_time(a["timestamp"]) < since)
    activity, on_branch = only_ref(activity, lambda a: a.get("ref"), f"refs/heads/{branch}")
    activity_complete = activity_complete and on_branch
    updates = ref_updates_outside_prs(activity, since)
    save("branch-activity", [{"type": a["activity_type"], "ref": a["ref"], "timestamp": a["timestamp"],
                              "actor": (a.get("actor") or {}).get("login"),
                              "before": a.get("before"), "after": a.get("after")} for a in activity])

    alerts_on, _ = gh.get(f"{base}/vulnerability-alerts")
    alerts_status, _ = gh.get(query(f"{base}/dependabot/alerts", state="open", per_page=1), allow=(403, 404))
    alerts, alerts_complete = (gh.follow(query(f"{base}/dependabot/alerts", state="open"), limit=10000)
                               if alerts_status == 200 else ([], False))
    # vulnerability-alerts answers 204 when Dependabot alerts are on and 404 when they are off.
    save("dependabot-alerts-open", {"setting_status": alerts_on, "status": alerts_status, "complete": alerts_complete,
                                    "alerts": [{"number": a["number"], "created_at": a["created_at"],
                                                "package": a["dependency"]["package"]["name"],
                                                "severity": alert_severity(a),
                                                "ghsa": (a.get("security_advisory") or {}).get("ghsa_id")}
                                               for a in alerts]})

    sec = meta.get("security_and_analysis") or {}
    status, _ = gh.get(query(f"{base}/secret-scanning/alerts", state="open", per_page=1), allow=(403, 404))
    secrets = gh.follow(query(f"{base}/secret-scanning/alerts", state="open"))[0] if status == 200 else None
    save("secret-scanning", {"settings": sec, "open_alerts": len(secrets) if secrets is not None else None})

    collaborators, collaborators_complete = gh.follow(query(f"{base}/collaborators", affiliation="all"))
    outside, outside_complete = gh.follow(query(f"{base}/collaborators", affiliation="outside"))
    roles = {}
    for c in collaborators:
        roles[c["role_name"]] = roles.get(c["role_name"], 0) + 1
    # Logins stay in the raw file for the auditor; the summary only counts roles.
    save("collaborators", {"by_role": roles, "outside_collaborators": len(outside),
                           "people": [{"login": c["login"], "role": c["role_name"]} for c in collaborators]})
    elapsed = time.monotonic() - started

    # --- Evaluate ---
    pr_rules = [r.get("parameters", {}) for r in rules or [] if r["type"] == "pull_request"]
    classic_reviews = (protection or {}).get("required_pull_request_reviews")
    if pr_rules:
        approvals_required = max(r.get("required_approving_review_count", 0) for r in pr_rules)
        rule_detail = f"rule on {branch}: pull_request, {approvals_required} approval(s) required"
    elif classic_reviews:
        rule_detail = (f"classic protection on {branch}: "
                       f"{classic_reviews.get('required_approving_review_count', 0)} approval(s) required")
    else:
        rule_detail = f"no pull request rule on {branch}"
    n = len(pr_rows)
    approved = sum(p["approval"] == "independent" for p in pr_rows)
    not_approved = {}
    for p in pr_rows:
        if p["approval"] not in ("independent", "none"):
            not_approved[p["approval"]] = not_approved.get(p["approval"], 0) + 1
    untested = [f"#{p['number']} {p['checks_at_merge']}" for p in pr_rows if p["checks_at_merge"] != "passed"]
    sla_result, sla_detail = sla_control(alerts_status, alerts, alerts_complete, now, sla_days)
    push_result, push_detail = direct_push_control(direct, commits, commits_complete, updates,
                                                   activity_complete and activity_covers(activity, since), branch)

    def control(cid, name, ok, detail, evidence):
        result = ok if isinstance(ok, str) else ("pass" if ok else "fail")
        return {"id": cid, "control": name, "result": result, "detail": detail, "evidence": evidence}

    controls = [
        control("CC8.1", "Changes to the default branch go through a pull request",
                "pass" if pr_rules or classic_reviews else ("fail" if rules_complete else "incomplete"), rule_detail,
                ["branch-rules.json", "branch-protection-classic.json"]),
        control("CC8.1", "Every merged change passed the required checks before the merge",
                pr_control(pr_rows, "checks_at_merge", "passed", prs_complete and rules_complete) if required
                else ("fail" if rules_complete else "incomplete"),
                f"required: {', '.join(name for name, _ in required) or 'none'}; "
                f"{n - len(untested)} of {n} merged PRs passed every required check before the merge"
                + (f" ({', '.join(untested)})" if untested else ""),
                ["branch-rules.json", "branch-protection-classic.json", "pr-*.json"]),
        control("CC8.1", "Every merged change was approved by someone other than its author",
                pr_control(pr_rows, "approval", "independent", prs_complete),
                f"{approved} of {n} merged PRs had an independent approval of the merged commit"
                + "".join(f"; {count} {state}" for state, count in sorted(not_approved.items())),
                ["pr-*.json"]),
        control("CC8.1", "Nothing reached the default branch without a pull request",
                push_result, push_detail, ["default-branch-commits.json", "branch-activity.json"]),
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
                ["repository.json", "secret-scanning.json"]),
        control("CC6.3", "Repository access follows least privilege",
                "needs a person" if collaborators_complete and outside_complete else "incomplete",
                f"roles: {roles}, outside collaborators: {len(outside)}; the list is evidence, the judgement is not",
                ["collaborators.json"]),
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
        "required_checks": [name for name, _ in required],
        "merged_prs": pr_rows, "commits_without_pr": direct,
        "branch_updates_without_pr": updates, "controls": controls,
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
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        ap.error("repo must be OWNER/REPO")

    out, s = collect(GitHub(token()), args.repo, args.days, args.sla_days, args.out)
    print(f"{s['repository']}, last {s['window_days']} days: {s['evidence_files']} evidence files, "
          f"{s['api_calls']} API calls, {s['seconds']} s")
    for c in s["controls"]:
        print(f"  {c['id']:6} {c['result']:15} {c['control']}\n         {c['detail']}")
    print(f"evidence: {out}")
    return 0 if all(c["result"] not in ("fail", "incomplete") for c in s["controls"]) else 1


if __name__ == "__main__":
    sys.exit(main())
