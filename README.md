# soc2-evidence-collector

Pull SOC 2 evidence from GitHub and Terraform instead of taking screenshots.

```bash
# GitHub: change management, vulnerability alerts, secret scanning, access
python3 collect.py OWNER/REPO --days 90

# Terraform: misconfigurations, with Trivy (https://trivy.dev)
./scan-iac.sh examples/terraform
```

`collect.py` needs a token that is admin on the repository, in `GITHUB_TOKEN` or from a logged-in `gh`. It uses only the Python standard library.

Write-up: [SOC 2 Evidence From GitHub and Terraform, and the Part That Still Needs a Person](https://devops-daily.com/posts/soc2-evidence-from-github-and-terraform)

The post quotes a run from 2026-10-19 13:19 UTC. After it, the commit that added the write-up link (e9d7770) went straight to main without a pull request, by an admin bypassing the ruleset. A new run reports it as a second commit without a pull request and a second branch update that was not a PR merge: the control working as the post describes.

## What it checks

| Criterion | Control | Evidence |
| --- | --- | --- |
| CC8.1 | Changes to the default branch go through a pull request | branch rules and classic protection |
| CC8.1 | Every merged change passed the required checks before the merge | the last run of each required check on the pull request's head commit that started before the merge; it must have succeeded before the merge |
| CC8.1 | Every merged change was approved by someone other than its author | each reviewer's last decision before the merge, for the merged commit |
| CC8.1 | Nothing reached the default branch without a pull request | each commit's merged PR into that branch, and the branch's activity log (pushes, force pushes) |
| CC7.1 | Dependency vulnerability alerts are on | Dependabot setting |
| CC7.1 | No critical or high alert is open past the SLA (`--sla-days`, default 30) | open Dependabot alerts |
| CC6.1 | Secret scanning and push protection are on | repository security settings |
| CC6.3 | Repository access follows least privilege | collaborator roles (a person judges this one) |

Every control is `pass`, `fail`, `needs a person` or `incomplete`. Missing data never passes. Partial data can still prove a failure, but these make a control `incomplete` instead of `pass`:

- alerts the token cannot read, or alerts without a known severity;
- any list cut at its limit (commits at 300, alerts at 10,000, other lists at 1,000);
- a branch activity log that does not reach back to the start of the window;
- a pull request or activity entry for a branch other than the one asked for.

Any other API error stops the run. Only a `success` conclusion passes a required check: GitHub lets a skipped or neutral required check through, but it ran no tests, so the collector reports it as `skipped`. A required check that reports through the older commit status API, not as a check run, shows as `missing`.

The pull request, commit and branch-activity controls look back over the window. The settings and the open alerts are read as they are when you run it, so run it on a schedule and keep every folder to cover a period.

## What you get

```
evidence/OWNER__REPO/<UTC time>/
  raw/*.json        the API fields each control uses, with the time they were collected
  summary.json      the controls, the merged PRs, and the commits and branch updates without a PR
  manifest.sha256   hashes of the raw files
```

The manifest shows whether a file changed after collection, as long as you store it where nobody can edit it.

The raw files keep logins (PR authors, reviewers, collaborators) for the auditor. Keep `evidence/` out of public repositories (it is in `.gitignore`).

## The demo in this repository

This repository is its own test subject. Its main branch has a ruleset that requires a pull request, one approval and the `test` check, with a bypass for organization admins, and the history was made on purpose:

- the first commit was pushed straight to main, before the ruleset existed;
- every pull request was merged by an admin with the bypass, so none has an independent approval;
- pull request #3 was merged before its `test` check finished;
- `examples/app/requirements.txt` pins old PyYAML and Jinja2 releases, so Dependabot has alerts to report;
- `examples/terraform` has an exports bucket with no encryption or public access block, and a database open to the internet.

The collector reports each of these. That is the point: the ruleset is not the evidence; what happened under it is.

## Tests

```bash
python3 tests/test_collect.py -v
```

MIT license.
