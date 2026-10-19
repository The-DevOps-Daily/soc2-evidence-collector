# soc2-evidence-collector

Pull SOC 2 evidence from GitHub and Terraform instead of taking screenshots.

```bash
# GitHub: change management, vulnerability alerts, secret scanning, access
python3 collect.py OWNER/REPO --days 90

# Terraform: misconfigurations, with Trivy (https://trivy.dev)
./scan-iac.sh examples/terraform
```

`collect.py` needs a token that is admin on the repository, in `GITHUB_TOKEN` or from a logged-in `gh`. It uses only the Python standard library.

Write-up: _link added when the post is published_.

## What it checks

| Criterion | Control | Evidence |
| --- | --- | --- |
| CC8.1 | Changes to the default branch go through a pull request | branch rules and classic protection |
| CC8.1 | Every merged change was tested before the merge | check runs on the merged commit, finished before the merge |
| CC8.1 | Every merged change was approved by someone other than its author | reviews that approved the merged commit, before the merge |
| CC8.1 | Nothing reached the default branch without a pull request | each commit's merged PR into that branch |
| CC7.1 | Dependency vulnerability alerts are on | Dependabot setting |
| CC7.1 | No critical or high alert is open past the SLA (`--sla-days`, default 30) | open Dependabot alerts |
| CC6.1 | Secret scanning and push protection are on | repository security settings |
| CC6.3 | Repository access follows least privilege | collaborator roles (a person judges this one) |

Every control is `pass`, `fail`, `needs a person` or `incomplete`. Missing data never passes: alerts the token cannot read, or a commit list cut at the limit, make a control `incomplete`.

## What you get

```
evidence/OWNER__REPO/<UTC time>/
  raw/*.json        every API response used, with the time it was collected
  summary.json      the controls, the merged PRs and the commits without a PR
  manifest.sha256   hashes of the raw files
```

The raw files keep collaborator logins for the auditor. Keep `evidence/` out of public repositories (it is in `.gitignore`).

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
