import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import collect  # noqa: E402

HEAD = "head-sha"
PR = {"merged_at": "2026-10-19T12:00:00Z", "user": {"login": "alice"}, "head": {"sha": HEAD}}
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


def review(login, state="APPROVED", at="2026-10-19T11:00:00Z", commit=HEAD):
    return {"user": {"login": login}, "state": state, "submitted_at": at, "commit_id": commit}


def run(conclusion="success", status="completed", done="2026-10-19T11:30:00Z"):
    return {"status": status, "conclusion": conclusion, "completed_at": done}


class Approval(unittest.TestCase):
    def test_approval_of_the_merged_commit_by_someone_else_counts(self):
        self.assertEqual(collect.approval_state(PR, [review("bob")]), "independent")

    def test_the_authors_own_approval_does_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("alice")]), "none")

    def test_an_approval_after_the_merge_does_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("bob", at="2026-10-19T13:00:00Z")]), "none")

    def test_comments_and_change_requests_do_not_count(self):
        reviews = [review("bob", "COMMENTED"), review("carol", "CHANGES_REQUESTED")]
        self.assertEqual(collect.approval_state(PR, reviews), "none")

    def test_an_approval_of_an_earlier_commit_is_stale(self):
        # Pushed after the approval: the merged code is not what was approved.
        self.assertEqual(collect.approval_state(PR, [review("bob", commit="older-sha")]), "stale")
        self.assertFalse(collect.independent_approval(PR, [review("bob", commit="older-sha")]))


class Checks(unittest.TestCase):
    def test_states(self):
        self.assertEqual(collect.checks_state([]), "none")
        self.assertEqual(collect.checks_state([run(), run("skipped")]), "passed")
        self.assertEqual(collect.checks_state([run(), run("failure")]), "failed")
        self.assertEqual(collect.checks_state([run(status="in_progress", conclusion=None)]), "pending")

    def test_a_run_that_finished_after_the_merge_did_not_gate_it(self):
        self.assertEqual(collect.checks_at_merge(PR, [run(done="2026-10-19T12:05:00Z")]), "not finished")
        self.assertEqual(collect.checks_at_merge(PR, [run()]), "passed")
        self.assertEqual(collect.checks_at_merge(PR, []), "none")


class Sla(unittest.TestCase):
    def alert(self, sev, created):
        return {
            "number": 1,
            "created_at": created,
            "security_advisory": {"severity": sev},
            "dependency": {"package": {"name": "pkg"}},
        }

    def test_only_old_critical_and_high_alerts_are_late(self):
        alerts = [
            self.alert("critical", "2026-09-01T00:00:00Z"),
            self.alert("high", "2026-10-10T00:00:00Z"),
            self.alert("medium", "2026-01-01T00:00:00Z"),
        ]
        late = collect.open_alerts_past_sla(alerts, NOW, 30)
        self.assertEqual([a["severity"] for a in late], ["critical"])
        self.assertEqual(collect.sla_control(200, alerts, NOW, 30)[0], "fail")
        self.assertEqual(collect.sla_control(200, [], NOW, 30)[0], "pass")

    def test_alerts_we_could_not_read_never_pass(self):
        for status in (403, 404):
            self.assertEqual(collect.sla_control(status, [], NOW, 30)[0], "incomplete")


class DirectPushes(unittest.TestCase):
    def pr(self, number, base="main", merged="2026-10-19T12:00:00Z"):
        return {"number": number, "merged_at": merged, "base": {"ref": base}}

    def test_a_commit_counts_only_through_a_merged_pr_into_the_branch_we_evaluated(self):
        self.assertTrue(collect.linked_to_merged_pr([self.pr(3)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(3, base="release")], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(3, merged=None)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(4)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([], "main", {3}))

    def test_a_truncated_commit_list_is_incomplete_not_a_pass(self):
        self.assertEqual(collect.direct_push_control([], [{}] * 300, 300, "main")[0], "incomplete")
        self.assertEqual(collect.direct_push_control([], [{}] * 12, 300, "main")[0], "pass")
        self.assertEqual(collect.direct_push_control([{"sha": "a"}], [{}] * 12, 300, "main")[0], "fail")


if __name__ == "__main__":
    unittest.main()
