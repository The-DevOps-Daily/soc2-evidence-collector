import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import collect  # noqa: E402

HEAD = "head-sha"
PR = {"merged_at": "2026-10-19T12:00:00Z", "user": {"login": "alice"}, "head": {"sha": HEAD}}
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
TEST = [("test", None)]


def review(login, state="APPROVED", at="2026-10-19T11:00:00Z", commit=HEAD):
    return {"user": {"login": login}, "state": state, "submitted_at": at, "commit_id": commit}


def run(conclusion="success", status="completed", done="2026-10-19T11:30:00Z", name="test", app=15368):
    return {"name": name, "app": {"id": app}, "status": status, "conclusion": conclusion, "completed_at": done}


class Approval(unittest.TestCase):
    def test_approval_of_the_merged_commit_by_someone_else_counts(self):
        self.assertEqual(collect.approval_state(PR, [review("bob")]), "independent")

    def test_the_authors_own_approval_does_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("alice")]), "none")

    def test_an_approval_after_the_merge_does_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("bob", at="2026-10-19T13:00:00Z")]), "none")

    def test_comments_do_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("bob", "COMMENTED")]), "none")

    def test_an_approval_of_an_earlier_commit_is_stale(self):
        # Pushed after the approval: the merged code is not what was approved.
        self.assertEqual(collect.approval_state(PR, [review("bob", commit="older-sha")]), "stale")
        self.assertFalse(collect.independent_approval(PR, [review("bob", commit="older-sha")]))

    def test_only_each_reviewers_last_decision_counts(self):
        approved_then_blocked = [review("bob", at="2026-10-19T10:00:00Z"),
                                 review("bob", "CHANGES_REQUESTED", at="2026-10-19T11:00:00Z")]
        self.assertEqual(collect.approval_state(PR, approved_then_blocked), "changes requested")
        blocked_then_approved = [review("bob", "CHANGES_REQUESTED", at="2026-10-19T10:00:00Z"),
                                 review("bob", at="2026-10-19T11:00:00Z")]
        self.assertEqual(collect.approval_state(PR, blocked_then_approved), "independent")
        # A comment after an approval does not withdraw it.
        approved_then_comment = [review("bob", at="2026-10-19T10:00:00Z"),
                                 review("bob", "COMMENTED", at="2026-10-19T11:00:00Z")]
        self.assertEqual(collect.approval_state(PR, approved_then_comment), "independent")

    def test_a_dismissed_approval_does_not_count(self):
        self.assertEqual(collect.approval_state(PR, [review("bob", "DISMISSED")]), "none")

    def test_another_reviewers_open_change_request_blocks(self):
        reviews = [review("bob"), review("carol", "CHANGES_REQUESTED")]
        self.assertEqual(collect.approval_state(PR, reviews), "changes requested")


class Checks(unittest.TestCase):
    def test_required_checks_come_from_rulesets_and_classic_protection(self):
        rules = [{"type": "required_status_checks",
                  "parameters": {"required_status_checks": [{"context": "test", "integration_id": 15368}]}}]
        classic = {"required_status_checks": {"contexts": ["lint"]}}
        self.assertEqual(collect.required_contexts(rules, classic), [("test", 15368), ("lint", None)])
        self.assertEqual(collect.required_contexts([], None), [])

    def test_a_required_check_that_passed_before_the_merge(self):
        self.assertEqual(collect.checks_at_merge(PR, [run(), run("skipped", name="docs")], TEST), "passed")

    def test_a_run_that_finished_after_the_merge_did_not_gate_it(self):
        self.assertEqual(collect.checks_at_merge(PR, [run(done="2026-10-19T12:05:00Z")], TEST), "not finished")
        self.assertEqual(collect.checks_at_merge(PR, [run(status="in_progress", conclusion=None, done=None)], TEST),
                         "not finished")

    def test_a_rerun_after_the_merge_does_not_hide_the_pass_before_it(self):
        runs = [run(), run(done="2026-10-19T12:30:00Z")]
        self.assertEqual(collect.checks_at_merge(PR, runs, TEST), "passed")

    def test_a_failure_before_the_merge(self):
        self.assertEqual(collect.checks_at_merge(PR, [run("failure")], TEST), "failed")

    def test_another_check_passing_does_not_stand_in_for_the_required_one(self):
        self.assertEqual(collect.checks_at_merge(PR, [run(name="lint")], TEST), "missing")
        self.assertEqual(collect.checks_at_merge(PR, [], TEST), "missing")

    def test_a_check_with_the_right_name_from_another_app_does_not_count(self):
        self.assertEqual(collect.checks_at_merge(PR, [run(app=999)], [("test", 15368)]), "missing")
        self.assertEqual(collect.checks_at_merge(PR, [run(app=15368)], [("test", 15368)]), "passed")


class PrControls(unittest.TestCase):
    def rows(self, *states):
        return [{"number": i, "approval": s} for i, s in enumerate(states)]

    def test_results(self):
        self.assertEqual(collect.pr_control(self.rows("independent", "independent"), "approval", "independent", True), "pass")
        self.assertEqual(collect.pr_control(self.rows("independent", "stale"), "approval", "independent", True), "fail")
        # A PR whose reviews were cut off, or a PR list that was cut off, can not pass.
        self.assertEqual(collect.pr_control(self.rows("independent", "incomplete"), "approval", "independent", True),
                         "incomplete")
        self.assertEqual(collect.pr_control(self.rows("independent"), "approval", "independent", False), "incomplete")
        # Partial data still proves a failure.
        self.assertEqual(collect.pr_control(self.rows("none", "incomplete"), "approval", "independent", False), "fail")
        # No merged PR in the window shows nothing about the control operating.
        self.assertEqual(collect.pr_control([], "approval", "independent", True), "fail")


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
        self.assertEqual(collect.sla_control(200, alerts, True, NOW, 30)[0], "fail")
        self.assertEqual(collect.sla_control(200, [], True, NOW, 30)[0], "pass")

    def test_the_sla_is_measured_in_time_not_whole_days(self):
        just_late = (NOW - timedelta(days=30, hours=1)).isoformat()
        on_time = (NOW - timedelta(days=30)).isoformat()
        self.assertEqual(len(collect.open_alerts_past_sla([self.alert("high", just_late)], NOW, 30)), 1)
        self.assertEqual(len(collect.open_alerts_past_sla([self.alert("high", on_time)], NOW, 30)), 0)

    def test_alerts_we_could_not_read_never_pass(self):
        for status in (403, 404):
            self.assertEqual(collect.sla_control(status, [], False, NOW, 30)[0], "incomplete")

    def test_a_cut_off_alert_list_or_an_unknown_severity_never_passes(self):
        new = self.alert("high", "2026-10-18T00:00:00Z")
        self.assertEqual(collect.sla_control(200, [new], False, NOW, 30)[0], "incomplete")
        self.assertEqual(collect.sla_control(200, [new, self.alert(None, "2026-10-18T00:00:00Z")], True, NOW, 30)[0],
                         "incomplete")
        # A late alert in a partial list is still a failure.
        old = self.alert("critical", "2026-09-01T00:00:00Z")
        self.assertEqual(collect.sla_control(200, [old], False, NOW, 30)[0], "fail")


class DirectPushes(unittest.TestCase):
    SINCE = NOW - timedelta(days=90)

    def pr(self, number, base="main", merged="2026-10-19T12:00:00Z"):
        return {"number": number, "merged_at": merged, "base": {"ref": base}}

    def activity(self, kind, at="2026-10-18T00:00:00Z"):
        return {"activity_type": kind, "timestamp": at}

    def test_a_commit_counts_only_through_a_merged_pr_into_the_branch_we_evaluated(self):
        self.assertTrue(collect.linked_to_merged_pr([self.pr(3)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(3, base="release")], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(3, merged=None)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([self.pr(4)], "main", {3}))
        self.assertFalse(collect.linked_to_merged_pr([], "main", {3}))

    def test_force_pushes_and_direct_pushes_are_branch_updates_outside_prs(self):
        log = [self.activity("pr_merge"), self.activity("force_push"), self.activity("push"),
               self.activity("push", at="2026-01-01T00:00:00Z")]
        updates = collect.ref_updates_outside_prs(log, self.SINCE)
        self.assertEqual([u["activity_type"] for u in updates], ["force_push", "push"])
        self.assertEqual(collect.direct_push_control([], [{}] * 3, True, updates, True, "main")[0], "fail")

    def test_the_activity_log_must_cover_the_window(self):
        self.assertTrue(collect.activity_covers([self.activity("pr_merge", at="2026-01-01T00:00:00Z")], self.SINCE))
        self.assertTrue(collect.activity_covers([self.activity("branch_creation")], self.SINCE))
        self.assertFalse(collect.activity_covers([self.activity("pr_merge")], self.SINCE))
        self.assertEqual(collect.direct_push_control([], [{}] * 3, True, [], False, "main")[0], "incomplete")

    def test_a_truncated_commit_list_is_incomplete_not_a_pass(self):
        self.assertEqual(collect.direct_push_control([], [{}] * 300, False, [], True, "main")[0], "incomplete")
        self.assertEqual(collect.direct_push_control([], [{}] * 12, True, [], True, "main")[0], "pass")
        self.assertEqual(collect.direct_push_control([{"sha": "a"}], [{}] * 12, True, [], True, "main")[0], "fail")


class Paging(unittest.TestCase):
    """GitHub.follow against canned pages: (status, data, Link header)."""

    def github(self, pages):
        gh = collect.GitHub("token")
        responses = iter(pages)
        gh.request = lambda url: next(responses)
        return gh

    def link(self, n):
        return f'<https://api.github.com/x?page={n}>; rel="next"'

    def test_follows_every_page(self):
        gh = self.github([(200, [1] * 100, self.link(2)), (200, [2] * 5, "")])
        items, complete = gh.follow("/x")
        self.assertEqual((len(items), complete), (105, True))

    def test_a_list_cut_at_the_limit_is_not_complete(self):
        gh = self.github([(200, [1] * 100, self.link(2)), (200, [2] * 100, self.link(3))])
        self.assertEqual(gh.follow("/x", limit=200)[1], False)

    def test_an_error_on_a_later_page_stops_the_run(self):
        gh = self.github([(200, [1] * 100, self.link(2)), (404, b"Not Found", "")])
        with self.assertRaises(SystemExit):
            gh.follow("/x")

    def test_stop_ends_a_sorted_list_early_and_completely(self):
        gh = self.github([(200, [5, 4, 3], self.link(2))])
        self.assertEqual(gh.follow("/x", stop=lambda i: i < 4), ([5, 4, 3], True))


if __name__ == "__main__":
    unittest.main()
