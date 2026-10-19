import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import collect  # noqa: E402

PR = {"merged_at": "2026-10-19T12:00:00Z", "user": {"login": "alice"}}


def review(login, state="APPROVED", at="2026-10-19T11:00:00Z"):
    return {"user": {"login": login}, "state": state, "submitted_at": at}


def run(conclusion="success", status="completed", done="2026-10-19T11:30:00Z"):
    return {"status": status, "conclusion": conclusion, "completed_at": done}


class IndependentApproval(unittest.TestCase):
    def test_approval_by_someone_else_before_merge_counts(self):
        self.assertTrue(collect.independent_approval(PR, [review("bob")]))

    def test_the_authors_own_approval_does_not_count(self):
        self.assertFalse(collect.independent_approval(PR, [review("alice")]))

    def test_an_approval_after_the_merge_does_not_count(self):
        self.assertFalse(collect.independent_approval(PR, [review("bob", at="2026-10-19T13:00:00Z")]))

    def test_comments_and_change_requests_do_not_count(self):
        self.assertFalse(
            collect.independent_approval(PR, [review("bob", "COMMENTED"), review("carol", "CHANGES_REQUESTED")])
        )


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
        now = datetime(2026, 10, 19, tzinfo=timezone.utc)
        alerts = [
            self.alert("critical", "2026-09-01T00:00:00Z"),
            self.alert("high", "2026-10-10T00:00:00Z"),
            self.alert("medium", "2026-01-01T00:00:00Z"),
        ]
        late = collect.open_alerts_past_sla(alerts, now, 30)
        self.assertEqual([a["severity"] for a in late], ["critical"])


if __name__ == "__main__":
    unittest.main()
