import copy
import unittest

from release_approvals import check_approvals


COMMIT = "a" * 40
MANIFEST = "b" * 64
REVIEWERS = {"security": 101, "provenance": 102}
PROTECTED = {
    "name": "beta-release",
    "protection_rules": [{
        "type": "required_reviewers",
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "reviewer": {"id": user_id}} for user_id in REVIEWERS.values()],
    }],
}


def comment(role, sequence=1, decision="approve", commit=COMMIT, manifest=MANIFEST):
    date = f"2026-11-26T10:00:{sequence:02d}Z"
    return {
        "id": sequence,
        "body": f"openvpn-go {decision} {role} {commit} {manifest}",
        "user": {"type": "User", "login": f"{role}-reviewer", "id": REVIEWERS[role]},
        "created_at": date,
        "updated_at": date,
        "html_url": f"https://example.test/issue#comment-{sequence}",
    }


class ReleaseApprovalTest(unittest.TestCase):
    def verify(self, comments, environment=PROTECTED, actor_id=7, actor="release-operator"):
        return check_approvals(environment, comments, REVIEWERS, actor_id, actor, COMMIT, MANIFEST)

    def test_both_approvals_bind_candidate(self):
        evidence = self.verify([comment("security"), comment("provenance", 2)])
        self.assertEqual(evidence["commit"], COMMIT)
        self.assertEqual(evidence["sha256sums_sha256"], MANIFEST)
        self.assertEqual(evidence["approvals"]["provenance"]["reviewer_id"], REVIEWERS["provenance"])

    def test_missing_stale_or_revoked_approval(self):
        security = comment("security")
        for comments in (
            [security],
            [security, comment("provenance", 2, commit="c" * 40)],
            [security, comment("provenance", 2, manifest="d" * 64)],
            [comment("provenance", 3, "revoke"), security, comment("provenance", 2)],
        ):
            with self.subTest(comments=comments), self.assertRaisesRegex(ValueError, "missing current"):
                self.verify(comments)

    def test_wrong_reviewer_edited_comment_or_self_approval(self):
        security, provenance = comment("security"), comment("provenance", 2)
        wrong = {**security, "user": provenance["user"]}
        edited = {**security, "updated_at": provenance["created_at"]}
        for altered in (wrong, edited):
            with self.subTest(comment=altered), self.assertRaisesRegex(ValueError, "missing current"):
                self.verify([altered, provenance])
        with self.assertRaisesRegex(ValueError, "independent reviewer IDs"):
            self.verify([security, provenance], actor_id=REVIEWERS["security"])
        with self.assertRaisesRegex(ValueError, "missing current"):
            self.verify([security, provenance], actor="security-reviewer")

    def test_unprotected_environment(self):
        security, provenance = comment("security"), comment("provenance", 2)
        self.assertTrue(self.verify([security, provenance]))
        disabled = copy.deepcopy(PROTECTED)
        disabled["protection_rules"][0]["prevent_self_review"] = False
        for environment in ({}, {"name": "beta-release"}, disabled, {**PROTECTED, "can_admins_bypass": True}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.verify([security, provenance], environment=environment)


if __name__ == "__main__":
    unittest.main()
