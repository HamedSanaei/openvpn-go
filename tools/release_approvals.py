"""Bind two GitHub reviewer decisions to the candidate commit and checksum manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


ROLES = ("security", "provenance")
DECISION = re.compile(
    r"openvpn-go (approve|revoke) (security|provenance) ([0-9a-f]{40}) ([0-9a-f]{64})"
)


def check_approvals(environment, comments, reviewers, actor_id, triggering_actor, commit, manifest_hash):
    expected = set(reviewers.values())
    if 0 in expected or len(expected) != len(ROLES) or actor_id in expected:
        raise ValueError("configure two distinct independent reviewer IDs")
    if environment.get("name") != "beta-release" or environment.get("can_admins_bypass") is True:
        raise ValueError("the beta-release environment must be protected")
    for rule in environment.get("protection_rules", []):
        if rule.get("type") == "required_reviewers" and rule.get("prevent_self_review") is True:
            eligible = {item["reviewer"]["id"] for item in rule["reviewers"] if item["type"] == "User"}
            if expected <= eligible:
                break
    else:
        raise ValueError("require both named reviewers in beta-release and prevent self-approval")

    latest = {}
    for comment in comments:
        user = comment.get("user") or {}
        if user.get("id") not in expected or user.get("type") != "User":
            continue
        if user["login"].casefold() == triggering_actor.casefold() or comment["created_at"] != comment["updated_at"]:
            continue
        match = DECISION.fullmatch((comment.get("body") or "").strip())
        if match is None:
            continue
        decision, role, approved_commit, approved_manifest = match.groups()
        if user["id"] != reviewers[role] or (approved_commit, approved_manifest) != (commit, manifest_hash):
            continue
        record = {
            "decision": decision,
            "reviewer_id": user["id"],
            "reviewer": user["login"],
            "comment_id": comment["id"],
            "comment_url": comment["html_url"],
            "created_at": comment["created_at"],
        }
        previous = latest.get(role)
        if previous is None or (record["created_at"], record["comment_id"]) > (previous["created_at"], previous["comment_id"]):
            latest[role] = record

    for role in ROLES:
        if latest.get(role, {}).get("decision") != "approve":
            raise ValueError(f"missing current independent {role} approval for this commit and manifest")
    return {"commit": commit, "sha256sums_sha256": manifest_hash, "approvals": latest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", type=Path)
    parser.add_argument("comments", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        commit = os.environ["GITHUB_SHA"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("expected the full candidate commit")
        ids = {role: int(os.environ.get(f"{role.upper()}_REVIEWER_ID") or 0) for role in ROLES}
        environment = json.loads(args.environment.read_text(encoding="utf-8"))
        pages = json.loads(args.comments.read_text(encoding="utf-8"))
        manifest_hash = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        evidence = check_approvals(environment, (comment for page in pages for comment in page), ids,
                                   int(os.environ["GITHUB_ACTOR_ID"]), os.environ["GITHUB_TRIGGERING_ACTOR"],
                                   commit, manifest_hash)
        print(json.dumps(evidence, indent=2, sort_keys=True))
    except (KeyError, OSError, TypeError, ValueError) as exc:
        sys.exit(f"Release approvals failed: {exc}")


if __name__ == "__main__":
    main()
