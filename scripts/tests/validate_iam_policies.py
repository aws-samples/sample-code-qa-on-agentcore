#!/usr/bin/env python3
"""Validate that every IAM policy document embedded in the deploy scripts is legal.

Catches two mistakes that only surface as a MalformedPolicyDocument at deploy time, long
after the phases that cost real minutes:
  - invalid JSON after shell expansion
  - keys IAM does not accept inside a Statement (a "_comment" key is rejected outright)

Run: python3 scripts/tests/validate_iam_policies.py
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ACCOUNT = "111122223333"
REGION = "us-east-1"
ROLE = "source-truth-index-role"

LEGAL_KEYS = {
    "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource",
    "Condition", "Principal", "NotPrincipal",
}

REPO = pathlib.Path(__file__).resolve().parents[2]

# Every shell file that embeds an IAM document. apply-dau-lambda.sh was MISSING from this list
# while carrying a real put-role-policy with the same hand-escaped construction — the validator
# had the exact blind spot it exists to catch. discover_policy_files() below fails the run if a
# file with a policy document is not listed here, so the next one cannot be missed either.
FILES = [
    "scripts/lib/create-iam.sh",
    "scripts/lib/provision_iam.sh",
    "scripts/lib/apply-dau-lambda.sh",
    # 可观测性 stage 里的 X-Ray → CloudWatch Logs 资源策略。它被 discover_policy_files()
    # 直接抓到并要求登记——守卫按设计生效了一次。
    "scripts/lib/apply-observability.sh",
    # 评估器 Lambda 的执行角色信任策略。同上，也是被 discover_policy_files() 抓出来才补登记的，
    # 说明这条「未登记即视为未审」的守卫是有效的，而不是装饰。
    "scripts/apply-evaluations.sh",
    # VPC endpoint 策略（AppSec finding 6ee01ebb）。三个 endpoint 原先继承 AWS 默认的
    # {"Principal":"*","Action":"*","Resource":"*"}，现在改为按 aws:PrincipalAccount 收敛到
    # 部署账号。同样是被 discover_policy_files() 抓出来才补登记的——守卫第三次生效。
    "scripts/lib/provision_network.sh",
]

# Inline policies AND trust policies. Trust policies were invisible before: a malformed one fails
# create-role on a fresh account just as late and as expensively, and a valid-but-wrong Principal
# is a cross-account trust bug worth surfacing.
DOC_RE = re.compile(
    # Three shapes:
    #   --policy-name <n> --policy-document '<json>' >     inline identity policy
    #   --assume-role-policy-document '<json>' >           trust policy
    #   --policy-document '<json>' >                       RESOURCE policy (VPC endpoint)
    # The third has no --policy-name to key off, so it is captured by its own group and audited by
    # check_endpoint_policy() rather than by the identity-policy rules — a VPC endpoint policy is a
    # different object with different legal shape (it carries Principal, and Action/Resource "*"
    # narrowed by a Condition is the CORRECT form there, whereas in an identity policy it is the
    # thing this file exists to reject). Added for AppSec finding 6ee01ebb.
    r"--(?:policy-name (\S+) --policy-document|(assume-role-policy-document)|(policy-document)) ('.*?'|\".*?\")\s*>",
    re.S,
)

# Variables deliberately left symbolic inside a JSON string. Anything else surviving expansion
# means the validator checked a document that is not what deploys.
ALLOWED_UNEXPANDED: set[str] = set()


def expand(raw: str) -> str:
    """Approximate the shell expansion these documents undergo."""
    raw = raw[1:-1]  # strip the outer quote
    raw = raw.replace("'\"${ACCOUNT}\"'", ACCOUNT)
    for name, value in (
        ("ACCOUNT", ACCOUNT),
        ("REGION", REGION),
        ("ROLE", ROLE),
        ("INDEX_ROLE", ROLE),
        ("RUNTIME_ROLE", "SourceTruthAgentRuntimeRole"),
        ("BUCKET", "source-truth-repo-111122223333-useast1"),
        ("LG_ARN", f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/source-truth/bot-gateway:*"),
    ):
        raw = raw.replace("${" + name + "}", value).replace("$" + name, value)
    raw = raw.replace('\\"', '"')
    return raw


def discover_policy_files() -> list[str]:
    """Every file under scripts/ that embeds an IAM document, so FILES cannot fall behind.

    scripts/tests/ is EXCLUDED. A test that asserts something about a policy necessarily quotes
    the flag name and fragments of the document, but it embeds nothing that ever deploys, so
    listing it here would demand a `present == matched` accounting for strings that are assertions
    rather than policies. Same blind spot the `code`-only counting below already documents for
    comments: this guard matches text, and cannot tell a policy from prose *about* a policy.
    Consequence to be aware of: a real document hidden under scripts/tests/ would go unaudited —
    acceptable only because nothing in that directory is deployed.
    """
    found = []
    for path in sorted(REPO.glob("scripts/**/*.sh")):
        if "scripts/tests/" in path.as_posix():
            continue
        text = path.read_text(errors="ignore")
        if "--policy-document" in text or "--assume-role-policy-document" in text:
            found.append(str(path.relative_to(REPO)))
    return found


def check_trust_policy(where: str, parsed: dict) -> int:
    """A trust policy must name a service principal and must not trust the world."""
    failures = 0
    for i, st in enumerate(parsed.get("Statement", [])):
        principal = st.get("Principal")
        if not isinstance(principal, dict) or not principal.get("Service"):
            print(f"  FAIL {where}[{i}]: trust policy without a Principal.Service")
            failures += 1
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            print(f"  FAIL {where}[{i}]: trust policy allows Principal AWS '*'")
            failures += 1
        actions = st.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if "sts:AssumeRole" not in actions and "sts:AssumeRoleWithWebIdentity" not in actions:
            print(f"  FAIL {where}[{i}]: trust policy Action is not an AssumeRole verb: {actions}")
            failures += 1
    return failures


def check_endpoint_policy(where: str, parsed: dict) -> int:
    """A VPC endpoint policy must not be the fully-open default (AppSec finding 6ee01ebb).

    Audited separately from identity policies because the legal shape differs: an endpoint policy
    carries `Principal`, and `Action`/`Resource` of "*" is normal there — what makes it safe or not
    is whether a Condition genuinely narrows WHO the endpoint will serve. The AWS default document
    is exactly {"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"} with no Condition,
    which lets any principal that can route to the endpoint reach any registry/bucket its IAM
    permits.

    OPERATOR AND VALUE ARE CHECKED, not just the key name. A first version tested only that a
    restricting key was PRESENT, and therefore passed this, which restricts nothing at all:
        {"Condition": {"StringLike": {"aws:PrincipalAccount": "*"}}}
    It also passed a malformed `[["111122223333"]]`. A guard that accepts a wildcard as a
    restriction is worse than no guard, because it certifies the thing it was written to catch.

    This turns the finding's fix into a standing assertion: an unconditioned — or cosmetically
    conditioned — Allow here fails the build, so the scoping cannot be silently dropped by a
    later edit.
    """
    # Equality-style operators only. StringLike admits wildcards; Not*/*IfExists invert or
    # weaken the test; ArnLike etc. are not meaningful for these keys.
    ALLOWED_OPS = {"StringEquals", "ArnEquals", "StringEqualsIgnoreCase", "NumericEquals"}
    RESTRICTING_KEYS = (
        "aws:principalaccount", "aws:principalorgid", "aws:principalarn",
        "aws:sourcevpc", "aws:sourcevpce", "s3:resourceaccount",
    )

    def restricts(cond: object) -> bool:
        if not isinstance(cond, dict) or not cond:
            return False
        for op, block in cond.items():
            if op not in ALLOWED_OPS or not isinstance(block, dict):
                continue
            for key, val in block.items():
                if key.lower() not in RESTRICTING_KEYS:
                    continue
                # Accept a non-empty scalar, or a non-empty list of non-empty scalars. Reject
                # any wildcard, and reject nested/other shapes rather than guessing.
                vals = val if isinstance(val, list) else [val]
                if not vals:
                    continue
                if all(isinstance(v, str) and v.strip() and "*" not in v and "?" not in v
                       for v in vals):
                    return True
        return False

    failures = 0
    statements = parsed.get("Statement")
    if not isinstance(statements, list):
        # main() already rejects a non-list Statement before reaching here, so this is not a
        # reachable defect — but a guard's helper should fail CLOSED on malformed input rather
        # than raise AttributeError and depend on its caller having validated first.
        print(f"  FAIL {where}: Statement must be a list to be audited (got "
              f"{type(statements).__name__})")
        return 1
    for i, st in enumerate(statements):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if not restricts(st.get("Condition")):
            print(f"  FAIL {where}[{i}]: endpoint policy Allow is not restricted by a caller/"
                  f"resource-owner condition using an equality operator and a concrete value "
                  f"(got Condition={st.get('Condition')!r}) — this is effectively the fully-open "
                  f"AWS default")
            failures += 1
    return failures


def main() -> int:
    failures = 0
    checked = 0

    # A file carrying an IAM document but absent from FILES would be validated by nothing.
    missing = [f for f in discover_policy_files() if f not in FILES]
    if missing:
        for f in missing:
            print(f"  FAIL {f}: embeds an IAM document but is not listed in FILES")
        failures += len(missing)

    for rel in FILES:
        src = (REPO / rel).read_text()
        # COVERAGE ASSERTION. DOC_RE ends with `\s*>`, so any --policy-document whose command does
        # not end in a redirect is silently skipped — `checked` does not even move. A review proved
        # this by appending a full account-escalation chain (iam:PassRole on Resource "*") with no
        # redirect: the validator printed "OK (19 documents)" and the document was never examined.
        # discover_policy_files() only guards against a FILE going unlisted; nothing guarded against
        # a DOCUMENT going unmatched inside a listed file, and the printed count was the only signal
        # while nobody knew what the denominator should be.
        # The anchor cannot simply be dropped: it is also what stops a double-quoted document being
        # truncated at its first \" by the non-greedy `".*?"`. So instead, count the documents that
        # are PRESENT independently and require the parser to have matched all of them.
        #
        # Count over CODE only. The first version counted raw text, so a comment that merely NAMED
        # `--policy-document` — for instance one explaining this very convention to the next author —
        # inflated the denominator and failed the file for a document that does not exist. Same blind
        # spot as any text-matching guard: it cannot tell code from prose about code.
        code = "\n".join(
            ln for ln in src.splitlines() if not ln.lstrip().startswith("#")
        )
        # BOTH SIDES MUST SEE THE SAME INPUT. `present` was counted over comment-stripped code
        # while `matched` scanned the RAW source, so a document mentioned in a COMMENT could
        # supply the match that balanced a real, unvalidated document in the code:
        #   aws iam put-role-policy --policy-document "$DANGEROUS_POLICY"   # variable → unmatched
        #   # decoy --policy-document '{…}' >                               # comment → matched
        # present=1, matched=1, exit 0, "OK (1 documents)" — with the dangerous document never
        # examined. Counting and matching over the same comment-stripped text removes the trick.
        present = len(re.findall(r"--policy-document|--assume-role-policy-document", code))
        docs = DOC_RE.findall(code)
        matched = len(docs)
        if matched != present:
            print(
                f"  FAIL {rel}: {present} policy document(s) present but the parser matched "
                f"{matched} — an unmatched document is NOT validated. Every "
                f"--policy-document command must end in a redirect (e.g. `>/dev/null`) so the "
                f"parser can find its boundary, or DOC_RE must be taught the new shape."
            )
            # abs(): when matched EXCEEDS present the old `present - matched` added a NEGATIVE
            # number, which could cancel a genuine failure counted elsewhere and turn a failing
            # run into exit 0. A mismatch in either direction is one problem, never a credit.
            failures += abs(present - matched)
        for name, is_trust, is_resource, doc in docs:
            label = name or ("assume-role-policy" if is_trust else "endpoint-policy")
            checked += 1
            expanded = expand(doc)

            # An unexpanded variable means we parsed something other than what deploys.
            leftover = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", expanded)) - ALLOWED_UNEXPANDED
            if leftover:
                print(f"  FAIL {rel} :: {label}: unexpanded variable(s) {sorted(leftover)} — extend expand()")
                failures += 1

            try:
                parsed = json.loads(expanded)
            except json.JSONDecodeError as exc:
                print(f"  FAIL {rel} :: {label}: invalid JSON — {exc}")
                failures += 1
                continue

            statements = parsed.get("Statement")
            if not isinstance(statements, list) or not statements:
                print(f"  FAIL {rel} :: {label}: Statement must be a non-empty list")
                failures += 1
                continue

            if is_trust:
                failures += check_trust_policy(f"{rel} :: {label}", parsed)
                continue

            if is_resource:
                # A resource policy, not an identity policy: audited by its own rules. The
                # identity-policy checks below (LEGAL_KEYS, the PassRole/AttachRolePolicy
                # escalation guards) would misfire here — `Principal` is legal in a resource
                # policy and is not in LEGAL_KEYS, and `Action`/`Resource` "*" narrowed by a
                # Condition is the correct shape rather than an escalation.
                failures += check_endpoint_policy(f"{rel} :: {label}", parsed)
                continue

            for i, st in enumerate(statements):
                illegal = sorted(set(st) - LEGAL_KEYS)
                if illegal:
                    print(f"  FAIL {rel} :: {label}[{i}]: illegal statement keys {illegal}")
                    failures += 1
                if "Effect" not in st or "Action" not in st:
                    print(f"  FAIL {rel} :: {label}[{i}]: missing Effect or Action")
                    failures += 1

            # Privilege-escalation guards. iam:PassRole on "*" next to lambda:CreateFunction is a
            # full account escalation chain; an unconditioned iam:AttachRolePolicy scoped to a
            # pattern that includes the role itself is self-escalation to admin.
            for i, st in enumerate(statements):
                actions = st.get("Action")
                actions = actions if isinstance(actions, list) else [actions]
                actions = [a for a in actions if isinstance(a, str)]
                resources = st.get("Resource")
                resources = resources if isinstance(resources, list) else [resources]

                if any(a == "iam:PassRole" for a in actions):
                    if "*" in resources:
                        print(f"  FAIL {rel} :: {label}[{i}]: iam:PassRole on Resource '*'")
                        failures += 1
                    if not st.get("Condition"):
                        print(f"  FAIL {rel} :: {label}[{i}]: iam:PassRole without a Condition")
                        failures += 1

                if any(a == "iam:AttachRolePolicy" for a in actions):
                    cond = json.dumps(st.get("Condition") or {})
                    if "iam:PolicyARN" not in cond:
                        print(f"  FAIL {rel} :: {label}[{i}]: iam:AttachRolePolicy without an iam:PolicyARN condition")
                        failures += 1

                if any(a == "iam:CreateServiceLinkedRole" for a in actions):
                    cond = json.dumps(st.get("Condition") or {})
                    if "iam:AWSServiceName" not in cond:
                        print(f"  FAIL {rel} :: {label}[{i}]: iam:CreateServiceLinkedRole without an iam:AWSServiceName condition")
                        failures += 1

    if failures:
        print(f"iam-policies: {failures} problem(s) across {checked} document(s)")
        return 1
    print(f"iam-policies: OK ({checked} documents)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
