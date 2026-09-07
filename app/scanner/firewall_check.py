"""Basic sanity checks on /ip firewall filter rules — deliberately not trying
to be a full firewall-policy analyzer. Two checks, both cheap, both high
signal-to-noise:

1. Is there an input-chain drop rule at all, or does the chain just fall
   through to RouterOS's (permissive-by-default-in-older-versions) implicit
   accept?
2. Any rule that accepts any-source/any-port into the input chain — the
   kind of rule that gets added "temporarily" for debugging and never
   removed.
"""


def check_firewall(rules: list[dict]) -> list[dict]:
    findings = []
    input_rules = [r for r in rules if r.get("chain") == "input"]

    has_drop_rule = any(
        r.get("action") == "drop" and r.get("disabled", "false") != "true"
        for r in input_rules
    )
    if not has_drop_rule:
        findings.append({
            "category": "firewall",
            "severity": "high",
            "title": "No active drop rule on the input chain",
            "detail": (
                "The input chain has no enabled 'drop' rule, meaning traffic "
                "not explicitly matched earlier falls through to whatever "
                "RouterOS's default policy is. Add an explicit drop-all rule "
                "at the end of the input chain."
            ),
            "reference": None,
        })

    for r in input_rules:
        if (
            r.get("action") == "accept"
            and r.get("disabled", "false") != "true"
            and not r.get("src-address")
            and not r.get("protocol")
        ):
            findings.append({
                "category": "firewall",
                "severity": "medium",
                "title": "Unrestricted accept rule on input chain",
                "detail": (
                    f"Rule (comment: {r.get('comment', 'none')!r}) accepts "
                    f"input traffic with no source-address or protocol "
                    f"restriction. Confirm this is intentional and scope it "
                    f"down if not."
                ),
                "reference": None,
            })

    return findings
