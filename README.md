# Cloud IAM Policy Analyzer

A small, dependency-free Python tool that statically reviews cloud IAM policy documents for least-privilege violations. It looks for the same class of issues that show up in cloud security assessments and access reviews: full wildcards, service-wide wildcards, write permissions on `*`, and sensitive actions (privilege escalation, key access, destructive operations) granted more broadly than they should be.

## Why this matters

Over-privileged IAM policies are one of the most common findings in cloud environments, and one of the easiest to catch early, if someone actually reads the policies. In security and IT operations work, reviewing access is recurring: onboarding vendors, auditing service accounts, preparing for compliance reviews. This tool turns that manual read-through into a repeatable check that runs in seconds and drops a Markdown summary into a ticket, a review, or a pull request. It needs nothing beyond Python's standard library, so it runs anywhere Python does.

## What it checks

| Rule | Severity | Meaning |
| --- | --- | --- |
| `full-wildcard-action` | Critical | `Action: "*"` (every action, every service) |
| `service-wildcard-action` | High | `Action: "s3:*"` style service-wide grants |
| `sensitive-action-on-wildcard-resource` | High | A sensitive action (e.g. `iam:PassRole`, `kms:Decrypt`) allowed on `Resource: "*"` |
| `write-action-on-wildcard-resource` | High | Any write/admin action allowed on `Resource: "*"` |
| `sensitive-action` | Medium | A sensitive action allowed, but scoped to specific resources |

The sensitive-action list includes AWS actions plus Azure-style action names (e.g. `Microsoft.Authorization/roleAssignments/write`) to show multi-cloud awareness. `Deny` statements are ignored, and read-only actions on scoped resources are not flagged.

## Repository layout

```
src/analyze_policy.py        # the analyzer (standard library only)
data/policies/               # four sample policies (all fictional)
  overly-broad-admin.json    # full wildcard -> Critical
  app-service-policy.json    # one service wildcard among scoped grants
  data-pipeline-policy.json  # sensitive actions on "*" -> High findings
  readonly-auditor.json      # clean read-only policy -> zero findings
```

## How to run

```bash
python3 src/analyze_policy.py
# optional: --policies <dir>   --out <summary-path>
```

## Sample output (actual run)

```
== app-service-policy.json: 1 finding(s)
   [    High] service-wildcard-action: Statement allows all actions of a service ('dynamodb:*').
== data-pipeline-policy.json: 4 finding(s)
   [    High] sensitive-action-on-wildcard-resource: Sensitive action 'kms:Decrypt' is allowed on resource '*'.
   [    High] sensitive-action-on-wildcard-resource: Sensitive action 'iam:PassRole' is allowed on resource '*'.
   [    High] sensitive-action-on-wildcard-resource: Sensitive action 'Microsoft.Authorization/roleAssignments/write' is allowed on resource '*'.
   [  Medium] sensitive-action: Sensitive action 's3:DeleteBucket' is allowed (resource-scoped).
== overly-broad-admin.json: 1 finding(s)
   [Critical] full-wildcard-action: Statement allows every action in every service ('*').
== readonly-auditor.json: 0 finding(s)

Markdown summary written to: .../cloud-iam-policy-analyzer/summary.md
```

The generated Markdown summary includes a per-policy findings table:

| Policy | Critical | High | Medium | Total |
|---|---|---|---|---|
| app-service-policy.json | 0 | 1 | 0 | 1 |
| data-pipeline-policy.json | 0 | 3 | 1 | 4 |
| overly-broad-admin.json | 1 | 0 | 0 | 1 |
| readonly-auditor.json | 0 | 0 | 0 | 0 |

## Limitations (honest ones)

- **Heuristic, not a solver.** It does not evaluate condition keys, SCPs, permission boundaries, role trust policies, or how policies combine. Real access is the intersection of all of those.
- **Read-only detection is name-based.** Whether an action "writes" is inferred from its name (`Get`/`List`/`Describe` prefixes), which is a good approximation, not a guarantee.
- **One policy format.** Input is AWS-style JSON (`Statement`/`Action`/`Resource`). Azure custom role definitions and GCP IAM bindings use different schemas and are not parsed; the Azure-style names appear in the sensitive list only.
- A finding means "worth a human look," not "definitely wrong." Some wildcard grants are deliberate break-glass design.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.
