# AI System Security Gate — ISO/IEC 27090 as Policy-as-Code

[![policy](https://github.com/teddy0-0y/iso27090-pac/actions/workflows/policy.yml/badge.svg)](https://github.com/teddy0-0y/iso27090-pac/actions/workflows/policy.yml)
[![self-service](https://github.com/teddy0-0y/iso27090-pac/actions/workflows/action-test.yml/badge.svg)](https://github.com/teddy0-0y/iso27090-pac/actions/workflows/action-test.yml)

Turn the AI-specific security guidance of **ISO/IEC 27090:2026** (*Cybersecurity —
Artificial intelligence — Addressing security threats and compromises to AI systems*)
into automated checks that run in CI.

Two modules, one policy engine (**OPA/Rego** via **Conftest**):

1. **AI system manifests** — teams describe each AI system in a short YAML
   manifest (model source, training data, RAG, endpoint exposure, agent tools,
   logging…), checked against **50 controls**.
2. **AWS Terraform plans** — the actual infrastructure (`terraform show -json`)
   for SageMaker, Bedrock, CloudTrail and IAM, checked against **21 controls**
   before anything is applied.

Every finding cites the ISO/IEC 27090 clause it enforces, and CI blocks merges
that would ship an unsafe configuration.

```
$ conftest test -p policy examples/noncompliant/shadow-chatbot.yaml
FAIL - [AIS-SC-02] Model format 'bin' can execute arbitrary code when loaded; use a safe format such as safetensors (ISO/IEC 27090 B.4.3)
FAIL - [AIS-LLM-02] Untrusted content enters the prompt but is not segregated from instructions (indirect prompt injection) (ISO/IEC 27090 6.9.1, 6.9.4)
FAIL - [AIS-AGT-01] Agent identity is 'inherit_user'; it must use a dedicated identity, not inherit user permissions (ISO/IEC 27090 6.11.3.3)
...
52 tests, 0 passed, 6 warnings, 46 failures, 0 exceptions
```

## Use it in your repo (self-service)

No cloning, no installing OPA or Conftest, no ticket to the security team.

**GitHub Action** — add to any workflow:

```yaml
- uses: actions/checkout@v4
- uses: teddy0-0y/iso27090-pac@v1
  with:
    manifest: ai-system.yaml            # paths or globs
    terraform-plan: infra/plan.json     # optional: terraform show -json output
```

Violations fail the job, appear as annotations on the PR, and are listed in
the run summary with the control ID and ISO/IEC 27090 clause.

| Input | Default | Purpose |
|---|---|---|
| `manifest` | | AI system manifest paths/globs |
| `terraform-plan` | | Terraform plan JSON paths/globs |
| `config` | | Extra Conftest data, e.g. [`config/aws.yaml`](config/aws.yaml) to require a CloudTrail trail |
| `extra-policy` | | Directory of your own Rego rules, run alongside the built-in ones |
| `fail-on-warn` | `false` | Treat warnings as failures |
| `job-summary` | `true` | Write the Markdown report to the run summary |

Outputs: `passed`, `failures`, `warnings`, `waived`. A full workflow that also
plans Terraform with OIDC credentials is in
[`examples/consumer/workflow.yml`](examples/consumer/workflow.yml).

**Pre-commit hook** — catch problems before they are committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/teddy0-0y/iso27090-pac
    rev: v1.0.0
    hooks:
      - id: iso27090-manifest        # any staged YAML with kind: AISystem
      - id: iso27090-terraform-plan  # staged plan*.json / tfplan*.json
```

**Command line** — `bin/iso27090-gate ai-system.yaml --plan plan.json`
(exit code 0 pass, 1 violations, 2 usage error).

How the self-service pieces are hardened:

- **One engine, three entry points.** The Action, the hook and the CLI all run
  `bin/iso27090-gate`, so a developer's laptop and CI give the same verdict.
- **Pinned, verified tooling.** If Conftest is not installed, the gate downloads
  one pinned release and checks it against a SHA-256 hard-coded in the script;
  a mismatch aborts instead of running an unverified binary.
- **Fail closed.** A glob that matches no files fails the check, so a renamed
  manifest can't silently turn the gate into a no-op.
- **No script injection.** Action inputs reach the shell only through
  environment variables, never `${{ }}` interpolation inside `run:`.
- **Tested as consumers use it.** [`action-test.yml`](.github/workflows/action-test.yml)
  runs the Action via `uses: ./` on Linux and macOS and the hooks via
  `pre-commit try-repo` against a throwaway consumer repo.

For production use, pin to a commit SHA instead of `@v1`
(`uses: teddy0-0y/iso27090-pac@<sha>`), the same supply-chain practice the
policies enforce for models.

## Why

AI systems inherit every conventional vulnerability *plus* new ones: data
poisoning, evasion, membership inference, model extraction and inversion,
prompt injection, unsafe model serialization, over-privileged agents. Most of
the defences are configuration decisions that are made once and then forgotten.
Encoding them as policy makes them reviewable, testable, and enforced on every
change.

## What it checks

| Domain | Controls | Examples |
|---|---|---|
| Governance | GOV-00…05 | AI inventory, risk assessment, threat model and red-team recency |
| Supply chain | SC-01…07 | Signed/pinned models, no pickle-based weights, weight scanning, trojan testing |
| Data | DATA-01…10 | Provenance, integrity hashes, PII minimization + DP/de-identification, RAG authz |
| Inference | INF-01…06 | AuthN, per-user throttling, confidence-score exposure, sponge-DoS budgets |
| LLM | LLM-01…06 | Prompt-injection filtering, context segregation, output encoding for XSS/SQLi |
| Agents | AGT-01…07 | Dedicated short-lived identity, scoped tools, human approval, sandboxing |
| Operations | OPS-01…08 | Usage logging fields, continuous validation, env separation, human oversight |

Full catalog with clause references: [`docs/controls.md`](docs/controls.md).

## Module 2: AWS infrastructure (Terraform plans)

The manifest says what a team *claims*; the Terraform plan is what will
actually be *deployed*. The `aws` namespace evaluates the plan before `apply`:

```
$ terraform show -json tfplan > plan.json
$ conftest test -p policy --namespace aws plan.json
FAIL - [AIS-AWS-SM-01] aws_sagemaker_endpoint_configuration.fraud: Endpoint configuration has no kms_key_arn; ... (ISO/IEC 27090 7.6, B.7.4)
FAIL - [AIS-AWS-BR-01] aws_bedrockagent_agent.copilot: Bedrock agent has no guardrail_configuration; ... (ISO/IEC 27090 6.9.4, 6.8.4, 6.11.3.2)
FAIL - [AIS-AWS-CT-02] aws_cloudtrail.ai: Trail has enable_logging = false (ISO/IEC 27090 7.5)
FAIL - [AIS-AWS-IAM-03] aws_iam_role_policy.ml: AI workload role can ["bedrock:deleteguardrail", "cloudtrail:stoplogging"]; ... (ISO/IEC 27090 5.3, 6.11.3.3)
...
25 tests, 0 passed, 11 warnings, 14 failures, 0 exceptions
```

| Area | Controls | Examples |
|---|---|---|
| SageMaker | SM-01…04 | Endpoint and data-capture KMS, network isolation, notebook internet/root access |
| Bedrock | BR-01…05 | Agents bound to guardrails, PROMPT_ATTACK filter strength, PII filters, invocation logging |
| CloudTrail | CT-01…06 | Logging on, multi-region, log-file validation, S3 data events for training data |
| IAM | IAM-00…05 | No `*`/`service:*`, no `iam:PassRole` on `*`, AI roles can't disable logging/guardrails, no FullAccess policies, confused-deputy conditions |

Plan-specific handling:

- **Unknown values.** A KMS key created in the same plan has no ARN until
  apply; the plan marks it in `after_unknown`. Those count as set, so
  correctly-wired resources are not false positives.
- **Workload-aware IAM.** IAM-03 reads each role's trust policy and only applies
  the "can't disable your own monitoring" rule to roles assumable by
  SageMaker or Bedrock.
- **Central trails.** Many organisations run one org-wide CloudTrail, so a
  missing trail is a warning by default; pass
  `--data config/` with `ai27090_config.aws.require_trail_in_plan: true` to enforce.

`examples/terraform/{compliant,noncompliant}/` contain the `.tf` source and the
matching `plan.json`. CI also generates **real** plans from that source with a
mock-credential provider (offline, never applied) and gates them, so the rules
are proven against genuine provider output. Locally: `make plan EX=noncompliant`.

### Design choices

- **Risk-tiered enforcement.** Each control is `deny`, `warn`, or `warn_high`
  (a recommendation that becomes a hard failure when `risk_tier: high`).
  A manifest with no tier is treated as high — fail closed.
- **Context-aware rules.** LLM controls only apply to generative systems; agent
  controls only when an agent is enabled; RAG authorization only when the RAG
  corpus is sensitive; confidence-score exposure is a hard failure only for
  public endpoints over PII-trained models.
- **Time-boxed risk acceptance.** `metadata.exceptions` can waive a control,
  but only with a reason, an approver and a future expiry. Invalid or expired
  exceptions are ignored and flagged (AIS-GOV-05).
- **One aggregation point.** Rule packages emit structured findings
  (`id`, `clause`, `level`, `msg`); `policy/main.rego` resolves them to
  deny/warn/waived and also exposes a JSON `report`.

## Layout

```
policy/
  main.rego              # Conftest entry point: deny / warn / report
  lib/lib.rego           # helpers: tiering, dates, exceptions
  rules/*.rego           # one package per domain
  tests/                 # manifest unit tests
  aws/
    aws.rego             # Conftest entry point for Terraform plans (namespace aws)
    lib.rego             # plan helpers: unknown values, nested blocks
    rules/*.rego         # sagemaker, bedrock, cloudtrail, iam
    tests/               # plan unit tests
examples/
  compliant/             # high-risk RAG+agent copilot; medium-risk fraud model with a waiver
  noncompliant/          # a "shadow AI" chatbot that fails 46 checks
  terraform/             # .tf + plan.json, compliant and non-compliant
  consumer/              # copy-paste workflow and pre-commit config for other teams
bin/iso27090-gate        # shared runner for the Action, the hook and the CLI
action.yml               # reusable GitHub Action
.pre-commit-hooks.yaml   # published pre-commit hooks
docs/controls.md         # control catalog and clause mapping
.github/workflows/       # lint → 136 tests (≥90% coverage) → gate examples → gate real plans
```

## Usage

Requires [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) ≥ 1.0 and
[Conftest](https://www.conftest.dev/install/).

```bash
make lint        # opa fmt + opa check --strict
make test        # 136 unit tests, fails under 90% coverage
make check       # compliant manifests must pass
make check-aws   # compliant Terraform plan must pass
make demo        # see a failing manifest
make demo-aws    # see a failing Terraform plan
make report FILE=examples/compliant/fraud-scoring.yaml        # JSON summary
make report-aws FILE=examples/terraform/noncompliant/plan.json
make plan EX=compliant   # real offline plan (needs terraform)
```

Gate your own repo:

```bash
conftest test -p path/to/policy ai-system.yaml
conftest test -p path/to/policy --namespace aws plan.json
conftest test -p path/to/policy --namespace aws plan.json --output junit > results.xml
```

## Writing a manifest

Start from [`examples/compliant/support-copilot.yaml`](examples/compliant/support-copilot.yaml)
(every field is exercised there). Top-level shape:

```yaml
kind: AISystem
metadata: { name, inventory_id, owner, risk_tier: low|medium|high, exceptions: [...] }
spec:
  type: generative | predictive
  governance:   { risk_assessment, threat_model, red_team }
  supply_chain: { dependency_scanning }
  model:        { source, format, checksum, signature_verified, ... }
  data:         { training: {...}, continuous_learning: {...}, rag: {...} }
  inference:    { exposure, authentication_required, rate_limit, ... }
  llm:          { prompt_injection: {...}, output: {...}, untrusted_content_sources }
  agent:        { enabled, credentials, tools: [{name, action, scopes, requires_human_approval}] }
  operations:   { logging, monitoring, environment, human_oversight, guardrails }
```

## Limitations

A manifest is a *declaration*. These policies verify that the right controls
are claimed and consistently configured, not that they work. Pair the gate with
evidence collection (e.g. checking the declared checksum against the artifact
in the registry) and with the red-team and threat-model activities the standard
recommends. The Terraform module closes part of that gap for AWS by checking
what will really be deployed, but it still cannot see controls that live in
application code (e.g. a guardrail passed on each `InvokeModel` call) or in
other accounts (org trails, SCPs).

## About the standard

This project references ISO/IEC 27090:2026 clause numbers only. It does not
reproduce the standard's text. Obtain the standard from ISO or your national
standards body.
