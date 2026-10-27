# Control catalog

Each control maps to one or more clauses of ISO/IEC 27090:2026. Descriptions are
written for this project and do not reproduce the standard's text; read the
standard for the authoritative guidance.

**Level**
- `deny` — hard requirement; the check fails.
- `warn` — recommendation; reported but never fails.
- `warn/high` — warning for `low`/`medium` systems, **deny** for `risk_tier: high`
  (and for manifests with no tier, which default to high).

## Governance (clause 5)

| ID | Clause | Level | Check | Why |
|---|---|---|---|---|
| AIS-GOV-00 | 5.1, 6.1 | deny | `kind: AISystem`, valid `spec.type` and `risk_tier` | Schema sanity |
| AIS-GOV-01 | 5.2 | deny | `inventory_id` and `owner` set | AI inventory and accountability |
| AIS-GOV-02 | 5.1, 5.2 | deny | Risk assessment completed | Risk-based control selection |
| AIS-GOV-03 | 5.6 | warn/high | Threat model exists; reviewed ≤ 365 days (staleness = warn) | Surfaces AI-specific attack paths |
| AIS-GOV-04 | 5.7 | warn/high | Red team exercise ≤ 365 days | Adversary emulation |
| AIS-GOV-05 | 5.2 | warn | Exceptions are well-formed and unexpired | Risk-acceptance hygiene |

## Supply chain and model integrity (5.5, 6.7, 6.11.4, B.4)

| ID | Clause | Level | Check | Threat |
|---|---|---|---|---|
| AIS-SC-01 | 5.5.5, B.4.3 | deny | Third-party model has a verified signature or pinned sha256 | Tampered / substituted model |
| AIS-SC-02 | B.4.3 | deny | Weights not in a pickle-based format (`pt`, `bin`, `pkl`…) | Code execution on model load |
| AIS-SC-03 | 5.5.5 | warn/high | Model from a verified repository | Model trojans |
| AIS-SC-04 | 6.11.4 | warn/high | Model provenance documented | Provenance confusion |
| AIS-SC-05 | B.4.2 | warn/high | Third-party weights scanned for malicious code | Backdoors in weight files |
| AIS-SC-06 | 5.5.4, 5.5.5 | warn | AI dependency scanning enabled | Malicious libraries |
| AIS-SC-07 | 5.5.4, 5.5.5 | warn/high | Behavioural validation of pre-trained model | Hidden trigger behaviour |

## Data (6.2, 6.4, 6.11.2, 7.6, B.6)

| ID | Clause | Level | Check | Threat |
|---|---|---|---|---|
| AIS-DATA-01 | 5.3, 6.2.4, 6.11.4 | deny | Every training source has provenance; untrusted sources are sanitized | Data poisoning |
| AIS-DATA-02 | 6.2.3, 6.2.4 | deny | Dataset integrity verification (hashes) | Silent tampering |
| AIS-DATA-03 | 6.2.4, B.6.4 | deny / warn/high | Least privilege (deny); just-in-time access (warn/high) | Poisoning, data leak |
| AIS-DATA-04 | 7.6, B.6.4 | deny | Training data encrypted at rest | Direct training data leak |
| AIS-DATA-05 | 6.4.4, 6.6.4, 6.11.2.2 | deny | PII → minimization **and** (de-identification **or** differential privacy) | Membership inference, model inversion |
| AIS-DATA-06 | 6.11.2.3 | warn | Retention period defined | Data limitation |
| AIS-DATA-07 | 6.2.3 | warn/high | Anomaly / drift detection on training data | Poisoning detection |
| AIS-DATA-08 | 6.2.1, 6.2.3 | deny | Continuous learning validates and anomaly-checks new data | Online poisoning |
| AIS-DATA-09 | 6.2.1, 6.9.4 | deny | RAG sources vetted | RAG poisoning, indirect injection |
| AIS-DATA-10 | 5.3, 7.6, B.7.1 | deny | Sensitive RAG: per-document authorization + encryption | Leakage through retrieval |

## Inference endpoint (5.3, 6.3–6.6, 7.7, 7.8, B.2)

| ID | Clause | Level | Check | Threat |
|---|---|---|---|---|
| AIS-INF-01 | 5.3 | deny | Authentication required | Unauthenticated abuse |
| AIS-INF-02 | 6.5.4, 6.6.4, 7.8 | deny (public) / warn | Per-user rate limit with positive RPM | Extraction, inversion, evasion search |
| AIS-INF-03 | 6.5.4, 6.6.1 | deny / warn | No confidence scores from a public model trained on PII | Model inversion |
| AIS-INF-04 | B.2.3 | warn | Per-query timeout / compute budget | Sponge DoS |
| AIS-INF-05 | 6.3.3, 6.3.4, 7.7 | warn/high | Predictive models: OOD and adversarial input detection | Evasion |
| AIS-INF-06 | 6.4.3, 6.5.3, 7.7.2 | warn/high | Public endpoints: per-caller query-pattern monitoring | Extraction, membership inference |

## Generative AI / LLM (6.8–6.10) — only when `spec.type: generative`

| ID | Clause | Level | Check | Threat |
|---|---|---|---|---|
| AIS-LLM-01 | 6.9.3, 6.9.4 | deny | Input filtering / injection classifier | Direct prompt injection, jailbreak |
| AIS-LLM-02 | 6.9.1, 6.9.4 | deny | Untrusted context (RAG, web, email) is segregated from instructions | Indirect prompt injection |
| AIS-LLM-03 | 6.8.3, 6.8.4 | deny (PII / sensitive RAG) / warn | Output filter for sensitive data | Sensitive model output |
| AIS-LLM-04 | 6.10.4 | deny | Output to browser / SQL / shell is validated and encoded | XSS / injection via output |
| AIS-LLM-05 | 6.9.4 | warn | Hardened system prompt | Injection resistance |
| AIS-LLM-06 | 5.7, 6.9.4 | warn/high | Adversarial prompt test suite before release | Regression of defences |

## Agents (5.3, 6.11.3) — only when `spec.agent.enabled: true`

| ID | Clause | Level | Check | Threat |
|---|---|---|---|---|
| AIS-AGT-01 | 6.11.3.3 | deny | Dedicated agent identity (not inherited from user) | Excessive agency |
| AIS-AGT-02 | 5.3, 6.11.3.3 | deny | Credentials expire ≤ 60 min | Standing privilege |
| AIS-AGT-03 | 6.11.3.3 | deny | Every tool has explicit, non-wildcard scopes | Over-broad permissions |
| AIS-AGT-04 | 6.11.3.2, 6.11.3.3 | deny / warn | Human approval for `external`, `delete`, `execute`, `payment` (warn for `write`) | Injected harmful actions |
| AIS-AGT-05 | 6.11.3.3 | deny | Code-executing / computer-use agents are sandboxed | Host compromise |
| AIS-AGT-06 | 6.11.3.3, 7.5 | deny | Agent action audit log | Non-repudiation, forensics |
| AIS-AGT-07 | 6.11.3.3 | warn/high | Kill switch / privilege restriction on anomaly | Runaway agent |

## Operations (6.11.3, 7.2–7.6)

| ID | Clause | Level | Check | Why |
|---|---|---|---|---|
| AIS-OPS-01 | 7.5 | deny | Usage logging enabled | Incident reconstruction |
| AIS-OPS-02 | 7.5 | warn/high | Logs include input, output, timestamp, user_id, model_version | Same |
| AIS-OPS-03 | 6.11.3.5 | warn/high | Continuous validation against a test set | Detect lasting poisoning effects |
| AIS-OPS-04 | 5.3 | warn/high | Behavioural baseline monitoring | Detect abuse with valid credentials |
| AIS-OPS-05 | 7.6 | deny | Dev / prod separation | Protect development assets |
| AIS-OPS-06 | 7.2, 7.4 | warn | Mitigations regression-tested after retraining | Conflicting / decaying mitigations |
| AIS-OPS-07 | 7.6 | warn | End-of-life disposal procedure | Residual data / model exposure |
| AIS-OPS-08 | 6.11.3.2 | deny (high only) | Human oversight or guardrails | Overreliance |

## AWS Terraform plans (namespace `aws`)

Input: `terraform show -json <planfile>`. Resources being deleted and data
sources are ignored. Attributes that are only known after apply (for example the
ARN of a KMS key created in the same plan) count as **set**: the reference
exists, only its value is pending. Levels here are `deny` or `warn` (no risk tier).

### SageMaker

| ID | Clause | Level | Resource | Check |
|---|---|---|---|---|
| AIS-AWS-SM-01 | 7.6, B.7.4 | deny | `aws_sagemaker_endpoint_configuration` | `kms_key_arn` set |
| AIS-AWS-SM-02 | B.7.1, B.7.4 / 7.5 | deny / warn | `aws_sagemaker_endpoint_configuration` | Data capture encrypted with `kms_key_id` (deny); no data capture at all (warn) |
| AIS-AWS-SM-03 | 5.3, B.4 | warn | `aws_sagemaker_model` | `enable_network_isolation` and `vpc_config` |
| AIS-AWS-SM-04 | 7.6, B.6.4 | deny / warn | `aws_sagemaker_notebook_instance` | `direct_internet_access = "Disabled"` and `kms_key_id` (deny); `root_access = "Disabled"` (warn) |

### Bedrock

| ID | Clause | Level | Resource | Check |
|---|---|---|---|---|
| AIS-AWS-BR-01 | 6.9.4, 6.8.4, 6.11.3.2 | deny | `aws_bedrockagent_agent` | `guardrail_configuration` present |
| AIS-AWS-BR-02 | 6.9.3, 6.9.4 | deny | `aws_bedrock_guardrail` | `PROMPT_ATTACK` filter with input strength MEDIUM or HIGH |
| AIS-AWS-BR-03 | 6.8.3, 6.8.4 | warn | `aws_bedrock_guardrail` | `sensitive_information_policy_config` present |
| AIS-AWS-BR-04 | 7.6, B.6.4 | warn / deny | guardrail, agent, `aws_bedrock_custom_model` | Customer-managed KMS keys (deny for fine-tuned model weights) |
| AIS-AWS-BR-05 | 7.5 | warn / deny | `aws_bedrock_model_invocation_logging_configuration` | Missing from a plan that uses Bedrock (warn); present but text delivery off (deny) |

### CloudTrail

| ID | Clause | Level | Check |
|---|---|---|---|
| AIS-AWS-CT-01 | 7.5 | warn (deny with `require_trail_in_plan`) | Plan with AI resources has a trail, or one is confirmed elsewhere |
| AIS-AWS-CT-02 | 7.5 | deny | `enable_logging` is not `false` |
| AIS-AWS-CT-03 | 7.5 | deny | `is_multi_region_trail = true` (Bedrock cross-region inference) |
| AIS-AWS-CT-04 | 6.11.4, 7.5 | deny | `enable_log_file_validation = true` |
| AIS-AWS-CT-05 | 7.5 | warn | `kms_key_id` set |
| AIS-AWS-CT-06 | 6.2.3, 7.6 | warn | S3 object data events recorded (basic or advanced selectors) |

### IAM

| ID | Clause | Level | Check |
|---|---|---|---|
| AIS-AWS-IAM-00 | 5.3 | warn | Policy JSON is unknown at plan time, so it cannot be evaluated |
| AIS-AWS-IAM-01 | 5.3, 6.11.3.3 | deny | No `Allow` of `*`, `service:*`, or `NotAction` |
| AIS-AWS-IAM-02 | 6.11.3.3 | deny | No `iam:PassRole` on `Resource: "*"` (privilege escalation) |
| AIS-AWS-IAM-03 | 5.3, 6.11.3.3 | deny | Roles trusted by SageMaker/Bedrock cannot stop CloudTrail, delete guardrails, change invocation logging, or disable KMS keys |
| AIS-AWS-IAM-04 | 5.3, 6.11.3.3 | deny | No AdministratorAccess, PowerUserAccess, IAMFullAccess, AmazonSageMakerFullAccess, AmazonBedrockFullAccess, AmazonS3FullAccess |
| AIS-AWS-IAM-05 | 5.3 | warn | AI service trust policies carry `aws:SourceAccount` / `aws:SourceArn` (confused deputy) |

### Known gaps

- A guardrail used with direct `InvokeModel` calls is attached in application
  code, not in Terraform, so only agents (BR-01) are checked for guardrail binding.
- `aws_iam_role_policy` is matched to its role by name. If the role name is
  itself unknown at plan time, IAM-03 cannot attribute the policy to an AI role.
- Org-level trails, SCPs and permission boundaries live outside a workload's
  plan and are not evaluated.

## Not covered (and why)

Some guidance in the standard is not machine-checkable from a declaration file:
choosing robust training algorithms, adversarial training trade-offs, differential
privacy parameter tuning, explainability, and federated-learning design (Annex C).
These belong in the threat model and red-team scope rather than in a gate.
