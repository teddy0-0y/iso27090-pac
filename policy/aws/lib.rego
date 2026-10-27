# Helpers for evaluating `terraform show -json <planfile>` output.
#
# Plan JSON shape (format_version 1.x):
#   resource_changes[]: { address, mode, type, name,
#                         change: { actions, before, after, after_unknown } }
# Values computed at apply time (e.g. the ARN of a KMS key created in the same
# plan) are absent from `after` and flagged `true` in `after_unknown`.
# Such values count as "set": the reference exists, only its value is pending.
package ai27090.aws.lib

is_plan if is_array(input.resource_changes)

# Resources that will exist after apply (create, update, replace, no-op).
resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.change.actions != ["delete"]
}

of_type(t) := {rc | some rc in resources; rc.type == t}

any_of_type(types) := {rc | some rc in resources; rc.type in types}

after(rc) := object.get(rc.change, "after", {})

after_unknown(rc) := object.get(rc.change, "after_unknown", {})

attr(rc, name, default_value) := object.get(after(rc), name, default_value)

empty_values := {null, "", [], {}}

# Attribute has a known, non-empty value, or will be computed at apply time.
present(rc, name) if not object.get(after(rc), name, null) in empty_values

present(rc, name) if object.get(after_unknown(rc), name, false) == true

# Nested single blocks are lists of 0 or 1 objects in plan JSON.
block(rc, name) := b if {
	some b in attr(rc, name, [])
} else := {}

has_block(rc, name) if count(attr(rc, name, [])) > 0

has_block(rc, name) if object.get(after_unknown(rc), name, false) == true

# Normalise IAM JSON fields that may be a string or a list.
as_list(x) := x if is_array(x)

else := [x]

# Config (override with:  conftest test --data config/aws.yaml ...)
#   ai27090_config:
#     aws:
#       require_trail_in_plan: true
config := c if {
	c := data.ai27090_config.aws
} else := {}

finding(rc, id, clause, level, msg) := {
	"id": id,
	"clause": clause,
	"level": level,
	"msg": msg,
	"address": rc.address,
}

plan_finding(id, clause, level, msg) := {
	"id": id,
	"clause": clause,
	"level": level,
	"msg": msg,
	"address": "(plan)",
}

# Resource types that indicate AI workloads in this plan
ai_types := {
	"aws_sagemaker_endpoint",
	"aws_sagemaker_endpoint_configuration",
	"aws_sagemaker_model",
	"aws_sagemaker_notebook_instance",
	"aws_sagemaker_domain",
	"aws_bedrockagent_agent",
	"aws_bedrockagent_knowledge_base",
	"aws_bedrock_guardrail",
	"aws_bedrock_custom_model",
	"aws_bedrock_provisioned_model_throughput",
}

has_ai_workload if count(any_of_type(ai_types)) > 0
