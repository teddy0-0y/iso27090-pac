# AWS IAM least privilege for AI workloads — ISO/IEC 27090 5.3, 6.11.3.3
package ai27090.aws.rules.iam

import data.ai27090.aws.lib

# ---------------------------------------------------------------------------
# Collect every policy document in the plan
# ---------------------------------------------------------------------------

# {rc, doc} for documents whose JSON is known at plan time
docs contains {"rc": rc, "doc": json.unmarshal(p)} if {
	some rc in lib.any_of_type({"aws_iam_policy", "aws_iam_role_policy"})
	p := lib.attr(rc, "policy", null)
	is_string(p)
}

docs contains {"rc": rc, "doc": json.unmarshal(ip.policy)} if {
	some rc in lib.of_type("aws_iam_role")
	some ip in lib.attr(rc, "inline_policy", [])
	is_string(object.get(ip, "policy", null))
}

allow_statements contains {"rc": d.rc, "stmt": s} if {
	some d in docs
	some s in lib.as_list(d.doc.Statement)
	s.Effect == "Allow"
}

actions(s) := {lower(a) | some a in lib.as_list(object.get(s, "Action", []))}

resources(s) := {r | some r in lib.as_list(object.get(s, "Resource", []))}

# AIS-AWS-IAM-00: policies that can't be evaluated until apply
findings contains lib.finding(rc, "AIS-AWS-IAM-00", "5.3", "warn", "Policy document is computed at apply time and could not be checked; render it with a data source so its content is known at plan time") if {
	some rc in lib.any_of_type({"aws_iam_policy", "aws_iam_role_policy"})
	object.get(lib.after_unknown(rc), "policy", false) == true
}

# AIS-AWS-IAM-01: no full wildcards ("*" or "service:*")
findings contains lib.finding(x.rc, "AIS-AWS-IAM-01", "5.3, 6.11.3.3", "deny", sprintf("Policy allows wildcard action '%v'; grant only the specific actions the workload needs", [a])) if {
	some x in allow_statements
	some a in actions(x.stmt)
	wildcard_action(a)
}

wildcard_action(a) if a == "*"

wildcard_action(a) if endswith(a, ":*")

findings contains lib.finding(x.rc, "AIS-AWS-IAM-01", "5.3, 6.11.3.3", "deny", "Policy uses NotAction with Allow, which grants every action not listed") if {
	some d in docs
	some s in lib.as_list(d.doc.Statement)
	s.Effect == "Allow"
	object.get(s, "NotAction", null) != null
	x := {"rc": d.rc}
}

# AIS-AWS-IAM-02: iam:PassRole on any role enables privilege escalation
findings contains lib.finding(x.rc, "AIS-AWS-IAM-02", "6.11.3.3", "deny", "Policy allows iam:PassRole on Resource '*'; scope it to the specific execution role ARNs") if {
	some x in allow_statements
	"iam:passrole" in actions(x.stmt)
	"*" in resources(x.stmt)
}

# AIS-AWS-IAM-03: AI workload roles cannot disable the controls that watch them
defense_evasion := {
	"cloudtrail:stoplogging",
	"cloudtrail:deletetrail",
	"cloudtrail:updatetrail",
	"cloudtrail:puteventselectors",
	"bedrock:deleteguardrail",
	"bedrock:updateguardrail",
	"bedrock:deletemodelinvocationloggingconfiguration",
	"bedrock:putmodelinvocationloggingconfiguration",
	"kms:scheduledeletion",
	"kms:disablekey",
	"kms:putkeypolicy",
}

findings contains lib.finding(x.rc, "AIS-AWS-IAM-03", "5.3, 6.11.3.3", "deny", sprintf("AI workload role can %v; workloads must not be able to disable logging, guardrails or keys", [sort(hits)])) if {
	some x in allow_statements
	attached_to_ai_role(x.rc)
	hits := actions(x.stmt) & defense_evasion
	count(hits) > 0
}

# ---------------------------------------------------------------------------
# Roles assumed by AI services
# ---------------------------------------------------------------------------

ai_principals := {
	"sagemaker.amazonaws.com",
	"bedrock.amazonaws.com",
}

trust_statements(rc) := [s |
	p := lib.attr(rc, "assume_role_policy", null)
	is_string(p)
	some s in lib.as_list(json.unmarshal(p).Statement)
]

service_principals(s) := {p | some p in lib.as_list(object.get(object.get(s, "Principal", {}), "Service", []))}

ai_role(rc) if {
	some s in trust_statements(rc)
	count(service_principals(s) & ai_principals) > 0
}

ai_role_names := {lib.attr(rc, "name", "") | some rc in lib.of_type("aws_iam_role"); ai_role(rc)}

attached_to_ai_role(rc) if {
	rc.type == "aws_iam_role"
	ai_role(rc)
}

attached_to_ai_role(rc) if {
	rc.type == "aws_iam_role_policy"
	lib.attr(rc, "role", "") in ai_role_names
}

# AIS-AWS-IAM-04: no broad AWS-managed policies on AI roles or anywhere in the plan
broad_managed := {
	"AdministratorAccess",
	"PowerUserAccess",
	"IAMFullAccess",
	"AmazonSageMakerFullAccess",
	"AmazonBedrockFullAccess",
	"AmazonS3FullAccess",
}

policy_name(arn) := name if {
	parts := split(arn, "/")
	name := parts[count(parts) - 1]
}

findings contains lib.finding(rc, "AIS-AWS-IAM-04", "5.3, 6.11.3.3", "deny", sprintf("Role is granted the broad managed policy %v", [policy_name(arn)])) if {
	some rc in lib.of_type("aws_iam_role_policy_attachment")
	arn := lib.attr(rc, "policy_arn", "")
	policy_name(arn) in broad_managed
}

findings contains lib.finding(rc, "AIS-AWS-IAM-04", "5.3, 6.11.3.3", "deny", sprintf("Role is granted the broad managed policy %v", [policy_name(arn)])) if {
	some rc in lib.of_type("aws_iam_role")
	some arn in lib.attr(rc, "managed_policy_arns", [])
	policy_name(arn) in broad_managed
}

# AIS-AWS-IAM-05: service trust is bound to this account (confused-deputy protection)
findings contains lib.finding(rc, "AIS-AWS-IAM-05", "5.3", "warn", "Role trusted by an AI service has no aws:SourceAccount / aws:SourceArn condition (confused-deputy risk)") if {
	some rc in lib.of_type("aws_iam_role")
	some s in trust_statements(rc)
	count(service_principals(s) & ai_principals) > 0
	not source_condition(s)
}

source_condition(s) if {
	some _, kv in object.get(s, "Condition", {})
	some k, _ in kv
	lower(k) in {"aws:sourceaccount", "aws:sourcearn"}
}
