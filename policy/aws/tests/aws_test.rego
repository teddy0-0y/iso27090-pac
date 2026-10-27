package ai27090.aws.tests

# ---------------------------------------------------------------------------
# Helpers: build minimal plan JSON documents
# ---------------------------------------------------------------------------

res(t, after) := res_u(t, after, {})

res_u(t, after, unknown) := {
	"address": sprintf("%s.test", [t]),
	"mode": "managed",
	"type": t,
	"name": "test",
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}

plan(resources) := {"format_version": "1.2", "resource_changes": resources}

findings(p) := r if {
	r := data.aws.all_findings with input as p
}

ids(p, level) := {f.id | some f in findings(p); f.level == level}

denied(p) := ids(p, "deny")

warned(p) := ids(p, "warn")

# A trail that satisfies every CloudTrail control (used to silence CT-01)
good_trail := res("aws_cloudtrail", {
	"enable_logging": true,
	"is_multi_region_trail": true,
	"enable_log_file_validation": true,
	"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
	"event_selector": [{"data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3:::b/"]}]}],
})

with_trail(r) := plan([good_trail, r])

doc(stmts) := json.marshal({"Version": "2012-10-17", "Statement": stmts})

# ---------------------------------------------------------------------------
# Plan handling
# ---------------------------------------------------------------------------

test_non_plan_input_rejected if {
	msgs := data.aws.deny with input as {"kind": "AISystem"}
	some m in msgs
	contains(m, "not a Terraform plan")
}

test_empty_plan_has_no_findings if count(findings(plan([]))) == 0

test_deleted_resources_ignored if {
	r := object.union(res("aws_sagemaker_endpoint_configuration", {}), {"change": {"actions": ["delete"], "after": null}})
	count(findings(plan([r]))) == 0
}

test_data_sources_ignored if {
	r := object.union(res("aws_sagemaker_endpoint_configuration", {}), {"mode": "data"})
	count(findings(plan([r]))) == 0
}

# ---------------------------------------------------------------------------
# SageMaker
# ---------------------------------------------------------------------------

test_sm01_missing_kms if "AIS-AWS-SM-01" in denied(with_trail(res("aws_sagemaker_endpoint_configuration", {"kms_key_arn": null})))

test_sm01_known_kms_ok if not "AIS-AWS-SM-01" in denied(with_trail(res("aws_sagemaker_endpoint_configuration", {"kms_key_arn": "arn:aws:kms:x"})))

test_sm01_unknown_kms_counts_as_set if {
	r := res_u("aws_sagemaker_endpoint_configuration", {}, {"kms_key_arn": true})
	not "AIS-AWS-SM-01" in denied(with_trail(r))
}

test_sm02_capture_without_kms if {
	r := res("aws_sagemaker_endpoint_configuration", {
		"kms_key_arn": "k",
		"data_capture_config": [{"enable_capture": true, "kms_key_id": null}],
	})
	"AIS-AWS-SM-02" in denied(with_trail(r))
}

test_sm02_capture_with_unknown_kms_ok if {
	r := res_u(
		"aws_sagemaker_endpoint_configuration",
		{"kms_key_arn": "k", "data_capture_config": [{"enable_capture": true}]},
		{"data_capture_config": [{"kms_key_id": true}]},
	)
	not "AIS-AWS-SM-02" in denied(with_trail(r))
}

test_sm02_no_capture_warns if "AIS-AWS-SM-02" in warned(with_trail(res("aws_sagemaker_endpoint_configuration", {"kms_key_arn": "k"})))

test_sm03_no_isolation_warns if "AIS-AWS-SM-03" in warned(with_trail(res("aws_sagemaker_model", {"vpc_config": [{"subnets": ["s"]}]})))

test_sm03_isolated_in_vpc_ok if {
	r := res("aws_sagemaker_model", {"enable_network_isolation": true, "vpc_config": [{"subnets": ["s"]}]})
	not "AIS-AWS-SM-03" in warned(with_trail(r))
}

test_sm04_notebook_defaults if {
	p := with_trail(res("aws_sagemaker_notebook_instance", {}))
	"AIS-AWS-SM-04" in denied(p)
	"AIS-AWS-SM-04" in warned(p)
}

test_sm04_locked_down_notebook_ok if {
	r := res_u("aws_sagemaker_notebook_instance", {"direct_internet_access": "Disabled", "root_access": "Disabled"}, {"kms_key_id": true})
	count(findings(with_trail(r))) == 0
}

# ---------------------------------------------------------------------------
# Bedrock
# ---------------------------------------------------------------------------

good_guardrail := res("aws_bedrock_guardrail", {
	"kms_key_arn": "k",
	"content_policy_config": [{"filters_config": [{"type": "PROMPT_ATTACK", "input_strength": "HIGH", "output_strength": "NONE"}]}],
	"sensitive_information_policy_config": [{"pii_entities_config": [{"type": "EMAIL", "action": "ANONYMIZE"}]}],
})

logging_on := res("aws_bedrock_model_invocation_logging_configuration", {"logging_config": [{"text_data_delivery_enabled": true}]})

test_br01_agent_without_guardrail if {
	p := plan([good_trail, logging_on, res("aws_bedrockagent_agent", {"guardrail_configuration": [], "customer_encryption_key_arn": "k"})])
	"AIS-AWS-BR-01" in denied(p)
}

test_br01_agent_with_unknown_guardrail_id_ok if {
	a := res_u(
		"aws_bedrockagent_agent",
		{"guardrail_configuration": [{"guardrail_version": "DRAFT"}], "customer_encryption_key_arn": "k"},
		{"guardrail_configuration": [{"guardrail_identifier": true}]},
	)
	count(findings(plan([good_trail, logging_on, a]))) == 0
}

test_br02_good_guardrail_passes if count(findings(plan([good_trail, logging_on, good_guardrail]))) == 0

test_br02_low_strength if {
	g := json.patch(good_guardrail, [{"op": "replace", "path": "/change/after/content_policy_config/0/filters_config/0/input_strength", "value": "LOW"}])
	"AIS-AWS-BR-02" in denied(plan([good_trail, logging_on, g]))
}

test_br02_no_prompt_attack_filter if {
	g := json.patch(good_guardrail, [{"op": "replace", "path": "/change/after/content_policy_config", "value": []}])
	"AIS-AWS-BR-02" in denied(plan([good_trail, logging_on, g]))
}

test_br03_no_pii_filter if {
	g := json.patch(good_guardrail, [{"op": "replace", "path": "/change/after/sensitive_information_policy_config", "value": []}])
	"AIS-AWS-BR-03" in warned(plan([good_trail, logging_on, g]))
}

test_br04_custom_model_without_cmk if "AIS-AWS-BR-04" in denied(plan([good_trail, logging_on, res("aws_bedrock_custom_model", {})]))

test_br05_no_invocation_logging_warns if "AIS-AWS-BR-05" in warned(plan([good_trail, good_guardrail]))

test_br05_text_logging_disabled if {
	l := res("aws_bedrock_model_invocation_logging_configuration", {"logging_config": [{"text_data_delivery_enabled": false}]})
	"AIS-AWS-BR-05" in denied(plan([good_trail, good_guardrail, l]))
}

# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

ai_resource := res("aws_sagemaker_model", {"enable_network_isolation": true, "vpc_config": [{"subnets": ["s"]}]})

test_ct01_missing_trail_warns_by_default if {
	p := plan([ai_resource])
	"AIS-AWS-CT-01" in warned(p)
	not "AIS-AWS-CT-01" in denied(p)
}

test_ct01_missing_trail_denied_when_required if {
	r := data.aws.all_findings with input as plan([ai_resource]) with data.ai27090_config.aws as {"require_trail_in_plan": true}
	some f in r
	f.id == "AIS-AWS-CT-01"
	f.level == "deny"
}

test_ct01_no_ai_resources_no_finding if not "AIS-AWS-CT-01" in warned(plan([res("aws_s3_bucket", {})]))

test_ct_good_trail_passes if count(findings(plan([ai_resource, good_trail]))) == 0

test_ct02_logging_disabled if {
	t := json.patch(good_trail, [{"op": "replace", "path": "/change/after/enable_logging", "value": false}])
	"AIS-AWS-CT-02" in denied(plan([t]))
}

test_ct03_single_region if {
	t := json.patch(good_trail, [{"op": "remove", "path": "/change/after/is_multi_region_trail"}])
	"AIS-AWS-CT-03" in denied(plan([t]))
}

test_ct04_no_validation if {
	t := json.patch(good_trail, [{"op": "replace", "path": "/change/after/enable_log_file_validation", "value": false}])
	"AIS-AWS-CT-04" in denied(plan([t]))
}

test_ct05_no_kms if {
	t := json.patch(good_trail, [{"op": "remove", "path": "/change/after/kms_key_id"}])
	"AIS-AWS-CT-05" in warned(plan([t]))
}

test_ct06_no_s3_data_events if {
	t := json.patch(good_trail, [{"op": "replace", "path": "/change/after/event_selector", "value": []}])
	"AIS-AWS-CT-06" in warned(plan([ai_resource, t]))
}

test_ct06_advanced_selector_ok if {
	t := json.patch(good_trail, [
		{"op": "replace", "path": "/change/after/event_selector", "value": []},
		{"op": "add", "path": "/change/after/advanced_event_selector", "value": [{"field_selector": [
			{"field": "eventCategory", "equals": ["Data"]},
			{"field": "resources.type", "equals": ["AWS::S3::Object"]},
		]}]},
	])
	not "AIS-AWS-CT-06" in warned(plan([ai_resource, t]))
}

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

sm_trust(with_condition) := doc([object.union(
	{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"},
	cond(with_condition),
)])

cond(true) := {"Condition": {"StringEquals": {"aws:SourceAccount": "111122223333"}}}

cond(false) := {}

ai_role := res("aws_iam_role", {"name": "ml-exec", "assume_role_policy": sm_trust(true)})

role_policy(stmts) := res("aws_iam_role_policy", {"role": "ml-exec", "policy": doc(stmts)})

test_iam_scoped_policy_passes if {
	p := plan([ai_role, role_policy([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}])])
	count(findings(p)) == 0
}

test_iam01_service_wildcard if "AIS-AWS-IAM-01" in denied(plan([role_policy([{"Effect": "Allow", "Action": "Bedrock:*", "Resource": "*"}])]))

test_iam01_full_wildcard if "AIS-AWS-IAM-01" in denied(plan([res("aws_iam_policy", {"policy": doc([{"Effect": "Allow", "Action": "*", "Resource": "*"}])})]))

test_iam01_single_statement_object if {
	# Statement may be an object rather than a list
	p := res("aws_iam_policy", {"policy": json.marshal({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}})})
	"AIS-AWS-IAM-01" in denied(plan([p]))
}

test_iam01_deny_wildcard_is_fine if not "AIS-AWS-IAM-01" in denied(plan([role_policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}])]))

test_iam01_not_action if "AIS-AWS-IAM-01" in denied(plan([role_policy([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])]))

test_iam01_inline_policy_on_role if {
	r := res("aws_iam_role", {
		"name": "x",
		"assume_role_policy": sm_trust(true),
		"inline_policy": [{"name": "p", "policy": doc([{"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"}])}],
	})
	"AIS-AWS-IAM-01" in denied(plan([r]))
}

test_iam02_passrole_star if "AIS-AWS-IAM-02" in denied(plan([role_policy([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}])]))

test_iam02_passrole_scoped_ok if {
	p := plan([role_policy([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/ml-exec"}])])
	not "AIS-AWS-IAM-02" in denied(p)
}

test_iam03_ai_role_can_stop_logging if {
	p := plan([ai_role, role_policy([{"Effect": "Allow", "Action": "cloudtrail:StopLogging", "Resource": "arn:aws:cloudtrail:us-east-1:111122223333:trail/t"}])])
	"AIS-AWS-IAM-03" in denied(p)
}

test_iam03_non_ai_role_not_flagged if {
	admin := res("aws_iam_role", {"name": "ml-exec", "assume_role_policy": doc([{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}])})
	p := plan([admin, role_policy([{"Effect": "Allow", "Action": "cloudtrail:StopLogging", "Resource": "arn:aws:cloudtrail:us-east-1:111122223333:trail/t"}])])
	not "AIS-AWS-IAM-03" in denied(p)
}

test_iam04_full_access_attachment if {
	a := res("aws_iam_role_policy_attachment", {"role": "ml-exec", "policy_arn": "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"})
	"AIS-AWS-IAM-04" in denied(plan([a]))
}

test_iam04_admin_via_managed_policy_arns if {
	r := res("aws_iam_role", {"name": "x", "managed_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]})
	"AIS-AWS-IAM-04" in denied(plan([r]))
}

test_iam04_readonly_attachment_ok if {
	a := res("aws_iam_role_policy_attachment", {"role": "ml-exec", "policy_arn": "arn:aws:iam::aws:policy/AmazonSageMakerReadOnly"})
	not "AIS-AWS-IAM-04" in denied(plan([a]))
}

test_iam05_trust_without_source_condition if "AIS-AWS-IAM-05" in warned(plan([res("aws_iam_role", {"name": "x", "assume_role_policy": sm_trust(false)})]))

test_iam00_unknown_policy if {
	p := res_u("aws_iam_policy", {"name": "p"}, {"policy": true})
	"AIS-AWS-IAM-00" in warned(plan([p]))
}

# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------

test_message_includes_address_and_clause if {
	msgs := data.aws.deny with input as plan([role_policy([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}])])
	some m in msgs
	startswith(m, "[AIS-AWS-IAM-02] aws_iam_role_policy.test: ")
	endswith(m, "(ISO/IEC 27090 6.11.3.3)")
}
