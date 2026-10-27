# Amazon Bedrock — ISO/IEC 27090 6.8, 6.9, 7.5, 7.6
package ai27090.aws.rules.bedrock

import data.ai27090.aws.lib

strong := {"MEDIUM", "HIGH"}

# AIS-AWS-BR-01: every agent is bound to a guardrail
findings contains lib.finding(rc, "AIS-AWS-BR-01", "6.9.4, 6.8.4, 6.11.3.2", "deny", "Bedrock agent has no guardrail_configuration; prompts and responses are not filtered") if {
	some rc in lib.of_type("aws_bedrockagent_agent")
	not lib.has_block(rc, "guardrail_configuration")
}

filters(rc) := [f |
	some c in lib.attr(rc, "content_policy_config", [])
	some f in object.get(c, "filters_config", [])
]

prompt_attack_strength(rc) := s if {
	some f in filters(rc)
	f.type == "PROMPT_ATTACK"
	s := object.get(f, "input_strength", "NONE")
} else := "NONE"

# AIS-AWS-BR-02: guardrail blocks prompt attacks (jailbreak / injection) at MEDIUM or HIGH
findings contains lib.finding(rc, "AIS-AWS-BR-02", "6.9.3, 6.9.4", "deny", sprintf("Guardrail PROMPT_ATTACK filter input strength is %v; must be MEDIUM or HIGH", [prompt_attack_strength(rc)])) if {
	some rc in lib.of_type("aws_bedrock_guardrail")
	not prompt_attack_strength(rc) in strong
}

# AIS-AWS-BR-03: guardrail masks or blocks sensitive information (PII) in outputs
findings contains lib.finding(rc, "AIS-AWS-BR-03", "6.8.3, 6.8.4", "warn", "Guardrail has no sensitive_information_policy_config (PII / regex filtering)") if {
	some rc in lib.of_type("aws_bedrock_guardrail")
	not lib.has_block(rc, "sensitive_information_policy_config")
}

# AIS-AWS-BR-04: Bedrock resources are encrypted with customer-managed keys
findings contains lib.finding(rc, "AIS-AWS-BR-04", "7.6", "warn", "Guardrail is not encrypted with a customer-managed KMS key (kms_key_arn)") if {
	some rc in lib.of_type("aws_bedrock_guardrail")
	not lib.present(rc, "kms_key_arn")
}

findings contains lib.finding(rc, "AIS-AWS-BR-04", "7.6", "warn", "Agent session data is not encrypted with a customer-managed KMS key (customer_encryption_key_arn)") if {
	some rc in lib.of_type("aws_bedrockagent_agent")
	not lib.present(rc, "customer_encryption_key_arn")
}

findings contains lib.finding(rc, "AIS-AWS-BR-04", "7.6, B.6.4", "deny", "Custom (fine-tuned) model weights are not encrypted with a customer-managed KMS key (customer_encryption_key_id)") if {
	some rc in lib.of_type("aws_bedrock_custom_model")
	not lib.present(rc, "customer_encryption_key_id")
}

# AIS-AWS-BR-05: model invocation logging captures prompts and responses
bedrock_types := {
	"aws_bedrockagent_agent",
	"aws_bedrockagent_knowledge_base",
	"aws_bedrock_guardrail",
	"aws_bedrock_custom_model",
	"aws_bedrock_provisioned_model_throughput",
}

uses_bedrock if count(lib.any_of_type(bedrock_types)) > 0

findings contains lib.plan_finding("AIS-AWS-BR-05", "7.5", "warn", "Plan uses Bedrock but defines no aws_bedrock_model_invocation_logging_configuration; confirm invocation logging is enabled for this account and region") if {
	uses_bedrock
	count(lib.of_type("aws_bedrock_model_invocation_logging_configuration")) == 0
}

findings contains lib.finding(rc, "AIS-AWS-BR-05", "7.5", "deny", "Invocation logging does not deliver text data; prompts and responses are not recorded") if {
	some rc in lib.of_type("aws_bedrock_model_invocation_logging_configuration")
	lc := lib.block(rc, "logging_config")
	not object.get(lc, "text_data_delivery_enabled", false) == true
}
