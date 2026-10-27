package ai27090.tests

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

test_compliant_fixture_has_no_findings if {
	count(results(good)) == 0
}

# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------

test_gov00_wrong_kind if "AIS-GOV-00" in denied(set("/kind", "Deployment"))

test_gov00_unknown_type if "AIS-GOV-00" in denied(set("/spec/type", "robot"))

test_gov00_invalid_tier if "AIS-GOV-00" in denied(set("/metadata/risk_tier", "extreme"))

test_gov01_missing_inventory if "AIS-GOV-01" in denied(drop("/metadata/inventory_id"))

test_gov01_missing_owner if "AIS-GOV-01" in denied(drop("/metadata/owner"))

test_gov02_no_risk_assessment if "AIS-GOV-02" in denied(set("/spec/governance/risk_assessment/completed", false))

test_gov03_no_threat_model if "AIS-GOV-03" in denied(drop("/spec/governance/threat_model"))

test_gov03_stale_threat_model_is_warning if {
	inp := set("/spec/governance/threat_model/last_reviewed", "2024-01-01")
	"AIS-GOV-03" in warned(inp)
	not "AIS-GOV-03" in denied(inp)
}

test_gov04_red_team_missing if "AIS-GOV-04" in denied(drop("/spec/governance/red_team"))

test_gov04_red_team_stale if "AIS-GOV-04" in denied(set("/spec/governance/red_team/last_exercise", "2025-06-01"))

test_gov04_unparsable_date_is_stale if "AIS-GOV-04" in denied(set("/spec/governance/red_team/last_exercise", "last spring"))

# ---------------------------------------------------------------------------
# Risk tier behaviour
# ---------------------------------------------------------------------------

test_missing_tier_defaults_to_high if {
	inp := json.patch(good, [
		{"op": "remove", "path": "/metadata/risk_tier"},
		{"op": "remove", "path": "/spec/governance/threat_model"},
	])
	"AIS-GOV-03" in denied(inp)
}

test_warn_high_is_only_warning_for_medium_tier if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/metadata/risk_tier", "value": "medium"},
		{"op": "remove", "path": "/spec/governance/threat_model"},
	])
	"AIS-GOV-03" in warned(inp)
	not "AIS-GOV-03" in denied(inp)
}

# ---------------------------------------------------------------------------
# Supply chain
# ---------------------------------------------------------------------------

test_sc01_unverified_third_party_model if {
	inp := json.patch(good, [
		{"op": "remove", "path": "/spec/model/checksum"},
		{"op": "replace", "path": "/spec/model/signature_verified", "value": false},
	])
	"AIS-SC-01" in denied(inp)
}

test_sc01_checksum_alone_is_enough if {
	inp := set("/spec/model/signature_verified", false)
	not "AIS-SC-01" in denied(inp)
}

test_sc01_internal_model_not_checked if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/model/source", "value": "internal"},
		{"op": "remove", "path": "/spec/model/checksum"},
		{"op": "remove", "path": "/spec/model/signature_verified"},
	])
	not "AIS-SC-01" in denied(inp)
}

test_sc02_pickle_format_denied if "AIS-SC-02" in denied(set("/spec/model/format", "PT"))

test_sc02_unknown_format_warns if "AIS-SC-02" in warned(set("/spec/model/format", "custom-binary"))

test_sc03_unverified_repository if "AIS-SC-03" in denied(set("/spec/model/from_verified_repository", false))

test_sc04_no_provenance if "AIS-SC-04" in denied(drop("/spec/model/provenance_documented"))

test_sc05_not_scanned if "AIS-SC-05" in denied(drop("/spec/model/scanned_for_malicious_code"))

test_sc06_no_dependency_scanning if "AIS-SC-06" in warned(drop("/spec/supply_chain"))

test_sc07_no_behavioral_validation if "AIS-SC-07" in denied(drop("/spec/model/behavioral_validation"))

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

test_data01_source_without_provenance if {
	"AIS-DATA-01" in denied(set("/spec/data/training/sources/0/provenance_documented", false))
}

test_data01_untrusted_unsanitized if "AIS-DATA-01" in denied(set("/spec/data/training/sources/0/trusted", false))

test_data01_untrusted_but_sanitized_ok if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/data/training/sources/0/trusted", "value": false},
		{"op": "add", "path": "/spec/data/training/sources/0/sanitized", "value": true},
	])
	not "AIS-DATA-01" in denied(inp)
}

test_data02_no_integrity if "AIS-DATA-02" in denied(drop("/spec/data/training/integrity_verification"))

test_data03_no_least_privilege if "AIS-DATA-03" in denied(set("/spec/data/training/access/least_privilege", false))

test_data04_no_encryption if "AIS-DATA-04" in denied(drop("/spec/data/training/encryption_at_rest"))

test_data05_pii_without_minimization if "AIS-DATA-05" in denied(drop("/spec/data/training/pii_controls/minimization"))

test_data05_pii_without_deid_or_dp if "AIS-DATA-05" in denied(drop("/spec/data/training/pii_controls/deidentification"))

test_data05_dp_satisfies_requirement if {
	inp := json.patch(good, [
		{"op": "remove", "path": "/spec/data/training/pii_controls/deidentification"},
		{"op": "add", "path": "/spec/data/training/pii_controls/differential_privacy", "value": true},
	])
	not "AIS-DATA-05" in denied(inp)
}

test_data06_no_retention if "AIS-DATA-06" in warned(drop("/spec/data/training/retention_days"))

test_data07_no_anomaly_detection if "AIS-DATA-07" in denied(drop("/spec/data/training/anomaly_detection"))

test_data08_continuous_learning_unvalidated if {
	"AIS-DATA-08" in denied(set("/spec/data/continuous_learning/enabled", true))
}

test_data09_rag_unvetted if "AIS-DATA-09" in denied(set("/spec/data/rag/sources_vetted", false))

test_data10_rag_sensitive_no_authz if "AIS-DATA-10" in denied(drop("/spec/data/rag/per_document_authz"))

test_data10_rag_not_sensitive_no_authz_ok if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/data/rag/contains_sensitive", "value": false},
		{"op": "remove", "path": "/spec/data/rag/per_document_authz"},
	])
	not "AIS-DATA-10" in denied(inp)
}

# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

test_inf01_no_auth if "AIS-INF-01" in denied(set("/spec/inference/authentication_required", false))

test_inf02_public_without_rate_limit if "AIS-INF-02" in denied(drop("/spec/inference/rate_limit"))

test_inf02_internal_without_rate_limit_warns if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/inference/exposure", "value": "internal"},
		{"op": "remove", "path": "/spec/inference/rate_limit"},
	])
	"AIS-INF-02" in warned(inp)
	not "AIS-INF-02" in denied(inp)
}

test_inf02_zero_rpm if "AIS-INF-02" in denied(set("/spec/inference/rate_limit/requests_per_minute", 0))

test_inf03_public_scores_with_pii if "AIS-INF-03" in denied(set("/spec/inference/returns_confidence_scores", true))

test_inf03_public_scores_without_pii_warns if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/inference/returns_confidence_scores", "value": true},
		{"op": "replace", "path": "/spec/data/training/contains_pii", "value": false},
	])
	"AIS-INF-03" in warned(inp)
	not "AIS-INF-03" in denied(inp)
}

test_inf04_no_timeout if "AIS-INF-04" in warned(drop("/spec/inference/query_timeout_seconds"))

test_inf05_predictive_without_input_checks if {
	inp := set("/spec/type", "predictive")
	"AIS-INF-05" in denied(inp)
}

test_inf05_not_applied_to_generative if not "AIS-INF-05" in denied(good)

test_inf06_no_query_monitoring if "AIS-INF-06" in denied(drop("/spec/inference/query_pattern_monitoring"))

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

test_llm01_no_input_filter if "AIS-LLM-01" in denied(set("/spec/llm/prompt_injection/input_filtering", false))

test_llm02_rag_without_segregation if "AIS-LLM-02" in denied(drop("/spec/llm/prompt_injection/input_segregation"))

test_llm02_web_source_without_segregation if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/data/rag/enabled", "value": false},
		{"op": "add", "path": "/spec/llm/untrusted_content_sources", "value": ["web_search"]},
		{"op": "remove", "path": "/spec/llm/prompt_injection/input_segregation"},
	])
	"AIS-LLM-02" in denied(inp)
}

test_llm02_no_untrusted_context_ok if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/data/rag/enabled", "value": false},
		{"op": "remove", "path": "/spec/llm/prompt_injection/input_segregation"},
	])
	not "AIS-LLM-02" in denied(inp)
}

test_llm03_no_output_filter if "AIS-LLM-03" in denied(drop("/spec/llm/output/sensitive_data_filter"))

test_llm04_sql_consumer_without_encoding if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/llm/output/consumers", "value": ["sql"]},
		{"op": "remove", "path": "/spec/llm/output/validation_and_encoding"},
	])
	"AIS-LLM-04" in denied(inp)
}

test_llm04_plain_text_consumer_ok if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/llm/output/consumers", "value": ["chat_plaintext"]},
		{"op": "remove", "path": "/spec/llm/output/validation_and_encoding"},
	])
	not "AIS-LLM-04" in denied(inp)
}

test_llm05_no_hardened_prompt if "AIS-LLM-05" in warned(drop("/spec/llm/prompt_injection/hardened_system_prompt"))

test_llm06_no_adversarial_testing if "AIS-LLM-06" in denied(drop("/spec/llm/prompt_injection/adversarial_testing"))

test_llm_rules_skip_predictive if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/type", "value": "predictive"},
		{"op": "remove", "path": "/spec/llm"},
		{"op": "add", "path": "/spec/inference/input_checks", "value": {"ood_detection": true, "adversarial_detection": true}},
	])
	count({id | some id in denied(inp); startswith(id, "AIS-LLM")}) == 0
	count({id | some id in warned(inp); startswith(id, "AIS-LLM")}) == 0
}

# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

test_agt01_inherited_identity if "AIS-AGT-01" in denied(set("/spec/agent/credentials/identity", "inherit_user"))

test_agt02_long_ttl if "AIS-AGT-02" in denied(set("/spec/agent/credentials/ttl_minutes", 1440))

test_agt02_missing_ttl if "AIS-AGT-02" in denied(drop("/spec/agent/credentials/ttl_minutes"))

test_agt03_wildcard_scope if "AIS-AGT-03" in denied(set("/spec/agent/tools/0/scopes", ["db:*"]))

test_agt03_no_scopes if "AIS-AGT-03" in denied(drop("/spec/agent/tools/0/scopes"))

test_agt04_payment_without_approval if "AIS-AGT-04" in denied(drop("/spec/agent/tools/1/requires_human_approval"))

test_agt04_write_without_approval_warns if {
	inp := set("/spec/agent/tools/0/action", "write")
	"AIS-AGT-04" in warned(inp)
	not "AIS-AGT-04" in denied(inp)
}

test_agt05_code_execution_outside_sandbox if {
	inp := json.patch(good, [
		{"op": "add", "path": "/spec/agent/tools/0/action", "value": "execute"},
		{"op": "add", "path": "/spec/agent/tools/0/requires_human_approval", "value": true},
		{"op": "replace", "path": "/spec/agent/execution_environment", "value": "host"},
	])
	"AIS-AGT-05" in denied(inp)
}

test_agt05_computer_use_outside_sandbox if {
	inp := json.patch(good, [
		{"op": "add", "path": "/spec/agent/computer_use", "value": true},
		{"op": "remove", "path": "/spec/agent/execution_environment"},
	])
	"AIS-AGT-05" in denied(inp)
}

test_agt06_no_audit_log if "AIS-AGT-06" in denied(drop("/spec/agent/action_audit_log"))

test_agt07_no_kill_switch if "AIS-AGT-07" in denied(drop("/spec/agent/kill_switch"))

test_agent_rules_skip_when_disabled if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/spec/agent/enabled", "value": false},
		{"op": "replace", "path": "/spec/agent/credentials/identity", "value": "inherit_user"},
	])
	count({id | some id in denied(inp); startswith(id, "AIS-AGT")}) == 0
}

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

test_ops01_logging_disabled if "AIS-OPS-01" in denied(set("/spec/operations/logging/enabled", false))

test_ops02_missing_log_fields if "AIS-OPS-02" in denied(set("/spec/operations/logging/fields", ["input"]))

test_ops03_no_continuous_validation if "AIS-OPS-03" in denied(drop("/spec/operations/monitoring/continuous_validation"))

test_ops04_no_baseline if "AIS-OPS-04" in denied(drop("/spec/operations/monitoring/behavioral_baseline"))

test_ops05_no_env_separation if "AIS-OPS-05" in denied(drop("/spec/operations/environment"))

test_ops06_no_mitigation_regression if "AIS-OPS-06" in warned(drop("/spec/operations/monitoring/mitigation_regression_tests"))

test_ops07_no_disposal if "AIS-OPS-07" in warned(drop("/spec/operations/end_of_life_disposal"))

test_ops08_high_risk_no_oversight if "AIS-OPS-08" in denied(drop("/spec/operations/human_oversight"))

test_ops08_guardrails_satisfy if {
	inp := json.patch(good, [
		{"op": "remove", "path": "/spec/operations/human_oversight"},
		{"op": "add", "path": "/spec/operations/guardrails", "value": true},
	])
	not "AIS-OPS-08" in denied(inp)
}

# ---------------------------------------------------------------------------
# Exceptions (risk acceptance)
# ---------------------------------------------------------------------------

broken_auth := set("/spec/inference/authentication_required", false)

with_exception(e) := json.patch(broken_auth, [{"op": "add", "path": "/metadata/exceptions", "value": [e]}])

test_valid_exception_waives_control if {
	inp := with_exception({"id": "AIS-INF-01", "reason": "r", "approved_by": "ciso", "expires": "2027-01-01"})
	"AIS-INF-01" in waived(inp)
	not "AIS-INF-01" in denied(inp)
}

test_expired_exception_not_applied if {
	inp := with_exception({"id": "AIS-INF-01", "reason": "r", "approved_by": "ciso", "expires": "2026-01-01"})
	"AIS-INF-01" in denied(inp)
	"AIS-GOV-05" in warned(inp)
}

test_exception_without_approver_not_applied if {
	inp := with_exception({"id": "AIS-INF-01", "reason": "r", "expires": "2027-01-01"})
	"AIS-INF-01" in denied(inp)
	"AIS-GOV-05" in warned(inp)
}

test_exception_only_covers_named_control if {
	inp := json.patch(with_exception({"id": "AIS-INF-01", "reason": "r", "approved_by": "ciso", "expires": "2027-01-01"}), [{"op": "remove", "path": "/spec/data/training/encryption_at_rest"}])
	"AIS-DATA-04" in denied(inp)
}

# ---------------------------------------------------------------------------
# Conftest-facing output
# ---------------------------------------------------------------------------

test_deny_message_format if {
	msgs := data.main.deny with input as broken_auth with data.ai27090.config.now as fixed_now
	some m in msgs
	startswith(m, "[AIS-INF-01] ")
	endswith(m, "(ISO/IEC 27090 5.3)")
}

test_report_counts if {
	r := data.main.report with input as broken_auth with data.ai27090.config.now as fixed_now
	r.counts == {"deny": 1, "warn": 0, "waived": 0}
	r.risk_tier == "high"
}
