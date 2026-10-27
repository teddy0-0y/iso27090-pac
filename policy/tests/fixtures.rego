# Test fixtures and helpers. `good` is a fully compliant high-risk generative
# system with RAG and an agent; tests break one field at a time with json.patch.
package ai27090.tests

fixed_now := "2026-10-27T00:00:00Z"

good := {
	"apiVersion": "ai-security.example/v1",
	"kind": "AISystem",
	"metadata": {
		"name": "fixture",
		"inventory_id": "AI-0001",
		"owner": "owner@example.com",
		"risk_tier": "high",
	},
	"spec": {
		"type": "generative",
		"governance": {
			"risk_assessment": {"completed": true},
			"threat_model": {"completed": true, "last_reviewed": "2026-08-01"},
			"red_team": {"last_exercise": "2026-09-01"},
		},
		"supply_chain": {"dependency_scanning": true},
		"model": {
			"source": "third_party",
			"format": "safetensors",
			"checksum": "sha256:abc",
			"signature_verified": true,
			"from_verified_repository": true,
			"provenance_documented": true,
			"scanned_for_malicious_code": true,
			"behavioral_validation": true,
		},
		"data": {
			"training": {
				"sources": [{"name": "s1", "trusted": true, "provenance_documented": true}],
				"integrity_verification": true,
				"anomaly_detection": true,
				"encryption_at_rest": true,
				"access": {"least_privilege": true, "just_in_time": true},
				"contains_pii": true,
				"pii_controls": {"minimization": true, "deidentification": true},
				"retention_days": 365,
			},
			"continuous_learning": {"enabled": false},
			"rag": {
				"enabled": true,
				"sources_vetted": true,
				"contains_sensitive": true,
				"per_document_authz": true,
				"encryption_at_rest": true,
			},
		},
		"inference": {
			"exposure": "public",
			"authentication_required": true,
			"rate_limit": {"per_user": true, "requests_per_minute": 30},
			"returns_confidence_scores": false,
			"query_timeout_seconds": 30,
			"query_pattern_monitoring": true,
		},
		"llm": {
			"prompt_injection": {
				"input_filtering": true,
				"input_segregation": true,
				"hardened_system_prompt": true,
				"adversarial_testing": true,
			},
			"output": {
				"consumers": ["browser"],
				"sensitive_data_filter": true,
				"validation_and_encoding": true,
			},
		},
		"agent": {
			"enabled": true,
			"execution_environment": "sandboxed",
			"action_audit_log": true,
			"kill_switch": true,
			"credentials": {"identity": "dedicated", "ttl_minutes": 15},
			"tools": [
				{"name": "read_tool", "action": "read", "scopes": ["x:read"]},
				{"name": "pay_tool", "action": "payment", "scopes": ["pay:max-100"], "requires_human_approval": true},
			],
		},
		"operations": {
			"human_oversight": true,
			"end_of_life_disposal": true,
			"logging": {"enabled": true, "fields": ["input", "output", "timestamp", "user_id", "model_version"]},
			"monitoring": {
				"continuous_validation": true,
				"behavioral_baseline": true,
				"mitigation_regression_tests": true,
			},
			"environment": {"dev_prod_separated": true},
		},
	},
}

# Evaluate the policy for an input with a pinned clock.
results(inp) := r if {
	r := data.main.all_findings with input as inp with data.ai27090.config.now as fixed_now
}

ids_with(inp, effective) := {f.id | some f in results(inp); f.effective == effective}

denied(inp) := ids_with(inp, "deny")

warned(inp) := ids_with(inp, "warn")

waived(inp) := ids_with(inp, "waived")

# Shorthands for one-field mutations
set(path, value) := json.patch(good, [{"op": "add", "path": path, "value": value}])

drop(path) := json.patch(good, [{"op": "remove", "path": path}])
