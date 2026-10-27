# Logging, monitoring, environments and mitigation lifecycle — ISO/IEC 27090 5.3, 6.11.3.5, 7.2–7.6
package ai27090.rules.operations

import data.ai27090.lib

ops := lib.get(["spec", "operations"], {})

logging := object.get(ops, "logging", {})

monitoring := object.get(ops, "monitoring", {})

env := object.get(ops, "environment", {})

# Fields that let an incident be reconstructed (date and time combined as timestamp)
required_log_fields := {"input", "output", "timestamp", "user_id", "model_version"}

# AIS-OPS-01: model use is logged
findings contains lib.finding("AIS-OPS-01", "7.5", "deny", "Model usage logging is not enabled") if {
	not object.get(logging, "enabled", false) == true
}

# AIS-OPS-02: log records carry enough detail to reconstruct incidents
findings contains lib.finding("AIS-OPS-02", "7.5", "warn_high", sprintf("Usage logs are missing recommended fields: %v", [sort(missing)])) if {
	object.get(logging, "enabled", false) == true
	missing := required_log_fields - {f | some f in object.get(logging, "fields", [])}
	count(missing) > 0
}

# AIS-OPS-03: behaviour is continuously validated against a test set
findings contains lib.finding("AIS-OPS-03", "6.11.3.5", "warn_high", "No continuous validation of model behaviour against a test set") if {
	not object.get(monitoring, "continuous_validation", false) == true
}

# AIS-OPS-04: behavioural baseline for query patterns, responses and resource use
findings contains lib.finding("AIS-OPS-04", "5.3", "warn_high", "No behavioural baseline monitoring for the AI system") if {
	not object.get(monitoring, "behavioral_baseline", false) == true
}

# AIS-OPS-05: development, test and production are separated
findings contains lib.finding("AIS-OPS-05", "7.6", "deny", "Development and production environments are not separated") if {
	not object.get(env, "dev_prod_separated", false) == true
}

# AIS-OPS-06: mitigation portfolio is re-verified after retraining (mitigations can conflict or decay)
findings contains lib.finding("AIS-OPS-06", "7.2, 7.4", "warn", "Security mitigations are not regression-tested when the model is retrained") if {
	not object.get(monitoring, "mitigation_regression_tests", false) == true
}

# AIS-OPS-07: secure disposal of data and models at end of life
findings contains lib.finding("AIS-OPS-07", "7.6", "warn", "No end-of-life disposal procedure for data and models") if {
	not object.get(ops, "end_of_life_disposal", false) == true
}

# AIS-OPS-08: high-risk systems keep a human in the loop for consequential decisions
findings contains lib.finding("AIS-OPS-08", "6.11.3.2", "deny", "High-risk system has no human oversight or guardrail on its decisions") if {
	lib.is_high
	not object.get(ops, "human_oversight", false) == true
	not object.get(ops, "guardrails", false) == true
}
