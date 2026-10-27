# Governance, threat modelling and red teaming — ISO/IEC 27090 clause 5
package ai27090.rules.governance

import data.ai27090.lib

# AIS-GOV-00: the file must be an AISystem manifest with a known system type
findings contains lib.finding("AIS-GOV-00", "5.1", "deny", "Manifest kind must be AISystem") if {
	object.get(input, "kind", "") != "AISystem"
}

findings contains lib.finding("AIS-GOV-00", "Table 2", "deny", sprintf("spec.type must be 'generative' or 'predictive', got '%v'", [lib.system_type])) if {
	not lib.system_type in {"generative", "predictive"}
}

findings contains lib.finding("AIS-GOV-00", "6.1", "deny", sprintf("metadata.risk_tier must be low, medium or high, got '%v'", [lib.tier])) if {
	not lib.tier in {"low", "medium", "high"}
}

# AIS-GOV-01: the system is registered in the organisation's AI inventory with an owner
findings contains lib.finding("AIS-GOV-01", "5.2", "deny", "System is not registered in the AI inventory (metadata.inventory_id and metadata.owner are required)") if {
	lib.get(["metadata", "inventory_id"], null) == null
}

findings contains lib.finding("AIS-GOV-01", "5.2", "deny", "System is not registered in the AI inventory (metadata.inventory_id and metadata.owner are required)") if {
	lib.get(["metadata", "inventory_id"], null) != null
	lib.get(["metadata", "owner"], null) == null
}

# AIS-GOV-02: an information security risk assessment has been performed
findings contains lib.finding("AIS-GOV-02", "5.1, 5.2", "deny", "No completed risk assessment recorded (spec.governance.risk_assessment.completed)") if {
	not lib.enabled(["spec", "governance", "risk_assessment", "completed"])
}

# AIS-GOV-03: an AI-specific threat model exists and was reviewed in the last year
findings contains lib.finding("AIS-GOV-03", "5.6", "warn_high", "No threat model recorded for this AI system") if {
	not lib.enabled(["spec", "governance", "threat_model", "completed"])
}

findings contains lib.finding("AIS-GOV-03", "5.6", "warn", "Threat model has not been reviewed in the last 365 days") if {
	lib.enabled(["spec", "governance", "threat_model", "completed"])
	lib.stale(["spec", "governance", "threat_model", "last_reviewed"], 365)
}

# AIS-GOV-04: adversary-emulating red team exercise in the last year
findings contains lib.finding("AIS-GOV-04", "5.7", "warn_high", "No AI red team exercise in the last 365 days") if {
	lib.stale(["spec", "governance", "red_team", "last_exercise"], 365)
}

# AIS-GOV-05: exception hygiene — invalid or expired risk acceptances are flagged
findings contains lib.finding("AIS-GOV-05", "5.2", "warn", sprintf("Exception for %v is invalid or expired and is NOT applied (needs id, reason, approved_by and a future expires date)", [object.get(e, "id", "?")])) if {
	some e in lib.get(["metadata", "exceptions"], [])
	not lib.valid_exception(e)
}
