# Training data, RAG data and data limitation — ISO/IEC 27090 6.2, 6.4, 6.11.2, 7.6, B.6
package ai27090.rules.data_security

import data.ai27090.lib

training := lib.get(["spec", "data", "training"], {})

rag := lib.get(["spec", "data", "rag"], {})

cl := lib.get(["spec", "data", "continuous_learning"], {})

# AIS-DATA-01: every training source has documented provenance (zero trust: verify regardless of origin)
findings contains lib.finding("AIS-DATA-01", "5.3, 6.2.4, 6.11.4", "deny", sprintf("Training source '%v' has no documented provenance", [object.get(s, "name", "?")])) if {
	some s in object.get(training, "sources", [])
	not object.get(s, "provenance_documented", false) == true
}

# Untrusted / unvetted sources must go through sanitization before training
findings contains lib.finding("AIS-DATA-01", "6.2.4", "deny", sprintf("Untrusted training source '%v' is used without sanitization", [object.get(s, "name", "?")])) if {
	some s in object.get(training, "sources", [])
	not object.get(s, "trusted", false) == true
	not object.get(s, "sanitized", false) == true
}

findings contains lib.finding("AIS-DATA-01", "6.11.4", "warn", "No training data sources declared (spec.data.training.sources)") if {
	count(object.get(training, "sources", [])) == 0
}

# AIS-DATA-02: dataset integrity checks (e.g. stored hashes) detect tampering
findings contains lib.finding("AIS-DATA-02", "6.2.3, 6.2.4", "deny", "Training data integrity verification is not enabled") if {
	not object.get(training, "integrity_verification", false) == true
}

# AIS-DATA-03: least-privilege, just-in-time access to training data
findings contains lib.finding("AIS-DATA-03", "6.2.4, B.6.4", "deny", "Training data access is not restricted to least privilege") if {
	not object.get(object.get(training, "access", {}), "least_privilege", false) == true
}

findings contains lib.finding("AIS-DATA-03", "6.2.4, B.6.4", "warn_high", "Training data access is not just-in-time (JIT/JEA)") if {
	not object.get(object.get(training, "access", {}), "just_in_time", false) == true
}

# AIS-DATA-04: training data is encrypted at rest
findings contains lib.finding("AIS-DATA-04", "7.6, B.6.4", "deny", "Training data is not encrypted at rest") if {
	not object.get(training, "encryption_at_rest", false) == true
}

# AIS-DATA-05: PII in training data is minimized and protected against membership inference / inversion
findings contains lib.finding("AIS-DATA-05", "6.4.4, 6.11.2.2", "deny", "Training data contains PII but data minimization is not applied") if {
	lib.trains_on_pii
	not lib.enabled(["spec", "data", "training", "pii_controls", "minimization"])
}

findings contains lib.finding("AIS-DATA-05", "6.4.4, 6.6.4", "deny", "Training data contains PII but neither de-identification nor differential privacy is applied") if {
	lib.trains_on_pii
	not lib.enabled(["spec", "data", "training", "pii_controls", "deidentification"])
	not lib.enabled(["spec", "data", "training", "pii_controls", "differential_privacy"])
}

# AIS-DATA-06: a retention period is defined for training data
findings contains lib.finding("AIS-DATA-06", "6.11.2.3", "warn", "No retention period defined for training data (spec.data.training.retention_days)") if {
	not is_number(object.get(training, "retention_days", null))
}

# AIS-DATA-07: poisoning detection (anomaly / distribution-drift checks) on training data
findings contains lib.finding("AIS-DATA-07", "6.2.3", "warn_high", "No anomaly or distribution-drift detection on training data") if {
	not object.get(training, "anomaly_detection", false) == true
}

# AIS-DATA-08: continuous learning turns operational inputs into training data
findings contains lib.finding("AIS-DATA-08", "6.2.1, 7.6", "deny", "Continuous learning is enabled but incoming data is not validated before re-training") if {
	object.get(cl, "enabled", false) == true
	not object.get(cl, "input_validation", false) == true
}

findings contains lib.finding("AIS-DATA-08", "6.2.3", "deny", "Continuous learning is enabled without anomaly detection on incoming data") if {
	object.get(cl, "enabled", false) == true
	not object.get(cl, "anomaly_detection", false) == true
}

# AIS-DATA-09: RAG repositories are vetted (poisoning + indirect prompt injection)
findings contains lib.finding("AIS-DATA-09", "6.2.1, 6.9.4", "deny", "RAG is enabled but its document sources are not vetted") if {
	lib.rag_enabled
	not object.get(rag, "sources_vetted", false) == true
}

# AIS-DATA-10: RAG over sensitive data authorizes every retrieval for the requesting user
findings contains lib.finding("AIS-DATA-10", "5.3, 7.6, B.7.1", "deny", "RAG over sensitive data does not enforce per-document authorization for the requesting user") if {
	lib.rag_sensitive
	not object.get(rag, "per_document_authz", false) == true
}

findings contains lib.finding("AIS-DATA-10", "7.6", "deny", "RAG repository holds sensitive data but is not encrypted at rest") if {
	lib.rag_sensitive
	not object.get(rag, "encryption_at_rest", false) == true
}
