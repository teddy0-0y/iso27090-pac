# Inference endpoint protections — ISO/IEC 27090 5.3, 6.3, 6.5, 6.6, 7.7, 7.8, B.2
package ai27090.rules.inference

import data.ai27090.lib

inf := lib.get(["spec", "inference"], {})

rate := object.get(inf, "rate_limit", {})

# AIS-INF-01: every request is authenticated (never trust, always verify)
findings contains lib.finding("AIS-INF-01", "5.3", "deny", "Inference endpoint does not require authentication") if {
	not object.get(inf, "authentication_required", false) == true
}

# AIS-INF-02: per-user throttling to hinder exfiltration / inversion / evasion experiments
findings contains lib.finding("AIS-INF-02", "6.5.4, 6.6.4, 7.8", "deny", "Public inference endpoint has no per-user rate limit") if {
	lib.is_public
	not object.get(rate, "per_user", false) == true
}

findings contains lib.finding("AIS-INF-02", "7.8", "warn", "Internal inference endpoint has no per-user rate limit") if {
	not lib.is_public
	not object.get(rate, "per_user", false) == true
}

findings contains lib.finding("AIS-INF-02", "7.8", "deny", "Rate limit is declared but requests_per_minute is missing or not positive") if {
	object.get(rate, "per_user", false) == true
	not object.get(rate, "requests_per_minute", 0) > 0
}

# AIS-INF-03: avoid returning raw confidence scores (fuel for model inversion / extraction)
findings contains lib.finding("AIS-INF-03", "6.5.4, 6.6.1", "deny", "Public endpoint returns confidence scores from a model trained on PII (model inversion risk)") if {
	object.get(inf, "returns_confidence_scores", false) == true
	lib.is_public
	lib.trains_on_pii
}

findings contains lib.finding("AIS-INF-03", "6.5.4", "warn", "Endpoint returns confidence scores; consider withholding or rounding them") if {
	object.get(inf, "returns_confidence_scores", false) == true
	not lib.is_public
}

findings contains lib.finding("AIS-INF-03", "6.5.4", "warn", "Endpoint returns confidence scores; consider withholding or rounding them") if {
	object.get(inf, "returns_confidence_scores", false) == true
	lib.is_public
	not lib.trains_on_pii
}

# AIS-INF-04: per-query time/resource budget against sponge-style DoS
findings contains lib.finding("AIS-INF-04", "B.2.3", "warn", "No per-query timeout or compute budget (spec.inference.query_timeout_seconds)") if {
	not object.get(inf, "query_timeout_seconds", 0) > 0
}

# AIS-INF-05: out-of-distribution / adversarial input detection for predictive models
findings contains lib.finding("AIS-INF-05", "6.3.4, 7.7.1", "warn_high", "Predictive model has no out-of-distribution input detection") if {
	lib.is_predictive
	not lib.enabled(["spec", "inference", "input_checks", "ood_detection"])
}

findings contains lib.finding("AIS-INF-05", "6.3.3, 7.7.2", "warn_high", "Predictive model has no adversarial input detection") if {
	lib.is_predictive
	not lib.enabled(["spec", "inference", "input_checks", "adversarial_detection"])
}

# AIS-INF-06: query-pattern analytics detect extraction / membership-inference probing
findings contains lib.finding("AIS-INF-06", "6.4.3, 6.5.3, 7.7.2", "warn_high", "No per-caller query-pattern monitoring for extraction or inference attacks") if {
	lib.is_public
	not object.get(inf, "query_pattern_monitoring", false) == true
}
