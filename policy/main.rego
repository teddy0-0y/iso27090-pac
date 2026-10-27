# Entry point for Conftest (default namespace "main").
#
# Every rule package under data.ai27090.rules.* emits `findings`.
# This package resolves each finding to deny / warn / waived based on the
# system's risk tier and any approved, unexpired exceptions.
package main

import data.ai27090.lib

all_findings contains f if {
	some domain
	some v in data.ai27090.rules[domain].findings
	f := object.union(v, {"domain": domain, "effective": effective(v)})
}

effective(v) := "waived" if {
	lib.waived(v.id)
} else := "deny" if {
	v.level == "deny"
} else := "deny" if {
	v.level == "warn_high"
	lib.is_high
} else := "warn"

format(f) := sprintf("[%s] %s (ISO/IEC 27090 %s)", [f.id, f.msg, f.clause])

deny contains format(f) if {
	some f in all_findings
	f.effective == "deny"
}

warn contains format(f) if {
	some f in all_findings
	f.effective == "warn"
}

warn contains sprintf("WAIVED %s", [format(f)]) if {
	some f in all_findings
	f.effective == "waived"
}

# Machine-readable summary: opa eval -d policy -i file.yaml data.main.report
report := {
	"system": object.get(input, ["metadata", "name"], "unknown"),
	"risk_tier": lib.tier,
	"counts": {
		"deny": count([f | some f in all_findings; f.effective == "deny"]),
		"warn": count([f | some f in all_findings; f.effective == "warn"]),
		"waived": count([f | some f in all_findings; f.effective == "waived"]),
	},
	"findings": sort_findings,
}

sort_findings := [f |
	some id in sort({x.id | some x in all_findings})
	some f in all_findings
	f.id == id
]
