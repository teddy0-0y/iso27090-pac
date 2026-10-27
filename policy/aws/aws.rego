# Conftest entry point for Terraform plans:
#   terraform show -json tfplan > plan.json
#   conftest test -p policy --namespace aws plan.json
package aws

import data.ai27090.aws.lib

all_findings contains f if {
	some domain
	some v in data.ai27090.aws.rules[domain].findings
	f := object.union(v, {"domain": domain})
}

format(f) := sprintf("[%s] %s: %s (ISO/IEC 27090 %s)", [f.id, f.address, f.msg, f.clause])

deny contains "Input is not a Terraform plan (missing resource_changes); run `terraform show -json <planfile>`" if {
	not lib.is_plan
}

deny contains format(f) if {
	some f in all_findings
	f.level == "deny"
}

warn contains format(f) if {
	some f in all_findings
	f.level == "warn"
}

report := {
	"resources_evaluated": count(lib.resources),
	"counts": {
		"deny": count([f | some f in all_findings; f.level == "deny"]),
		"warn": count([f | some f in all_findings; f.level == "warn"]),
	},
	"findings": sort([[f.id, f.address, f.level, f.msg] | some f in all_findings]),
}
