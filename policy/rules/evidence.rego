# Evidence for self-attested controls — supports ISO/IEC 27090 5.2 and 5.4
#
# This is an assurance control added by this project. The standard asks for an
# AI governance programme (5.2) and for documentation as an engineering practice
# (5.4); it does not itself require evidence links. GOV-06 makes those
# expectations checkable.
#
# A manifest is self-reported: "risk_assessment.completed: true" is only a claim.
# For controls that produce a reviewable artefact (an assessment, a report, a test
# run), the manifest must link to it under spec.evidence, keyed by control ID:
#
#   spec:
#     evidence:
#       AIS-GOV-02: https://jira.example.com/browse/SEC-1234
#
# Evidence is checked only for controls the manifest claims to meet. A claim of
# `false` is already caught by the control itself.
package ai27090.rules.evidence

import data.ai27090.lib

evidence := lib.get(["spec", "evidence"], {})

# control ID -> path of the claim that needs evidence
claims := {
	"AIS-GOV-02": ["spec", "governance", "risk_assessment", "completed"],
	"AIS-GOV-03": ["spec", "governance", "threat_model", "completed"],
	"AIS-SC-04": ["spec", "model", "provenance_documented"],
	"AIS-SC-05": ["spec", "model", "scanned_for_malicious_code"],
	"AIS-SC-07": ["spec", "model", "behavioral_validation"],
	"AIS-LLM-06": ["spec", "llm", "prompt_injection", "adversarial_testing"],
}

claimed(id) if {
	id != "AIS-LLM-06"
	lib.enabled(claims[id])
}

# LLM controls only apply to generative systems
claimed("AIS-LLM-06") if {
	lib.is_generative
	lib.enabled(claims["AIS-LLM-06"])
}

# A red-team exercise is claimed by recording its date
claimed("AIS-GOV-04") if lib.get(["spec", "governance", "red_team", "last_exercise"], null) != null

# Only http(s) links count, so reviewers can open the artefact
valid_link(v) if {
	is_string(v)
	regex.match(`^https?://[^\s/]+\.[^\s]+$`, v)
}

# AIS-GOV-06: attested controls link to evidence a reviewer can check
findings contains object.union(
	lib.finding("AIS-GOV-06", "5.2, 5.4", "warn_high", sprintf("%v is marked as done but has no evidence link (spec.evidence.%v)", [id, id])),
	{"evidence_for": id},
) if {
	some id in evidence_controls
	claimed(id)
	not id in object.keys(evidence)
}

findings contains object.union(
	lib.finding("AIS-GOV-06", "5.2, 5.4", "warn_high", sprintf("Evidence for %v must be an http(s) link, got '%v'", [id, evidence[id]])),
	{"evidence_for": id},
) if {
	some id in evidence_controls
	claimed(id)
	id in object.keys(evidence)
	not valid_link(evidence[id])
}

evidence_controls := object.keys(claims) | {"AIS-GOV-04"}
