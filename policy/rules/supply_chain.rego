# AI supply chain and model integrity — ISO/IEC 27090 5.5, 6.7, 6.11.4, Annex B.4
package ai27090.rules.supply_chain

import data.ai27090.lib

model := lib.get(["spec", "model"], {})

third_party if model.source == "third_party"

# Serialization formats that can execute code when loaded.
unsafe_formats := {"pickle", "pkl", "pt", "pth", "bin", "joblib", "ckpt"}

safe_formats := {"safetensors", "onnx", "gguf", "savedmodel", "tflite", "coreml"}

has_checksum if startswith(object.get(model, "checksum", ""), "sha256:")

# AIS-SC-01: externally sourced models are pinned and verified before use
findings contains lib.finding("AIS-SC-01", "5.5.5, B.4.3", "deny", "Third-party model has neither a verified signature nor a pinned sha256 checksum") if {
	third_party
	not object.get(model, "signature_verified", false) == true
	not has_checksum
}

# AIS-SC-02: model weights use a format that cannot execute code on load
findings contains lib.finding("AIS-SC-02", "B.4.3", "deny", sprintf("Model format '%v' can execute arbitrary code when loaded; use a safe format such as safetensors", [model.format])) if {
	lower(model.format) in unsafe_formats
}

findings contains lib.finding("AIS-SC-02", "B.4.3", "warn", sprintf("Model format '%v' is not on the known-safe list; confirm it cannot execute code on load", [f])) if {
	f := lower(object.get(model, "format", "unspecified"))
	not f in unsafe_formats
	not f in safe_formats
}

# AIS-SC-03: third-party models come from a verified repository
findings contains lib.finding("AIS-SC-03", "5.5.5", "warn_high", "Third-party model is not from a verified/approved model repository") if {
	third_party
	not object.get(model, "from_verified_repository", false) == true
}

# AIS-SC-04: model provenance (origin, training lineage, licence) is documented
findings contains lib.finding("AIS-SC-04", "6.11.4", "warn_high", "Model provenance is not documented") if {
	not object.get(model, "provenance_documented", false) == true
}

# AIS-SC-05: third-party weight files are scanned for embedded malicious code
findings contains lib.finding("AIS-SC-05", "B.4.2", "warn_high", "Third-party model weights have not been scanned for malicious code") if {
	third_party
	not object.get(model, "scanned_for_malicious_code", false) == true
}

# AIS-SC-06: AI libraries and frameworks are scanned for vulnerable/malicious dependencies
findings contains lib.finding("AIS-SC-06", "5.5.4, 5.5.5", "warn", "AI dependency scanning is not enabled (spec.supply_chain.dependency_scanning)") if {
	not lib.enabled(["spec", "supply_chain", "dependency_scanning"])
}

# AIS-SC-07: pre-trained models are tested for hidden/unexpected behaviour (trojans)
findings contains lib.finding("AIS-SC-07", "5.5.4, 5.5.5", "warn_high", "Third-party model has not been validated for unexpected (trojan/backdoor) behaviour") if {
	third_party
	not object.get(model, "behavioral_validation", false) == true
}
