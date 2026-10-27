# Generative AI / LLM controls — ISO/IEC 27090 6.8, 6.9, 6.10
# Only evaluated when spec.type == "generative".
package ai27090.rules.llm

import data.ai27090.lib

llm := lib.get(["spec", "llm"], {})

pi := object.get(llm, "prompt_injection", {})

out := object.get(llm, "output", {})

# Content that is not written by the user or developer reaches the context window
untrusted_context if lib.rag_enabled

untrusted_context if count(object.get(llm, "untrusted_content_sources", [])) > 0

# Downstream consumers that interpret model output as markup or commands
interpreting_consumers := {"browser", "html", "sql", "shell", "code_execution", "email_html"}

risky_consumers := {c | some c in object.get(out, "consumers", []); c in interpreting_consumers}

# AIS-LLM-01: user prompts are validated / filtered (direct injection, jailbreaks)
findings contains lib.finding("AIS-LLM-01", "6.9.3, 6.9.4", "deny", "No prompt-injection input filtering or classification on user prompts") if {
	lib.is_generative
	not object.get(pi, "input_filtering", false) == true
}

# AIS-LLM-02: untrusted context (RAG, web, email, files) is segregated from instructions
findings contains lib.finding("AIS-LLM-02", "6.9.1, 6.9.4", "deny", "Untrusted content enters the prompt but is not segregated from instructions (indirect prompt injection)") if {
	lib.is_generative
	untrusted_context
	not object.get(pi, "input_segregation", false) == true
}

# AIS-LLM-03: outputs are scanned for sensitive data (PII, secrets) before release
findings contains lib.finding("AIS-LLM-03", "6.8.3, 6.8.4", "deny", "Model may emit PII/sensitive data but no output filter is configured") if {
	lib.is_generative
	sensitive_sources
	not object.get(out, "sensitive_data_filter", false) == true
}

findings contains lib.finding("AIS-LLM-03", "6.8.3", "warn", "No sensitive-data output filter configured") if {
	lib.is_generative
	not sensitive_sources
	not object.get(out, "sensitive_data_filter", false) == true
}

sensitive_sources if lib.trains_on_pii

sensitive_sources if lib.rag_sensitive

# AIS-LLM-04: model output is untrusted; encode/validate before an interpreter sees it
findings contains lib.finding("AIS-LLM-04", "6.10.4", "deny", sprintf("Model output is consumed by %v without output validation/encoding (XSS / injection risk)", [sort(risky_consumers)])) if {
	lib.is_generative
	count(risky_consumers) > 0
	not object.get(out, "validation_and_encoding", false) == true
}

# AIS-LLM-05: hardened system prompt (meta-prompt) that resists harmful instructions
findings contains lib.finding("AIS-LLM-05", "6.9.4", "warn", "System prompt has not been hardened against injection") if {
	lib.is_generative
	not object.get(pi, "hardened_system_prompt", false) == true
}

# AIS-LLM-06: adversarial prompt-injection test suite runs before release
findings contains lib.finding("AIS-LLM-06", "5.7, 6.9.4", "warn_high", "No adversarial prompt-injection testing before release") if {
	lib.is_generative
	not object.get(pi, "adversarial_testing", false) == true
}
