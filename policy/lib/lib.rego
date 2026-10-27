# Shared helpers for all ISO/IEC 27090 rule packages.
package ai27090.lib

# ---------------------------------------------------------------------------
# Input accessors (never undefined: missing fields fall back to a default)
# ---------------------------------------------------------------------------

get(path, default_value) := object.get(input, path, default_value)

# true only when the field exists AND is literally `true`
enabled(path) if object.get(input, path, false) == true

# Missing risk tier is treated as "high" (fail closed).
tier := object.get(input, ["metadata", "risk_tier"], "high")

is_high if tier == "high"

system_type := object.get(input, ["spec", "type"], "")

is_generative if system_type == "generative"

is_predictive if system_type == "predictive"

is_public if get(["spec", "inference", "exposure"], "public") == "public"

trains_on_pii if enabled(["spec", "data", "training", "contains_pii"])

rag_enabled if enabled(["spec", "data", "rag", "enabled"])

rag_sensitive if {
	rag_enabled
	enabled(["spec", "data", "rag", "contains_sensitive"])
}

# ---------------------------------------------------------------------------
# Time helpers. Tests pin "now" with:  with data.ai27090.config.now as "..."
# ---------------------------------------------------------------------------

now_ns := time.parse_rfc3339_ns(data.ai27090.config.now) if {
	data.ai27090.config.now
} else := time.now_ns()

# Accepts "2026-09-01" or full RFC3339 (some YAML parsers emit the latter).
parse_date(s) := t if {
	t := time.parse_ns("2006-01-02", s)
} else := t if {
	t := time.parse_rfc3339_ns(s)
}

ns_per_day := ((24 * 60) * 60) * 1000000000

days_since(s) := (now_ns - parse_date(s)) / ns_per_day

# true when the date is missing, unparsable, or older than max_days
stale(path, _) if get(path, null) == null

stale(path, _) if {
	d := get(path, null)
	d != null
	not parse_date(d)
}

stale(path, max_days) if days_since(get(path, null)) > max_days

# ---------------------------------------------------------------------------
# Finding constructor
#
# level:
#   "deny"       hard requirement, always fails the check
#   "warn"       recommendation, never fails
#   "warn_high"  recommendation that becomes "deny" when risk_tier == high
# ---------------------------------------------------------------------------

finding(id, clause, level, msg) := {
	"id": id,
	"clause": clause,
	"level": level,
	"msg": msg,
}

# ---------------------------------------------------------------------------
# Risk-acceptance exceptions (metadata.exceptions)
# An exception applies only if it names a control id, has a reason and an
# approver, and its expiry date is still in the future.
# ---------------------------------------------------------------------------

valid_exception(e) if {
	e.id
	e.reason
	e.approved_by
	t := parse_date(e.expires)
	t > now_ns
}

waived(control_id) if {
	some e in get(["metadata", "exceptions"], [])
	e.id == control_id
	valid_exception(e)
}
