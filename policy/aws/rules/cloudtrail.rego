# AWS CloudTrail — ISO/IEC 27090 6.11.4, 7.5, 7.6
package ai27090.aws.rules.cloudtrail

import data.ai27090.aws.lib

trails := lib.of_type("aws_cloudtrail")

# AIS-AWS-CT-01: an audit trail covers the AI workload
# Organisations often run one org-wide trail from a central account, so by
# default a missing trail is a warning. Set require_trail_in_plan to enforce.
findings contains lib.plan_finding("AIS-AWS-CT-01", "7.5", level, "Plan creates AI resources but no CloudTrail trail; confirm an organization trail covers this account") if {
	lib.has_ai_workload
	count(trails) == 0
	level := trail_required_level
}

trail_required_level := "deny" if {
	object.get(lib.config, "require_trail_in_plan", false) == true
} else := "warn"

# AIS-AWS-CT-02: logging is switched on
findings contains lib.finding(rc, "AIS-AWS-CT-02", "7.5", "deny", "Trail has enable_logging = false") if {
	some rc in trails
	lib.attr(rc, "enable_logging", true) == false
}

# AIS-AWS-CT-03: multi-region (Bedrock cross-region inference and regional endpoints)
findings contains lib.finding(rc, "AIS-AWS-CT-03", "7.5", "deny", "Trail is not multi-region; AI API calls in other regions are not recorded") if {
	some rc in trails
	not lib.attr(rc, "is_multi_region_trail", false) == true
}

# AIS-AWS-CT-04: log integrity (tamper-evident, immutable audit records)
findings contains lib.finding(rc, "AIS-AWS-CT-04", "6.11.4, 7.5", "deny", "Trail log file validation is disabled; tampering with audit logs would go undetected") if {
	some rc in trails
	not lib.attr(rc, "enable_log_file_validation", false) == true
}

# AIS-AWS-CT-05: logs encrypted with a customer-managed key
findings contains lib.finding(rc, "AIS-AWS-CT-05", "7.5", "warn", "Trail logs are not encrypted with a customer-managed KMS key (kms_key_id)") if {
	some rc in trails
	not lib.present(rc, "kms_key_id")
}

# AIS-AWS-CT-06: S3 data events are logged so reads/writes of training data are visible
s3_data_events(rc) if {
	some sel in lib.attr(rc, "event_selector", [])
	some dr in object.get(sel, "data_resource", [])
	dr.type == "AWS::S3::Object"
}

s3_data_events(rc) if {
	some sel in lib.attr(rc, "advanced_event_selector", [])
	some fs in object.get(sel, "field_selector", [])
	fs.field == "resources.type"
	"AWS::S3::Object" in object.get(fs, "equals", [])
}

findings contains lib.finding(rc, "AIS-AWS-CT-06", "6.2.3, 7.6", "warn", "Trail does not record S3 data events; access to or tampering with training data will not be logged") if {
	lib.has_ai_workload
	some rc in trails
	not s3_data_events(rc)
}
