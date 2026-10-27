# Amazon SageMaker — ISO/IEC 27090 7.5, 7.6, B.4, B.6, B.7
package ai27090.aws.rules.sagemaker

import data.ai27090.aws.lib

# AIS-AWS-SM-01: endpoint storage volumes are encrypted with a customer-managed KMS key
findings contains lib.finding(rc, "AIS-AWS-SM-01", "7.6, B.7.4", "deny", "Endpoint configuration has no kms_key_arn; model and inference data on the ML storage volume are not encrypted with a customer-managed key") if {
	some rc in lib.of_type("aws_sagemaker_endpoint_configuration")
	not lib.present(rc, "kms_key_arn")
}

# AIS-AWS-SM-02: captured inference inputs/outputs are encrypted; capture exists for monitoring
findings contains lib.finding(rc, "AIS-AWS-SM-02", "B.7.1, B.7.4", "deny", "Data capture stores model inputs and outputs in S3 without a KMS key (kms_key_id)") if {
	some rc in lib.of_type("aws_sagemaker_endpoint_configuration")
	dc := lib.block(rc, "data_capture_config")
	object.get(dc, "enable_capture", true) == true
	dc != {}
	object.get(dc, "kms_key_id", null) in lib.empty_values
	not capture_kms_unknown(rc)
}

capture_kms_unknown(rc) if {
	some u in object.get(lib.after_unknown(rc), "data_capture_config", [])
	object.get(u, "kms_key_id", false) == true
}

findings contains lib.finding(rc, "AIS-AWS-SM-02", "7.5", "warn", "Data capture is not configured; inference inputs/outputs cannot be monitored or used to reconstruct incidents") if {
	some rc in lib.of_type("aws_sagemaker_endpoint_configuration")
	not lib.has_block(rc, "data_capture_config")
}

# AIS-AWS-SM-03: model containers are network-isolated (a backdoored model cannot call out)
findings contains lib.finding(rc, "AIS-AWS-SM-03", "5.3, B.4", "warn", "Model container is not network-isolated (enable_network_isolation)") if {
	some rc in lib.of_type("aws_sagemaker_model")
	not lib.attr(rc, "enable_network_isolation", false) == true
}

findings contains lib.finding(rc, "AIS-AWS-SM-03", "5.3", "warn", "Model is not deployed into a VPC (vpc_config)") if {
	some rc in lib.of_type("aws_sagemaker_model")
	not lib.has_block(rc, "vpc_config")
}

# AIS-AWS-SM-04: notebook instances (the development environment) are locked down
findings contains lib.finding(rc, "AIS-AWS-SM-04", "7.6", "deny", "Notebook instance has direct internet access (direct_internet_access defaults to Enabled)") if {
	some rc in lib.of_type("aws_sagemaker_notebook_instance")
	lib.attr(rc, "direct_internet_access", "Enabled") != "Disabled"
}

findings contains lib.finding(rc, "AIS-AWS-SM-04", "7.6, B.6.4", "deny", "Notebook instance storage is not encrypted with a KMS key (kms_key_id)") if {
	some rc in lib.of_type("aws_sagemaker_notebook_instance")
	not lib.present(rc, "kms_key_id")
}

findings contains lib.finding(rc, "AIS-AWS-SM-04", "7.6", "warn", "Notebook users have root access (root_access defaults to Enabled)") if {
	some rc in lib.of_type("aws_sagemaker_notebook_instance")
	lib.attr(rc, "root_access", "Enabled") != "Disabled"
}
