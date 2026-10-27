# A fraud-scoring SageMaker endpoint and a Bedrock support agent, configured
# to pass every AWS control. plan.json in this folder is the matching
# `terraform show -json` output.

locals {
  account_id     = "111122223333"
  training_data  = "arn:aws:s3:::acme-ai-training-data"
  subnets        = ["subnet-0aaa1111bbbb2222c"]
  security_group = ["sg-0123456789abcdef0"]
}

resource "aws_kms_key" "ai" {
  description         = "CMK for AI workloads"
  enable_key_rotation = true
}

# --- SageMaker -------------------------------------------------------------

resource "aws_iam_role" "sagemaker_exec" {
  name = "fraud-model-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "sagemaker_exec" {
  name = "read-model-artifacts"
  role = aws_iam_role.sagemaker_exec.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["${local.training_data}/models/fraud/*"]
    }]
  })
}

resource "aws_sagemaker_model" "fraud" {
  name                     = "fraud-gbm-v7"
  execution_role_arn       = aws_iam_role.sagemaker_exec.arn
  enable_network_isolation = true
  primary_container {
    image          = "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1"
    model_data_url = "s3://acme-ai-training-data/models/fraud/model.tar.gz"
  }
  vpc_config {
    subnets            = local.subnets
    security_group_ids = local.security_group
  }
}

resource "aws_sagemaker_endpoint_configuration" "fraud" {
  name        = "fraud-gbm-v7"
  kms_key_arn = aws_kms_key.ai.arn
  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.fraud.name
    initial_instance_count = 2
    instance_type          = "ml.m5.large"
  }
  data_capture_config {
    enable_capture              = true
    initial_sampling_percentage = 100
    destination_s3_uri          = "s3://acme-ai-inference-capture/fraud"
    kms_key_id                  = aws_kms_key.ai.arn
    capture_options { capture_mode = "Input" }
    capture_options { capture_mode = "Output" }
  }
}

resource "aws_sagemaker_endpoint" "fraud" {
  name                 = "fraud-gbm"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.fraud.name
}

resource "aws_sagemaker_notebook_instance" "research" {
  name                   = "fraud-research"
  instance_type          = "ml.t3.medium"
  role_arn               = aws_iam_role.sagemaker_exec.arn
  kms_key_id             = aws_kms_key.ai.arn
  direct_internet_access = "Disabled"
  root_access            = "Disabled"
  subnet_id              = local.subnets[0]
  security_groups        = local.security_group
}

# --- Bedrock ---------------------------------------------------------------

resource "aws_bedrock_guardrail" "copilot" {
  name                      = "support-copilot"
  blocked_input_messaging   = "Sorry, I can't help with that request."
  blocked_outputs_messaging = "Sorry, I can't share that."
  kms_key_arn               = aws_kms_key.ai.arn

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type   = "US_SOCIAL_SECURITY_NUMBER"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }
  }
}

resource "aws_iam_role" "bedrock_agent" {
  name = "support-copilot-agent"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_agent" {
  name = "invoke-model"
  role = aws_iam_role.bedrock_agent.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-v1:0"]
    }]
  })
}

resource "aws_bedrockagent_agent" "copilot" {
  agent_name                  = "support-copilot"
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  foundation_model            = "anthropic.claude-sonnet-4-5-v1:0"
  customer_encryption_key_arn = aws_kms_key.ai.arn
  idle_session_ttl_in_seconds = 600
  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.copilot.guardrail_id
    guardrail_version    = "DRAFT"
  }
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled      = true
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    s3_config {
      bucket_name = "acme-ai-invocation-logs"
      key_prefix  = "bedrock"
    }
  }
}

# --- CloudTrail ------------------------------------------------------------

resource "aws_cloudtrail" "ai" {
  name                       = "ai-workloads"
  s3_bucket_name             = "acme-cloudtrail-logs"
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.ai.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${local.training_data}/"]
    }
  }
}
