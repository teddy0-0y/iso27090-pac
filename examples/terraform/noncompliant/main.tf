# The same workload built "the fast way". Every resource uses provider
# defaults or shortcuts that the AWS policies reject. plan.json in this folder
# is the matching `terraform show -json` output.

resource "aws_s3_bucket" "scratch" {
  bucket_prefix = "ml-scratch-"
}

# --- IAM -------------------------------------------------------------------

resource "aws_iam_role" "ml" {
  name = "ml-everything"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = ["sagemaker.amazonaws.com", "bedrock.amazonaws.com"] }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ml_full" {
  role       = aws_iam_role.ml.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role_policy" "ml" {
  name = "ml-inline"
  role = aws_iam_role.ml.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["sagemaker:*", "s3:GetObject"], Resource = "*" },
      { Effect = "Allow", Action = "iam:PassRole", Resource = "*" },
      { Effect = "Allow", Action = ["cloudtrail:StopLogging", "bedrock:DeleteGuardrail"], Resource = "*" }
    ]
  })
}

# Policy JSON depends on a bucket ARN that only exists after apply
resource "aws_iam_policy" "scratch_access" {
  name = "ml-scratch-access"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "${aws_s3_bucket.scratch.arn}/*" }]
  })
}

# --- SageMaker -------------------------------------------------------------

resource "aws_sagemaker_model" "fraud" {
  name               = "fraud-gbm-v7"
  execution_role_arn = aws_iam_role.ml.arn
  primary_container {
    image          = "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1"
    model_data_url = "s3://acme-ai-training-data/models/fraud/model.tar.gz"
  }
}

resource "aws_sagemaker_endpoint_configuration" "fraud" {
  name = "fraud-gbm-v7"
  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.fraud.name
    initial_instance_count = 1
    instance_type          = "ml.m5.large"
  }
  data_capture_config {
    enable_capture              = true
    initial_sampling_percentage = 100
    destination_s3_uri          = "s3://acme-ai-inference-capture/fraud"
    capture_options { capture_mode = "Input" }
  }
}

resource "aws_sagemaker_notebook_instance" "research" {
  name          = "fraud-research"
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.ml.arn
}

# --- Bedrock ---------------------------------------------------------------

resource "aws_bedrock_guardrail" "copilot" {
  name                      = "support-copilot"
  blocked_input_messaging   = "Blocked."
  blocked_outputs_messaging = "Blocked."
  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "LOW"
      output_strength = "NONE"
    }
  }
}

resource "aws_bedrockagent_agent" "copilot" {
  agent_name              = "support-copilot"
  agent_resource_role_arn = aws_iam_role.ml.arn
  foundation_model        = "anthropic.claude-sonnet-4-5-v1:0"
}

resource "aws_bedrock_custom_model" "tuned" {
  custom_model_name     = "support-tuned"
  job_name              = "support-tuning-1"
  base_model_identifier = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1"
  role_arn              = aws_iam_role.ml.arn
  customization_type    = "FINE_TUNING"
  hyperparameters       = { epochCount = "2", batchSize = "1", learningRate = "0.00001" }
  training_data_config { s3_uri = "s3://acme-ai-training-data/tickets.jsonl" }
  output_data_config { s3_uri = "s3://acme-ai-training-data/output/" }
}

# --- CloudTrail ------------------------------------------------------------

resource "aws_cloudtrail" "ai" {
  name           = "ai-workloads"
  s3_bucket_name = "acme-cloudtrail-logs"
  enable_logging = false
}
