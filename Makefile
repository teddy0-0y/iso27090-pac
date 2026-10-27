POLICY := policy
OPA ?= opa
CONFTEST ?= conftest
TERRAFORM ?= terraform
TF_EXAMPLES := examples/terraform

.PHONY: all fmt lint test check check-aws demo demo-aws report report-aws plan

all: lint test check check-aws

fmt:
	$(OPA) fmt -w $(POLICY)

lint:
	$(OPA) fmt --list --fail $(POLICY)
	$(OPA) check --strict $(POLICY)

test:
	$(OPA) test $(POLICY) --coverage --threshold 90 --format=json > /dev/null
	$(OPA) test $(POLICY)

# --- AI system manifests (namespace: main) ---------------------------------

check:
	$(CONFTEST) test -p $(POLICY) examples/compliant/

demo:
	-$(CONFTEST) test -p $(POLICY) examples/noncompliant/

# make report FILE=examples/compliant/fraud-scoring.yaml
report:
	$(OPA) eval -d $(POLICY) -i $(FILE) --format=pretty data.main.report

# --- Terraform plans for AWS AI resources (namespace: aws) -----------------

check-aws:
	$(CONFTEST) test -p $(POLICY) --namespace aws $(TF_EXAMPLES)/compliant/plan.json

demo-aws:
	-$(CONFTEST) test -p $(POLICY) --namespace aws $(TF_EXAMPLES)/noncompliant/plan.json

# make report-aws FILE=examples/terraform/noncompliant/plan.json
report-aws:
	$(OPA) eval -d $(POLICY) -i $(FILE) --format=pretty data.aws.report

# Generate a real plan offline (mock credentials, never applies):
#   make plan EX=noncompliant
# Writes examples/terraform/$(EX)/plan.real.json and checks it.
plan:
	cp $(TF_EXAMPLES)/providers.tf.example $(TF_EXAMPLES)/$(EX)/providers.tf
	cd $(TF_EXAMPLES)/$(EX) && $(TERRAFORM) init -input=false -no-color > /dev/null \
		&& $(TERRAFORM) plan -input=false -refresh=false -out=tfplan -no-color > /dev/null \
		&& $(TERRAFORM) show -json tfplan > plan.real.json
	-$(CONFTEST) test -p $(POLICY) --namespace aws $(TF_EXAMPLES)/$(EX)/plan.real.json
