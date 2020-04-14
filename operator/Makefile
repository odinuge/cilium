# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs

TARGETS := cilium-operator cilium-operator-none cilium-operator-aws cilium-operator-azure

.PHONY: $(TARGETS)
all: $(TARGETS)

cilium-operator: OPERATOR_TAGS=operator_aws,operator_azure
cilium-operator-none: OPERATOR_TAGS=""
cilium-operator-aws: OPERATOR_TAGS=operator_aws
cilium-operator-azure: OPERATOR_TAGS=operator_azure

$(TARGETS):
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -tags $(OPERATOR_TAGS) -o $(@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGETS)
	$(GO) clean $(GOCLEAN)
