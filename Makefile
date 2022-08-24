# Set the default goal
.DEFAULT_GOAL := build
MAKEFLAGS += --no-print-directory

BIN := bin

GO ?= go
DOCKER ?= docker
KIND ?= kind

export KUBECONFIG ?= ${HOME}/.kube/config

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GINKGO=$(GOBIN)/ginkgo

SOURCES := $(shell find . -name '*.go')

IMAGE_TAG := dev
IMAGE_NAME := docker.io/danielpacak/kube-security-manager:$(IMAGE_TAG)

MKDOCS_IMAGE_REF := mkdocs-material:kube-security-manager
MKDOCS_PORT := 8000

$(BIN):
	$(Q)mkdir -p $@

$(BIN)/kube-security-manager: $(SOURCES) | $(BIN)
	CGO_ENABLED=0 GOOS=linux $(GO) build -o $@ ./cmd/security-manager/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	$(GO) install github.com/onsi/ginkgo/ginkgo

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	$(GO) test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: itests-starboard-operator
## Runs integration tests for Starboard Operator with code coverage enabled
itests-starboard-operator: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/operator,\
	github.com/aquasecurity/starboard/pkg/operator/predicate,\
	github.com/aquasecurity/starboard/pkg/operator/controller,\
	github.com/aquasecurity/starboard/pkg/plugin,\
	github.com/aquasecurity/starboard/pkg/plugin/trivy,\
	github.com/aquasecurity/starboard/pkg/plugin/polaris,\
	github.com/aquasecurity/starboard/pkg/plugin/conftest,\
	github.com/aquasecurity/starboard/pkg/configauditreport,\
	github.com/aquasecurity/starboard/pkg/vulnerabilityreport,\
	github.com/aquasecurity/starboard/pkg/kubebench \
	./itest/starboard-operator

.PHONY: check-kubeconfig
check-kubeconfig:
ifndef KUBECONFIG
	$(error Environment variable KUBECONFIG is not set)
else
	@echo "KUBECONFIG=${KUBECONFIG}"
endif

## Removes build artifacts
clean:
	@rm -r ./bin 2> /dev/null || true
	@rm -r ./dist 2> /dev/null || true

.PHONY: docker-build
docker-build: $(BIN)/kube-security-manager
	$(DOCKER) image build --no-cache -t $(IMAGE_NAME) -f build/security-manager/Dockerfile bin

.PHONY: kind-load-images
kind-load-images: docker-build
	$(KIND) load docker-image $(IMAGE_NAME)

## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	$(DOCKER) image build -t $(MKDOCS_IMAGE_REF) -f build/mkdocs-material/Dockerfile bin
	$(DOCKER) container run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE_REF)

.PHONY: \
	clean \
	mkdocs-serve
