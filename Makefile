# Set the default goal
.DEFAULT_GOAL := build
MAKEFLAGS += --no-print-directory

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
STARBOARD_CLI_IMAGE := aquasec/starboard:$(IMAGE_TAG)
STARBOARD_OPERATOR_IMAGE := aquasec/starboard-operator:$(IMAGE_TAG)
STARBOARD_SCANNER_AQUA_IMAGE := aquasec/starboard-scanner-aqua:$(IMAGE_TAG)
STARBOARD_OPERATOR_IMAGE_UBI8 := aquasec/starboard-operator:$(IMAGE_TAG)-ubi8

MKDOCS_IMAGE := aquasec/mkdocs-material:starboard
MKDOCS_PORT := 8000

.PHONY: all
all: build

.PHONY: build
build: build-starboard-operator

## Builds the starboard-operator binary
build-starboard-operator: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-operator ./cmd/security-manager/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	@go install github.com/onsi/ginkgo/ginkgo

.PHONY: test
## Runs both unit and integration tests
test: unit-tests itests-starboard-operator

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

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

## Builds Docker images for all binaries
docker-build: \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8

## Builds Docker image for Starboard operator
docker-build-starboard-operator: build-starboard-operator
	$(DOCKER) build --no-cache -t $(STARBOARD_OPERATOR_IMAGE) -f build/starboard-operator/Dockerfile bin
	
## Builds Docker image for Starboard operator ubi8
docker-build-starboard-operator-ubi8: build-starboard-operator
	$(DOCKER) build --no-cache -f build/starboard-operator/Dockerfile.ubi8 -t $(STARBOARD_OPERATOR_IMAGE_UBI8) bin

kind-load-images: \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8
	$(KIND) load docker-image \
		$(STARBOARD_OPERATOR_IMAGE) \
		$(STARBOARD_OPERATOR_IMAGE_UBI8)

## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	$(DOCKER) build -t $(MKDOCS_IMAGE) -f build/mkdocs-material/Dockerfile bin
	$(DOCKER) run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

.PHONY: \
	clean \
	docker-build \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8 \
	kind-load-images \
	mkdocs-serve
