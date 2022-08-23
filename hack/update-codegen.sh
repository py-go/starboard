#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bash vendor/k8s.io/code-generator/generate-groups.sh all \
  github.com/danielpacak/kube-security-manager/pkg/generated \
  github.com/danielpacak/kube-security-manager/pkg/apis \
  aquasecurity:v1alpha1 \
  --output-base "${GOPATH}/src" \
  --go-header-file "hack/boilerplate.go.txt"
