#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/crd
STATIC_DIR=$SCRIPT_ROOT/deploy/static

cat $CRD_DIR/vulnerabilityreports.crd.yaml \
  $CRD_DIR/configauditreports.crd.yaml \
  $CRD_DIR/clusterconfigauditreports.crd.yaml \
  $CRD_DIR/ciskubebenchreports.crd.yaml \
  $STATIC_DIR/01-starboard-operator.ns.yaml \
  $STATIC_DIR/02-starboard-operator.rbac.yaml \
  $STATIC_DIR/03-starboard-operator.config.yaml \
  $STATIC_DIR/04-starboard-operator.policies.yaml \
  $STATIC_DIR/05-starboard-operator.deployment.yaml > $STATIC_DIR/starboard.yaml
