#!/bin/bash

# Script to check for common security misconfigurations in a Kubernetes cluster

# Function to log messages
log() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check for pods running with root privileges
check_root_privileges() {
  log "Checking for pods running with root privileges..."
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] |
    select(.spec.containers[].securityContext.runAsUser == null or .spec.containers[].securityContext.runAsUser == 0) |
    "\(.metadata.namespace) \(.metadata.name)"' | while read -r namespace pod; do
      log "Pod $pod in namespace $namespace is running as root"
  done
}

# Function to check for pods without resource limits
check_resource_limits() {
  log "Checking for pods without resource limits..."
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] |
    .metadata.namespace as $namespace |
    .metadata.name as $pod |
    .spec.containers[] |
    select((.resources.limits.cpu == null) or (.resources.limits.memory == null)) |
    "\($namespace) \($pod)"' | while read -r namespace pod; do
      log "Pod $pod in namespace $namespace does not have resource limits set"
  done
}

# Function to check for services with external exposure
check_external_services() {
  log "Checking for services with external exposure..."
  kubectl get svc --all-namespaces -o json | jq -r '
    .items[] |
    select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") |
    "\(.metadata.namespace) \(.metadata.name) \(.spec.type)"' | while read -r namespace service type; do
      log "Service $service in namespace $namespace is exposed externally as $type"
  done
}

# Function to check for configurations allowing privilege escalation
check_privilege_escalation() {
  log "Checking for privilege escalation configurations..."
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] |
    .metadata.namespace as $namespace |
    .metadata.name as $pod |
    .spec.containers[] |
    select(.securityContext.allowPrivilegeEscalation == null or .securityContext.allowPrivilegeEscalation == true) |
    "\($namespace) \($pod)"' | while read -r namespace pod; do
      log "Pod $pod in namespace $namespace allows privilege escalation"
  done
}

# Function to check for unencrypted secrets
check_unencrypted_secrets() {
  log "Checking for unencrypted secrets..."
  kubectl get secrets --all-namespaces -o json | jq -r '
    .items[] |
    select(.type != "kubernetes.io/service-account-token") |
    .data | keys[] as $k |
    "\(.metadata.namespace) \(.metadata.name) \($k)"' | while read -r namespace secret key; do
      log "Secret $secret in namespace $namespace contains key $key which may be unencrypted"
  done
}

# Main function to run all checks
run_checks() {
  check_root_privileges
  echo
  check_resource_limits
  echo
  check_external_services
  echo
  check_privilege_escalation
  echo
  check_unencrypted_secrets
}

# Run all checks
log "Starting security checks for Kubernetes cluster"
run_checks
log "Security checks completed"
