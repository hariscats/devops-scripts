#!/bin/bash

# Script to monitor CPU and memory usage, resource requests and limits of all pods,
# and allocatable capacity of nodes in a given namespace

# Function to log messages
log() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Check if namespace is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <namespace>"
  exit 1
fi

NAMESPACE=$1

# Function to get actual resource usage for all pods in the namespace
get_actual_resource_usage() {
  kubectl top pod -n $NAMESPACE --no-headers | awk '{print $1, $2, $3}'
}

# Function to get resource requests and limits for all pods in the namespace
get_requests_and_limits() {
  kubectl get pods -n $NAMESPACE -o json | jq -r '
    .items[] |
    .metadata.name as $name |
    .spec.containers[] |
    [$name, .resources.requests.cpu, .resources.requests.memory, .resources.limits.cpu, .resources.limits.memory] |
    @tsv' | column -t
}

# Function to get allocatable capacity of nodes
get_allocatable_capacity() {
  kubectl get nodes -o json | jq -r '
    .items[] |
    .metadata.name as $name |
    .status.allocatable |
    [$name, .cpu, .memory] |
    @tsv' | column -t
}

# Function to get detailed resource usage
get_detailed_resource_usage() {
  echo "Pod Name  CPU Usage  Memory Usage  CPU Request  Memory Request  CPU Limit  Memory Limit"
  paste <(kubectl top pod -n $NAMESPACE --no-headers | awk '{print $1, $2, $3}') \
        <(kubectl get pods -n $NAMESPACE -o json | jq -r '
          .items[] |
          .metadata.name as $name |
          .spec.containers[] |
          [$name, .resources.requests.cpu // "none", .resources.requests.memory // "none", .resources.limits.cpu // "none", .resources.limits.memory // "none"] |
          @tsv' | sort)
}

# Log initial resource usage
log "Initial resource usage for namespace: $NAMESPACE"
get_detailed_resource_usage
echo

# Log node allocatable capacity
log "Allocatable capacity of nodes:"
get_allocatable_capacity
echo

# Monitor resource usage in a loop
while true; do
  log "Monitoring resource usage for namespace: $NAMESPACE"
  get_actual_resource_usage
  echo
  sleep 60  # Adjust the sleep duration as needed
done
