#!/bin/bash

# Script to scrape error messages from Kubernetes pod logs.

# Variables
NAMESPACE=${1:-default} # Default namespace is "default" if not provided
KEYWORD=${2:-"error"}   # Default keyword to search for is "error"
OUTPUT_FILE="pod_error_logs.txt"

# Start script
echo "Scraping logs for namespace: $NAMESPACE and searching for keyword: $KEYWORD"

# Clean up any old logs
if [ -f "$OUTPUT_FILE" ]; then
  echo "Cleaning up old log file: $OUTPUT_FILE"
  rm "$OUTPUT_FILE"
fi

# Get all pod names in the namespace
PODS=$(kubectl get pods -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}')

if [ -z "$PODS" ]; then
  echo "No pods found in namespace: $NAMESPACE"
  exit 1
fi

# Loop through each pod and scrape logs
for POD in $PODS; do
  echo "Processing pod: $POD"

  # Get the logs for the pod
  LOGS=$(kubectl logs -n $NAMESPACE $POD 2>/dev/null)

  # Filter logs for the keyword and append to output file
  if echo "$LOGS" | grep -i "$KEYWORD" > /dev/null; then
    echo "Errors found in pod: $POD. Adding to log file."
    echo "---- Logs for pod: $POD ----" >> $OUTPUT_FILE
    echo "$LOGS" | grep -i "$KEYWORD" >> $OUTPUT_FILE
    echo "-----------------------------" >> $OUTPUT_FILE
  else
    echo "No errors found in pod: $POD"
  fi
done

echo "Log scraping completed. Output written to $OUTPUT_FILE"
