"""
Purpose: Extract and Display K8s Cluster CA Certificate

This script is designed to assist InfoSec and DevOps engineers when integrating services or setting up secure connections between different parts of your infrastructure and the Kubernetes API server, it is often necessary to have the cluster's CA certificate. This script automates the process of extracting this certificate from a specified kubeconfig file, which is particularly useful in environments where multiple clusters are managed, and manual verification of secure communication channels is required. By providing a straightforward method to retrieve and decode the CA certificate, this script facilitates easier setup of secure connections and aids in the quick validation of the cluster's identity, enhancing security and efficiency in Kubernetes cluster management.

Usage:
- Ensure you have a valid kubeconfig file for the AKS cluster you wish to extract the CA certificate from.
- Update the 'kubeconfig_path' variable in the script to point to your kubeconfig file.
- Run the script. The decoded CA certificate will be printed to the console.
"""

import base64
from kubernetes import config
from kubernetes.config.kube_config import KubeConfigLoader
import yaml

# Specify the path to your kubeconfig file
kubeconfig_path = r'C:\path\to\your\kubeconfig'

# Load the kubeconfig file manually
with open(kubeconfig_path, 'r') as f:
    kubeconfig_data = yaml.safe_load(f)

# Extract the current context name
current_context_name = kubeconfig_data['current-context']

# Find the cluster name from the current context
cluster_name = None
for context in kubeconfig_data['contexts']:
    if context['name'] == current_context_name:
        cluster_name = context['context']['cluster']
        break

# Extract the CA certificate data for the cluster
ca_certificate_data = None
for cluster in kubeconfig_data['clusters']:
    if cluster['name'] == cluster_name:
        ca_certificate_data = cluster['cluster']['certificate-authority-data']
        break

if ca_certificate_data:
    # Decode and print the CA certificate
    decoded_ca_certificate = base64.b64decode(ca_certificate_data).decode('utf-8')
    print("Decoded CA Certificate:")
    print(decoded_ca_certificate)
else:
    print("CA certificate not found for the cluster.")
