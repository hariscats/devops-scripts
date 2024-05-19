#!/usr/bin/env python3

from kubernetes import client, config
import sys

def connect_to_cluster():
    # Load kubeconfig and initialize K8s client
    config.load_kube_config()
    return client.CoreV1Api()

def check_nodes(v1):
    """
    Checks the status of all nodes in the Kubernetes cluster.
    Iterates through each node in the cluster and checks its 'Ready' condition. 
    If any node is not in 'Ready' state, it's considered as a potential issue.
    
    Args:
        v1 (client.CoreV1Api): An instance of the CoreV1Api client to interact with Kubernetes.

    Returns:
        bool: True if all nodes are in 'Ready' state, False otherwise.
    """
    print("Checking node statuses...")
    nodes = v1.list_node().items
    for node in nodes:
        for condition in node.status.conditions:
            if condition.type == 'Ready' and condition.status != 'True':
                print(f"Warning: Node {node.metadata.name} is not in Ready state.")
                return False
    return True

def check_system_pods(v1):
    """
    Checks the status of system pods in the 'kube-system' namespace.

    Iterates through the pods in the 'kube-system' namespace and checks their phase.
    If any system pod is not in 'Running' or 'Succeeded' phase, it's flagged as an issue.

    Args:
        v1 (client.CoreV1Api): An instance of the CoreV1Api client to interact with Kubernetes.

    Returns:
        bool: True if all system pods are in expected state, False otherwise.
    """
    print("Checking system pods in kube-system namespace...")
    pods = v1.list_namespaced_pod(namespace="kube-system").items
    for pod in pods:
        if pod.status.phase not in ['Running', 'Succeeded']:
            print(f"Warning: System Pod {pod.metadata.name} is not running as expected.")
            return False
    return True

def main():
    v1 = connect_to_cluster()

    if not check_nodes(v1):
        sys.exit("Node check failed. Control plane might be unhealthy.")

    if not check_system_pods(v1):
        sys.exit("System pods check failed. Control plane might be unhealthy.")

    print("AKS cluster control plane appears to be healthy.")

if __name__ == "__main__":
    main()
