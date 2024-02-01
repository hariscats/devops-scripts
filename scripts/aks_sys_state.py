from kubernetes import client, config
import sys

def connect_to_cluster():
    # Load kubeconfig and initialize K8s client
    config.load_kube_config()
    return client.CoreV1Api()

def check_nodes(v1):
    print("Checking node statuses...")
    nodes = v1.list_node().items
    for node in nodes:
        for condition in node.status.conditions:
            if condition.type == 'Ready' and condition.status != 'True':
                print(f"Warning: Node {node.metadata.name} is not in Ready state.")
                return False
    return True
