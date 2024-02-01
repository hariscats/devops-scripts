from kubernetes import client, config
import sys

def connect_to_cluster():
    # Load kubeconfig and initialize K8s client
    config.load_kube_config()
    return client.CoreV1Api()
