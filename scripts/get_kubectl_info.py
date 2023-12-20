import subprocess
import json

def run_kubectl_command(command):
    """
    Run a kubectl command and return the output
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()

    if process.returncode != 0:
        print(f"Error: {error.decode().strip()}")
        return None
    return output.decode().strip()

def get_kubectl_version():
    """
    Get the version information of kubectl
    """
    command = "kubectl version --client -o json"
    output = run_kubectl_command(command)
    if output:
        version_info = json.loads(output)
        print("kubectl Version Information:")
        print(json.dumps(version_info, indent=4))

def get_cluster_info():
    """
    Get the cluster information
    """
    command = "kubectl cluster-info"
    output = run_kubectl_command(command)
    if output:
        print("Cluster Information:")
        print(output)

def get_api_resources():
    """
    Get the available API resources in the cluster
    """
    command = "kubectl api-resources"
    output = run_kubectl_command(command)
    if output:
        print("API Resources:")
        print(output)

# Example usage
get_kubectl_version()
get_cluster_info()
get_api_resources()
