#!/usr/bin/env python3
"""
Author : Hariscats
Date   : 2023-06-18
Purpose: Docker utilities for everyday DevOps tasks:
         - List containers with resource usage
         - Find and remove dangling images and volumes
         - Clean up Docker system
         - Monitor container health and logs
         - Export/import Docker images

Requires Docker CLI to be installed and accessible
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time
from collections import defaultdict


class DockerUtils:
    """Docker utility functions for common DevOps tasks"""

    @staticmethod
    def run_command(command):
        """Run a Docker command and return the output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")
            print(f"STDERR: {e.stderr.strip()}")
            return None

    def check_docker_installed(self):
        """Check if Docker is installed and accessible"""
        version = self.run_command("docker --version")
        if not version:
            print("Docker is not installed or not accessible.")
            return False
        print(f"Using {version}")
        return True

    def list_containers(self, all_containers=False, format_json=False):
        """List running or all containers with resource usage"""
        if not self.check_docker_installed():
            return

        all_flag = "-a" if all_containers else ""

        if format_json:
            # Get container details in JSON format
            command = f"docker ps {all_flag} --format '{{{{json .}}}}'"
            output = self.run_command(command)
            if output:
                containers = []
                for line in output.splitlines():
                    if line.strip():
                        containers.append(json.loads(line.strip()))
                return containers
        else:
            # Get container details with stats
            containers = []

            # Get container IDs
            command = f"docker ps {all_flag} --format '{{{{.ID}}}}'"
            output = self.run_command(command)
            if not output:
                return []

            container_ids = output.splitlines()

            for container_id in container_ids:
                # Get container details
                details_cmd = f"docker ps {all_flag} --filter id={container_id} --format '{{{{.ID}}}}|{{{{.Names}}}}|{{{{.Image}}}}|{{{{.Status}}}}|{{{{.RunningFor}}}}|{{{{.Size}}}}'"
                details = self.run_command(details_cmd)

                if not details:
                    continue

                # Get container stats
                stats_cmd = f"docker stats --no-stream {container_id} --format '{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.NetIO}}}}|{{{{.BlockIO}}}}'"
                stats = self.run_command(stats_cmd)

                if not stats:
                    stats = "N/A|N/A|N/A|N/A|N/A"

                id, name, image, status, running, size = details.split("|")
                cpu, mem_usage, mem_perc, net_io, block_io = stats.split("|")

                container = {
                    "ID": id,
                    "Name": name,
                    "Image": image,
                    "Status": status,
                    "Running For": running,
                    "Size": size,
                    "CPU %": cpu,
                    "Memory Usage": mem_usage,
                    "Memory %": mem_perc,
                    "Network I/O": net_io,
                    "Block I/O": block_io,
                }
                containers.append(container)

            return containers

    def find_dangling_images(self):
        """Find and list dangling images (untagged images)"""
        if not self.check_docker_installed():
            return []

        command = "docker images -f 'dangling=true' --format '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedSince}}'"
        output = self.run_command(command)

        if not output:
            return []

        dangling_images = []
        for line in output.splitlines():
            if line.strip():
                id, repo, tag, size, created = line.split("|")
                dangling_images.append(
                    {"ID": id, "Repository": repo, "Tag": tag, "Size": size, "Created": created}
                )

        return dangling_images

    def find_dangling_volumes(self):
        """Find and list dangling volumes"""
        if not self.check_docker_installed():
            return []

        command = (
            "docker volume ls -f 'dangling=true' --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}'"
        )
        output = self.run_command(command)

        if not output:
            return []

        dangling_volumes = []
        for line in output.splitlines():
            if line.strip():
                parts = line.split("|")
                if len(parts) >= 2:  # Some formats might not have all fields
                    name = parts[0]
                    driver = parts[1]
                    mountpoint = parts[2] if len(parts) > 2 else "N/A"

                    dangling_volumes.append(
                        {"Name": name, "Driver": driver, "Mountpoint": mountpoint}
                    )

        return dangling_volumes

    def clean_docker(self, prune_all=False, prune_volumes=False):
        """Clean up Docker system (containers, images, networks, volumes)"""
        if not self.check_docker_installed():
            return False

        if prune_all:
            print("Pruning all unused Docker objects...")
            result = self.run_command("docker system prune -af")
            print(result)
        else:
            print("Pruning unused containers, networks, and images...")
            result = self.run_command("docker system prune -f")
            print(result)

        if prune_volumes:
            print("Pruning unused volumes...")
            result = self.run_command("docker volume prune -f")
            print(result)

        return True

    def remove_dangling_images(self):
        """Remove all dangling images"""
        if not self.check_docker_installed():
            return False

        dangling_images = self.find_dangling_images()
        if not dangling_images:
            print("No dangling images found.")
            return True

        print(f"Removing {len(dangling_images)} dangling images...")
        result = self.run_command("docker rmi $(docker images -f 'dangling=true' -q)")
        print(result if result else "Images removed successfully.")
        return True

    def remove_dangling_volumes(self):
        """Remove all dangling volumes"""
        if not self.check_docker_installed():
            return False

        dangling_volumes = self.find_dangling_volumes()
        if not dangling_volumes:
            print("No dangling volumes found.")
            return True

        print(f"Removing {len(dangling_volumes)} dangling volumes...")
        result = self.run_command("docker volume rm $(docker volume ls -f 'dangling=true' -q)")
        print(result if result else "Volumes removed successfully.")
        return True

    def monitor_container(self, container_name, duration_seconds=60, interval_seconds=5):
        """Monitor a specific container's health and resource usage"""
        if not self.check_docker_installed():
            return

        # Check if container exists
        command = f"docker ps -a --filter name={container_name} --format '{{{{.Names}}}}'"
        output = self.run_command(command)

        if not output:
            print(f"Container '{container_name}' not found.")
            return

        print(
            f"Monitoring container '{container_name}' for {duration_seconds} seconds (interval: {interval_seconds}s)..."
        )

        end_time = time.time() + duration_seconds

        while time.time() < end_time:
            # Clear screen
            os.system("cls" if os.name == "nt" else "clear")  # nosec

            # Get container stats
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H: %M: %S")
            print(f"Container Monitor - {container_name} - {timestamp}")
            print("=" * 80)

            # Get container basic info
            info_cmd = f"docker ps -a --filter name={container_name} --format '{{{{.ID}}}}|{{{{.Status}}}}|{{{{.Image}}}}|{{{{.RunningFor}}}}'"
            info = self.run_command(info_cmd)

            if info:
                id, status, image, running = info.split("|")
                print(f"ID: {id}")
                print(f"Status: {status}")
                print(f"Image: {image}")
                print(f"Running For: {running}")

            # Get container stats
            stats_cmd = f"docker stats --no-stream {container_name} --format 'CPU: {{{{.CPUPerc}}}} | Memory: {{{{.MemUsage}}}} ({{{{.MemPerc}}}}) | Net I/O: {{{{.NetIO}}}} | Block I/O: {{{{.BlockIO}}}}'"
            stats = self.run_command(stats_cmd)

            print("\nResource Usage: ")
            print(stats if stats else "N/A")

            # Get latest logs
            print("\nLatest Logs: ")
            logs_cmd = f"docker logs {container_name} --tail 10"
            logs = self.run_command(logs_cmd)

            print(logs if logs else "No logs available.")

            # Sleep before next update
            print(f"\nUpdating in {interval_seconds} seconds...")
            time.sleep(interval_seconds)

    def export_image(self, image_name, output_path):
        """Export a Docker image to a tar file"""
        if not self.check_docker_installed():
            return False

        # Check if image exists
        command = f"docker images {image_name} --format '{{{{.Repository}}}}: {{{{.Tag}}}}'"
        output = self.run_command(command)

        if not output:
            print(f"Image '{image_name}' not found.")
            return False

        # Add .tar extension if not provided
        if not output_path.endswith(".tar"):
            output_path += ".tar"

        print(f"Exporting image '{image_name}' to '{output_path}'...")
        result = self.run_command(f"docker save -o {output_path} {image_name}")

        if os.path.exists(output_path):
            print(f"Image exported successfully to {output_path}")
            return True
        else:
            print("Failed to export image.")
            return False

    def import_image(self, tar_path):
        """Import a Docker image from a tar file"""
        if not self.check_docker_installed():
            return False

        if not os.path.exists(tar_path):
            print(f"File '{tar_path}' not found.")
            return False

        print(f"Importing image from '{tar_path}'...")
        result = self.run_command(f"docker load -i {tar_path}")

        print(result)
        return "Loaded image" in result

    def show_docker_disk_usage(self):
        """Show Docker disk usage"""
        if not self.check_docker_installed():
            return

        print("Docker Disk Usage: ")
        print("=" * 80)

        result = self.run_command("docker system df -v")
        print(result)


def print_table(items, header=None):
    """Print data in a tabular format"""
    if not items:
        print("No data to display.")
        return

    # If items is a list of dictionaries
    if isinstance(items[0], dict):
        # Get all keys from all dictionaries
        all_keys = set()
        for item in items:
            all_keys.update(item.keys())

        # Use provided header or keys from dictionaries
        if not header:
            header = list(all_keys)

        # Calculate column widths
        col_widths = [len(str(col)) for col in header]

        for item in items:
            for i, col in enumerate(header):
                # Ensure column width is at least as wide as the longest value
                if col in item:
                    col_widths[i] = max(col_widths[i], len(str(item.get(col, ""))))

        # Print header
        header_str = " | ".join(f"{col: {col_widths[i]}}" for i, col in enumerate(header))
        print(header_str)
        print("-" * len(header_str))

        # Print rows
        for item in items:
            row = []
            for i, col in enumerate(header):
                value = item.get(col, "")
                row.append(f"{str(value): {col_widths[i]}}")
            print(" | ".join(row))

    # If items is a list of strings
    elif isinstance(items[0], str):
        for item in items:
            print(item)


def main():
    """Main function to parse arguments and execute commands"""
    parser = argparse.ArgumentParser(description="Docker utilities for everyday DevOps tasks")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List containers command
    list_parser = subparsers.add_parser("list", help="List containers with resource usage")
    list_parser.add_argument(
        "-a", "--all", action="store_true", help="Show all containers (default: running only)"
    )

    # Clean command
    clean_parser = subparsers.add_parser("clean", help="Clean up Docker system")
    clean_parser.add_argument("-a", "--all", action="store_true", help="Prune all unused objects")
    clean_parser.add_argument("-v", "--volumes", action="store_true", help="Prune volumes as well")

    # Find dangling resources command
    dangling_parser = subparsers.add_parser("dangling", help="Find dangling resources")
    dangling_parser.add_argument("-i", "--images", action="store_true", help="Find dangling images")
    dangling_parser.add_argument(
        "-v", "--volumes", action="store_true", help="Find dangling volumes"
    )
    dangling_parser.add_argument(
        "-r", "--remove", action="store_true", help="Remove found dangling resources"
    )

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor a container")
    monitor_parser.add_argument("container", help="Container name or ID")
    monitor_parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=60,
        help="Monitoring duration in seconds (default: 60)",
    )
    monitor_parser.add_argument(
        "-i", "--interval", type=int, default=5, help="Update interval in seconds (default: 5)"
    )

    # Export/Import commands
    export_parser = subparsers.add_parser("export", help="Export a Docker image")
    export_parser.add_argument("image", help="Image name to export (name: tag)")
    export_parser.add_argument("output", help="Output file path")

    import_parser = subparsers.add_parser("import", help="Import a Docker image")
    import_parser.add_argument("tarfile", help="Path to the tar file")

    # Disk usage command
    disk_usage_parser = subparsers.add_parser("disk-usage", help="Show Docker disk usage")

    args = parser.parse_args()

    docker_utils = DockerUtils()

    # Execute commands
    if args.command == "list":
        containers = docker_utils.list_containers(args.all)
        if containers:
            header = ["ID", "Name", "Image", "Status", "Memory Usage", "CPU %"]
            print_table(containers, header)
        else:
            print("No containers found.")

    elif args.command == "clean":
        docker_utils.clean_docker(args.all, args.volumes)

    elif args.command == "dangling":
        if args.images:
            images = docker_utils.find_dangling_images()
            if images:
                print(f"Found {len(images)} dangling images: ")
                header = ["ID", "Repository", "Tag", "Size", "Created"]
                print_table(images, header)
                if args.remove:
                    docker_utils.remove_dangling_images()
            else:
                print("No dangling images found.")

        if args.volumes:
            volumes = docker_utils.find_dangling_volumes()
            if volumes:
                print(f"Found {len(volumes)} dangling volumes: ")
                header = ["Name", "Driver", "Mountpoint"]
                print_table(volumes, header)
                if args.remove:
                    docker_utils.remove_dangling_volumes()
            else:
                print("No dangling volumes found.")

        # Default behavior if no flags specified: show both
        if not args.images and not args.volumes:
            images = docker_utils.find_dangling_images()
            volumes = docker_utils.find_dangling_volumes()

            if images:
                print(f"Found {len(images)} dangling images: ")
                header = ["ID", "Repository", "Tag", "Size", "Created"]
                print_table(images, header)
            else:
                print("No dangling images found.")

            print()

            if volumes:
                print(f"Found {len(volumes)} dangling volumes: ")
                header = ["Name", "Driver", "Mountpoint"]
                print_table(volumes, header)
            else:
                print("No dangling volumes found.")

    elif args.command == "monitor":
        docker_utils.monitor_container(args.container, args.duration, args.interval)

    elif args.command == "export":
        docker_utils.export_image(args.image, args.output)

    elif args.command == "import":
        docker_utils.import_image(args.tarfile)

    elif args.command == "disk-usage":
        docker_utils.show_docker_disk_usage()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
