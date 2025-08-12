"""
Docker management utilities for DevOps tasks.

Provides functionality for:
- Container lifecycle management
- Resource monitoring and cleanup
- Image operations
- Volume management
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import click
from rich.console import Console
from rich.table import Table

from ..common.utils import format_bytes, setup_logging

logger = logging.getLogger(__name__)
console = Console()


class DockerError(Exception):
    """Custom exception for Docker-related errors."""

    pass


class DockerManager:
    """Docker utility class for common DevOps tasks."""

    def __init__(self, timeout: int = 30):
        """Initialize Docker manager.

        Args:
            timeout: Command timeout in seconds
        """
        self.timeout = timeout
        self._check_docker_available()

    def _check_docker_available(self) -> None:
        """Check if Docker is installed and accessible."""
        try:
            result = self._run_command("docker --version")
            logger.info(f"Docker available: {result.strip()}")
        except subprocess.CalledProcessError:
            raise DockerError("Docker is not installed or not accessible")

    def _run_command(self, command: str) -> str:
        """Run a Docker command and return output.

        Args:
            command: Command to execute

        Returns:
            Command output

        Raises:
            DockerError: If command fails
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {command}\\nError: {e.stderr.strip()}"
            logger.error(error_msg)
            raise DockerError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            error_msg = f"Command timed out after {self.timeout}s: {command}"
            logger.error(error_msg)
            raise DockerError(error_msg) from e

    def list_containers(
        self, all_containers: bool = False, include_stats: bool = True
    ) -> List[Dict[str, str]]:
        """List containers with optional resource statistics.

        Args:
            all_containers: Include stopped containers
            include_stats: Include resource usage statistics

        Returns:
            List of container information dictionaries
        """
        all_flag = "-a" if all_containers else ""

        # Get basic container info
        command = f"docker ps {all_flag} --format '{{{{json .}}}}'"
        output = self._run_command(command)

        if not output:
            return []

        containers = []
        for line in output.splitlines():
            if line.strip():
                container = json.loads(line.strip())

                # Add stats if requested and container is running
                if include_stats and container.get("State") == "running":
                    stats = self._get_container_stats(container["ID"])
                    container.update(stats)

                containers.append(container)

        return containers

    def _get_container_stats(self, container_id: str) -> Dict[str, str]:
        """Get resource statistics for a container.

        Args:
            container_id: Container ID

        Returns:
            Dictionary with CPU, memory, and I/O stats
        """
        try:
            command = f"""docker stats --no-stream {container_id} --format \
'{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.NetIO}}}}|{{{{.BlockIO}}}}'"""
            stats_output = self._run_command(command)

            cpu, mem_usage, mem_perc, net_io, block_io = stats_output.split("|")

            return {
                "CPUPerc": cpu,
                "MemUsage": mem_usage,
                "MemPerc": mem_perc,
                "NetIO": net_io,
                "BlockIO": block_io,
            }
        except Exception as e:
            logger.warning(f"Failed to get stats for {container_id}: {e}")
            return {
                "CPUPerc": "N/A",
                "MemUsage": "N/A",
                "MemPerc": "N/A",
                "NetIO": "N/A",
                "BlockIO": "N/A",
            }

    def find_dangling_images(self) -> List[Dict[str, str]]:
        """Find dangling (untagged) images.

        Returns:
            List of dangling image information
        """
        command = """docker images -f 'dangling=true' --format \
'{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedSince}}'"""
        output = self._run_command(command)

        if not output:
            return []

        dangling_images = []
        for line in output.splitlines():
            if line.strip():
                parts = line.split("|")
                if len(parts) >= 5:
                    dangling_images.append(
                        {
                            "ID": parts[0],
                            "Repository": parts[1],
                            "Tag": parts[2],
                            "Size": parts[3],
                            "Created": parts[4],
                        }
                    )

        return dangling_images

    def find_dangling_volumes(self) -> List[Dict[str, str]]:
        """Find dangling (unused) volumes.

        Returns:
            List of dangling volume information
        """
        command = "docker volume ls -f 'dangling=true' --format '{{.Name}}|{{.Driver}}'"
        output = self._run_command(command)

        if not output:
            return []

        dangling_volumes = []
        for line in output.splitlines():
            if line.strip():
                parts = line.split("|")
                if len(parts) >= 2:
                    dangling_volumes.append(
                        {
                            "Name": parts[0],
                            "Driver": parts[1],
                        }
                    )

        return dangling_volumes

    def cleanup_system(
        self, prune_all: bool = False, prune_volumes: bool = False, force: bool = False
    ) -> Dict[str, str]:
        """Clean up Docker system resources.

        Args:
            prune_all: Remove all unused objects (not just dangling)
            prune_volumes: Also prune unused volumes
            force: Don't prompt for confirmation

        Returns:
            Dictionary with cleanup results
        """
        results = {}

        # System prune
        if prune_all:
            command = "docker system prune -af" if force else "docker system prune -a"
        else:
            command = "docker system prune -f" if force else "docker system prune"

        try:
            result = self._run_command(command)
            results["system_prune"] = result
        except DockerError as e:
            results["system_prune"] = f"Failed: {e}"

        # Volume prune
        if prune_volumes:
            vol_command = "docker volume prune -f" if force else "docker volume prune"
            try:
                result = self._run_command(vol_command)
                results["volume_prune"] = result
            except DockerError as e:
                results["volume_prune"] = f"Failed: {e}"

        return results

    def get_disk_usage(self) -> Dict[str, Any]:
        """Get Docker disk usage information.

        Returns:
            Dictionary with disk usage details
        """
        command = "docker system df --format '{{json .}}'"
        output = self._run_command(command)

        if not output:
            return {}

        # Parse the verbose output
        usage_data = {}
        lines = output.splitlines()

        for line in lines:
            if line.strip():
                try:
                    data = json.loads(line.strip())
                    usage_data = data
                    break
                except json.JSONDecodeError:
                    # Fallback to simple parsing
                    continue

        return usage_data

    def monitor_container(self, container_name: str, duration: int = 60, interval: int = 5) -> None:
        """Monitor a container's resource usage in real-time.

        Args:
            container_name: Container name or ID
            duration: Monitoring duration in seconds
            interval: Update interval in seconds
        """
        # Verify container exists
        try:
            self._run_command(
                f"docker ps -a --filter name={container_name} --format '{{{{.Names}}}}'"
            )
        except DockerError:
            raise DockerError(f"Container '{container_name}' not found")

        console.print(f"Monitoring {container_name} for {duration}s (interval: {interval}s)")

        end_time = time.time() + duration

        while time.time() < end_time:
            # Clear screen
            console.clear()

            # Get container info
            timestamp = datetime.now().strftime("%Y-%m-%d %H: %M: %S")
            console.print(f"[bold]Container Monitor - {container_name} - {timestamp}[/bold]")
            console.print("=" * 80)

            try:
                # Get basic info
                info_cmd = f"""docker ps -a --filter name={container_name} \
--format '{{{{.ID}}}}|{{{{.Status}}}}|{{{{.Image}}}}|{{{{.RunningFor}}}}'"""
                info = self._run_command(info_cmd)

                if info:
                    container_id, status, image, running = info.split("|")

                    table = Table(show_header=False)
                    table.add_row("ID: ", container_id)
                    table.add_row("Status: ", status)
                    table.add_row("Image: ", image)
                    table.add_row("Running For: ", running)
                    console.print(table)

                # Get stats
                if "running" in status.lower():
                    stats = self._get_container_stats(container_name)

                    stats_table = Table(title="Resource Usage")
                    stats_table.add_column("Metric")
                    stats_table.add_column("Value")

                    for key, value in stats.items():
                        stats_table.add_row(key.replace("Perc", " %"), value)

                    console.print(stats_table)

                # Get recent logs
                try:
                    logs = self._run_command(f"docker logs {container_name} --tail 5")
                    console.print("\\n[bold]Recent Logs: [/bold]")
                    console.print(logs or "No logs available")
                except DockerError:
                    console.print("\\n[bold]Recent Logs: [/bold] N/A")

            except Exception as e:
                console.print(f"[red]Error monitoring container: {e}[/red]")

            time.sleep(interval)

    def export_image(self, image_name: str, output_path: Union[str, Path]) -> bool:
        """Export Docker image to tar file.

        Args:
            image_name: Image name and tag
            output_path: Output file path

        Returns:
            True if successful, False otherwise
        """
        output_path = Path(output_path)
        if not output_path.suffix:
            output_path = output_path.with_suffix(".tar")

        try:
            # Check if image exists
            self._run_command(
                f"docker images {image_name} --format '{{{{.Repository}}}}: {{{{.Tag}}}}'"
            )

            # Export image
            command = f"docker save -o {output_path} {image_name}"
            self._run_command(command)

            if output_path.exists():
                console.print(f"[green]Image exported to {output_path}[/green]")
                return True
            else:
                console.print("[red]Export failed[/red]")
                return False

        except DockerError as e:
            console.print(f"[red]Export failed: {e}[/red]")
            return False

    def import_image(self, tar_path: Union[str, Path]) -> bool:
        """Import Docker image from tar file.

        Args:
            tar_path: Path to tar file

        Returns:
            True if successful, False otherwise
        """
        tar_path = Path(tar_path)
        if not tar_path.exists():
            console.print(f"[red]File not found: {tar_path}[/red]")
            return False

        try:
            result = self._run_command(f"docker load -i {tar_path}")
            console.print(f"[green]{result}[/green]")
            return "Loaded image" in result
        except DockerError as e:
            console.print(f"[red]Import failed: {e}[/red]")
            return False


# CLI Implementation
@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Docker management utilities."""
    ctx.ensure_object(dict)
    level = "DEBUG" if verbose else "INFO"
    setup_logging(level=level)
    ctx.obj["manager"] = DockerManager()


@cli.command()
@click.option("--all", "-a", is_flag=True, help="Show all containers")
@click.option("--no-stats", is_flag=True, help="Don't include resource stats")
@click.pass_context
def list_containers(ctx: click.Context, all: bool, no_stats: bool) -> None:
    """List containers with resource usage."""
    manager = ctx.obj["manager"]

    try:
        containers = manager.list_containers(all_containers=all, include_stats=not no_stats)

        if not containers:
            console.print("No containers found.")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Name")
        table.add_column("Image")
        table.add_column("Status")
        table.add_column("CPU %")
        table.add_column("Memory")

        for container in containers:
            table.add_row(
                container.get("Names", "N/A"),
                container.get("Image", "N/A"),
                container.get("Status", "N/A"),
                container.get("CPUPerc", "N/A"),
                container.get("MemUsage", "N/A"),
            )

        console.print(table)

    except DockerError as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.option("--all", "-a", is_flag=True, help="Remove all unused objects")
@click.option("--volumes", "-v", is_flag=True, help="Also prune volumes")
@click.option("--force", "-f", is_flag=True, help="Don't prompt for confirmation")
@click.pass_context
def cleanup(ctx: click.Context, all: bool, volumes: bool, force: bool) -> None:
    """Clean up Docker system."""
    manager = ctx.obj["manager"]

    try:
        results = manager.cleanup_system(prune_all=all, prune_volumes=volumes, force=force)

        for operation, result in results.items():
            console.print(f"[bold]{operation}: [/bold]")
            console.print(result)
            console.print()

    except DockerError as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.option("--remove", "-r", is_flag=True, help="Remove found resources")
@click.pass_context
def dangling(ctx: click.Context, remove: bool) -> None:
    """Find and optionally remove dangling resources."""
    manager = ctx.obj["manager"]

    try:
        # Find dangling images
        images = manager.find_dangling_images()
        if images:
            console.print(f"Found {len(images)} dangling images: ")

            table = Table()
            table.add_column("ID")
            table.add_column("Repository")
            table.add_column("Tag")
            table.add_column("Size")

            for img in images:
                table.add_row(img["ID"][:12], img["Repository"], img["Tag"], img["Size"])
            console.print(table)
        else:
            console.print("No dangling images found.")

        # Find dangling volumes
        volumes = manager.find_dangling_volumes()
        if volumes:
            console.print(f"\\nFound {len(volumes)} dangling volumes: ")

            table = Table()
            table.add_column("Name")
            table.add_column("Driver")

            for vol in volumes:
                table.add_row(vol["Name"], vol["Driver"])
            console.print(table)
        else:
            console.print("\\nNo dangling volumes found.")

        if remove and (images or volumes):
            if click.confirm("Remove all dangling resources?"):
                results = manager.cleanup_system(prune_volumes=True, force=True)
                console.print("[green]Cleanup completed.[/green]")

    except DockerError as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.argument("container_name")
@click.option("--duration", "-d", default=60, help="Duration in seconds")
@click.option("--interval", "-i", default=5, help="Update interval in seconds")
@click.pass_context
def monitor(ctx: click.Context, container_name: str, duration: int, interval: int) -> None:
    """Monitor a container's resource usage."""
    manager = ctx.obj["manager"]

    try:
        manager.monitor_container(container_name, duration, interval)
    except DockerError as e:
        console.print(f"[red]Error: {e}[/red]")


def main() -> None:
    """Entry point for docker-utils command."""
    cli()


if __name__ == "__main__":
    main()
