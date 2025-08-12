#!/usr/bin/env python3
"""
Example: Docker container health check and cleanup automation.

This example demonstrates how to use the devops-tools Docker utilities
to perform automated health checks and cleanup operations.
"""

import sys
import time
from pathlib import Path

from devops_tools.common.utils import setup_logging
from devops_tools.containers.docker_manager import DockerError, DockerManager


def main():
    """Main execution function."""
    # Set up logging
    logger = setup_logging(level="INFO")

    try:
        # Initialize Docker manager
        manager = DockerManager(timeout=30)
        logger.info("Docker manager initialized successfully")

        # 1. Check current container status
        logger.info("=== Container Health Check ===")
        containers = manager.list_containers(all_containers=True, include_stats=True)

        if not containers:
            logger.info("No containers found")
        else:
            logger.info(f"Found {len(containers)} containers: ")
            for container in containers:
                name = container.get("Names", "Unknown")
                status = container.get("Status", "Unknown")
                cpu = container.get("CPUPerc", "N/A")
                memory = container.get("MemUsage", "N/A")

                logger.info(f"  {name}: {status} (CPU: {cpu}, Memory: {memory})")

        # 2. Find and report dangling resources
        logger.info("\\n=== Resource Cleanup Check ===")

        # Check dangling images
        dangling_images = manager.find_dangling_images()
        if dangling_images:
            total_images = len(dangling_images)
            logger.warning(f"Found {total_images} dangling images")
            for img in dangling_images[:5]:  # Show first 5
                logger.info(f"  {img['ID'][: 12]}: {img['Size']}")
            if total_images > 5:
                logger.info(f"  ... and {total_images - 5} more")
        else:
            logger.info("No dangling images found")

        # Check dangling volumes
        dangling_volumes = manager.find_dangling_volumes()
        if dangling_volumes:
            logger.warning(f"Found {len(dangling_volumes)} dangling volumes")
            for vol in dangling_volumes[:5]:  # Show first 5
                logger.info(f"  {vol['Name']} ({vol['Driver']})")
        else:
            logger.info("No dangling volumes found")

        # 3. Show disk usage
        logger.info("\\n=== Docker Disk Usage ===")
        try:
            usage = manager.get_disk_usage()
            if usage:
                logger.info("Docker disk usage information retrieved")
                # Process usage data as needed
            else:
                logger.info("Could not retrieve disk usage information")
        except DockerError as e:
            logger.warning(f"Could not get disk usage: {e}")

        # 4. Perform cleanup if there are dangling resources
        if dangling_images or dangling_volumes:
            logger.info("\\n=== Performing Cleanup ===")

            # Ask for confirmation in interactive mode
            if sys.stdin.isatty():
                response = input("Perform cleanup of dangling resources? (y/N): ")
                if response.lower() != "y":
                    logger.info("Cleanup cancelled by user")
                    return

            # Perform cleanup
            try:
                results = manager.cleanup_system(
                    prune_all=False,  # Only remove dangling resources
                    prune_volumes=True,  # Include volumes
                    force=True,  # Don't prompt again
                )

                logger.info("Cleanup completed: ")
                for operation, result in results.items():
                    logger.info(f"  {operation}: {result}")

            except DockerError as e:
                logger.error(f"Cleanup failed: {e}")
        else:
            logger.info("\\n=== No Cleanup Needed ===")
            logger.info("All Docker resources are in good shape!")

        # 5. Example: Monitor a specific container (if any are running)
        running_containers = [c for c in containers if "running" in c.get("Status", "").lower()]
        if running_containers:
            container_name = running_containers[0]["Names"]
            logger.info(f"\\n=== Monitoring Example: {container_name} ===")
            logger.info("Monitoring for 30 seconds (this is just an example)...")

            # In a real scenario, you might want to monitor for longer
            # or implement custom monitoring logic
            try:
                manager.monitor_container(container_name, duration=30, interval=10)
            except KeyboardInterrupt:
                logger.info("Monitoring interrupted by user")
            except DockerError as e:
                logger.warning(f"Monitoring failed: {e}")

        logger.info("\\n=== Docker Health Check Complete ===")

    except DockerError as e:
        logger.error(f"Docker operation failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
