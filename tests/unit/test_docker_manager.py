"""Test Docker manager functionality."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from devops_tools.containers.docker_manager import DockerError, DockerManager


class TestDockerManager:
    """Test cases for DockerManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch("devops_tools.containers.docker_manager.DockerManager._check_docker_available"):
            self.manager = DockerManager(timeout=10)

    def test_init_with_timeout(self):
        """Test DockerManager initialization with custom timeout."""
        with patch("devops_tools.containers.docker_manager.DockerManager._check_docker_available"):
            manager = DockerManager(timeout=30)
            assert manager.timeout == 30

    @patch("subprocess.run")
    def test_run_command_success(self, mock_run):
        """Test successful command execution."""
        # Mock successful command
        mock_run.return_value = MagicMock(stdout="docker version output", stderr="", returncode=0)

        result = self.manager._run_command("docker --version")
        assert result == "docker version output"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_command_failure(self, mock_run):
        """Test command execution failure."""
        # Mock failed command
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "docker", stderr="command not found"
        )

        with pytest.raises(DockerError) as exc_info:
            self.manager._run_command("invalid-command")

        assert "Command failed" in str(exc_info.value)

    @patch.object(DockerManager, "_run_command")
    def test_list_containers_empty(self, mock_run):
        """Test listing containers when none exist."""
        mock_run.return_value = ""

        containers = self.manager.list_containers()
        assert containers == []

    @patch.object(DockerManager, "_run_command")
    def test_list_containers_with_data(self, mock_run):
        """Test listing containers with actual data."""
        mock_output = """{"ID":"abc123","Names":"test-container","Image":"nginx","Status":"running"}
{"ID":"def456","Names":"test-db","Image":"postgres","Status":"exited"}"""

        mock_run.return_value = mock_output

        containers = self.manager.list_containers(include_stats=False)
        assert len(containers) == 2
        assert containers[0]["Names"] == "test-container"
        assert containers[1]["Image"] == "postgres"

    @patch.object(DockerManager, "_run_command")
    def test_find_dangling_images(self, mock_run):
        """Test finding dangling images."""
        mock_output = "sha256:abc123|<none>|<none>|100MB|2 hours ago"
        mock_run.return_value = mock_output

        images = self.manager.find_dangling_images()
        assert len(images) == 1
        assert images[0]["ID"] == "sha256:abc123"
        assert images[0]["Size"] == "100MB"

    @patch.object(DockerManager, "_run_command")
    def test_find_dangling_volumes(self, mock_run):
        """Test finding dangling volumes."""
        mock_output = "volume123|local"
        mock_run.return_value = mock_output

        volumes = self.manager.find_dangling_volumes()
        assert len(volumes) == 1
        assert volumes[0]["Name"] == "volume123"
        assert volumes[0]["Driver"] == "local"

    @patch.object(DockerManager, "_run_command")
    def test_cleanup_system_basic(self, mock_run):
        """Test basic system cleanup."""
        mock_run.return_value = "Total reclaimed space: 1.2GB"

        results = self.manager.cleanup_system()
        assert "system_prune" in results
        assert "1.2GB" in results["system_prune"]

    @patch.object(DockerManager, "_run_command")
    def test_cleanup_system_with_volumes(self, mock_run):
        """Test system cleanup including volumes."""
        mock_run.return_value = "Cleanup completed"

        results = self.manager.cleanup_system(prune_volumes=True)
        assert "system_prune" in results
        assert "volume_prune" in results

    @patch("pathlib.Path.exists")
    @patch.object(DockerManager, "_run_command")
    def test_export_image_success(self, mock_run, mock_exists):
        """Test successful image export."""
        mock_run.return_value = "nginx:latest"
        mock_exists.return_value = True

        result = self.manager.export_image("nginx:latest", "/tmp/nginx.tar")
        assert result is True

    @patch("pathlib.Path.exists")
    @patch.object(DockerManager, "_run_command")
    def test_import_image_success(self, mock_run, mock_exists):
        """Test successful image import."""
        mock_exists.return_value = True
        mock_run.return_value = "Loaded image: nginx:latest"

        result = self.manager.import_image("/tmp/nginx.tar")
        assert result is True

    @patch("pathlib.Path.exists")
    def test_import_image_file_not_found(self, mock_exists):
        """Test import with non-existent file."""
        mock_exists.return_value = False

        result = self.manager.import_image("/tmp/nonexistent.tar")
        assert result is False


# Integration test (requires Docker to be installed)
@pytest.mark.integration
class TestDockerManagerIntegration:
    """Integration tests for DockerManager."""

    def setup_method(self):
        """Set up integration test fixtures."""
        try:
            self.manager = DockerManager()
        except DockerError:
            pytest.skip("Docker not available for integration tests")

    def test_docker_available(self):
        """Test that Docker is available for integration tests."""
        # This test will be skipped if Docker is not available
        assert self.manager is not None

    def test_list_containers_integration(self):
        """Test actual container listing."""
        containers = self.manager.list_containers(include_stats=False)
        # Should not raise an exception
        assert isinstance(containers, list)
