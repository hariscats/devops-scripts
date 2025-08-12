# DevOps Tools

A comprehensive collection of automation scripts and utilities for DevOps tasks.

## Overview

This repository provides a structured set of tools for common DevOps operations:

- **AWS Tools**: Resource inspection, cost analysis, and security assessment
- **Container Tools**: Docker management, cleanup, and monitoring
- **Monitoring Tools**: System monitoring, log analysis, and performance tracking
- **Git Tools**: Repository analysis and automation
- **Web Tools**: HAR file viewing, testing servers, and web utilities

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/hariscats/devops-scripts.git
cd devops-scripts

# Install in development mode
pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install
```

### Using pip (when published)

```bash
pip install devops-tools
```

## Quick Start

After installation, you'll have access to several command-line tools:

```bash
# Docker management
docker-utils list --all
docker-utils cleanup --volumes

# AWS resource inspection
aws-inspector --regions us-east-1,us-west-2 --services ec2,s3

# System monitoring
system-monitor --duration 60 --interval 5

# Git analysis
git-analyzer --repo-path /path/to/repo --format json

# Log analysis
log-analyzer --file /var/log/app.log --pattern ERROR
```

## Project Structure

```
src/devops_tools/
├── aws/           # AWS utilities
├── containers/    # Container management
├── git/           # Git analysis tools
├── monitoring/    # System and application monitoring
├── web/           # Web utilities
└── common/        # Shared utilities
```

## Features

### Docker Tools
- List containers with resource usage
- Clean up dangling images and volumes
- Monitor container performance
- Export/import images
- System disk usage analysis

### AWS Tools
- Multi-region resource inventory
- Cost optimization recommendations
- Security assessment
- Compliance checking
- Resource utilization analysis

### Monitoring Tools
- Cross-platform system monitoring
- Log file analysis with pattern matching
- Application performance tracing
- Resource usage tracking

### Git Tools
- Repository analysis and statistics
- Commit pattern analysis
- Branch and contributor insights
- Code quality metrics

## Configuration

Configuration files are stored in the `config/` directory:

- `logging.yaml`: Logging configuration
- `aws-defaults.json`: Default AWS settings
- `monitoring-thresholds.json`: Monitoring alert thresholds

## Development

### Setup Development Environment

```bash
# Install development dependencies
make install-dev

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src --cov-report=term-missing

# Specific test
pytest tests/unit/test_containers/
```

### Code Quality

This project uses several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **pre-commit**: Git hooks for quality checks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite and ensure all checks pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Author

**Hariscats** - DevOps Engineer

For questions or support, please open an issue on GitHub.
