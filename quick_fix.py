#!/usr/bin/env python3
"""
Quick fix script to address common pre-commit issues.
This script fixes common formatting and linting issues in the codebase.
"""

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


def run_command(cmd: List[str], cwd: Path = None) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def main():
    """Main function to fix common issues."""
    project_root = Path(__file__).parent

    print("🔧 Quick Fix Script for DevOps Tools")
    print("=" * 50)

    # 1. Format code with black
    print("1. Formatting code with black...")
    exit_code, stdout, stderr = run_command(
        [sys.executable, "-m", "black", "src/", "tests/", "examples/", "--line-length", "100"],
        cwd=project_root,
    )

    if exit_code == 0:
        print("   ✅ Black formatting complete")
    else:
        print(f"   ⚠️ Black had issues: {stderr}")

    # 2. Remove unused imports and fix import order
    print("2. Fixing imports...")

    # Try to install autoflake if not available
    subprocess.run([sys.executable, "-m", "pip", "install", "autoflake"], capture_output=True)

    # Remove unused imports
    exit_code, stdout, stderr = run_command(
        [
            sys.executable,
            "-m",
            "autoflake",
            "--in-place",
            "--remove-unused-variables",
            "--remove-all-unused-imports",
            "--recursive",
            "src/",
            "tests/",
            "examples/",
        ],
        cwd=project_root,
    )

    if exit_code == 0:
        print("   ✅ Unused imports removed")
    else:
        print("   ⚠️ Autoflake not available or had issues")

    # 3. Run a targeted pre-commit check
    print("3. Running pre-commit on critical files...")

    critical_files = ["src/devops_tools/aws/credentials.py", "tests/unit/test_docker_manager.py"]

    for file in critical_files:
        if (project_root / file).exists():
            exit_code, stdout, stderr = run_command(
                ["pre-commit", "run", "--files", file], cwd=project_root
            )

            if exit_code == 0:
                print(f"   ✅ {file} passed pre-commit")
            else:
                print(f"   ⚠️ {file} has remaining issues")

    print("\n🎯 Quick fixes complete!")
    print("Some issues may remain and require manual fixing:")
    print("- Long docstrings and complex expressions")
    print("- Type annotations for complex functions")
    print("- Module-level docstrings")
    print("\nRun 'pre-commit run --all-files' to see remaining issues.")


if __name__ == "__main__":
    main()
