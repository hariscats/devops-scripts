#!/usr/bin/env python3
"""
AWS Credentials Manager.

In your .bashrc/.zshrc add `eval $(python <path to script>)`
Or simply run `eval $(python <path to script>)`
This avoids adding your aws credentials to bash/zsh history
"""

import os
import sys
from configparser import ConfigParser
from typing import List


def setAwsCredentials(args: List[str]) -> None:
    """Set AWS credentials from configuration file."""
    config = ConfigParser()
    if len(args) > 1:
        config.read(args[1])
    else:
        config.read(os.getenv("HOME") + "/.aws/credentials")

    print(
        "export AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s && "
        "echo 'aws credentials set'"
        % (
            config.get("default", "aws_access_key_id"),
            config.get("default", "aws_secret_access_key"),
        )
    )


if __name__ == "__main__":
    setAwsCredentials(sys.argv)
