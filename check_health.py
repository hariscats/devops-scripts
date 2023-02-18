#!/usr/bin/env python3
"""                                                       
Author : Hariscats
Date   : 2023-02-18
Purpose: Check system health
"""


import requests
import socket
import shutil
import psutil


def test_localhost():
    localhost = socket.gethostbyname('localhost')
    return localhost == "127.0.0.1"

def test_connectivity():
    request = requests.get("http://www.google.com")
    response = request
    return response.status_code == 200

def verify_disk_usage(disk):
    """Verifies that there's enough free space on disk"""
    du = shutil.disk_usage(disk)
    free = du.free / du.total * 100
    return free > 20

def verify_cpu_usage():
    """Verifies that there's enough unused CPU"""
    usage = psutil.cpu_percent(1)
    return usage < 75


# If not enough disk or CPU capacity, print error
if not verify_disk_usage('/') or not verify_cpu_usage():
    print("ERROR!")
elif test_localhost() and test_connectivity():
    print("Everything ok")
else:
    print("Network checks failed")
