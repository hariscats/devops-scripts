#!/usr/bin/env python3
"""
Author : Hariscats
Date   : 2023-06-12
Purpose: Cross-platform system monitoring tool that displays:
         - CPU usage
         - Memory usage
         - Disk usage
         - Network statistics
         - Running processes (top 10 by CPU usage)
         
Works on Linux, macOS, and Windows without external dependencies
"""

import os
import sys
import time
import datetime
import socket
import platform
import subprocess
from collections import defaultdict


def get_system_info():
    """Get basic system information"""
    system_info = {
        "Platform": platform.system(),
        "Platform Release": platform.release(),
        "Platform Version": platform.version(),
        "Architecture": platform.machine(),
        "Hostname": socket.gethostname(),
        "Processor": platform.processor(),
        "Python Version": platform.python_version()
    }
    return system_info


def get_cpu_info():
    """Get CPU usage information in a cross-platform way"""
    try:
        system = platform.system()
        cpu_info = {}
        
        if system == "Linux":
            # Using /proc/stat on Linux
            with open('/proc/stat', 'r') as f:
                cpu_lines = [line for line in f if line.startswith('cpu')]
                
            cpu_info["CPU Cores"] = len(cpu_lines) - 1  # Minus the aggregate line
            
            # Use top to get a simple CPU percentage
            with os.popen('top -bn1 | grep "Cpu(s)"') as f:
                cpu_usage = f.read().strip()
                cpu_info["CPU Usage"] = cpu_usage
                
        elif system == "Darwin":  # macOS
            # Get number of cores
            with os.popen('sysctl -n hw.ncpu') as f:
                cpu_info["CPU Cores"] = f.read().strip()
                
            # Use top to get CPU load
            with os.popen('top -l 1 | grep "CPU usage"') as f:
                cpu_usage = f.read().strip()
                cpu_info["CPU Usage"] = cpu_usage
                
        elif system == "Windows":
            # Using WMIC on Windows
            with os.popen('wmic cpu get NumberOfCores') as f:
                output = f.read().strip().split('\n')
                if len(output) > 1:
                    cpu_info["CPU Cores"] = output[1].strip()
                    
            # Get CPU load percentage
            with os.popen('wmic cpu get LoadPercentage') as f:
                output = f.read().strip().split('\n')
                if len(output) > 1:
                    cpu_info["CPU Usage"] = f"{output[1].strip()}%"
        
        return cpu_info
    except Exception as e:
        return {"Error": str(e)}


def get_memory_info():
    """Get memory usage information in a cross-platform way"""
    try:
        system = platform.system()
        memory_info = {}
        
        if system == "Linux":
            # Using /proc/meminfo on Linux
            mem_dict = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    key, value = line.split(':', 1)
                    mem_dict[key.strip()] = value.strip()
                    
            total = int(mem_dict['MemTotal'].split()[0])
            free = int(mem_dict['MemFree'].split()[0])
            buffers = int(mem_dict['Buffers'].split()[0]) if 'Buffers' in mem_dict else 0
            cached = int(mem_dict['Cached'].split()[0]) if 'Cached' in mem_dict else 0
            
            used = total - free - buffers - cached
            percent_used = (used / total) * 100 if total > 0 else 0
            
            memory_info["Total Memory"] = f"{total/1024:.2f} MB"
            memory_info["Used Memory"] = f"{used/1024:.2f} MB"
            memory_info["Memory Usage"] = f"{percent_used:.2f}%"
            
        elif system == "Darwin":  # macOS
            # Using vm_stat on macOS
            with os.popen('vm_stat') as f:
                vm_stat = f.read().strip()
                
            lines = vm_stat.split('\n')
            mem_dict = {}
            for line in lines[1:]:  # Skip the first line
                if ':' in line:
                    key, value = line.split(':', 1)
                    mem_dict[key.strip()] = int(value.strip().rstrip('.').replace(',', ''))
            
            # Calculate memory in pages
            page_size = 4096  # Default page size on macOS
            free = mem_dict.get('Pages free', 0)
            active = mem_dict.get('Pages active', 0)
            inactive = mem_dict.get('Pages inactive', 0)
            speculative = mem_dict.get('Pages speculative', 0)
            wired = mem_dict.get('Pages wired down', 0)
            
            # Get total physical memory
            with os.popen('sysctl -n hw.memsize') as f:
                total_bytes = int(f.read().strip())
                
            # Convert to MB
            total_mb = total_bytes / 1024 / 1024
            used_pages = active + inactive + wired
            used_mb = (used_pages * page_size) / 1024 / 1024
            percent_used = (used_mb / total_mb) * 100 if total_mb > 0 else 0
            
            memory_info["Total Memory"] = f"{total_mb:.2f} MB"
            memory_info["Used Memory"] = f"{used_mb:.2f} MB"
            memory_info["Memory Usage"] = f"{percent_used:.2f}%"
            
        elif system == "Windows":
            # Using WMIC on Windows
            with os.popen('wmic OS get TotalVisibleMemorySize /Value') as f:
                total = f.read().strip().split('=')[1] if '=' in f.read().strip() else "0"
            
            with os.popen('wmic OS get FreePhysicalMemory /Value') as f:
                free = f.read().strip().split('=')[1] if '=' in f.read().strip() else "0"
            
            # Convert to numeric values
            try:
                total_kb = float(total)
                free_kb = float(free)
                used_kb = total_kb - free_kb
                percent_used = (used_kb / total_kb) * 100 if total_kb > 0 else 0
                
                memory_info["Total Memory"] = f"{total_kb/1024:.2f} MB"
                memory_info["Used Memory"] = f"{used_kb/1024:.2f} MB"
                memory_info["Memory Usage"] = f"{percent_used:.2f}%"
            except ValueError:
                memory_info["Error"] = "Failed to convert memory values"
        
        return memory_info
    except Exception as e:
        return {"Error": str(e)}


def get_disk_info():
    """Get disk usage information in a cross-platform way"""
    try:
        system = platform.system()
        disk_info = {}
        
        if system == "Linux" or system == "Darwin":  # Linux or macOS
            # Using df command
            with os.popen('df -h') as f:
                df_output = f.read().strip()
                
            disk_info["Disk Usage"] = df_output
            
        elif system == "Windows":
            # Using WMIC on Windows
            with os.popen('wmic logicaldisk get DeviceID,Size,FreeSpace') as f:
                disk_output = f.read().strip()
                
            disk_info["Disk Usage"] = disk_output
        
        return disk_info
    except Exception as e:
        return {"Error": str(e)}


def get_network_info():
    """Get network statistics in a cross-platform way"""
    try:
        system = platform.system()
        network_info = {}
        
        if system == "Linux":
            # Using /proc/net/dev on Linux
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
                
            interfaces = defaultdict(dict)
            for line in lines[2:]:  # Skip header lines
                parts = line.split(':')
                if len(parts) >= 2:
                    interface = parts[0].strip()
                    data = parts[1].split()
                    if len(data) >= 16:  # Check sufficient data fields
                        interfaces[interface]["RX Bytes"] = data[0]
                        interfaces[interface]["TX Bytes"] = data[8]
            
            network_info["Interfaces"] = dict(interfaces)
                
        elif system == "Darwin":  # macOS
            # Using netstat on macOS
            with os.popen('netstat -ib') as f:
                lines = f.readlines()
                
            interfaces = {}
            for line in lines[1:]:  # Skip header line
                parts = line.split()
                if len(parts) >= 10:
                    interface = parts[0]
                    if interface not in interfaces:
                        interfaces[interface] = {}
                    interfaces[interface]["RX Bytes"] = parts[6]
                    interfaces[interface]["TX Bytes"] = parts[9]
            
            network_info["Interfaces"] = interfaces
                
        elif system == "Windows":
            # Using netstat on Windows
            with os.popen('netstat -e') as f:
                netstat_output = f.read().strip()
                
            network_info["Statistics"] = netstat_output
        
        return network_info
    except Exception as e:
        return {"Error": str(e)}


def get_process_info():
    """Get information about the top 10 processes by CPU usage"""
    try:
        system = platform.system()
        
        if system == "Linux":
            # Using ps command on Linux
            with os.popen('ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11') as f:
                processes = f.read().strip()
                
        elif system == "Darwin":  # macOS
            # Using ps command on macOS
            with os.popen('ps -eo pid,ppid,command,%mem,%cpu -r | head -n 11') as f:
                processes = f.read().strip()
                
        elif system == "Windows":
            # Using WMIC on Windows
            with os.popen('wmic process get Caption,ProcessId,ParentProcessId,WorkingSetSize /Format:csv | sort') as f:
                processes = f.read().strip()
                processes = "Top Processes:\n" + processes
        
        return processes
    except Exception as e:
        return f"Error getting process info: {e}"


def display_system_monitor():
    """Display system monitoring information"""
    # Get current timestamp
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Clear the screen based on the platform
    os.system('cls' if platform.system() == "Windows" else 'clear')
    
    # Print header
    print("=" * 80)
    print(f"SYSTEM MONITOR - {current_time}")
    print("=" * 80)
    
    # Display system information
    print("\n[SYSTEM INFORMATION]")
    for key, value in get_system_info().items():
        print(f"{key}: {value}")
    
    # Display CPU information
    print("\n[CPU INFORMATION]")
    for key, value in get_cpu_info().items():
        print(f"{key}: {value}")
    
    # Display memory information
    print("\n[MEMORY INFORMATION]")
    for key, value in get_memory_info().items():
        print(f"{key}: {value}")
    
    # Display disk information
    print("\n[DISK INFORMATION]")
    print(get_disk_info().get("Disk Usage", "N/A"))
    
    # Display network information
    print("\n[NETWORK INFORMATION]")
    network_info = get_network_info()
    if "Interfaces" in network_info:
        for interface, stats in network_info["Interfaces"].items():
            print(f"Interface: {interface}")
            for stat_name, stat_value in stats.items():
                print(f"  {stat_name}: {stat_value}")
    else:
        print(network_info.get("Statistics", "N/A"))
    
    # Display process information
    print("\n[TOP PROCESSES (by CPU usage)]")
    print(get_process_info())
    
    print("\n" + "=" * 80)
    print(f"Press Ctrl+C to exit. Refreshing in 5 seconds...")
    print("=" * 80)


if __name__ == "__main__":
    print("Starting system monitor... Press Ctrl+C to exit.")
    try:
        while True:
            display_system_monitor()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nExiting system monitor.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")