#!/usr/bin/env python3
"""
Author : Hariscats
Date   : 2023-06-15
Purpose: Log file analyzer that can parse various log formats and extract useful information:
         - Detect and count errors by type
         - Identify patterns in logs
         - Find time periods with high error rates
         - Extract IP addresses and user agents
         - Generate a summary report

Supports common log formats (Apache, Nginx, syslogs) and custom regex patterns
"""

import argparse
import datetime
import ipaddress
import os
import re
import sys
import time
from collections import Counter, defaultdict

# Regular expressions for different log formats
LOG_PATTERNS = {
    "apache": {
        "pattern": r'(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.*?) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"',
        "fields": [
            "ip",
            "date",
            "time",
            "timezone",
            "method",
            "url",
            "protocol",
            "status",
            "size",
            "referer",
            "user_agent",
        ],
    },
    "nginx": {
        "pattern": r'(\S+) - \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.*?) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"',
        "fields": [
            "ip",
            "date",
            "time",
            "timezone",
            "method",
            "url",
            "protocol",
            "status",
            "size",
            "referer",
            "user_agent",
        ],
    },
    "syslog": {
        "pattern": r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.*)",
        "fields": ["timestamp", "host", "process", "message"],
    },
}

# Error patterns to search for in logs
ERROR_PATTERNS = [
    r"error",
    r"fail",
    r"exception",
    r"traceback",
    r"fatal",
    r"warn",
    r"critical",
    r"denied",
    r"refused",
    r"timeout",
    r"unavailable",
    r"stacktrace",
    r"unauthorized",
    r"permission",
]


def guess_log_format(log_file, sample_lines=10):
    """Attempt to guess the log format based on samples"""
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        sample = [next(f) for _ in range(sample_lines) if f]

    for fmt_name, fmt_data in LOG_PATTERNS.items():
        match_count = 0
        for line in sample:
            if re.search(fmt_data["pattern"], line):
                match_count += 1

        # If more than half of the lines match, assume this format
        if match_count > len(sample) / 2:
            return fmt_name

    return "unknown"


def parse_log_line(line, log_format):
    """Parse a log line according to the format"""
    if log_format in LOG_PATTERNS:
        pattern = LOG_PATTERNS[log_format]["pattern"]
        fields = LOG_PATTERNS[log_format]["fields"]

        match = re.search(pattern, line)
        if match:
            return dict(zip(fields, match.groups()))

    return None


def extract_ips(log_entries):
    """Extract and validate IP addresses"""
    ips = []
    for entry in log_entries:
        if "ip" in entry:
            ip = entry["ip"]
            try:
                # Validate IP address
                ipaddress.ip_address(ip)
                ips.append(ip)
            except ValueError:
                pass
    return ips


def extract_error_messages(log_entries, log_format):
    """Extract error messages from log entries"""
    errors = []

    for entry in log_entries:
        # Check based on log format
        if log_format == "apache" or log_format == "nginx":
            # HTTP status codes 4xx and 5xx indicate errors
            if "status" in entry and entry["status"].startswith(("4", "5")):
                errors.append(
                    {
                        "timestamp": entry.get("date", "") + " " + entry.get("time", ""),
                        "status": entry.get("status", ""),
                        "url": entry.get("url", ""),
                        "ip": entry.get("ip", ""),
                    }
                )
        elif log_format == "syslog":
            # Check for error patterns in the message
            if "message" in entry:
                message = entry["message"].lower()
                if any(re.search(pattern, message) for pattern in ERROR_PATTERNS):
                    errors.append(
                        {
                            "timestamp": entry.get("timestamp", ""),
                            "host": entry.get("host", ""),
                            "process": entry.get("process", ""),
                            "message": entry.get("message", ""),
                        }
                    )

    return errors


def find_patterns(log_entries, log_format):
    """Find common patterns in log entries"""
    patterns = defaultdict(int)

    if log_format == "apache" or log_format == "nginx":
        # Count URL patterns
        for entry in log_entries:
            if "url" in entry:
                # Extract the base path without query parameters
                url_parts = entry["url"].split("?")[0]
                # Replace numeric IDs with a placeholder
                normalized_url = re.sub(r"/\d+", "/:id", url_parts)
                patterns[normalized_url] += 1
    elif log_format == "syslog":
        # Count message patterns
        for entry in log_entries:
            if "message" in entry:
                # Remove numbers and variable parts from messages
                normalized_message = re.sub(r"\d+", ":num", entry["message"])
                normalized_message = re.sub(r"\"[^\"]+\"", '":var"', normalized_message)
                patterns[normalized_message] += 1

    return patterns


def find_time_periods_with_high_errors(errors, interval_minutes=5):
    """Find time periods with high error rates"""
    if not errors:
        return []

    # Extract timestamps and convert to datetime objects
    timestamps = []
    for error in errors:
        if "timestamp" in error:
            try:
                # Handle different timestamp formats
                if log_format == "apache" or log_format == "nginx":
                    dt = datetime.datetime.strptime(error["timestamp"], "%d/%b/%Y %H:%M:%S")
                elif log_format == "syslog":
                    # Example syslog format: Jan  1 00:00:00
                    year = datetime.datetime.now().year  # Assume current year
                    dt = datetime.datetime.strptime(
                        f"{error['timestamp']} {year}", "%b %d %H:%M:%S %Y"
                    )
                timestamps.append(dt)
            except ValueError:
                continue

    if not timestamps:
        return []

    # Sort timestamps
    timestamps.sort()

    # Count errors in intervals
    intervals = defaultdict(int)
    for dt in timestamps:
        # Round down to the nearest interval
        rounded = dt.replace(
            minute=(dt.minute // interval_minutes) * interval_minutes, second=0, microsecond=0
        )
        intervals[rounded] += 1

    # Calculate average errors per interval
    total_errors = sum(intervals.values())
    total_intervals = len(intervals)
    if total_intervals == 0:
        return []

    avg_errors = total_errors / total_intervals

    # Find intervals with higher than average error counts
    high_error_intervals = []
    for interval, count in sorted(intervals.items()):
        if count > avg_errors * 1.5:  # 50% more than average
            end_interval = interval + datetime.timedelta(minutes=interval_minutes)
            high_error_intervals.append(
                {
                    "start": interval.strftime("%Y-%m-%d %H:%M:%S"),
                    "end": end_interval.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": count,
                }
            )

    return sorted(high_error_intervals, key=lambda x: x["count"], reverse=True)


def generate_summary(log_file, log_entries, errors, ip_stats, patterns, high_error_periods):
    """Generate a summary of the log analysis"""
    summary = {
        "log_file": log_file,
        "analysis_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_lines_analyzed": len(log_entries),
        "total_errors": len(errors),
        "unique_ips": len(set(ip_stats)),
        "top_10_ips": Counter(ip_stats).most_common(10),
        "top_10_patterns": sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10],
        "high_error_periods": high_error_periods[:5],  # Top 5 periods
    }

    # Error breakdown by type (for HTTP logs)
    if log_format == "apache" or log_format == "nginx":
        status_codes = Counter(error.get("status", "") for error in errors)
        summary["error_status_codes"] = status_codes.most_common()

    return summary


def print_summary(summary):
    """Print the summary report in a readable format"""
    print("\n" + "=" * 80)
    print(f"LOG ANALYSIS SUMMARY: {summary['log_file']}")
    print(f"Analysis time: {summary['analysis_time']}")
    print("=" * 80)

    print(f"\nTotal lines analyzed: {summary['total_lines_analyzed']}")
    print(f"Total errors detected: {summary['total_errors']}")
    print(f"Unique IP addresses: {summary['unique_ips']}")

    if "error_status_codes" in summary:
        print("\nError breakdown by HTTP status code:")
        for status, count in summary["error_status_codes"]:
            print(f"  {status}: {count}")

    print("\nTop 10 IP addresses:")
    for ip, count in summary["top_10_ips"]:
        print(f"  {ip}: {count} requests")

    print("\nTop 10 patterns:")
    for pattern, count in summary["top_10_patterns"]:
        print(f"  {pattern}: {count} occurrences")

    print("\nTime periods with high error rates:")
    for period in summary["high_error_periods"]:
        print(f"  {period['start']} to {period['end']}: {period['count']} errors")

    print("\n" + "=" * 80)


def analyze_log(log_file, format=None):
    """Analyze a log file and generate a report"""
    print(f"Analyzing log file: {log_file}")

    # Check if file exists
    if not os.path.isfile(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return

    # Guess log format if not specified
    global log_format
    log_format = format
    if not log_format:
        log_format = guess_log_format(log_file)
        print(f"Detected log format: {log_format}")

    if log_format == "unknown":
        print("Error: Could not determine log format. Please specify format using --format.")
        return

    # Parse the log file
    print("Parsing log entries...")
    log_entries = []
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_log_line(line, log_format)
            if entry:
                log_entries.append(entry)

    if not log_entries:
        print("No valid log entries found. Check if the correct format is specified.")
        return

    print(f"Successfully parsed {len(log_entries)} log entries.")

    # Extract IPs
    print("Extracting IP addresses...")
    ip_stats = extract_ips(log_entries)
    print(f"Found {len(set(ip_stats))} unique IP addresses.")

    # Find errors
    print("Identifying errors...")
    errors = extract_error_messages(log_entries, log_format)
    print(f"Found {len(errors)} errors.")

    # Find patterns
    print("Finding common patterns...")
    patterns = find_patterns(log_entries, log_format)

    # Find high error periods
    print("Analyzing error time distribution...")
    high_error_periods = find_time_periods_with_high_errors(errors)

    # Generate and print summary
    print("\nGenerating summary report...")
    summary = generate_summary(
        log_file, log_entries, errors, ip_stats, patterns, high_error_periods
    )
    print_summary(summary)

    return summary


def main():
    """Main function to parse arguments and analyze logs"""
    parser = argparse.ArgumentParser(description="Log file analyzer")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument(
        "--format", choices=list(LOG_PATTERNS.keys()), help="Log format (apache, nginx, syslog)"
    )

    args = parser.parse_args()

    analyze_log(args.log_file, args.format)


if __name__ == "__main__":
    main()
