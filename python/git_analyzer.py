#!/usr/bin/env python3
"""
Author : Hariscats
Date   : 2023-06-20
Purpose: Git repository analyzer that provides insights on:
         - Commit history and patterns
         - Contributors and their contributions
         - Branch statistics and divergence
         - File change frequency
         - Code churn metrics
         - Release tag analysis

Requires Git CLI to be installed and accessible
"""

import os
import sys
import re
import argparse
import subprocess
import datetime
from collections import Counter, defaultdict
import json
from operator import itemgetter


class GitAnalyzer:
    """Git repository analyzer for DevOps insights"""

    def __init__(self, repo_path=None):
        """Initialize with repository path"""
        self.repo_path = repo_path if repo_path else os.getcwd()
        
    @staticmethod
    def run_git_command(command, repo_path=None):
        """Run a git command in the repository"""
        try:
            if repo_path:
                # Change to the repository directory
                original_dir = os.getcwd()
                os.chdir(repo_path)
                
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            if repo_path:
                # Change back to original directory
                os.chdir(original_dir)
                
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error executing git command: {e}")
            print(f"STDERR: {e.stderr.strip()}")
            return None
            
    def is_git_repo(self):
        """Check if the path is a git repository"""
        git_dir = os.path.join(self.repo_path, ".git")
        return os.path.exists(git_dir) and os.path.isdir(git_dir)
    
    def get_repo_info(self):
        """Get basic repository information"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        info = {}
        
        # Get remote URL
        remote_url = self.run_git_command("git config --get remote.origin.url", self.repo_path)
        info["Remote URL"] = remote_url if remote_url else "No remote configured"
        
        # Get current branch
        current_branch = self.run_git_command("git rev-parse --abbrev-ref HEAD", self.repo_path)
        info["Current Branch"] = current_branch if current_branch else "Unknown"
        
        # Get last commit
        last_commit = self.run_git_command("git log -1 --pretty=format:'%h - %s (%an, %ar)'", self.repo_path)
        info["Last Commit"] = last_commit if last_commit else "No commits"
        
        # Get all branches
        branches = self.run_git_command("git branch -a", self.repo_path)
        if branches:
            branch_list = [b.strip().replace('* ', '') for b in branches.split('\n')]
            info["Branches"] = branch_list
            info["Branch Count"] = len(branch_list)
        
        # Get tag count
        tags = self.run_git_command("git tag", self.repo_path)
        if tags:
            tag_list = tags.split('\n')
            info["Tag Count"] = len(tag_list)
        else:
            info["Tag Count"] = 0
        
        # Get commit count
        commit_count = self.run_git_command("git rev-list --count HEAD", self.repo_path)
        info["Commit Count"] = commit_count if commit_count else "0"
        
        # Get first commit date
        first_commit_date = self.run_git_command("git log --reverse --pretty=format:'%ad' --date=short | head -1", self.repo_path)
        info["First Commit"] = first_commit_date if first_commit_date else "Unknown"
        
        # Get repository age
        if first_commit_date:
            try:
                first_date = datetime.datetime.strptime(first_commit_date, '%Y-%m-%d')
                today = datetime.datetime.now()
                age_days = (today - first_date).days
                info["Repository Age"] = f"{age_days} days"
            except ValueError:
                info["Repository Age"] = "Unknown"
        
        return info
    
    def get_commit_history(self, days=30, branch=None):
        """Get commit history for the specified time period"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        # Set up branch specification
        branch_spec = f"{branch}" if branch else "HEAD"
        
        # Get commits for the specified time period
        cmd = f"git log --pretty=format:'%h|%an|%ae|%ad|%s' --date=short --since='{days} days ago' {branch_spec}"
        commit_data = self.run_git_command(cmd, self.repo_path)
        
        if not commit_data:
            return []
        
        commits = []
        for line in commit_data.split('\n'):
            if '|' in line:
                hash, author, email, date, subject = line.split('|', 4)
                commits.append({
                    "hash": hash,
                    "author": author,
                    "email": email,
                    "date": date,
                    "subject": subject
                })
        
        return commits
    
    def get_contributor_stats(self):
        """Get statistics about repository contributors"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        # Get detailed contributor statistics
        cmd = "git shortlog -sn --all"
        contributors_data = self.run_git_command(cmd, self.repo_path)
        
        if not contributors_data:
            return []
        
        # Parse contributor data
        contributors = []
        for line in contributors_data.split('\n'):
            if line.strip():
                match = re.match(r'\s*(\d+)\s+(.+)', line)
                if match:
                    count, name = match.groups()
                    contributors.append({
                        "name": name,
                        "commits": int(count)
                    })
        
        # Get more detailed information about each contributor
        for contributor in contributors:
            name = contributor["name"]
            
            # Get first commit date
            cmd = f"git log --author='{name}' --reverse --pretty=format:'%ad' --date=short | head -1"
            first_date = self.run_git_command(cmd, self.repo_path)
            contributor["first_commit"] = first_date if first_date else "Unknown"
            
            # Get latest commit date
            cmd = f"git log --author='{name}' --pretty=format:'%ad' --date=short | head -1"
            last_date = self.run_git_command(cmd, self.repo_path)
            contributor["latest_commit"] = last_date if last_date else "Unknown"
            
            # Get email(s)
            cmd = f"git log --author='{name}' --pretty=format:'%ae' | sort | uniq"
            emails = self.run_git_command(cmd, self.repo_path)
            contributor["emails"] = emails.split('\n') if emails else []
            
            # Get lines added/removed (approximate)
            cmd = f"git log --author='{name}' --pretty=tformat: --numstat"
            stats_data = self.run_git_command(cmd, self.repo_path)
            
            if stats_data:
                added = 0
                removed = 0
                files_changed = set()
                
                for line in stats_data.split('\n'):
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 3:
                            try:
                                # Handle binary files which are marked as '-'
                                if parts[0] != '-':
                                    added += int(parts[0])
                                if parts[1] != '-':
                                    removed += int(parts[1])
                                files_changed.add(parts[2])
                            except ValueError:
                                pass
                
                contributor["lines_added"] = added
                contributor["lines_removed"] = removed
                contributor["files_changed"] = len(files_changed)
        
        return contributors
    
    def get_branch_stats(self):
        """Get statistics about branches in the repository"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        # Get all branches
        cmd = "git branch -a"
        all_branches = self.run_git_command(cmd, self.repo_path)
        
        if not all_branches:
            return []
        
        branches = []
        local_branches = []
        
        # Extract local branches
        for branch in all_branches.split('\n'):
            branch = branch.strip()
            if branch.startswith('* '):
                branch = branch[2:]  # Remove the '* ' prefix for current branch
                is_current = True
            else:
                is_current = False
                
            if not branch.startswith('remotes/'):
                local_branches.append(branch)
                
                # Get last commit info for this branch
                cmd = f"git log -1 --pretty=format:'%h|%an|%ae|%ad|%s' --date=short {branch}"
                commit_info = self.run_git_command(cmd, self.repo_path)
                
                if commit_info:
                    hash, author, email, date, subject = commit_info.split('|', 4)
                    
                    # Get the age of the branch (days since last commit)
                    try:
                        last_commit_date = datetime.datetime.strptime(date, '%Y-%m-%d')
                        today = datetime.datetime.now()
                        age_days = (today - last_commit_date).days
                    except ValueError:
                        age_days = "Unknown"
                    
                    # Count commits in this branch
                    cmd = f"git rev-list --count {branch}"
                    commit_count = self.run_command_git(cmd, self.repo_path) or "0"
                    
                    branches.append({
                        "name": branch,
                        "current": is_current,
                        "last_commit_hash": hash,
                        "last_commit_author": author,
                        "last_commit_date": date,
                        "last_commit_subject": subject,
                        "age_days": age_days,
                        "commit_count": commit_count
                    })
        
        # For each branch, calculate how far ahead/behind it is from master/main
        main_branch = self.get_main_branch_name()
        
        for branch in branches:
            if branch["name"] != main_branch:
                # Commits ahead of main branch
                cmd = f"git rev-list --count {main_branch}..{branch['name']}"
                ahead = self.run_git_command(cmd, self.repo_path) or "0"
                
                # Commits behind main branch
                cmd = f"git rev-list --count {branch['name']}..{main_branch}"
                behind = self.run_git_command(cmd, self.repo_path) or "0"
                
                branch["ahead_of_main"] = ahead
                branch["behind_main"] = behind
        
        return branches
    
    def get_main_branch_name(self):
        """Determine the main branch name (master or main)"""
        cmd = "git branch"
        branches = self.run_git_command(cmd, self.repo_path)
        
        if branches:
            if 'main' in branches:
                return 'main'
            elif 'master' in branches:
                return 'master'
        
        # Default fallback
        return 'master'
    
    def get_file_change_frequency(self, days=90):
        """Analyze file change frequency within the specified time period"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        # Get all files changed in the time period
        cmd = f"git log --name-only --pretty=format: --since='{days} days ago'"
        changed_files = self.run_git_command(cmd, self.repo_path)
        
        if not changed_files:
            return []
        
        # Count file occurrences
        file_counter = Counter(f for f in changed_files.split('\n') if f.strip())
        
        # Create result with details
        files = []
        for file_path, change_count in file_counter.most_common():
            if file_path:  # Skip empty paths
                # Get last change date
                cmd = f"git log -1 --pretty=format:'%ad' --date=short -- '{file_path}'"
                last_modified = self.run_git_command(cmd, self.repo_path)
                
                # Get creator and creation date
                cmd = f"git log --diff-filter=A --pretty=format:'%an|%ad' --date=short -- '{file_path}'"
                creation_info = self.run_git_command(cmd, self.repo_path)
                
                creator = "Unknown"
                created_date = "Unknown"
                
                if creation_info:
                    try:
                        creator, created_date = creation_info.split('|')
                    except ValueError:
                        pass
                
                files.append({
                    "path": file_path,
                    "changes": change_count,
                    "last_modified": last_modified if last_modified else "Unknown",
                    "creator": creator,
                    "created_date": created_date
                })
        
        return files
    
    def get_code_churn_by_period(self, period='month', count=12):
        """Get code churn metrics (lines added/deleted) by time period"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        if period == 'month':
            # Get code churn by month for the past count months
            cmd = f"git log --pretty=format:'%ad' --date=format:'%Y-%m' --shortstat"
            churn_data = self.run_git_command(cmd, self.repo_path)
        elif period == 'week':
            # Get code churn by week
            cmd = f"git log --pretty=format:'%ad' --date=format:'%Y-%U' --shortstat"
            churn_data = self.run_git_command(cmd, self.repo_path)
        else:
            # Default to daily for any other value
            cmd = f"git log --pretty=format:'%ad' --date=short --shortstat"
            churn_data = self.run_git_command(cmd, self.repo_path)
        
        if not churn_data:
            return []
        
        # Process the output
        lines = churn_data.split('\n')
        churn_by_period = defaultdict(lambda: {"files_changed": 0, "insertions": 0, "deletions": 0, "commits": 0})
        current_period = None
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith(' '):
                # This is a date line
                current_period = line
                churn_by_period[current_period]["commits"] += 1
            elif line and current_period:
                # This is a stats line
                files_match = re.search(r'(\d+) files? changed', line)
                insertions_match = re.search(r'(\d+) insertions?', line)
                deletions_match = re.search(r'(\d+) deletions?', line)
                
                if files_match:
                    churn_by_period[current_period]["files_changed"] += int(files_match.group(1))
                if insertions_match:
                    churn_by_period[current_period]["insertions"] += int(insertions_match.group(1))
                if deletions_match:
                    churn_by_period[current_period]["deletions"] += int(deletions_match.group(1))
        
        # Convert to list and sort by period
        result = []
        for period, stats in churn_by_period.items():
            result.append({
                "period": period,
                **stats,
                "net_lines": stats["insertions"] - stats["deletions"]
            })
        
        # Sort by period (which is date formatted appropriately)
        result.sort(key=itemgetter("period"), reverse=True)
        
        # Limit to the specified count
        return result[:count]
    
    def get_release_analysis(self):
        """Analyze release tags and versions"""
        if not self.is_git_repo():
            return {"Error": "Not a git repository"}
        
        # Get all tags with dates
        cmd = "git for-each-ref --sort=-taggerdate --format='%(refname:short)|%(taggerdate:short)|%(subject)' refs/tags"
        tags_data = self.run_git_command(cmd, self.repo_path)
        
        if not tags_data or tags_data.isspace():
            # Try alternative format for lightweight tags
            cmd = "git for-each-ref --sort=-creatordate --format='%(refname:short)|%(creatordate:short)|%(subject)' refs/tags"
            tags_data = self.run_git_command(cmd, self.repo_path)
            
        if not tags_data or tags_data.isspace():
            return []
        
        tags = []
        for line in tags_data.split('\n'):
            if line.strip():
                parts = line.split('|')
                if len(parts) >= 2:
                    tag_name = parts[0]
                    tag_date = parts[1]
                    tag_message = parts[2] if len(parts) > 2 else ""
                    
                    # Get commit hash for this tag
                    cmd = f"git rev-parse {tag_name}"
                    commit_hash = self.run_git_command(cmd, self.repo_path)
                    
                    # Get stats for changes since previous tag
                    if len(tags) > 0:
                        previous_tag = tags[-1]["name"]
                        cmd = f"git diff --shortstat {previous_tag}..{tag_name}"
                    else:
                        cmd = f"git diff --shortstat {tag_name}^ {tag_name}"
                        
                    diff_stats = self.run_git_command(cmd, self.repo_path)
                    
                    # Parse diff stats
                    files_changed = 0
                    insertions = 0
                    deletions = 0
                    
                    if diff_stats:
                        files_match = re.search(r'(\d+) files? changed', diff_stats)
                        insertions_match = re.search(r'(\d+) insertions?', diff_stats)
                        deletions_match = re.search(r'(\d+) deletions?', diff_stats)
                        
                        if files_match:
                            files_changed = int(files_match.group(1))
                        if insertions_match:
                            insertions = int(insertions_match.group(1))
                        if deletions_match:
                            deletions = int(deletions_match.group(1))
                    
                    # Get contributors for this release
                    if len(tags) > 0:
                        previous_tag = tags[-1]["name"]
                        cmd = f"git shortlog -sn {previous_tag}..{tag_name}"
                    else:
                        cmd = f"git shortlog -sn {tag_name}"
                        
                    contributors_data = self.run_git_command(cmd, self.repo_path)
                    contributors = []
                    
                    if contributors_data:
                        for contributor_line in contributors_data.split('\n'):
                            if contributor_line.strip():
                                match = re.match(r'\s*(\d+)\s+(.+)', contributor_line)
                                if match:
                                    count, name = match.groups()
                                    contributors.append({"name": name, "commits": int(count)})
                    
                    tags.append({
                        "name": tag_name,
                        "date": tag_date,
                        "message": tag_message,
                        "commit": commit_hash,
                        "files_changed": files_changed,
                        "insertions": insertions,
                        "deletions": deletions,
                        "net_lines": insertions - deletions,
                        "contributors": contributors,
                        "contributor_count": len(contributors)
                    })
        
        # Sort tags by date (newest first)
        return sorted(tags, key=lambda x: x.get("date", ""), reverse=True)


def print_json(data):
    """Print data in JSON format"""
    print(json.dumps(data, indent=2))


def print_table(data, headers=None, sort_by=None, reverse=False):
    """Print data in a tabular format"""
    if not data:
        print("No data available.")
        return
        
    # Ensure we're working with a list of dictionaries
    if not isinstance(data, list) or not isinstance(data[0], dict):
        print("Data format not suitable for tabular display.")
        return
    
    # Sort data if specified
    if sort_by:
        data = sorted(data, key=lambda x: x.get(sort_by, ""), reverse=reverse)
    
    # Determine headers if not provided
    if not headers:
        headers = list(data[0].keys())
    
    # Calculate column widths
    col_widths = [len(str(h)) for h in headers]
    
    for item in data:
        for i, header in enumerate(headers):
            if header in item:
                col_widths[i] = max(col_widths[i], len(str(item[header])))
    
    # Print header row
    header_row = " | ".join(f"{h:{w}}" for h, w in zip(headers, col_widths))
    print(header_row)
    print("-" * len(header_row))
    
    # Print data rows
    for item in data:
        row = []
        for i, header in enumerate(headers):
            value = item.get(header, "")
            row.append(f"{str(value):{col_widths[i]}}")
        print(" | ".join(row))


def main():
    """Main function to parse arguments and analyze git repositories"""
    parser = argparse.ArgumentParser(description='Git repository analyzer')
    
    parser.add_argument('--path', '-p', help='Path to the git repository (default: current directory)')
    parser.add_argument('--json', '-j', action='store_true', help='Output in JSON format')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show repository information')
    
    # Commits command
    commits_parser = subparsers.add_parser('commits', help='Show commit history')
    commits_parser.add_argument('--days', '-d', type=int, default=30, help='Number of days to analyze (default: 30)')
    commits_parser.add_argument('--branch', '-b', help='Branch to analyze (default: current branch)')
    
    # Contributors command
    contrib_parser = subparsers.add_parser('contributors', help='Show contributor statistics')
    
    # Branches command
    branches_parser = subparsers.add_parser('branches', help='Show branch statistics')
    
    # Files command
    files_parser = subparsers.add_parser('files', help='Show file change frequency')
    files_parser.add_argument('--days', '-d', type=int, default=90, help='Number of days to analyze (default: 90)')
    
    # Churn command
    churn_parser = subparsers.add_parser('churn', help='Show code churn metrics')
    churn_parser.add_argument('--period', '-p', choices=['day', 'week', 'month'], default='month', 
                             help='Time period for grouping (default: month)')
    churn_parser.add_argument('--count', '-c', type=int, default=12, 
                             help='Number of periods to show (default: 12)')
    
    # Releases command
    releases_parser = subparsers.add_parser('releases', help='Show release/tag analysis')
    
    args = parser.parse_args()
    
    # Default to info command if no command specified
    if not args.command:
        args.command = 'info'
    
    # Create analyzer for specified repository or current directory
    repo_path = args.path if args.path else os.getcwd()
    analyzer = GitAnalyzer(repo_path)
    
    # Check if this is a git repository
    if not analyzer.is_git_repo():
        print(f"Error: {repo_path} is not a git repository.")
        return 1
    
    # Execute requested command
    if args.command == 'info':
        result = analyzer.get_repo_info()
        if args.json:
            print_json(result)
        else:
            print("Repository Information:")
            print("=" * 50)
            for key, value in result.items():
                if isinstance(value, list):
                    print(f"{key}:")
                    for item in value:
                        print(f"  - {item}")
                else:
                    print(f"{key}: {value}")
    
    elif args.command == 'commits':
        result = analyzer.get_commit_history(args.days, args.branch)
        if args.json:
            print_json(result)
        else:
            print(f"Commit History (last {args.days} days):")
            print("=" * 50)
            headers = ["hash", "date", "author", "subject"]
            print_table(result, headers, sort_by="date", reverse=True)
    
    elif args.command == 'contributors':
        result = analyzer.get_contributor_stats()
        if args.json:
            print_json(result)
        else:
            print("Contributor Statistics:")
            print("=" * 50)
            headers = ["name", "commits", "first_commit", "latest_commit", "lines_added", "lines_removed"]
            print_table(result, headers, sort_by="commits", reverse=True)
    
    elif args.command == 'branches':
        result = analyzer.get_branch_stats()
        if args.json:
            print_json(result)
        else:
            print("Branch Statistics:")
            print("=" * 50)
            headers = ["name", "current", "last_commit_date", "age_days", "commit_count", "ahead_of_main", "behind_main"]
            print_table(result, headers)
    
    elif args.command == 'files':
        result = analyzer.get_file_change_frequency(args.days)
        if args.json:
            print_json(result)
        else:
            print(f"File Change Frequency (last {args.days} days):")
            print("=" * 50)
            headers = ["path", "changes", "last_modified", "creator", "created_date"]
            print_table(result, headers, sort_by="changes", reverse=True)
    
    elif args.command == 'churn':
        result = analyzer.get_code_churn_by_period(args.period, args.count)
        if args.json:
            print_json(result)
        else:
            print(f"Code Churn by {args.period} (last {args.count} periods):")
            print("=" * 50)
            headers = ["period", "commits", "files_changed", "insertions", "deletions", "net_lines"]
            print_table(result, headers)
    
    elif args.command == 'releases':
        result = analyzer.get_release_analysis()
        if args.json:
            print_json(result)
        else:
            print("Release/Tag Analysis:")
            print("=" * 50)
            headers = ["name", "date", "files_changed", "insertions", "deletions", "contributor_count"]
            print_table(result, headers)


if __name__ == "__main__":
    main()