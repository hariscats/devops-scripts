#!/usr/bin/env python3
"""
Author : Hariscats
Date   : 2023-06-25
Purpose: AWS Resource Inspector:
         - Inventory of AWS resources across regions and services
         - Cost analysis and optimization recommendations
         - Identify underutilized resources
         - Security assessment of key settings
         - Compliance with best practices

Depends on boto3 library (pip install boto3)
AWS credentials must be configured via aws configure, env vars, or instance profile
"""

import argparse
import datetime
import json
import os
import sys
import time
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError
except ImportError:
    print("Error: boto3 library not found. Please install it using: ")
    print("pip install boto3")
    sys.exit(1)


class AWSInspector:
    """AWS resource inventory and analysis"""

    def __init__(self, regions=None, profile=None):
        """
        Initialize with optional regions list and profile name
        If regions is None, will use all available regions
        """
        self.session = self._create_session(profile)

        # Get available regions if not specified
        if not regions:
            ec2_client = self.session.client("ec2", region_name=self._get_default_region())
            try:
                regions_response = ec2_client.describe_regions()
                self.regions = [region["RegionName"] for region in regions_response["Regions"]]
            except (ClientError, NoRegionError) as e:
                print(f"Error accessing AWS: {e}")
                print("Please ensure your AWS credentials are configured correctly.")
                sys.exit(1)
        else:
            self.regions = regions

        print(f"Using regions: {', '.join(self.regions)}")

        # Initialize cache
        self.cache = {}

    def _create_session(self, profile):
        """Create a boto3 session with optional profile"""
        try:
            if profile:
                return boto3.Session(profile_name=profile)
            else:
                return boto3.Session()
        except Exception as e:
            print(f"Error creating AWS session: {e}")
            sys.exit(1)

    def _get_default_region(self):
        """Get the default region from environment or config"""
        return os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    def _get_client(self, service, region):
        """Get a boto3 client for the specified service and region"""
        cache_key = f"{service}_{region}"
        if cache_key not in self.cache:
            self.cache[cache_key] = self.session.client(service, region_name=region)
        return self.cache[cache_key]

    def _get_account_id(self):
        """Get the current AWS account ID"""
        sts_client = self._get_client("sts", self._get_default_region())
        try:
            return sts_client.get_caller_identity()["Account"]
        except Exception:
            return "Unknown"

    def _format_size(self, size_bytes):
        """Format byte size to human-readable format"""
        if size_bytes == 0:
            return "0B"

        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes: .2f} {units[i]}"

    def _format_timestamp(self, ts):
        """Format timestamp to readable format"""
        if not ts:
            return "N/A"

        if isinstance(ts, datetime.datetime):
            return ts.strftime("%Y-%m-%d %H: %M: %S")
        return str(ts)

    def get_ec2_inventory(self, region):
        """Get EC2 instance inventory for a region"""
        ec2_client = self._get_client("ec2", region)

        try:
            # Get all instances
            response = ec2_client.describe_instances()

            instances = []
            total_running = 0
            total_stopped = 0

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    instance_type = instance.get("InstanceType")
                    state = instance.get("State", {}).get("Name", "unknown")

                    # Count by state
                    if state == "running":
                        total_running += 1
                    elif state == "stopped":
                        total_stopped += 1

                    # Get name tag
                    name = "N/A"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    # Calculate days since launch
                    launch_time = instance.get("LaunchTime")
                    days_running = 0
                    if launch_time:
                        delta = datetime.datetime.now(launch_time.tzinfo) - launch_time
                        days_running = delta.days

                    instance_data = {
                        "InstanceId": instance_id,
                        "Name": name,
                        "Type": instance_type,
                        "State": state,
                        "LaunchTime": self._format_timestamp(launch_time),
                        "DaysRunning": days_running,
                        "PublicIP": instance.get("PublicIpAddress", "N/A"),
                        "PrivateIP": instance.get("PrivateIpAddress", "N/A"),
                        "VPC": instance.get("VpcId", "N/A"),
                        "Subnet": instance.get("SubnetId", "N/A"),
                        "Architecture": instance.get("Architecture", "N/A"),
                    }

                    instances.append(instance_data)

            # Get pricing information for the instance types
            # Note: This would require a separate pricing API call
            # Not implementing here due to complexity, but would be a good addition

            return {
                "Instances": instances,
                "RunningCount": total_running,
                "StoppedCount": total_stopped,
                "TotalCount": len(instances),
            }
        except ClientError as e:
            print(f"Error getting EC2 inventory for region {region}: {e}")
            return {
                "Instances": [],
                "RunningCount": 0,
                "StoppedCount": 0,
                "TotalCount": 0,
                "Error": str(e),
            }

    def get_s3_inventory(self):
        """Get S3 bucket inventory (global service)"""
        s3_client = self._get_client("s3", self._get_default_region())

        try:
            response = s3_client.list_buckets()

            buckets = []
            total_size = 0
            bucket_count = 0

            for bucket in response["Buckets"]:
                bucket_name = bucket["Name"]
                bucket_count += 1

                # Get bucket region
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = location["LocationConstraint"] or "us-east-1"  # None means us-east-1
                except ClientError:
                    region = "Unknown"

                # Calculate bucket size (might be slow for large buckets)
                bucket_size = 0
                object_count = 0

                try:
                    s3_region_client = self._get_client(
                        "s3", region if region != "Unknown" else self._get_default_region()
                    )
                    paginator = s3_region_client.get_paginator("list_objects_v2")
                    page_iterator = paginator.paginate(Bucket=bucket_name)

                    for page in page_iterator:
                        if "Contents" in page:
                            for obj in page["Contents"]:
                                bucket_size += obj["Size"]
                                object_count += 1

                except ClientError as e:
                    print(f"Error calculating size for bucket {bucket_name}: {e}")

                total_size += bucket_size

                bucket_data = {
                    "Name": bucket_name,
                    "CreationDate": self._format_timestamp(bucket["CreationDate"]),
                    "Region": region,
                    "SizeBytes": bucket_size,
                    "SizeHuman": self._format_size(bucket_size),
                    "ObjectCount": object_count,
                }

                # Check bucket encryption
                try:
                    encryption = s3_region_client.get_bucket_encryption(Bucket=bucket_name)
                    bucket_data["Encrypted"] = True
                    bucket_data["EncryptionType"] = (
                        encryption.get("ServerSideEncryptionConfiguration", {})
                        .get("Rules", [{}])[0]
                        .get("ApplyServerSideEncryptionByDefault", {})
                        .get("SSEAlgorithm", "Unknown")
                    )
                except ClientError:
                    bucket_data["Encrypted"] = False
                    bucket_data["EncryptionType"] = "None"

                # Check bucket public access settings
                try:
                    public_access = s3_region_client.get_public_access_block(Bucket=bucket_name)
                    bucket_data["BlockPublicAcls"] = public_access.get(
                        "PublicAccessBlockConfiguration", {}
                    ).get("BlockPublicAcls", False)
                    bucket_data["BlockPublicPolicy"] = public_access.get(
                        "PublicAccessBlockConfiguration", {}
                    ).get("BlockPublicPolicy", False)
                    bucket_data["IgnorePublicAcls"] = public_access.get(
                        "PublicAccessBlockConfiguration", {}
                    ).get("IgnorePublicAcls", False)
                    bucket_data["RestrictPublicBuckets"] = public_access.get(
                        "PublicAccessBlockConfiguration", {}
                    ).get("RestrictPublicBuckets", False)
                except ClientError:
                    bucket_data["BlockPublicAcls"] = "Unknown"
                    bucket_data["BlockPublicPolicy"] = "Unknown"
                    bucket_data["IgnorePublicAcls"] = "Unknown"
                    bucket_data["RestrictPublicBuckets"] = "Unknown"

                buckets.append(bucket_data)

            return {
                "Buckets": buckets,
                "TotalSize": total_size,
                "TotalSizeHuman": self._format_size(total_size),
                "TotalCount": bucket_count,
            }
        except ClientError as e:
            print(f"Error getting S3 inventory: {e}")
            return {
                "Buckets": [],
                "TotalSize": 0,
                "TotalSizeHuman": "0 B",
                "TotalCount": 0,
                "Error": str(e),
            }

    def get_rds_inventory(self, region):
        """Get RDS instance inventory for a region"""
        rds_client = self._get_client("rds", region)

        try:
            response = rds_client.describe_db_instances()

            instances = []
            multi_az_count = 0

            for db in response.get("DBInstances", []):
                instance_id = db.get("DBInstanceIdentifier")
                instance_class = db.get("DBInstanceClass")
                engine = db.get("Engine")
                status = db.get("DBInstanceStatus", "unknown")
                storage = db.get("AllocatedStorage", 0)  # in GB

                if db.get("MultiAZ", False):
                    multi_az_count += 1

                instance_data = {
                    "DBInstanceIdentifier": instance_id,
                    "DBInstanceClass": instance_class,
                    "Engine": engine,
                    "EngineVersion": db.get("EngineVersion", "N/A"),
                    "Status": status,
                    "AllocatedStorage": storage,
                    "StorageType": db.get("StorageType", "N/A"),
                    "MultiAZ": db.get("MultiAZ", False),
                    "PubliclyAccessible": db.get("PubliclyAccessible", False),
                    "Endpoint": db.get("Endpoint", {}).get("Address", "N/A"),
                    "Port": db.get("Endpoint", {}).get("Port", "N/A"),
                    "VPC": db.get("DBSubnetGroup", {}).get("VpcId", "N/A"),
                    "CreatedTime": self._format_timestamp(db.get("InstanceCreateTime")),
                    "BackupRetention": db.get("BackupRetentionPeriod", 0),
                    "Encrypted": db.get("StorageEncrypted", False),
                }

                instances.append(instance_data)

            return {
                "DBInstances": instances,
                "TotalCount": len(instances),
                "MultiAZCount": multi_az_count,
            }
        except ClientError as e:
            print(f"Error getting RDS inventory for region {region}: {e}")
            return {"DBInstances": [], "TotalCount": 0, "MultiAZCount": 0, "Error": str(e)}

    def get_lambda_inventory(self, region):
        """Get Lambda function inventory for a region"""
        lambda_client = self._get_client("lambda", region)

        try:
            response = lambda_client.list_functions()

            functions = []
            total_size = 0

            for func in response.get("Functions", []):
                function_name = func.get("FunctionName")
                runtime = func.get("Runtime")
                memory = func.get("MemorySize", 0)  # in MB
                code_size = func.get("CodeSize", 0)  # in bytes

                total_size += code_size

                function_data = {
                    "FunctionName": function_name,
                    "Runtime": runtime,
                    "MemorySize": memory,
                    "CodeSize": self._format_size(code_size),
                    "Handler": func.get("Handler", "N/A"),
                    "LastModified": func.get("LastModified", "N/A"),
                    "Timeout": func.get("Timeout", 0),
                    "Environment": "Yes" if "Environment" in func else "No",
                }

                # Get function concurrency settings
                try:
                    concurrency = lambda_client.get_function_concurrency(FunctionName=function_name)
                    function_data["ReservedConcurrency"] = concurrency.get(
                        "ReservedConcurrentExecutions", "Unreserved"
                    )
                except ClientError:
                    function_data["ReservedConcurrency"] = "Unreserved"

                functions.append(function_data)

            return {
                "Functions": functions,
                "TotalCount": len(functions),
                "TotalSize": self._format_size(total_size),
            }
        except ClientError as e:
            print(f"Error getting Lambda inventory for region {region}: {e}")
            return {"Functions": [], "TotalCount": 0, "TotalSize": "0 B", "Error": str(e)}

    def get_iam_inventory(self):
        """Get IAM inventory (global service)"""
        iam_client = self._get_client("iam", self._get_default_region())

        try:
            # Get users
            users_response = iam_client.list_users()
            users = []

            for user in users_response.get("Users", []):
                username = user.get("UserName")
                user_id = user.get("UserId")

                # Check if user has MFA enabled
                mfa_devices = iam_client.list_mfa_devices(UserName=username)
                mfa_enabled = len(mfa_devices.get("MFADevices", [])) > 0

                # Get access keys
                access_keys = iam_client.list_access_keys(UserName=username)
                access_key_details = []

                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key.get("AccessKeyId")
                    status = key.get("Status")
                    created = key.get("CreateDate")

                    # Get last used info
                    try:
                        key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                        last_used = key_last_used.get("AccessKeyLastUsed", {}).get(
                            "LastUsedDate", "Never"
                        )
                    except ClientError:
                        last_used = "Error"

                    access_key_details.append(
                        {
                            "AccessKeyId": key_id,
                            "Status": status,
                            "Created": self._format_timestamp(created),
                            "LastUsed": self._format_timestamp(last_used),
                        }
                    )

                user_data = {
                    "UserName": username,
                    "UserId": user_id,
                    "Arn": user.get("Arn", "N/A"),
                    "CreateDate": self._format_timestamp(user.get("CreateDate")),
                    "PasswordLastUsed": self._format_timestamp(
                        user.get("PasswordLastUsed", "Never")
                    ),
                    "MFAEnabled": mfa_enabled,
                    "AccessKeys": access_key_details,
                    "AccessKeyCount": len(access_key_details),
                }

                users.append(user_data)

            # Get roles
            roles_response = iam_client.list_roles()
            roles = []

            for role in roles_response.get("Roles", []):
                role_data = {
                    "RoleName": role.get("RoleName", "N/A"),
                    "RoleId": role.get("RoleId", "N/A"),
                    "Arn": role.get("Arn", "N/A"),
                    "CreateDate": self._format_timestamp(role.get("CreateDate")),
                    "Description": role.get("Description", "N/A"),
                }

                roles.append(role_data)

            # Get policies
            policies_response = iam_client.list_policies(Scope="Local")  # Only customer-managed
            policies = []

            for policy in policies_response.get("Policies", []):
                policy_data = {
                    "PolicyName": policy.get("PolicyName", "N/A"),
                    "PolicyId": policy.get("PolicyId", "N/A"),
                    "Arn": policy.get("Arn", "N/A"),
                    "CreateDate": self._format_timestamp(policy.get("CreateDate")),
                    "UpdateDate": self._format_timestamp(policy.get("UpdateDate")),
                    "DefaultVersionId": policy.get("DefaultVersionId", "N/A"),
                    "AttachmentCount": policy.get("AttachmentCount", 0),
                }

                policies.append(policy_data)

            # Check password policy
            try:
                password_policy = iam_client.get_account_password_policy()
                policy = password_policy.get("PasswordPolicy", {})
            except ClientError:
                policy = {}

            return {
                "Users": users,
                "UserCount": len(users),
                "Roles": roles,
                "RoleCount": len(roles),
                "Policies": policies,
                "PolicyCount": len(policies),
                "PasswordPolicy": {
                    "MinimumPasswordLength": policy.get("MinimumPasswordLength", 0),
                    "RequireSymbols": policy.get("RequireSymbols", False),
                    "RequireNumbers": policy.get("RequireNumbers", False),
                    "RequireUppercaseCharacters": policy.get("RequireUppercaseCharacters", False),
                    "RequireLowercaseCharacters": policy.get("RequireLowercaseCharacters", False),
                    "AllowUsersToChangePassword": policy.get("AllowUsersToChangePassword", False),
                    "ExpirePasswords": policy.get("ExpirePasswords", False),
                    "MaxPasswordAge": policy.get("MaxPasswordAge", 0),
                },
            }
        except ClientError as e:
            print(f"Error getting IAM inventory: {e}")
            return {
                "Users": [],
                "UserCount": 0,
                "Roles": [],
                "RoleCount": 0,
                "Policies": [],
                "PolicyCount": 0,
                "Error": str(e),
            }

    def get_ebs_inventory(self, region):
        """Get EBS volume inventory for a region"""
        ec2_client = self._get_client("ec2", region)

        try:
            response = ec2_client.describe_volumes()

            volumes = []
            total_size_gb = 0
            unused_count = 0
            unencrypted_count = 0

            for volume in response.get("Volumes", []):
                volume_id = volume.get("VolumeId")
                volume_type = volume.get("VolumeType")
                size = volume.get("Size", 0)  # in GB
                state = volume.get("State", "unknown")

                total_size_gb += size

                # Check if volume is attached
                attachments = volume.get("Attachments", [])
                is_attached = len(attachments) > 0

                if not is_attached:
                    unused_count += 1

                # Check if volume is encrypted
                is_encrypted = volume.get("Encrypted", False)

                if not is_encrypted:
                    unencrypted_count += 1

                volume_data = {
                    "VolumeId": volume_id,
                    "VolumeType": volume_type,
                    "Size": size,
                    "State": state,
                    "CreateTime": self._format_timestamp(volume.get("CreateTime")),
                    "AvailabilityZone": volume.get("AvailabilityZone", "N/A"),
                    "Encrypted": is_encrypted,
                    "KmsKeyId": volume.get("KmsKeyId", "N/A"),
                    "Iops": volume.get("Iops", "N/A"),
                    "Attached": is_attached,
                    "InstanceId": attachments[0].get("InstanceId", "N/A") if is_attached else "N/A",
                    "AttachTime": (
                        self._format_timestamp(attachments[0].get("AttachTime"))
                        if is_attached
                        else "N/A"
                    ),
                    "Device": attachments[0].get("Device", "N/A") if is_attached else "N/A",
                }

                volumes.append(volume_data)

            return {
                "Volumes": volumes,
                "TotalCount": len(volumes),
                "TotalSizeGB": total_size_gb,
                "UnusedCount": unused_count,
                "UnencryptedCount": unencrypted_count,
            }
        except ClientError as e:
            print(f"Error getting EBS inventory for region {region}: {e}")
            return {
                "Volumes": [],
                "TotalCount": 0,
                "TotalSizeGB": 0,
                "UnusedCount": 0,
                "UnencryptedCount": 0,
                "Error": str(e),
            }

    def get_optimization_recommendations(self, inventory):
        """Generate cost optimization recommendations based on inventory"""
        recommendations = []

        # Check for stopped EC2 instances
        for region, data in inventory.get("ec2", {}).items():
            instances = data.get("Instances", [])
            for instance in instances:
                if instance.get("State") == "stopped" and instance.get("DaysRunning", 0) > 30:
                    recommendations.append(
                        {
                            "Type": "EC2",
                            "Resource": f"{instance.get('InstanceId')} ({instance.get('Name')})",
                            "Region": region,
                            "Issue": "Instance stopped for over 30 days",
                            "Recommendation": "Consider terminating the instance and its volumes if no longer needed",
                            "EstimatedSavings": "Variable",  # Would need pricing API integration
                        }
                    )

        # Check for unattached EBS volumes
        for region, data in inventory.get("ebs", {}).items():
            volumes = data.get("Volumes", [])
            for volume in volumes:
                if not volume.get("Attached"):
                    # Calculate approximate cost based on volume type and size
                    size_gb = volume.get("Size", 0)
                    volume_type = volume.get("VolumeType", "gp2")

                    # Very rough pricing estimate - would need pricing API for accuracy
                    if volume_type == "gp2" or volume_type == "gp3":
                        monthly_cost = size_gb * 0.10  # $0.10 per GB-month is approximate
                    elif volume_type == "io1" or volume_type == "io2":
                        monthly_cost = size_gb * 0.125  # Higher for provisioned IOPS
                    else:
                        monthly_cost = size_gb * 0.08  # Standard, sc1, st1

                    recommendations.append(
                        {
                            "Type": "EBS",
                            "Resource": volume.get("VolumeId"),
                            "Region": region,
                            "Issue": "Unattached EBS volume",
                            "Recommendation": "Delete the volume if not needed or create a snapshot before deletion",
                            "EstimatedSavings": f"~${monthly_cost: .2f}/month",
                        }
                    )

        # Check for RDS instances that could use reserved instances
        for region, data in inventory.get("rds", {}).items():
            instances = data.get("DBInstances", [])
            for instance in instances:
                # This is a simplified check - a real implementation would look at usage patterns
                recommendations.append(
                    {
                        "Type": "RDS",
                        "Resource": instance.get("DBInstanceIdentifier"),
                        "Region": region,
                        "Issue": "On-demand RDS instance",
                        "Recommendation": "Consider Reserved Instances for long-running databases",
                        "EstimatedSavings": "Up to 60% compared to on-demand",
                    }
                )

        # Check S3 bucket lifecycle policies
        for bucket in inventory.get("s3", {}).get("Buckets", []):
            bucket_name = bucket.get("Name")
            object_count = bucket.get("ObjectCount", 0)

            if object_count > 100000:  # Just an example threshold
                recommendations.append(
                    {
                        "Type": "S3",
                        "Resource": bucket_name,
                        "Region": bucket.get("Region"),
                        "Issue": "Large number of objects without lifecycle policy",
                        "Recommendation": "Implement lifecycle policies to transition infrequently accessed data to cheaper storage classes",
                        "EstimatedSavings": "Variable based on data patterns",
                    }
                )

        # Check security recommendations
        # Check for unencrypted EBS volumes
        for region, data in inventory.get("ebs", {}).items():
            volumes = data.get("Volumes", [])
            for volume in volumes:
                if not volume.get("Encrypted"):
                    recommendations.append(
                        {
                            "Type": "Security",
                            "Resource": volume.get("VolumeId"),
                            "Region": region,
                            "Issue": "Unencrypted EBS volume",
                            "Recommendation": "Create an encrypted copy of the volume",
                            "EstimatedSavings": "N/A - Security Improvement",
                        }
                    )

        # Check for S3 buckets without encryption
        for bucket in inventory.get("s3", {}).get("Buckets", []):
            if not bucket.get("Encrypted"):
                recommendations.append(
                    {
                        "Type": "Security",
                        "Resource": bucket.get("Name"),
                        "Region": bucket.get("Region"),
                        "Issue": "S3 bucket without default encryption",
                        "Recommendation": "Enable default encryption for the bucket",
                        "EstimatedSavings": "N/A - Security Improvement",
                    }
                )

        # Check for IAM users without MFA
        for user in inventory.get("iam", {}).get("Users", []):
            if not user.get("MFAEnabled"):
                recommendations.append(
                    {
                        "Type": "Security",
                        "Resource": user.get("UserName"),
                        "Region": "global",
                        "Issue": "IAM user without MFA enabled",
                        "Recommendation": "Enable MFA for the IAM user",
                        "EstimatedSavings": "N/A - Security Improvement",
                    }
                )

            # Check for old access keys
            for key in user.get("AccessKeys", []):
                # Parse the creation timestamp
                if key.get("Status") == "Active":
                    try:
                        created_str = key.get("Created")
                        # Simple string comparison for dates in format 'YYYY-MM-DD'
                        if created_str and created_str.startswith("20"):  # Basic validation
                            created_date = datetime.datetime.strptime(
                                created_str.split()[0], "%Y-%m-%d"
                            )
                            today = datetime.datetime.now()
                            days_old = (today - created_date).days

                            if days_old > 90:  # Another example threshold
                                recommendations.append(
                                    {
                                        "Type": "Security",
                                        "Resource": f"{user.get('UserName')} - {key.get('AccessKeyId')}",
                                        "Region": "global",
                                        "Issue": f"Access key is {days_old} days old",
                                        "Recommendation": "Rotate access keys regularly (recommended every 90 days)",
                                        "EstimatedSavings": "N/A - Security Improvement",
                                    }
                                )
                    except (ValueError, TypeError):
                        pass

        return recommendations

    def get_full_inventory(self):
        """Get complete inventory across all configured regions"""
        inventory = {
            "account_id": self._get_account_id(),
            "timestamp": self._format_timestamp(datetime.datetime.now()),
            "s3": self.get_s3_inventory(),
            "iam": self.get_iam_inventory(),
            "ec2": {},
            "ebs": {},
            "rds": {},
            "lambda": {},
        }

        # Collect region-specific resources
        for region in self.regions:
            print(f"Collecting inventory for region: {region}...")
            inventory["ec2"][region] = self.get_ec2_inventory(region)
            inventory["ebs"][region] = self.get_ebs_inventory(region)
            inventory["rds"][region] = self.get_rds_inventory(region)
            inventory["lambda"][region] = self.get_lambda_inventory(region)

        # Generate recommendations
        print("Generating recommendations...")
        inventory["recommendations"] = self.get_optimization_recommendations(inventory)

        return inventory

    def print_inventory_summary(self, inventory):
        """Print a summary of the inventory"""
        print("\n===== AWS Resource Inventory Summary =====")
        print(f"Account ID: {inventory['account_id']}")
        print(f"Timestamp: {inventory['timestamp']}")
        print("\n----- EC2 Instances -----")
        total_running = sum(data.get("RunningCount", 0) for data in inventory["ec2"].values())
        total_stopped = sum(data.get("StoppedCount", 0) for data in inventory["ec2"].values())
        total_instances = sum(data.get("TotalCount", 0) for data in inventory["ec2"].values())
        print(
            f"Total Instances: {total_instances} (Running: {total_running}, Stopped: {total_stopped})"
        )

        print("\n----- EBS Volumes -----")
        total_volumes = sum(data.get("TotalCount", 0) for data in inventory["ebs"].values())
        total_size = sum(data.get("TotalSizeGB", 0) for data in inventory["ebs"].values())
        unused_volumes = sum(data.get("UnusedCount", 0) for data in inventory["ebs"].values())
        unencrypted = sum(data.get("UnencryptedCount", 0) for data in inventory["ebs"].values())
        print(f"Total Volumes: {total_volumes} (Size: {total_size} GB)")
        print(f"Unattached Volumes: {unused_volumes}")
        print(f"Unencrypted Volumes: {unencrypted}")

        print("\n----- S3 Buckets -----")
        print(f"Total Buckets: {inventory['s3'].get('TotalCount', 0)}")
        print(f"Total Size: {inventory['s3'].get('TotalSizeHuman', '0')}")

        print("\n----- RDS Databases -----")
        total_dbs = sum(data.get("TotalCount", 0) for data in inventory["rds"].values())
        multi_az_dbs = sum(data.get("MultiAZCount", 0) for data in inventory["rds"].values())
        print(f"Total DB Instances: {total_dbs} (Multi-AZ: {multi_az_dbs})")

        print("\n----- Lambda Functions -----")
        total_functions = sum(data.get("TotalCount", 0) for data in inventory["lambda"].values())
        print(f"Total Lambda Functions: {total_functions}")

        print("\n----- IAM -----")
        print(f"IAM Users: {inventory['iam'].get('UserCount', 0)}")
        print(f"IAM Roles: {inventory['iam'].get('RoleCount', 0)}")
        print(f"IAM Policies: {inventory['iam'].get('PolicyCount', 0)}")

        print("\n----- Recommendations -----")
        recommendations = inventory.get("recommendations", [])
        cost_recs = [r for r in recommendations if r.get("Type") != "Security"]
        security_recs = [r for r in recommendations if r.get("Type") == "Security"]

        print(f"Cost Optimization Recommendations: {len(cost_recs)}")
        print(f"Security Recommendations: {len(security_recs)}")


def main():
    """Main function to parse arguments and execute commands"""
    parser = argparse.ArgumentParser(description="AWS Resource Inspector")

    parser.add_argument(
        "--regions", nargs="+", help="AWS regions to inspect (default: all regions)"
    )
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--output", help="Output file for full inventory (JSON format)")
    parser.add_argument(
        "--service",
        choices=["ec2", "ebs", "s3", "rds", "lambda", "iam", "all"],
        default="all",
        help="Service to inspect (default: all)",
    )

    args = parser.parse_args()

    # Create inspector
    inspector = AWSInspector(args.regions, args.profile)

    # If specific service requested
    if args.service != "all":
        print(f"Inspecting {args.service.upper()} resources...")

        if args.service == "ec2":
            for region in inspector.regions:
                print(f"\nEC2 Instances in {region}: ")
                ec2_data = inspector.get_ec2_inventory(region)
                print(
                    f"Total: {ec2_data['TotalCount']} (Running: {ec2_data['RunningCount']}, Stopped: {ec2_data['StoppedCount']})"
                )

                # Print instance details
                for i, instance in enumerate(ec2_data["Instances"]):
                    print(f"\n{i+1}. {instance['InstanceId']} - {instance['Name']}")
                    print(f"   Type: {instance['Type']}, State: {instance['State']}")
                    print(
                        f"   Launch Time: {instance['LaunchTime']}, Days Running: {instance['DaysRunning']}"
                    )
                    print(
                        f"   Public IP: {instance['PublicIP']}, Private IP: {instance['PrivateIP']}"
                    )

        elif args.service == "ebs":
            for region in inspector.regions:
                print(f"\nEBS Volumes in {region}: ")
                ebs_data = inspector.get_ebs_inventory(region)
                print(f"Total: {ebs_data['TotalCount']}, Size: {ebs_data['TotalSizeGB']} GB")
                print(
                    f"Unused: {ebs_data['UnusedCount']}, Unencrypted: {ebs_data['UnencryptedCount']}"
                )

                # Print volume details
                for i, volume in enumerate(ebs_data["Volumes"]):
                    print(f"\n{i+1}. {volume['VolumeId']}")
                    print(
                        f"   Type: {volume['VolumeType']}, Size: {volume['Size']} GB, State: {volume['State']}"
                    )
                    print(f"   Encrypted: {volume['Encrypted']}, Attached: {volume['Attached']}")
                    if volume["Attached"]:
                        print(f"   Instance: {volume['InstanceId']}, Device: {volume['Device']}")

        elif args.service == "s3":
            s3_data = inspector.get_s3_inventory()
            print("\nS3 Buckets: ")
            print(f"Total: {s3_data['TotalCount']}, Size: {s3_data['TotalSizeHuman']}")

            # Print bucket details
            for i, bucket in enumerate(s3_data["Buckets"]):
                print(f"\n{i+1}. {bucket['Name']}")
                print(f"   Region: {bucket['Region']}, Created: {bucket['CreationDate']}")
                print(f"   Size: {bucket['SizeHuman']}, Objects: {bucket['ObjectCount']}")
                print(
                    f"   Encrypted: {bucket['Encrypted']}, Encryption Type: {bucket['EncryptionType']}"
                )
                print(
                    f"   Public Access Blocked: {bucket['BlockPublicAcls']} (ACLs), {bucket['BlockPublicPolicy']} (Policy)"
                )

        elif args.service == "rds":
            for region in inspector.regions:
                print(f"\nRDS Instances in {region}: ")
                rds_data = inspector.get_rds_inventory(region)
                print(f"Total: {rds_data['TotalCount']}, Multi-AZ: {rds_data['MultiAZCount']}")

                # Print instance details
                for i, db in enumerate(rds_data["DBInstances"]):
                    print(f"\n{i+1}. {db['DBInstanceIdentifier']}")
                    print(
                        f"   Engine: {db['Engine']} {db['EngineVersion']}, Class: {db['DBInstanceClass']}"
                    )
                    print(f"   Storage: {db['AllocatedStorage']} GB, Type: {db['StorageType']}")
                    print(f"   Multi-AZ: {db['MultiAZ']}, Encrypted: {db['Encrypted']}")
                    print(
                        f"   Public Access: {db['PubliclyAccessible']}, Backup Retention: {db['BackupRetention']} days"
                    )

        elif args.service == "lambda":
            for region in inspector.regions:
                print(f"\nLambda Functions in {region}: ")
                lambda_data = inspector.get_lambda_inventory(region)
                print(f"Total: {lambda_data['TotalCount']}, Size: {lambda_data['TotalSize']}")

                # Print function details
                for i, func in enumerate(lambda_data["Functions"]):
                    print(f"\n{i+1}. {func['FunctionName']}")
                    print(f"   Runtime: {func['Runtime']}, Handler: {func['Handler']}")
                    print(f"   Memory: {func['MemorySize']} MB, Timeout: {func['Timeout']} sec")
                    print(
                        f"   Code Size: {func['CodeSize']}, Last Modified: {func['LastModified']}"
                    )
                    print(
                        f"   Environment Variables: {func['Environment']}, Reserved Concurrency: {func['ReservedConcurrency']}"
                    )

        elif args.service == "iam":
            iam_data = inspector.get_iam_inventory()
            print("\nIAM Resources: ")
            print(
                f"Users: {iam_data['UserCount']}, Roles: {iam_data['RoleCount']}, Policies: {iam_data['PolicyCount']}"
            )

            # Print user details
            print("\nUsers: ")
            for i, user in enumerate(iam_data["Users"]):
                print(f"\n{i+1}. {user['UserName']}")
                print(f"   Created: {user['CreateDate']}, MFA Enabled: {user['MFAEnabled']}")
                print(f"   Password Last Used: {user['PasswordLastUsed']}")
                print(f"   Access Keys: {user['AccessKeyCount']}")
                for j, key in enumerate(user["AccessKeys"]):
                    print(f"     - Key {j+1}: {key['AccessKeyId']}, Status: {key['Status']}")
                    print(f"       Created: {key['Created']}, Last Used: {key['LastUsed']}")

    else:
        # Get full inventory
        print("Collecting full AWS inventory. This may take a while...")
        inventory = inspector.get_full_inventory()

        # Print summary
        inspector.print_inventory_summary(inventory)

        # Output to file if requested
        if args.output:
            print(f"\nWriting full inventory to {args.output}...")
            with open(args.output, "w") as f:
                json.dump(inventory, f, indent=2, default=str)
            print("Done!")


if __name__ == "__main__":
    main()
