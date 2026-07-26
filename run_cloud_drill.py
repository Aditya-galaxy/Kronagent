#!/usr/bin/env python3
import asyncio
import os
import sys
import random
import string
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.schemas import ProposedAction, ActionClass

# Helper to generate unique suffixes for resources
def get_random_suffix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_live_credentials() -> bool:
    """Checks if valid live AWS credentials are set in the environment."""
    try:
        session = boto3.Session()
        creds = session.get_credentials()
        if creds is not None:
            sts = session.client("sts")
            sts.get_caller_identity()
            return True
    except Exception:
        pass
    return False

async def run_drill(region: str, mock_mode: bool):
    suffix = get_random_suffix()
    user_name = f"kronagent-drill-user-{suffix}"
    
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    
    # 1. Setup Temporary Drill Resources
    print(f"[*] Deploying temporary drill resources in region '{region}'...")
    
    # Create IAM User
    print(f"    - Creating IAM User: {user_name}")
    iam.create_user(UserName=user_name)
    
    # Create Access Key
    print(f"    - Creating Access Key for user: {user_name}")
    key_resp = iam.create_access_key(UserName=user_name)
    access_key_id = key_resp["AccessKey"]["AccessKeyId"]
    
    # Fetch VPC ID for NACL
    vpcs = ec2.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    
    # Create Network ACL
    print(f"    - Creating temporary Network ACL in VPC: {vpc_id}")
    nacl_resp = ec2.create_network_acl(VpcId=vpc_id)
    nacl_id = nacl_resp["NetworkAcl"]["NetworkAclId"]
    
    # Initialize the adapter
    adapter = AwsContainmentAdapter(
        region=region,
        quarantine_nacl_id=nacl_id
    )
    
    try:
        # ------------------------------------------------------------------- #
        # DRILL 1: ATTACH_DENY_ALL_TO_PRINCIPAL
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 1: ATTACH_DENY_ALL_TO_PRINCIPAL ---")
        action1 = ProposedAction(
            action_class=ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
            target=user_name,
            provider="aws",
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail1, rollback1 = await adapter.perform(action1)
        print(f"[+] Containment result: {detail1}")
        print(f"    Rollback command hint: {rollback1}")
        
        # Verify state
        print("[*] Verifying resource state in AWS...")
        policies = iam.list_user_policies(UserName=user_name)
        policy_names = policies.get("PolicyNames", [])
        if "kronagent-quarantine-deny-all" not in policy_names:
            raise RuntimeError("Verification failed: Deny-all policy is not attached to IAM User.")
        print("[+] SUCCESS: Deny-all policy verified on IAM User.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        iam.delete_user_policy(UserName=user_name, PolicyName="kronagent-quarantine-deny-all")
        
        # Verify rollback
        print("[*] Verifying rollback state...")
        policies = iam.list_user_policies(UserName=user_name)
        if "kronagent-quarantine-deny-all" in policies.get("PolicyNames", []):
            raise RuntimeError("Verification failed: Deny-all policy was not deleted during rollback.")
        print("[+] SUCCESS: Rollback verified (Deny-all policy removed).")
        
        # ------------------------------------------------------------------- #
        # DRILL 2: DISABLE_ACCESS_KEY
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 2: DISABLE_ACCESS_KEY ---")
        action2 = ProposedAction(
            action_class=ActionClass.DISABLE_ACCESS_KEY,
            target=access_key_id,
            provider="aws",
            parameters={"user_name": user_name},
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail2, rollback2 = await adapter.perform(action2)
        print(f"[+] Containment result: {detail2}")
        print(f"    Rollback command hint: {rollback2}")
        
        # Verify state
        print("[*] Verifying access key state in AWS...")
        keys = iam.list_access_keys(UserName=user_name)
        key_metadata = next(k for k in keys["AccessKeyMetadata"] if k["AccessKeyId"] == access_key_id)
        if key_metadata["Status"] != "Inactive":
            raise RuntimeError("Verification failed: Access key is still active.")
        print("[+] SUCCESS: Access key state is Inactive.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Active")
        
        # Verify rollback
        print("[*] Verifying rollback state...")
        keys = iam.list_access_keys(UserName=user_name)
        key_metadata = next(k for k in keys["AccessKeyMetadata"] if k["AccessKeyId"] == access_key_id)
        if key_metadata["Status"] != "Active":
            raise RuntimeError("Verification failed: Access key was not reactivated during rollback.")
        print("[+] SUCCESS: Rollback verified (Access key reactivated).")
        
        # ------------------------------------------------------------------- #
        # DRILL 3: BLOCK_IP
        # ------------------------------------------------------------------- #
        print("\n[+] --- DRILL 3: BLOCK_IP ---")
        action3 = ProposedAction(
            action_class=ActionClass.BLOCK_IP,
            target="99.99.99.99",
            provider="aws",
            rationale="Kronagent Cloud Drill"
        )
        print("[*] Executing containment action...")
        detail3, rollback3 = await adapter.perform(action3)
        print(f"[+] Containment result: {detail3}")
        print(f"    Rollback command hint: {rollback3}")
        
        # Verify state
        print("[*] Verifying network ACL state in AWS...")
        acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
        entries = acls["NetworkAcls"][0]["Entries"]
        deny_entries = [e for e in entries if e["CidrBlock"] == "99.99.99.99/32" and e["RuleAction"] == "deny"]
        if len(deny_entries) < 2:  # Ingress and Egress deny rules
            raise RuntimeError("Verification failed: Ingress/Egress deny rule not found in NACL entries.")
        print("[+] SUCCESS: Remote IP block rules verified in Network ACL.")
        
        # Chaos Rollback Drill
        print("[*] Executing Chaos Rollback...")
        for entry in deny_entries:
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=entry["RuleNumber"],
                Egress=entry["Egress"]
            )
            
        # Verify rollback
        print("[*] Verifying rollback state...")
        acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
        entries = acls["NetworkAcls"][0]["Entries"]
        deny_entries = [e for e in entries if e["CidrBlock"] == "99.99.99.99/32" and e["RuleAction"] == "deny"]
        if len(deny_entries) > 0:
            raise RuntimeError("Verification failed: Deny rules were not deleted from NACL.")
        print("[+] SUCCESS: Rollback verified (Deny rules removed from NACL).")
        
        print("\n[+] ============================================================")
        print("[+]           ALL CLOUD CONTAINMENT DRILLS PASSED")
        print("[+] ============================================================")
        
    finally:
        print("\n[*] Cleaning up temporary drill resources...")
        try:
            print(f"    - Deleting Access Key: {access_key_id}")
            iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        except Exception as e:
            print(f"      [!] Failed to delete access key: {e}")
            
        try:
            print(f"    - Deleting IAM User: {user_name}")
            iam.delete_user(UserName=user_name)
        except Exception as e:
            print(f"      [!] Failed to delete IAM user: {e}")
            
        try:
            print(f"    - Deleting Network ACL: {nacl_id}")
            ec2.delete_network_acl(NetworkAclId=nacl_id)
        except Exception as e:
            print(f"      [!] Failed to delete network ACL: {e}")
        print("[*] Cleanup complete.")

async def main():
    has_creds = check_live_credentials()
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    
    if has_creds:
        print("[*] Valid live AWS credentials detected. Running in LIVE mode.")
        await run_drill(region, mock_mode=False)
    else:
        print("[*] No active AWS credentials found. Running in SIMULATION mode via moto...")
        try:
            from moto import mock_aws
        except ImportError:
            print("[-] 'moto' library is required to run the simulated cloud drill. Please install it.")
            sys.exit(1)
            
        with mock_aws():
            # Setup mock VPC and Subnet so we can query vpc/nacl
            ec2 = boto3.client("ec2", region_name=region)
            ec2.create_vpc(CidrBlock="10.0.0.0/16")
            await run_drill(region, mock_mode=True)

if __name__ == "__main__":
    asyncio.run(main())
