#!/usr/bin/env python3
"""
Script to cleanup (delete) all authorization rules from ISE
"""

import urllib3
import requests
import json
import time
import os
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

# ISE Configuration
ISE_HOST = os.getenv('ISE_HOST', '10.48.30.215')
ISE_URL = f"https://{ISE_HOST}/api/v1/policy/network-access/policy-set/04574412-7127-43d6-b1ca-0a00ba7a0199/authorization"
ISE_USERNAME = os.getenv('ISE_USERNAME', 'admin')
ISE_PASSWORD = os.getenv('ISE_PASSWORD', 'C1sc0123@')

def get_all_rules():
    """
    GET all authorization rules from ISE
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    print(f"Fetching all authorization rules from ISE...")
    print(f"URL: {ISE_URL}\n")

    try:
        response = requests.get(
            ISE_URL,
            headers=headers,
            auth=(ISE_USERNAME, ISE_PASSWORD),
            verify=False
        )

        if response.status_code == 200:
            data = response.json()
            rules = data.get('response', [])
            print(f"Found {len(rules)} authorization rules\n")
            return rules
        else:
            print(f"✗ FAILED to fetch rules - Status {response.status_code}")
            print(f"Response: {response.text}")
            return []

    except Exception as e:
        print(f"✗ ERROR: {e}")
        return []

def delete_rule(rule_id, rule_name):
    """
    DELETE a specific authorization rule by ID
    """
    url = f"{ISE_URL}/{rule_id}"

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    try:
        response = requests.delete(
            url,
            headers=headers,
            auth=(ISE_USERNAME, ISE_PASSWORD),
            verify=False
        )

        if response.status_code == 204:
            print(f"✓ SUCCESS: Deleted '{rule_name}'")
            return True
        else:
            print(f"✗ FAILED: '{rule_name}' - Status {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"✗ ERROR: '{rule_name}' - {e}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("ISE Authorization Rule Cleanup Script")
    print("="*60 + "\n")

    # Get all rules
    rules = get_all_rules()

    if not rules:
        print("No rules to delete or failed to fetch rules.")
        exit(0)

    # Confirm deletion
    print("="*60)
    print("WARNING: This will delete ALL authorization rules!")
    print("="*60)
    response = input("Are you sure you want to continue? (yes/no): ")

    if response.lower() != 'yes':
        print("Deletion cancelled.")
        exit(0)

    print("\nStarting deletion process...\n")

    success_count = 0
    failed_count = 0
    total = len(rules)

    for index, rule in enumerate(rules, start=1):
        rule_id = rule.get('rule', {}).get('id')
        rule_name = rule.get('rule', {}).get('name', 'Unknown')

        print(f"[{index}/{total}] Deleting: {rule_name} (ID: {rule_id})")

        if delete_rule(rule_id, rule_name):
            success_count += 1
        else:
            failed_count += 1

        # Small delay between requests
        if index < total:
            time.sleep(0.3)

    print("\n" + "="*60)
    print("Summary:")
    print(f"  Total: {total}")
    print(f"  Deleted: {success_count}")
    print(f"  Failed: {failed_count}")
    print("="*60)
