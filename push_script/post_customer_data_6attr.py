#!/usr/bin/env python3
"""
Script to POST customer authorization data to ISE with 3 attributes
Creates combinations with 4 values each, starting with all 3 attributes
Limited to top 100 rules
"""

import urllib3
import requests
import json
import itertools
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

# Values to iterate through (4 values now)
VALUES = ["Value1", "Value2", "Value3", "Value4"]

# Maximum number of rules to create
MAX_RULES = 100

def create_condition_children(attributes):
    """
    Create condition children based on provided attributes
    attributes: dict with keys and their values
    """
    children = []

    for attr_name, attr_value in attributes.items():
        children.append({
            "link": None,
            "conditionType": "ConditionAttributes",
            "isNegate": False,
            "dictionaryName": "EndPoints",
            "attributeName": attr_name,
            "operator": "equals",
            "dictionaryValue": None,
            "attributeValue": attr_value
        })

    return children

def create_authorization_rule(attributes, rule_number, rank):
    """
    Create an authorization rule with specified attributes and rank
    """
    rule_name = f"Auth_Rule_{rule_number}"

    children = create_condition_children(attributes)

    payload = {
        "rule": {
            "default": False,
            "name": rule_name,
            "rank": rank,
            "state": "enabled",
            "condition": {
                "link": None,
                "conditionType": "ConditionAndBlock",
                "isNegate": False,
                "children": children
            }
        },
        "profile": ["PermitAccess"],
        "securityGroup": None
    }

    return payload

def post_to_ise(payload, rule_name):
    """
    POST authorization rule to ISE
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    json_payload = json.dumps(payload, indent=2)

    try:
        response = requests.post(
            ISE_URL,
            headers=headers,
            auth=(ISE_USERNAME, ISE_PASSWORD),
            data=json_payload,
            verify=False
        )

        if response.status_code == 201:
            print(f"✓ SUCCESS: {rule_name} created")
            return True
        else:
            print(f"✗ FAILED: {rule_name} - Status {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"✗ ERROR: {rule_name} - {e}")
        return False

def generate_rules():
    """
    Generate rule configurations starting with most specific (all 3 attributes)
    Then 2-attribute combinations
    Limited to MAX_RULES
    """
    rules = []

    # 1. All 3 attributes (4^3 = 64 combinations)
    print("\n" + "="*60)
    print("Generating rules with ALL 3 attributes...")
    print("="*60)
    for nz, t, rv in itertools.product(VALUES, repeat=3):
        if len(rules) >= MAX_RULES:
            break
        rules.append({
            'NetworkZone': nz,
            'Tenant': t,
            'rVLAN': rv
        })

    # 2. Tenant + rVLAN only (4^2 = 16 combinations)
    if len(rules) < MAX_RULES:
        print("\n" + "="*60)
        print("Generating rules with Tenant + rVLAN only...")
        print("="*60)
        for t, rv in itertools.product(VALUES, repeat=2):
            if len(rules) >= MAX_RULES:
                break
            rules.append({
                'Tenant': t,
                'rVLAN': rv
            })

    # 3. NetworkZone + rVLAN only (16 combinations)
    if len(rules) < MAX_RULES:
        print("\n" + "="*60)
        print("Generating rules with NetworkZone + rVLAN only...")
        print("="*60)
        for nz, rv in itertools.product(VALUES, repeat=2):
            if len(rules) >= MAX_RULES:
                break
            rules.append({
                'NetworkZone': nz,
                'rVLAN': rv
            })

    # 4. NetworkZone + Tenant only (16 combinations)
    if len(rules) < MAX_RULES:
        print("\n" + "="*60)
        print("Generating rules with NetworkZone + Tenant only...")
        print("="*60)
        for nz, t in itertools.product(VALUES, repeat=2):
            if len(rules) >= MAX_RULES:
                break
            rules.append({
                'NetworkZone': nz,
                'Tenant': t
            })

    return rules

if __name__ == "__main__":
    # Generate rule configurations
    all_rules = generate_rules()
    total = len(all_rules)

    print("\n" + "="*60)
    print(f"Total rules to create: {total}")
    print(f"URL: {ISE_URL}")
    print("="*60 + "\n")

    success_count = 0
    failed_count = 0
    rank = 0

    for rule_number, attributes in enumerate(all_rules, start=1):
        # Create a readable string of attributes
        attr_str = ", ".join([f"{k}={v}" for k, v in attributes.items()])
        rule_name = f"Auth_Rule_{rule_number}"

        print(f"[{rule_number}/{total}] Rank {rank} - {rule_name}: {attr_str}")

        payload = create_authorization_rule(attributes, rule_number, rank)

        if post_to_ise(payload, rule_name):
            success_count += 1
        else:
            failed_count += 1

        rank += 1

        # Small delay between requests
        if rule_number < total:
            time.sleep(0.5)

    print("\n" + "="*60)
    print("Summary:")
    print(f"  Total: {total}")
    print(f"  Success: {success_count}")
    print(f"  Failed: {failed_count}")
    print("="*60)
