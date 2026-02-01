#!/usr/bin/env python3
"""
Script to POST customer authorization data to ISE
Creates all combinations with 3 attributes, then 2 attributes, then 1 attribute
"""

import urllib3
import requests
import json
import itertools
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ISE Configuration
ISE_URL = "https://10.48.30.215/api/v1/policy/network-access/policy-set/04574412-7127-43d6-b1ca-0a00ba7a0199/authorization"
ISE_USERNAME = "admin"
ISE_PASSWORD = "C1sc0123@"

# Values to iterate through
VALUES = ["Value1", "Value2", "Value3"]

def create_condition_children(attributes):
    """
    Create condition children based on provided attributes
    attributes: dict with keys like 'NetworkZone', 'Tenant', 'rVLAN' and their values
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
    Generate all rule configurations
    """
    rules = []

    # 1. All 3 attributes (27 combinations)
    print("\n" + "="*60)
    print("Generating rules with ALL 3 attributes...")
    print("="*60)
    for nz, t, rv in itertools.product(VALUES, repeat=3):
        rules.append({
            'NetworkZone': nz,
            'Tenant': t,
            'rVLAN': rv
        })

    # 2. Remove NetworkZone, keep Tenant and rVLAN (9 combinations)
    print("\n" + "="*60)
    print("Generating rules with Tenant + rVLAN only...")
    print("="*60)
    for t, rv in itertools.product(VALUES, repeat=2):
        rules.append({
            'Tenant': t,
            'rVLAN': rv
        })

    # 3. Remove Tenant, keep NetworkZone and rVLAN (9 combinations)
    print("\n" + "="*60)
    print("Generating rules with NetworkZone + rVLAN only...")
    print("="*60)
    for nz, rv in itertools.product(VALUES, repeat=2):
        rules.append({
            'NetworkZone': nz,
            'rVLAN': rv
        })

    # 4. Remove rVLAN, keep NetworkZone and Tenant (9 combinations)
    print("\n" + "="*60)
    print("Generating rules with NetworkZone + Tenant only...")
    print("="*60)
    for nz, t in itertools.product(VALUES, repeat=2):
        rules.append({
            'NetworkZone': nz,
            'Tenant': t
        })

    # 5. Only NetworkZone (3 values)
    print("\n" + "="*60)
    print("Generating rules with NetworkZone only...")
    print("="*60)
    for nz in VALUES:
        rules.append({
            'NetworkZone': nz
        })

    # 6. Only Tenant (3 values)
    print("\n" + "="*60)
    print("Generating rules with Tenant only...")
    print("="*60)
    for t in VALUES:
        rules.append({
            'Tenant': t
        })

    # 7. Only rVLAN (3 values)
    print("\n" + "="*60)
    print("Generating rules with rVLAN only...")
    print("="*60)
    for rv in VALUES:
        rules.append({
            'rVLAN': rv
        })

    return rules

if __name__ == "__main__":
    # Generate all rule configurations
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
