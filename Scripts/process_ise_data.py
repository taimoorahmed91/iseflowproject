import json
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Get the absolute path to the configs directory
script_dir = Path(__file__).parent
project_root = script_dir.parent
configs_dir = project_root / "configs"

print("=" * 60)
print("Processing ISE Data")
print("=" * 60)

# Load all JSON files
print("\n[1/5] Loading JSON files...")

def load_json(filename):
    filepath = configs_dir / filename
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            print(f"  ✓ Loaded {filename}")
            return data
    except FileNotFoundError:
        print(f"  ✗ File not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON decode error in {filename}: {str(e)}")
        return None

conditions_data = load_json("conditions.json")
policysets_data = load_json("policysets.json")
authentication_data = load_json("authentication.json")
authorization_data = load_json("authorization.json")
authorization_profiles_data = load_json("authorization_profiles.json")
authorization_profiles_detail_data = load_json("authorization_profiles_detail.json")
downloadable_acl_data = load_json("downloadable_acl.json")
allowed_protocols_data = load_json("allowed_protocols.json")
allowed_protocols_detail_data = load_json("allowed_protocols_detail.json")

# Build conditions lookup dictionary
print("\n[2/5] Building condition lookup dictionary...")
conditions_lookup = {}

if conditions_data and 'response' in conditions_data:
    for condition in conditions_data['response']:
        if 'id' in condition:
            conditions_lookup[condition['id']] = condition
    print(f"  ✓ Indexed {len(conditions_lookup)} conditions")
else:
    print("  ✗ No conditions found")

# Build authorization profiles lookup
print("\n[3/5] Building authorization profiles lookup...")
authz_profiles_lookup = {}

if authorization_profiles_data and 'SearchResult' in authorization_profiles_data:
    resources = authorization_profiles_data['SearchResult'].get('resources', [])
    for profile in resources:
        if 'id' in profile:
            authz_profiles_lookup[profile['id']] = profile
        if 'name' in profile:
            authz_profiles_lookup[profile['name']] = profile
    print(f"  ✓ Indexed {len(resources)} authorization profiles")
else:
    print("  ✗ No authorization profiles found")

# Build downloadable ACLs lookup
print("\n[4/6] Building downloadable ACLs lookup...")
dacl_lookup = {}

if downloadable_acl_data and 'SearchResult' in downloadable_acl_data:
    resources = downloadable_acl_data['SearchResult'].get('resources', [])
    for acl in resources:
        if 'id' in acl:
            dacl_lookup[acl['id']] = acl
        if 'name' in acl:
            dacl_lookup[acl['name']] = acl
    print(f"  ✓ Indexed {len(resources)} downloadable ACLs")
else:
    print("  ✗ No downloadable ACLs found")

# Build allowed protocols lookup
print("\n[5/8] Building allowed protocols lookup...")
allowed_protocols_lookup = {}

if allowed_protocols_data and 'SearchResult' in allowed_protocols_data:
    resources = allowed_protocols_data['SearchResult'].get('resources', [])
    for protocol in resources:
        if 'id' in protocol:
            allowed_protocols_lookup[protocol['id']] = protocol
        if 'name' in protocol:
            allowed_protocols_lookup[protocol['name']] = protocol
    print(f"  ✓ Indexed {len(resources)} allowed protocols")
else:
    print("  ✗ No allowed protocols found")

# Build authorization profiles detail lookup
print("\n[6/8] Building authorization profiles detail lookup...")
authz_profiles_detail_lookup = {}

if authorization_profiles_detail_data and isinstance(authorization_profiles_detail_data, list):
    for entry in authorization_profiles_detail_data:
        if 'data' in entry and 'AuthorizationProfile' in entry['data']:
            profile = entry['data']['AuthorizationProfile']
            if 'id' in profile:
                authz_profiles_detail_lookup[profile['id']] = profile
            if 'name' in profile:
                authz_profiles_detail_lookup[profile['name']] = profile
    print(f"  ✓ Indexed {len(authorization_profiles_detail_data)} authorization profile details")
else:
    print("  ✗ No authorization profile details found")

# Build allowed protocols detail lookup
print("\n[7/8] Building allowed protocols detail lookup...")
allowed_protocols_detail_lookup = {}

if allowed_protocols_detail_data and isinstance(allowed_protocols_detail_data, list):
    for entry in allowed_protocols_detail_data:
        if 'data' in entry and 'AllowedProtocols' in entry['data']:
            protocol = entry['data']['AllowedProtocols']
            if 'id' in protocol:
                allowed_protocols_detail_lookup[protocol['id']] = protocol
            if 'name' in protocol:
                allowed_protocols_detail_lookup[protocol['name']] = protocol
    print(f"  ✓ Indexed {len(allowed_protocols_detail_data)} allowed protocol details")
else:
    print("  ✗ No allowed protocol details found")

# Recursive function to resolve condition references
def resolve_condition(condition, depth=0, max_depth=10):
    """Recursively resolve condition references to their full definitions"""

    if condition is None:
        return None

    if depth > max_depth:
        print(f"  ⚠ Warning: Max recursion depth reached, possible circular reference")
        return condition

    # If this is a reference, resolve it
    if condition.get('conditionType') == 'ConditionReference':
        condition_id = condition.get('id')
        if condition_id and condition_id in conditions_lookup:
            # Replace with the full condition definition
            resolved = conditions_lookup[condition_id].copy()
            # Recursively resolve the replaced condition
            return resolve_condition(resolved, depth + 1, max_depth)
        else:
            print(f"  ⚠ Warning: Condition reference ID '{condition_id}' not found")
            return condition

    # If this is a block (AND/OR), resolve all children
    if condition.get('conditionType') in ['ConditionAndBlock', 'ConditionOrBlock']:
        if 'children' in condition and isinstance(condition['children'], list):
            resolved_children = []
            for child in condition['children']:
                resolved_child = resolve_condition(child, depth + 1, max_depth)
                resolved_children.append(resolved_child)
            condition['children'] = resolved_children

    return condition

# Extract policy set ID from href URL
def extract_policyset_id(href):
    """Extract policy set ID from the href URL"""
    if not href:
        return None
    # URL format: https://10.48.30.215/api/v1/policy/network-access/policy-set/{ID}/...
    parts = href.split('/')
    # Find 'policy-set' in the path and get the next segment
    try:
        idx = parts.index('policy-set')
        if idx + 1 < len(parts):
            return parts[idx + 1]
    except (ValueError, IndexError):
        pass
    return None

# Process and link all data
print("\n[8/8] Processing and linking data...")

processed_data = {
    "metadata": {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_policy_sets": 0,
        "total_authentication_policies": 0,
        "total_authorization_policies": 0
    },
    "policy_sets": [],
    "reference_data": {
        "authorization_profiles": authz_profiles_lookup,
        "authorization_profiles_detail": authz_profiles_detail_lookup,
        "downloadable_acls": dacl_lookup,
        "allowed_protocols": allowed_protocols_lookup,
        "allowed_protocols_detail": allowed_protocols_detail_lookup
    }
}

# Create policy set dictionary
policy_sets_dict = {}

if policysets_data and 'response' in policysets_data:
    for ps in policysets_data['response']:
        policy_set = ps.copy()

        # Resolve condition if present
        if 'condition' in policy_set and policy_set['condition']:
            print(f"  → Resolving condition for policy set: {policy_set.get('name')}")
            policy_set['condition'] = resolve_condition(policy_set['condition'])

        # Initialize empty arrays for policies
        policy_set['authentication_policies'] = []
        policy_set['authorization_policies'] = []

        policy_sets_dict[policy_set['id']] = policy_set

    print(f"  ✓ Processed {len(policy_sets_dict)} policy sets")

# Link authentication policies to policy sets
auth_count = 0
if authentication_data and isinstance(authentication_data, list):
    for auth_entry in authentication_data:
        ps_href = auth_entry.get('policy_set_href')
        ps_id = extract_policyset_id(ps_href)

        if ps_id and ps_id in policy_sets_dict:
            if 'data' in auth_entry and 'response' in auth_entry['data']:
                for auth_policy in auth_entry['data']['response']:
                    # Resolve condition if present
                    if 'rule' in auth_policy and 'condition' in auth_policy['rule'] and auth_policy['rule']['condition']:
                        auth_policy['rule']['condition'] = resolve_condition(auth_policy['rule']['condition'])

                    policy_sets_dict[ps_id]['authentication_policies'].append(auth_policy)
                    auth_count += 1

    print(f"  ✓ Linked {auth_count} authentication policies")

# Link authorization policies to policy sets
authz_count = 0
if authorization_data and isinstance(authorization_data, list):
    for authz_entry in authorization_data:
        ps_href = authz_entry.get('policy_set_href')
        ps_id = extract_policyset_id(ps_href)

        if ps_id and ps_id in policy_sets_dict:
            if 'data' in authz_entry and 'response' in authz_entry['data']:
                for authz_policy in authz_entry['data']['response']:
                    # Resolve condition if present
                    if 'rule' in authz_policy and 'condition' in authz_policy['rule'] and authz_policy['rule']['condition']:
                        authz_policy['rule']['condition'] = resolve_condition(authz_policy['rule']['condition'])

                    policy_sets_dict[ps_id]['authorization_policies'].append(authz_policy)
                    authz_count += 1

    print(f"  ✓ Linked {authz_count} authorization policies")

# Sort policies by rank and convert to array
for ps_id, ps in policy_sets_dict.items():
    # Sort authentication policies by rank
    ps['authentication_policies'].sort(key=lambda x: x.get('rule', {}).get('rank', 999))
    # Sort authorization policies by rank
    ps['authorization_policies'].sort(key=lambda x: x.get('rule', {}).get('rank', 999))

    processed_data['policy_sets'].append(ps)

# Sort policy sets by rank
processed_data['policy_sets'].sort(key=lambda x: x.get('rank', 999))

# Update metadata
processed_data['metadata']['total_policy_sets'] = len(processed_data['policy_sets'])
processed_data['metadata']['total_authentication_policies'] = auth_count
processed_data['metadata']['total_authorization_policies'] = authz_count

# Save processed data
output_file = configs_dir / "processed_data.json"
with open(output_file, 'w') as f:
    json.dump(processed_data, f, indent=2)

print(f"\n✓ Saved processed data to {output_file}")
print(f"  - Policy Sets: {processed_data['metadata']['total_policy_sets']}")
print(f"  - Authentication Policies: {processed_data['metadata']['total_authentication_policies']}")
print(f"  - Authorization Policies: {processed_data['metadata']['total_authorization_policies']}")
print(f"  - Authorization Profiles: {len(authz_profiles_lookup)}")
print(f"  - Authorization Profiles (Detail): {len(authz_profiles_detail_lookup)}")
print(f"  - Downloadable ACLs: {len(dacl_lookup)}")
print(f"  - Allowed Protocols: {len(allowed_protocols_lookup)}")
print(f"  - Allowed Protocols (Detail): {len(allowed_protocols_detail_lookup)}")

print("\n" + "=" * 60)
print("Processing Complete")
print("=" * 60)
