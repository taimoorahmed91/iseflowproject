import subprocess
import sys
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the directory where this script is located
script_dir = Path(__file__).parent
project_root = script_dir.parent
configs_dir = project_root / "configs"

# Get the policy set name filter from environment
POLICYSET_FILTER = os.getenv('POLICYSET')

if not POLICYSET_FILTER:
    print("✗ POLICYSET environment variable not set in .env file")
    sys.exit(1)

print("=" * 60)
print("Starting Conditional ISE Data Collection")
print(f"Policy Set Filter: '{POLICYSET_FILTER}'")
print("=" * 60)

# Define the initial scripts to run
initial_scripts = [
    "conditions.py",
    "downloadable_acl.py",
    "authorization_profiles.py",
    "authorization_profiles_detail.py",
    "allowed_protocols.py",
    "allowed_protocols_detail.py",
    "policysets.py"
]

failed_scripts = []

# Run initial scripts
total_steps = len(initial_scripts) + 1 + 3  # initial scripts (7) + filtering (1) + conditional scripts (3) = 11
for idx, script in enumerate(initial_scripts, 1):
    script_path = script_dir / script

    print(f"\n[{idx}/{total_steps}] Running {script}...")
    print("-" * 60)

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            check=True
        )

        if result.stdout:
            print(result.stdout)

        print(f"✓ {script} completed successfully")

    except subprocess.CalledProcessError as e:
        print(f"✗ {script} failed with exit code {e.returncode}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        failed_scripts.append(script)
        sys.exit(1)

# Filter policy sets based on POLICYSET name
print(f"\n[{len(initial_scripts) + 1}/{total_steps}] Filtering policy sets by name...")
print("-" * 60)

policysets_file = configs_dir / "policysets.json"
policyset_href_file = configs_dir / "policyset_href.json"

try:
    with open(policysets_file, 'r') as f:
        policysets_data = json.load(f)

    # Extract policy sets that match the filter
    filtered_hrefs = []
    matched_policies = []

    if 'response' in policysets_data:
        for policy in policysets_data['response']:
            policy_name = policy.get('name', '')
            if POLICYSET_FILTER.lower() in policy_name.lower():
                if 'link' in policy and 'href' in policy['link']:
                    filtered_hrefs.append(policy['link']['href'])
                    matched_policies.append(policy_name)
                    print(f"  ✓ Matched: {policy_name}")

    if not filtered_hrefs:
        print(f"✗ No policy sets found matching '{POLICYSET_FILTER}'")
        sys.exit(1)

    print(f"\n✓ Found {len(filtered_hrefs)} matching policy set(s)")

    # Save filtered hrefs to file (overwrite the original)
    with open(policyset_href_file, 'w') as f:
        json.dump(filtered_hrefs, f, indent=2)

    print(f"✓ Updated {policyset_href_file} with filtered hrefs")

except Exception as e:
    print(f"✗ Error filtering policy sets: {str(e)}")
    sys.exit(1)

# Run authentication and authorization scripts with filtered hrefs
conditional_scripts = [
    "authentication.py",
    "authorization.py",
    "process_ise_data.py"
]

for idx, script in enumerate(conditional_scripts, len(initial_scripts) + 2):
    script_path = script_dir / script

    print(f"\n[{idx}/{total_steps}] Running {script}...")
    print("-" * 60)

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            check=True
        )

        if result.stdout:
            print(result.stdout)

        print(f"✓ {script} completed successfully")

    except subprocess.CalledProcessError as e:
        print(f"✗ {script} failed with exit code {e.returncode}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        failed_scripts.append(script)
        sys.exit(1)

# Summary
print("\n" + "=" * 60)
print("Execution Summary")
print("=" * 60)

if not failed_scripts:
    print("✓ All scripts completed successfully!")
    print(f"✓ Processed policy sets matching '{POLICYSET_FILTER}':")
    for policy_name in matched_policies:
        print(f"  - {policy_name}")
else:
    print(f"✗ {len(failed_scripts)} script(s) failed:")
    for script in failed_scripts:
        print(f"  - {script}")
    sys.exit(1)
