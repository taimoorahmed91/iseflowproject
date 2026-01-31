import subprocess
import sys
from pathlib import Path

# Get the directory where this script is located
script_dir = Path(__file__).parent

# Define the scripts to run in sequence
scripts = [
    "conditions.py",
    "downloadable_acl.py",
    "authorization_profiles.py",
    "authorization_profiles_detail.py",
    "allowed_protocols.py",
    "allowed_protocols_detail.py",
    "policysets.py",
    "authentication.py",
    "authorization.py",
    "process_ise_data.py"
]

print("=" * 60)
print("Starting ISE Data Collection")
print("=" * 60)

failed_scripts = []

# Run each script in sequence
for idx, script in enumerate(scripts, 1):
    script_path = script_dir / script

    print(f"\n[{idx}/{len(scripts)}] Running {script}...")
    print("-" * 60)

    try:
        # Run the script and wait for it to complete
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            check=True
        )

        # Print the output from the script
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

        # Ask user if they want to continue
        response = input("\nContinue with remaining scripts? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("\n✗ Execution stopped by user")
            break

    except Exception as e:
        print(f"✗ Unexpected error running {script}: {str(e)}")
        failed_scripts.append(script)
        break

# Summary
print("\n" + "=" * 60)
print("Execution Summary")
print("=" * 60)

if not failed_scripts:
    print("✓ All scripts completed successfully!")
else:
    print(f"✗ {len(failed_scripts)} script(s) failed:")
    for script in failed_scripts:
        print(f"  - {script}")
    sys.exit(1)
