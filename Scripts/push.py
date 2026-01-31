import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

# Get the project root directory (parent of Scripts)
script_dir = Path(__file__).parent
project_root = script_dir.parent

# Change to project root directory
os.chdir(project_root)

print("=" * 60)
print("Git Push Script")
print("=" * 60)

# Check if git is initialized
def is_git_initialized():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

# Initialize git if needed
if not is_git_initialized():
    print("\n[1/6] Initializing git repository...")
    try:
        subprocess.run(["git", "init"], check=True)
        subprocess.run(["git", "branch", "-M", "main"], check=True)
        print("  ✓ Git repository initialized")
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed to initialize git: {e}")
        sys.exit(1)
else:
    print("\n[1/6] Git repository already initialized")

# Check if remote origin exists
def has_remote_origin():
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout.strip()
    except subprocess.CalledProcessError:
        return False, None

has_remote, remote_url = has_remote_origin()

if not has_remote:
    print("\n[2/6] Adding remote origin...")
    remote_url = input("Enter GitHub repository URL: ").strip()
    if not remote_url:
        print("  ✗ No remote URL provided")
        sys.exit(1)
    try:
        subprocess.run(["git", "remote", "add", "origin", remote_url], check=True)
        print(f"  ✓ Remote origin added: {remote_url}")
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed to add remote: {e}")
        sys.exit(1)
else:
    print(f"\n[2/6] Remote origin already configured: {remote_url}")

# Get commit message
print("\n[3/6] Preparing commit...")
if len(sys.argv) > 1:
    commit_message = " ".join(sys.argv[1:])
else:
    # Generate default commit message with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    commit_message = f"Update ISE data - {timestamp}"

print(f"  Commit message: \"{commit_message}\"")

# Check git status
print("\n[4/6] Checking git status...")
try:
    result = subprocess.run(
        ["git", "status", "--short"],
        capture_output=True,
        text=True,
        check=True
    )
    if result.stdout.strip():
        print("  Changes detected:")
        status_lines = result.stdout.strip().split('\n')
        for line in status_lines[:10]:  # Show first 10 files
            print(f"    {line}")
        if len(status_lines) > 10:
            remaining = len(status_lines) - 10
            print(f"    ... and {remaining} more files")
    else:
        print("  No changes to commit")
        print("\n✓ Repository is up to date")
        sys.exit(0)
except subprocess.CalledProcessError as e:
    print(f"  ✗ Failed to check status: {e}")
    sys.exit(1)

# Stage all changes
print("\n[5/6] Staging changes...")
try:
    subprocess.run(["git", "add", "."], check=True)
    print("  ✓ All changes staged")
except subprocess.CalledProcessError as e:
    print(f"  ✗ Failed to stage changes: {e}")
    sys.exit(1)

# Commit changes
print("\n[6/6] Committing and pushing...")
try:
    subprocess.run(["git", "commit", "-m", commit_message], check=True)
    print("  ✓ Changes committed")
except subprocess.CalledProcessError as e:
    print(f"  ✗ Failed to commit: {e}")
    sys.exit(1)

# Push to remote
try:
    # Check if branch has upstream
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        # No upstream, set it
        subprocess.run(["git", "push", "-u", "origin", "main"], check=True)
    else:
        # Upstream exists, just push
        subprocess.run(["git", "push"], check=True)

    print("  ✓ Changes pushed to remote")
except subprocess.CalledProcessError as e:
    print(f"  ✗ Failed to push: {e}")
    print("\n  Note: You may need to authenticate or check your remote URL")
    sys.exit(1)

print("\n" + "=" * 60)
print("✓ Successfully pushed to GitHub!")
print("=" * 60)
