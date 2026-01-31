import os
import shutil
from pathlib import Path

# Get the absolute path to the project root (parent of Scripts directory)
script_dir = Path(__file__).parent
project_root = script_dir.parent
OUTPUT_DIR = project_root / "configs"

# Convert to string for compatibility
OUTPUT_DIR = str(OUTPUT_DIR)

if not os.path.exists(OUTPUT_DIR):
    print(f"✓ Directory {OUTPUT_DIR} does not exist, nothing to clean")
    exit(0)

# Count files before deletion
files = [f for f in os.listdir(OUTPUT_DIR) if os.path.isfile(os.path.join(OUTPUT_DIR, f))]
file_count = len(files)

if file_count == 0:
    print(f"✓ Directory {OUTPUT_DIR} is already empty")
    exit(0)

# Ask for confirmation
print(f"Found {file_count} file(s) in {OUTPUT_DIR}:")
for file in files:
    print(f"  - {file}")

response = input("\nAre you sure you want to delete all files? (yes/no): ")

if response.lower() in ['yes', 'y']:
    # Delete all files in the directory
    for file in files:
        file_path = os.path.join(OUTPUT_DIR, file)
        try:
            os.remove(file_path)
            print(f"  ✓ Deleted {file}")
        except Exception as e:
            print(f"  ✗ Error deleting {file}: {str(e)}")

    print(f"\n✓ Cleanup complete - deleted {file_count} file(s)")
else:
    print("\n✗ Cleanup cancelled")
