import http.client
import os
from dotenv import load_dotenv
import json
import base64
import ssl
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# Get values from .env
ISE_FQDN = os.getenv('ISE_FQDN')
ISE_USERNAME = os.getenv('ISE_USERNAME')
ISE_PASSWORD = os.getenv('ISE_PASSWORD')

# Get the absolute path to the configs directory
script_dir = Path(__file__).parent
project_root = script_dir.parent
OUTPUT_DIR = str(project_root / "configs")

# Create Basic Auth header (Base64 encoded)
credentials = f"{ISE_USERNAME}:{ISE_PASSWORD}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()

# Make connection (disable SSL verification for self-signed certs)
context = ssl._create_unverified_context()
conn = http.client.HTTPSConnection(ISE_FQDN, context=context)

headers = {
    'content-type': "application/json",
    'accept': "application/json",
    'authorization': f"Basic {encoded_credentials}"
}

print("Fetching downloadable ACLs from ERS API...")

conn.request("GET", "/ers/config/downloadableacl", headers=headers)
res = conn.getresponse()
data = res.read()

# Parse JSON response
json_data = json.loads(data.decode("utf-8"))

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Save to file
output_file = f"{OUTPUT_DIR}/downloadable_acl.json"
with open(output_file, 'w') as f:
    json.dump(json_data, f, indent=2)

print(f"✓ Saved downloadable ACLs to {output_file}")

# Check if there are resources and count them
if 'SearchResult' in json_data and 'resources' in json_data['SearchResult']:
    resource_count = len(json_data['SearchResult']['resources'])
    print(f"  Total downloadable ACLs found: {resource_count}")
