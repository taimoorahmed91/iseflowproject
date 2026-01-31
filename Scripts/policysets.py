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

conn.request("GET", "/api/v1/policy/network-access/policy-set", headers=headers)
res = conn.getresponse()
data = res.read()

# Parse JSON response
json_data = json.loads(data.decode("utf-8"))

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Save full response to file
output_file = f"{OUTPUT_DIR}/policysets.json"
with open(output_file, 'w') as f:
    json.dump(json_data, f, indent=2)

print(f"✓ Saved policy sets to {output_file}")

# Extract all href values
hrefs = []

def extract_hrefs(obj, hrefs_list):
    """Recursively extract all href values from JSON object"""
    if isinstance(obj, dict):
        if 'href' in obj:
            hrefs_list.append(obj['href'])
        for value in obj.values():
            extract_hrefs(value, hrefs_list)
    elif isinstance(obj, list):
        for item in obj:
            extract_hrefs(item, hrefs_list)

extract_hrefs(json_data, hrefs)

# Save hrefs to separate file
href_file = f"{OUTPUT_DIR}/policyset_href.json"
with open(href_file, 'w') as f:
    json.dump(hrefs, f, indent=2)

print(f"✓ Saved {len(hrefs)} href(s) to {href_file}")
