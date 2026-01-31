import http.client
import os
from dotenv import load_dotenv
import json
import base64
import ssl
from urllib.parse import urlparse
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

# Load hrefs from file
href_file = f"{OUTPUT_DIR}/policyset_href.json"
with open(href_file, 'r') as f:
    hrefs = json.load(f)

print(f"Found {len(hrefs)} policy set(s) to process")

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Store all authorization results
all_authorization_data = []

# Process each href
for idx, href in enumerate(hrefs, 1):
    # Parse the URL to extract the path
    parsed_url = urlparse(href)
    authz_path = f"{parsed_url.path}/authorization"

    print(f"\n[{idx}/{len(hrefs)}] Fetching authorization for: {authz_path}")

    # Make connection (disable SSL verification for self-signed certs)
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(ISE_FQDN, context=context)

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': f"Basic {encoded_credentials}"
    }

    try:
        conn.request("GET", authz_path, headers=headers)
        res = conn.getresponse()
        data = res.read()

        # Parse JSON response
        json_data = json.loads(data.decode("utf-8"))

        # Store with reference to original policy set
        result = {
            "policy_set_href": href,
            "authorization_url": f"https://{ISE_FQDN}{authz_path}",
            "data": json_data
        }
        all_authorization_data.append(result)

        print(f"  ✓ Successfully retrieved authorization data")

    except Exception as e:
        print(f"  ✗ Error: {str(e)}")
        all_authorization_data.append({
            "policy_set_href": href,
            "authorization_url": f"https://{ISE_FQDN}{authz_path}",
            "error": str(e)
        })
    finally:
        conn.close()

# Save all results to file
output_file = f"{OUTPUT_DIR}/authorization.json"
with open(output_file, 'w') as f:
    json.dump(all_authorization_data, f, indent=2)

print(f"\n✓ Saved all authorization data to {output_file}")
print(f"  Total processed: {len(all_authorization_data)} policy set(s)")
