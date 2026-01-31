import http.client
import os
from dotenv import load_dotenv
import json
import base64
import ssl
from pathlib import Path
from urllib.parse import urlparse

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

# Load allowed protocols from file
allowed_protocols_file = f"{OUTPUT_DIR}/allowed_protocols.json"
with open(allowed_protocols_file, 'r') as f:
    allowed_protocols_data = json.load(f)

# Extract hrefs from resources
hrefs = []
if 'SearchResult' in allowed_protocols_data and 'resources' in allowed_protocols_data['SearchResult']:
    for resource in allowed_protocols_data['SearchResult']['resources']:
        if 'link' in resource and 'href' in resource['link']:
            hrefs.append(resource['link']['href'])

print(f"Found {len(hrefs)} allowed protocol(s) to fetch details for")

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Store all detailed results
all_details = []

# Process each href
for idx, href in enumerate(hrefs, 1):
    # Parse the URL to extract the path
    parsed_url = urlparse(href)
    detail_path = parsed_url.path

    print(f"\n[{idx}/{len(hrefs)}] Fetching details for: {detail_path}")

    # Make connection (disable SSL verification for self-signed certs)
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(ISE_FQDN, context=context)

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': f"Basic {encoded_credentials}"
    }

    try:
        conn.request("GET", detail_path, headers=headers)
        res = conn.getresponse()
        data = res.read()

        # Parse JSON response
        json_data = json.loads(data.decode("utf-8"))

        # Store with reference to original href
        result = {
            "href": href,
            "data": json_data
        }
        all_details.append(result)

        print(f"  ✓ Successfully retrieved details")

    except Exception as e:
        print(f"  ✗ Error: {str(e)}")
        all_details.append({
            "href": href,
            "error": str(e)
        })
    finally:
        conn.close()

# Save all results to file
output_file = f"{OUTPUT_DIR}/allowed_protocols_detail.json"
with open(output_file, 'w') as f:
    json.dump(all_details, f, indent=2)

print(f"\n✓ Saved all allowed protocol details to {output_file}")
print(f"  Total processed: {len(all_details)} allowed protocol(s)")
