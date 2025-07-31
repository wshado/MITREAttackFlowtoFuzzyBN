

#collect_json_flows.py
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote

# URL of example flows page
BASE_URL = "https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/"

# Output folder
OUTPUT_FOLDER = "downloaded_attack_flow_jsons"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Fetch page
print("🔎 Fetching example flows page...")
resp = requests.get(BASE_URL)
resp.raise_for_status()

soup = BeautifulSoup(resp.text, "html.parser")

# Find all links ending in .json
links = soup.find_all("a", href=True)
json_links = [link["href"] for link in links if link["href"].endswith(".json")]

if not json_links:
    print("⚠ No JSON files found on the page.")
    exit(1)

print(f"✅ Found {len(json_links)} JSON files. Starting download...")

for json_link in json_links:
    # Decode URL encoding (remove %20, etc.)
    clean_name = unquote(os.path.basename(json_link))
    clean_name = clean_name.replace(" ", "_")

    full_url = BASE_URL + json_link
    local_path = os.path.join(OUTPUT_FOLDER, clean_name)

    try:
        r = requests.get(full_url)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            f.write(r.content)
        print(f"✅ Saved: {clean_name}")
    except requests.RequestException as e:
        print(f"❌ Failed to download {clean_name}: {e}")

print("\n🎉 All example flow JSONs downloaded successfully!")
