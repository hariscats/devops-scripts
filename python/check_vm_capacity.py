import json
import subprocess

# List of regions and SKUs to check
regions = ["eastus", "westus", "centralus", "eastus2", "westus2"]
skus_to_check = ["Standard_D2s_v3", "Standard_B2ms", "Standard_F4s_v2"]

# Function to check availability of SKUs in a specific region
def check_sku_availability(region, sku):
    try:
        # Run the az CLI command to get SKU availability in a specific region
        result = subprocess.run(
            ["az", "vm", "list-skus", "--location", region, "--output", "json"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"Error fetching data for region {region}")
            return None
        
        # Parse the JSON output
        skus = json.loads(result.stdout)

        # Check if the SKU is in the list of available SKUs for the region
        available_sku = next((item for item in skus if item["name"] == sku), None)
        return available_sku is not None

    except Exception as e:
        print(f"Error checking SKU {sku} in {region}: {e}")
        return None


# Check all SKUs in all regions
for region in regions:
    print(f"\nChecking availability in region: {region}")
    for sku in skus_to_check:
        is_available = check_sku_availability(region, sku)
        if is_available:
            print(f"SKU {sku} is available in {region}")
        else:
            print(f"SKU {sku} is NOT available in {region}")
