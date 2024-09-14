import json
import subprocess
import logging

# Configure logging for better output control
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# List of regions and SKUs to check
regions = ["eastus", "westus", "centralus", "eastus2", "westus2"]
skus_to_check = ["Standard_G2", "Standard_B2ms", "Standard_F4s_v2"]

def fetch_skus_for_region(region):
    """
    Fetches all available SKUs for a given region using Azure CLI.

    Args:
        region (str): Azure region name.

    Returns:
        list: A list of SKUs available in the region, or None if an error occurs.
    """
    try:
        # Execute the Azure CLI command to list VM SKUs for the region
        result = subprocess.run(
            ["az", "vm", "list-skus", "--location", region, "--output", "json"],
            capture_output=True, text=True
        )

        # Check if the command was successful
        if result.returncode != 0:
            logging.error(f"Failed to retrieve SKUs for region: {region}")
            return None
        
        # Parse the JSON output
        skus = json.loads(result.stdout)
        return skus

    except Exception as e:
        logging.error(f"Exception occurred while fetching SKUs for region {region}: {e}")
        return None

def is_sku_available(region, sku, skus):
    """
    Checks if a given SKU is available in the list of SKUs for a region.

    Args:
        region (str): Azure region name.
        sku (str): VM SKU name to check.
        skus (list): List of SKU objects for the region.

    Returns:
        bool: True if SKU is available, False otherwise.
    """
    # Use list comprehension to find if SKU exists in the available SKUs for the region
    return any(item['name'] == sku for item in skus)

def check_sku_availability_in_all_regions(skus_to_check, regions):
    """
    Iteratively checks the availability of SKUs across all specified regions.

    Args:
        skus_to_check (list): List of SKUs to check.
        regions (list): List of regions to check the SKUs in.
    """
    for region in regions:
        logging.info(f"\nChecking SKU availability in region: {region}")

        # Fetch available SKUs for the region
        skus = fetch_skus_for_region(region)
        
        if skus is None:
            logging.error(f"Skipping region {region} due to an error.")
            continue

        for sku in skus_to_check:
            # Check if the specific SKU is available
            if is_sku_available(region, sku, skus):
                logging.info(f"SKU {sku} is available in {region}")
            else:
                logging.info(f"SKU {sku} is NOT available in {region}")

# Execute the script to check SKU availability
if __name__ == "__main__":
    check_sku_availability_in_all_regions(skus_to_check, regions)
