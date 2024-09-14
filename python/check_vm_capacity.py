import json
import subprocess
import logging

# Configure logging for better output control
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# List of regions and SKUs to check
regions = ["eastus", "westus", "centralus", "eastus2", "westus2"]
skus_to_check = ["Standard_D2s_v3", "Standard_B2ms", "Standard_F4s_v2"]

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

def is_sku_available_for_subscription(sku):
    """
    Checks if the SKU is available for the subscription (i.e., not restricted by 'NotAvailableForSubscription').

    Args:
        sku (dict): SKU object containing the details for availability.

    Returns:
        bool: True if the SKU is available for the subscription, False if restricted.
    """
    restrictions = sku.get("restrictions", [])
    
    # Check for any restriction that has the reason "NotAvailableForSubscription"
    for restriction in restrictions:
        if restriction.get("reasonCode") == "NotAvailableForSubscription":
            return False

    return True

def is_sku_available(region, sku_name, skus):
    """
    Checks if a given SKU is available in the list of SKUs for a region, considering subscription restrictions.

    Args:
        region (str): Azure region name.
        sku_name (str): VM SKU name to check.
        skus (list): List of SKU objects for the region.

    Returns:
        bool: True if SKU is available and not restricted, False otherwise.
    """
    # Find the SKU in the list for the given name
    for sku in skus:
        if sku['name'] == sku_name:
            # Check if it is available for the subscription (no restriction)
            if is_sku_available_for_subscription(sku):
                return True
            else:
                logging.info(f"SKU {sku_name} is restricted for subscription in {region}.")
                return False
    return False

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
