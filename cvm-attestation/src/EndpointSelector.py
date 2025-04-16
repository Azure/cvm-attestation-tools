# EndpointSelector.py
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import random
from src.Logger import Logger
from src.ImdsClient import ImdsClient

class EndpointSelector:
  def __init__(self, json_file, logger: Logger):
    """
    Initialize with the JSON file containing location-attestation mappings.

    Parameters:
    json_file (str): Path to the JSON file with endpoint mappings.
    logger (Logger): Logger instance for logging.
    """

    self.logger = logger
    self.endpoints = self.load_endpoints(json_file)


  def load_endpoints(self, json_file):
    """
    Load endpoint data from a JSON file.

    Parameters:
    json_file (str): Path to the JSON file.

    Returns:
    dict: Dictionary of endpoints.
    """

    self.logger.info(f"Loading endpoints from {json_file}")
    try:
      with open(json_file, 'r') as file:
        endpoints = json.load(file)

      cleaned_endpoints = {key.replace(" ", "").lower(): value for key, value in endpoints.items()}
      return cleaned_endpoints
    except json.JSONDecodeError:
      self.logger.error(f"Error: Failed to decode JSON from file '{json_file}'.")
      return {}
    except FileNotFoundError:
      self.logger.error(f"Error: JSON file '{json_file}' not found.")
      return {}


  def get_endpoint(self, region):
    """
    Get attestation URI for a region or select a random one if not found.

    Parameters:
    region (str): Region name.

    Returns:
    str: Attestation URI for the region or a random one if not found.
    """

    # Normalize the region name by removing spaces
    region = region.replace(" ", "").lower()
    self.logger.info(f"Getting endpoint for region: {region}")

    if region in self.endpoints:
      return self.endpoints[region]
    else:
      self.logger.warning(
        f"Warning: Region '{region}' not found. Selecting a random region."
      )
      return random.choice(list(self.endpoints.values())) if self.endpoints else None
  

  def get_attestation_endpoint(self):
    """
    Get the attestation endpoint based on the region.

    Returns:
    str: Attestation endpoint.
    """

    imds_client = ImdsClient(self.logger)
    region = imds_client.get_region_from_compute_metadata()
    print(region)

    return self.get_endpoint(region)
