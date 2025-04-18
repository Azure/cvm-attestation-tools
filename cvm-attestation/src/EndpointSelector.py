# EndpointSelector.py
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import random
from src.Logger import Logger
from src.ImdsClient import ImdsClient
from src.Isolation import IsolationType
import os


# Define supported isolation types for better error reporting
SUPPORTED_ISOLATION_TYPES = {
    IsolationType.TDX: { "path": "/attest/TdxVm", "query": "?api-version=2023-04-01-preview" },
    IsolationType.SEV_SNP: { "path": "/attest/SevSnpVm", "query": "?api-version=2022-08-01" }
}

# Define attestation type mapping
ATTESTATION_TYPES = {
    "guest": { "path": "/attest/AzureGuest", "query": "?api-version=2020-10-01" },
    "platform": SUPPORTED_ISOLATION_TYPES
}


class EndpointSelector:
  def __init__(self, json_file, logger: Logger):
    """
    Initialize with the JSON file containing location-attestation mappings.

    Parameters:
    json_file (str): Path to the JSON file with endpoint mappings.
    logger (Logger): Logger instance for logging.
    """

    self.logger = logger
    self.endpoints = self._load_endpoints(json_file)


  def _load_endpoints(self, json_file):
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


  def _get_endpoint(self, region):
    """
    Retrieve the attestation URI for a specific region. If the region is not
    found, return a randomly selected URI from the available endpoints.

    Parameters:
      region (str): Region name.

    Returns:
      str: Attestation URI for the region or a randomly selected one.
    """

    region = region.replace(" ", "").lower()
    self.logger.info(f"Getting endpoint for region: {region}")

    if region in self.endpoints:
      return self.endpoints[region]

    self.logger.warning(
      f"Region '{region}' not found in configured endpoints. Using random endpoint instead."
    )

    return random.choice(list(self.endpoints.values()))


  def get_attestation_endpoint(self, isolation_type: IsolationType, attestation_type: str):
    """
    Get the attestation endpoint based on the region.

    Parameters:
    isolation_type (IsolationType): Isolation type.
    attestation_type (str): Attestation type.

    Returns:
    str: Attestation endpoint.
    """

    imds_client = ImdsClient(self.logger)
    region = imds_client.get_region_from_compute_metadata()
    base_url = self._get_endpoint(region)

    type = attestation_type.lower()
    if type not in ATTESTATION_TYPES:
      raise ValueError(f"Invalid attestation type '{type}'. Supported types: {', '.join(ATTESTATION_TYPES.keys())}")

    if type == "guest":
      return base_url + ATTESTATION_TYPES[type]["path"] + ATTESTATION_TYPES[type]["query"]
    
    if isolation_type not in SUPPORTED_ISOLATION_TYPES:
      supported_types = ", ".join(SUPPORTED_ISOLATION_TYPES.keys())
      raise ValueError(f"Invalid isolation type '{type}'. Supported types: {supported_types}")

    isolation_info = SUPPORTED_ISOLATION_TYPES[isolation_type]
    return base_url + isolation_info["path"] + isolation_info["query"]
