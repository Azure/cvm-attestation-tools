# test_EndpointSelector.py
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import json
import random
from unittest.mock import MagicMock, patch
from src.EndpointSelector import EndpointSelector
from src.Isolation import IsolationType

# Sample test data
MOCK_ENDPOINTS = {
  "West Europe": "https://europe_endpoint.test.net",
  "East US": "https://eastus_endpoint.test.net",
  "Japan East": "https://japan_east_endpoint.test.net"
}

# Fixture to create an EndpointSelector instance with mock data
@pytest.fixture
def endpoint_selector(mocker):
  logger = MagicMock()
  mocker.patch.object(logger, 'info')
  mocker.patch.object(logger, 'error')
  mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps(MOCK_ENDPOINTS)))
  return EndpointSelector("mock_attestation_lookup.json", logger)


def test_get_endpoint_valid_region(endpoint_selector):
  assert endpoint_selector._get_endpoint("West Europe") == MOCK_ENDPOINTS["West Europe"]


def test_get_endpoint_from_random_selector_when_region_is_not_found(endpoint_selector):
  with patch("random.choice", return_value="https://japan_east_endpoint.test.net"):
    uri = endpoint_selector._get_endpoint("Unknown Region")
    assert uri == "https://japan_east_endpoint.test.net"


def test_load_endpoints_file_not_found(mocker):
  logger = MagicMock()
  mocker.patch.object(logger, 'info')
  mocker.patch.object(logger, 'error')
  mocker.patch("builtins.open", side_effect=FileNotFoundError)
  selector = EndpointSelector("non_existent_file.json", logger)

  assert selector.endpoints == {}


def test_random_selection_endpoint(endpoint_selector):
  with patch("random.choice") as mock_random:
    mock_random.side_effect = lambda x: x[0]
    uri = endpoint_selector._get_endpoint("Nonexistent Region")

    assert uri == list(MOCK_ENDPOINTS.values())[0]


def test_region_match_without_spaces(endpoint_selector):
  assert endpoint_selector._get_endpoint("WestEurope") == MOCK_ENDPOINTS["West Europe"]


def test_region_match_with_spaces(endpoint_selector):
  assert endpoint_selector._get_endpoint("West Europe") == MOCK_ENDPOINTS["West Europe"]


def test_region_case_insensitivity(endpoint_selector):
  assert endpoint_selector._get_endpoint("west europe") == MOCK_ENDPOINTS["West Europe"]


def test_get_attestation_platform_endpoint_for_tdx(endpoint_selector, mocker):
  mock_imds_client = mocker.patch("src.EndpointSelector.ImdsClient")
  mock_imds_instance = mock_imds_client.return_value
  mock_imds_instance.get_region_from_compute_metadata.return_value = "West Europe"

  uri = endpoint_selector.get_attestation_endpoint(IsolationType.TDX, "platform")
  assert uri == MOCK_ENDPOINTS["West Europe"] + "/attest/TdxVm?api-version=2023-04-01-preview"


def test_get_attestation_platform_endpoint_for_snp(endpoint_selector, mocker):
  mock_imds_client = mocker.patch("src.EndpointSelector.ImdsClient")
  mock_imds_instance = mock_imds_client.return_value
  mock_imds_instance.get_region_from_compute_metadata.return_value = "West Europe"

  actual = endpoint_selector.get_attestation_endpoint(IsolationType.SEV_SNP, "platform")
  expected = MOCK_ENDPOINTS["West Europe"] + "/attest/SevSnpVm?api-version=2022-08-01"
  assert actual == expected


def test_get_attestation_guest_endpoint(endpoint_selector, mocker):
  mock_imds_client = mocker.patch("src.EndpointSelector.ImdsClient")
  mock_imds_instance = mock_imds_client.return_value
  mock_imds_instance.get_region_from_compute_metadata.return_value = "West Europe"

  actual = endpoint_selector.get_attestation_endpoint(IsolationType.SEV_SNP, "guest")
  expected = MOCK_ENDPOINTS["West Europe"] + "/attest/AzureGuest?api-version=2020-10-01"
  assert actual == expected

  actual = endpoint_selector.get_attestation_endpoint(IsolationType.TDX, "guest")
  assert actual == expected
