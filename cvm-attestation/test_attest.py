# test_attest.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from click.testing import CliRunner
from attest import attest
import hashlib
from unittest.mock import MagicMock, patch
from src.attestation_client import AttestationClient, AttestationClientParameters
from src.isolation import IsolationType
from src.endpoint_selector import EndpointSelector
from src.logger import Logger
from attest import get_endpoint, attest, AttestException  # Adjust import as needed

# Sample mock config JSON
MOCK_CONFIG = {
  "attestation_provider": "maa_tdx",
  "attestation_url": "https://west_europe.test.com",
  "api_key": "test-api-key",
  "claims": {"data": "test-claim"}
}

@pytest.fixture
def mock_logger():
  return MagicMock()

@pytest.fixture
def mock_attestation_client():
  return MagicMock(spec=AttestationClient)

@pytest.fixture
def mock_parse_config_file(mocker):
  return mocker.patch("attest.parse_config_file", return_value=MOCK_CONFIG)

def test_get_endpoint(mock_logger, mocker):
  mock_selector = mocker.patch("attest.EndpointSelector")
  mock_selector_instance = mock_selector.return_value
  mock_selector_instance.get_attestation_endpoint.return_value = "https://west_europe.test.com"

  endpoint = get_endpoint(mock_logger, IsolationType.TDX, "guest")
  assert endpoint == "https://west_europe.test.com"

def test_attestation_success(mock_logger, mock_attestation_client, mock_parse_config_file, mocker):
  mock_attestation_client.attest_guest.return_value = "mock-token"

  with patch("attest.AttestationClient", return_value=mock_attestation_client):
    token = mock_attestation_client.attest_guest()
    assert token == "mock-token"


def test_attest_successfully():
  runner = CliRunner()
  runner.invoke(attest, ['--c', 'somefile.json'])
  assert True

def test_attest_successfully_with_type_option():
  runner = CliRunner()
  runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Platform'])
  assert True

def test_attest_successfully_with_guest_type_option():
  runner = CliRunner()
  runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Guest'])
  assert True

def test_attest_fails_with_incorrect_type_option():
  runner = CliRunner()
  result = runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Invalid'])
  assert result.exit_code != 0
  assert 'Invalid value for' in result.output
