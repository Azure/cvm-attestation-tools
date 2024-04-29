import pytest
from unittest.mock import MagicMock, patch
from AttestationClient import AttestationClient, Logger, AttestationClientParameters, IsolationType, Verifier
from src.AttestationProvider import *

# Fixture to create an AttestationClient instance
@pytest.fixture
def attestation_client(mocker):
    logger = MagicMock()
    mocker.patch.object(logger, 'info')
    mocker.patch.object(logger, 'error')

    parameters = AttestationClientParameters(
        endpoint='http://someendpoint.com/api',
        verifier=Verifier.MAA,
        isolation_type=IsolationType.TDX,
        claims='user_claims')
    return AttestationClient(logger, parameters)

# Test for attest_platform method with TDX isolation type
def test_attest_platform_tdx(attestation_client):
  # Update the parameters to TDX isolation type
  attestation_client.parameters.isolation_type = IsolationType.TDX

  # Mock the external functions and methods called within attest_platform
  with patch('AttestationClient.get_hcl_report', return_value='hcl_report'), \
       patch('AttestationClient.extract_report_type', return_value='tdx'), \
       patch('AttestationClient.extract_runtime_data', return_value='runtime_data'), \
       patch('AttestationClient.extract_hw_report', return_value='hw_report'), \
       patch('AttestationClient.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('AttestationClient.get_td_quote', return_value='td_quote'), \
       patch('src.AttestationProvider.MAAProvider.attest_platform', return_value='encoded_token'):

    token = attestation_client.attest_platform()
    assert token == 'encoded_token'


def test_attest_platform_sev_snp(attestation_client):
  # Update the parameters to SEV_SNP isolation type
  attestation_client.parameters.isolation_type = IsolationType.SEV_SNP

  # Mock the external functions and methods called within attest_platform
  with patch('AttestationClient.get_hcl_report', return_value='hcl_report'), \
       patch('AttestationClient.extract_report_type', return_value='snp'), \
       patch('AttestationClient.extract_runtime_data', return_value='runtime_data'), \
       patch('AttestationClient.extract_hw_report', return_value='hw_report'), \
       patch('AttestationClient.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('AttestationClient.get_vcek_certificate', return_value='cert_chain'), \
       patch('AttestationClient.json.dumps', return_value='some_string'), \
       patch('AttestationClient.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('src.AttestationProvider.MAAProvider.attest_platform', return_value='encoded_token'):

    token = attestation_client.attest_platform()
    assert token == 'encoded_token'