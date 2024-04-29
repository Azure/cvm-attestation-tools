import pytest
from unittest.mock import MagicMock, patch
from AttestationClient import AttestationClient, Logger, AttestationClientParameters, IsolationType, Verifier
from src.AttestationProvider import *
from AttestationTypes import EphemeralKey
from pytest_mock import mocker

RESPONSE_JSON = {}


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
       patch('src.ReportParser.ReportParser.extract_report_type', return_value='tdx'), \
       patch('src.ReportParser.ReportParser.extract_runtimes_data', return_value='runtime_data'), \
       patch('src.ReportParser.ReportParser.extract_hw_report', return_value='hw_report'), \
       patch('src.Encoder.Encoder.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('src.ImdsClient.ImdsClient.get_td_quote', return_value='td_quote'), \
       patch('src.AttestationProvider.MAAProvider.attest_platform', return_value='encoded_token'):

    token = attestation_client.attest_platform()
    assert token == 'encoded_token'


def test_attest_platform_sev_snp(attestation_client):
  # Update the parameters to SEV_SNP isolation type
  attestation_client.parameters.isolation_type = IsolationType.SEV_SNP

  # Mock the external functions and methods called within attest_platform
  with patch('AttestationClient.get_hcl_report', return_value='hcl_report'), \
       patch('src.ReportParser.ReportParser.extract_report_type', return_value='snp'), \
       patch('src.ReportParser.ReportParser.extract_runtimes_data', return_value='runtime_data'), \
       patch('src.ReportParser.ReportParser.extract_hw_report', return_value='hw_report'), \
       patch('src.Encoder.Encoder.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('src.ImdsClient.ImdsClient.get_vcek_certificate', return_value='cert_chain'), \
       patch('AttestationClient.json.dumps', return_value='some_string'), \
       patch('src.Encoder.Encoder.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
       patch('src.AttestationProvider.MAAProvider.attest_platform', return_value='encoded_token'):

    token = attestation_client.attest_platform()
    assert token == 'encoded_token'

# def test_attest_guest_sev_snp(attestation_client, mocker):
#   ephemeral_key_mock = EphemeralKey(bytes(), bytes(), bytes())
#   pcr_quote_mock = (bytes(), bytes())
#   response_mock = {
#     'EncryptedInnerKey': 'key',
#     'AuthenticationData': 'auth',
#     'EncryptionParams': {
#       'Iv': 'iv',

#     },
#     'Jwt': 'dummy_encrypted_token'
#   }
#   aesgcm = MagicMock()
#   mocker.patch.object(aesgcm, 'decrypt')
# #   mocker.patch.object(aesgcm, 'error')

#   # Update the parameters to SEV_SNP isolation type
#   attestation_client.parameters.isolation_type = IsolationType.SEV_SNP
#   with patch.multiple('AttestationClient',
#     get_hcl_report=MagicMock(return_value='hcl_report'),
#     get_aik_cert=MagicMock(return_value=bytes('aik_cert', 'utf-8')),
#     get_aik_pub=MagicMock(return_value=bytes('aik_pub', 'utf-8')),
#     get_pcr_quote=MagicMock(return_value=pcr_quote_mock),
#     get_pcr_values=MagicMock(return_value=bytes('pcr_val', 'utf-8')),
#     # ... include other patches here
#     ):

# #   # Mock the external functions and methods called within attest_guest
# #   with patch('AttestationClient.get_hcl_report', return_value='hcl_report'), \
# #        patch('AttestationClient.get_aik_cert', return_value=bytes('aik_cert', 'utf-8')), \
# #        patch('AttestationClient.get_aik_pub', return_value=bytes('aik_pub', 'utf-8')), \
# #        patch('AttestationClient.get_pcr_quote', return_value=pcr_quote_mock), \
# #        patch('AttestationClient.get_pcr_values', return_value='pcr_values'), \
# #        patch('AttestationClient.get_ephemeral_key', return_value=ephemeral_key_mock), \
# #        patch('AttestationClient.get_measurements', return_value=bytes('tcg_logs', 'utf-8')), \
# #        patch('AttestationTypes.TpmInfo.get_values', return_value=bytes()), \
# #        patch('src.ReportParser.ReportParser.extract_report_type', return_value='snp'), \
# #        patch('src.ReportParser.ReportParser.extract_runtimes_data', return_value=bytes()), \
# #        patch('src.ReportParser.ReportParser.extract_hw_report', return_value='hw_report'), \
# #        patch('src.Encoder.Encoder.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
# #        patch('src.ImdsClient.ImdsClient.get_vcek_certificate', return_value=bytes()), \
# #        patch('AttestationClient.json.dumps', return_value='some_string'), \
# #        patch('src.Encoder.Encoder.base64url_encode', side_effect=lambda x: f'encoded_{x}'), \
# #        patch('src.AttestationProvider.MAAProvider.attest_guest', return_value='encoded_token'), \
# #        patch('AttestationClient.urlsafe_b64decode', return_value=bytes('decoded_response', 'utf-8')), \
# #        patch('src.Encoder.Encoder.base64decode', side_effect=lambda x: f'decoded_{x}'), \
# #        patch('AttestationClient.json.loads', return_value=response_mock), \
# #        patch('AttestationClient.decrypt_with_ephemeral_key', return_value='decrypted'), \
# #        patch('AttestationClient.AESGCM.decrypt', return_value=aesgcm):

#     token = attestation_client.attest_guest()
#     assert token == 'encoded_token'