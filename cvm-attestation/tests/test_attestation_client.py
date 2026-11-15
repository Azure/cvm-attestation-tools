# test_attestation_client.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from unittest.mock import MagicMock, patch
from src.attestation_client import AttestationClient, AttestationClientParameters, AttestationResult, IsolationType, HardwareEvidence, Verifier
from src.snp_utils import SnpFormatter
from src.attestation_provider import *
from src.attestation_types import EphemeralKey
from pytest_mock import mocker


@pytest.fixture
@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
def attestation_client(mock_report_parser, mock_tss_wrapper, mocker):
  # Mock the log object
  log_mock = mocker.Mock()

  # Mock the parameters
  parameters_mock = mocker.Mock()
  parameters_mock.user_claims = "mock_user_claims"
  parameters_mock.max_retries = 5

  # Mock TssWrapper and ReportParser calls during initialization
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = IsolationType.SEV_SNP

  # Create an instance of AttestationClient with mocked log and parameters
  return AttestationClient(logger=log_mock, parameters=parameters_mock)


@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
@patch('src.attestation_client.Encoder')
@patch('src.attestation_client.ImdsClient')
@patch('src.attestation_client.MAAProvider')
def test_attest_platform_success_snp(
  mock_imds_client,
  mock_encoder,
  mock_report_parser,
  mock_tss_wrapper,
  mock_attestation_provider,
  attestation_client):

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = IsolationType.SEV_SNP
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"
  
  # Mock Encoder methods
  mock_encoder.base64url_encode.side_effect = lambda x: f"encoded_{x.decode()}" if isinstance(x, bytes) else f"encoded_{x}"

  # Mock ImdsClient methods
  imds_client_instance = mock_imds_client.return_value
  imds_client_instance.get_vcek_certificate.return_value = b"mock_vcek_cert_chain"
  
  # Mock attestation provider methods
  mock_attestation_provider_instance = mock_attestation_provider.return_value
  mock_attestation_provider_instance.attest_platform.return_value = "mock_token"
  attestation_client.provider = mock_attestation_provider_instance

  encoded_token = attestation_client.attest_platform()

  assert encoded_token == "mock_token"
  attestation_client.log.info.assert_any_call('Attesting Platform Evidence...')
  attestation_client.log.info.assert_any_call('TOKEN:')
  attestation_client.log.info.assert_any_call("mock_token")


@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
@patch('src.attestation_client.Encoder')
@patch('src.attestation_client.ImdsClient')
@patch('src.attestation_client.MAAProvider')
def test_attest_platform_success_tdx(
  mock_imds_client,
  mock_encoder,
  mock_report_parser,
  mock_tss_wrapper,
  mock_attestation_provider,
  attestation_client):

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = IsolationType.TDX
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"
  
  # Mock Encoder methods
  mock_encoder.base64url_encode.side_effect = lambda x: f"encoded_{x.decode()}" if isinstance(x, bytes) else f"encoded_{x}"

  # Mock ImdsClient methods
  imds_client_instance = mock_imds_client.return_value
  imds_client_instance.get_td_quote.return_value = b"mock_td_quote"
  
  # Mock attestation provider methods
  mock_attestation_provider_instance = mock_attestation_provider.return_value
  mock_attestation_provider_instance.attest_platform.return_value = "mock_token"
  attestation_client.provider = mock_attestation_provider_instance

  encoded_token = attestation_client.attest_platform()

  assert encoded_token == "mock_token"
  attestation_client.log.info.assert_any_call('Attesting Platform Evidence...')
  attestation_client.log.info.assert_any_call('TOKEN:')
  attestation_client.log.info.assert_any_call("mock_token")


@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
@patch('src.attestation_client.AttestationClient.log_snp_report')
def test_get_hardware_evidence_success(
  mock_log_snp_report,
  mock_report_parser,
  mock_tss_wrapper,
  attestation_client):

  # Mock log_snp_report
  mock_log_snp_report.return_value = None

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = IsolationType.SEV_SNP
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"

  evidence = attestation_client.get_hardware_evidence()
  assert isinstance(evidence, HardwareEvidence)
  assert evidence.hardware_report == b"mock_hw_report"
  assert evidence.runtime_data == b"mock_runtime_data"
  attestation_client.log.info.assert_called_with('Collecting hardware evidence...')


@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
@patch('src.attestation_client.Encoder')
@patch('src.attestation_client.ImdsClient')
def test_get_hardware_evidence_tdx_successful(
  mock_imds_client,
  mock_encoder,
  mock_report_parser,
  mock_tss_wrapper,
  attestation_client):

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = IsolationType.TDX
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"

  # Mock ImdsClient methods
  imds_client_instance = mock_imds_client.return_value
  imds_client_instance.get_td_quote.return_value = b"mock_td_quote"

  # Mock Encoder methods
  mock_encoder.base64url_encode.side_effect = lambda x: f"encoded_{x.decode()}" if isinstance(x, bytes) else f"encoded_{x}"
  mock_encoder.base64url_decode.side_effect = lambda x: b"decoded_" + x if isinstance(x, bytes) else b"decoded_" + x.encode()

  evidence = attestation_client.get_hardware_evidence()
  assert isinstance(evidence, HardwareEvidence)
  assert evidence.hardware_report == b"decoded_mock_td_quote"
  assert evidence.runtime_data == b"mock_runtime_data"


@patch('src.attestation_client.TssWrapper')
@patch('src.attestation_client.ReportParser')
def test_get_hardware_evidence_exception(mock_report_parser, mock_tss_wrapper, attestation_client):
  # Mock TssWrapper to raise an exception
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.side_effect = Exception("some_exception")

  attestation_client.get_hardware_evidence()
  attestation_client.log.error.assert_called_with("Error while reading hardware report. Exception some_exception")


PLATFORM_EVIDENCE = {'hw_evidence': 'hw', 'runtime_data': 'rt', 'report_type': 'SEV_SNP'}
GUEST_ATTESTATION_INFO = '{"AttestationProtocolVersion": "2.0"}'
GUEST_EVIDENCE = {'attestation_info': {'AttestationProtocolVersion': '2.0'}, 'platform_evidence': None}


def make_client(isolation_type=IsolationType.TRUSTED_LAUNCH, claims=None, max_retries=1):
  parameters = AttestationClientParameters(
    "https://test.attest.azure.net", Verifier.MAA, isolation_type, claims=claims, max_retries=max_retries)
  client = AttestationClient(MagicMock(), parameters)
  client.provider = MagicMock()
  return client


@pytest.fixture
def guest_mocks(mocker):
  tss_wrapper = mocker.patch('src.attestation_client.TssWrapper').return_value
  tss_wrapper.get_pcr_quote.return_value = ('quote', 'sig')
  tss_wrapper.get_ephemeral_key.return_value = ('key', 'key_handle', 'tpm')
  mocker.patch('src.attestation_client.OsInfo')
  mocker.patch('src.attestation_client.get_measurements')
  mocker.patch('src.attestation_client.TpmInfo')
  guest_parameters = mocker.patch('src.attestation_client.GuestAttestationParameters')
  guest_parameters.return_value.toJson.return_value = GUEST_ATTESTATION_INFO
  mocker.patch('src.attestation_client.time.sleep')
  return tss_wrapper, guest_parameters


def test_collect_guest_evidence_releases_ephemeral_key_without_calling_provider(guest_mocks):
  tss_wrapper, _ = guest_mocks
  client = make_client()

  assert client.collect_guest_evidence() == GUEST_EVIDENCE
  tss_wrapper.release_ephemeral_key.assert_called_once_with('key_handle', 'tpm')
  client.provider.attest_guest.assert_not_called()


def test_collect_guest_evidence_uses_byte_claims_as_client_payload(guest_mocks):
  _, guest_parameters = guest_mocks
  client = make_client(claims=b'{"nonce":"abc"}')

  client.collect_guest_evidence()
  assert guest_parameters.call_args.args[4] == {"nonce": "abc"}


def test_attest_guest_detailed_decrypts_response_with_ephemeral_key(guest_mocks, mocker):
  tss_wrapper, _ = guest_mocks
  client = make_client()
  client.provider.attest_guest.return_value = 'encoded_response'
  mocker.patch.object(
    AttestationClient, '_decrypt_guest_response', autospec=True,
    side_effect=lambda self, response, guest_evidence: guest_evidence.decrypt(b'inner_key') and b'jwt')

  result = client.attest_guest_detailed()

  assert result == AttestationResult(token=b'jwt', evidence=GUEST_EVIDENCE)
  tss_wrapper.decrypt_with_ephemeral_key.assert_called_once_with(b'inner_key', mocker.ANY, 'key_handle', 'tpm')
  tss_wrapper.release_ephemeral_key.assert_not_called()


def test_attest_guest_detailed_returns_evidence_when_no_token_received(guest_mocks):
  tss_wrapper, _ = guest_mocks
  client = make_client(max_retries=2)
  client.provider.attest_guest.return_value = None

  result = client.attest_guest_detailed()

  assert result == AttestationResult(token=None, evidence=GUEST_EVIDENCE)
  assert client.provider.attest_guest.call_count == 2
  assert tss_wrapper.release_ephemeral_key.call_count == 2
  assert client.attest_guest() is None


def test_attest_guest_detailed_releases_ephemeral_key_when_provider_raises(guest_mocks):
  tss_wrapper, _ = guest_mocks
  client = make_client()
  client.provider.attest_guest.side_effect = AttestationProviderException("provider error")

  with pytest.raises(AttestationProviderException):
    client.attest_guest_detailed()
  tss_wrapper.release_ephemeral_key.assert_called_once_with('key_handle', 'tpm')


def test_attest_platform_detailed_returns_token_and_evidence(mocker):
  mocker.patch.object(AttestationClient, '_collect_platform_evidence', return_value=PLATFORM_EVIDENCE)
  client = make_client(IsolationType.SEV_SNP)
  client.provider.attest_platform.return_value = 'token'

  assert client.attest_platform_detailed() == AttestationResult(token='token', evidence=PLATFORM_EVIDENCE)
  client.provider.attest_platform.assert_called_once_with('hw', 'rt')
  assert client.attest_platform() == 'token'


def test_attest_platform_detailed_returns_evidence_when_no_token_received(mocker):
  mocker.patch.object(AttestationClient, '_collect_platform_evidence', return_value=PLATFORM_EVIDENCE)
  mocker.patch('src.attestation_client.time.sleep')
  client = make_client(IsolationType.SEV_SNP, max_retries=2)
  client.provider.attest_platform.return_value = None

  assert client.attest_platform_detailed() == AttestationResult(token=None, evidence=PLATFORM_EVIDENCE)
  assert client.provider.attest_platform.call_count == 2


def test_collect_platform_evidence_snp_without_calling_provider(mocker):
  mocker.patch('src.attestation_client.TssWrapper')
  report_parser = mocker.patch('src.attestation_client.ReportParser')
  report_parser.extract_report_type.return_value = IsolationType.SEV_SNP
  report_parser.extract_hw_report.return_value = b'hw_report'
  report_parser.extract_runtimes_data.return_value = b'runtime_data'
  imds_client = mocker.patch('src.attestation_client.ImdsClient').return_value
  imds_client.get_vcek_certificate.return_value = b'vcek_cert_chain'
  mocker.patch.object(AttestationClient, 'log_snp_report')
  client = make_client(IsolationType.SEV_SNP)

  evidence = client.collect_platform_evidence()

  assert evidence['report_type'] == 'SEV_SNP'
  assert evidence['hw_evidence'] == SnpFormatter.format_snp_evidence(b'hw_report', b'vcek_cert_chain')
  client.provider.attest_platform.assert_not_called()


def test_max_retries_is_passed_to_maa_provider():
  parameters = AttestationClientParameters(
    "https://test.attest.azure.net", Verifier.MAA, IsolationType.SEV_SNP, max_retries=3)
  assert AttestationClient(MagicMock(), parameters).provider.max_retries == 3


@pytest.mark.parametrize("max_retries", [0, -1, None])
def test_invalid_max_retries_is_rejected(max_retries):
  with pytest.raises(ValueError):
    AttestationClientParameters(
      "https://test.attest.azure.net", Verifier.MAA, IsolationType.SEV_SNP, max_retries=max_retries)
