import pytest
from unittest.mock import MagicMock, patch
from AttestationClient import HardwareEvidence, TssWrapper
from AttestationClient import AttestationClient, AttestationClientParameters, IsolationType, Verifier
from src.AttestationProvider import *
from AttestationTypes import EphemeralKey
from pytest_mock import mocker


@pytest.fixture
def attestation_client(mocker):
  # Mock the log object
  log_mock = mocker.Mock()

  # Mock the parameters
  parameters_mock = mocker.Mock()
  parameters_mock.user_claims = "mock_user_claims"
  parameters_mock.isolation_type = IsolationType.SEV_SNP

  # Create an instance of AttestationClient with mocked log and parameters
  return AttestationClient(logger=log_mock, parameters=parameters_mock)


@patch('AttestationClient.TssWrapper')
@patch('AttestationClient.ReportParser')
@patch('AttestationClient.Encoder')
@patch('AttestationClient.ImdsClient')
@patch('AttestationClient.MAAProvider')
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
  mock_report_parser.extract_report_type.return_value = "snp"
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


@patch('AttestationClient.TssWrapper')
@patch('AttestationClient.ReportParser')
@patch('AttestationClient.Encoder')
@patch('AttestationClient.ImdsClient')
@patch('AttestationClient.MAAProvider')
def test_attest_platform_success_tdx(
  mock_imds_client,
  mock_encoder,
  mock_report_parser,
  mock_tss_wrapper,
  mock_attestation_provider,
  attestation_client):

  attestation_client.parameters.isolation_type = IsolationType.TDX

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = "tdx"
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


@patch('AttestationClient.TssWrapper')
@patch('AttestationClient.ReportParser')
@patch.object(AttestationClient, 'log_snp_report')
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
  mock_report_parser.extract_report_type.return_value = "snp"
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"

  evidence = attestation_client.get_hardware_evidence()
  assert isinstance(evidence, HardwareEvidence)
  assert evidence.hardware_report == b"mock_hw_report"
  assert evidence.runtime_data == b"mock_runtime_data"
  attestation_client.log.info.assert_called_with('Collecting hardware evidence...')


@patch('AttestationClient.TssWrapper')
@patch('AttestationClient.ReportParser')
def test_get_hardware_evidence_tdx_not_supported(mock_report_parser, mock_tss_wrapper, attestation_client):
  # Set isolation type to TDX
  attestation_client.parameters.isolation_type = IsolationType.TDX

  # Mock methods in TssWrapper and ReportParser
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.return_value = "mock_hcl_report"
  mock_report_parser.extract_report_type.return_value = "tdx"
  mock_report_parser.extract_hw_report.return_value = b"mock_hw_report"
  mock_report_parser.extract_runtimes_data.return_value = b"mock_runtime_data"
  
  evidence = attestation_client.get_hardware_evidence()
  assert isinstance(evidence, HardwareEvidence)
  assert evidence.hardware_report == b"mock_hw_report"
  assert evidence.runtime_data == b"mock_runtime_data"
  attestation_client.log.info.assert_called_with('Hardware report parsing for TDX not supported yet')


@patch('AttestationClient.TssWrapper')
@patch('AttestationClient.ReportParser')
def test_get_hardware_evidence_exception(mock_report_parser, mock_tss_wrapper, attestation_client):
  # Mock TssWrapper to raise an exception
  tss_wrapper_instance = mock_tss_wrapper.return_value
  tss_wrapper_instance.get_hcl_report.side_effect = Exception("some_exception")

  attestation_client.get_hardware_evidence()
  attestation_client.log.error.assert_called_with("Error while reading hardware report. Exception some_exception")
