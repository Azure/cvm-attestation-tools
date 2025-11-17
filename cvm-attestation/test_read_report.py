# test_read_report.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import json
import os
from unittest.mock import MagicMock, Mock, patch, mock_open, call
from click.testing import CliRunner
from read_report import read_report, handle_hardware_report
from AttestationClient import AttestationClient, HardwareEvidence, AttestationClientParameters, Verifier
from src.Isolation import IsolationType


@pytest.fixture
def mock_logger():
  """Create a mock logger."""
  logger = MagicMock()
  logger.info = MagicMock()
  logger.error = MagicMock()
  return logger


@pytest.fixture
def mock_attestation_client(mock_logger):
  """Create a mock attestation client."""
  client = MagicMock(spec=AttestationClient)
  client.log = mock_logger
  return client


@pytest.fixture
def snp_hardware_evidence():
  """Create mock SNP hardware evidence."""
  # Create a minimal valid SNP report (1184 bytes)
  hardware_report = b'\x00' * 1184
  runtime_data = json.dumps({
    "keys": [{
      "key_type": "RSA",
      "key": "test_key_data"
    }]
  }).encode()
  evidence = HardwareEvidence(IsolationType.SEV_SNP, hardware_report, runtime_data)
  return evidence


@pytest.fixture
def tdx_v4_hardware_evidence():
  """Create mock TDX v4 hardware evidence."""
  # Create a minimal valid TDX v4 quote
  # Header (48 bytes)
  header = (
    b'\x04\x00' +           # version = 4
    b'\x02\x00' +           # attestation_key_type
    b'\x81\x00\x00\x00' +   # tee_type
    b'\x00\x00' +           # reserved_0
    b'\x00\x00' +           # reserved_1
    b'\x01' * 16 +          # qe_vendor_id
    b'\x02' * 20            # user_data
  )
  
  # Body (584 bytes)
  body = (
    b'\x03' * 16 +          # tee_tcb_svn
    b'\x04' * 48 +          # mrseam
    b'\x05' * 48 +          # mrsignerseam
    b'\x06' * 8 +           # seam_attributes
    b'\x07' * 8 +           # td_attributes
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # xfam
    b'\x08' * 48 +          # mr_td
    b'\x09' * 48 +          # mr_config_id
    b'\x0a' * 48 +          # mr_owner
    b'\x0b' * 48 +          # mr_owner_config
    b'\x0c' * 48 +          # rtmr_0
    b'\x0d' * 48 +          # rtmr_1
    b'\x0e' * 48 +          # rtmr_2
    b'\x0f' * 48 +          # rtmr_3
    b'\x10' * 64            # report_data
  )
  
  # Signature data
  import struct
  cert_data_size = 10
  signature_data = (
    b'\x11' * 64 +                        # signature
    b'\x12' * 64 +                        # attestation_key
    b'\x13\x00' +                         # qe_certification_data_type
    struct.pack('<I', cert_data_size) +   # cert_data_size
    b'\x14' * cert_data_size              # cert_data
  )
  
  quote_signature_data_len = struct.pack('<I', len(signature_data))
  hardware_report = header + body + quote_signature_data_len + signature_data
  
  runtime_data = json.dumps({
    "keys": [{
      "key_type": "RSA",
      "key": "test_key_data"
    }]
  }).encode()
  
  evidence = HardwareEvidence(IsolationType.TDX, hardware_report, runtime_data)
  return evidence


@pytest.fixture
def tdx_v5_hardware_evidence():
  """Create mock TDX v5 hardware evidence."""
  # Create a minimal valid TDX v5 quote
  import struct
  
  # Header (48 bytes)
  header = (
    b'\x05\x00' +           # version = 5
    b'\x02\x00' +           # attestation_key_type
    b'\x81\x00\x00\x00' +   # tee_type
    b'\x00\x00' +           # reserved_1
    b'\x00\x00' +           # reserved_2
    b'\x01' * 16 +          # qe_vendor_id
    b'\x02' * 20            # user_data
  )
  
  # Body Descriptor (6 bytes)
  body_descriptor_header = (
    b'\x03\x00' +           # quote_body_type
    struct.pack('<I', 648)  # size (648 bytes for v5)
  )
  
  # Body (648 bytes)
  body = (
    b'\x04' * 16 +          # tee_tcb_svn
    b'\x05' * 48 +          # mrseam
    b'\x06' * 48 +          # mrsignerseam
    b'\x07' * 8 +           # seam_attributes
    b'\x08' * 8 +           # td_attributes
    struct.pack('<Q', 456) + # xfam
    b'\x09' * 48 +          # mr_td
    b'\x0a' * 48 +          # mr_config_id
    b'\x0b' * 48 +          # mr_owner
    b'\x0c' * 48 +          # mr_owner_config
    b'\x0d' * 48 +          # rtmr[0]
    b'\x0e' * 48 +          # rtmr[1]
    b'\x0f' * 48 +          # rtmr[2]
    b'\x10' * 48 +          # rtmr[3]
    b'\x11' * 64 +          # report_data
    b'\x12' * 16 +          # tee_tcb_svn_2
    b'\x13' * 48            # mr_service_td
  )
  
  # Signature data
  signature_data = b'\x14' * 100
  quote_signature_data_len = struct.pack('<I', len(signature_data))
  
  hardware_report = header + body_descriptor_header + body + quote_signature_data_len + signature_data
  
  runtime_data = json.dumps({
    "keys": [{
      "key_type": "RSA",
      "key": "test_key_data"
    }]
  }).encode()
  
  evidence = HardwareEvidence(IsolationType.TDX, hardware_report, runtime_data)
  return evidence


class TestHandleHardwareReportSNP:
  """Tests for handle_hardware_report with SNP reports."""
  
  def test_handle_snp_report_success(self, mock_attestation_client, snp_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = snp_hardware_evidence
    
    with patch('read_report.AttestationReport') as mock_report_class, \
         patch('builtins.open', mock_open()) as mock_file, \
         patch('read_report.json.dump') as mock_json_dump:
      
      mock_report = MagicMock()
      mock_report_class.deserialize.return_value = mock_report
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify hardware evidence was retrieved
      mock_attestation_client.get_hardware_evidence.assert_called_once()
      
      # Verify SNP report was deserialized
      mock_report_class.deserialize.assert_called_once_with(snp_hardware_evidence.hardware_report)
      
      # Verify report was displayed
      mock_report.display.assert_called_once()
      
      # Verify files were written
      assert mock_file.call_count == 2
      
      # Verify logger messages
      mock_attestation_client.log.info.assert_any_call("Reading hardware report...")
      mock_attestation_client.log.info.assert_any_call(f"Hardware report type: {IsolationType.SEV_SNP}")
      mock_attestation_client.log.info.assert_any_call("Got attestation report successfully!")
  
  def test_handle_snp_report_parse_failure(self, mock_attestation_client, snp_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = snp_hardware_evidence
    
    with patch('read_report.AttestationReport') as mock_report_class:
      mock_report_class.deserialize.side_effect = Exception("Parse error")
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify error was logged
      mock_attestation_client.log.error.assert_called_once()
      assert "Failed to parse the SNP report" in str(mock_attestation_client.log.error.call_args)


class TestHandleHardwareReportTDX:
  """Tests for handle_hardware_report with TDX quotes."""
  
  def test_handle_tdx_v4_report_success(self, mock_attestation_client, tdx_v4_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = tdx_v4_hardware_evidence
    
    with patch('builtins.open', mock_open()) as mock_file, \
         patch('read_report.json.dump') as mock_json_dump, \
         patch('builtins.print') as mock_print:
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify hardware evidence was retrieved
      mock_attestation_client.get_hardware_evidence.assert_called_once()
      
      # Verify quote was printed
      mock_print.assert_called_once()
      
      # Verify files were written
      assert mock_file.call_count == 2
      
      # Verify logger messages
      mock_attestation_client.log.info.assert_any_call("Reading hardware report...")
      mock_attestation_client.log.info.assert_any_call(f"Hardware report type: {IsolationType.TDX}")
      mock_attestation_client.log.info.assert_any_call("Got TD quote successfully!")
  
  def test_handle_tdx_v5_report_success(self, mock_attestation_client, tdx_v5_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = tdx_v5_hardware_evidence
    
    with patch('builtins.open', mock_open()) as mock_file, \
         patch('read_report.json.dump') as mock_json_dump, \
         patch('builtins.print') as mock_print:
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify hardware evidence was retrieved
      mock_attestation_client.get_hardware_evidence.assert_called_once()
      
      # Verify quote was printed
      mock_print.assert_called_once()
      
      # Verify files were written
      assert mock_file.call_count == 2
      
      # Verify logger messages
      mock_attestation_client.log.info.assert_any_call("Got TD quote successfully!")
  
  def test_handle_tdx_report_unicode_error(self, mock_attestation_client, tdx_v4_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = tdx_v4_hardware_evidence
    
    with patch('read_report.Quote') as mock_quote_class:
      mock_quote_class.from_bytes.side_effect = UnicodeDecodeError('utf-8', b'', 0, 1, 'test error')
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify error was logged
      mock_attestation_client.log.error.assert_called_once()
      assert "Failed to decode the TD quote header" in str(mock_attestation_client.log.error.call_args)
  
  def test_handle_tdx_report_parse_failure(self, mock_attestation_client, tdx_v4_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = tdx_v4_hardware_evidence
    
    with patch('read_report.Quote') as mock_quote_class:
      mock_quote_class.from_bytes.side_effect = Exception("Parse error")
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify error was logged
      mock_attestation_client.log.error.assert_called_once()
      assert "Failed to parse the TD quote" in str(mock_attestation_client.log.error.call_args)


class TestHandleHardwareReportInvalid:
  """Tests for handle_hardware_report with invalid report types."""
  
  def test_handle_invalid_report_type(self, mock_attestation_client):
    invalid_evidence = HardwareEvidence(IsolationType.UNDEFINED, b'\x00' * 100, b'{}')
    mock_attestation_client.get_hardware_evidence.return_value = invalid_evidence
    
    with pytest.raises(ValueError) as excinfo:
      handle_hardware_report(mock_attestation_client)
    
    assert "Invalid hardware report type: IsolationType.UNDEFINED" in str(excinfo.value)


class TestHandleHardwareReportFileOperations:
  """Tests for file writing operations in handle_hardware_report."""
  
  def test_hardware_report_file_written(self, mock_attestation_client, snp_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = snp_hardware_evidence
    
    with patch('read_report.AttestationReport') as mock_report_class, \
         patch('builtins.open', mock_open()) as mock_file, \
         patch('read_report.json.dump'):
      
      mock_report_class.deserialize.return_value = MagicMock()
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify report.bin was opened for writing
      mock_file.assert_any_call('report.bin', 'wb')
      
      # Get the file handle and verify write was called with hardware_report
      file_handle = mock_file()
      file_handle.write.assert_any_call(snp_hardware_evidence.hardware_report)
      
      # Verify logger message
      mock_attestation_client.log.info.assert_any_call(
        "Hardware report successfully written to: report.bin"
      )
  
  def test_runtime_data_json_written(self, mock_attestation_client, snp_hardware_evidence):
    mock_attestation_client.get_hardware_evidence.return_value = snp_hardware_evidence
    
    with patch('read_report.AttestationReport') as mock_report_class, \
         patch('builtins.open', mock_open()) as mock_file, \
         patch('read_report.json.dump') as mock_json_dump, \
         patch('read_report.json.loads') as mock_json_loads:
      
      mock_report_class.deserialize.return_value = MagicMock()
      mock_json_loads.return_value = {"test": "data"}
      
      handle_hardware_report(mock_attestation_client)
      
      # Verify runtime_data.json was opened for writing
      mock_file.assert_any_call('runtime_data.json', 'w')
      
      # Verify json.dump was called
      mock_json_dump.assert_called_once()
      
      # Verify logger message
      mock_attestation_client.log.info.assert_any_call(
        "Runtime Data successfully written to: 'runtime_data.json'"
      )



class TestHardwareEvidenceStructure:
  """Tests for the HardwareEvidence data structure used in tests."""
  
  def test_snp_evidence_structure(self, snp_hardware_evidence):
    assert snp_hardware_evidence.type == IsolationType.SEV_SNP
    assert isinstance(snp_hardware_evidence.hardware_report, bytes)
    assert len(snp_hardware_evidence.hardware_report) == 1184
    assert isinstance(snp_hardware_evidence.runtime_data, bytes)
    
    # Verify runtime_data is valid JSON
    runtime_json = json.loads(snp_hardware_evidence.runtime_data)
    assert 'keys' in runtime_json
  
  def test_tdx_v4_evidence_structure(self, tdx_v4_hardware_evidence):
    assert tdx_v4_hardware_evidence.type == IsolationType.TDX
    assert isinstance(tdx_v4_hardware_evidence.hardware_report, bytes)
    
    # Verify it's a valid v4 quote (version bytes should be 0x04 0x00)
    assert tdx_v4_hardware_evidence.hardware_report[0:2] == b'\x04\x00'
  
  def test_tdx_v5_evidence_structure(self, tdx_v5_hardware_evidence):
    assert tdx_v5_hardware_evidence.type == IsolationType.TDX
    assert isinstance(tdx_v5_hardware_evidence.hardware_report, bytes)
    
    # Verify it's a valid v5 quote (version bytes should be 0x05 0x00)
    assert tdx_v5_hardware_evidence.hardware_report[0:2] == b'\x05\x00'
