# test_quote_v4.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import struct
import os
from src.quote_v4 import QuoteV4


@pytest.fixture
def valid_v4_quote_data():
  # Header (48 bytes)
  header = (
    b'\x04\x00' +           # version (2 bytes) = 4
    b'\x02\x00' +           # attestation_key_type (2 bytes) = 2
    b'\x81\x00\x00\x00' +   # tee_type (4 bytes)
    b'\x00\x00' +           # reserved_0 (2 bytes)
    b'\x00\x00' +           # reserved_1 (2 bytes)
    b'\x01' * 16 +          # qe_vendor_id (16 bytes)
    b'\x02' * 20            # user_data (20 bytes)
  )

  # Body (584 bytes)
  body = (
    b'\x03' * 16 +          # tee_tcb_svn (16 bytes)
    b'\x04' * 48 +          # mrseam (48 bytes)
    b'\x05' * 48 +          # mrsignerseam (48 bytes)
    b'\x06' * 8 +           # seam_attributes (8 bytes)
    b'\x07' * 8 +           # td_attributes (8 bytes)
    struct.pack('<Q', 123) + # xfam (8 bytes)
    b'\x08' * 48 +          # mr_td (48 bytes)
    b'\x09' * 48 +          # mr_config_id (48 bytes)
    b'\x0a' * 48 +          # mr_owner (48 bytes)
    b'\x0b' * 48 +          # mr_owner_config (48 bytes)
    b'\x0c' * 48 +          # rtmr_0 (48 bytes)
    b'\x0d' * 48 +          # rtmr_1 (48 bytes)
    b'\x0e' * 48 +          # rtmr_2 (48 bytes)
    b'\x0f' * 48 +          # rtmr_3 (48 bytes)
    b'\x10' * 64            # report_data (64 bytes)
  )

  # Signature data (variable length, minimum 134 bytes)
  cert_data_size = 10
  signature_data = (
    b'\x11' * 64 +                        # signature (64 bytes)
    b'\x12' * 64 +                        # attestation_key (64 bytes)
    b'\x13\x00' +                         # qe_certification_data_type (2 bytes)
    struct.pack('<I', cert_data_size) +   # cert_data_size (4 bytes)
    b'\x14' * cert_data_size              # cert_data (variable)
  )
  
  signature_len = struct.pack('<I', len(signature_data))
  
  return header + body + signature_len + signature_data


@pytest.fixture
def minimal_v4_quote_data():
  header = (
    b'\x04\x00' +           # version (2 bytes) = 4
    b'\x02\x00' +           # attestation_key_type (2 bytes) = 2
    b'\x81\x00\x00\x00' +   # tee_type (4 bytes)
    b'\x00\x00' +           # reserved_0 (2 bytes)
    b'\x00\x00' +           # reserved_1 (2 bytes)
    b'\x00' * 16 +          # qe_vendor_id (16 bytes)
    b'\x00' * 20            # user_data (20 bytes)
  )

  body = b'\x00' * 584
  cert_data_size = 0
  signature_data = b'\x00' * 64 + b'\x00' * 64 + b'\x00\x00' + struct.pack('<I', cert_data_size)
  signature_len = struct.pack('<I', len(signature_data))

  return header + body + signature_len + signature_data


class TestQuoteV4Initialization:
  """Tests for QuoteV4 initialization."""

  def test_initialization_with_valid_data(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)

    assert quote.parsed_data is not None
    assert quote.version == 4
    assert quote.parsed_data.header.version == 4

  def test_initialization_with_minimal_data(self, minimal_v4_quote_data):
    quote = QuoteV4(minimal_v4_quote_data)

    assert quote.parsed_data is not None
    assert quote.version == 4

  def test_initialization_with_empty_data_raises_error(self):
    with pytest.raises(ValueError) as excinfo:
      QuoteV4(b'')

    assert "Failed to parse TD Quote v4" in str(excinfo.value)

  def test_initialization_with_truncated_header_raises_error(self):
    truncated_header = b'\x04\x00\x02\x00'  # Only 4 bytes instead of 48

    with pytest.raises(ValueError) as excinfo:
      QuoteV4(truncated_header)

    assert "Failed to parse TD Quote v4" in str(excinfo.value)

  def test_initialization_with_truncated_body_raises_error(self):
    header = b'\x04\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    incomplete_body = b'\x00' * 100  # Less than required 584 bytes
    
    with pytest.raises(ValueError) as excinfo:
      QuoteV4(header + incomplete_body)
    
    assert "Failed to parse TD Quote v4" in str(excinfo.value)


class TestQuoteV4Version:
  """Tests for version property."""

  def test_version_returns_4(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    assert quote.version == 4

  def test_version_matches_header_version(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    assert quote.version == quote.parsed_data.header.version


class TestQuoteV4Deserialization:
  """Tests for deserialize method."""

  def test_deserialize_parses_header_correctly(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    
    assert quote.parsed_data.header.version == 4
    assert quote.parsed_data.header.attestation_key_type == 2
    assert quote.parsed_data.header.tee_type == b'\x81\x00\x00\x00'
    assert quote.parsed_data.header.qe_vendor_id == b'\x01' * 16
    assert quote.parsed_data.header.user_data == b'\x02' * 20

  def test_deserialize_parses_body_correctly(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    
    assert quote.parsed_data.td_quote_body.tee_tcb_svn == b'\x03' * 16
    assert quote.parsed_data.td_quote_body.mrseam == b'\x04' * 48
    assert quote.parsed_data.td_quote_body.mrsignerseam == b'\x05' * 48
    assert quote.parsed_data.td_quote_body.xfam == 123
    assert quote.parsed_data.td_quote_body.mr_td == b'\x08' * 48
    assert quote.parsed_data.td_quote_body.rtmr_0 == b'\x0c' * 48
    assert quote.parsed_data.td_quote_body.rtmr_3 == b'\x0f' * 48
    assert quote.parsed_data.td_quote_body.report_data == b'\x10' * 64

  def test_deserialize_parses_signature_correctly(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    
    assert quote.parsed_data.quote_signature_data.signature == b'\x11' * 64
    assert quote.parsed_data.quote_signature_data.attestation_key == b'\x12' * 64
    assert quote.parsed_data.quote_signature_data.cert_data_size == 10
    assert quote.parsed_data.quote_signature_data.cert_data == b'\x14' * 10


class TestQuoteV4Serialization:
  """Tests for serialize method."""

  def test_serialize_returns_bytes(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    serialized = quote.serialize()
    
    assert isinstance(serialized, bytes)

  def test_serialize_roundtrip_preserves_data(self, valid_v4_quote_data):
    quote1 = QuoteV4(valid_v4_quote_data)
    serialized = quote1.serialize()
    quote2 = QuoteV4(serialized)
    
    assert quote1.parsed_data.header.version == quote2.parsed_data.header.version
    assert quote1.parsed_data.header.qe_vendor_id == quote2.parsed_data.header.qe_vendor_id
    assert quote1.parsed_data.td_quote_body.mr_td == quote2.parsed_data.td_quote_body.mr_td
    assert quote1.parsed_data.quote_signature_data.signature == quote2.parsed_data.quote_signature_data.signature

  def test_serialize_minimal_data_roundtrip(self, minimal_v4_quote_data):
    quote1 = QuoteV4(minimal_v4_quote_data)
    serialized = quote1.serialize()
    quote2 = QuoteV4(serialized)
    
    assert quote1.version == quote2.version
    assert quote1.parsed_data.header.version == quote2.parsed_data.header.version

  def test_serialize_without_parsed_data_raises_error(self):
    # Create a quote but then manually clear parsed_data
    quote = QuoteV4.__new__(QuoteV4)
    quote.parsed_data = None
    
    with pytest.raises(ValueError) as excinfo:
      quote.serialize()
    
    assert "Cannot serialize: No parsed data available" in str(excinfo.value)


class TestQuoteV4Accessors:
  """Tests for accessor methods."""

  def test_get_header_returns_header(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    header = quote.get_header()
    
    assert header is not None
    assert header.version == 4
    assert header.attestation_key_type == 2

  def test_get_body_returns_body(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    body = quote.get_body()
    
    assert body is not None
    assert body.mr_td == b'\x08' * 48
    assert body.xfam == 123

  def test_get_signature_data_returns_signature(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    sig = quote.get_signature_data()
    
    assert sig is not None
    assert sig.signature == b'\x11' * 64
    assert sig.cert_data_size == 10

  def test_accessors_return_none_without_parsed_data(self):
    quote = QuoteV4.__new__(QuoteV4)
    quote.parsed_data = None
    
    assert quote.get_header() is None
    assert quote.get_body() is None
    assert quote.get_signature_data() is None


class TestQuoteV4StringRepresentation:
  """Tests for __str__ method."""

  def test_str_returns_none_without_parsed_data(self):
    quote = QuoteV4.__new__(QuoteV4)
    quote.parsed_data = None
    
    result = quote.__str__()
    
    assert result == "No parsed data available."

  def test_str_with_valid_data_prints_output(self, valid_v4_quote_data):
    quote = QuoteV4(valid_v4_quote_data)
    result = quote.__str__()
    
    assert "Quote Header:" in result
    assert "Version: 4" in result
    assert "TD Quote Body:" in result
    assert "Quote Signature Data:" in result


class TestQuoteV4EdgeCases:
  """Tests for edge cases and boundary conditions."""

  def test_large_cert_data_size(self):
    header = b'\x04\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body = b'\x00' * 584
    
    cert_data_size = 1000
    signature_data = b'\x00' * 64 + b'\x00' * 64 + b'\x00\x00' + struct.pack('<I', cert_data_size) + b'\xff' * cert_data_size
    signature_len = struct.pack('<I', len(signature_data))
    
    data = header + body + signature_len + signature_data
    quote = QuoteV4(data)
    
    assert quote.parsed_data.quote_signature_data.cert_data_size == 1000
    assert len(quote.parsed_data.quote_signature_data.cert_data) == 1000

  def test_max_uint64_xfam_value(self):
    header = b'\x04\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    
    max_uint64 = 0xFFFFFFFFFFFFFFFF
    # Body structure: tee_tcb_svn(16) + mrseam(48) + mrsignerseam(48) + seam_attributes(8) + 
    #                 td_attributes(8) + xfam(8) + mr_td(48) + mr_config_id(48) + mr_owner(48) + 
    #                 mr_owner_config(48) + rtmr_0(48) + rtmr_1(48) + rtmr_2(48) + rtmr_3(48) + report_data(64)
    body = (
      b'\x00' * 16 +                     # tee_tcb_svn
      b'\x00' * 48 +                     # mrseam
      b'\x00' * 48 +                     # mrsignerseam
      b'\x00' * 8 +                      # seam_attributes
      b'\x00' * 8 +                      # td_attributes
      struct.pack('<Q', max_uint64) +    # xfam (8 bytes)
      b'\x00' * 48 +                     # mr_td
      b'\x00' * 48 +                     # mr_config_id
      b'\x00' * 48 +                     # mr_owner
      b'\x00' * 48 +                     # mr_owner_config
      b'\x00' * 48 +                     # rtmr_0
      b'\x00' * 48 +                     # rtmr_1
      b'\x00' * 48 +                     # rtmr_2
      b'\x00' * 48 +                     # rtmr_3
      b'\x00' * 64                       # report_data
    )
    
    signature_data = b'\x00' * 64 + b'\x00' * 64 + b'\x00\x00' + struct.pack('<I', 0)
    signature_len = struct.pack('<I', len(signature_data))
    
    data = header + body + signature_len + signature_data
    quote = QuoteV4(data)
    
    assert quote.parsed_data.td_quote_body.xfam == max_uint64

  def test_zero_signature_length(self):
    header = b'\x04\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body = b'\x00' * 584
    signature_len = struct.pack('<I', 0)
    
    # This should fail because signature data has minimum size requirements
    with pytest.raises(ValueError):
      QuoteV4(header + body + signature_len)

class TestQuoteV4WithRealQuote:
  def read_real_quote(self):
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "reports", "td_quote_v4.dat")
    with open(file_path, "rb") as file:
      td_quote = file.read()

    return td_quote
  
  def test_real_quote_parsing(self):
    quote = QuoteV4(self.read_real_quote())

    # checking that the header matches expected values
    assert quote.parsed_data.header.version == 4
    assert quote.parsed_data.header.attestation_key_type == 2
    assert quote.parsed_data.header.tee_type == bytes.fromhex('81000000')
    assert quote.parsed_data.header.qe_vendor_id == bytes.fromhex('939a7233f79c4ca9940a0db3957f0607')
    assert quote.parsed_data.header.user_data == bytes.fromhex('3e9e5a71a84fa26c3f1f1e4935176ca600000000')

    # checking that the body fields match expected values
    assert quote.parsed_data.td_quote_body.tee_tcb_svn == bytes.fromhex('07010300000000000000000000000000')
    assert quote.parsed_data.td_quote_body.mrseam == bytes.fromhex('49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6')
    assert quote.parsed_data.td_quote_body.mrsignerseam == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.seam_attributes == bytes.fromhex('0000000000000000')
    assert quote.parsed_data.td_quote_body.td_attributes == bytes.fromhex('0000001000000000')
    assert quote.parsed_data.td_quote_body.xfam == 399591
    assert quote.parsed_data.td_quote_body.mr_td == bytes.fromhex('888b31b57a1cad6a358ce8c6a08f40198fa171596e01f70d5f360ee4798150983e55d2f89d804c3bfec06a44220c91b2')
    assert quote.parsed_data.td_quote_body.mr_config_id == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.mr_owner == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.mr_owner_config == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.rtmr_0 == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.rtmr_1 == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.rtmr_2 == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.rtmr_3 == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.td_quote_body.report_data == bytes.fromhex('e771caa11b55b340c5e0b6220adb4b8dcbf7a4bccb030f84ae088bd582aba4ac0000000000000000000000000000000000000000000000000000000000000000')

    # checking that the signature data matches expected values
    assert quote.parsed_data.quote_signature_data.signature == bytes.fromhex('0d3ad92b96cdff82ab473c6d654c3d0e60a7ae5657cbb470db99694c3e20d4771a8763c49dfb71b929748c385789fbdc303aaae205e1ada1b4621b339495b258')
    assert quote.parsed_data.quote_signature_data.attestation_key == bytes.fromhex('fde279fe998c7134a61545d9ec0f202de01a33248cfaa1a81936bc7f834681926467c7383302a8976cc2d8303428461b128ebe0a9cbf30f4b0887811a56eca24')
    assert quote.parsed_data.quote_signature_data.cert_data_size == 4166


class TestQuoteV4String:
  def test_str_returns_string_not_prints(self, valid_v4_quote_data, capsys):
    quote = QuoteV4(valid_v4_quote_data)
    
    # Call __str__ and capture the result
    result = str(quote)
    
    # Verify it returns a string
    assert isinstance(result, str)
    assert len(result) > 0
    
    # Verify nothing was printed to stdout
    captured = capsys.readouterr()
    assert captured.out == ""
    
    # Verify the string contains expected content
    assert "Quote Header:" in result
    assert "TD Quote Body:" in result
    assert "Quote Signature Data:" in result
    assert "Version: 4" in result
