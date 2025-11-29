# test_quote_v5.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import struct
import os
from src.quote_v5 import QuoteV5


@pytest.fixture
def valid_v5_quote_data():
  # Header (48 bytes)
  header = (
    b'\x05\x00' +           # version (2 bytes) = 5
    b'\x02\x00' +           # attestation_key_type (2 bytes) = 2
    b'\x81\x00\x00\x00' +   # tee_type (4 bytes)
    b'\x00\x00' +           # reserved_1 (2 bytes)
    b'\x00\x00' +           # reserved_2 (2 bytes)
    b'\x01' * 16 +          # qe_vendor_id (16 bytes)
    b'\x02' * 20            # user_data (20 bytes)
  )
  
  # Body Descriptor (6 bytes)
  body_descriptor_header = (
    b'\x03\x00' +           # quote_body_type (2 bytes)
    struct.pack('<I', 648)  # size (4 bytes) - v5 body is 648 bytes
  )
  
  # Body (648 bytes)
  body = (
    b'\x04' * 16 +          # tee_tcb_svn (16 bytes)
    b'\x05' * 48 +          # mrseam (48 bytes)
    b'\x06' * 48 +          # mrsignerseam (48 bytes)
    b'\x07' * 8 +           # seam_attributes (8 bytes)
    b'\x08' * 8 +           # td_attributes (8 bytes)
    struct.pack('<Q', 456) + # xfam (8 bytes)
    b'\x09' * 48 +          # mr_td (48 bytes)
    b'\x0a' * 48 +          # mr_config_id (48 bytes)
    b'\x0b' * 48 +          # mr_owner (48 bytes)
    b'\x0c' * 48 +          # mr_owner_config (48 bytes)
    b'\x0d' * 48 +          # rtmr[0] (48 bytes)
    b'\x0e' * 48 +          # rtmr[1] (48 bytes)
    b'\x0f' * 48 +          # rtmr[2] (48 bytes)
    b'\x10' * 48 +          # rtmr[3] (48 bytes)
    b'\x11' * 64 +          # report_data (64 bytes)
    b'\x12' * 16 +          # tee_tcb_svn_2 (16 bytes)
    b'\x13' * 48            # mr_service_td (48 bytes)
  )
  
  # Signature data (variable length)
  signature_data_len = 100
  signature_data = b'\x14' * signature_data_len
  signature_len = struct.pack('<I', signature_data_len)

  return header + body_descriptor_header + body + signature_len + signature_data


@pytest.fixture
def minimal_v5_quote_data():
  header = (
    b'\x05\x00' +           # version (2 bytes) = 5
    b'\x02\x00' +           # attestation_key_type (2 bytes) = 2
    b'\x81\x00\x00\x00' +   # tee_type (4 bytes)
    b'\x00\x00' +           # reserved_1 (2 bytes)
    b'\x00\x00' +           # reserved_2 (2 bytes)
    b'\x00' * 16 +          # qe_vendor_id (16 bytes)
    b'\x00' * 20            # user_data (20 bytes)
  )
  
  body_descriptor_header = (
    b'\x00\x00' +           # quote_body_type (2 bytes)
    struct.pack('<I', 648)  # size (4 bytes)
  )
  
  body = b'\x00' * 648
  signature_data_len = 0
  signature_len = struct.pack('<I', signature_data_len)
  
  return header + body_descriptor_header + body + signature_len


class TestQuoteV5Initialization:
  def test_initialization_with_valid_data(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert quote.parsed_data is not None
    assert quote.version == 5
    assert quote.parsed_data.header.version == 5

  def test_initialization_with_minimal_data(self, minimal_v5_quote_data):
    quote = QuoteV5(minimal_v5_quote_data)
    
    assert quote.parsed_data is not None
    assert quote.version == 5

  def test_initialization_with_empty_data_raises_error(self):
    with pytest.raises(ValueError) as excinfo:
      QuoteV5(b'')
    
    assert "Failed to parse TD Quote v5" in str(excinfo.value)

  def test_initialization_with_truncated_header_raises_error(self):
    truncated_header = b'\x05\x00\x02\x00'  # Only 4 bytes instead of 48
    
    with pytest.raises(ValueError) as excinfo:
      QuoteV5(truncated_header)
    
    assert "Failed to parse TD Quote v5" in str(excinfo.value)

  def test_initialization_with_truncated_body_raises_error(self):
    header = b'\x05\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body_descriptor = b'\x00\x00' + struct.pack('<I', 648)
    incomplete_body = b'\x00' * 100  # Less than required 648 bytes
    
    with pytest.raises(ValueError) as excinfo:
      QuoteV5(header + body_descriptor + incomplete_body)
    
    assert "Failed to parse TD Quote v5" in str(excinfo.value)


class TestQuoteV5Version:
  """Tests for version property."""

  def test_version_returns_5(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    assert quote.version == 5

  def test_version_matches_header_version(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    assert quote.version == quote.parsed_data.header.version


class TestQuoteV5Deserialization:
  """Tests for deserialize method."""

  def test_deserialize_parses_header_correctly(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert quote.parsed_data.header.version == 5
    assert quote.parsed_data.header.attestation_key_type == 2
    assert quote.parsed_data.header.tee_type == 0x81
    assert quote.parsed_data.header.qe_vendor_id == b'\x01' * 16
    assert quote.parsed_data.header.user_data == b'\x02' * 20

  def test_deserialize_parses_body_descriptor_correctly(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert quote.parsed_data.body.quote_body_type == b'\x03\x00'
    assert quote.parsed_data.body.size == 648

  def test_deserialize_parses_body_correctly(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert quote.parsed_data.body.body.tee_tcb_svn == b'\x04' * 16
    assert quote.parsed_data.body.body.mrseam == b'\x05' * 48
    assert quote.parsed_data.body.body.mrsignerseam == b'\x06' * 48
    assert quote.parsed_data.body.body.xfam == 456
    assert quote.parsed_data.body.body.mr_td == b'\x09' * 48
    assert len(quote.parsed_data.body.body.rtmr) == 4
    assert quote.parsed_data.body.body.rtmr[0] == b'\x0d' * 48
    assert quote.parsed_data.body.body.rtmr[3] == b'\x10' * 48
    assert quote.parsed_data.body.body.report_data == b'\x11' * 64
    assert quote.parsed_data.body.body.tee_tcb_svn_2 == b'\x12' * 16
    assert quote.parsed_data.body.body.mr_service_td == b'\x13' * 48

  def test_deserialize_parses_signature_correctly(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert quote.parsed_data.quote_signature_data_len == 100
    assert quote.parsed_data.quote_signature_data == b'\x14' * 100


class TestQuoteV5Serialization:
  """Tests for serialize method."""

  def test_serialize_returns_bytes(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    serialized = quote.serialize()
    
    assert isinstance(serialized, bytes)

  def test_serialize_roundtrip_preserves_data(self, valid_v5_quote_data):
    quote1 = QuoteV5(valid_v5_quote_data)
    serialized = quote1.serialize()
    quote2 = QuoteV5(serialized)
    
    assert quote1.parsed_data.header.version == quote2.parsed_data.header.version
    assert quote1.parsed_data.header.qe_vendor_id == quote2.parsed_data.header.qe_vendor_id
    assert quote1.parsed_data.body.body.mr_td == quote2.parsed_data.body.body.mr_td
    assert quote1.parsed_data.body.body.rtmr[0] == quote2.parsed_data.body.body.rtmr[0]
    assert quote1.parsed_data.quote_signature_data == quote2.parsed_data.quote_signature_data

  def test_serialize_minimal_data_roundtrip(self, minimal_v5_quote_data):
    quote1 = QuoteV5(minimal_v5_quote_data)
    serialized = quote1.serialize()
    quote2 = QuoteV5(serialized)
    
    assert quote1.version == quote2.version
    assert quote1.parsed_data.header.version == quote2.parsed_data.header.version

  def test_serialize_without_parsed_data_raises_error(self):
    # Create a quote but then manually clear parsed_data
    quote = QuoteV5.__new__(QuoteV5)
    quote.parsed_data = None
    
    with pytest.raises(ValueError) as excinfo:
      quote.serialize()
    
    assert "Cannot serialize: No parsed data available" in str(excinfo.value)


class TestQuoteV5Accessors:
  """Tests for accessor methods."""

  def test_get_header_returns_header(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    header = quote.get_header()
    
    assert header is not None
    assert header.version == 5
    assert header.attestation_key_type == 2

  def test_get_body_returns_body(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    body = quote.get_body()
    
    assert body is not None
    assert body.mr_td == b'\x09' * 48
    assert body.xfam == 456
    assert len(body.rtmr) == 4

  def test_get_body_descriptor_returns_descriptor(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    descriptor = quote.get_body_descriptor()
    
    assert descriptor is not None
    assert descriptor.quote_body_type == b'\x03\x00'
    assert descriptor.size == 648

  def test_get_signature_data_returns_signature(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    sig = quote.get_signature_data()
    
    assert sig is not None
    assert sig == b'\x14' * 100

  def test_accessors_return_none_without_parsed_data(self):
    quote = QuoteV5.__new__(QuoteV5)
    quote.parsed_data = None
    
    assert quote.get_header() is None
    assert quote.get_body() is None
    assert quote.get_body_descriptor() is None
    assert quote.get_signature_data() is None


class TestQuoteV5StringRepresentation:
  """Tests for __str__ method."""

  def test_str_returns_none_without_parsed_data(self):
    quote = QuoteV5.__new__(QuoteV5)
    quote.parsed_data = None
    
    result = quote.__str__()
    
    assert result == "No parsed data available."

  def test_str_with_valid_data_prints_output(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    result = quote.__str__()
    
    assert "TD Quote Header:" in result
    assert "Version: 5" in result
    assert "TD Quote Body Descriptor:" in result
    assert "TD Quote Body:" in result
    assert "Quote Signature Data:" in result


class TestQuoteV5EdgeCases:
  """Tests for edge cases and boundary conditions."""

  def test_large_signature_data(self):
    header = b'\x05\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body_descriptor = b'\x00\x00' + struct.pack('<I', 648)
    body = b'\x00' * 648
    
    signature_data_len = 5000
    signature_data = b'\xff' * signature_data_len
    signature_len = struct.pack('<I', signature_data_len)
    
    data = header + body_descriptor + body + signature_len + signature_data
    quote = QuoteV5(data)
    
    assert quote.parsed_data.quote_signature_data_len == 5000
    assert len(quote.parsed_data.quote_signature_data) == 5000

  def test_max_uint64_xfam_value(self):
    header = b'\x05\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body_descriptor = b'\x00\x00' + struct.pack('<I', 648)
    
    max_uint64 = 0xFFFFFFFFFFFFFFFF
    # Body structure: tee_tcb_svn(16) + mrseam(48) + mrsignerseam(48) + seam_attributes(8) +
    #                 td_attributes(8) + xfam(8) + mr_td(48) + mr_config_id(48) + mr_owner(48) +
    #                 mr_owner_config(48) + rtmr[4](192) + report_data(64) + tee_tcb_svn_2(16) + mr_service_td(48)
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
      b'\x00' * 48 +                     # rtmr[0]
      b'\x00' * 48 +                     # rtmr[1]
      b'\x00' * 48 +                     # rtmr[2]
      b'\x00' * 48 +                     # rtmr[3]
      b'\x00' * 64 +                     # report_data
      b'\x00' * 16 +                     # tee_tcb_svn_2
      b'\x00' * 48                       # mr_service_td
    )
    
    signature_len = struct.pack('<I', 0)
    
    data = header + body_descriptor + body + signature_len
    quote = QuoteV5(data)
    
    assert quote.parsed_data.body.body.xfam == max_uint64

  def test_rtmr_array_access(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    assert len(quote.parsed_data.body.body.rtmr) == 4
    assert quote.parsed_data.body.body.rtmr[0] == b'\x0d' * 48
    assert quote.parsed_data.body.body.rtmr[1] == b'\x0e' * 48
    assert quote.parsed_data.body.body.rtmr[2] == b'\x0f' * 48
    assert quote.parsed_data.body.body.rtmr[3] == b'\x10' * 48

  def test_v5_specific_fields(self, valid_v5_quote_data):
    quote = QuoteV5(valid_v5_quote_data)
    
    # v5 has tee_tcb_svn_2 and mr_service_td which v4 doesn't have
    assert quote.parsed_data.body.body.tee_tcb_svn_2 == b'\x12' * 16
    assert quote.parsed_data.body.body.mr_service_td == b'\x13' * 48
    
    # v5 has body descriptor which v4 doesn't have
    assert hasattr(quote.parsed_data, 'body')
    assert hasattr(quote.parsed_data.body, 'quote_body_type')
    assert hasattr(quote.parsed_data.body, 'size')

  def test_zero_signature_length(self):
    header = b'\x05\x00' + b'\x02\x00' + b'\x81\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 16 + b'\x00' * 20
    body_descriptor = b'\x00\x00' + struct.pack('<I', 648)
    body = b'\x00' * 648
    signature_len = struct.pack('<I', 0)
    
    data = header + body_descriptor + body + signature_len
    quote = QuoteV5(data)
    
    assert quote.parsed_data.quote_signature_data_len == 0
    assert quote.parsed_data.quote_signature_data == b''

class TestQuoteV5WithRealQuote:
  def read_real_quote(self):
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "reports", "td_quote_v5.dat")
    with open(file_path, "rb") as file:
      td_quote = file.read()

    return td_quote
  
  def test_real_quote_parsing(self):
    quote = QuoteV5(self.read_real_quote())

    # checking that the header matches expected values
    assert quote.parsed_data.header.version == 5
    assert quote.parsed_data.header.attestation_key_type == 2
    assert quote.parsed_data.header.tee_type == 129
    assert quote.parsed_data.header.reserved_1 == b'\x00\x00'
    assert quote.parsed_data.header.reserved_2 == b'\x00\x00'
    assert quote.parsed_data.header.qe_vendor_id == bytes.fromhex('939a7233f79c4ca9940a0db3957f0607')
    assert quote.parsed_data.header.user_data == bytes.fromhex('024bf66821177eaf36a4d13dda53b76700000000')

    # checking that the body descriptor matches expected values
    assert quote.parsed_data.body.quote_body_type == b'\x03\x00'
    assert quote.parsed_data.body.size == 648

    # checking that the body fields match expected values
    assert quote.parsed_data.body.body.tee_tcb_svn == bytes.fromhex('07010300000000000000000000000000')
    assert quote.parsed_data.body.body.mrseam == bytes.fromhex('49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6')
    assert quote.parsed_data.body.body.mrsignerseam == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.seam_attributes == bytes.fromhex('0000000000000000')
    assert quote.parsed_data.body.body.td_attributes == bytes.fromhex('0000001000000000')
    assert quote.parsed_data.body.body.xfam == 399591
    assert quote.parsed_data.body.body.mr_td == bytes.fromhex('273828c46252fcbdd8ad2dd907130222b03466d52a2911d70c1a5950895d6bd1ae451d382d5a9b1b4c0ed0e5ae9a3dbd')
    assert quote.parsed_data.body.body.mr_config_id == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.mr_owner == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.mr_owner_config == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.rtmr[0] == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.rtmr[1] == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.rtmr[2] == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.rtmr[3] == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.report_data == bytes.fromhex('9cb7f308432c91f9a968d5b335d2ed9c63e7ddccaf4f960a27b5bd306efb3d750000000000000000000000000000000000000000000000000000000000000000')
    assert quote.parsed_data.body.body.tee_tcb_svn_2 == bytes.fromhex('0d010400000000000000000000000000')
    assert quote.parsed_data.body.body.mr_service_td == bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

    # checking that the signature data length matches expected value
    assert quote.parsed_data.quote_signature_data_len == 4300


class TestQuoteV5String:
  def test_str_returns_string_not_prints(self, valid_v5_quote_data, capsys):
    quote = QuoteV5(valid_v5_quote_data)
    
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
    assert "Version: 5" in result
