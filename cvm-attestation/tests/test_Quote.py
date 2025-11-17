# test_Quote.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import struct
from src.Quote import Quote
from src.QuoteV4 import QuoteV4
from src.QuoteV5 import QuoteV5


class TestQuoteFactory:
  def test_from_bytes_creates_v4_quote(self):
    header = (
      b'\x04\x00' +                # version
      b'\x02\x00' +                # att_key_type
      b'\x81\x00\x00\x00' +        # tee_type
      b'\x00\x00' +                # reserved
      b'\x00\x00' +                # reserved
      b'\x00' * 16 +               # qe_svn, pce_svn, uuid, user_data, etc.
      b'\x00' * 20                 # more reserved/user data
    )
    body = b'\x00' * 584
    signature_data = b'\x00' * 64 + b'\x00' * 64 + b'\x00\x00' + struct.pack('<I', 0)
    signature_len = struct.pack('<I', len(signature_data))
    data = header + body + signature_len + signature_data
    
    quote = Quote.from_bytes(data)
    
    assert isinstance(quote, QuoteV4)
    assert quote.version == 4

  def test_from_bytes_creates_v5_quote(self):
    header = (
      b'\x05\x00' +                # version
      b'\x02\x00' +                # att_key_type
      b'\x81\x00\x00\x00' +        # tee_type
      b'\x00\x00' +                # reserved
      b'\x00\x00' +                # reserved
      b'\x00' * 16 +               # qe_svn, pce_svn, uuid, user_data, etc.
      b'\x00' * 20                 # more reserved/user data
    )
    body_descriptor = b'\x00\x00' + struct.pack('<I', 648)
    body = b'\x00' * 648
    signature_len = struct.pack('<I', 0)
    data = header + body_descriptor + body + signature_len
    
    quote = Quote.from_bytes(data)
    
    assert isinstance(quote, QuoteV5)
    assert quote.version == 5

  def test_from_bytes_with_empty_data_raises_error(self):
    with pytest.raises(ValueError) as excinfo:
      Quote.from_bytes(b'')
    
    assert "Data too short" in str(excinfo.value)

  def test_from_bytes_with_unsupported_version_raises_error(self):
    data = b'\x63\x00' + b'\x00' * 100
    
    with pytest.raises(ValueError) as excinfo:
      Quote.from_bytes(data)
    
    assert "Unsupported quote version: 99" in str(excinfo.value)

  def test_roundtrip_v4_quote(self):
    header = (
      b'\x04\x00' +                # version
      b'\x02\x00' +                # att_key_type
      b'\x81\x00\x00\x00' +        # tee_type
      b'\x00\x00' +                # reserved
      b'\x00\x00' +                # reserved
      b'\x01' * 16 +               # qe_svn, pce_svn, uuid, user_data, etc.
      b'\x02' * 20                 # more reserved/user data
    )
    body = b'\x03' * 584
    signature_data = b'\x04' * 64 + b'\x05' * 64 + b'\x06\x00' + struct.pack('<I', 10) + b'\x07' * 10
    signature_len = struct.pack('<I', len(signature_data))
    original_data = header + body + signature_len + signature_data
    
    quote1 = Quote.from_bytes(original_data)
    serialized = quote1.serialize()
    quote2 = Quote.from_bytes(serialized)
    
    assert quote1.version == quote2.version
    assert quote1.parsed_data.header.qe_vendor_id == quote2.parsed_data.header.qe_vendor_id

  def test_roundtrip_v5_quote(self):
    header = (
      b'\x05\x00' +                # version
      b'\x02\x00' +                # att_key_type
      b'\x81\x00\x00\x00' +        # tee_type
      b'\x00\x00' +                # reserved
      b'\x00\x00' +                # reserved
      b'\x01' * 16 +               # qe_svn, pce_svn, uuid, user_data, etc.
      b'\x02' * 20                 # more reserved/user data
    )
    body_descriptor = b'\x03\x00' + struct.pack('<I', 648)
    body = b'\x04' * 648
    signature_len = struct.pack('<I', 100)
    signature_data = b'\x05' * 100
    original_data = header + body_descriptor + body + signature_len + signature_data
    
    quote1 = Quote.from_bytes(original_data)
    serialized = quote1.serialize()
    quote2 = Quote.from_bytes(serialized)
    
    assert quote1.version == quote2.version
    assert quote1.parsed_data.header.qe_vendor_id == quote2.parsed_data.header.qe_vendor_id