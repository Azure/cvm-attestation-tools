# QuoteV4.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import sys
from src.Quote import Quote
from construct import Struct, Int16ul, Int32ul, Int64ul, Bytes, this


class QuoteV4(Quote):
  """TD Quote Version 4 implementation."""
  
	# Class-level struct definitions
  HEADER_STRUCT = Struct(
    "version" / Int16ul,
    "attestation_key_type" / Int16ul,
    "tee_type" / Bytes(4),
    "reserved_0" / Int16ul,
    "reserved_1" / Int16ul,
    "qe_vendor_id" / Bytes(16),
    "user_data" / Bytes(20)
  )

  BODY_STRUCT = Struct(
    "tee_tcb_svn" / Bytes(16),
    "mrseam" / Bytes(48),
    "mrsignerseam" / Bytes(48),
    "seam_attributes" / Bytes(8),
    "td_attributes" / Bytes(8),
    "xfam" / Int64ul,
    "mr_td" / Bytes(48),
    "mr_config_id" / Bytes(48),
    "mr_owner" / Bytes(48),
    "mr_owner_config" / Bytes(48),
    "rtmr_0" / Bytes(48),
    "rtmr_1" / Bytes(48),
    "rtmr_2" / Bytes(48),
    "rtmr_3" / Bytes(48),
    "report_data" / Bytes(64)
  )

  SIGNATURE_STRUCT = Struct(
    "signature" / Bytes(64),
    "attestation_key" / Bytes(64),
    "qe_certification_data_type" / Bytes(2),
    "cert_data_size" / Int32ul,
    "cert_data" / Bytes(this.cert_data_size)
  )

  QUOTE_STRUCT = Struct(
    "header" / HEADER_STRUCT,
    "td_quote_body" / BODY_STRUCT,
    "quote_signature_data_len" / Int32ul,
    "quote_signature_data" / SIGNATURE_STRUCT,
  )
  
  def __init__(self, data: bytes):
    """
    Initialize QuoteV4 with raw binary data.
    :param data: Raw binary quote data
    """
    super().__init__()
    self.deserialize(data)

  @property
  def version(self) -> int:
    """Return the quote version number from parsed data."""
    if self.parsed_data and hasattr(self.parsed_data, 'header'):
      return self.parsed_data.header.version
    return 4  # Default for v4 if not yet parsed

  def deserialize(self, data: bytes) -> None:
    """
    Parse the raw quote data using v4 structure definitions.
    :param data: Raw binary quote data
    """

    try:
      self.parsed_data = self.QUOTE_STRUCT.parse(data)
    except Exception as e:
      print(f"Error parsing TD Quote v4: {e}", file=sys.stderr)
      raise ValueError(f"Failed to parse TD Quote v4: {e}")

  def serialize(self) -> bytes:
    """
    Serialize the Quote object back to binary format.
    :return: Raw binary quote data
    """
    if self.parsed_data is None:
      raise ValueError("Cannot serialize: No parsed data available")

    try:
      return self.QUOTE_STRUCT.build(self.parsed_data)
    except Exception as e:
      print(f"Error serializing TD Quote v4: {e}", file=sys.stderr)
      raise ValueError(f"Failed to serialize TD Quote v4: {e}")

  def __str__(self) -> str:
    """
    String representation of the quote for printing.
    :return: Formatted string with quote details
    """
    if self.parsed_data is None:
      return "No parsed data available."
    
    lines = []
    lines.append("Quote Header:")
    lines.append(f"  Version: {self.parsed_data.header.version}")
    lines.append(f"  Attestation Key Type: {self.parsed_data.header.attestation_key_type}")
    lines.append(f"  TEE Type: {self.parsed_data.header.tee_type.hex()}")
    lines.append(f"  QE Vendor ID: {self.parsed_data.header.qe_vendor_id.hex()}")
    lines.append(f"  User Data: {self.parsed_data.header.user_data.hex()}")

    lines.append("\nTD Quote Body:")
    lines.append(f"  TEE TCB SVN: {self.parsed_data.td_quote_body.tee_tcb_svn.hex()}")
    lines.append(f"  MR SEAM: {self.parsed_data.td_quote_body.mrseam.hex()}")
    lines.append(f"  MR SIGNER SEAM: {self.parsed_data.td_quote_body.mrsignerseam.hex()}")
    lines.append(f"  SEAM ATTRIBUTES: {self.parsed_data.td_quote_body.seam_attributes.hex()}")
    lines.append(f"  TD ATTRIBUTES: {self.parsed_data.td_quote_body.td_attributes.hex()}")
    lines.append(f"  XFAM: {self.parsed_data.td_quote_body.xfam}")
    lines.append(f"  MR TD: {self.parsed_data.td_quote_body.mr_td.hex()}")
    lines.append(f"  MR CONFIG ID: {self.parsed_data.td_quote_body.mr_config_id.hex()}")
    lines.append(f"  MR OWNER: {self.parsed_data.td_quote_body.mr_owner.hex()}")
    lines.append(f"  MR OWNER CONFIG: {self.parsed_data.td_quote_body.mr_owner_config.hex()}")
    lines.append(f"  RTMR[0]: {self.parsed_data.td_quote_body.rtmr_0.hex()}")
    lines.append(f"  RTMR[1]: {self.parsed_data.td_quote_body.rtmr_1.hex()}")
    lines.append(f"  RTMR[2]: {self.parsed_data.td_quote_body.rtmr_2.hex()}")
    lines.append(f"  RTMR[3]: {self.parsed_data.td_quote_body.rtmr_3.hex()}")
    lines.append(f"  REPORT DATA: {self.parsed_data.td_quote_body.report_data.hex()}")

    lines.append("\nQuote Signature Data:")
    lines.append(f"  Signature: {self.parsed_data.quote_signature_data.signature.hex()}")
    lines.append(f"  Attestation Key: {self.parsed_data.quote_signature_data.attestation_key.hex()}")
    lines.append(f"  Cert Data Size: {self.parsed_data.quote_signature_data.cert_data_size}")
    
    return "\n".join(lines)

  def get_header(self):
    """Return the parsed header."""
    return self.parsed_data.header if self.parsed_data else None

  def get_body(self):
    """Return the parsed quote body."""
    return self.parsed_data.td_quote_body if self.parsed_data else None
  
  def get_signature_data(self):
    """Return the parsed signature data."""
    return self.parsed_data.quote_signature_data if self.parsed_data else None
