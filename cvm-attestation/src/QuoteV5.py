# QuoteV5.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import sys
from src.Quote import Quote
from construct import Struct, Int16ul, Int32ul, Int64ul, Bytes, Array, this


class QuoteV5(Quote):
  """TD Quote Version 5 implementation."""
  
  # Class-level struct definitions that can be used by all methods
  HEADER_STRUCT = Struct(
    "version" / Int16ul,
    "attestation_key_type" / Int16ul,
    "tee_type" / Int32ul,
    "reserved_1" / Bytes(2),
    "reserved_2" / Bytes(2),
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
    "rtmr" / Array(4, Bytes(48)),
    "report_data" / Bytes(64),
    "tee_tcb_svn_2" / Bytes(16),
    "mr_service_td" / Bytes(48)
  )

  BODY_DESCRIPTOR_STRUCT = Struct(
    "quote_body_type" / Bytes(2),
    "size" / Int32ul,
    "body" / BODY_STRUCT
  )
  
  QUOTE_STRUCT = Struct(
    "header" / HEADER_STRUCT,
    "body" / BODY_DESCRIPTOR_STRUCT,
    "quote_signature_data_len" / Int32ul,
    "quote_signature_data" / Bytes(this.quote_signature_data_len)
  )
  
  def __init__(self, data: bytes):
    """
    Initialize QuoteV5 with raw binary data.
    :param data: Raw binary quote data
    """
    super().__init__()
    self.deserialize(data)
  
  @property
  def version(self) -> int:
    """Return the quote version number from parsed data."""
    if self.parsed_data and hasattr(self.parsed_data, 'header'):
      return self.parsed_data.header.version
    return 5  # Default for v5 if not yet parsed
  
  def deserialize(self, data: bytes) -> None:
    """
    Parse the raw quote data using v5 structure definitions.
    :param data: Raw binary quote data
    """
    try:
      self.parsed_data = self.QUOTE_STRUCT.parse(data)
    except Exception as e:
      print(f"Error parsing TD Quote v5: {e}", file=sys.stderr)
      raise ValueError(f"Failed to parse TD Quote v5: {e}")
  
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
      print(f"Error serializing TD Quote v5: {e}", file=sys.stderr)
      raise ValueError(f"Failed to serialize TD Quote v5: {e}")
  
  def __str__(self) -> str:
    """
    String representation of the quote for printing.
    :return: Formatted string with quote details
    """
    if self.parsed_data is None:
      return "No parsed data available."
    
    lines = []
    lines.append("TD Quote Header:")
    lines.append(f"  Version: {self.parsed_data.header.version}")
    lines.append(f"  Attestation Key Type: {self.parsed_data.header.attestation_key_type}")
    lines.append(f"  TEE Type: {self.parsed_data.header.tee_type}")
    lines.append(f"  Reserved 1: {self.parsed_data.header.reserved_1.hex()}")
    lines.append(f"  Reserved 2: {self.parsed_data.header.reserved_2.hex()}")
    lines.append(f"  QE Vendor ID: {self.parsed_data.header.qe_vendor_id.hex()}")
    lines.append(f"  User Data: {self.parsed_data.header.user_data.hex()}")
    
    lines.append("\nTD Quote Body Descriptor:")
    lines.append(f"  Quote Body Type: {self.parsed_data.body.quote_body_type.hex()}")
    lines.append(f"  Size: {self.parsed_data.body.size}")
    
    lines.append("\nTD Quote Body:")
    lines.append(f"  TEE TCB SVN: {self.parsed_data.body.body.tee_tcb_svn.hex()}")
    lines.append(f"  MRSEAM: {self.parsed_data.body.body.mrseam.hex()}")
    lines.append(f"  MRSIGNERSEAM: {self.parsed_data.body.body.mrsignerseam.hex()}")
    lines.append(f"  SEAM ATTRIBUTES: {self.parsed_data.body.body.seam_attributes.hex()}")
    lines.append(f"  TD ATTRIBUTES: {self.parsed_data.body.body.td_attributes.hex()}")
    lines.append(f"  XFAM: {self.parsed_data.body.body.xfam}")
    lines.append(f"  MR TD: {self.parsed_data.body.body.mr_td.hex()}")
    lines.append(f"  MR CONFIG ID: {self.parsed_data.body.body.mr_config_id.hex()}")
    lines.append(f"  MR OWNER: {self.parsed_data.body.body.mr_owner.hex()}")
    lines.append(f"  MR OWNER CONFIG: {self.parsed_data.body.body.mr_owner_config.hex()}")
    for i, rtmr in enumerate(self.parsed_data.body.body.rtmr):
      lines.append(f"  RTMR[{i}]: {rtmr.hex()}")
    lines.append(f"  REPORT DATA: {self.parsed_data.body.body.report_data.hex()}")
    lines.append(f"  TEE TCB SVN 2: {self.parsed_data.body.body.tee_tcb_svn_2.hex()}")
    lines.append(f"  MR SERVICE TD: {self.parsed_data.body.body.mr_service_td.hex()}")
    
    lines.append("\nQuote Signature Data:")
    lines.append(f"  Length: {self.parsed_data.quote_signature_data_len}")
    lines.append(f"  Data: {self.parsed_data.quote_signature_data.hex()}")
    
    return "\n".join(lines)

  def get_header(self):
    """Return the parsed header."""
    return self.parsed_data.header if self.parsed_data else None

  def get_body(self):
    """Return the parsed quote body."""
    return self.parsed_data.body.body if self.parsed_data else None

  def get_body_descriptor(self):
    """Return the parsed body descriptor."""
    return self.parsed_data.body if self.parsed_data else None

  def get_signature_data(self):
    """Return the parsed signature data."""
    return self.parsed_data.quote_signature_data if self.parsed_data else None
