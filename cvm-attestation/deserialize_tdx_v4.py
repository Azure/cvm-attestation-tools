# deserialize_tdx_v4.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
from construct import Struct, Int16ul, Int32ul, Int64ul, Bytes, Array, this
import sys


def deserialize_td_quotev4(tq_quote):
    """
    Parses the given TD quote object and returns the structured data.
    :param tq_quote: The TD quote binary data.
    :return: Parsed TD Quote structure.
    """
    
    QuoteHeaderv4 = Struct(
        "version" / Int16ul,
        "attestation_key_type" / Int16ul,
        "tee_type" / Bytes(4),
        "reserved_0" / Int16ul,
        "reserved_1" / Int16ul,
        "qe_vendor_id" / Bytes(16),
        "user_data" / Bytes(20)
    )

    TDQuoteBodyv4 = Struct(
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

    QuoteSignatureDatav4 = Struct(
        "signature" / Bytes(64),
        "attestation_key" / Bytes(64),
        "qe_certification_data_type" / Bytes(2),
        "cert_data_size" / Int32ul,
        "cert_data" / Bytes(this.cert_data_size)
    )

    TDQuote_V4 = Struct(
    "header" / QuoteHeaderv4,
    "td_quote_body" / TDQuoteBodyv4,
    "quote_signature_data_len" / Int32ul,
    "quote_signature_data" / QuoteSignatureDatav4,
    )

    try:
        return TDQuote_V4.parse(tq_quote)
    except Exception as e:
        print(f"Error parsing TD Quote: {e}", file=sys.stderr)
        return None

def print_td_quotev4(parsed_quote):
  print("Quote Header:")
  print(f"  Version: {parsed_quote.header.version}")
  print(f"  Attestation Key Type: {parsed_quote.header.attestation_key_type}")
  print(f"  TEE Type: {parsed_quote.header.tee_type.hex()}")
  print(f"  QE Vendor ID: {parsed_quote.header.qe_vendor_id.hex()}")
  print(f"  User Data: {parsed_quote.header.user_data.hex()}")

  print("\nTD Quote Body:")
  print(f"  TEE TCB SVN: {parsed_quote.td_quote_body.tee_tcb_svn.hex()}")
  print(f"  MR SEAM: {parsed_quote.td_quote_body.mrseam.hex()}")
  print(f"  MR SIGNER SEAM: {parsed_quote.td_quote_body.mrsignerseam.hex()}")
  print(f"  SEAM ATTRIBUTES: {parsed_quote.td_quote_body.seam_attributes.hex()}")
  print(f"  TD ATTRIBUTES: {parsed_quote.td_quote_body.td_attributes.hex()}")
  print(f"  XFAM: {parsed_quote.td_quote_body.xfam}")
  print(f"  MR TD: {parsed_quote.td_quote_body.mr_td.hex()}")
  print(f"  MR CONFIG ID: {parsed_quote.td_quote_body.mr_config_id.hex()}")
  print(f"  MR OWNER: {parsed_quote.td_quote_body.mr_owner.hex()}")
  print(f"  MR OWNER CONFIG: {parsed_quote.td_quote_body.mr_owner_config.hex()}")
  print(f"  RTMR[0]: {parsed_quote.td_quote_body.rtmr_0.hex()}")
  print(f"  RTMR[1]: {parsed_quote.td_quote_body.rtmr_1.hex()}")
  print(f"  RTMR[2]: {parsed_quote.td_quote_body.rtmr_2.hex()}")
  print(f"  RTMR[3]: {parsed_quote.td_quote_body.rtmr_3.hex()}")
  print(f"  REPORT DATA: {parsed_quote.td_quote_body.report_data.hex()}")

  print("\nQuote Signature Data:")
  print(f"  Signature: {parsed_quote.quote_signature_data.signature.hex()}")
  print(f"  Attestation Key: {parsed_quote.quote_signature_data.attestation_key.hex()}")
  print(f"  Cert Data Size: {parsed_quote.quote_signature_data.cert_data_size}")