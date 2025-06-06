# deserialize_tdx_v5.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from construct import Struct, Int16ul, Int32ul, Int64ul, Bytes, Array, this

def deserialize_td_quotev5(tq_quote):
    """
    Parses the given TD quote object and returns the structured data.
    """
    TDQuoteHeaderv5 = Struct(
        "version" / Int16ul,
        "attestation_key_type" / Int16ul,
        "tee_type" / Int32ul,
        "reserved_1" / Bytes(2),
        "reserved_2" / Bytes(2),
        "qe_vendor_id" / Bytes(16),
        "user_data" / Bytes(20)
    )
    

    TDQuoteBodyv5 = Struct(
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

    TDQuoteBodyDescriptorv5 = Struct(
        "quote_body_type" / Bytes(2),
        "size" / Int32ul,
        "body" / TDQuoteBodyv5
    )
    
    TDQuotev5 = Struct(
        "header" / TDQuoteHeaderv5,
        "body" / TDQuoteBodyDescriptorv5,
        "quote_signature_data_len" / Int32ul,
        "quote_signature_data" / Bytes(this.quote_signature_data_len)
    )
    
    try:
        return TDQuotev5.parse(tq_quote)
    except Exception as e:
        print(f"Error parsing TD Quote: {e}", file=sys.stderr)
        return None

def print_td_quotev5(parsed_quote):
    """
    Prints the parsed TD quote data in a structured format.
    """
    print("TD Quote Header:")
    print(f"  Version: {parsed_quote.header.version}")
    print(f"  Attestation Key Type: {parsed_quote.header.attestation_key_type}")
    print(f"  TEE Type: {parsed_quote.header.tee_type}")
    print(f"  Reserved 1: {parsed_quote.header.reserved_1.hex()}")
    print(f"  Reserved 2: {parsed_quote.header.reserved_2.hex()}")
    print(f"  QE Vendor ID: {parsed_quote.header.qe_vendor_id.hex()}")
    print(f"  User Data: {parsed_quote.header.user_data.hex()}")
    
    print("\nTD Quote Body Descriptor:")
    print(f"  Quote Body Type: {parsed_quote.body.quote_body_type.hex()}")
    print(f"  Size: {parsed_quote.body.size}")
    
    print("\nTD Quote Body:")
    print(f"  TEE TCB SVN: {parsed_quote.body.body.tee_tcb_svn.hex()}")
    print(f"  MRSEAM: {parsed_quote.body.body.mrseam.hex()}")
    print(f"  MRSIGNERSEAM: {parsed_quote.body.body.mrsignerseam.hex()}")
    print(f"  SEAM ATTRIBUTES: {parsed_quote.body.body.seam_attributes.hex()}")
    print(f"  TD ATTRIBUTES: {parsed_quote.body.body.td_attributes.hex()}")
    print(f"  XFAM: {parsed_quote.body.body.xfam}")
    print(f"  MR TD: {parsed_quote.body.body.mr_td.hex()}")
    print(f"  MR CONFIG ID: {parsed_quote.body.body.mr_config_id.hex()}")
    print(f"  MR OWNER: {parsed_quote.body.body.mr_owner.hex()}")
    print(f"  MR OWNER CONFIG: {parsed_quote.body.body.mr_owner_config.hex()}")
    for i, rtmr in enumerate(parsed_quote.body.body.rtmr):
        print(f"  RTMR[{i}]: {rtmr.hex()}")
    print(f"  REPORT DATA: {parsed_quote.body.body.report_data.hex()}")
    print(f"  TEE TCB SVN 2: {parsed_quote.body.body.tee_tcb_svn_2.hex()}")
    print(f"  MR SERVICE TD: {parsed_quote.body.body.mr_service_td.hex()}")
    
    print("\nQuote Signature Data:")
    print(f"  Length: {parsed_quote.quote_signature_data_len}")
    print(f"  Data: {parsed_quote.quote_signature_data.hex()}")