# snp_utils.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from src.encoder import Encoder


class SnpFormatter:
  """
  Formats SEV-SNP hardware evidence.
  """

  @staticmethod
  def format_snp_evidence(snp_report: bytes, vcek_cert_chain: bytes) -> str:
    """
    Returns the SNP report and VCEK certificate chain as base64url encoded JSON:
    {"SnpReport": "<base64url>", "VcekCertChain": "<base64url>"}
    """
    hardware_evidence = {
      'SnpReport': Encoder.base64url_encode(snp_report),
      'VcekCertChain': Encoder.base64url_encode(vcek_cert_chain)
    }
    hardware_evidence = json.dumps(hardware_evidence)
    hardware_evidence = bytearray(hardware_evidence.encode('utf-8'))
    return Encoder.base64url_encode(hardware_evidence)
