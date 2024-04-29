# Isolation.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from enum import Enum
import tpm_wrapper
from base64 import urlsafe_b64encode

def base64url_encode(data):
  return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")


class IsolationType(Enum):
  UNDEFINED = 0
  TRUSTED_LAUNCH = 1
  SEV_SNP = 2
  TDX = 3


class IsolationInfo:
  def __init__(self, isolation_type=IsolationType.UNDEFINED, snp_report=b'', runtime_data=b'', vcek_cert=""):
    self.isolation_type = isolation_type
    self.snp_report = snp_report
    self.runtime_data = runtime_data
    self.vcek_cert = vcek_cert

  def validate(self):
    # Add your validation logic here
    pass

  def get_values(self):
    type = ""
    isolation = {}
    if self.isolation_type == IsolationType.SEV_SNP:
      type = "SevSnp"

      hardware_evidence = {
        'SnpReport': base64url_encode(self.snp_report),
        'VcekCertChain': base64url_encode(self.vcek_cert)
      }
      hardware_evidence = json.dumps(hardware_evidence)
      hardware_evidence = bytearray(hardware_evidence.encode('utf-8'))
      encoded_hw_evidence = base64url_encode(hardware_evidence)

      isolation = {
        "Type": type,
        "Evidence": {
          "Proof": encoded_hw_evidence,
          "RunTimeData": base64url_encode(self.runtime_data),
        }
      }

      return isolation
