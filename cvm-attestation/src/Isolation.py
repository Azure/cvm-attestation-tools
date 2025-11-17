# Isolation.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from enum import Enum
import tpm_wrapper
from src.Encoder import Encoder


class IsolationType(Enum):
  UNDEFINED = 0
  VBS = 1
  SEV_SNP = 2
  TRUSTED_LAUNCH = 3
  TDX = 4


class Evidence:
  def validate(self):
    raise NotImplementedError("Subclasses must implement validate method")

  def get_evidence(self):
    raise NotImplementedError("Subclasses must implement get_evidence method")


class SnpEvidence(Evidence):
  def __init__(self, snp_report=b'', runtime_data=b'', vcek_cert=b""):
    self.snp_report = snp_report
    self.runtime_data = runtime_data
    self.vcek_cert = vcek_cert

  def validate(self):
    # Add validation logic
    pass

  def get_evidence(self):
    hardware_evidence = {
      'SnpReport': Encoder.base64url_encode(self.snp_report),
      'VcekCertChain': Encoder.base64url_encode(self.vcek_cert)
    }
    hardware_evidence = json.dumps(hardware_evidence)
    hardware_evidence = bytearray(hardware_evidence.encode('utf-8'))
    encoded_hw_evidence = Encoder.base64url_encode(hardware_evidence)

    return {
      "Type": "SevSnp",
      "Evidence": {
        "Proof": encoded_hw_evidence,
        "RunTimeData": Encoder.base64url_encode(self.runtime_data),
      }
    }


class TdxEvidence(Evidence):
  def __init__(self, encoded_hw_evidence=b'', runtime_data=b''):
    self.encoded_hw_evidence = encoded_hw_evidence
    self.runtime_data = runtime_data


  def validate(self):
    # Add validation logic
    pass


  def get_evidence(self):
    return {
      "Type": "Tdx",
      "Evidence": {
        "Proof": Encoder.base64_encode(self.encoded_hw_evidence),
        "RunTimeData": Encoder.base64_encode(self.runtime_data),
      }
    }


class Isolation:
  def __init__(self, isolation_type=IsolationType.UNDEFINED, evidence: Evidence = None):
    self.isolation_type = isolation_type
    self.evidence = evidence

  def validate(self):
    if self.evidence:
      self.evidence.validate()

  def get_values(self):
    if self.evidence:
      return self.evidence.get_evidence()
    return {"Type": "Undefined", "Evidence": {}}
