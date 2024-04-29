# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from base64 import urlsafe_b64encode, b64encode
import json
import jwt
import click
from enum import Enum
from src.OsInfo import OsType
from src.Isolation import IsolationType
from tpm_wrapper import get_hcl_report
from src.verifier import verify_evidence
from src.Logger import Logger
from src.report_parser import *
from src.imds import get_vcek_certificate, get_td_quote
from src.AttestationProvider import MAAProvider, ITAProvider

# The version number of the attestation protocol between the client and the service.
PROTOCOL_VERSION = "2.0"

# List of PCR values for each OS Type
LINUX_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7]
WINDOWS_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14]


def base64url_encode(data):
  return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")


def base64_encode(data):
  base64_bytes = b64encode(data)
  # Return the base64url encoded string
  return base64_bytes.decode('utf-8')


# Function to encode a string to base64url
def base64_encode_string(input_string):
    # Convert string to bytes
    bytes_to_encode = input_string.encode('utf-8')
    # Perform base64 encoding
    base64_bytes = b64encode(bytes_to_encode)
    # Return the base64url encoded string
    return base64_bytes.decode('utf-8')

class GuestAttestationParameters:
  def __init__(self, os_info=None, tcg_logs=None, tpm_info=None, isolation=None):
    self.os_info = os_info
    self.tcg_logs = tcg_logs
    self.tpm_info = tpm_info
    self.isolation = isolation
  
  def toJson(self):
    return json.dumps({
      'AttestationProtocolVersion': PROTOCOL_VERSION,
      'OSType': base64_encode_string(str(self.os_info.type)),
      'OSDistro': base64_encode_string(self.os_info.distro_name),
      'OSVersionMajor': str(self.os_info.major_version),
      'OSVersionMinor': str(self.os_info.minor_version),
      'OSBuild': base64_encode_string(self.os_info.build),
      'TcgLogs': base64_encode(self.tcg_logs),
      'ClientPayload': base64_encode_string(""),
      'TpmInfo': self.tpm_info.get_values(),
      'IsolationInfo': self.isolation.get_values()
    })


class PlatformAttestationParameters:
  def __init__(self, hardware_report, runtime_data):
    self.hardware_report = hardware_report
    self.runtime_data = runtime_data


class Verifier(Enum):
  UNDEFINED = 0 # Undefined type
  MAA = 1       # Microsoft Attestation Service
  ITA = 2       # Intel Trusted Authority


class AttestationClientParameters:
  def __init__(self, endpoint: str, verifier: Verifier, isolation_type: IsolationType, claims = None, api_key = None):
    # Validate the isolation type
    if not isinstance(isolation_type, IsolationType):
      raise ValueError(f"Unsupported isolation type: {isolation_type}. Supported types: {list(IsolationType)}")
    
     # Validate the verifier
    if not isinstance(verifier, Verifier):
      raise ValueError(f"Unsupported isolation type: {verifier}. Supported types: {list(Verifier)}")

    self.endpoint = endpoint
    self.verifier = verifier
    self.api_key = api_key
    self.isolation_type = isolation_type
    self.user_claims = claims


class AttestationClient:
  def __init__(self, logger: Logger, parameters: AttestationClientParameters):
    verifier = parameters.verifier
    isolation_type = parameters.isolation_type
    endpoint = parameters.endpoint
    api_key = parameters.api_key

    self.parameters = parameters
    self.logger = logger

    self.provider = MAAProvider(logger,isolation_type,endpoint) if verifier == Verifier.MAA else ITAProvider(logger,isolation_type,endpoint, api_key) if verifier == Verifier.ITA else None
  
  def guest_attest():
    return True

  def attest_platform(self):
    self.logger.info('Attesting Platform Evidence...')

    isolation_type = self.parameters.isolation_type 

    # Extract Hardware Report and Runtime Data
    hcl_report = get_hcl_report(self.parameters.user_claims)
    report_type = extract_report_type(hcl_report)
    runtime_data = extract_runtime_data(hcl_report)
    hw_report = extract_hw_report(hcl_report)

    # Set request data based on the platform
    encoded_report = base64url_encode(hw_report)
    encoded_runtime_data = base64url_encode(runtime_data)
    encoded_token = ""
    encoded_hw_evidence = ""
    if report_type == 'tdx' and isolation_type == IsolationType.TDX:
      encoded_hw_evidence = get_td_quote(encoded_report)
    elif report_type == 'snp' and isolation_type == IsolationType.SEV_SNP:
      cert_chain = get_vcek_certificate()
      snp_report = {
        'SnpReport': encoded_report,
        'VcekCertChain': base64url_encode(cert_chain)
      }
      snp_report = json.dumps(snp_report)
      snp_report = bytearray(snp_report.encode('utf-8'))
      encoded_hw_evidence = base64url_encode(snp_report)
    else:
      self.logger.info('Invalid Hardware Report Type')

    # verify hardware evidence
    encoded_token = self.provider.attest_platform(encoded_hw_evidence, encoded_runtime_data)
    return encoded_token