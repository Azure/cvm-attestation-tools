# attestation_client.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
from base64 import urlsafe_b64decode
from src.snp import AttestationReport
from src.os_info import OsInfo
from src.isolation import IsolationType, Isolation, TdxEvidence, SnpEvidence, TrustedLaunchEvidence
from src.logger import Logger
from src.report_parser import ReportParser
from src.imds_client import ImdsClient
from src.attestation_provider import MAAProvider, ITAProvider, validate_max_retries
from src.attestation_types import TpmInfo
from src.measurements import get_measurements
from src.encoder import Encoder
from src.tpm_wrapper import TssWrapper
from src.snp_utils import SnpFormatter
from src.claims import validate_claims, claims_to_client_payload
from requests.exceptions import RequestException

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# The version number of the attestation protocol between the client and the service.
PROTOCOL_VERSION = "2.0"


class GuestAttestationParameters:
  def __init__(self, os_info=None, tcg_logs=None, tpm_info=None, isolation=None, user_claims = None):
    self.os_info = os_info
    self.tcg_logs = tcg_logs
    self.tpm_info = tpm_info
    self.isolation = isolation
    self.user_claims = user_claims
  
  def toJson(self):
    return json.dumps({
      'AttestationProtocolVersion': PROTOCOL_VERSION,
      'OSType': Encoder.base64_encode_string(str(self.os_info.type)),
      'OSDistro': Encoder.base64_encode_string(self.os_info.distro_name),
      'OSVersionMajor': str(self.os_info.major_version),
      'OSVersionMinor': str(self.os_info.minor_version),
      'OSBuild': Encoder.base64_encode_string(self.os_info.build),
      'TcgLogs': Encoder.base64_encode(self.tcg_logs),
      'ClientPayload': self.user_claims if self.user_claims else {},
      'TpmInfo': self.tpm_info.get_values(),
      'IsolationInfo': self.isolation.get_values()
    })


class HardwareEvidence:
  """
  A class to represent hardware evidence.

  Attributes
  ----------
  hardware_report : bytes
    The hardware report.
  runtime_data : bytes
    The runtime data.
  """

  def __init__(self, report_type: IsolationType, hardware_report: bytes, runtime_data: bytes):
    if not isinstance(report_type, IsolationType):
      raise TypeError(f"Expected IsolationType for report_type, got {type(report_type).__name__}")
    if not isinstance(hardware_report, bytes):
      raise TypeError(f"Expected bytes for hardware_report, got {type(hardware_report).__name__}")
    if not isinstance(runtime_data, bytes):
      raise TypeError(f"Expected bytes for runtime_data, got {type(runtime_data).__name__}")

    self.type = report_type
    self.hardware_report = hardware_report
    self.runtime_data = runtime_data


@dataclass(frozen=True, kw_only=True)
class AttestationResult:
  """
  The outcome of an attestation request. New fields are added with defaults,
  so code that reads existing fields keeps working.

  Attributes
  ----------
  token : str | bytes | None
    The token from the attestation provider (the value attest_guest() or
    attest_platform() returns), or None if no token was received.
  evidence : dict | None
    The evidence sent to the attestation provider on the last attempt, or None
    if no evidence was collected.
  """
  token: Optional[Union[str, bytes]]
  evidence: Optional[dict]


class _GuestEvidence:
  """
  Guest evidence together with the ephemeral TPM key that the attestation
  provider uses to encrypt its response. The key must be used to decrypt the
  response or released.
  """

  def __init__(self, tss_wrapper, pcr_list, key_handle, tpm):
    self.tss_wrapper = tss_wrapper
    self.pcr_list = pcr_list
    self.key_handle = key_handle
    self.tpm = tpm
    self.attestation_info = None
    self.evidence = None
    self._released = False

  def decrypt(self, encrypted_data):
    # decrypt_with_ephemeral_key closes the TPM connection
    self._released = True
    return self.tss_wrapper.decrypt_with_ephemeral_key(
      encrypted_data, self.pcr_list, self.key_handle, self.tpm)

  def release(self):
    if not self._released:
      self._released = True
      self.tss_wrapper.release_ephemeral_key(self.key_handle, self.tpm)


class Verifier(Enum):
  UNDEFINED = 0 # Undefined type
  MAA = 1       # Microsoft Attestation Service
  ITA = 2       # Intel Trusted Authority


class AttestationClientParameters:
  def __init__(self, endpoint: str, verifier: Verifier, isolation_type: IsolationType, claims = None, api_key = None, max_retries: int = 5):
    """
    Parameters
    ----------
    claims
      Optional user claims. Either a JSON-serializable value (typically a dict),
      whose json.dumps() output is bound into the hardware report, or
      bytes/bytearray holding UTF-8 encoded JSON, which are bound exactly as given.
    max_retries
      Maximum number of attempts (1 means no retries). Applies to collecting and
      submitting evidence, and to each MAA request.
    """
    # Validate the isolation type
    if not isinstance(isolation_type, IsolationType):
      raise ValueError(f"Unsupported isolation type: {isolation_type}. Supported types: {list(IsolationType)}")
    
     # Validate the verifier
    if not isinstance(verifier, Verifier):
      raise ValueError(f"Unsupported verifier type: {verifier}. Supported types: {list(Verifier)}")

    validate_claims(claims)
    validate_max_retries(max_retries)

    self.endpoint = endpoint
    self.verifier = verifier
    self.api_key = api_key
    self.isolation_type = isolation_type
    self.user_claims = claims
    self.max_retries = max_retries

class UnsupportedReportTypeException(Exception):
  pass


class AttestationClient():
  def __init__(self, logger: Logger, parameters: AttestationClientParameters):
    verifier = parameters.verifier
    endpoint = parameters.endpoint
    api_key = parameters.api_key

    self.parameters = parameters
    self.log = logger

    if verifier == Verifier.MAA:
      self.provider = MAAProvider(logger, parameters.isolation_type, endpoint, parameters.max_retries)
    elif verifier == Verifier.ITA:
      self.provider = ITAProvider(logger, parameters.isolation_type, endpoint, api_key)
    else:
      self.provider = None

  def get_hardware_evidence(self) -> HardwareEvidence:
    """
    Returns an instance of the HardwareEvidence class.

    Returns
    -------
    HardwareEvidence
      The current instance of the HardwareEvidence class.
    """

    try:
      self.log.info('Collecting hardware evidence...')

      # Extract Hardware Report and Runtime Data
      tss_wrapper = TssWrapper(self.log)
      hcl_report = tss_wrapper.get_hcl_report(self.parameters.user_claims)
      report_type = ReportParser.extract_report_type(hcl_report)
      hw_report = ReportParser.extract_hw_report(hcl_report)
      runtime_data = ReportParser.extract_runtimes_data(hcl_report)

      if report_type == IsolationType.SEV_SNP:
        self.log_snp_report(hw_report)
      elif report_type == IsolationType.TDX:
        self.log.info("Fetching td quote...")

        # Logs important TDX fields from the hardware report
        imds_client = ImdsClient(self.log)
        encoded_report = Encoder.base64url_encode(hw_report)
        encoded_hw_evidence = imds_client.get_td_quote(encoded_report)
        hw_report = Encoder.base64url_decode(encoded_hw_evidence)

        self.log.info("Finished fetching td quote")

        self.log.info("Hardware report parsing for TDX not supported yet")
      else:
        raise UnsupportedReportTypeException(f"Unsupported report type: {report_type}")

      return HardwareEvidence(report_type, hw_report, runtime_data)
    except Exception as e:
      self.log.error(f"Error while reading hardware report. Exception {e}")

  def collect_platform_evidence(self):
    """
    Collects platform (hardware) evidence without sending it to the attestation provider.

    Returns
    -------
    dict
      The platform evidence: hw_evidence, runtime_data and report_type.
    """
    self.log.info('Collecting Platform Evidence...')
    return self._collect_platform_evidence()

  def collect_guest_evidence(self):
    """
    Collects guest evidence without sending it to the attestation provider.

    Returns
    -------
    dict
      The guest evidence: attestation_info, and platform_evidence for SEV-SNP
      and TDX (None for Trusted Launch).
    """
    self.log.info('Collecting Guest Evidence...')
    guest_evidence = self._collect_guest_evidence()
    guest_evidence.release()
    return guest_evidence.evidence

  def attest_guest(self):
    """
    Attest the Hardware and Guest

    Returns the token, or None if no token was received.
    """
    return self.attest_guest_detailed().token

  def attest_platform(self):
    """
    Attest the Hardware

    Returns the token, or None if no token was received.
    """
    return self.attest_platform_detailed().token

  def attest_guest_detailed(self) -> AttestationResult:
    """
    Attest the Hardware and Guest

    Returns
    -------
    AttestationResult
      The token (None if no token was received) and the guest evidence that was sent.
    """
    evidence = None
    retries = 0
    backoff_factor = 1
    while retries < self.parameters.max_retries:
      try:
        self.log.info('Attesting Guest Evidence...')
        guest_evidence = self._collect_guest_evidence()
        evidence = guest_evidence.evidence
        try:
          request = {
            "AttestationInfo": Encoder.base64url_encode_string(guest_evidence.attestation_info)
          }
          self.log.info('Sending guest attestation request to provider...')
          self.log.debug(f'Request object (full): {request}')

          encoded_response = self.provider.attest_guest(request)
          if encoded_response:
            token = self._decrypt_guest_response(encoded_response, guest_evidence)
            return AttestationResult(token=token, evidence=evidence)

          self.log.error("Token was not received from attestation provider")
        finally:
          guest_evidence.release()
      except RequestException as e:
        self.log.error(f"Request to attest guest failed with an exception: {e}")

      retries += 1
      if retries < self.parameters.max_retries:
        sleep_time = backoff_factor * (2 ** (retries - 1))
        self.log.info(f"Retrying in {sleep_time} seconds...")
        time.sleep(sleep_time)

    self.log.error("Attestation failed after all retries have been exhausted")
    return AttestationResult(token=None, evidence=evidence)

  def attest_platform_detailed(self) -> AttestationResult:
    """
    Attest the Hardware

    Returns
    -------
    AttestationResult
      The token (None if no token was received) and the platform evidence that was sent.
    """
    evidence = None
    retries = 0
    backoff_factor = 1
    while retries < self.parameters.max_retries:
      try:
        self.log.info('Attesting Platform Evidence...')
        evidence = self._collect_platform_evidence()

        encoded_token = self.provider.attest_platform(evidence['hw_evidence'], evidence['runtime_data'])
        if encoded_token:
          self.log.info('TOKEN:')
          self.log.info(encoded_token)
          self.provider.print_platform_claims(encoded_token)
          return AttestationResult(token=encoded_token, evidence=evidence)

        self.log.error("Token was not received from attestation provider")
      except RequestException as e:
        self.log.error(f"Request to attest platform failed with an exception: {e}")

      retries += 1
      if retries < self.parameters.max_retries:
        sleep_time = backoff_factor * (2 ** (retries - 1))
        self.log.info(f"Retrying in {sleep_time} seconds...")
        time.sleep(sleep_time)

    self.log.error("Attestation failed after all retries have been exhausted")
    return AttestationResult(token=None, evidence=evidence)

  def _collect_platform_evidence(self):
    tss_wrapper = TssWrapper(self.log)

    # Extract Hardware Report and Runtime Data
    hcl_report = tss_wrapper.get_hcl_report(self.parameters.user_claims)
    report_type = ReportParser.extract_report_type(hcl_report)
    runtime_data = ReportParser.extract_runtimes_data(hcl_report)
    hw_report = ReportParser.extract_hw_report(hcl_report)

    # Set request data based on the platform
    encoded_report = Encoder.base64url_encode(hw_report)
    encoded_runtime_data = Encoder.base64url_encode(runtime_data)
    encoded_hw_evidence = ""

    imds_client = ImdsClient(self.log)
    if report_type == IsolationType.TDX:
      encoded_hw_evidence = imds_client.get_td_quote(encoded_report)
    elif report_type == IsolationType.SEV_SNP:
      # Logs important SNP fields from the hardware report
      self.log_snp_report(hw_report)

      cert_chain = imds_client.get_vcek_certificate()
      encoded_hw_evidence = SnpFormatter.format_snp_evidence(hw_report, cert_chain)
    else:
      self.log.info('Invalid Hardware Report Type')

    self.log.info(f'Hardware evidence size: {len(encoded_hw_evidence)} bytes')
    self.log.info(f'Runtime data size: {len(encoded_runtime_data)} bytes')
    self.log.debug(f'Hardware evidence (full): {encoded_hw_evidence}')
    self.log.debug(f'Runtime data (full): {encoded_runtime_data}')

    return {
      'hw_evidence': encoded_hw_evidence,
      'runtime_data': encoded_runtime_data,
      'report_type': report_type.name
    }

  def _collect_guest_evidence(self):
    """
    Collects guest evidence. The caller must release() the returned object, or
    use it to decrypt the attestation provider's response.
    """
    isolation_type = self.parameters.isolation_type
    self.log.info(f'Processing {isolation_type.name} attestation...')

    platform_evidence = None
    if isolation_type == IsolationType.TRUSTED_LAUNCH:
      isolation_evidence = TrustedLaunchEvidence()

    elif isolation_type in [IsolationType.SEV_SNP, IsolationType.TDX]:
      hardware_evidence = self.get_hardware_evidence()
      hw_report = hardware_evidence.hardware_report
      runtime_data = hardware_evidence.runtime_data

      if isolation_type == IsolationType.SEV_SNP:
        imds_client = ImdsClient(self.log)
        cert_chain = imds_client.get_vcek_certificate()
        encoded_hw_evidence = SnpFormatter.format_snp_evidence(hw_report, cert_chain)
        isolation_evidence = SnpEvidence(hw_report, runtime_data, cert_chain)
      else:  # TDX: hw_report is already the TD quote from IMDS
        encoded_hw_evidence = Encoder.base64url_encode(hw_report)
        isolation_evidence = TdxEvidence(hw_report, runtime_data)

      platform_evidence = {
        'hw_evidence': encoded_hw_evidence,
        'runtime_data': Encoder.base64url_encode(runtime_data),
        'report_type': isolation_type.name
      }

    else:
      self.log.error(f'Unsupported isolation type: {isolation_type}')
      raise UnsupportedReportTypeException(f"Unsupported isolation type: {isolation_type}")

    # Collect guest attestation parameters
    os_info = OsInfo()
    tss_wrapper = TssWrapper(self.log)
    aik_cert = tss_wrapper.get_aik_cert()
    aik_pub = tss_wrapper.get_aik_pub()
    pcr_quote, sig = tss_wrapper.get_pcr_quote(os_info.pcr_list)
    pcr_values = tss_wrapper.get_pcr_values(os_info.pcr_list)
    key, key_handle, tpm = tss_wrapper.get_ephemeral_key(os_info.pcr_list)
    guest_evidence = _GuestEvidence(tss_wrapper, os_info.pcr_list, key_handle, tpm)
    try:
      tpm_info = TpmInfo(aik_cert, aik_pub, pcr_quote, sig, pcr_values, key)
      tcg_logs = get_measurements(os_info.type)
      isolation = Isolation(isolation_type, isolation_evidence)
      client_payload = claims_to_client_payload(self.parameters.user_claims)

      param = GuestAttestationParameters(os_info, tcg_logs, tpm_info, isolation, client_payload)
      guest_evidence.attestation_info = param.toJson()
      guest_evidence.evidence = {
        'attestation_info': json.loads(guest_evidence.attestation_info),
        'platform_evidence': platform_evidence
      }
    except Exception:
      guest_evidence.release()
      raise

    return guest_evidence

  def _decrypt_guest_response(self, encoded_response, guest_evidence):
    self.log.info('Parsing encoded token...')

    # decode the response
    response = urlsafe_b64decode(encoded_response + '==').decode('utf-8')
    response = json.loads(response)

    # parse encrypted inner key
    encrypted_inner_key = response['EncryptedInnerKey']
    encrypted_inner_key = json.dumps(encrypted_inner_key)
    encrypted_inner_key_decoded = Encoder.base64decode(encrypted_inner_key)

    # parse Encryption Parameters
    encryption_params_json = response['EncryptionParams']
    iv = json.dumps(encryption_params_json['Iv'])
    iv = Encoder.base64decode(iv)

    auth_data = response['AuthenticationData']
    auth_data = json.dumps(auth_data)
    auth_data = Encoder.base64decode(auth_data)

    decrypted_inner_key = guest_evidence.decrypt(encrypted_inner_key_decoded)

    # parse the encrypted token
    encrypted_jwt = response['Jwt']
    encrypted_jwt = json.dumps(encrypted_jwt)
    encrypted_jwt = Encoder.base64decode(encrypted_jwt)

    # Your AES key
    key = decrypted_inner_key

    # Create an AESGCM object with the generated key
    aesgcm = AESGCM(key)

    self.log.info('Decrypting JWT...')

    associated_data = bytearray(b'Transport Key')

    # NOTE: authentication data is part of the cipher's last 16 bytes
    cipher_message = encrypted_jwt + auth_data

    # Decrypt the token using the same key, nonce, and associated data
    decrypted_data = aesgcm.decrypt(iv, cipher_message, bytes(associated_data))
    self.log.info("Decrypted JWT Successfully.")
    self.log.info('TOKEN:')
    self.log.info(decrypted_data.decode('utf-8'))

    encoded_token = decrypted_data.decode('utf-8')
    self.provider.print_guest_claims(encoded_token)

    return decrypted_data

  def log_snp_report(self, hw_report):
    """
    Logs snp snp attestation report fields.
    """
    report_instance = AttestationReport.deserialize(hw_report)
    self.log.info(f"Attestation report size: {len(hw_report)} bytes")
    self.log.info(f"Report version: {report_instance.version}")
    self.log.info(f"Report guest svn: {report_instance.guest_svn}")

    formatted_tcb = "".join(f"{byte:02X}" for byte in report_instance.current_tcb.serialize()[::-1])
    self.log.info(f"Current TCB version: {formatted_tcb}")

    formatted_tcb = "".join(f"{byte:02X}" for byte in report_instance.reported_tcb.serialize()[::-1])
    self.log.info(f"Reported TCB version: {formatted_tcb}")

    formatted_tcb = "".join(f"{byte:02X}" for byte in report_instance.committed_tcb.serialize()[::-1])
    self.log.info(f"Commited TCB version: {formatted_tcb}")

    formatted_tcb = "".join(f"{byte:02X}" for byte in report_instance.launch_tcb.serialize()[::-1])
    self.log.info(f"Launched TCB version: {formatted_tcb}")
