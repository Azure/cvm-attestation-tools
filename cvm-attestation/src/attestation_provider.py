# attestation_provider.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import jwt
import requests
from requests.exceptions import RequestException

from src.isolation import IsolationType
from src.logger import Logger

DEFAULT_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


class AttestationProviderException(Exception):
  pass


class IAttestationProvider(ABC):
  """
  Interface to Attestation Provider

  This interface defines the methods that must be implemented by any attestation provider.
  """

  @abstractmethod
  def attest_guest(self):
    """
    Verfies the Guest and Hardware Evidence provided by the Attester
    """
    pass

  @abstractmethod
  def attest_platform(self):
    """
    Verfies the Hardware Evidence provided by the Attester
    """
    pass


class MAAProvider(IAttestationProvider):
  def __init__(self, logger: Logger, isolation: IsolationType, endpoint: str):
    # Validate the isolation type
    if not isinstance(isolation, IsolationType):
      raise ValueError(
        f"Unsupported isolation type: {isolation}. Supported types: {list(IsolationType)}"
      )

    # Validate the endpoint - HTTPS is required so attestation tokens are
    # delivered over an authenticated, encrypted channel.
    parsed_endpoint = urlparse(endpoint)
    if parsed_endpoint.scheme != "https" or not parsed_endpoint.netloc:
      raise ValueError(
        f"Invalid endpoint: {endpoint}. Endpoint must be a valid HTTPS URL."
      )

    self.log = logger
    self.isolation = isolation
    self.endpoint = endpoint

  def _send_attestation_request(self, payload):
    """
    Sends an attestation request to the provider with retries and exponential backoff.
    """
    max_retries = 5
    backoff_factor = 1
    retries = 0

    while retries < max_retries:
      try:
        self.log.info("Sending attestation request to provider...")

        response = requests.post(
          self.endpoint, data=json.dumps(payload), headers=DEFAULT_HEADERS
        )

        if response.status_code == 200:
          self.log.info("Received token from attestation provider")
          response_json = json.loads(response.text)
          encoded_token = response_json["token"]

          return encoded_token
        elif response.status_code == 400:
          self.log.error(
            f"Failed to verify evidence due to invalid collateral, error: {response.text}"
          )
          self.log.error(f"Request payload: {json.dumps(payload)}")
          return None
        elif response.status_code == 429:
          self.log.warning(f"Too many requests, error: {response.text}")
          retries += 1
          if retries < max_retries:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
              sleep_time = int(retry_after)
              self.log.info(f"Retrying in {sleep_time} seconds...")
              time.sleep(sleep_time)
            else:
              sleep_time = backoff_factor * (2 ** (retries - 1))
              self.log.info(f"Retrying in {sleep_time} seconds...")
              time.sleep(sleep_time)
          else:
            raise AttestationProviderException(
              f"Unexpected Error. Status code: {response.status_code}, error: {response.text}"
            )
        else:
          self.log.error(
            f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}"
          )
          retries += 1
          if retries < max_retries:
            sleep_time = backoff_factor * (2 ** (retries - 1))
            self.log.info(f"Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)
          else:
            raise AttestationProviderException(
              f"Unexpected status code: {response.status_code}, error: {response.text}"
            )

      except RequestException as e:
        self.log.error(f"Request failed with an exception: {e}")
        retries += 1
        if retries < max_retries:
          sleep_time = backoff_factor * (2 ** (retries - 1))
          self.log.info(f"Retrying in {sleep_time} seconds...")
          time.sleep(sleep_time)
        else:
          self.log.error(
            f"Request failed after all retries have been exhausted. Error: {e}"
          )
          raise AttestationProviderException(
            f"Request failed after all retries have been exhausted. Error: {e}"
          )

  def attest_platform(self, evidence, runtime_data):
    """
    Verifies the Hardware Evidence provided by the Attester.
    """
    payload = self.create_payload(evidence, runtime_data)
    return self._send_attestation_request(payload)

  def attest_guest(self, evidence):
    """
    Verifies the Guest and Hardware Evidence provided by the Attester.
    """
    return self._send_attestation_request(evidence)

  def print_snp_platform_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      self.log.info(f"Compliance Status: {claims.get('x-ms-compliance-status', 'N/A')}")
      self.log.info(f"Claims:")
      self.log.info(
        f"Attestation Type: {claims.get('x-ms-attestation-type', 'N/A')}"
      )
      self.log.info(f"Status: {claims.get('x-ms-compliance-status', 'N/A')}")
      self.log.info(
        f"SNP Bootloader SVN: {claims.get('x-ms-sevsnpvm-bootloader-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP Guest SVN: {claims.get('x-ms-sevsnpvm-guestsvn', 'N/A')}"
      )
      self.log.info(
        f"SNP Microcode SVN: {claims.get('x-ms-sevsnpvm-microcode-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP Firmware SVN: {claims.get('x-ms-sevsnpvm-snpfw-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP TEE SVN: {claims.get('x-ms-sevsnpvm-tee-svn', 'N/A')}"
      )
      self.log.info(
        f"Report Data: {claims.get('x-ms-sevsnpvm-reportdata', 'N/A')}"
      )
      self.log.info(
        f"User Claims Digest: {claims.get('x-ms-runtime', {}).get('user-data', 'N/A')}"
      )
      if claims.get("x-ms-compliance-status", "N/A") == "azure-compliant-cvm":
        self.log.info("Attested Platform Successfully!!")
      else:
        self.log.warning(
          "Attestation failed. The platform is not compliant with Azure's security requirements."
        )
    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def print_platform_claims(self, encoded_token):
    if self.isolation == IsolationType.TDX:
      self.print_tdx_platform_claims(encoded_token)
    elif self.isolation == IsolationType.SEV_SNP:
      self.print_snp_platform_claims(encoded_token)
    else:
      raise ValueError(
        f"Invalid Isolation Type. print_platform_claims - Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP}"
      )

  def print_tdx_platform_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      self.log.info(f"Compliance Status: {claims.get('x-ms-compliance-status', 'N/A')}")
      self.log.info(f"Claims:")
      self.log.info(
        f"Attestation Type: {claims.get('x-ms-attestation-type', 'N/A')}"
      )
      self.log.info(f"TCB Status: {claims.get('attester_tcb_status', 'N/A')}")
      self.log.info(f"TCB SVN : {claims.get('tdx_tee_tcb_svn', 'N/A')}")
      self.log.info(
        f"TPM Persisted: {claims.get('x-ms-runtime', {}).get('vm-configuration', {}).get('tpm-persisted', 'N/A')}"
      )
      self.log.info(f"Report Data: {claims.get('tdx_report_data', 'N/A')}")
      self.log.info(
        f"User Claims Digest: {claims.get('x-ms-runtime', {}).get('user-data', 'N/A')}"
      )
      if claims.get("x-ms-compliance-status", "N/A") == "azure-compliant-cvm":
        self.log.info("Attested Platform Successfully!!")
      else:
        self.log.warning(
          "Attestation failed. The platform is not compliant with Azure's security requirements."
        )
    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def print_guest_claims(self, encoded_token):
    if self.isolation == IsolationType.TDX:
      self.print_tdx_guest_claims(encoded_token)
    elif self.isolation == IsolationType.SEV_SNP:
      self.print_snp_guest_claims(encoded_token)
    elif self.isolation == IsolationType.TRUSTED_LAUNCH:
      self.print_trusted_launch_guest_claims(encoded_token)
    else:
      raise ValueError(
        f"Invalid Isolation Type. print_guest_claims - Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP} and {IsolationType.TRUSTED_LAUNCH}"
      )

  def print_trusted_launch_guest_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      self.log.info(f"Claims:")
      self.log.info(
        f"Attestation Type: {claims.get('x-ms-attestation-type', 'N/A')}"
      )
      self.log.info(
        f"Protocol Version: {claims.get('x-ms-azurevm-attestation-protocol-ver', 'N/A')}"
      )
      self.log.info(f"VM ID: {claims.get('x-ms-azurevm-vmid', 'N/A')}")

      # OS Information
      self.log.info(f"OS Type: {claims.get('x-ms-azurevm-ostype', 'N/A')}")
      self.log.info(f"OS Distro: {claims.get('x-ms-azurevm-osdistro', 'N/A')}")
      self.log.info(
        f"OS Version: {claims.get('x-ms-azurevm-osversion-major', 'N/A')}.{claims.get('x-ms-azurevm-osversion-minor', 'N/A')}"
      )
      self.log.info(f"OS Build: {claims.get('x-ms-azurevm-osbuild', 'N/A')}")

      # Security Configuration
      self.log.info(f"Secure Boot: {claims.get('secureboot', 'N/A')}")
      self.log.info(
        f"Boot Debug Enabled: {claims.get('x-ms-azurevm-bootdebug-enabled', 'N/A')}"
      )
      self.log.info(
        f"Kernel Debug Enabled: {claims.get('x-ms-azurevm-kerneldebug-enabled', 'N/A')}"
      )
      self.log.info(
        f"Hypervisor Debug Enabled: {claims.get('x-ms-azurevm-hypervisordebug-enabled', 'N/A')}"
      )
      self.log.info(
        f"Test Signing Enabled: {claims.get('x-ms-azurevm-testsigning-enabled', 'N/A')}"
      )
      self.log.info(
        f"Flight Signing Enabled: {claims.get('x-ms-azurevm-flightsigning-enabled', 'N/A')}"
      )
      self.log.info(
        f"Debuggers Disabled: {claims.get('x-ms-azurevm-debuggersdisabled', 'N/A')}"
      )

      # Validation Status
      self.log.info(
        f"DB Validated: {claims.get('x-ms-azurevm-dbvalidated', 'N/A')}"
      )
      self.log.info(
        f"DBX Validated: {claims.get('x-ms-azurevm-dbxvalidated', 'N/A')}"
      )
      self.log.info(
        f"Default Secure Boot Keys Validated: {claims.get('x-ms-azurevm-default-securebootkeysvalidated', 'N/A')}"
      )

      # PCR Information
      attested_pcrs = claims.get("x-ms-azurevm-attested-pcrs", [])
      self.log.info(f"Attested PCRs: {attested_pcrs}")

      self.log.info("Attested Trusted Launch Guest Successfully!!")

    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def print_snp_guest_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      isolation_tee = claims.get("x-ms-isolation-tee", {})
      self.log.info(f"Compliance Status: {claims.get('x-ms-compliance-status', 'N/A')}")
      self.log.info(f"Claims:")
      self.log.info(
        f"Attestation Type: {isolation_tee.get('x-ms-attestation-type', 'N/A')}"
      )
      self.log.info(
        f"Status: {isolation_tee.get('x-ms-compliance-status', 'N/A')}"
      )
      self.log.info(
        f"SNP Bootloader SVN: {isolation_tee.get('x-ms-sevsnpvm-bootloader-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP Guest SVN: {isolation_tee.get('x-ms-sevsnpvm-guestsvn', 'N/A')}"
      )
      self.log.info(
        f"SNP Microcode SVN: {isolation_tee.get('x-ms-sevsnpvm-microcode-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP Firmware SVN: {isolation_tee.get('x-ms-sevsnpvm-snpfw-svn', 'N/A')}"
      )
      self.log.info(
        f"SNP TEE SVN: {isolation_tee.get('x-ms-sevsnpvm-tee-svn', 'N/A')}"
      )
      self.log.info(
        f"Report Data: {isolation_tee.get('x-ms-sevsnpvm-reportdata', 'N/A')}"
      )
      self.log.info(
        f"User Claims Digest: {isolation_tee.get('x-ms-runtime', {}).get('user-data', 'N/A')}"
      )
      if "x-ms-azurevm-os-provisioning" in claims:
        self.log.info(
          f"OS provisioning claims: {claims.get('x-ms-azurevm-os-provisioning', 'N/A')}"
        )
      if claims.get("x-ms-compliance-status", "N/A") == "azure-compliant-cvm":
        self.log.info("Attested Platform Successfully!!")
      else:
        self.log.warning(
          "Attestation failed. The platform is not compliant with Azure's security requirements."
        )
    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def print_tdx_guest_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      isolation_tee = claims.get("x-ms-isolation-tee", {})
      self.log.info(f"Compliance Status: {claims.get('x-ms-compliance-status', 'N/A')}")
      self.log.info(f"Claims:")
      self.log.info(
        f"Attestation Type: {isolation_tee.get('x-ms-attestation-type', 'N/A')}"
      )
      self.log.info(
        f"Status: {isolation_tee.get('x-ms-compliance-status', 'N/A')}"
      )
      self.log.info(f"MR SEAM: {isolation_tee.get('tdx_mrseam', 'N/A')}")
      self.log.info(f"MR TD: {isolation_tee.get('tdx_report_data', 'N/A')}")
      self.log.info(f"SEAM SVN: {isolation_tee.get('tdx_seamsvn', 'N/A')}")
      self.log.info(
        f"TD Attributes: {isolation_tee.get('tdx_td_attributes', 'N/A')}"
      )
      self.log.info(
        f"TEE TCB SVN: {isolation_tee.get('tdx_tee_tcb_svn', 'N/A')}"
      )
      self.log.info(
        f"Report Data: {isolation_tee.get('tdx_report_data', 'N/A')}"
      )
      self.log.info(
        f"User Claims Digest: {isolation_tee.get('x-ms-runtime', {}).get('user-data', 'N/A')}"
      )
      if "x-ms-azurevm-os-provisioning" in claims:
        self.log.info(
          f"OS provisioning claims: {claims.get('x-ms-azurevm-os-provisioning', 'N/A')}"
        )
      if claims.get("x-ms-compliance-status", "N/A") == "azure-compliant-cvm":
        self.log.info("Attested Platform Successfully!!")
      else:
        self.log.warning(
          "Attestation failed. The platform is not compliant with Azure's security requirements."
        )
    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def create_payload(self, evidence: str, runtimes_data: str):
    # Check if evidence and runtimes_data are strings
    if not isinstance(evidence, str):
      raise ValueError("The 'evidence' argument must be an encoded string.")
    if not isinstance(runtimes_data, str):
      raise ValueError("The 'runtimes_data' argument must be an encoded string.")

    payload = ""
    runtime_data_format = {"data": runtimes_data, "dataType": "JSON"}

    if self.isolation == IsolationType.TDX:
      payload = {"quote": evidence, "runtimeData": runtime_data_format}
    elif self.isolation == IsolationType.SEV_SNP:
      payload = {"report": evidence, "runtimeData": runtime_data_format}
    else:
      raise ValueError(
        f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP}"
      )
    return payload


class ITAProvider(IAttestationProvider):
  def __init__(
    self, logger: Logger, isolation: IsolationType, endpoint: str, api_key: str
  ):
    # Validate the isolation type
    if not isinstance(isolation, IsolationType):
      raise ValueError(
        f"Unsupported isolation type: {isolation}. Supported types: {list(IsolationType)}"
      )

    # Validate the endpoint - HTTPS is required so attestation tokens and
    # the api_key are sent over an authenticated, encrypted channel.
    parsed_endpoint = urlparse(endpoint)
    if parsed_endpoint.scheme != "https" or not parsed_endpoint.netloc:
      raise ValueError(
        f"Invalid endpoint: {endpoint}. Endpoint must be a valid HTTPS URL."
      )

    self.log = logger
    self.isolation = isolation
    self.endpoint = endpoint
    self.api_key = api_key

  def attest_guest(self, evidence):
    """
    Verfies the Guest and Hardware Evidence provided by the Attester
    """
    pass

  def print_platform_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      self.log.info(f"Attester TCB Status: {claims.get('attester_tcb_status', 'N/A')}")
      self.log.info(f"Claims:")
      self.log.info(f"Attestation Type: {claims.get('attester_type', 'N/A')}")
      self.log.info(f"TCB Status: {claims.get('attester_tcb_status', 'N/A')}")
      self.log.info(
        f"TDX Debuggable : {claims.get('tdx_is_debuggable', 'N/A')}"
      )
      if claims.get("attester_tcb_status", "N/A") == "UpToDate":
        self.log.info("Attested Platform Successfully!!")
      else:
        self.log.warning(
          "Attestation failed. The platform is not compliant with Azure's security requirements."
        )
    except Exception as e:
      raise AttestationProviderException(
        f"Exception while decoding jwt. Exception: {e}"
      )

  def create_payload(self, evidence: str, runtimes_data: str):
    # Check if evidence and runtimes_data are strings
    if not isinstance(evidence, str):
      raise ValueError("The 'evidence' argument must be an encoded string.")
    if not isinstance(runtimes_data, str):
      raise ValueError("The 'runtimes_data' argument must be an encoded string.")

    payload = ""
    if self.isolation == IsolationType.TDX:
      payload = {"quote": evidence}
    else:
      raise ValueError(
        f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}"
      )
    return payload

  def attest_platform(self, evidence, runtime_data):
    """
    Verfies the Hardware Evidence provided by the Attester
    """

    try:
      headers = DEFAULT_HEADERS
      headers["x-api-key"] = self.api_key
      payload = self.create_payload(evidence, runtime_data)

      self.log.info("Sending attestation request to provider...")

      # Sends request to MAA for attesting the guest
      response = requests.post(
        self.endpoint, data=json.dumps(payload), headers=headers
      )

      # Check the response from the server
      if response.status_code == 200:
        self.log.info("Received token from attestation provider")
        response_json = json.loads(response.text)
        encoded_token = response_json["token"]

        return encoded_token
      else:
        self.log.error(
          f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}"
        )
        raise ValueError(
          f"Unexpected status code: {response.status_code}, error: {response.text}"
        )
    except RequestException as e:
      self.log.error(f"Request failed: {e}")
      raise SystemError(f"Request failed: {e}")
