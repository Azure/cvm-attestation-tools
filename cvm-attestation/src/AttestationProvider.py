# AttestationProvider.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import requests
import json
import jwt
import time
from abc import ABC, abstractmethod
from src.Isolation import IsolationType
from src.Logger import Logger
from urllib.parse import urlparse
from requests.exceptions import RequestException


DEFAULT_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}


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

     # Validate the endpoint
    parsed_endpoint = urlparse(endpoint)
    if not parsed_endpoint.scheme or not parsed_endpoint.netloc:
      raise ValueError(
        f"Invalid endpoint: {endpoint}. Endpoint must be a valid URL."
      )

    self.log = logger
    self.isolation = isolation
    self.endpoint = endpoint


  def attest_platform(self, evidence, runtime_data):
    """
    Verfies the Hardware Evidence provided by the Attester
    """

    # Sends request to MAA using exponential backoff to handle
    # any transient network issue.
    max_retries = 5
    retries = 0
    backoff_factor = 1
    while retries < max_retries:
      try:
        payload = self.create_payload(evidence, runtime_data)

        self.log.info("Sending attestation request to provider...")

        # Sends request to MAA for attesting the guest
        response = requests.post(
          self.endpoint,
          data=json.dumps(payload),
          headers=DEFAULT_HEADERS
        )

        # Check the response from the server if there is an error
        # we retry until all retries have been exhausted
        if response.status_code == 200:
          self.log.info("Received token from attestation provider")
          response_json = json.loads(response.text)
          encoded_token = response_json['token']

          return encoded_token
        elif response.status_code == 400:
          self.log.error(
            f"Failed to verify evidence due to invalid collateral, error: {response.text}"
          )

          return None
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


  def attest_guest(self, evidence):
    """
    Verfies the Guest and Hardware Evidence provided by the Attester
    """

    # Sends request to MAA using exponential backoff to handle
    # any transient network issue
    max_retries = 5
    retries = 0
    backoff_factor = 1
    while retries < max_retries:
      try:
        self.log.info("Sending attestation request to provider...")

        # Sends request to MAA for attesting the guest
        response = requests.post(
          self.endpoint,
          data=json.dumps(evidence),
          headers=DEFAULT_HEADERS
        )

        # Check the response from the server
        if response.status_code == 200:
          self.log.info("Received token from attestation provider")
          response_json = json.loads(response.text)
          encoded_token = response_json['token']

          return encoded_token
        elif response.status_code == 400:
          self.log.error(
            f"Failed to verify evidence due to invalid collateral, error: {response.text}"
          )

          return None
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


  def print_snp_platform_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      if claims['x-ms-compliance-status'] == 'azure-compliant-cvm':
        self.log.info(f"Claims:")
        self.log.info(f"Attestation Type: {claims['x-ms-attestation-type']}")
        self.log.info(f"Status: {claims['x-ms-compliance-status']}")
        self.log.info(f"SNP Bootloader SVN: {claims['x-ms-sevsnpvm-bootloader-svn']}")
        self.log.info(f"SNP Guest SVN: {claims['x-ms-sevsnpvm-guestsvn']}")
        self.log.info(f"SNP Microcode SVN: {claims['x-ms-sevsnpvm-microcode-svn']}")
        self.log.info(f"SNP Firmware SVN: {claims['x-ms-sevsnpvm-snpfw-svn']}")
        self.log.info(f"SNP TEE SVN: {claims['x-ms-sevsnpvm-tee-svn']}")
        self.log.info(f"Report Data: {claims['x-ms-sevsnpvm-reportdata']}")
        self.log.info(f"User Claims Digest: {claims['x-ms-runtime']['user-data']}")
        self.log.info("Attested Platform Successfully!!")
    except Exception as e:
      raise AttestationProviderException(f'Exception while decoding jwt. Exception: {e}')


  def print_platform_claims(self, encoded_token):
    if self.isolation == IsolationType.TDX:
      self.print_tdx_platform_claims(encoded_token)
    elif self.isolation == IsolationType.SEV_SNP:
      self.print_snp_platform_claims(encoded_token)
    else:
      raise ValueError(
        f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP}"
      )


  def print_tdx_platform_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      if claims['x-ms-compliance-status'] == 'azure-compliant-cvm':
        self.log.info(f"Claims:")
        self.log.info(f"Attestation Type: {claims['x-ms-attestation-type']}")
        self.log.info(f"TCB Status: {claims['attester_tcb_status']}")
        self.log.info(f"TCB SVN : {claims['tdx_tee_tcb_svn']}")
        self.log.info(f"TPM Persisted: {claims['x-ms-runtime']['vm-configuration']['tpm-persisted']}")
        self.log.info(f"Report Data: {claims['x-ms-reportdata']}")
        self.log.info(f"User Claims Digest: {claims['x-ms-runtime']['user-data']}")
        self.log.info("Attested Platform Successfully!!")
    except Exception as e:
      raise AttestationProviderException(f'Exception while decoding jwt. Exception: {e}')


  def print_guest_claims(self, encoded_token):
    try:
      claims = jwt.decode(encoded_token, options={"verify_signature": False})

      if claims['x-ms-isolation-tee']['x-ms-compliance-status'] == 'azure-compliant-cvm':
        self.log.info(f"Claims:")
        self.log.info(f"Attestation Type: {claims['x-ms-isolation-tee']['x-ms-attestation-type']}")
        self.log.info(f"Status: {claims['x-ms-isolation-tee']['x-ms-compliance-status']}")
        self.log.info(f"SNP Bootloader SVN: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-bootloader-svn']}")
        self.log.info(f"SNP Guest SVN: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-guestsvn']}")
        self.log.info(f"SNP Microcode SVN: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-microcode-svn']}")
        self.log.info(f"SNP Firmware SVN: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-snpfw-svn']}")
        self.log.info(f"SNP TEE SVN: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-tee-svn']}")
        self.log.info(f"Report Data: {claims['x-ms-isolation-tee']['x-ms-sevsnpvm-reportdata']}")
        self.log.info(f"User Claims Digest: {claims['x-ms-isolation-tee']['x-ms-runtime']['user-data']}")
        self.log.info("Attested Guest Successfully!!")
    except Exception as e:
      raise AttestationProviderException(f'Exception while decoding jwt. Exception: {e}')


  def create_payload(self, evidence: str, runtimes_data: str):
    # Check if evidence and runtimes_data are strings
    if not isinstance(evidence, str):
      raise ValueError("The 'evidence' argument must be an encoded string.")
    if not isinstance(runtimes_data, str):
      raise ValueError("The 'runtimes_data' argument must be an encoded string.")

    payload = ''
    runtime_data_format = {
      'data': runtimes_data,
      'dataType': 'JSON'
    }

    if self.isolation == IsolationType.TDX:
      payload = {
        'quote': evidence,
        'runtimeData': runtime_data_format
      }
    elif self.isolation == IsolationType.SEV_SNP:
      payload = {
        'report': evidence,
        'runtimeData': runtime_data_format
      }
    else:
      raise ValueError(
        f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP}"
      )
    return payload


class ITAProvider(IAttestationProvider):
  def __init__(self, logger: Logger, isolation: IsolationType, endpoint: str, api_key: str):
    # Validate the isolation type
    if not isinstance(isolation, IsolationType):
      raise ValueError(f"Unsupported isolation type: {isolation}. Supported types: {list(IsolationType)}")

      # Validate the endpoint
    parsed_endpoint = urlparse(endpoint)
    if not parsed_endpoint.scheme or not parsed_endpoint.netloc:
      raise ValueError(f"Invalid endpoint: {endpoint}. Endpoint must be a valid URL.")

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

      if claims['attester_tcb_status'] == 'UpToDate':
        self.log.info(f"Claims:")
        self.log.info(f"Attestation Type: {claims['attester_type']}")
        self.log.info(f"TCB Status: {claims['attester_tcb_status']}")
        self.log.info(f"TDX Debuggable : {claims['tdx_is_debuggable']}")
        self.log.info("Attested Platform Successfully!!")
    except Exception as e:
      raise AttestationProviderException(f'Exception while decoding jwt. Exception: {e}')


  def create_payload(self, evidence: str, runtimes_data: str):
    # Check if evidence and runtimes_data are strings
    if not isinstance(evidence, str):
      raise ValueError("The 'evidence' argument must be an encoded string.")
    if not isinstance(runtimes_data, str):
      raise ValueError("The 'runtimes_data' argument must be an encoded string.")

    payload = ''
    if self.isolation == IsolationType.TDX:
      payload = {
      'quote': evidence
    }
    else:
      raise ValueError(f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}")
    return payload


  def attest_platform(self, evidence, runtime_data):
    """
    Verfies the Hardware Evidence provided by the Attester
    """

    try:
      headers = DEFAULT_HEADERS
      headers['x-api-key'] = self.api_key
      payload = self.create_payload(evidence, runtime_data)

      self.log.info("Sending attestation request to provider...")

      # Sends request to MAA for attesting the guest
      response = requests.post(
          self.endpoint,
          data=json.dumps(payload),
          headers=headers
      )

      # Check the response from the server
      if response.status_code == 200:
        self.log.info("Received token from attestation provider")
        response_json = json.loads(response.text)
        encoded_token = response_json['token']

        return encoded_token
      else:
        self.log.error(f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}")
        raise ValueError(f"Unexpected status code: {response.status_code}, error: {response.text}")
    except RequestException as e:
      self.log.error(f"Request failed: {e}")
      raise SystemError(f"Request failed: {e}")