import requests
import json
from abc import ABC, abstractmethod
from src.Isolation import IsolationType
from src.Logger import Logger
from urllib.parse import urlparse
from requests.exceptions import RequestException


DEFAULT_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}

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
      raise ValueError(f"Unsupported isolation type: {isolation}. Supported types: {list(IsolationType)}")

     # Validate the endpoint
    parsed_endpoint = urlparse(endpoint)
    if not parsed_endpoint.scheme or not parsed_endpoint.netloc:
      raise ValueError(f"Invalid endpoint: {endpoint}. Endpoint must be a valid URL.")

    self.logger = logger
    self.isolation = isolation
    self.endpoint = endpoint


  def attest_guest(self, evidence):
    """
    Verfies the Guest and Hardware Evidence provided by the Attester
    """

    try:
      self.logger.info("Sending attestation request to provider...")

      # Sends request to MAA for attesting the guest
      response = requests.post(
          self.endpoint,
          data=json.dumps(evidence),
          headers=DEFAULT_HEADERS
      )

      # Check the response from the server
      if response.status_code == 200:
        self.logger.info("Received token from attestation provider")
        response_json = json.loads(response.text)
        encoded_token = response_json['token']

        return encoded_token
      else:
        self.logger.error(f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}")
        raise ValueError(f"Unexpected status code: {response.status_code}, error: {response.text}")
    except RequestException as e:
      self.logger.error(f"Request failed: {e}")
      raise SystemError(f"Request failed: {e}")


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
      raise ValueError(f"Invalid Isolation Type. Valid Types: {IsolationType.TDX}, {IsolationType.SEV_SNP}")
    return payload


  def attest_platform(self, evidence, runtime_data):
    """
    Verfies the Hardware Evidence provided by the Attester
    """

    try:
      payload = self.create_payload(evidence, runtime_data)

      self.logger.info("Sending attestation request to provider...")

      # Sends request to MAA for attesting the guest
      response = requests.post(
          self.endpoint,
          data=json.dumps(payload),
          headers=DEFAULT_HEADERS
      )

      # Check the response from the server
      if response.status_code == 200:
        self.logger.info("Received token from attestation provider")
        response_json = json.loads(response.text)
        encoded_token = response_json['token']

        return encoded_token
      else:
        self.logger.error(f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}")
        raise ValueError(f"Unexpected status code: {response.status_code}, error: {response.text}")
    except RequestException as e:
      self.logger.error(f"Request failed: {e}")
      raise SystemError(f"Request failed: {e}")


class ITAProvider(IAttestationProvider):
  def __init__(self, logger: Logger, isolation: IsolationType, endpoint: str, api_key: str):
    # Validate the isolation type
    if not isinstance(isolation, IsolationType):
      raise ValueError(f"Unsupported isolation type: {isolation}. Supported types: {list(IsolationType)}")

      # Validate the endpoint
    parsed_endpoint = urlparse(endpoint)
    if not parsed_endpoint.scheme or not parsed_endpoint.netloc:
      raise ValueError(f"Invalid endpoint: {endpoint}. Endpoint must be a valid URL.")

    self.logger = logger
    self.isolation = isolation
    self.endpoint = endpoint
    self.api_key = api_key


  def attest_guest(self, evidence):
    """
    Verfies the Guest and Hardware Evidence provided by the Attester
    """
    pass


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

      self.logger.info("Sending attestation request to provider...")

      # Sends request to MAA for attesting the guest
      response = requests.post(
          self.endpoint,
          data=json.dumps(payload),
          headers=headers
      )

      # Check the response from the server
      if response.status_code == 200:
        self.logger.info("Received token from attestation provider")
        response_json = json.loads(response.text)
        encoded_token = response_json['token']

        return encoded_token
      else:
        self.logger.error(f"Failed to verify evidence, status code: {response.status_code}, error: {response.text}")
        raise ValueError(f"Unexpected status code: {response.status_code}, error: {response.text}")
    except RequestException as e:
      self.logger.error(f"Request failed: {e}")
      raise SystemError(f"Request failed: {e}")