import requests
import json
import time
from src.Logger import Logger

ACC_URL = "http://169.254.169.254/acc"
QUOTE_PATH = "/tdquote"
TD_QUOTE_ENDPOINT = ACC_URL + QUOTE_PATH

IMDS_URL = "http://169.254.169.254/metadata"
THIM_PATH = "/THIM/amd/certification"
THIM_ENDPOINT = IMDS_URL + THIM_PATH

INSTANCE = "/instance?api-version=2021-01-01&format=json"
COMPUTE_METADATA_URL = IMDS_URL + INSTANCE

METADATA_HEADERS = {
  'Content-Type': 'application/json',
  'Metadata': 'true'
}


class TDQuoteException(Exception):
  pass


class VcekCertException(Exception):
  pass


class ImdsClient:
  def __init__(self, logger: Logger):
    self.log = logger

  def _send_request_with_retries(self, method, url, headers=None, data=None,
                                 max_retries=5, initial_delay=1, delay_strategy='constant',
                                 expected_status=200, exception_class=Exception):
    retries = 0
    delay = initial_delay

    while retries < max_retries:
      try:
        self.log.info(f"Sending {method.upper()} request to {url}")
        response = requests.request(method, url, headers=headers, data=data)

        if response.status_code == expected_status:
          return response

        self.log.warning(f"Unexpected status code {response.status_code}: {response.text}")
        retries += 1
        if retries >= max_retries:
          raise exception_class(f"Error {response.status_code}: {response.text}")
      except requests.exceptions.RequestException as e:
        self.log.error("Request exception occurred", exc_info=True)
        retries += 1
        if retries >= max_retries:
          raise exception_class(f"HTTP request failed with error {e}") from e

      self.log.info(f"Retrying in {delay} seconds... Attempt {retries}")
      time.sleep(delay)
      delay = delay * 2 if delay_strategy == 'exponential' else delay

    raise exception_class("Request failed after all retries")

  def get_td_quote(self, encoded_report):
    """
    Get the TD quote from the IMDS endpoint.
    Parameters:
      encoded_report: The encoded report to be sent in the request body.
    
    Returns:
      The TD quote received from the IMDS endpoint.
    """
 
    headers = {'Content-Type': 'application/json'}
    request_body = json.dumps({"report": encoded_report})

    response = self._send_request_with_retries(
      method='post',
      url=TD_QUOTE_ENDPOINT,
      headers=headers,
      data=request_body,
      exception_class=TDQuoteException
    )

    try:
      evidence_json = response.json()
      self.log.info("Received td quote successfully")
      return evidence_json['quote']
    except json.JSONDecodeError as e:
      self.log.error("Failed to decode TD quote JSON", exc_info=True)
      raise TDQuoteException(f"JSON decoding error: {e}") from e

  def get_vcek_certificate(self):
    """
    Get the VCEK certificate from the IMDS endpoint.

    Returns:
      The VCEK certificate received from the IMDS endpoint.
    """

    response = self._send_request_with_retries(
      method='get',
      url=THIM_ENDPOINT,
      headers=METADATA_HEADERS,
      delay_strategy='exponential',
      exception_class=VcekCertException
    )

    try:
      data_json = response.json()
      self.log.info(f"Received VCEK certificate, TCB version: {data_json.get('tcbm')}")
      cert_chain = data_json['vcekCert'] + data_json['certificateChain']
      return bytearray(cert_chain.encode('utf-8'))
    except json.JSONDecodeError as e:
      self.log.error("Failed to decode VCEK certificate JSON", exc_info=True)
      raise VcekCertException(f"JSON decoding error: {e}") from e

  def get_region_from_compute_metadata(self):
    """
    Get the region from the compute metadata.

    Returns:
      The region string if available, otherwise None.
    """
    try:
      response = self._send_request_with_retries(
        method='get',
        url=COMPUTE_METADATA_URL,
        headers=METADATA_HEADERS,
        exception_class=TDQuoteException  # Or define a specific exception if needed
      )

      metadata = response.json()
      return metadata.get('compute', {}).get('location')
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
      self.log.error(f"Exception retrieving compute metadata: {e}", exc_info=True)
      return None

