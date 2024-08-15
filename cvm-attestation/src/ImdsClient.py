# ImdsClient.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import requests
import json
import time
from src.Logger import Logger

# IMDS endpoint for getting the TD Quote
ACC_URL = "http://169.254.169.254/acc"
QUOTE_PATH = "/tdquote"
IMDS_ENDPOINT = ACC_URL + QUOTE_PATH

# IMDS endpoint for getting the VCek certificate
IMDS_URL = "http://169.254.169.254/metadata";
THIM_PATH = "/THIM/amd/certification";
THIM_ENDPOINT = IMDS_URL + THIM_PATH


class TDQuoteException(Exception):
  pass


class VcekCertException(Exception):
  pass


class ImdsClient:
  def __init__(self, logger: Logger):
    self.log = logger

  def get_td_quote(self, encoded_report):
    # setup imds request
    headers = {'Content-Type': 'application/json'}
    request_body = {
      "report": encoded_report
    }

    # Request TD Quote with 5 retries delaying by 1 second each request
    delay = 1
    max_retries = 5
    retries = 0
    while retries < max_retries:
      try:
        self.log.info("Starting td quote request")
        response = requests.post(
          IMDS_ENDPOINT,
          data=json.dumps(request_body),
          headers=headers
        )

        if response.status_code == 200:
          self.log.info("Received td quote successfully")
          evidence_json = json.loads(response.text)
          encoded_quote = evidence_json['quote']

          return encoded_quote
        else:
          self.log.error('Failed to get td quote')
          self.log.error(f'response: {response.text}')

          retries += 1
          if retries >= max_retries:
            raise TDQuoteException(f'Error {response.status_code}: {response.text}')

          self.log.info(f"Retrying in {delay} seconds... Attempt {retries}")
          time.sleep(delay)
      except requests.exceptions.RequestException as e:
        self.log.error("Exception while fetching td quote", exc_info=True)

        retries += 1
        if retries >= max_retries:
          raise TDQuoteException(f'HTTP request failed with error {e}') from e

        self.log.info(f"Retrying in {delay} seconds... Attempt {retries}")
        time.sleep(delay)
      except json.JSONDecodeError as e:
        self.log.error("JSON decode error", exc_info=True)
        raise TDQuoteException(f'Error decoding JSON response. Error: {e}') from e


  def get_vcek_certificate(self):
    # setup imds request
    headers = {
      'Content-Type': 'application/json',
      'Metadata': 'true'
    }

    # Request Vcek Certificate with 5 retries, increasing delay by 2x each request
    delay = 1
    max_retries = 5
    retries = 0
    while retries < max_retries:
      try:
        self.log.info("Starting vcek certificate request")
        response = requests.get(
          THIM_ENDPOINT,
          headers = headers
        )

        if response.status_code == 200:
          data_json = json.loads(response.text)
          self.log.info(f"Received certificate successfully, TCB version: {data_json['tcbm']}")
          cert = data_json['vcekCert']
          chain = data_json['certificateChain']
          cert_chain = cert + chain
          cert_chain = bytearray(cert_chain.encode('utf-8'))

          return cert_chain
        else:
          self.log.error('Failed to get vcek certificate')
          self.log.error(f'response: {response.text}')

          retries += 1
          if retries >= max_retries:
            raise VcekCertException(f'Error {response.status_code}: {response.text}')

          self.log.info(f"Retrying in {delay} seconds... Attempt {retries}")
          time.sleep(delay)
          delay *= 2
      except requests.exceptions.RequestException as e:
        self.log.error("Exception while fetching vcek certificate", exc_info=True)

        retries += 1
        if retries >= max_retries:
          raise VcekCertException(f'HTTP request failed with error {e}') from e

        self.log.info(f"Retrying in {delay} seconds... Attempt {retries}")
        time.sleep(delay)
      except json.JSONDecodeError as e:
        print(e)
        self.log.error("JSON decode error", exc_info=True)
        raise VcekCertException(f'Error decoding JSON response. Error: {e}') from e