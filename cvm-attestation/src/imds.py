import requests
import json
import logging

# IMDS endpoint for getting the TD Quote
ACC_URL = "http://169.254.169.254/acc"
QUOTE_PATH = "/tdquote"
IMDS_ENDPOINT = ACC_URL + QUOTE_PATH

# IMDS endpoint for getting the VCek certificate
IMDS_URL = "http://169.254.169.254/metadata";
THIM_PATH = "/THIM/amd/certification";
THIM_ENDPOINT = IMDS_URL + THIM_PATH


def get_td_quote(encoded_report):
  # setup imds request
  headers = {'Content-Type': 'application/json'}
  request_body = {
    "report": encoded_report
  }

  try:
    print("Starting td quote request")
    response = requests.post(
      IMDS_ENDPOINT,
      data = json.dumps(request_body),
      headers = headers)

    if response.status_code == 200:
      print("Received td quote successfully")
      evidence_json = json.loads(response.text)
      encoded_quote = evidence_json['quote']
      return encoded_quote
    else:
      logging.error('Failed to get td quote')
      logging.error('response: ', response.text)
  except:
    logging.error("Exception while fetching td quote")


def get_vcek_certificate():
  # setup imds request
  headers = {
    'Content-Type': 'application/json',
    'Metadata': 'true'
  }

  try:
    print("Starting vcek certificate request")
    response = requests.get(
      THIM_ENDPOINT,
      headers = headers)

    if response.status_code == 200:
      print("Received certificate successfully")
      data_json = json.loads(response.text)
      cert = data_json['vcekCert']
      chain = data_json['certificateChain']
      cert_chain = cert + chain
      cert_chain = bytearray(cert_chain.encode('utf-8'))

      return cert_chain
    else:
      logging.error('Failed to get certificacte')
      logging.error('response: ', response.text)
  except:
    logging.error("Exception while fetching certificacte")
