# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import click
from AttestationClient import AttestationClient, AttestationClientParameters, Verifier
from src.Isolation import IsolationType
from src.Logger import Logger
from urllib.parse import urlparse


def parse_config_file(filename):
  with open(filename, 'r') as json_file:
    # Parse the JSON data
    data = json.load(json_file)
  return data


IsolationTypeLookup = {
  'maa_tdx': IsolationType.TDX,
  'maa_snp': IsolationType.SEV_SNP,
  'ita': IsolationType.TDX,
  'default': IsolationType.UNDEFINED
}


AttestationProviderLookup = {
  'maa_tdx': Verifier.MAA,
  'maa_snp': Verifier.MAA,
  'ita': Verifier.ITA,
  'default': Verifier.UNDEFINED
}


class AttestException(Exception):
  pass

@click.command()
@click.option(
  '--c',
  type=str,
  required=True,
  help = 'Config json file',
)
@click.option(
  '--t',
  type=click.Choice(['Guest', 'Platform'], case_sensitive=False),
  default='Platform',
  help='Attestation type: Guest or Platform (Default)'
)
def attest(c, t):
  # create a new console logger
  logger = Logger('logger').get_logger()
  logger.info("Attestation started...")
  logger.info(f"Reading config file: {c}")

  attestation_type = t
  file_path = 'report.bin'

  # creates an attestation parameters based on user's config
  config_json = parse_config_file(c)
  provider_tag = config_json.get('attestation_provider', None)
  endpoint = config_json.get('attestation_url', None)
  api_key = config_json.get('api_key', None)
  claims = config_json.get('claims', None)

  logger.info("Attestation tool configuration:")
  logger.info(f"provider_tag: {provider_tag}")
  logger.info(f"endpoint: {endpoint}")
  logger.info(f"api_key: {api_key}")
  logger.info(f"claims: {claims}")

  # Build attestation client parameters
  isolation_type = IsolationTypeLookup.get(provider_tag, IsolationTypeLookup['default'])
  provider = AttestationProviderLookup.get(provider_tag, AttestationProviderLookup['default'])
  client_parameters = AttestationClientParameters(endpoint, provider, isolation_type, claims, api_key)

  # Attest based on user configuration
  attestation_client = AttestationClient(logger, client_parameters)
  hw_report = attestation_client.get_hardware_report()

  # Store hardware report
  with open(file_path, 'wb') as file:
    file.write(hw_report)
  logger.info(f"Output successfully written to: {file_path}")

  parsed_endpoint = urlparse(endpoint)
  if not parsed_endpoint.scheme or not parsed_endpoint.netloc:
    raise ValueError(f"Invalid endpoint: {endpoint}. Endpoint must be a valid URL.")

  if attestation_type.lower() == str('Guest').lower():
    # if attesting the guest we need to make sure the right endpoint is used
    if 'attest/AzureGuest' in endpoint:
      token = attestation_client.attest_guest()
    else:
      raise AttestException('Invalid endpoint. Make sure endpoint is correct for attesting the Guest')
  elif attestation_type.lower() == str('Platform').lower():
    token = attestation_client.attest_platform()
  else:
    raise AttestException('Invalid parameter for attestation type')


if __name__ == "__main__":
  attest()