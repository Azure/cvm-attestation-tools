# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import click
import hashlib
from AttestationClient import AttestationClient, AttestationClientParameters, Verifier
from src.Isolation import IsolationType
from src.Logger import Logger
from urllib.parse import urlparse
from src.EndpointSelector import EndpointSelector
import os


def parse_config_file(filename):
  with open(filename, 'r') as json_file:
    return json.load(json_file)


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


def get_base_url(logger):
  """
  Get the base URL for the attestation endpoint based on the region.
  """
  current_dir = os.getcwd()
  filename = 'attestation_uri_table.json'
  endpoint_file_path = os.path.join(current_dir, filename)

  endpoint_selector = EndpointSelector(endpoint_file_path, logger)
  base_url = endpoint_selector.get_attestation_endpoint()

  return base_url

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
@click.option('--s', is_flag=True, help="Save hardware evidence to files.")
def attest(c, t, s):
  # create a new console logger
  logger = Logger('logger').get_logger()
  logger.info("Attestation started...")
  logger.info(f"Reading config file: {c}")

  attestation_type = t

  # creates an attestation parameters based on user's config
  config_json = parse_config_file(c)
  provider_tag = config_json.get('attestation_provider', None)
  endpoint = config_json.get('attestation_url', None)
  api_key = config_json.get('api_key', None)
  claims = config_json.get('claims', None)

  logger.info("Attestation tool configuration:")
  logger.info(f"provider_tag: {provider_tag}")
  logger.info(f"api_key: {api_key}")
  logger.info(f"claims: {claims}")

  base_url = get_base_url(logger)
  logger.info(f"Base URL for Region: {base_url}")

  isolation_type = IsolationTypeLookup.get(provider_tag, IsolationTypeLookup['default'])

  endpoint = ""
  # get attestation endpoint based on the region
  if attestation_type.lower() == str('Guest').lower():
    endpoint = "/attest/AzureGuest"
    query_param = "?api-version=2020-10-01"

    endpoint = base_url + endpoint + query_param
  elif attestation_type.lower() == str('Platform').lower():
    path = ""
    query_param = ""
    if isolation_type == IsolationType.TDX:
      path = "/attest/TdxVm"
      query_param = "?api-version=2023-04-01-preview"
    elif isolation_type == IsolationType.SEV_SNP:
      path = "/attest/SevSnpVm"
      query_param = "?api-version=2022-08-01"
    else:
      pass

    endpoint = base_url + path + query_param
  else:
    raise AttestException('Invalid parameter for attestation type')
  logger.info(f"Attestation endpoint: {endpoint}")

  # Log SHA512 of user provided claims
  hash_object = hashlib.sha512(json.dumps(claims).encode('utf-8'))
  hex_dig = hash_object.hexdigest()
  logger.info(f"SHA512 of user provided claims: {hex_dig.upper()}")

  # Build attestation client parameters
  provider = AttestationProviderLookup.get(provider_tag, AttestationProviderLookup['default'])
  client_parameters = AttestationClientParameters(endpoint, provider, isolation_type, claims, api_key)

  # Attest based on user configuration
  attestation_client = AttestationClient(logger, client_parameters)

  if attestation_type.lower() == str('Guest').lower():
      token = attestation_client.attest_guest()
  elif attestation_type.lower() == str('Platform').lower():
    token = attestation_client.attest_platform()
  else:
    raise AttestException('Invalid parameter for attestation type')

  # Store hardware report and runtime data to files if the save flag is specified
  if s:
    # get the hardware evidence obtained by the attstation client
    hardware_evidence = attestation_client.get_hardware_evidence()
    hardware_report = hardware_evidence.hardware_report
    runtime_data = hardware_evidence.runtime_data

    # Store hardware report
    file_path = 'report.bin'
    with open(file_path, 'wb') as file:
      file.write(hardware_report)
    logger.info(f"Output successfully written to: {file_path}")

    # Stores the runtime data in a json file
    json_data = json.loads(runtime_data)
    with open('runtime_data.json', 'w') as file:
      json.dump(json_data, file, indent=2)
      logger.info(f"Output successfully written to: 'runtime_data.json'")


if __name__ == "__main__":
  attest()