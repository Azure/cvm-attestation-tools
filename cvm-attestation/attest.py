# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
import click
import hashlib
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger
from src.endpoint_selector import EndpointSelector
import os


def parse_config_file(filename):
  with open(filename, 'r') as json_file:
    return json.load(json_file)


ISOLATION_TYPE_LOOKUP = {
  'maa_tdx': IsolationType.TDX,
  'maa_snp': IsolationType.SEV_SNP,
  'ita': IsolationType.TDX,
  'default': IsolationType.UNDEFINED
}


ATTESTATION_PROVIDER_LOOKUP = {
  'maa_tdx': Verifier.MAA,
  'maa_snp': Verifier.MAA,
  'ita': Verifier.ITA,
  'default': Verifier.UNDEFINED
}


ATTESTATION_METHODS = {
  "guest": "attest_guest",
  "platform": "attest_platform"
}


class AttestException(Exception):
  pass


def get_endpoint(logger, isolation_type: IsolationType, attestation_type: str):
  """
  Get the base URL for the attestation endpoint based on the region.
  """
  current_dir = os.getcwd()
  filename = 'attestation_uri_table.json'
  endpoint_file_path = os.path.join(current_dir, filename)

  endpoint_selector = EndpointSelector(endpoint_file_path, logger)
  return endpoint_selector.get_attestation_endpoint(isolation_type, attestation_type)


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
  attestation_type = attestation_type.lower()

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

  isolation_type = ISOLATION_TYPE_LOOKUP.get(provider_tag, ISOLATION_TYPE_LOOKUP['default'])
  endpoint = get_endpoint(logger, isolation_type, attestation_type)
  logger.info(f"Attestation endpoint: {endpoint}")

  # Log SHA512 of user provided claims
  hash_object = hashlib.sha512(json.dumps(claims).encode('utf-8'))
  hex_dig = hash_object.hexdigest()
  logger.info(f"SHA512 of user provided claims: {hex_dig.upper()}")

  # Build attestation client parameters
  provider = ATTESTATION_PROVIDER_LOOKUP.get(provider_tag, ATTESTATION_PROVIDER_LOOKUP['default'])
  client_parameters = AttestationClientParameters(
    endpoint=endpoint,
    verifier=provider,
    claims=claims,
    api_key=api_key
  )

  # Attest based on user configuration
  attestation_client = AttestationClient(logger, client_parameters)
  if attestation_type in ATTESTATION_METHODS:
    method_name = ATTESTATION_METHODS[attestation_type]
    token = getattr(attestation_client, method_name)()
  else:
    raise AttestException(f"Invalid parameter for attestation type: '{attestation_type}'. \
                          Supported types: {', '.join(ATTESTATION_METHODS.keys())}")

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