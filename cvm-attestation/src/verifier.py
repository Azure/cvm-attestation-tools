# verifier.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import requests
import json
import logging
from abc import ABC, abstractmethod
from src.Isolation import *
from src.Logger import *

DEFAULT_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
DEFAULT_VERIFIERS = {
  'maa_tdx': {
    'host': 'https://sharedweu.weu.attest.azure.net',
    'path': '/attest/TdxVm',
    'version': 'api-version=2023-04-01-preview', 
  },
  'maa_snp': {
    'host': 'https://sharedweu.weu.attest.azure.net',
    'path': '/attest/SevSnpVm',
    'version': 'api-version=2022-08-01'
  },
  'ita': {
    'host': 'https://api.trustauthority.intel.com',
    'path': '/appraisal/v1/attest'
  }
}

def get_endpoint(verifier):
  obj = DEFAULT_VERIFIERS[verifier]
  endpoint = obj.get('host') + obj.get('path')

  if 'version' in obj:
    endpoint = endpoint + '?' + obj.get('version')
  return endpoint


def create_payload(verifier, evidence, runtimes_data):
  payload = ''
  if verifier == 'maa_tdx':
    payload = {
      'quote': evidence,
      'runtimeData': {
        'data': runtimes_data,
        'dataType': 'JSON'
      }
    }
  elif verifier == 'maa_snp':
    payload = {
      'report': evidence,
      'runtimeData': {
        'data': runtimes_data,
        'dataType': 'JSON'
      }
    }
  elif verifier == 'ita':
    payload = {
      'quote': evidence
    }
  else:
    print('Invalid attestation provider')
  return payload


def verify_evidence(config):
  evidence = config['evidence']
  runtime_data = config['runtime_data']
  verifier_type = config['verifier'] or 'maa_tdx'
  api_key = '' or config['api_key']
  endpoint = '' or config['endpoint']

  payload = create_payload(verifier_type, evidence, runtime_data)
  headers = DEFAULT_HEADERS

  if api_key:
    headers['x-api-key'] = api_key

  print("Sending request to Attestation Provider")
  response = requests.post(
    endpoint if endpoint else get_endpoint(verifier_type),
    data = json.dumps(payload),
    headers = headers)

  if response.status_code == 200:
    response_json = json.loads(response.text)

    print("Got response from Attestation Provider")
    print()
    print("TOKEN: \n")
    print(response_json['token'])
    encoded_token = response_json['token']
    return encoded_token
  else:
    logging.error('Failed to verify evidence, error: ', response.text)


def verify_guest_evidence(config):
  evidence = config['evidence']
  endpoint = config['endpoint']
  print(endpoint)

  headers = DEFAULT_HEADERS

  print("Sending request to Attestation Provider")
  response = requests.post(
    endpoint,
    data = json.dumps(evidence),
    headers = headers)

  if response.status_code == 200:
    response_json = json.loads(response.text)

    print("Got response from Attestation Provider")
    print()
    print("TOKEN: \n")
    print(response_json['token'])
    encoded_token = response_json['token']
    return encoded_token
  else:
    logging.error('Failed to verify evidence, error: ', response.text)


def print_vm_configuration(claims):
  print("CVM Configuration:")
  print("\tConsole Enabled: ", claims['x-ms-runtime']['vm-configuration']['console-enabled'])
  print("\tSecure Boot Enabled: ", claims['x-ms-runtime']['vm-configuration']['secure-boot'])
  print("\tTPM Enabled: ", claims['x-ms-runtime']['vm-configuration']['tpm-enabled'])
  print("\tUser Data: ", claims['x-ms-runtime']['user-data'])


def print_x_ms_fields(claims):
  print("\tAttestation Type: ", claims['x-ms-attestation-type'])
  print("\tStatus: ", claims['x-ms-compliance-status'])

def print_tdx_maa_claims(claims):
  if claims['x-ms-compliance-status'] == 'azure-compliant-cvm':
    print()
    print("Attested Platform Successfully!!")

  print()
  print("Claims:")
  print_x_ms_fields(claims)
  print("\tTCB Status: ", claims['attester_tcb_status'])
  print("\tTCB SVN: ", claims['tdx_tee_tcb_svn'])
  print()
  print_vm_configuration(claims)
  print("\tTPM Persisted: ", claims['x-ms-runtime']['vm-configuration']['tpm-persisted'])


def print_tdx_ita_claims(claims):
  if claims['attester_tcb_status'] == 'UpToDate':
    print()
    print("Attested Platform Successfully!!")

  print()
  print("Claims:")
  print("\tTCB Status: ", claims['attester_tcb_status'])
  print("\tTDX Debuggable: ", claims['tdx_is_debuggable'])
  print("\tEvidence Type: ", claims['attester_type'])
  print()


def print_snp_claims(claims):
  if claims['x-ms-compliance-status'] == 'azure-compliant-cvm':
    print()
    print("Attested Platform Successfully!!")

  print()
  print("Claims:")
  print_x_ms_fields(claims)
  print("\tBootloader SVN: ", claims['x-ms-sevsnpvm-bootloader-svn'])
  print("\tGuest SVN: ", claims['x-ms-sevsnpvm-guestsvn'])
  print("\tMicrocode SVN: ", claims['x-ms-sevsnpvm-microcode-svn'])
  print()
  print_vm_configuration(claims)
  print()

def print_token_claims(claims, verfier='maa'):
  if verfier == 'maa_tdx':
    print_tdx_maa_claims(claims)
  elif verfier == 'ita':
    print_tdx_ita_claims(claims)
  elif verfier == 'maa_snp':
    print_snp_claims(claims)
  else:
    logging.error('Invalid verifier')


class AttestationProvider:
    def __init__(self, verifier, isolation, endpoint, api_key=None):
        self.verifier = verifier
        self.isolation = isolation
        self.endpoint = endpoint
        self.api_key = api_key

    def get_provider(self):
        provider_lookup = {
            'maa_tdx': 'MAA',
            'maa_snp': 'MAA',
            'ita': 'ITA',
            'default': 'UNDEFINED'
        }
        return provider_lookup.get(self.verifier, provider_lookup['default'])

    def get_isolation(self):
        isolation_lookup = {
            'maa_tdx': 'TDX',
            'maa_snp': 'SEV_SNP',
            'ita': 'TDX',
            'default': 'UNDEFINED'
        }
        return isolation_lookup.get(self.verifier, isolation_lookup['default'])

# Usage example:
attestation = AttestationProvider(verifier='maa_tdx', isolation='TDX', endpoint='https://api.example.com', api_key='12345')
provider = attestation.get_provider()
isolation = attestation.get_isolation()