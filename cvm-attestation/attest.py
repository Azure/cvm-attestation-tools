from base64 import urlsafe_b64encode
import json
import jwt
import click
from src.report_parser import *
import tpm_wrapper
import src.imds
import src.verifier

def base64url_encode(data):
  return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")


def parse_config_file(filename):
  with open(filename, 'r') as json_file:
      # Parse the JSON data
      data = json.load(json_file)
  return data

def get_cert_chain():
  response = src.imds.get_vcek_certificate()
  return extract_cert_chain(response)

@click.command()
@click.option('--c', type=str)
def main(c):
  print("Attestation client started...")
  print(c)
  print()

  config_json = parse_config_file(c)

  # Extract data from HCL report
  hcl_report = tpm_wrapper.get_hcl_report(config_json['claims'])
  report_type = extract_report_type(hcl_report)
  runtime_data = extract_runtime_data(hcl_report)
  hw_report = extract_hw_report(hcl_report)

  # Set request data based on the platform
  encoded_report = base64url_encode(hw_report)
  encoded_runtime_data = base64url_encode(runtime_data)
  encoded_token = ""
  encoded_hw_evidence = ""
  if report_type == 'tdx':
    encoded_hw_evidence = src.imds.get_td_quote(encoded_report)
  elif report_type == 'snp':
    cert_chain = src.imds.get_vcek_certificate()
    snp_report = {
      'SnpReport': encoded_report,
      'VcekCertChain': base64url_encode(cert_chain)
    }
    snp_report = json.dumps(snp_report)
    snp_report = bytearray(snp_report.encode('utf-8'))
    encoded_hw_evidence = base64url_encode(snp_report)
  else:
    print('error')

  # Verify hardware evidence
  encoded_token = src.verifier.verify_evidence({
    'evidence': encoded_hw_evidence,
    'runtime_data': encoded_runtime_data,
    'verifier': config_json['attestation_provider'],
    'api_key': config_json['api_key'],
    'endpoint': config_json['attestation_url']
  })

  # Print claims
  try:
    claims = jwt.decode(encoded_token, options={"verify_signature": False})

    src.verifier.print_token_claims(claims, config_json['attestation_provider'])
  except:
    print('Error while parsing jwt')

if __name__ == "__main__":
  main()