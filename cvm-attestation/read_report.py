import click
from AttestationClient import AttestationClient, AttestationClientParameters, Verifier
from src.Isolation import IsolationType
from src.Logger import Logger
from snp import AttestationReport
from src.ImdsClient import ImdsClient
from src.Encoder import Encoder
from deserialize_tdx import deserialize_td_quote, print_td_quote
import os


DEFAULT_ENDPOINT = 'https://sharedweu.weu.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01'

@click.command()
@click.option(
  '--t', '-type',
  type=click.Choice(['snp_report', 'td_quote'], case_sensitive=True),
  default='snp_report',
  help='Specify the type of hardware report to dump: snp_report or td_quote.'
)
@click.option(
  '--o', '-out',
  type=click.Path(writable=True, dir_okay=False),
  required=False,
  help='Specify the file path to store the output (optional).'
)
def read_report(t, o):
  """
  CLI tool to read and optionally save hardware reports.
  """
  logger = Logger('logger').get_logger()

  logger.info("Attestation started...")
  logger.info(f"Report type selected: {t}")

  # Initialize attestation client
  client_parameters = AttestationClientParameters(
    DEFAULT_ENDPOINT,
    Verifier.MAA,
    IsolationType.TDX, #was SEV_SNP
    ''
  )
  attestation_client = AttestationClient(logger, client_parameters)

  # Handle the hardware report
  handle_hardware_report(t, o, attestation_client)


def handle_hardware_report(report_type, output_path, attestation_client):
  """
  Handle the hardware report generation and optional saving.
  """
  logger = attestation_client.log
  logger.info(f"Reading hardware report: {report_type}")
  evidence = attestation_client.get_hardware_evidence()
  if report_type == 'snp_report':
    # Retrieve and deserialize the SNP report
    report = AttestationReport.deserialize(evidence.hardware_report)

    # Display the report
    report.display()

    filename = 'report.bin'
    # Optionally save the report to a file
    if output_path:
      filename = output_path

    with open(filename, 'wb') as file:
      file.write(report_binary)
    logger.info(f"Report saved to: {filename}")

    logger.info("Got attestation report successfully!")
  elif report_type == 'td_quote':
    imds_client = ImdsClient(logger)
    hw_report = evidence.hardware_report
    encoded_hw_report = Encoder.base64url_encode(hw_report)
    encoded_hw_evidence = imds_client.get_td_quote(encoded_hw_report)
    td_quote = Encoder.base64url_decode(encoded_hw_evidence)
    print("length of td_quote:", len(td_quote))
    deserialized_td_quote = deserialize_td_quote(td_quote)
    print_td_quote(deserialized_td_quote)
  else:
    raise ValueError(f"Invalid hardware report type: {report_type}")


if __name__ == "__main__":
  read_report()