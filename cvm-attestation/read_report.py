import click
from AttestationClient import AttestationClient, AttestationClientParameters, Verifier
from src.Isolation import IsolationType
from src.Logger import Logger
from snp import SNP_VM_REPORT


DEFAULT_ENDPOINT = 'https://sharedweu.weu.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01'

@click.command()
@click.option(
  '--t', '-type',
  type=click.Choice(['snp_report', 'td_quote'], case_sensitive=True),
  required=True,
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
    IsolationType.SEV_SNP,
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

  if report_type == 'snp_report':
    # Retrieve and deserialize the SNP report
    report_binary = attestation_client.get_hardware_report()
    report = SNP_VM_REPORT.deserialize(report_binary)

    # Display the report
    report.display()

    # Optionally save the report to a file
    if output_path:
      save_to_file(output_path, report_binary)
      logger.info(f"Report saved to: {output_path}")

    elif report_type == 'td_quote':
      logger.info("TD Quote report option is not implemented yet.")
    else:
      raise ValueError(f"Invalid hardware report type: {report_type}")


def save_to_file(file_path, content):
  """
  Save binary content to the specified file path.
  """
  with open(file_path, 'wb') as file:
    file.write(content)
  print(f"Output successfully written to: {file_path}")


if __name__ == "__main__":
  read_report()