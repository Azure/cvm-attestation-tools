import click
from AttestationClient import AttestationClient, AttestationClientParameters, Verifier
from src.Isolation import IsolationType
from src.Logger import Logger
from snp import AttestationReport
from src.ImdsClient import ImdsClient
from src.Encoder import Encoder
import json
from src.Quote import Quote
from src.QuoteV4 import QuoteV4
from src.QuoteV5 import QuoteV5


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
    IsolationType.SEV_SNP if t == 'snp_report' else IsolationType.TDX,
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
      file.write(evidence.hardware_report)
    logger.info(f"Report saved to: {filename}")

    logger.info("Got attestation report successfully!")
  elif report_type == 'td_quote':
    try:
      quote = Quote()
      print(quote.deserialize(evidence.hardware_report))
      logger.info("Got TD quote successfully!")

      # Store hardware report
      file_path = 'report.bin'
      with open(file_path, 'wb') as file:
        file.write(evidence.hardware_report)
      logger.info(f"Output successfully written to: {file_path}")

      # Stores the runtime data in a json file
      json_data = json.loads(evidence.runtime_data)
      with open('runtime_data.json', 'w') as file:
        json.dump(json_data, file, indent=2)
        logger.info(f"Output successfully written to: 'runtime_data.json'")
    
    except UnicodeDecodeError:
      logger.error("Failed to decode the TD quote header. Ensure the report is valid.")
      return
    
  else:
    raise ValueError(f"Invalid hardware report type: {report_type}")


if __name__ == "__main__":
  read_report()