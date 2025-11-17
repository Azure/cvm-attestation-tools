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
def read_report():
  """
  CLI tool to read and optionally save hardware reports.
  """
  logger = Logger('logger').get_logger()

  logger.info("Attestation started...")

  # Initialize attestation client
  client_parameters = AttestationClientParameters(
    endpoint=DEFAULT_ENDPOINT,
    verifier=Verifier.MAA,
    claims='',
    api_key=None
  )
  attestation_client = AttestationClient(logger, client_parameters)

  # Handle the hardware report
  handle_hardware_report(attestation_client)


def handle_hardware_report(attestation_client):
  """
  Handle the hardware report generation and optional saving.
  """
  logger = attestation_client.log
  logger.info(f"Reading hardware report...")

  evidence = attestation_client.get_hardware_evidence()
  logger.info(f"Hardware report type: {evidence.type}")

  # make sure that the hardware report type is the expected one
  if evidence.type not in [IsolationType.SEV_SNP, IsolationType.TDX]:
    raise ValueError(f"Invalid hardware report type: {evidence.type}")

  # check each individual type
  if evidence.type == IsolationType.SEV_SNP:
    try:
      # Retrieve and deserialize the SNP report
      report = AttestationReport.deserialize(evidence.hardware_report)

      # Display the report
      report.display()
      logger.info("Got attestation report successfully!")
    except Exception as e:
      logger.error(f"Failed to parse the SNP report: {e}")
      return
  elif evidence.type == IsolationType.TDX:
    try:
      quote = Quote.from_bytes(evidence.hardware_report)
      print(quote)
      logger.info("Got TD quote successfully!")
    except UnicodeDecodeError:
      logger.error("Failed to decode the TD quote header. Ensure the report is valid.")
      return
    except Exception as e:
      logger.error(f"Failed to parse the TD quote: {e}")
      return

  # Store hardware report
  file_path = 'report.bin'
  with open(file_path, 'wb') as file:
    file.write(evidence.hardware_report)
  logger.info(f"Hardware report successfully written to: {file_path}")

  # Stores the runtime data in a json file
  json_data = json.loads(evidence.runtime_data)
  with open('runtime_data.json', 'w') as file:
    json.dump(json_data, file, indent=2)
    logger.info(f"Runtime Data successfully written to: 'runtime_data.json'")


if __name__ == "__main__":
  read_report()