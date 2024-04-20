# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from base64 import urlsafe_b64encode, b64encode
import json
import jwt
import click
from tpm_wrapper import get_aik_cert, get_aik_pub, get_pcr_quote, get_pcr_values

# The version number of the attestation protocol between the client and the service.
PROTOCOL_VERSION = "2.0"

# List of PCR values for each OS Type
LINUX_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7]
WINDOWS_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14]


def base64url_encode(data):
  return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")


# Function to encode a string to base64url
def base64url_encode_string(input_string):
    # Convert string to bytes
    bytes_to_encode = input_string.encode('utf-8')
    # Perform base64 encoding
    base64_bytes = b64encode(bytes_to_encode)
    # Convert to base64url by replacing '+' with '-' and '/' with '_'
    base64url_bytes = base64_bytes.replace(b'+', b'-').replace(b'/', b'_')
    # Return the base64url encoded string
    return base64url_bytes.decode('utf-8')

class GuestAttestationParameters:
  def __init__(self, os_info=None, tcg_logs=None, tpm_info=None, isolation=None):
    self.os_info = os_info
    self.tcg_logs = tcg_logs
    self.tpm_info = tpm_info
    self.isolation = isolation
  
  def toJson(self):
    os_info = self.os_info

    parameters = {
      'AttestationProtocolVersion': PROTOCOL_VERSION,
      'OSType': base64url_encode_string(str(os_info.type)),
      'OSDistro': base64url_encode_string(os_info.distro_name),
      'OSVersionMajor': base64url_encode_string(str(os_info.major_version)),
      'OSVersionMinor': base64url_encode_string(str(os_info.minor_version)),
      'OSBuild': base64url_encode_string(os_info.build),
      'TcgLogs': base64url_encode(self.tcg_logs),
      'ClientPayload': base64url_encode_string(""),
      # 'TpmInfo': base64url_encode(self.tpm_info.toJson()),
      'IsolationInfo': base64url_encode_string(self.isolation.to_json())
    }

    return json.dumps(parameters)

# def get_tpm_info():
#   aik_cert = get_aik_cert()
#   aik_pub = get_aik_pub()

# #   pcr_list = []
    

#   # get pcr list base of system
#   pcr_quote = get_pcr_quote(LINUX_PCR_LIST)
#   print(pcr_quote)

#   pcr_values = get_pcr_values(LINUX_PCR_LIST)
#   print(pcr_values)

