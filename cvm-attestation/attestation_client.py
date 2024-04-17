# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from base64 import urlsafe_b64encode
import json
import jwt
import click
from tpm_wrapper import get_aik_cert, get_aik_pub, get_pcr_quote, get_pcr_values


LINUX_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7]
WINDOWS_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14]

def base64url_encode(data):
  return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")


def get_tpm_info(system):
  aik_cert = get_aik_cert()
  aik_pub = get_aik_pub()

#   pcr_list = []
    

  # get pcr list base of system
  pcr_quote = get_pcr_quote(LINUX_PCR_LIST)
  print(pcr_quote)

  pcr_values = get_pcr_values(LINUX_PCR_LIST)
  print(pcr_values)

