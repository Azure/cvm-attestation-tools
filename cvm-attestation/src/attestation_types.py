# attestation_types.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from enum import Enum
from base64 import urlsafe_b64encode, b64encode

def base64_encode(data):
  base64_bytes = b64encode(data)
  # Return the base64url encoded string
  return base64_bytes.decode('utf-8')


# The version number of the attestation protocol between the client and the service.
PROTOCOL_VERSION = "2.0"


class TpmInfo:
  def __init__(self, aik_cert=None, aik_pub=None, pcr_quote=None, pcr_sig=None, pcr_values=None, key=None):
    self.aik_cert = aik_cert
    self.aik_pub = aik_pub 
    self.pcr_quote = pcr_quote
    self.pcr_signature = pcr_sig
    self.pcr_values = pcr_values
    self.key = key

  def get_values(self):
    tpm_info = {
      "AikCert": base64_encode(self.aik_cert),
      "AikPub": base64_encode(self.aik_pub),
      "PcrQuote": base64_encode(self.pcr_quote),
      "PcrSignature": base64_encode(self.pcr_signature),
      "EncKeyPub": base64_encode(self.key.encryptionKey),
      "EncKeyCertifyInfo": base64_encode(self.key.certifyInfo),
      "EncKeyCertifyInfoSignature": base64_encode(self.key.certifyInfoSignature),
    }

    pcrs = []
    pcr_set = []
    for pcr_value in self.pcr_values:
      pcr = {
        "Index": pcr_value.index,
        "Digest": base64_encode(pcr_value.digest)
      }

      pcr_set.append(pcr_value.index)
      pcrs.append(pcr)

    tpm_info.update({"PcrSet": pcr_set})
    tpm_info.update({"PCRs": pcrs})

    return tpm_info


class PcrValue:
  def __init__(self, index=0, digest=None):
    self.index = index
    self.digest = digest if digest is not None else bytearray()


class PcrQuote:
  def __init__(self, quote=None, signature=None):
    self.quote = quote
    self.signature = signature


class EphemeralKey:
  def __init__(self, key=None, certifyInfo=None, certifyInfoSig=None):
    self.encryptionKey = key
    self.certifyInfo = certifyInfo
    self.certifyInfoSignature = certifyInfoSig
