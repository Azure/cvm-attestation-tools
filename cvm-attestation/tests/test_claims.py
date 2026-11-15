# test_claims.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from hashlib import sha512

import pytest
from unittest.mock import MagicMock, patch

from src.attestation_client import AttestationClientParameters, Verifier
from src.claims import claims_to_bytes, claims_to_client_payload, validate_claims
from src.isolation import IsolationType
from src.tpm_wrapper import TssWrapper, HCL_USER_DATA_INDEX


CLAIMS_DICT = {"nonce": "abc", "count": 1}
# Deliberately not the json.dumps() formatting of CLAIMS_DICT
CLAIMS_BYTES = b'{"nonce":"abc","count":1}'


def test_dict_claims_are_serialized_with_json_dumps():
  assert claims_to_bytes(CLAIMS_DICT) == json.dumps(CLAIMS_DICT).encode('utf-8')
  assert claims_to_client_payload(CLAIMS_DICT) == CLAIMS_DICT


@pytest.mark.parametrize("claims", [CLAIMS_BYTES, bytearray(CLAIMS_BYTES)])
def test_byte_claims_are_used_exactly(claims):
  assert claims_to_bytes(claims) == CLAIMS_BYTES
  assert claims_to_client_payload(claims) == CLAIMS_DICT


@pytest.mark.parametrize("claims", [None, {}, '', b''])
def test_empty_claims(claims):
  assert claims_to_bytes(claims) is None
  assert claims_to_client_payload(claims) == {}


@pytest.mark.parametrize("claims", [b'not json', b'\xff\xfe'])
def test_invalid_byte_claims_are_rejected(claims):
  with pytest.raises(ValueError):
    validate_claims(claims)
  with pytest.raises(ValueError):
    AttestationClientParameters(
      "https://test.attest.azure.net", Verifier.MAA, IsolationType.SEV_SNP, claims=claims)


@pytest.mark.parametrize("claims, expected_hashed_bytes", [
  (CLAIMS_DICT, json.dumps(CLAIMS_DICT).encode('utf-8')),
  (CLAIMS_BYTES, CLAIMS_BYTES),
])
def test_get_hcl_report_binds_claims_digest(claims, expected_hashed_bytes):
  tss_wrapper = TssWrapper(MagicMock())
  with patch.object(TssWrapper, 'write_to_nv_index') as mock_write, \
       patch.object(TssWrapper, 'read_nv_index', return_value=b'hcl_report'):
    assert tss_wrapper.get_hcl_report(claims) == b'hcl_report'

  mock_write.assert_called_once_with(HCL_USER_DATA_INDEX, sha512(expected_hashed_bytes).digest())
