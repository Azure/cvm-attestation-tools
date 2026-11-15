# claims.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json

# User claims can be supplied in two forms:
#   - A JSON-serializable value (typically a dict). The bytes bound into the
#     hardware report are produced with json.dumps().
#   - bytes/bytearray holding UTF-8 encoded JSON. These exact bytes are bound
#     into the hardware report, so a relying party can recompute the digest
#     from the same bytes without depending on Python's JSON formatting.
BYTES_TYPES = (bytes, bytearray)


def validate_claims(claims):
  """
  Raises ValueError if byte claims are not UTF-8 encoded JSON.
  """
  if isinstance(claims, BYTES_TYPES) and claims:
    _parse_claims_bytes(claims)


def claims_to_bytes(claims):
  """
  Returns the bytes whose digest is bound into the hardware report,
  or None if no claims were supplied.
  """
  if not claims:
    return None
  if isinstance(claims, BYTES_TYPES):
    return bytes(claims)
  return json.dumps(claims).encode('utf-8')


def claims_to_client_payload(claims):
  """
  Returns the claims as a JSON value for the guest attestation ClientPayload.
  """
  if not claims:
    return {}
  if isinstance(claims, BYTES_TYPES):
    return _parse_claims_bytes(claims)
  return claims


def _parse_claims_bytes(claims):
  try:
    return json.loads(bytes(claims).decode('utf-8'))
  except (UnicodeDecodeError, json.JSONDecodeError) as e:
    raise ValueError(f"Claims bytes must be UTF-8 encoded JSON: {e}") from e
