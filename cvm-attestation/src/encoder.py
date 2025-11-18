# encoder.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from base64 import urlsafe_b64encode, b64decode, b64encode

class Encoder:
  @staticmethod
  def base64url_encode(data):
    """
    Encode data bytes to base64url

    Parameters:
    data (bytes): The data to encode.

    Returns:
    str: The base64url encoded string.
    """

    return str(urlsafe_b64encode(data).rstrip(b'='), "utf-8")
  

  @staticmethod
  def base64url_encode_string(data):
    """
    Encode string to base64url

    Parameters:
    data (str): The data to encode.

    Returns:
    str: The base64url encoded string.
    """

    bytes_to_encode = data.encode('utf-8')
    base64_bytes = b64encode(bytes_to_encode)
    base64url_bytes = base64_bytes.replace(b'+', b'-').replace(b'/', b'_')
    return base64url_bytes.decode('utf-8').rstrip('=')

  @staticmethod
  def base64_encode(data):
    """
    Encode data bytes to base64

    Parameters:
    data (bytes): The data to encode.

    Returns:
    str: The base64 encoded string.
    """
    return str(b64encode(data), "utf-8")
  
  @staticmethod
  def base64_encode_string(data):
    """
    Encode string to base64url

    Parameters:
    data (str): The data to encode.

    Returns:
    str: The base64 encoded string.
    """

    bytes_to_encode = data.encode('utf-8')
    base64_bytes = b64encode(bytes_to_encode)
    return base64_bytes.decode('utf-8')
  
  @staticmethod
  def base64decode(data):
    """
    Decode base64 encoded data string to decoded string

    Parameters:
    data (str): The base64 encoded data to be decoded.

    Returns:
    str: The data decoded string.
    """

    data_bytes = bytes(data, 'utf-8')
    base64_bytes = b64decode(data_bytes)
    return base64_bytes

  @staticmethod
  def base64url_decode(data):
    """
    Decode base64url encoded data string to bytes

    Parameters:
    data (str): The base64url encoded data to be decoded.

    Returns:
    bytes: The decoded data bytes.
    """
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - (len(data) % 4) if (len(data) % 4) else 0
    data += "=" * padding
    return b64decode(data)