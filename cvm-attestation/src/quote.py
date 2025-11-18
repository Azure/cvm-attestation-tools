# quote.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from abc import ABC, abstractmethod
from typing import Optional


class Quote(ABC):
  """Abstract base class for TD Quote parsing."""

  def __init__(self):
    """
    Initialize the quote. Subclasses should parse data in their constructor.
    """
    self.parsed_data = None

  @staticmethod
  def from_bytes(data: bytes) -> 'Quote':
    """
    Factory method to create the appropriate Quote subclass based on version.
    
    :param data: Raw binary quote data
    :return: Instance of QuoteV4 or QuoteV5 based on the version in the data
    :raises ValueError: If the version is unsupported or data is invalid
    
    Example usage:
        quote_data = read_quote_from_file()
        quote = Quote.from_bytes(quote_data)
        print(f"Detected quote version: {quote.version}")
        print(quote)
    """
    if len(data) < 2:
      raise ValueError("Data too short to contain version header")
    
    # Read version from the first 2 bytes (little-endian uint16)
    version = int.from_bytes(data[0:2], byteorder='little')
    
    if version == 4:
      from src.quote_v4 import QuoteV4
      return QuoteV4(data)
    elif version == 5:
      from src.quote_v5 import QuoteV5
      return QuoteV5(data)
    else:
      raise ValueError(f"Unsupported quote version: {version}. Only versions 4 and 5 are supported.")

  @abstractmethod
  def serialize(self) -> bytes:
    """
    Serialize the Quote object back to binary format.
    :return: Raw binary quote data
    """
    pass
  
  @abstractmethod
  def deserialize(self, data: bytes) -> Optional['Quote']:
    """
    Deserializes raw binary data into the appropriate Quote subclass.
    :param data: Raw binary quote data
    :return: Instance of QuoteV4 or QuoteV5 based on the version in the data
    """
    pass

  @abstractmethod
  def __str__(self) -> str:
    """
    String representation of the quote for printing.
    :return: Formatted string with quote details
    """
    pass

  @property
  @abstractmethod
  def version(self) -> int:
    """Return the quote version number."""
    pass
