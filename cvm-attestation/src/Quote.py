# Quote.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from abc import ABC, abstractmethod
import sys
from typing import Optional
from construct import Struct, Int16ul, Bytes


class Quote(ABC):
  """Abstract base class for TD Quote parsing."""

  def __init__(self):
    """
    Initialize the quote. Subclasses should parse data in their constructor.
    """
    self.parsed_data = None

  @abstractmethod
  def serialize(self) -> bytes:
    """
    Serialize the Quote object back to binary format.
    :return: Raw binary quote data
    """
    pass
  
  @abstractmethod
  def deserialize(cls, data: bytes) -> Optional['Quote']:
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
