# OsInfo.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from enum import Enum


DISTRO_NAME_KEY = "NAME";
DISTRO_VERSION_KEY = "VERSION_ID";
LINUX_OS_BUILD = "NotApplication";


class OsType(Enum):
  INVALID = 0
  LINUX = 1
  WINDOWS = 2


class OsInfo:
  def __init__(self, os=None):
    # self.type = type if type is not None else OsType.INVALID
    self.distro_name = ""
    # self.build = build
    self.distro_version_major = 0
    self.distro_version_minor = 0
    if os == "Linux":
      self.parse_os_info(self.get_os_info())

    def validate(self):
      # Add your validation logic here
      return None==None

  def to_json(self):
    # Add your JSON conversion logic here
    pass


  # Function to parse NAME and VERSION_ID
  def parse_os_info(self, os_info):
    self.distro_name = os_info.get('NAME')
    version = os_info.get('VERSION_ID')
    self.distro_version_major, self.distro_version_minor = version.strip().split('.', 1)

  def get_os_info(self):
    os_info = {}
    with open('/etc/os-release') as f:
      for line in f:
        key, value = line.strip().split('=', 1)
        os_info[key] = value.strip('"')

    print(os_info)
    return os_info
