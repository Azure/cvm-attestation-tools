# os_info.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import platform


DISTRO_NAME_KEY = "NAME";
DISTRO_VERSION_KEY = "VERSION_ID";
LINUX_OS_BUILD = "NotApplication"
WINDOWS_OS_BUILD = "NotApplication"

# List of PCR values for each OS Type
LINUX_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7]
WINDOWS_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14]


class OsTypeException(Exception):
  pass


class OsInfo:
  def __init__(self, os=None):
    self.type = OsInfo.get_os()
    self.distro_name = ""
    self.build = ""
    self.major_version = 0
    self.minor_version = 0

    # Check system we are running to get the right parameters
    if self.type == "Linux":
      self.build = LINUX_OS_BUILD
      self.pcr_list = LINUX_PCR_LIST
      self.parse_linux_os_info(self.get_linux_os_info())
    elif self.type == 'Windows':
      self.build = WINDOWS_OS_BUILD
      self.pcr_list = WINDOWS_PCR_LIST
      self.major_version = 10
      self.minor_version = 0
    else:
      raise OsTypeException('Unknown OS')

  @staticmethod
  def get_os():
    os_name = platform.system()
    if os_name == 'Windows':
      return 'Windows'
    elif os_name == 'Linux':
      return 'Linux'
    else:
      raise OsTypeException('Unknown OS')

  def validate(self):
    return True

  def get_os_info_values(self):
    os_info = {
      'OSType': self.type,
      'OSDistro': self.distro_name,
      'OSVersionMajor': self.major_version,
      'OSVersionMinor': self.minor_version,
      'OSBuild': self.build,
    }
    return os_info


  # Function to parse NAME and VERSION_ID
  def parse_linux_os_info(self, os_info):
    self.distro_name = os_info.get('NAME')
    version = os_info.get('VERSION_ID')
    self.major_version, self.minor_version = version.strip().split('.', 1)


  def get_linux_os_info(self):
    os_info = {}
    with open('/etc/os-release') as f:
      for line in f:
        key, value = line.strip().split('=', 1)
        os_info[key] = value.strip('"')

    return os_info