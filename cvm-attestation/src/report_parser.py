# report_parser.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from src.isolation import IsolationType

# byte offset of the td report
HW_REPORT_START = 32
HW_REPORT_END = 1216

# Hardware report sizes
TD_REPORT_SIZE = 1024
SNP_REPORT_SIZE = HW_REPORT_END - HW_REPORT_START

# byte offset of hcl data
HCL_DATA_OFFSET = 1216
HCL_REPORT_TYPE_OFFSET = 8
HCL_REPORT_TYPE_OFFSET_START = HCL_DATA_OFFSET + HCL_REPORT_TYPE_OFFSET
HCL_REQUEST_DATA_SIZE_OFFSET = 16
RUNTIME_DATA_SIZE_OFFSET = HCL_DATA_OFFSET + HCL_REQUEST_DATA_SIZE_OFFSET

# byte offset of the runtime data
HCL_REQUEST_DATA_OFFSET = 20
RUNTIME_DATA_OFFSET = HCL_DATA_OFFSET + HCL_REQUEST_DATA_OFFSET

# Map integer report types returned from HCL to IsolationType enum
REPORT_TYPE = {
  0: 'invalid_report',
  1: IsolationType.VBS,
  2: IsolationType.SEV_SNP,
  3: IsolationType.TRUSTED_LAUNCH,
  4: IsolationType.TDX
}

# Map report types to their sizes
REPORT_SIZE = {
  IsolationType.TDX: TD_REPORT_SIZE,
  IsolationType.SEV_SNP: SNP_REPORT_SIZE
}

class ReportParser:
  @staticmethod
  def extract_report_type(report):
    """
    Extract the report type from the HCL report blob

    Parameters:
    report (bytes): The HCL report blob.

    Returns:
    str: The report type as string based on REPORT_TYPE table
    """
    list = []
    for i in range(HCL_REPORT_TYPE_OFFSET_START, HCL_REPORT_TYPE_OFFSET_START + 4):
      list.append(report[i])

    request_type = int.from_bytes(bytes(list), byteorder='little', signed=False)
    return REPORT_TYPE[request_type]


  @staticmethod
  def extract_hw_report(report):
    """
    Extract the the hardware report blob from the HCL report blob

    Parameters:
    report (bytes): The HCL report blob.

    Returns:
    bytes: The hardware report blob bytes
    """
    list = []
    hw_report_size = 0
    report_type = ReportParser.extract_report_type(report)

    if report_type not in REPORT_SIZE:
      raise ValueError(f"Unsupported report type: {report_type}")

    hw_report_size = REPORT_SIZE[report_type]
    for i in range(HW_REPORT_START, HW_REPORT_START + hw_report_size):
      list.append(report[i])

    return bytes(list)


  @staticmethod
  def extract_runtimes_data(report):
    """
    Extract the the runtimes data from the HCL report blob

    Parameters:
    report (bytes): The HCL report blob.

    Returns:
    bytes: The runtimes data bytes
    """
    data_size_bytes = []

    # extract bytes of the runtime data size to know its length
    for t in range(RUNTIME_DATA_SIZE_OFFSET, RUNTIME_DATA_SIZE_OFFSET + 4):
      data_size_bytes.append(report[t])
    data_size = int.from_bytes(bytes(data_size_bytes), byteorder='little', signed=False)
    runtimes_data_bytes = []

    # extract bytes of the runtime data
    for i in range(RUNTIME_DATA_OFFSET, RUNTIME_DATA_OFFSET + data_size):
      runtimes_data_bytes.append(report[i])

    return bytes(runtimes_data_bytes)
