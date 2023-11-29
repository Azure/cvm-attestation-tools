'''
    Attestation Report parser helpers
'''

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

REPORT_TYPE = {
  0: 'invalid_report',
  1: 'reserved',
  2: 'snp',
  3: 'tvm',
  4: 'tdx'
}

def extract_report_type(report):
  list = []
  for i in range(HCL_REPORT_TYPE_OFFSET_START, HCL_REPORT_TYPE_OFFSET_START + 4):
    list.append(report[i])

  request_type = int.from_bytes(bytes(list), byteorder='little', signed=False)
  return REPORT_TYPE[request_type]

def extract_hw_report(report):
  list = []
  hw_report_size = 0
  report_type = extract_report_type(report)

  if report_type == 'tdx':
    hw_report_size = TD_REPORT_SIZE
  elif report_type == 'snp':
    hw_report_size = SNP_REPORT_SIZE

  for i in range(HW_REPORT_START, HW_REPORT_START + hw_report_size):
    list.append(report[i])

  return bytes(list)


def extract_runtime_data(report):
  data_size_bytes = []

  # extract bytes of the runtime data size to know its length
  for t in range(RUNTIME_DATA_SIZE_OFFSET, RUNTIME_DATA_SIZE_OFFSET + 4):
    data_size_bytes.append(report[t])
  data_size = int.from_bytes(bytes(data_size_bytes), byteorder='little', signed=False)
  runtime_data_bytes = []

  # extract bytes of the runtime data
  for i in range(RUNTIME_DATA_OFFSET, RUNTIME_DATA_OFFSET + data_size):
    runtime_data_bytes.append(report[i])

  return bytes(runtime_data_bytes)
