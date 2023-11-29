from  hashlib import sha512
import json
from external.TSS_MSR.src.Tpm import *


HCL_REPORT_INDEX = '0x01400001'
HCL_USER_DATA_INDEX = '0x1400002'


# write user data to nv index
def write_to_nv_index(index, user_data):
  tpm = Tpm()
  tpm.connect()

  attributes =  TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD
  attributes |=  TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD

  auth = TPM_HANDLE(TPM_RH.OWNER)
  nvIndex = TPM_HANDLE(int(index, 16))
  handle = TPMS_NV_PUBLIC(nvIndex, TPM_ALG_ID.SHA256, attributes, None, 64)

  # undefine nv space if its defined
  try:
    tpm.NV_UndefineSpace(auth, nvIndex)
  except:
    print('Index is not defined yet')

  # define the nv idex to write the user data
  tpm.NV_DefineSpace(auth, None, handle)
  tpm.NV_Write(auth, nvIndex, user_data, 0)

  data = tpm.NV_Read(auth, nvIndex , 64, 0)
  if len(data) != 0:
    print('Wrote data successfully')

  tpm.close()


def read_nv_index(index):
  tpm = Tpm()
  tpm.connect()

  handle = TPM_HANDLE(int(index, 16))
  response = tpm.NV_ReadPublic(handle)
  auth = TPM_HANDLE(TPM_RH.OWNER)

  total_bytes_to_read = response.nvPublic.dataSize
  bytes_read = 0
  buffer_size = 1024

  # store the hcl report
  hcl_report = b''

  while bytes_read < total_bytes_to_read:
    # Calculate how many bytes to read in this iteration
    bytes_to_read = min(buffer_size, total_bytes_to_read - bytes_read)

    # Read the data into the buffer
    data = tpm.NV_Read(auth, handle , bytes_to_read, bytes_read)
    hcl_report = hcl_report + data

    # Update the total bytes read
    bytes_read += bytes_to_read
  return hcl_report


def get_hcl_report(user_data):
  print('Getting hcl report from vTPM...')

  if user_data:
    hash_bytes = sha512(json.dumps(user_data).encode('utf-8')).digest()
    write_to_nv_index(HCL_USER_DATA_INDEX, hash_bytes)

  # read hcl report from nv index
  hcl_report = read_nv_index(HCL_REPORT_INDEX)

  if hcl_report:
    print('Got HCL Report from vTPM!')
  else:
    print('Error while getting HCL report')

  return hcl_report