# tpm_wrapper.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from  hashlib import sha512
import json
from external.TSS_MSR.src.Tpm import *
import types


HCL_REPORT_INDEX = '0x01400001'
HCL_USER_DATA_INDEX = '0x1400002'

AIK_CERT_INDEX = '0x01C101D0'
AIK_PUB_INDEX = '0x81000000'


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

  tpm.close()

  return hcl_report


def read_public(index):
  tpm = Tpm()
  tpm.connect()
  handle = TPM_HANDLE(int(index, 16) + 3)
  out = tpm.ReadPublic(handle)
  # buf = out.fromTpm(out.outPublic)
  # print()
  # print(out.name)
  # print(''.join('{:02x}'.format(x) for x in out.outPublic.toBytes()))

  tpm.close()
  return out.outPublic.toBytes()


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


def get_aik_cert():
  # read aik cert from nv index
  return read_nv_index(AIK_CERT_INDEX)


def get_aik_pub():
  # read aik pub from nv index
  return read_public(AIK_PUB_INDEX)


def get_pcr_quote(pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_mask = 0
  for i in pcr_list:
    pcr_mask |= 1 << i

  select = [None] * 3
  select[0] = pcr_mask & 0xFF
  select[1] = pcr_mask & 0xFF
  select[2] = pcr_mask & 0xFF

  
  pcr_select = [TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, select)]

  handle = TPM_HANDLE(int(AIK_PUB_INDEX, 16) + 3)
  pcr_quote = tpm.Quote(handle, 0, TPMS_NULL_SIG_SCHEME(), pcr_select)
  quote = {}
  print(pcr_quote.quoted)
  print(pcr_quote.signature)
  quote_buf = pcr_quote.quoted.toBytes()
  print('Quoted: ', ''.join('{:02x}'.format(x) for x in quote_buf))

  signature = pcr_quote.signature.sig
  hash = pcr_quote.signature.hash
  sig_bytes = pcr_quote.signature.toBytes()
  print('Alg: ', hash)
  print('Sig: ', ''.join('{:02x}'.format(x) for x in sig_bytes))

  return quote_buf, sig_bytes


def get_pcr_values(pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_mask = 0
  for i in pcr_list:
    print(i)
    pcr_mask |= 1 << i

  select = [None] * 3
  select[0] = pcr_mask & 0xFF00 >> 8
  select[1] = pcr_mask & 0xFF0000 >> 16
  select[2] = pcr_mask & 0xFF000000 >> 24

  
  pcr_select = [TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, select)]

  pcr_values = []
  values = tpm.PCR_Read(pcr_select)
  # print(values.pcrValues)
  index = 0
  for v in values.pcrValues:
    hex_string = ''.join('{:02x}'.format(x) for x in v.buffer)
    # print(v.buffer)
    pcr = PcrValue(index, v.buffer)
    pcr_values.append(pcr)
    print(index, hex_string)
    index = index + 1
  return pcr_values


def get_ephemeral_key(pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_mask = 0
  for i in pcr_list:
    print(i)
    pcr_mask |= 1 << i

  select = [None] * 3
  select[0] = pcr_mask & 0xFF00 >> 8
  select[1] = pcr_mask & 0xFF0000 >> 16
  select[2] = pcr_mask & 0xFF000000 >> 24
  pcr_select = [TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, select)]

  in_public = TPMT_PUBLIC(
            TPM_ALG_ID.SHA256,
            (TPMA_OBJECT.decrypt |
              TPMA_OBJECT.fixedTPM |
              TPMA_OBJECT.fixedParent |
              TPMA_OBJECT.sensitiveDataOrigin |
              TPMA_OBJECT.noDA),
            None,
            TPMS_RSA_PARMS(
              TPMT_SYM_DEF_OBJECT(),
              TPMS_NULL_SIG_SCHEME(),
              2048,
              0),
            TPM2B_PUBLIC_KEY_RSA())
  
  primary_handle = TPM_HANDLE()
  # tpm.FlushContext(primary_handle)

  cleanSlots(tpm, TPM_HT.PERSISTENT)
  cleanSlots(tpm, TPM_HT.TRANSIENT)
  cleanSlots(tpm, TPM_HT.LOADED_SESSION)

  handle = tpm.CreatePrimary(primary_handle, TPMS_SENSITIVE_CREATE(), in_public, bytearray(0), pcr_select)
  # response = tpm.Create(handle.getHandle(), TPMS_SENSITIVE_CREATE(), in_public, bytearray(0), pcr_select)
  # # print(response.outPrivate)
  # # print(response.outPublic)
  # test = tpm.Load(primary_handle, response.outPrivate, response.outPublic)

  # print('response: ', test.creationData)
  out_public = handle.outPublic
  encryption_key = out_public.toBytes()
  # print()
  print('Enc Key: ', ''.join('{:02x}'.format(x) for x in encryption_key))
  # print()
  # print('Test: ', primary_handle)

  response = tpm.Certify(handle.getHandle(), primary_handle, bytearray(), TPMS_NULL_SIG_SCHEME())
  certify_info = response.certifyInfo.toBytes()
  signature = response.signature.toBytes()

  ephemeral_Key = EphemeralKey(encryption_key, certify_info, signature)

  # clear the tpm slots
  cleanSlots(tpm, TPM_HT.PERSISTENT)
  cleanSlots(tpm, TPM_HT.TRANSIENT)
  cleanSlots(tpm, TPM_HT.LOADED_SESSION)

  tpm.close()

  return ephemeral_Key

def cleanSlots(tpm, slotType):
    caps = tpm.GetCapability(TPM_CAP.HANDLES, slotType << 24, 8)
    handles = caps.capabilityData

    if len(handles.handle) == 0:
        print("No dangling", slotType, "handles")
    else:
        for h in handles.handle:
            print("Dangling", slotType, "handle 0x" + hex(h.handle))
            if slotType == TPM_HT.PERSISTENT:
                tpm.allowErrors().EvictControl(TPM_HANDLE.OWNER, h, h)
                if tpm.lastResponseCode not in [TPM_RC.SUCCESS, TPM_RC.HIERARCHY]:
                    raise(tpm.lastError)
            else:
                tpm.FlushContext(h)
# cleanSlots()