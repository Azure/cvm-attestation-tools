# tpm_wrapper.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from hashlib import sha512, sha256
import json
from external.TSS_MSR.src.Tpm import *
from AttestationTypes import *
from external.TSS_MSR.src.Crypt import Crypto as crypto

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


HCL_REPORT_INDEX = '0x01400001'
HCL_USER_DATA_INDEX = '0x1400002'

AIK_CERT_INDEX = '0x01C101D0'
AIK_PUB_INDEX = '0x81000000'

key_out_public = CreatePrimaryResponse()

def sha256_hash_update(data_chunks):
    # Initialize the SHA-256 hash context
    sha256_ctx = sha256()

    # Update the context with each chunk of data
    for pcr in data_chunks:
        print(pcr.index, pcr.digest)
        sha256_ctx.update(pcr.digest)

    # Get the final hash value
    final_hash = sha256_ctx.hexdigest()
    print(final_hash)
    return final_hash

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
  cleanSlots(tpm, TPM_HT.TRANSIENT)
  cleanSlots(tpm, TPM_HT.LOADED_SESSION)

  handle = TPM_HANDLE(index)
  # tpm.allowErrors().EvictControl(TPM_HANDLE.OWNER, handle, handle)
  outPub = tpm.allowErrors().ReadPublic(handle)
  h = outPub
  if (tpm.lastResponseCode == TPM_RC.SUCCESS):
      print("Persistent key 0x" + hex(handle.handle) + " already exists")
  else:
      print("Failed to read Public Area")
  # outPub = outPub.outPublic
  print(''.join('{:02x}'.format(x) for x in outPub.toBytes()))

  tpm.close()
  return outPub.toBytes()


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
  return read_public((int(AIK_PUB_INDEX, 16) + 3))


def get_pcr_quote(pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_select = get_pcr_select(pcr_list)
  sign_handle = TPM_HANDLE(int(AIK_PUB_INDEX, 16) + 3)
  pcr_quote = tpm.Quote(sign_handle, None, TPMS_NULL_SIG_SCHEME(), pcr_select)
  quote_buf = pcr_quote.quoted.toBytes()
  sig_bytes = pcr_quote.signature.sig

  tpm.close()

  return quote_buf, sig_bytes


def get_pcr_select(pcr_list):
  pcr_mask = 0
  for i in pcr_list:
    pcr_mask |= 1 << i

  select = [None] * 3
  select[0] = (pcr_mask & 0xFF) 
  select[1] = (pcr_mask & 0xFF00) >> 8
  select[2] = (pcr_mask & 0xFF0000) >> 16

  pcr_select = [TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, select)]
  return pcr_select


def get_pcr_values(pcr_list):
  tpm = Tpm()
  tpm.connect()
  
  pcr_select = get_pcr_select(pcr_list)

  pcr_values = []
  values = tpm.PCR_Read(pcr_select)
  # print(values.pcrValues)
  index = 0
  for v in values.pcrValues:
    hex_string = ''.join('{:02x}'.format(x) for x in v.buffer)
    # print(v.buffer)
    pcr = PcrValue(index, v.buffer)
    pcr_values.append(pcr)
    # print(index, hex_string)
    index = index + 1
  
  tpm.close()
  return pcr_values


def create_ephemeral_key(pcr_list):
  tpm = Tpm()
  tpm.connect()
  pcr_select = get_pcr_select(pcr_list)

  pcrs = get_pcr_values(pcr_list)

  aes_256 = TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 256, TPM_ALG_ID.CFB)
  rsa_params = TPMS_RSA_PARMS(aes_256, TPMS_SIG_SCHEME_RSAPSS(), 2048, 0)
  attributes = (
    TPMA_OBJECT.decrypt |
    TPMA_OBJECT.fixedTPM |
    TPMA_OBJECT.fixedParent |
    TPMA_OBJECT.sensitiveDataOrigin |
    TPMA_OBJECT.noDA
  )

  in_public = TPMT_PUBLIC(
    nameAlg=TPM_ALG_ID.SHA256,
    objectAttributes=attributes,
    authPolicy=None,
    parameters=rsa_params,
    unique=TPM2B_PUBLIC_KEY_RSA()
  )
  symWrapperDef = TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 256, TPM_ALG_ID.CFB)
  symWrapperTemplate = TPMT_PUBLIC(TPM_ALG_ID.SHA256,
            attributes,
            None,
            TPMS_RSA_PARMS(symWrapperDef, TPMS_ENC_SCHEME_RSAES(), 2048, 0),
            TPM2B_PUBLIC_KEY_RSA())

  # Start a policy session to be used with ActivateCredential()
  nonceCaller = crypto.randomBytes(20)
  respSas = tpm.StartAuthSession(None, None, nonceCaller, None, TPM_SE.TRIAL, NullSymDef, TPM_ALG_ID.SHA256)
  hSess = respSas.handle
  print('DRS >> StartAuthSession(POLICY_SESS) returned ' + str(tpm.lastResponseCode) + '; sess handle: ' + str(hSess.handle))
  sess = Session(hSess, respSas.nonceTPM)

  # Retrieve the policy digest computed by the TPM
  pcr_digest = sha256_hash_update(pcrs)
  resp = tpm.PolicyPCR(hSess, bytes.fromhex(pcr_digest), pcr_select)
  dupPolicyDigest = tpm.PolicyGetDigest(hSess)
  print('DRS >> PolicyGetDigest() returned ' + str(tpm.lastResponseCode))
  print('Digest Size: ', len(pcr_digest))

  
  print(dupPolicyDigest)
  in_public.authPolicy = dupPolicyDigest
  symWrapperTemplate.authPolicy = dupPolicyDigest

  print(base64_encode(bytes.fromhex(pcr_digest)))
  primary = TPM_HANDLE(TPM_RH.OWNER)
  idKey = tpm.CreatePrimary(primary, TPMS_SENSITIVE_CREATE(), in_public, None, pcr_select)
  print('DRS >> CreatePrimary(idKey) returned ' + str(tpm.lastResponseCode))

  if (not idKey.getHandle()):
      raise(Exception("CreatePrimary failed for " + in_public))

  # clear the tpm slots
  cleanSlots(tpm, TPM_HT.TRANSIENT)
  cleanSlots(tpm, TPM_HT.LOADED_SESSION)
  tpm.close()

  return idKey

def get_ephemeral_key(pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_select = get_pcr_select(pcr_list)

  pcrs = get_pcr_values(pcr_list)

  in_public = TPMT_PUBLIC(
            TPM_ALG_ID.SHA256,
            (
              TPMA_OBJECT.decrypt |
              TPMA_OBJECT.fixedTPM |
              TPMA_OBJECT.fixedParent |
              TPMA_OBJECT.sensitiveDataOrigin |
              TPMA_OBJECT.noDA
            ),
            None,
            TPMS_RSA_PARMS(
              TPMT_SYM_DEF_OBJECT(),
              TPMS_NULL_ASYM_SCHEME(),
              2048,
              0),
            TPM2B_PUBLIC_KEY_RSA())

  primary_handle = TPM_HANDLE()
  sign = TPM_HANDLE(int(AIK_PUB_INDEX, 16) + 3)

  # Start a policy session to be used with ActivateCredential()
  nonceCaller = crypto.randomBytes(20)
  respSas = tpm.StartAuthSession(None, None, nonceCaller, None, TPM_SE.TRIAL, NullSymDef, TPM_ALG_ID.SHA256)
  hSess = respSas.handle
  print('DRS >> StartAuthSession(POLICY_SESS) returned ' + str(tpm.lastResponseCode) + '; sess handle: ' + str(hSess.handle))
  sess = Session(hSess, respSas.nonceTPM)

  # Retrieve the policy digest computed by the TPM
  pcr_digest = sha256_hash_update(pcrs)
  resp = tpm.PolicyPCR(hSess, bytes.fromhex(pcr_digest), pcr_select)
  dupPolicyDigest = tpm.PolicyGetDigest(hSess)
  print('DRS >> PolicyGetDigest() returned ' + str(tpm.lastResponseCode))
  print('Digest Size: ', len(pcr_digest))

  session = NullPwSession
  
  print(dupPolicyDigest)
  in_public.authPolicy = dupPolicyDigest

  idKey = tpm.withSession(NullPwSession)  \
              .CreatePrimary(Owner, TPMS_SENSITIVE_CREATE(), in_public, None, pcr_select)
  print('DRS >> CreatePrimary(idKey) returned ' + str(tpm.lastResponseCode))
  # encryption_key = idKey.outPublic.toBytes()

  encryption_key = idKey.outPublic.asTpm2B()
 
  print('CreatePrimary returned ' + str(tpm.lastResponseCode))
  if (not idKey.getHandle()):
      raise(Exception("CreatePrimary failed for " + in_public))

  response = tpm.Certify(idKey.getHandle(), sign, 0, TPMS_NULL_ASYM_SCHEME())
  print('Dat: ', response.certifyInfo.attested)
  buf = TpmBuffer(response.certifyInfo.asTpm2B()).createObj(TPM2B_ATTEST)
  print(buf.attestationData.attested)
  certify_info = response.certifyInfo.toBytes()
  signature = response.signature.sig

  ephemeral_Key = EphemeralKey(encryption_key, certify_info, signature)

  print(idKey.outPublic.unique.buffer)
  # key_out_public = TpmBuffer(idKey.toBytes()).createObj(CreatePrimaryResponse)
  print(key_out_public)
  # clear the tpm slots
  # cleanSlots(tpm, TPM_HT.TRANSIENT)
  cleanSlots(tpm, TPM_HT.LOADED_SESSION)

  tpm.close()

  return ephemeral_Key


def decrypt_with_ephemeral_key(encrypted_data, pcr_list):
  tpm = Tpm()
  tpm.connect()

  pcr_select = get_pcr_select(pcr_list)

  pcrs = get_pcr_values(pcr_list)

  persistent = TPM_HANDLE(0x80000000)
  nonceCaller = crypto.randomBytes(20)
  respSas = tpm.StartAuthSession(None, None, nonceCaller, None, TPM_SE.POLICY, NullSymDef, TPM_ALG_ID.SHA256)
  hSess = respSas.handle
  print('DRS >> StartAuthSession(POLICY_SESS) returned ' + str(tpm.lastResponseCode) + '; sess handle: ' + str(hSess.handle))
  sess = Session(hSess, respSas.nonceTPM)

  # Retrieve the policy digest computed by the TPM
  pcr_digest = sha256_hash_update(pcrs)
  tpm.PolicyPCR(hSess, bytes.fromhex(pcr_digest), pcr_select)
  print('DRS >> PolicyGetDigest() returned ' + str(tpm.lastResponseCode))
  print('Digest Size: ', len(pcr_digest))

  in_scheme =  TPMT_RSA_SCHEME(TPMS_SCHEME_RSAES()).details

  # print(key_out_public.outPublic.parameters.symmetric.keyBits)

  data_plain = "Hello World\n"
  

  att = (
              TPMA_OBJECT.decrypt |
              TPMA_OBJECT.fixedTPM |
              TPMA_OBJECT.fixedParent |
              TPMA_OBJECT.sensitiveDataOrigin |
              TPMA_OBJECT.noDA
            )
  response = tpm.allowErrors().ReadPublic(persistent)
  print(response.outPublic.objectAttributes == att)
  #tpm.allowErrors().EvictControl(TPM_HANDLE.OWNER, hPers, hPers)
  if (tpm.lastResponseCode == TPM_RC.SUCCESS):
      print("Persistent key " + hex(persistent.handle) + " already exists")
      print("Handle Type " + str(persistent.getType().value))
  else:
    print("No Exist")
    pass
  #   h = idKey.handle
  #   tpm.EvictControl(TPM_HANDLE.OWNER, h, persistent)
  #   tpm.FlushContext(h)
  # encryption_key = idKey.outPublic.toBytes()

  try:
    # encrypted = tpm.withSession(sess).RSA_Encrypt(persistent, bytes(data_plain, 'utf-8'), TPMS_NULL_ASYM_SCHEME(), None)
    # print('Encrypted Data Bytes: ', encrypted)
    decrypted_data \
      = tpm.withSession(sess).RSA_Decrypt(persistent, encrypted_data, TPMS_SCHEME_RSAES(), None)
    print('Decrypted Inner Decryption Key...')
    print(decrypted_data)

    tpm.close()
    return decrypted_data
  except Exception as e:
    print("Exception: ", e)
    # clear the tpm slots
    cleanSlots(tpm, TPM_HT.TRANSIENT)
    cleanSlots(tpm, TPM_HT.LOADED_SESSION)

    tpm.close()

  return ""

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