# tpm_wrapper.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from hashlib import sha512, sha256
import json
from external.TSS_MSR.src.Tpm import *
from AttestationTypes import *
from external.TSS_MSR.src.Crypt import Crypto as crypto
from src.Logger import Logger

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


HCL_REPORT_INDEX = '0x01400001'
HCL_USER_DATA_INDEX = '0x1400002'

AIK_CERT_INDEX = '0x01C101D0'
AIK_PUB_INDEX = '0x81000000'

class TssWrapper:
  def __init__(self, logger: Logger):
    self.log = logger

  @staticmethod
  def sha256_hash_update(data_chunks):
    # Initialize the SHA-256 hash context
    sha256_ctx = sha256()

    # Update the context with each chunk of data
    for pcr in data_chunks:
      sha256_ctx.update(pcr.digest)

    # Get the final hash value
    final_hash = sha256_ctx.hexdigest()
    return final_hash

  # write user data to nv index
  def write_to_nv_index(self, index, user_data):
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
      self.log.info('Index is not defined yet')

    # define the nv idex to write the user data
    tpm.NV_DefineSpace(auth, None, handle)
    tpm.NV_Write(auth, nvIndex, user_data, 0)

    data = tpm.NV_Read(auth, nvIndex , 64, 0)
    if len(data) != 0:
      self.log.info('Wrote data successfully')

    tpm.close()


  def read_nv_index(self, index):
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


  def read_public(self, index):
    tpm = Tpm()
    tpm.connect()

    handle = TPM_HANDLE(index)
    outPub = tpm.allowErrors().ReadPublic(handle)
    h = outPub
    if (tpm.lastResponseCode == TPM_RC.SUCCESS):
      self.log.info("Persistent key 0x" + hex(handle.handle) + " already exists")
    else:
      self.log.info("Failed to read Public Area")


    tpm.close()
    return outPub.toBytes()


  def get_hcl_report(self, user_data):
    self.log.info('Getting hcl report from vTPM...')

    if user_data:
      hash_bytes = sha512(json.dumps(user_data).encode('utf-8')).digest()
      self.write_to_nv_index(HCL_USER_DATA_INDEX, hash_bytes)

    # read hcl report from nv index
    hcl_report = self.read_nv_index(HCL_REPORT_INDEX)

    if hcl_report:
      self.log.info('Got HCL Report from vTPM!')
    else:
      self.log.info('Error while getting HCL report')

    return hcl_report


  def get_aik_cert(self):
    # read aik cert from nv index
    return self.read_nv_index(AIK_CERT_INDEX)


  def get_aik_pub(self):
    # read aik pub from nv index
    return self.read_public((int(AIK_PUB_INDEX, 16) + 3))


  def get_pcr_quote(self, pcr_list):
    tpm = Tpm()
    tpm.connect()

    pcr_select = self.get_pcr_select(pcr_list)
    sign_handle = TPM_HANDLE(int(AIK_PUB_INDEX, 16) + 3)

    self.get_pcr_values(pcr_list)
    pcr_quote = tpm.Quote(sign_handle, None, TPMS_NULL_SIG_SCHEME(), pcr_select)

    quote_buf = pcr_quote.quoted.toBytes()
    self.log.info('Quoted: ', ''.join('{:02x}'.format(x) for x in quote_buf))

    sig_bytes = pcr_quote.signature.sig
    self.log.info('Sig: ', ''.join('{:02x}'.format(x) for x in sig_bytes))

    tpm.close()

    return quote_buf, sig_bytes


  def get_pcr_select(pcr_list):
    pcr_mask = 0
    for i in pcr_list:
      pcr_mask |= (1 << i)

    select = [None] * 3
    select[0] = (pcr_mask & 0xFF) 
    select[1] = (pcr_mask & 0xFF00) >> 8
    select[2] = (pcr_mask & 0xFF0000) >> 16

    pcr_select = [TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, select)]
    return pcr_select


  def get_pcr_values(self, pcr_list):
    tpm = Tpm()
    tpm.connect()

    self.log.info('Reading PCR Values')
    
    pcr_select = self.get_pcr_select(pcr_list)

    pcr_values = []
    pcr_values_count = 0
    maskSum = 1
    while maskSum != 0:
      ret = tpm.PCR_Read(self, pcr_select)
      self.log.info("here")
      pcrUpdateCounter = ret.pcrUpdateCounter
      pcrVals = ret.pcrValues
      pcrSel = ret.pcrSelectionOut

      if pcrVals and pcrSel:
        index = 0
        for value in pcrVals:
          hex_string = ''.join('{:02x}'.format(x) for x in value.buffer)
          pcr = PcrValue(pcr_values_count, value.buffer)
          pcr_values.insert(pcr_values_count, pcr)
          index = index + 1
          pcr_values_count = pcr_values_count + 1

        pcr_values_count = pcr_values_count + 3
        self.log.info(pcr_select[0].pcrSelect)
        maskSum = 0
        i = 0
        while i < len(pcrSel[0].pcrSelect):
          pcr_select[0].pcrSelect[i] &= (~pcrSel[0].pcrSelect[i])
          maskSum = maskSum + pcr_select[0].pcrSelect[i]
          i = i + 1
    tpm.close()
    return pcr_values

  def get_ephemeral_key(self, pcr_list):
    tpm = Tpm()
    tpm.connect()

    pcr_select = self.get_pcr_select(pcr_list)

    pcrs = self.get_pcr_values(pcr_list)

    attributes = (
      TPMA_OBJECT.decrypt |
      TPMA_OBJECT.fixedTPM |
      TPMA_OBJECT.fixedParent |
      TPMA_OBJECT.sensitiveDataOrigin |
      TPMA_OBJECT.noDA
    )
    parameters = TPMS_RSA_PARMS(
      TPMT_SYM_DEF_OBJECT(),
      TPMS_NULL_ASYM_SCHEME(),
      2048,
      0
    )
    in_public = TPMT_PUBLIC(
      TPM_ALG_ID.SHA256, attributes,
      None,
      parameters,
      TPM2B_PUBLIC_KEY_RSA()
    )

    sign = TPM_HANDLE(int(AIK_PUB_INDEX, 16) + 3)

    # Start a policy session to be used with ActivateCredential()
    nonceCaller = crypto.randomBytes(20)
    respSas = tpm.StartAuthSession(None, None, nonceCaller, None, TPM_SE.TRIAL, NullSymDef, TPM_ALG_ID.SHA256)
    hSess = respSas.handle
    self.log.info('DRS >> StartAuthSession(POLICY_SESS) returned ' + str(tpm.lastResponseCode) + '; sess handle: ' + str(hSess.handle))
    sess = Session(hSess, respSas.nonceTPM)

    # Retrieve the policy digest computed by the TPM
    pcr_digest = self.sha256_hash_update(pcrs)
    resp = tpm.PolicyPCR(hSess, bytes.fromhex(pcr_digest), pcr_select)
    dupPolicyDigest = tpm.PolicyGetDigest(hSess)
    in_public.authPolicy = dupPolicyDigest
    self.log.info('DRS >> PolicyGetDigest() returned ' + str(tpm.lastResponseCode))

    # Create RSA Key
    idKey = tpm.withSession(NullPwSession)  \
                .CreatePrimary(Owner, TPMS_SENSITIVE_CREATE(), in_public, None, pcr_select)
    self.log.info('DRS >> CreatePrimary(idKey) returned ' + str(tpm.lastResponseCode))

    encryption_key = idKey.outPublic.asTpm2B()
    self.log.info('CreatePrimary returned ' + str(tpm.lastResponseCode))
    if (not idKey.getHandle()):
        raise(Exception("CreatePrimary failed for " + in_public))
  

    response = tpm.Certify(idKey.getHandle(), sign, 0, TPMS_NULL_ASYM_SCHEME())
    self.log.info('Dat: ', response.certifyInfo.attested)
    buf = TpmBuffer(response.certifyInfo.asTpm2B()).createObj(TPM2B_ATTEST)
    self.log.info(buf.attestationData.attested)
    certify_info = response.certifyInfo.toBytes()
    signature = response.signature.sig

    ephemeral_Key = EphemeralKey(encryption_key, certify_info, signature)

    self.cleanSlots(tpm, TPM_HT.LOADED_SESSION)

    # not closing TPM connection since we need the key handle
    return ephemeral_Key, idKey.getHandle(), tpm


  def decrypt_with_ephemeral_key(self, encrypted_data, pcr_list, handle, tpm):
    #tpm = Tpm()
    #tpm.connect()

    pcr_select = self.get_pcr_select(pcr_list)
    pcrs = self.get_pcr_values(pcr_list)

    nonceCaller = crypto.randomBytes(20)
    respSas = tpm.StartAuthSession(None, None, nonceCaller, None, TPM_SE.POLICY, NullSymDef, TPM_ALG_ID.SHA256)
    hSess = respSas.handle
    self.log.info('DRS >> StartAuthSession(POLICY_SESS) returned ' + str(tpm.lastResponseCode) + '; sess handle: ' + str(hSess.handle))
    sess = Session(hSess, respSas.nonceTPM)

    # Retrieve the policy digest computed by the TPM
    pcr_digest = self.sha256_hash_update(pcrs)
    tpm.PolicyPCR(hSess, bytes.fromhex(pcr_digest), pcr_select)
    self.log.info('DRS >> PolicyGetDigest() returned ' + str(tpm.lastResponseCode))

    try:
      decrypted_data \
        = tpm.withSession(sess).RSA_Decrypt(handle, encrypted_data, TPMS_SCHEME_RSAES(), None)
      self.log.info('Decrypted Inner Decryption Key...')

      tpm.close()

      return decrypted_data
    except Exception as e:
      self.log.info("Exception: ", e)
      # clear the tpm slots
      self.cleanSlots(tpm, TPM_HT.TRANSIENT)
      self.cleanSlots(tpm, TPM_HT.LOADED_SESSION)

      tpm.close()

    return ""


  def cleanSlots(self, tpm, slotType):
      caps = tpm.GetCapability(TPM_CAP.HANDLES, slotType << 24, 8)
      handles = caps.capabilityData

      if len(handles.handle) == 0:
        self.log.info("No dangling", slotType, "handles")
      else:
        for h in handles.handle:
          self.log.info("Dangling", slotType, "handle 0x" + hex(h.handle))
          if slotType == TPM_HT.PERSISTENT:
            tpm.allowErrors().EvictControl(TPM_HANDLE.OWNER, h, h)
            if tpm.lastResponseCode not in [TPM_RC.SUCCESS, TPM_RC.HIERARCHY]:
              raise(tpm.lastError)
          else:
              tpm.FlushContext(h)