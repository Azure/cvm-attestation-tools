import struct
from typing import List


class Signature:
  def __init__(self, r_component=None, s_component=None, reserved=None):
    self.r_component = r_component or [0] * 72  # RComponent[72]
    self.s_component = s_component or [0] * 72  # SComponent[72]
    self.reserved = reserved or [0] * 368       # RSVD[368]

  def serialize(self):
    return struct.pack(
      '<72s72s368s',
      bytes(self.r_component),
      bytes(self.s_component),
      bytes(self.reserved)
    )

  @classmethod
  def deserialize(cls, data):
    unpacked_data = struct.unpack('<72s72s368s', data)
    return cls(
      list(unpacked_data[0]),
      list(unpacked_data[1]),
      list(unpacked_data[2])
    )


class TcbVersion:
  def __init__(self, bootloader=0, tee=0, reserved=0, snp=0, microcode=0):
    self.bootloader = bootloader
    self.tee = tee
    self.reserved = reserved
    self.snp = snp
    self.microcode = microcode

  def serialize(self):
    return struct.pack(
      '>Q',
      (self.microcode << 56)
      | (self.snp << 48)
      | (self.reserved << 16)
      | (self.tee << 8)
      | self.bootloader
    )

  @classmethod
  def deserialize(cls, data):
    unpacked_data = struct.unpack('<Q', data)[0]
    return cls(
      bootloader=unpacked_data & 0xFF,
      tee=(unpacked_data >> 8) & 0xFF,
      reserved=(unpacked_data >> 16) & 0xFFFFFFFF,
      snp=(unpacked_data >> 48) & 0xFF,
      microcode=(unpacked_data >> 56) & 0xFF
    )

class PlatformInfo:
  def __init__(self, smt_enabled=0, tsme_enabled=0, ecc_enabled=0, rapl_disabled=0, ciphertext_hiding_enabled=0, reserved=0):
    self.smt_enabled = smt_enabled
    self.tsme_enabled = tsme_enabled
    self.ecc_enabled = ecc_enabled
    self.rapl_disabled = rapl_disabled
    self.ciphertext_hiding_enabled = ciphertext_hiding_enabled
    self.reserved = reserved

  def serialize(self):
    return (
      (self.reserved << 5)
      | (self.ciphertext_hiding_enabled << 4)
      | (self.rapl_disabled << 3)
      | (self.ecc_enabled << 2)
      | (self.tsme_enabled << 1)
      | self.smt_enabled
    )

  @classmethod
  def deserialize(cls, data):
    unpacked_data = struct.unpack('<Q', data)[0]
    return cls(
      smt_enabled=unpacked_data & 0x1,
      tsme_enabled=(unpacked_data >> 1) & 0x1,
      ecc_enabled=(unpacked_data >> 2) & 0x1,
      rapl_disabled=(unpacked_data >> 3) & 0x1,
      ciphertext_hiding_enabled=(unpacked_data >> 4) & 0x1,
      reserved=(unpacked_data >> 5) & ((1 << 59) - 1)  # Mask bits 5 to 63
    )


class KeyInfo:
  def __init__(self, author_key_en=0, mask_chip_key=0, signing_key=0, reserved=0):
    """
    Initialize the KeyInfo structure.
    """
    self.author_key_en = author_key_en      # Bit 0
    self.mask_chip_key = mask_chip_key      # Bit 1
    self.signing_key = signing_key          # Bits 2–4
    self.reserved = reserved                # Bits 5–31

  def serialize(self):
    """
    Serialize the KeyInfo structure into a 4-byte little-endian integer.
    """
    return struct.pack(
      '<I',
      (self.reserved << 5) |
      (self.signing_key << 2) |
      (self.mask_chip_key << 1) |
      self.author_key_en
    )

  @classmethod
  def deserialize(cls, data):
    """
    Deserialize a 4-byte little-endian integer into a KeyInfo instance.
    """
    value = struct.unpack('<I', data)[0]
    return cls(
      author_key_en=value & 0x1,
      mask_chip_key=(value >> 1) & 0x1,
      signing_key=(value >> 2) & 0x7,
      reserved=(value >> 5) & 0x7FFFFFF
    )



class AttestationReport:
  # Define the structure's format string as a class-level constant
  FORMAT_STRING = (
    '<IIQ16s16sII'  # version, guest_svn, policy, family_id, image_id, vmpl, sig_algo
    'Q'             # current_tcb (8 bytes)
    'Q'             # plat_info (8 bytes)
    'I'             # key_info (4 bytes)
    'I'             # _reserved_0 (4 bytes)
    '64s'           # report_data (64 bytes)
    '48s'           # measurement (48 bytes)
    '32s'           # host_data (32 bytes)
    '48s'           # id_key_digest (48 bytes)
    '48s'           # author_key_digest (48 bytes)
    '32s'           # report_id (32 bytes)
    '32s'           # report_id_ma (32 bytes)
    'Q'             # reported_tcb (8 bytes)
    '24s'           # _reserved_1 (24 bytes)
    '64s'           # chip_id (64 bytes)
    'Q'             # committed_tcb (8 bytes)
    'BBBB'          # current_build, current_minor, current_major, _reserved_2
    'BBBB'          # committed_build, committed_minor, committed_major, _reserved_3
    'Q'             # launch_tcb (8 bytes)
    '168s'          # _reserved_4 (168 bytes)
    '512s'          # signature (512 bytes)
  )

  @classmethod
  def calculate_size(cls):
    """
    Calculate the total size of the class based on its format string.
    """
    return struct.calcsize(cls.FORMAT_STRING)

  def __init__(self):
    self.version = 0
    self.guest_svn = 0
    self.policy = 0
    self.family_id = [0] * 16
    self.image_id = [0] * 16
    self.vmpl = 0
    self.sig_algo = 0
    self.current_tcb = TcbVersion()
    self.plat_info = PlatformInfo()
    self.key_info = KeyInfo()
    self._reserved_0 = 0
    self.report_data = [0] * 64
    self.measurement = [0] * 48
    self.host_data = [0] * 32
    self.id_key_digest = [0] * 48
    self.author_key_digest = [0] * 48
    self.report_id = [0] * 32
    self.report_id_ma = [0] * 32
    self.reported_tcb = TcbVersion()
    self._reserved_1 = [0] * 24
    self.chip_id = [0] * 64
    self.committed_tcb = TcbVersion()
    self.current_build = 0
    self.current_minor = 0
    self.current_major = 0
    self._reserved_2 = 0
    self.committed_build = 0
    self.committed_minor = 0
    self.committed_major = 0
    self._reserved_3 = 0
    self.launch_tcb = TcbVersion()
    self._reserved_4 = [0] * 168
    self.signature = Signature()

  def serialize(self):
    return struct.pack(
      self.FORMAT_STRING,
      self.version,                     # int
      self.guest_svn,                   # int
      self.policy,                      # int or uint64_t
      bytes(self.family_id),            # bytes
      bytes(self.image_id),             # bytes
      self.vmpl,                        # int
      self.sig_algo,                    # int
      self.current_tcb.serialize(),     # Should return bytes or int (Q)
      self.plat_info.serialize(),       # Should return bytes or int (Q)
      self.key_info.serialize(),        # Should return bytes or int (I)
      self._reserved_0,                 # int
      bytes(self.report_data),          # bytes
      bytes(self.measurement),          # bytes
      bytes(self.host_data),            # bytes
      bytes(self.id_key_digest),        # bytes
      bytes(self.author_key_digest),    # bytes
      bytes(self.report_id),            # bytes
      bytes(self.report_id_ma),         # bytes
      self.reported_tcb.serialize(),    # Should return bytes or int (Q)
      bytes(self._reserved_1),          # bytes
      bytes(self.chip_id),              # bytes
      self.committed_tcb.serialize(),   # Should return bytes or int (Q)
      self.current_build,               # int
      self.current_minor,               # int
      self.current_major,               # int
      self._reserved_2,                 # int
      self.committed_build,             # int
      self.committed_minor,             # int
      self.committed_major,             # int
      self._reserved_3,                 # int
      self.launch_tcb.serialize(),      # Should return bytes or int (Q)
      bytes(self._reserved_4),          # bytes
      self.signature.serialize()        # Should return bytes (512 bytes)
    )


  @classmethod
  def deserialize(cls, data):
    """
    Deserialize a binary blob into an instance of the class.
    """
    unpacked_data = struct.unpack(cls.FORMAT_STRING, data)

    instance = cls()
    instance.version = unpacked_data[0]
    instance.guest_svn = unpacked_data[1]
    instance.policy = unpacked_data[2]
    instance.family_id = list(unpacked_data[3])
    instance.image_id = list(unpacked_data[4])
    instance.vmpl = unpacked_data[5]
    instance.sig_algo = unpacked_data[6]
    instance.current_tcb = TcbVersion.deserialize(struct.pack('<Q', unpacked_data[7]))
    instance.plat_info = PlatformInfo.deserialize(struct.pack('<Q', unpacked_data[8]))
    instance.key_info = KeyInfo.deserialize(struct.pack('<I', unpacked_data[9]))
    instance._reserved_0 = unpacked_data[10]
    instance.report_data = list(unpacked_data[11])
    instance.measurement = list(unpacked_data[12])
    instance.host_data = list(unpacked_data[13])
    instance.id_key_digest = list(unpacked_data[14])
    instance.author_key_digest = list(unpacked_data[15])
    instance.report_id = list(unpacked_data[16])
    instance.report_id_ma = list(unpacked_data[17])
    instance.reported_tcb = TcbVersion.deserialize(struct.pack('<Q', unpacked_data[18]))
    instance._reserved_1 = list(unpacked_data[19])
    instance.chip_id = list(unpacked_data[20])
    instance.committed_tcb = TcbVersion.deserialize(struct.pack('<Q', unpacked_data[21]))
    instance.current_build = unpacked_data[22]
    instance.current_minor = unpacked_data[23]
    instance.current_major = unpacked_data[24]
    instance._reserved_2 = unpacked_data[25]
    instance.committed_build = unpacked_data[26]
    instance.committed_minor = unpacked_data[27]
    instance.committed_major = unpacked_data[28]
    instance._reserved_3 = unpacked_data[29]
    instance.launch_tcb = TcbVersion.deserialize(struct.pack('<Q', unpacked_data[30]))
    instance._reserved_4 = list(unpacked_data[31])
    instance.signature = Signature.deserialize(unpacked_data[32])

    return instance


  def format_data(self, data):
    """
    Format the report data into a multi-line hex output, with 16 bytes per line.
    """
    lines = []
    for i in range(0, len(data), 16):
      chunk = data[i:i+16]
      lines.append(" ".join(f"{byte:02x}" for byte in chunk))  # Format bytes as hex
    return "\n".join(lines)


  def display(self):
    """
    Displays the full attestation report
    """
    print(f"Attestation Report ({self.calculate_size()} bytes):")
    print(f"Version:                      {self.version}")
    print(f"Guest SVN:                    {self.guest_svn}")
    print(f"\nGuest Policy (0x{self.policy:x}):")
    print(f"    ABI Major:     {(self.policy >> 8) & 0xff}")
    print(f"    ABI Minor:     {(self.policy >> 0) & 0xff}")
    print(f"    SMT Allowed:   {(self.policy >> 16) & 0x1}")
    print(f"    Migrate MA:    {(self.policy >> 18) & 0x1}")
    print(f"    Debug Allowed: {(self.policy >> 19) & 0x1}")
    print(f"    Single Socket: {(self.policy >> 20) & 0x1}")
    print()

    print("Family ID:                    ")
    for byte in self.family_id:
      print(f"{byte:02x} ", end='')
    print()
    print()

    print("Image ID:                     ")
    for byte in self.image_id:
      print(f"{byte:02x} ", end='')
    print()
    print()

    print(f"VMPL:                         {self.vmpl}")
    print(f"Signature Algorithm:          {self.sig_algo}")
    print()

    current_tcb = self.current_tcb.serialize()
    formatted_tcb = "".join(f"{byte:02X}" for byte in current_tcb)
    print(f"Current TCB: {formatted_tcb}")
    print(f"  Microcode:   {self.current_tcb.microcode}")
    print(f"  SNP:         {self.current_tcb.snp}")
    print(f"  TEE:         {self.current_tcb.tee}")
    print(f"  Boot Loader: {self.current_tcb.bootloader}")

    print(f"\nPlatform Info (1):")
    print(f"  SMT Enabled:               {self.plat_info.smt_enabled}")
    print(f"  TSME Enabled:              {self.plat_info.tsme_enabled}")
    print(f"  ECC Enabled:               {self.plat_info.ecc_enabled}")
    print(f"  RAPL Disabled:             {self.plat_info.rapl_disabled}")
    print(f"  Ciphertext Hiding Enabled: {self.plat_info.ciphertext_hiding_enabled}")

    print()

    print(f"Author Key Encryption:      {bool(self.key_info.author_key_en)}")
    print("Report Data:                     ")
    print(self.format_data(self.report_data))
    print()

    print("Measurement:                     ")
    print(self.format_data(self.measurement))
    print()

    print("Host Data:                     ")
    print(self.format_data(self.host_data))
    print()

    print("ID Key Digest:                     ")
    print(self.format_data(self.id_key_digest))
    print()

    print("Report ID:                     ")
    print(self.format_data(self.report_id))
    print()

    print("Report ID Migration Agent:                     ")
    print(self.format_data(self.report_id_ma))
    print()

    reported_tcb = self.reported_tcb.serialize()
    formatted_tcb = "".join(f"{byte:02X}" for byte in reported_tcb)
    print(f"Reported TCB:")
    print(f"TCB Version: {formatted_tcb}")
    print(f"  Microcode:   {self.reported_tcb.microcode}")
    print(f"  SNP:         {self.reported_tcb.snp}")
    print(f"  TEE:         {self.reported_tcb.tee}")
    print(f"  Boot Loader: {self.reported_tcb.bootloader}")
    print()

    print("Chip ID:                     ")
    print(self.format_data(self.chip_id))
    print()

    committed_tcb = self.committed_tcb.serialize()
    formatted_tcb = "".join(f"{byte:02X}" for byte in committed_tcb)
    print(f"Commited TCB: {formatted_tcb}")
    print(f"  Microcode:   {self.committed_tcb.microcode}")
    print(f"  SNP:         {self.committed_tcb.snp}")
    print(f"  TEE:         {self.committed_tcb.tee}")
    print(f"  Boot Loader: {self.committed_tcb.bootloader}")
    print()

    print(f"Current Build:                {self.current_build}")
    print(f"Current Minor:                {self.current_minor}")
    print(f"Current Major:                {self.current_major}")
    print(f"Committed Build:              {self.committed_build}")
    print(f"Committed Minor:              {self.committed_minor}")
    print(f"Committed Major:              {self.committed_major}")
    print()

    launch_tcb = self.launch_tcb.serialize()
    formatted_tcb = "".join(f"{byte:02X}" for byte in launch_tcb)
    print(f"Launched TCB: {formatted_tcb}")
    print(f"  Microcode:   {self.launch_tcb.microcode}")
    print(f"  SNP:         {self.launch_tcb.snp}")
    print(f"  TEE:         {self.launch_tcb.tee}")
    print(f"  Boot Loader: {self.launch_tcb.bootloader}")
    print()

    print("Signature:                     ")
    print(f"  R Component:")
    print(self.format_data(self.signature.r_component))
    print()
    print(f"  S Component:")
    print(self.format_data(self.signature.s_component))
    print()