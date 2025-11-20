# cvm-attestation/src/vbs.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import struct

VBS_VM_SHA256_SIZE = 32
VBS_VM_HOST_DATA_SIZE = 32
VBS_VM_MAX_SIGNATURE_SIZE = 256
VBS_VM_REPORT_DATA_LENGTH = 64
VBS_VM_IDENTITY_RESERVED = 64
VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT = 1

class VbsVmReportPkgHeader:
  FORMAT = '<IIIII'  # PackageSize, Version, SignatureScheme, SignatureSize, Reserved
  SIZE = struct.calcsize(FORMAT)

  def __init__(self, package_size=0, version=VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT, signature_scheme=0, signature_size=0, reserved=0):
    self.package_size = package_size
    self.version = version
    self.signature_scheme = signature_scheme
    self.signature_size = signature_size
    self.reserved = reserved

  def serialize(self) -> bytes:
    return struct.pack(self.FORMAT, self.package_size, self.version, self.signature_scheme, self.signature_size, self.reserved)

  @classmethod
  def deserialize(cls, data: bytes):
    fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
    return cls(*fields)


class VbsVmIdentity:
  FORMAT = f'<{VBS_VM_SHA256_SIZE}s{VBS_VM_SHA256_SIZE}s{VBS_VM_SHA256_SIZE}s{VBS_VM_HOST_DATA_SIZE}s' + 'IIIIII' + f'{VBS_VM_IDENTITY_RESERVED}s'
  SIZE = struct.calcsize(FORMAT)

  def __init__(
    self,
    owner_id: bytes = b'\x00' * VBS_VM_SHA256_SIZE,
    measurement: bytes = b'\x00' * VBS_VM_SHA256_SIZE,
    signer: bytes = b'\x00' * VBS_VM_SHA256_SIZE,
    host_data: bytes = b'\x00' * VBS_VM_HOST_DATA_SIZE,
    enabled_vtl: int = 0,
    policy: int = 0,
    guest_vtl: int = 0,
    guest_svn: int = 0,
    guest_product_id: int = 0,
    guest_module_id: int = 0,
    reserved: bytes = b'\x00' * VBS_VM_IDENTITY_RESERVED
  ):
    self.owner_id = owner_id
    self.measurement = measurement
    self.signer = signer
    self.host_data = host_data
    self.enabled_vtl = enabled_vtl
    self.policy = policy
    self.guest_vtl = guest_vtl
    self.guest_svn = guest_svn
    self.guest_product_id = guest_product_id
    self.guest_module_id = guest_module_id
    self.reserved = reserved

  def serialize(self) -> bytes:
    return struct.pack(
      self.FORMAT,
      self.owner_id,
      self.measurement,
      self.signer,
      self.host_data,
      self.enabled_vtl,
      self.policy,
      self.guest_vtl,
      self.guest_svn,
      self.guest_product_id,
      self.guest_module_id,
      self.reserved
    )

  @classmethod
  def deserialize(cls, data: bytes):
    fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
    return cls(
      owner_id=fields[0],
      measurement=fields[1],
      signer=fields[2],
      host_data=fields[3],
      enabled_vtl=fields[4],
      policy=fields[5],
      guest_vtl=fields[6],
      guest_svn=fields[7],
      guest_product_id=fields[8],
      guest_module_id=fields[9],
      reserved=fields[10]
    )


class VbsVmReport:
  # Header (pkg header) + Version (I) + ReportData (64) + Identity + Signature (256)
  # When combining struct formats, ensure only a single byte-order specifier at the start
  IDENTITY_FMT = VbsVmIdentity.FORMAT.lstrip('<')
  HEADER_FMT = VbsVmReportPkgHeader.FORMAT.lstrip('<')
  FORMAT = '<' + HEADER_FMT + 'I' + f'{VBS_VM_REPORT_DATA_LENGTH}s' + IDENTITY_FMT + f'{VBS_VM_MAX_SIGNATURE_SIZE}s'
  SIZE = struct.calcsize(FORMAT)

  def __init__(self):
    self.header = VbsVmReportPkgHeader()
    self.version = 0
    self.report_data = b'\x00' * VBS_VM_REPORT_DATA_LENGTH
    self.identity = VbsVmIdentity()
    self.signature = b'\x00' * VBS_VM_MAX_SIGNATURE_SIZE

  @classmethod
  def calculate_size(cls):
    return cls.SIZE

  def serialize(self) -> bytes:
    # Build identity block first to ensure correct packing
    identity_blob = self.identity.serialize()
    header_blob = self.header.serialize()
    body = struct.pack('<I', self.version)
    body += self.report_data
    body += identity_blob
    body += self.signature
    return header_blob + body

  @classmethod
  def deserialize(cls, data: bytes):
    if len(data) < cls.SIZE:
      raise ValueError(f"Data too short for VBS_VM_REPORT (need {cls.SIZE}, got {len(data)})")
    # Parse header
    offset = 0
    header = VbsVmReportPkgHeader.deserialize(data[offset:offset + VbsVmReportPkgHeader.SIZE])
    offset += VbsVmReportPkgHeader.SIZE
    # Version
    version = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    # ReportData
    report_data = data[offset:offset + VBS_VM_REPORT_DATA_LENGTH]
    offset += VBS_VM_REPORT_DATA_LENGTH
    # Identity
    identity = VbsVmIdentity.deserialize(data[offset:offset + VbsVmIdentity.SIZE])
    offset += VbsVmIdentity.SIZE
    # Signature
    signature = data[offset:offset + VBS_VM_MAX_SIGNATURE_SIZE]

    inst = cls()
    inst.header = header
    inst.version = version
    inst.report_data = report_data
    inst.identity = identity
    inst.signature = signature
    return inst

  def format_data(self, data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
      chunk = data[i:i+width]
      lines.append(" ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)

  def __str__(self):
    lines = []
    lines.append(f"VBS VM Report (size {self.calculate_size()} bytes)")
    lines.append(f"Package Header: size={self.header.package_size} version={self.header.version} sig_scheme={self.header.signature_scheme} sig_size={self.header.signature_size}")
    lines.append(f"Report Version: {self.version}")
    lines.append("Report Data:")
    lines.append(self.format_data(self.report_data))
    lines.append("\nIdentity:")
    lines.append(f"  OwnerId:    {self.identity.owner_id.hex()}")
    lines.append(f"  Measurement:  {self.identity.measurement.hex()}")
    lines.append(f"  Signer:     {self.identity.signer.hex()}")
    lines.append(f"  HostData:   {self.identity.host_data.hex()}")
    lines.append(f"  EnabledVtl:   0x{self.identity.enabled_vtl:08x}")
    lines.append(f"  Policy:     0x{self.identity.policy:08x}")
    lines.append(f"  GuestVtl:   {self.identity.guest_vtl}")
    lines.append(f"  GuestSvn:   {self.identity.guest_svn}")
    lines.append(f"  GuestProduct: {self.identity.guest_product_id}")
    lines.append(f"  GuestModule:  {self.identity.guest_module_id}")
    lines.append("\nSignature (first 64 bytes hex):")
    lines.append(self.signature[:64].hex())

    return "\n".join(lines)
