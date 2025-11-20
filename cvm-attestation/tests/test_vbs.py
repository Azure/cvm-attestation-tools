# test_vbs.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import struct
from src.vbs import (
  VbsVmReportPkgHeader,
  VbsVmIdentity,
  VbsVmReport,
  VBS_VM_SHA256_SIZE,
  VBS_VM_HOST_DATA_SIZE,
  VBS_VM_MAX_SIGNATURE_SIZE,
  VBS_VM_REPORT_DATA_LENGTH,
  VBS_VM_IDENTITY_RESERVED,
  VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT
)


class TestVbsVmReportPkgHeader:
  """Test VbsVmReportPkgHeader class."""

  @pytest.fixture
  def default_header(self):
    """Create a default header instance."""
    return VbsVmReportPkgHeader()

  @pytest.fixture
  def custom_header(self):
    """Create a custom header instance."""
    return VbsVmReportPkgHeader(
      package_size=1024,
      version=1,
      signature_scheme=2,
      signature_size=256,
      reserved=0
    )

  def test_default_initialization(self, default_header):
    """Test default header initialization."""
    assert default_header.package_size == 0
    assert default_header.version == VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT
    assert default_header.signature_scheme == 0
    assert default_header.signature_size == 0
    assert default_header.reserved == 0

  def test_custom_initialization(self, custom_header):
    """Test custom header initialization."""
    assert custom_header.package_size == 1024
    assert custom_header.version == 1
    assert custom_header.signature_scheme == 2
    assert custom_header.signature_size == 256
    assert custom_header.reserved == 0

  def test_serialize(self, custom_header):
    """Test header serialization."""
    data = custom_header.serialize()
    assert isinstance(data, bytes)
    assert len(data) == VbsVmReportPkgHeader.SIZE
    assert len(data) == 20  # 5 x 4 bytes (IIIII)

  def test_deserialize(self, custom_header):
    """Test header deserialization."""
    serialized = custom_header.serialize()
    deserialized = VbsVmReportPkgHeader.deserialize(serialized)
    
    assert deserialized.package_size == custom_header.package_size
    assert deserialized.version == custom_header.version
    assert deserialized.signature_scheme == custom_header.signature_scheme
    assert deserialized.signature_size == custom_header.signature_size
    assert deserialized.reserved == custom_header.reserved

  def test_serialize_deserialize_roundtrip(self, default_header):
    """Test that serialize/deserialize is reversible."""
    serialized = default_header.serialize()
    deserialized = VbsVmReportPkgHeader.deserialize(serialized)
    reserialized = deserialized.serialize()
    
    assert serialized == reserialized

  def test_size_constant(self):
    """Test that SIZE constant is correct."""
    assert VbsVmReportPkgHeader.SIZE == struct.calcsize('<IIIII')
    assert VbsVmReportPkgHeader.SIZE == 20


class TestVbsVmIdentity:
  """Test VbsVmIdentity class."""

  @pytest.fixture
  def default_identity(self):
    """Create a default identity instance."""
    return VbsVmIdentity()

  @pytest.fixture
  def custom_identity(self):
    """Create a custom identity instance."""
    return VbsVmIdentity(
      owner_id=b'\x01' * VBS_VM_SHA256_SIZE,
      measurement=b'\x02' * VBS_VM_SHA256_SIZE,
      signer=b'\x03' * VBS_VM_SHA256_SIZE,
      host_data=b'\x04' * VBS_VM_HOST_DATA_SIZE,
      enabled_vtl=1,
      policy=2,
      guest_vtl=3,
      guest_svn=4,
      guest_product_id=5,
      guest_module_id=6,
      reserved=b'\x07' * VBS_VM_IDENTITY_RESERVED
    )

  def test_default_initialization(self, default_identity):
    """Test default identity initialization."""
    assert default_identity.owner_id == b'\x00' * VBS_VM_SHA256_SIZE
    assert default_identity.measurement == b'\x00' * VBS_VM_SHA256_SIZE
    assert default_identity.signer == b'\x00' * VBS_VM_SHA256_SIZE
    assert default_identity.host_data == b'\x00' * VBS_VM_HOST_DATA_SIZE
    assert default_identity.enabled_vtl == 0
    assert default_identity.policy == 0
    assert default_identity.guest_vtl == 0
    assert default_identity.guest_svn == 0
    assert default_identity.guest_product_id == 0
    assert default_identity.guest_module_id == 0
    assert default_identity.reserved == b'\x00' * VBS_VM_IDENTITY_RESERVED

  def test_custom_initialization(self, custom_identity):
    """Test custom identity initialization."""
    assert custom_identity.owner_id == b'\x01' * VBS_VM_SHA256_SIZE
    assert custom_identity.measurement == b'\x02' * VBS_VM_SHA256_SIZE
    assert custom_identity.signer == b'\x03' * VBS_VM_SHA256_SIZE
    assert custom_identity.host_data == b'\x04' * VBS_VM_HOST_DATA_SIZE
    assert custom_identity.enabled_vtl == 1
    assert custom_identity.policy == 2
    assert custom_identity.guest_vtl == 3
    assert custom_identity.guest_svn == 4
    assert custom_identity.guest_product_id == 5
    assert custom_identity.guest_module_id == 6
    assert custom_identity.reserved == b'\x07' * VBS_VM_IDENTITY_RESERVED

  def test_serialize(self, custom_identity):
    """Test identity serialization."""
    data = custom_identity.serialize()
    assert isinstance(data, bytes)
    assert len(data) == VbsVmIdentity.SIZE

  def test_deserialize(self, custom_identity):
    """Test identity deserialization."""
    serialized = custom_identity.serialize()
    deserialized = VbsVmIdentity.deserialize(serialized)
    
    assert deserialized.owner_id == custom_identity.owner_id
    assert deserialized.measurement == custom_identity.measurement
    assert deserialized.signer == custom_identity.signer
    assert deserialized.host_data == custom_identity.host_data
    assert deserialized.enabled_vtl == custom_identity.enabled_vtl
    assert deserialized.policy == custom_identity.policy
    assert deserialized.guest_vtl == custom_identity.guest_vtl
    assert deserialized.guest_svn == custom_identity.guest_svn
    assert deserialized.guest_product_id == custom_identity.guest_product_id
    assert deserialized.guest_module_id == custom_identity.guest_module_id
    assert deserialized.reserved == custom_identity.reserved

  def test_serialize_deserialize_roundtrip(self, default_identity):
    """Test that serialize/deserialize is reversible."""
    serialized = default_identity.serialize()
    deserialized = VbsVmIdentity.deserialize(serialized)
    reserialized = deserialized.serialize()
    
    assert serialized == reserialized

  def test_size_constant(self):
    """Test that SIZE constant is correct."""
    expected_size = (
      VBS_VM_SHA256_SIZE +      # owner_id
      VBS_VM_SHA256_SIZE +      # measurement
      VBS_VM_SHA256_SIZE +      # signer
      VBS_VM_HOST_DATA_SIZE +   # host_data
      4 * 6 +                   # 6 integers (enabled_vtl, policy, guest_vtl, guest_svn, guest_product_id, guest_module_id)
      VBS_VM_IDENTITY_RESERVED  # reserved
    )
    assert VbsVmIdentity.SIZE == expected_size


class TestVbsVmReport:
  """Test VbsVmReport class."""

  @pytest.fixture
  def default_report(self):
    """Create a default report instance."""
    return VbsVmReport()

  @pytest.fixture
  def custom_report(self):
    """Create a custom report instance."""
    report = VbsVmReport()
    report.header = VbsVmReportPkgHeader(
      package_size=1024,
      version=1,
      signature_scheme=2,
      signature_size=256,
      reserved=0
    )
    report.version = 1
    report.report_data = b'\x01' * VBS_VM_REPORT_DATA_LENGTH
    report.identity = VbsVmIdentity(
      owner_id=b'\x02' * VBS_VM_SHA256_SIZE,
      measurement=b'\x03' * VBS_VM_SHA256_SIZE,
      signer=b'\x04' * VBS_VM_SHA256_SIZE,
      host_data=b'\x05' * VBS_VM_HOST_DATA_SIZE,
      enabled_vtl=10,
      policy=20,
      guest_vtl=1,
      guest_svn=100,
      guest_product_id=200,
      guest_module_id=300
    )
    report.signature = b'\x06' * VBS_VM_MAX_SIGNATURE_SIZE
    return report

  def test_default_initialization(self, default_report):
    """Test default report initialization."""
    assert isinstance(default_report.header, VbsVmReportPkgHeader)
    assert default_report.version == 0
    assert default_report.report_data == b'\x00' * VBS_VM_REPORT_DATA_LENGTH
    assert isinstance(default_report.identity, VbsVmIdentity)
    assert default_report.signature == b'\x00' * VBS_VM_MAX_SIGNATURE_SIZE

  def test_calculate_size(self):
    """Test calculate_size class method."""
    size = VbsVmReport.calculate_size()
    assert size == VbsVmReport.SIZE
    assert isinstance(size, int)
    assert size > 0

  def test_serialize(self, custom_report):
    """Test report serialization."""
    data = custom_report.serialize()
    assert isinstance(data, bytes)
    assert len(data) == VbsVmReport.SIZE

  def test_deserialize(self, custom_report):
    """Test report deserialization."""
    serialized = custom_report.serialize()
    deserialized = VbsVmReport.deserialize(serialized)
    
    # Check header
    assert deserialized.header.package_size == custom_report.header.package_size
    assert deserialized.header.version == custom_report.header.version
    assert deserialized.header.signature_scheme == custom_report.header.signature_scheme
    assert deserialized.header.signature_size == custom_report.header.signature_size
    
    # Check version
    assert deserialized.version == custom_report.version
    
    # Check report data
    assert deserialized.report_data == custom_report.report_data
    
    # Check identity
    assert deserialized.identity.owner_id == custom_report.identity.owner_id
    assert deserialized.identity.measurement == custom_report.identity.measurement
    assert deserialized.identity.signer == custom_report.identity.signer
    assert deserialized.identity.enabled_vtl == custom_report.identity.enabled_vtl
    assert deserialized.identity.policy == custom_report.identity.policy
    assert deserialized.identity.guest_svn == custom_report.identity.guest_svn
    
    # Check signature
    assert deserialized.signature == custom_report.signature

  def test_serialize_deserialize_roundtrip(self, default_report):
    """Test that serialize/deserialize is reversible."""
    serialized = default_report.serialize()
    deserialized = VbsVmReport.deserialize(serialized)
    reserialized = deserialized.serialize()
    
    assert serialized == reserialized

  def test_deserialize_short_data_raises_error(self):
    """Test that deserialize raises ValueError for short data."""
    short_data = b'\x00' * 10
    
    with pytest.raises(ValueError) as exc_info:
      VbsVmReport.deserialize(short_data)
    
    assert "Data too short" in str(exc_info.value)
    assert f"need {VbsVmReport.SIZE}" in str(exc_info.value)

  def test_format_data(self, default_report):
    """Test format_data method."""
    test_data = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    formatted = default_report.format_data(test_data, width=4)
    
    assert isinstance(formatted, str)
    assert "01 02 03 04" in formatted
    assert "05 06 07 08" in formatted

  def test_format_data_with_different_width(self, default_report):
    """Test format_data with different width."""
    test_data = b'\xaa\xbb\xcc\xdd\xee\xff'
    formatted = default_report.format_data(test_data, width=3)
    
    lines = formatted.split('\n')
    assert len(lines) == 2
    assert "aa bb cc" in lines[0]
    assert "dd ee ff" in lines[1]

  def test_str_representation(self, custom_report):
    """Test __str__ method."""
    str_repr = str(custom_report)
    
    assert isinstance(str_repr, str)
    assert "VBS VM Report" in str_repr
    assert "Package Header:" in str_repr
    assert "Report Version:" in str_repr
    assert "Report Data:" in str_repr
    assert "Identity:" in str_repr
    assert "Signature" in str_repr
    
    # Check for specific values
    assert "version=1" in str_repr
    assert f"size {VbsVmReport.calculate_size()} bytes" in str_repr

  def test_str_contains_identity_fields(self, custom_report):
    """Test that __str__ includes all identity fields."""
    str_repr = str(custom_report)
    
    assert "OwnerId:" in str_repr
    assert "Measurement:" in str_repr
    assert "Signer:" in str_repr
    assert "HostData:" in str_repr
    assert "EnabledVtl:" in str_repr
    assert "Policy:" in str_repr
    assert "GuestVtl:" in str_repr
    assert "GuestSvn:" in str_repr
    assert "GuestProduct:" in str_repr
    assert "GuestModule:" in str_repr

  def test_size_consistency(self):
    """Test that SIZE is consistent with structure."""
    header_size = VbsVmReportPkgHeader.SIZE
    version_size = 4  # uint32
    report_data_size = VBS_VM_REPORT_DATA_LENGTH
    identity_size = VbsVmIdentity.SIZE
    signature_size = VBS_VM_MAX_SIGNATURE_SIZE
    
    expected_size = header_size + version_size + report_data_size + identity_size + signature_size
    assert VbsVmReport.SIZE == expected_size


class TestVbsVmReportIntegration:
  """Integration tests for VBS VM Report structures."""

  def test_complete_workflow(self):
    """Test complete workflow: create, serialize, deserialize, verify."""
    # Create a report with custom data
    original = VbsVmReport()
    original.header.package_size = 2048
    original.header.signature_scheme = 1
    original.version = 1
    original.report_data = b'\xaa' * VBS_VM_REPORT_DATA_LENGTH
    original.identity.enabled_vtl = 0x03
    original.identity.guest_svn = 42
    original.signature = b'\xff' * VBS_VM_MAX_SIGNATURE_SIZE
    
    # Serialize
    serialized = original.serialize()
    assert len(serialized) == VbsVmReport.SIZE
    
    # Deserialize
    restored = VbsVmReport.deserialize(serialized)
    
    # Verify all fields match
    assert restored.header.package_size == original.header.package_size
    assert restored.version == original.version
    assert restored.report_data == original.report_data
    assert restored.identity.enabled_vtl == original.identity.enabled_vtl
    assert restored.identity.guest_svn == original.identity.guest_svn
    assert restored.signature == original.signature

  def test_binary_compatibility(self):
    """Test that binary format remains stable."""
    report = VbsVmReport()
    data = report.serialize()
    
    # Check that we can deserialize what we just serialized
    restored = VbsVmReport.deserialize(data)
    
    # Verify the report is valid
    assert restored.header.version == VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT
    assert len(restored.report_data) == VBS_VM_REPORT_DATA_LENGTH
    assert len(restored.signature) == VBS_VM_MAX_SIGNATURE_SIZE

  def test_all_fields_preserved(self):
    """Test that all fields are preserved through serialization."""
    # Create report with all unique values
    report = VbsVmReport()
    report.header = VbsVmReportPkgHeader(111, 222, 333, 444, 555)
    report.version = 999
    report.report_data = bytes(range(VBS_VM_REPORT_DATA_LENGTH))
    
    # Set identity with pattern
    report.identity.owner_id = bytes([(i % 256) for i in range(VBS_VM_SHA256_SIZE)])
    report.identity.measurement = bytes([((i * 2) % 256) for i in range(VBS_VM_SHA256_SIZE)])
    report.identity.enabled_vtl = 0x12345678
    report.identity.policy = 0x87654321
    report.identity.guest_svn = 12345
    
    # Set signature with pattern
    report.signature = bytes([((i * 3) % 256) for i in range(VBS_VM_MAX_SIGNATURE_SIZE)])
    
    # Round-trip
    serialized = report.serialize()
    restored = VbsVmReport.deserialize(serialized)
    
    # Verify header
    assert restored.header.package_size == 111
    assert restored.header.version == 222
    assert restored.header.signature_scheme == 333
    assert restored.header.signature_size == 444
    assert restored.header.reserved == 555
    
    # Verify other fields
    assert restored.version == 999
    assert restored.report_data == report.report_data
    assert restored.identity.owner_id == report.identity.owner_id
    assert restored.identity.measurement == report.identity.measurement
    assert restored.identity.enabled_vtl == 0x12345678
    assert restored.identity.policy == 0x87654321
    assert restored.identity.guest_svn == 12345
    assert restored.signature == report.signature
