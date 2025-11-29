# test_snp.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import struct
from src.snp import Signature, TcbVersion, PlatformInfo, KeyInfo, AttestationReport


@pytest.fixture
def sample_signature():
  return Signature(
    r_component=[0x01] * 72,
    s_component=[0x02] * 72,
    reserved=[0x00] * 368,
  )


@pytest.fixture
def sample_tcb_version():
  return TcbVersion(bootloader=1, tee=2, reserved=0, snp=3, microcode=4)


@pytest.fixture
def sample_platform_info():
  return PlatformInfo(
    smt_enabled=1,
    tsme_enabled=0,
    ecc_enabled=1,
    rapl_disabled=1,
    ciphertext_hiding_enabled=0,
    reserved=42,
  )


@pytest.fixture
def sample_key_info():
  return KeyInfo(author_key_en=1, mask_chip_key=0, signing_key=5, reserved=0)


@pytest.fixture
def sample_attestation_report(sample_signature, sample_tcb_version, sample_platform_info, sample_key_info):
  report = AttestationReport()
  report.version = 1
  report.guest_svn = 2
  report.policy = 0xABCD1234
  report.family_id = [0x01] * 16
  report.image_id = [0x02] * 16
  report.vmpl = 3
  report.sig_algo = 0x102
  report.current_tcb = sample_tcb_version
  report.plat_info = sample_platform_info
  report.key_info = sample_key_info
  report.report_data = [0x03] * 64
  report.measurement = [0x04] * 48
  report.host_data = [0x05] * 32
  report.id_key_digest = [0x06] * 48
  report.author_key_digest = [0x07] * 48
  report.report_id = [0x08] * 32
  report.report_id_ma = [0x09] * 32
  report.reported_tcb = sample_tcb_version
  report.chip_id = [0x10] * 64
  report.committed_tcb = sample_tcb_version
  report.signature = sample_signature
  return report


def test_signature_serialize_deserialize(sample_signature):
  serialized = sample_signature.serialize()
  assert len(serialized) == 512

  deserialized = Signature.deserialize(serialized)
  assert deserialized.r_component == sample_signature.r_component
  assert deserialized.s_component == sample_signature.s_component
  assert deserialized.reserved == sample_signature.reserved


def test_tcb_version_serialize_deserialize(sample_tcb_version):
  serialized = sample_tcb_version.serialize()
  assert len(serialized) == 8

  deserialized = TcbVersion.deserialize(serialized)
  assert deserialized.bootloader == sample_tcb_version.bootloader
  assert deserialized.tee == sample_tcb_version.tee
  assert deserialized.reserved == sample_tcb_version.reserved
  assert deserialized.snp == sample_tcb_version.snp
  assert deserialized.microcode == sample_tcb_version.microcode


def test_platform_info_serialize_deserialize(sample_platform_info):
  serialized_value = sample_platform_info.serialize()
  serialized = struct.pack('<Q', int.from_bytes(serialized_value, byteorder='little'))
  assert len(serialized) == 8

  deserialized = PlatformInfo.deserialize(serialized)
  assert deserialized.smt_enabled == sample_platform_info.smt_enabled
  assert deserialized.tsme_enabled == sample_platform_info.tsme_enabled
  assert deserialized.ecc_enabled == sample_platform_info.ecc_enabled
  assert deserialized.rapl_disabled == sample_platform_info.rapl_disabled
  assert deserialized.ciphertext_hiding_enabled == sample_platform_info.ciphertext_hiding_enabled
  assert deserialized.reserved == sample_platform_info.reserved


def test_key_info_serialize_deserialize(sample_key_info):
  serialized = sample_key_info.serialize()
  assert len(serialized) == 4

  deserialized = KeyInfo.deserialize(serialized)
  assert deserialized.author_key_en == sample_key_info.author_key_en
  assert deserialized.mask_chip_key == sample_key_info.mask_chip_key
  assert deserialized.signing_key == sample_key_info.signing_key
  assert deserialized.reserved == sample_key_info.reserved


def test_attestation_report_serialize_deserialize(sample_attestation_report):
  serialized = sample_attestation_report.serialize()
  assert len(serialized) == AttestationReport.calculate_size()
  

  deserialized = AttestationReport.deserialize(serialized)
  assert deserialized.version == sample_attestation_report.version
  assert deserialized.guest_svn == sample_attestation_report.guest_svn
  assert deserialized.policy == sample_attestation_report.policy
  assert deserialized.family_id == sample_attestation_report.family_id
  assert deserialized.image_id == sample_attestation_report.image_id
  assert deserialized.vmpl == sample_attestation_report.vmpl
  assert deserialized.sig_algo == sample_attestation_report.sig_algo
  assert deserialized.report_data == sample_attestation_report.report_data
  assert deserialized.measurement == sample_attestation_report.measurement
  assert deserialized.host_data == sample_attestation_report.host_data
  assert deserialized.id_key_digest == sample_attestation_report.id_key_digest
  assert deserialized.author_key_digest == sample_attestation_report.author_key_digest
  assert deserialized.report_id == sample_attestation_report.report_id
  assert deserialized.report_id_ma == sample_attestation_report.report_id_ma


def test_attestation_report_display(capsys, sample_attestation_report):
  sample_attestation_report.display()
  captured = capsys.readouterr()
  assert "Attestation Report" in captured.out
  assert "Version:" in captured.out
  assert "Guest SVN:" in captured.out
