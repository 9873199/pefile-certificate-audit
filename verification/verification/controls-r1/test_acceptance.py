"""Opaque payload controls and existing PE read-only integrations; never executes an image."""
import hashlib
import importlib.util
import struct
from pathlib import Path

import pefile
import pe_adapter as api
import pytest

spec = importlib.util.spec_from_file_location('pe_control_fixtures', Path(__file__).with_name('pe_fixtures.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
def test_opaque_certificate_payload_is_not_guessed_as_another_record(plus):
    # A valid-looking WIN_CERTIFICATE header inside an opaque payload is data,
    # not an independently indexed certificate. There is no signature check.
    payload = struct.pack('<IHH', 16, 0x200, 2) + b'opaque-data-only'
    assert len(payload) + 8 == 32
    wire = fixtures.minimal_pe(plus=plus, records=[fixtures.certificate(payload)])
    result = api.audit(wire, strict=True)
    assert result['present'] and not result['issues']
    assert len(result['certificates']) == 1
    assert result['certificates'][0]['declared_length'] == len(payload) + 8
    assert result['status'] == 'readable_unverified'


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
def test_file_and_pe_write_bytes_unchanged_across_audit_and_directory_parse(tmp_path, plus):
    records = [fixtures.certificate(b'abcd'), fixtures.certificate(b'pq')]
    overlay = b'ordinary trailing overlay'
    wire = fixtures.minimal_pe(plus=plus, records=records, overlay=overlay)
    filename = tmp_path / 'nonexecuted-static-fixture.bin'
    filename.write_bytes(wire)
    before_hash = hashlib.sha256(filename.read_bytes()).hexdigest()
    full = pefile.PE(str(filename), fast_load=False)
    fast = pefile.PE(str(filename), fast_load=True)
    try:
        full_before, fast_before = full.write(), fast.write()
        one = api.audit_object(full, strict=False)
        fast.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        two = api.audit_object(fast, strict=False)
        assert one == two
        assert full.write() == full_before == wire
        assert fast.write() == fast_before == wire
        assert full.get_overlay_data_start_offset() == 0x420
        assert full.get_overlay() == overlay
        assert fast.get_overlay_data_start_offset() == 0x420
        assert fast.get_overlay() == overlay
        assert isinstance(full.dump_dict(), dict)
        assert isinstance(fast.dump_dict(), dict)
    finally:
        full.close()
        fast.close()
    assert hashlib.sha256(filename.read_bytes()).hexdigest() == before_hash
    assert filename.read_bytes() == wire


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
def test_single_record_declared_interval_includes_zero_padding(plus):
    wire = fixtures.minimal_pe(plus=plus, records=[fixtures.certificate(b'abc')])
    result = api.audit(wire, strict=True)
    cert = result['certificates'][0]
    assert cert['offset'] == 0x400 and cert['declared_length'] == 16
    assert cert['end_offset'] == 0x410
    assert cert['aligned_end_offset'] == 0x410
    assert result['table_size'] == 16 and len(result['certificates']) == 1


def test_lenient_result_does_not_bypass_strict_rejection_on_reused_object():
    wire = fixtures.minimal_pe(records=[fixtures.certificate(b'', length=4)])
    with pefile.PE(data=wire, fast_load=True) as pe:
        before = pe.write()
        malformed = api.audit_object(pe, strict=False)
        assert malformed['status'] == 'malformed'
        with pytest.raises(api.StructureError) as caught:
            api.audit_object(pe, strict=True)
        assert caught.value.anomaly.code == 'length_less_than_header'
        assert caught.value.anomaly.offset == 0x400
        assert pe.write() == before == wire
