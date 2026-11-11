"""Exact native exception/code/offset checks, with unambiguously padded normal controls."""
import hashlib
import struct

import pefile
import pe_fixtures as fixtures
import pe_adapter as api
import pytest


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
def test_multiple_certificates_offsets_and_overlay_boundary(plus):
    wire = fixtures.minimal_pe(plus, [fixtures.certificate(b'abcd'), fixtures.certificate(b'pq')],
                               overlay=fixtures.certificate(b'overlay-not-certificate'))
    result = api.audit(wire, strict=True)
    assert result['present'] and not result['issues']
    assert result['status'] == 'readable_unverified'
    assert [(x['offset'], x['declared_length'], x['revision'], x['type'])
            for x in result['certificates']] == [(0x400, 16, 0x200, 2), (0x410, 16, 0x200, 2)]
    assert result['table_offset'] == 0x400 and result['table_size'] == 32
    assert api.audit(wire, fast_load=True) == api.audit(wire, fast_load=False)


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
def test_absent_directory_has_distinct_status(plus):
    wire = fixtures.minimal_pe(plus, records=[], offset=0, size=0)
    result = api.audit(wire)
    assert not result['present'] and not result['certificates'] and not result['issues']
    assert result['status'] in ('empty', 'absent')


def cases(plus):
    directory = 0x98 + (112 if plus else 96) + 4*8
    base = fixtures.minimal_pe(plus, records=[fixtures.certificate(b'abcdefgh')])
    shifted = bytearray(base[:0x400] + b'\0' + base[0x400:])
    struct.pack_into('<I', shifted, directory, 0x401)
    overlap = bytearray(fixtures.minimal_pe(plus, offset=0x300, size=16))
    overlap[0x300:0x310] = fixtures.certificate(b'abcdefgh')
    partial = bytearray(base + b'\x01\x02\x03\x04')
    struct.pack_into('<I', partial, directory+4, 20)
    extent = bytearray(base)
    struct.pack_into('<I', extent, directory+4, 64)
    return {
        'short-length': (fixtures.minimal_pe(plus, [fixtures.certificate(b'', length=4)]), 'length_less_than_header', 0x400),
        'zero-length': (fixtures.minimal_pe(plus, [fixtures.certificate(b'', length=0)]), 'length_less_than_header', 0x400),
        'truncated-record': (fixtures.minimal_pe(plus, [fixtures.certificate(b'abc', length=104)]), 'record_truncated', 0x400),
        'outside-offset': (fixtures.minimal_pe(plus, offset=0xfffffff0, size=0x40), 'directory_beyond_file', 0xfffffff0),
        'extent-wrap': (fixtures.minimal_pe(plus, offset=0x400, size=0xfffffff0), 'directory_beyond_file', 0x400),
        'extent-outside-file': (bytes(extent), 'directory_size_beyond_file', 0x400),
        'misaligned-base': (bytes(shifted), 'misaligned_record', 0x401),
        'section-overlap': (bytes(overlap), 'record_in_section_raw_data', 0x300),
        'last-header-cut': (bytes(partial), 'header_truncated', 0x410),
    }


@pytest.mark.parametrize('plus', [False, True], ids=['PE32', 'PE32plus'])
@pytest.mark.parametrize('name', list(cases(False)))
def test_damage_has_exact_native_issue_and_strict_error_without_rewriting(plus, name):
    wire, code, offset = cases(plus)[name]
    digest = hashlib.sha256(wire).hexdigest()
    with pefile.PE(data=wire, fast_load=True) as pe:
        before = pe.write()
        result = api.audit_object(pe, strict=False)
        assert result['present'] and result['status'] == 'malformed'
        assert (code, offset) in {(item['code'], item['offset']) for item in result['issues']}
        with pytest.raises(api.StructureError) as caught:
            api.audit_object(pe, strict=True)
        assert caught.value.anomaly.code == code
        assert caught.value.anomaly.offset == offset
        assert caught.value.security_directory.status == 'malformed'
        assert pe.write() == before == wire
    assert hashlib.sha256(wire).hexdigest() == digest


def test_record_cap_stops_the_forward_walk(monkeypatch):
    # The product documents a fixed module cap, not a caller max_records argument.
    # Explicit test instrumentation lowers that actual cap, like the native suite.
    monkeypatch.setattr(pefile, 'MAX_CERTIFICATE_ENTRIES', 3)
    wire = fixtures.minimal_pe(records=[fixtures.certificate(b'') for _ in range(8)])
    result = api.audit(wire, strict=False)
    assert len(result['certificates']) == 3
    assert ('too_many_entries', 0x418) in {(x['code'], x['offset']) for x in result['issues']}
    with pytest.raises(api.StructureError) as caught:
        api.audit(wire, strict=True)
    assert caught.value.anomaly.code == 'too_many_entries'
    assert caught.value.anomaly.offset == 0x418
