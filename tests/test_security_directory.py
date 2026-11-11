"""Structural audit tests for the IMAGE_DIRECTORY_ENTRY_SECURITY table.

The PE images used here are assembled in memory: no sample is ever executed
and no certificate chain is checked. Every corruption is applied to the same
minimal PE32 / PE32+ layout so that the two architectures can be compared
case by case. Assertions pin exact file offsets and anomaly codes, and every
test proves that parsing never mutates the original PE bytes.
"""

import hashlib
import struct

import pytest

import pefile

# Fixed layout shared by the minimal PE32 and PE32+ images.
NT_HEADERS_OFFSET = 0x80
OPTIONAL_HEADER_OFFSET = NT_HEADERS_OFFSET + 4 + 20  # 0x98
SECTION_RAW_OFFSET = 0x200
SECTION_RAW_SIZE = 0x200
CERTIFICATE_TABLE_OFFSET = 0x400
DEFAULT_FILE_SIZE = 0x460

PE32_OPTIONAL_SIZE = 0xE0
PE32PLUS_OPTIONAL_SIZE = 0xF0

WIN_CERT_HEADER_SIZE = pefile.WIN_CERTIFICATE_HEADER_SIZE
ALIGNMENT = pefile.WIN_CERTIFICATE_ALIGNMENT


def _optional_size(plus):
    return PE32PLUS_OPTIONAL_SIZE if plus else PE32_OPTIONAL_SIZE


def _data_directory_offset(plus):
    return OPTIONAL_HEADER_OFFSET + _optional_size(plus) - 16 * 8


def _section_header_offset(plus):
    return OPTIONAL_HEADER_OFFSET + _optional_size(plus)


def build_minimal_pe(plus=False, total_size=DEFAULT_FILE_SIZE, rva_sizes=16):
    """Build a minimal, parseable PE32 or PE32+ with one .text section.

    The section raw data occupies [0x200, 0x400); everything from 0x400 is
    free trailing space where the certificate table and overlay are placed.
    """

    machine = 0x8664 if plus else 0x14C
    magic = pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS if plus else pefile.OPTIONAL_HEADER_MAGIC_PE
    optional_size = _optional_size(plus)

    buf = bytearray(total_size)

    # DOS header: signature and e_lfanew only.
    struct.pack_into("<H", buf, 0, 0x5A4D)
    struct.pack_into("<I", buf, 0x3C, NT_HEADERS_OFFSET)

    # NT signature and IMAGE_FILE_HEADER.
    buf[NT_HEADERS_OFFSET:NT_HEADERS_OFFSET + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        buf,
        NT_HEADERS_OFFSET + 4,
        machine,
        1,                 # NumberOfSections
        0, 0, 0,
        optional_size,     # SizeOfOptionalHeader
        0x0102,            # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    off = OPTIONAL_HEADER_OFFSET
    if plus:
        # PE32+ standard fields.
        struct.pack_into("<HBBIII", buf, off, magic, 0, 0, 0x200, 0, 0)
        # PE32+ Windows-specific fields (24 qword/dword/word values).
        struct.pack_into(
            "<QIIHHHHHHIIIIHHQQQQII",
            buf,
            off + 24,
            0x140000000,       # ImageBase
            0x1000,            # SectionAlignment
            0x200,             # FileAlignment
            6, 0, 0, 0, 6, 0,  # version fields
            0,                 # Win32VersionValue
            0x3000,            # SizeOfImage
            SECTION_RAW_OFFSET,  # SizeOfHeaders
            0,                 # CheckSum
            3, 0,              # Subsystem, DllCharacteristics
            0x100000, 0x1000, 0x100000, 0x1000,
            0, rva_sizes,      # LoaderFlags, NumberOfRvaAndSizes
        )
    else:
        # PE32 standard fields.
        struct.pack_into(
            "<HBBIIIIII",
            buf,
            off,
            magic, 0, 0,
            0x200, 0, 0,       # SizeOfCode / initialized / uninitialized
            0x1000,            # AddressOfEntryPoint
            0x2000,            # BaseOfCode
            0x4000,            # BaseOfData
        )
        # PE32 Windows-specific fields.
        struct.pack_into(
            "<IIIHHHHHHIIIIHHIIIIII",
            buf,
            off + 28,
            0x00400000,        # ImageBase
            0x1000,            # SectionAlignment
            0x200,             # FileAlignment
            6, 0, 0, 0, 6, 0,  # version fields
            0,                 # Win32VersionValue
            0x3000,            # SizeOfImage
            SECTION_RAW_OFFSET,  # SizeOfHeaders
            0,                 # CheckSum
            3, 0,              # Subsystem, DllCharacteristics
            0x100000, 0x1000, 0x100000, 0x1000,
            0, rva_sizes,      # LoaderFlags, NumberOfRvaAndSizes
        )

    # Single section header.
    sh_off = _section_header_offset(plus)
    buf[sh_off:sh_off + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII",
        buf,
        sh_off + 8,
        SECTION_RAW_SIZE,        # Misc_VirtualSize
        0x1000,                  # VirtualAddress
        SECTION_RAW_SIZE,        # SizeOfRawData
        SECTION_RAW_OFFSET,      # PointerToRawData
    )
    struct.pack_into("<I", buf, sh_off + 36, 0x60000020)

    # Section raw data, filled so that certificate placement inside it is
    # unambiguously detectable.
    buf[SECTION_RAW_OFFSET:SECTION_RAW_OFFSET + SECTION_RAW_SIZE] = (
        b"\xCC" * SECTION_RAW_SIZE
    )
    return buf


def set_security_directory(buf, plus, virtual_address, size):
    """Patch IMAGE_DIRECTORY_ENTRY_SECURITY (data directory index 4)."""

    dd_off = _data_directory_offset(plus)
    struct.pack_into("<II", buf, dd_off + 4 * 8, virtual_address, size)


def make_certificate(length, revision=0x0200, cert_type=0x0002, fill=0xAB):
    """Build one WIN_CERTIFICATE blob of the given (aligned) total length."""

    payload = bytes([fill]) * (length - WIN_CERT_HEADER_SIZE)
    return struct.pack("<IHH", length, revision, cert_type) + payload


def place(buf, offset, blob):
    buf[offset:offset + len(blob)] = blob


def audit(buf, plus, strict=False, fast_load=False):
    data = bytes(buf)
    pe = pefile.PE(data=data, fast_load=fast_load)
    return pe, pe.parse_security_directory(strict=strict)


def anomaly_tuples(result):
    """(code, offset, record_index) triples in reporting order."""

    return [
        (anomaly.code, anomaly.offset, anomaly.record_index)
        for anomaly in result.all_anomalies()
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_no_certificate_table_is_distinct_from_a_broken_one(plus):
    buf = build_minimal_pe(plus)
    pe, result = audit(buf, plus)

    assert result.status == "empty"
    assert result.declared is False
    assert result.entries == []
    assert result.all_anomalies() == []
    assert result.valid_structure is False
    # Nothing claims signature validity.
    assert not hasattr(result, "signature_valid")
    # With no table, the free trailing space of the minimal image is overlay.
    assert pe.get_overlay_data_start_offset() == CERTIFICATE_TABLE_OFFSET


def test_security_directory_entry_absent():
    # NumberOfRvaAndSizes == 4 means data directory index 4 does not exist.
    # SizeOfOptionalHeader must match so pefile does not infer extra entries.
    for plus in (False, True):
        buf = build_minimal_pe(plus, rva_sizes=4)
        optional_size = _optional_size(plus)
        file_header_off = NT_HEADERS_OFFSET + 4
        struct.pack_into(
            "<H",
            buf,
            file_header_off + 16,
            # PE32: 96 header bytes + 4 directories; PE32+: 112 + 4.
            (96 if not plus else 112) + 4 * 8,
        )
        pe = pefile.PE(data=bytes(buf))
        result = pe.parse_security_directory()
        assert result.present is False
        assert result.status == "absent"
        assert result.declared is False
        assert optional_size  # sanity: original layout constant still known


@pytest.mark.parametrize("plus", [False, True])
def test_readable_table_is_not_reported_as_signature_valid(plus):
    buf = build_minimal_pe(plus, total_size=0x440)
    first = make_certificate(0x10, revision=0x0200, cert_type=0x0002)
    second = make_certificate(0x18, revision=0x0100, cert_type=0x0002, fill=0xCD)
    place(buf, CERTIFICATE_TABLE_OFFSET, first)
    place(buf, CERTIFICATE_TABLE_OFFSET + 0x10, second)
    # Overlay follows immediately after the 0x28 bytes of certificate data.
    buf[CERTIFICATE_TABLE_OFFSET + 0x28:CERTIFICATE_TABLE_OFFSET + 0x30] = (
        b"OVLAY!!" + b"\0"
    )
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x28)

    pe, result = audit(buf, plus)

    assert result.status == "readable_unverified"
    assert result.valid_structure is True
    assert result.all_anomalies() == []
    assert result.table_start_offset == CERTIFICATE_TABLE_OFFSET
    assert result.table_end_offset == CERTIFICATE_TABLE_OFFSET + 0x28

    assert len(result.entries) == 2
    entry0, entry1 = result.entries
    assert entry0.file_offset == 0x400
    assert entry0.dwLength == 0x10
    assert entry0.wRevision == 0x0200
    assert entry0.revision_name == "WIN_CERT_REVISION_2_0"
    assert entry0.wCertificateType == 0x0002
    assert entry0.certificate_type_name == "WIN_CERT_TYPE_PKCS_SIGNED_DATA"
    assert entry0.data_offset == 0x408
    assert entry0.end_offset == 0x410
    assert entry0.aligned_end_offset == 0x410
    assert entry0.data == b"\xAB" * 8

    assert entry1.file_offset == 0x410
    assert entry1.dwLength == 0x18
    assert entry1.wRevision == 0x0100
    assert entry1.revision_name == "WIN_CERT_REVISION_1_0"
    assert entry1.end_offset == 0x428
    assert entry1.aligned_end_offset == 0x428
    assert entry1.data == b"\xCD" * 0x10

    # The overlay must start right after the table and never be swallowed.
    assert pe.get_overlay_data_start_offset() == 0x428
    assert pe.get_overlay().startswith(b"OVLAY!!")

    # "Structurally readable" must never be phrased as a valid signature.
    assert "valid" not in result.status


@pytest.mark.parametrize("plus", [False, True])
def test_declared_length_smaller_than_header(plus):
    buf = build_minimal_pe(plus)
    place(buf, CERTIFICATE_TABLE_OFFSET, make_certificate(0x10))
    struct.pack_into("<I", buf, CERTIFICATE_TABLE_OFFSET, 4)
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_LENGTH_TOO_SMALL, CERTIFICATE_TABLE_OFFSET, 0),
    ]
    # The unparseable record header is still located for the report.
    assert result.entries[0].dwLength == 4
    assert result.entries[0].file_offset == CERTIFICATE_TABLE_OFFSET


@pytest.mark.parametrize("plus", [False, True])
def test_last_record_truncated(plus):
    # File ends at 0x420 but the record claims 0x40 bytes starting at 0x400.
    buf = build_minimal_pe(plus, total_size=0x420)
    place(
        buf,
        CERTIFICATE_TABLE_OFFSET,
        make_certificate(0x40)[:0x20],
    )
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x20)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_RECORD_TRUNCATED, CERTIFICATE_TABLE_OFFSET, 0),
    ]
    entry = result.entries[0]
    assert entry.dwLength == 0x40
    assert entry.end_offset == 0x440
    # Only the physically present payload is exposed.
    assert len(entry.data) == 0x20 - WIN_CERT_HEADER_SIZE


@pytest.mark.parametrize("plus", [False, True])
def test_directory_start_beyond_end_of_file(plus):
    buf = build_minimal_pe(plus)
    set_security_directory(buf, plus, 0x500, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_DIRENT_BEYOND_EOF, 0x500, None),
    ]
    assert result.entries == []


@pytest.mark.parametrize("plus", [False, True])
def test_directory_extent_runs_past_end_of_file(plus):
    buf = build_minimal_pe(plus, total_size=0x420)
    place(buf, CERTIFICATE_TABLE_OFFSET, make_certificate(0x10))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x40)

    pe, result = audit(buf, plus)
    codes = [code for code, _off, _idx in anomaly_tuples(result)]
    assert pefile.SECURITY_ANOMALY_DIRENT_SIZE_BEYOND_EOF in codes
    assert result.status == "malformed"


@pytest.mark.parametrize("plus", [False, True])
def test_integer_overflow_in_directory_extent(plus):
    buf = build_minimal_pe(plus)
    set_security_directory(buf, plus, 0xFFFFFFF0, 0x40)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_DIRENT_BEYOND_EOF, 0xFFFFFFF0, None),
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_records_overlapping_each_other(plus):
    buf = build_minimal_pe(plus)
    # First record claims [0x400, 0x420); a second header sits at 0x410.
    place(buf, 0x400, make_certificate(0x20))
    place(buf, 0x410, make_certificate(0x10, fill=0xCD))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x20)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    tuples = anomaly_tuples(result)
    assert any(
        code == pefile.SECURITY_ANOMALY_OVERLAPPING_RECORD
        and offset == 0x410
        for code, offset, _idx in tuples
    )


@pytest.mark.parametrize("plus", [False, True])
def test_record_length_breaks_eight_byte_alignment(plus):
    buf = build_minimal_pe(plus)
    # dwLength 0x14 is not a multiple of 8.
    place(buf, 0x400, make_certificate(0x14))
    place(buf, 0x418, make_certificate(0x10, fill=0xCD))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x28)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result)[0] == (
        pefile.SECURITY_ANOMALY_MISALIGNED_RECORD,
        CERTIFICATE_TABLE_OFFSET,
        0,
    )


@pytest.mark.parametrize("plus", [False, True])
def test_record_falls_inside_section_raw_data(plus):
    buf = build_minimal_pe(plus)
    place(buf, SECTION_RAW_OFFSET, make_certificate(0x10))
    set_security_directory(buf, plus, SECTION_RAW_OFFSET, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (
            pefile.SECURITY_ANOMALY_IN_SECTION_DATA,
            SECTION_RAW_OFFSET,
            0,
        ),
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_trailing_garbage_is_not_counted_as_certificate(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    # Zero terminator slot followed by non-directory bytes inside the extent.
    buf[0x410:0x418] = b"\0" * 8
    buf[0x418:0x420] = b"JUNKJUNK"
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x20)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    tuples = anomaly_tuples(result)
    assert any(
        code == pefile.SECURITY_ANOMALY_TRAILING_GARBAGE and offset == 0x410
        for code, offset, _idx in tuples
    )
    assert len(result.entries) == 1
    assert result.entries[0].file_offset == 0x400


@pytest.mark.parametrize("plus", [False, True])
def test_directory_size_does_not_match_records(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    # Declared 0x18 but only one 0x10 record exists; remainder is zero padding.
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x18)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_DIRENT_SIZE_MISMATCH, 0x410, None),
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_zero_offset_with_nonzero_size(plus):
    buf = build_minimal_pe(plus)
    set_security_directory(buf, plus, 0, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (pefile.SECURITY_ANOMALY_DIRENT_ZERO_OFFSET, 0, None),
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_directory_size_smaller_than_header(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 4)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result) == [
        (
            pefile.SECURITY_ANOMALY_DIRENT_SIZE_TOO_SMALL,
            CERTIFICATE_TABLE_OFFSET,
            None,
        ),
    ]


@pytest.mark.parametrize("plus", [False, True])
def test_entry_count_cap_is_enforced(plus, monkeypatch):
    monkeypatch.setattr(pefile, "MAX_CERTIFICATE_ENTRIES", 3)
    buf = build_minimal_pe(plus, total_size=0x500)
    for index in range(8):
        place(buf, 0x400 + index * 0x10, make_certificate(0x10))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x80)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    tuples = anomaly_tuples(result)
    assert any(
        code == pefile.SECURITY_ANOMALY_TOO_MANY_ENTRIES
        and offset == 0x430
        and record_index == 3
        for code, offset, record_index in tuples
    )
    # The walk always made forward progress and never exceeded the cap.
    assert len(result.entries) <= 3


@pytest.mark.parametrize("plus", [False, True])
def test_unknown_revision_and_type(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10, revision=0x0300, cert_type=0x0099))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    codes = {code for code, _off, _idx in anomaly_tuples(result)}
    assert pefile.SECURITY_ANOMALY_UNKNOWN_REVISION in codes
    assert pefile.SECURITY_ANOMALY_UNKNOWN_TYPE in codes
    # Unknown revision/type alone does not stop the structural walk.
    assert len(result.entries) == 1


@pytest.mark.parametrize("plus", [False, True])
def test_strict_mode_raises_and_keeps_partial_result(plus):
    buf = build_minimal_pe(plus, total_size=0x420)
    place(buf, 0x400, make_certificate(0x40)[:0x20])
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x20)

    pe = pefile.PE(data=bytes(buf))
    with pytest.raises(pefile.SecurityDirectoryError) as exc_info:
        pe.parse_security_directory(strict=True)

    error = exc_info.value
    assert error.anomaly.code == pefile.SECURITY_ANOMALY_RECORD_TRUNCATED
    partial = error.security_directory
    assert partial.strict is True
    assert partial.status == "malformed"
    assert len(partial.entries) == 1
    assert partial.entries[0].file_offset == CERTIFICATE_TABLE_OFFSET

    # Strict mode rejects any structural anomaly, even an otherwise readable
    # record that merely uses an unknown revision.
    odd = build_minimal_pe(plus)
    place(odd, 0x400, make_certificate(0x10, revision=0x0300))
    set_security_directory(odd, plus, CERTIFICATE_TABLE_OFFSET, 0x10)
    odd_pe = pefile.PE(data=bytes(odd))
    with pytest.raises(pefile.SecurityDirectoryError) as exc_info:
        odd_pe.parse_security_directory(strict=True)
    assert exc_info.value.anomaly.code == pefile.SECURITY_ANOMALY_UNKNOWN_REVISION
    # The same file is fully reported (not raised) in lenient mode.
    lenient = odd_pe.parse_security_directory(strict=False)
    assert lenient.status == "malformed"
    assert len(lenient.entries) == 1

    # A clean table must not raise in strict mode.
    clean = build_minimal_pe(plus)
    place(clean, 0x400, make_certificate(0x10))
    set_security_directory(clean, plus, CERTIFICATE_TABLE_OFFSET, 0x10)
    clean_pe = pefile.PE(data=bytes(clean))
    clean_result = clean_pe.parse_security_directory(strict=True)
    assert clean_result.status == "readable_unverified"


@pytest.mark.parametrize("plus", [False, True])
def test_zero_directory_size_with_records_is_malformed(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    # A non zero offset with a zero size cannot describe the present record.
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert any(
        code == pefile.SECURITY_ANOMALY_DIRENT_SIZE_MISMATCH
        for code, _off, _idx in anomaly_tuples(result)
    )
    # The record is still located for the forensic report.
    assert result.entries[0].file_offset == CERTIFICATE_TABLE_OFFSET


@pytest.mark.parametrize("plus", [False, True])
def test_misaligned_table_base_offset(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x404, make_certificate(0x10))
    set_security_directory(buf, plus, 0x404, 0x10)

    pe, result = audit(buf, plus)
    assert result.status == "malformed"
    assert anomaly_tuples(result)[0] == (
        pefile.SECURITY_ANOMALY_MISALIGNED_RECORD,
        0x404,
        None,
    )
    # Strict mode rejects the same condition.
    with pytest.raises(pefile.SecurityDirectoryError):
        pefile.PE(data=bytes(buf)).parse_security_directory(strict=True)


@pytest.mark.parametrize("plus", [False, True])
def test_fast_load_and_explicit_parse_agree(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x10)
    data = bytes(buf)

    fast = pefile.PE(data=data, fast_load=True)
    fast_result = fast.parse_security_directory()
    full = pefile.PE(data=data)
    full_result = full.parse_security_directory()

    assert fast_result.status == full_result.status
    assert anomaly_tuples(fast_result) == anomaly_tuples(full_result)
    assert [
        (entry.file_offset, entry.dwLength, entry.wRevision, entry.wCertificateType)
        for entry in fast_result.entries
    ] == [
        (entry.file_offset, entry.dwLength, entry.wRevision, entry.wCertificateType)
        for entry in full_result.entries
    ]
    # full_load() must not invalidate a previously computed audit.
    fast.full_load()
    assert fast.parse_security_directory().status == "readable_unverified"


@pytest.mark.parametrize("plus", [False, True])
def test_parsing_never_modifies_the_original_bytes(plus):
    buf = build_minimal_pe(plus, total_size=0x440)
    place(buf, 0x400, make_certificate(0x10))
    place(buf, 0x410, make_certificate(0x18, fill=0xCD))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x28)
    data = bytes(buf)
    digest_before = hashlib.sha256(data).hexdigest()

    pe = pefile.PE(data=data)
    pe.parse_security_directory(strict=False)
    pe.parse_security_directory(strict=True)
    pe.audit_security_directory()
    # write() round trip must reproduce the input byte for byte because the
    # audit structures are deliberately not registered for write-back.
    assert pe.write() == data
    assert hashlib.sha256(data).hexdigest() == digest_before
    assert hashlib.sha256(pe.write()).hexdigest() == digest_before


@pytest.mark.parametrize("plus", [False, True])
def test_audit_result_is_cached_and_alias_matches(plus):
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, 0x10)
    pe = pefile.PE(data=bytes(buf))

    first = pe.parse_security_directory()
    second = pe.parse_security_directory()
    assert first is second
    assert pe.audit_security_directory() is first

    strict = pe.parse_security_directory(strict=True)
    assert strict is not first
    assert strict.strict is True
    assert first.strict is False


@pytest.mark.parametrize("plus", [False, True])
def test_security_offset_is_never_treated_as_rva(plus):
    # The directory points at 0x400, which as an RVA would resolve inside the
    # .text section (RVA 0x1000 maps to file offset 0x200). The audit must use
    # it verbatim as a file offset and report the record at exactly 0x400.
    buf = build_minimal_pe(plus)
    place(buf, 0x400, make_certificate(0x10))
    set_security_directory(buf, plus, 0x400, 0x10)

    pe, result = audit(buf, plus)
    assert result.directory_offset == 0x400
    assert result.entries[0].file_offset == 0x400
    assert result.status == "readable_unverified"
    # Overlay bookkeeping also treats 0x400 as a raw file offset: the table
    # occupies [0x400, 0x410), so overlay starts exactly at 0x410 rather than
    # swallowing the certificate.
    assert pe.get_overlay_data_start_offset() == 0x410


@pytest.mark.parametrize("plus", [False, True])
def test_multi_certificate_sample_with_mixed_types(plus):
    # A normal, well-formed table carrying three records of different
    # revisions / types, followed by overlay outside the declared extent.
    buf = build_minimal_pe(plus, total_size=0x480)
    records = [
        (0x10, 0x0200, 0x0002, 0xAA),  # PKCS signed data, revision 2.0
        (0x18, 0x0100, 0x0002, 0xBB),  # PKCS signed data, revision 1.0
        (0x10, 0x0200, 0x0004, 0xCC),  # terminal server stack signed
    ]
    cursor = CERTIFICATE_TABLE_OFFSET
    total = 0
    for length, revision, cert_type, fill in records:
        place(buf, cursor, make_certificate(length, revision, cert_type, fill))
        cursor += length
        total += length
    buf[cursor:cursor + 6] = b"AFTER!"
    set_security_directory(buf, plus, CERTIFICATE_TABLE_OFFSET, total)

    pe, result = audit(buf, plus)
    assert result.status == "readable_unverified"
    assert result.valid_structure is True
    assert [entry.wCertificateType for entry in result.entries] == [2, 2, 4]
    assert [entry.dwLength for entry in result.entries] == [0x10, 0x18, 0x10]
    assert result.table_end_offset == CERTIFICATE_TABLE_OFFSET + total
    assert pe.get_overlay_data_start_offset() == CERTIFICATE_TABLE_OFFSET + total
    assert pe.get_overlay().startswith(b"AFTER!")
