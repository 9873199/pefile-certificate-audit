"""Field projection only; errors and statuses come from frozen pefile."""
import pefile
StructureError = pefile.SecurityDirectoryError

def project(result):
    return {'present': result.declared, 'status': result.status,
            'table_offset': result.directory_offset, 'table_size': result.directory_size,
            'certificates': [{'offset': entry.file_offset, 'declared_length': entry.dwLength,
                              'revision': entry.wRevision, 'type': entry.wCertificateType,
                              'end_offset': entry.end_offset,
                              'aligned_end_offset': entry.aligned_end_offset}
                             for entry in result.entries],
            'issues': [{'code': issue.code, 'offset': issue.offset,
                        'record_index': issue.record_index, 'message': issue.message}
                       for issue in result.all_anomalies()]}

def audit_object(pe, strict=False):
    return project(pe.parse_security_directory(strict=strict))

def audit(wire, strict=False, fast_load=False):
    with pefile.PE(data=wire, fast_load=fast_load) as pe:
        return audit_object(pe, strict=strict)
