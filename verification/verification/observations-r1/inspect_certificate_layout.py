"""Display frozen parser results directly, without compensating for either observed bug."""
import hashlib, json, struct
import pefile
import pe_fixtures as fixtures

for plus in (False, True):
    payload=struct.pack('<IHH',16,0x200,2)+b'opaque-data-only'
    wire=fixtures.minimal_pe(plus,records=[fixtures.certificate(payload)])
    with pefile.PE(data=wire,fast_load=True) as pe:
        result=pe.parse_security_directory(strict=False)
        print(json.dumps({'format':'PE32+' if plus else 'PE32','scenario':'one 32-byte record; header-like bytes are inside its opaque payload',
                          'declared_record_start':0x400,'declared_length':32,
                          'native_status':result.status,'native_entries':len(result.entries),
                          'native_issues':[{'code':x.code,'offset':x.offset} for x in result.all_anomalies()],
                          'input_sha256':hashlib.sha256(wire).hexdigest(),'write_unchanged':pe.write()==wire}))
        try: pe.parse_security_directory(strict=True)
        except pefile.SecurityDirectoryError as error:
            print('Strict rejection:',error.anomaly.code,'at',hex(error.anomaly.offset))
    wire=bytearray(fixtures.minimal_pe(plus,offset=0x300,size=16))
    wire[0x300:0x310]=fixtures.certificate(b'abcdefgh')
    wire=bytes(wire)
    with pefile.PE(data=wire,fast_load=True) as pe:
        try: pe.parse_security_directory(strict=True)
        except pefile.SecurityDirectoryError as error:
            print(json.dumps({'format':'PE32+' if plus else 'PE32','scenario':'record overlaps section raw bytes',
                              'strict_error':error.anomaly.code,'strict_error_offset':error.anomaly.offset,
                              'attached_partial_status':error.security_directory.status,
                              'attached_partial_entries':len(error.security_directory.entries),
                              'attached_partial_issues':len(error.security_directory.all_anomalies()),
                              'write_unchanged':pe.write()==wire}))
