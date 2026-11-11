"""Deterministic, non-executable minimal PE fixture builder for independent auditing."""
import struct

def certificate(payload=b'local certificate bytes',length=None,revision=0x0200,kind=0x0002):
    declared=((len(payload)+8+7)&~7) if length is None else length
    body=struct.pack('<IHH',declared,revision,kind)+payload
    return body+b'\0'*((-len(body))%8)

def minimal_pe(plus=False,records=None,offset=0x400,size=None,overlay=b'',section_raw=(0x200,0x200)):
    records=[certificate()] if records is None else records
    table=b''.join(records)
    data=bytearray(0x400)
    data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';optional_size=0xf0 if plus else 0xe0
    struct.pack_into('<HHIIIHH',data,0x84,0x8664 if plus else 0x14c,1,0,0,0,optional_size,0x2022)
    optional=0x98;struct.pack_into('<H',data,optional,0x20b if plus else 0x10b)
    struct.pack_into('<II',data,optional+32,0x1000,0x200)
    struct.pack_into('<II',data,optional+56,0x2000,0x200)
    struct.pack_into('<I',data,optional+(108 if plus else 92),16)
    directory=optional+(112 if plus else 96)+4*8
    struct.pack_into('<II',data,directory,offset,len(table) if size is None else size)
    section=optional+optional_size;data[section:section+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,section+8,0x100,0x1000,section_raw[1],section_raw[0])
    struct.pack_into('<I',data,section+36,0x60000020)
    if offset==0x400:data.extend(table)
    data.extend(overlay)
    return bytes(data)
