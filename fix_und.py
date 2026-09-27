#!/usr/bin/env python3
"""把 .ko symtab 中的 UND 符号重定向到同名 .cfi_jt 定义（CFI/LTO 残留修复）"""
import struct, sys

def fix(path):
    d = bytearray(open(path, 'rb').read())
    e_shoff, = struct.unpack_from('<Q', d, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x3A)
    def shdr(i):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', d, o)
        return dict(name=name, typ=typ, off=off, size=size, link=link, entsize=entsize, hdr=o)
    sh = [shdr(i) for i in range(e_shnum)]
    symtab = next(s for s in sh if s['typ'] == 2)  # SHT_SYMTAB
    strtab = sh[symtab['link']]
    def sname(off):
        end = d.index(b'\x00', strtab['off'] + off)
        return d[strtab['off'] + off:end].decode()
    n = symtab['size'] // symtab['entsize']
    fixed = []
    syms = []
    for i in range(n):
        o = symtab['off'] + i * symtab['entsize']
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, o)
        syms.append((o, st_name, st_info, st_other, st_shndx, st_value, st_size))
    # 建 cfi_jt 定义索引
    defs = {}
    for (o, name, info, other, shndx, value, size) in syms:
        if shndx != 0 and shndx != 0xffff:
            nm = sname(name)
            if nm.endswith('.cfi_jt'):
                defs[nm[:-len('.cfi_jt')]] = (shndx, value)
    for (o, name, info, other, shndx, value, size) in syms:
        if shndx == 0 and name:  # UND
            nm = sname(name)
            if nm in defs:
                new_shndx, new_value = defs[nm]
                struct.pack_into('<IBBHQQ', d, o, name, info, other, new_shndx, new_value, size)
                fixed.append(nm)
    open(path, 'wb').write(d)
    print(f"fixed {len(fixed)} UND syms: {fixed[:10]}")

fix(sys.argv[1])
