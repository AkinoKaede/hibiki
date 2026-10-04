"""Test-only software card arithmetic using GnuPG's independently installed libgcrypt.

Private test keys come from temporary GnuPG homes. This module is never linked into
HIbiki, packaged with iOS, or used for production private-key operations.
"""
import ctypes as C
import ctypes.util
import shutil
from pathlib import Path

path = ctypes.util.find_library('gcrypt')
if not path and shutil.which('gpg'):
    candidate = Path(shutil.which('gpg')).parent.parent/'lib/libgcrypt.dylib'
    if candidate.exists(): path = str(candidate)
if not path:
    raise RuntimeError('Install libgcrypt (provided with GnuPG) for mobile integration tests')
lib = C.CDLL(path)

def api(name, args, result=C.c_uint):
    fn = getattr(lib, name); fn.argtypes = args; fn.restype = result
    return fn

ptr = C.c_void_p
check = api('gcry_check_version', [C.c_char_p], C.c_char_p)
check(None)
sexp_new = api('gcry_sexp_new', [C.POINTER(ptr), ptr, C.c_size_t, C.c_int])
sexp_find = api('gcry_sexp_find_token', [ptr, C.c_char_p, C.c_size_t], ptr)
sexp_data = api('gcry_sexp_nth_data', [ptr, C.c_int, C.POINTER(C.c_size_t)], ptr)
sexp_free = api('gcry_sexp_release', [ptr], None)
sign = api('gcry_pk_sign', [C.POINTER(ptr), ptr, ptr])
ec_new = api('gcry_mpi_ec_new', [C.POINTER(ptr), ptr, C.c_char_p])
ec_get_mpi = api('gcry_mpi_ec_get_mpi', [C.c_char_p, ptr, C.c_int], ptr)
mpi_scan = api('gcry_mpi_scan', [C.POINTER(ptr), C.c_int, ptr, C.c_size_t, C.POINTER(C.c_size_t)])
mpi_print = api('gcry_mpi_print', [C.c_int, ptr, C.c_size_t, C.POINTER(C.c_size_t), ptr])
mpi_new = api('gcry_mpi_new', [C.c_uint], ptr)
mpi_free = api('gcry_mpi_release', [ptr], None)
point_new = api('gcry_mpi_point_new', [C.c_uint], ptr)
point_free = api('gcry_mpi_point_release', [ptr], None)
point_set = api('gcry_mpi_point_set', [ptr, ptr, ptr, ptr], ptr)
point_mul = api('gcry_mpi_ec_mul', [ptr, ptr, ptr, ptr], None)
point_affine = api('gcry_mpi_ec_get_affine', [ptr, ptr, ptr, ptr], C.c_int)
ctx_free = api('gcry_ctx_release', [ptr], None)
CURVES = {'ed25519': 'Ed25519', 'cv25519': 'Curve25519', 'nistp256': 'NIST P-256', 'nistp384': 'NIST P-384', 'nistp521': 'NIST P-521'}
WIDTHS = {'ed25519': 32, 'cv25519': 32, 'nistp256': 32, 'nistp384': 48, 'nistp521': 66}


def expr(text):
    data = text.encode(); result = ptr()
    assert sexp_new(C.byref(result), data, len(data), 1) == 0
    return result


def secret(key):
    name = key['algorithm']
    flags = '(flags eddsa)' if name == 'ed25519' else '(flags djb-tweak)' if name == 'cv25519' else ''
    return expr('(private-key(ecc(curve "%s")%s(q #%s#)(d #%s#)))' % (CURVES[name], flags, key['q'], key['d']))


def get_field(key, name):
    field = sexp_find(key, name.encode(), 0)
    length = C.c_size_t()
    data = sexp_data(field, 1, C.byref(length))
    result = C.string_at(data, length.value)
    sexp_free(field)
    return result


def ecc_sign(key, data):
    private = secret(key)
    flags = '(flags eddsa)(hash-algo sha512)' if key['algorithm'] == 'ed25519' else '(flags raw)'
    message = expr('(data%s(value #%s#))' % (flags, data.hex()))
    signature = ptr()
    try:
        assert sign(C.byref(signature), message, private) == 0
        width = WIDTHS[key['algorithm']]
        values = [get_field(signature, f) for f in ('r', 's')]
        if key['algorithm'] == 'ed25519':
            assert all(len(v) == width for v in values)
            return b''.join(values)
        return b''.join(v.lstrip(b'\0').rjust(width, b'\0') for v in values)
    finally:
        for value in [signature, message, private]: sexp_free(value)


def integer(data):
    value = ptr()
    assert mpi_scan(C.byref(value), 5, data, len(data), None) == 0
    return value


def ecdh(key, encoded):
    name = key['algorithm']; width = WIDTHS[name]
    private = secret(key); ctx = ptr()
    assert ec_new(C.byref(ctx), private, None) == 0
    scalar = ec_get_mpi(b'd', ctx, 1)
    if name == 'cv25519':
        x = integer(encoded[::-1]); y = integer(b'\0')
    else:
        assert encoded[0] == 4 and len(encoded) == width*2+1
        x = integer(encoded[1:width+1]); y = integer(encoded[width+1:])
    z = integer(b'\1'); point = point_new(0); out = point_new(0)
    rx = mpi_new(0); ry = mpi_new(0)
    try:
        point_set(point, x, y, z)
        point_mul(out, scalar, point, ctx)
        assert point_affine(rx, None if name == 'cv25519' else ry, out, ctx) == 0
        result = C.create_string_buffer(width); length = C.c_size_t()
        assert mpi_print(5, result, width, C.byref(length), rx) == 0
        raw = result.raw[:length.value].rjust(width, b'\0')
        return raw[::-1] if name == 'cv25519' else raw
    finally:
        for value in [scalar, x, y, z, rx, ry]: mpi_free(value)
        for value in [point, out]: point_free(value)
        ctx_free(ctx); sexp_free(private)


def secret_ecc_packets(data):
    result = []; offset = 0
    while offset < len(data):
        head = data[offset]; offset += 1
        if head & 64:
            tag = head & 63; n = data[offset]; offset += 1
            if n < 192: size = n
            elif n < 224: size = (n-192)*256+data[offset]+192; offset += 1
            elif n == 255: size = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
            else: raise AssertionError('partial packet')
        else:
            tag = (head >> 2) & 15; length = 1 << (head & 3)
            size = int.from_bytes(data[offset:offset+length], 'big'); offset += length
        packet = data[offset:offset+size]; offset += size
        if tag not in (5, 7): continue
        assert packet[0] == 4 and packet[5] in (18, 19, 22)
        pos = 6; oidlen = packet[pos]; pos += 1
        oid = packet[pos:pos+oidlen]; pos += oidlen
        def mpi():
            nonlocal pos
            size = (int.from_bytes(packet[pos:pos+2], 'big')+7)//8; pos += 2
            value = packet[pos:pos+size]; pos += size
            return value.hex()
        q = mpi()
        if packet[5] == 18: pos += packet[pos]+1
        assert packet[pos] == 0; pos += 1
        result.append({'q': q, 'd': mpi(), 'oid': oid.hex(), 'algo_id': packet[5]})
    return result


def make_ecc_card(device, signing, decryption):
    device.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'Mobile ECC <ecc@example.test>', signing, 'sign', '0')
    listing = device.gpg('--with-colons', '--list-secret-keys').stdout.decode()
    fpr = next(l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:'))
    device.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', fpr, decryption, 'encr', '0')
    lines = device.gpg('--with-colons', '--with-keygrip', '--list-secret-keys').stdout.decode().splitlines()
    prints = [l.split(':')[9] for l in lines if l.startswith('fpr:')]
    grips = [l.split(':')[9] for l in lines if l.startswith('grp:')]
    keys = secret_ecc_packets(device.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--export-secret-keys', fpr).stdout)
    for i, key in enumerate(keys): key.update(algorithm=[signing, decryption][i], fingerprint=prints[i], grip=grips[i], ref='OPENPGP.%s' % (i+1))
    return fpr, device.gpg('--export', fpr).stdout, {'serial': 'D2760001240103040005000012340000', 'keys': keys}
