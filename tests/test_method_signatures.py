import enum

import fixtures

import dnfile
from dnfile.utils import read_compressed_int




CALLING_CONVENTION_MASK = 0x0F
class CallingConvention(enum.Enum):
    DEFAULT = 0x00
    C = 0x1
    STDCALL= 0x2
    THISCALL = 0x3
    FASTCALL = 0x4
    VARARG = 0x5
    FIELD = 0x6
    LOCALSIG = 0x7
    PROPERTY = 0x8
    # Unmanaged calling convention encoded as modopts
    UNMANAGED = 0x9
    GENERICINST = 0xA
    # used ONLY for 64bit vararg PInvoke calls
    NATIVEVARARG = 0xB


SIGNATURE_FLAGS_MASK = 0xF0
class SignatureFlags(enum.IntFlag):
    GENERIC = 0x10
    HASTHIS = 0x20
    EXPLICIT_THIS = 0x40


class ElementType(enum.Enum):
    """
    EMCA-335 6th edition II.23.1.16
    """
    END          = 0x00  # Marks end of a list
    VOID         = 0x01
    BOOLEAN      = 0x02
    CHAR         = 0x03
    I1           = 0x04
    U1           = 0x05
    I2           = 0x06
    U2           = 0x07
    I4           = 0x08
    U4           = 0x09
    I8           = 0x0a
    U8           = 0x0b
    R4           = 0x0c
    R8           = 0x0d
    STRING       = 0x0e
    PTR          = 0x0f  # Followed by type
    BYREF        = 0x10  # Followed by type
    VALUETYPE    = 0x11  # Followed by TypeDef or TypeRef token
    CLASS        = 0x12  # Followed by TypeDef or TypeRef token
    VAR          = 0x13  # Generic parameter in a generic type definition, represented as number (compressed unsigned integer)
    ARRAY        = 0x14  # type rank boundsCount bound1 ... loCount lo1 ...
    GENERICINST  = 0x15  # Generic type instantiation. Followed by type type-arg-count type-1 ... type-n
    TYPEDBYREF   = 0x16
    I            = 0x18  # System.IntPtr
    U            = 0x19  # System.UIntPtr
    FNPTR        = 0x1b  # Followed by full method signature
    OBJECT       = 0x1c  # System.Object
    SZARRAY      = 0x1d  # Single-dim array with 0 lower bound
    MVAR         = 0x1e  # Generic parameter in a generic method definition, represented as number (compressed unsigned integer)
    CMOD_REQD    = 0x1f  # Required modifier : followed by a TypeDef or TypeRef token
    CMOD_OPT     = 0x20  # Optional modifier : followed by a TypeDef or TypeRef token
    INTERNAL     = 0x21  # Implemented within the CLI
    MODIFIER     = 0x40  # Or’d with following element types
    SENTINEL     = 0x41  # Sentinel for vararg method signature
    PINNED       = 0x45  # Denotes a local variable that points at a pinned object
    SYSTEM_TYPE  = 0x50  # Indicates an argument of type System.Type.
    BOXED_OBJECT = 0x51  # Used in custom attributes to specify a boxed object (§II.23.3).
    RESERVED     = 0x52  # Reserved
    FIELD        = 0x53  # Used in custom attributes to indicate a FIELD (§II.22.10, II.23.3).
    PROPERTY     = 0x54  # Used in custom attributes to indicate a PROPERTY (§II.22.10, II.23.3).
    ENUM         = 0x55  # Used in custom attributes to specify an enum (§II.23.3).


import io
import struct

# Rotate left: 0b1001 --> 0b0011
def rol(val, r_bits, max_bits):
    return (val << r_bits%max_bits) & (2**max_bits-1) \
        | ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

 
# Rotate right: 0b1001 --> 0b1100
def ror(val, r_bits, max_bits):
    return ((val & (2**max_bits-1)) >> r_bits%max_bits) \
        | (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def test_rol():
    assert rol(0b00000001, 1, 8) == 0b00000010
    assert rol(0b00000011, 1, 8) == 0b00000110
    assert rol(0b10000001, 1, 8) == 0b00000011


def test_ror():
    assert ror(0b10000000, 1, 8) == 0b01000000
    assert ror(0b11000000, 1, 8) == 0b01100000
    assert ror(0b10000001, 1, 8) == 0b11000000


class SignatureReader(io.BytesIO):
    def read_u8(self):
        return self.read(1)[0]

    def read_compressed_u32(self):
        """
        Read a compressed, unsigned integer per
        spec ECMA-335 II.23.2 Blobs and signatures.
        """
        b1 = self.read_u8()
        if b1 & 0x80 == 0:
            return struct.unpack(">B", bytes((b1, )))[0]
        elif b1 & 0x40 == 0:
            return struct.unpack(">H", bytes((b1 & 0x7F, self.read_u8())))[0]
        elif b1 & 0x20 == 0:
            return struct.unpack(">I", bytes((b1 & 0x3F, self.read_u8(), self.read_u8(), self.read_u8())))[0]
        else:
            raise ValueError("invalid compressed int")

    def read_compressed_i32(self):
        """
        Read a compressed, signed integer per
        spec ECMA-335 II.23.2 Blobs and signatures.
        """
        b1 = self.read_u8()

        if b1 & 0x80 == 0:
            # 7-bit, 1-byte integer
            n = b1

            # rotate right one bit, 7-bit number
            n = ror(n, 1, 7)

            # sign-extend 7-bit number to 8-bits
            if n & (1 << 6):
                n |= (1 << 7)

            # reinterpret as 8-bit, 1-byte, signed, big-endian integer
            return struct.unpack(">b", struct.pack(">B", n))[0]
        elif b1 & 0x40 == 0:
            # 14-bit, 2-byte, big-endian integer
            n = struct.unpack(">h", bytes((b1 & 0x7F, self.read_u8())))[0]

            # rotate right one bit, 14-bit number
            n = ror(n, 1, 14)

            # sign-extend 14-bit number to 16-bits
            if n & (1 << 13):
                n |= (1 << 14) | (1 << 15)

            # reinterpret as 16-bit, 2-byte, signed, big-endian integer
            return struct.unpack(">h", struct.pack(">H", n))[0]
        elif b1 & 0x20 == 0:
            # 29-bit, three byte, big endian integer
            n = struct.unpack(">i", bytes((b1 & 0x3F, self.read_u8(), self.read_u8(), self.read_u8())))[0]

            # rotate right one bit, 29-bit number
            n = ror(n, 1, 29)

            # sign-extend 29-bit number to 32-bits
            if n & (1 << 28):
                n |= (1 << 29) | (1 << 30) | (1 << 31)

            # reinterpret as 32-bit, 4-byte, signed, big-endian integer
            return struct.unpack(">i", struct.pack(">I", n))[0]
        else:
            raise ValueError("invalid compressed int")

    def read_type(self):
        elem = ElementType(self.read_u8())
        if elem == ElementType.VALUETYPE:
            return (elem, self.read_compressed_u32())
        else:
            return elem


import pytest
def test_signature_reader_u32():
    with pytest.raises(IndexError):
        SignatureReader(b"").read_compressed_u32()

    # these are the tests from
    # spec ECMA-335 II.23.2 Blobs and signatures.
    assert 0x03 == SignatureReader(b"\x03").read_compressed_u32()
    assert 0x7F == SignatureReader(b"\x7F").read_compressed_u32()
    assert 0x80 == SignatureReader(b"\x80\x80").read_compressed_u32()
    assert 0x2E57 == SignatureReader(b"\xAE\x57").read_compressed_u32()
    assert 0x3FFF == SignatureReader(b"\xBF\xFF").read_compressed_u32()
    assert 0x4000 == SignatureReader(b"\xC0\x00\x40\x00").read_compressed_u32()
    assert 0x1FFFFFFF == SignatureReader(b"\xDF\xFF\xFF\xFF").read_compressed_u32()


def test_signature_reader_i32():
    # these are the tests from
    # spec ECMA-335 II.23.2 Blobs and signatures.
    assert 3 == SignatureReader(b"\x06").read_compressed_i32()
    assert -3 == SignatureReader(b"\x7B").read_compressed_i32()
    assert 64 == SignatureReader(b"\x80\x80").read_compressed_i32()
    assert -64 == SignatureReader(b"\x01").read_compressed_i32()
    assert 8192 == SignatureReader(b"\xC0\x00\x40\x00").read_compressed_i32()
    assert -8192 == SignatureReader(b"\x80\x01").read_compressed_i32()
    assert 268435455 == SignatureReader(b"\xDF\xFF\xFF\xFE").read_compressed_i32()
    assert -268435456 == SignatureReader(b"\xC0\x00\x00\x01").read_compressed_i32()


class Signature:
    def __init__(self, buf):
        self.buf = buf

import collections
Signature = collections.namedtuple("Signature", ["flags", "calling_convention", "ret_type", "params"])


def parse_signature(buf: bytes) -> Signature:
    r = SignatureReader(buf)
    b1 = r.read_u8()

    flags = SignatureFlags(b1 & SIGNATURE_FLAGS_MASK)
    calling_convention = CallingConvention(b1 & CALLING_CONVENTION_MASK)

    param_count = r.read_compressed_u32()

    ret_type = r.read_type()

    params = []
    for _ in range(param_count):
        params.append(r.read_type())

    return Signature(flags, calling_convention, ret_type, params)

import binascii
def test_method_signature():
    # instance void class [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::'.ctor'(int32)
    print(parse_signature(binascii.unhexlify(b"20010108")))
    # instance void class [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::'.ctor'()
    print(parse_signature(binascii.unhexlify(b"200001")))
    # instance void class [mscorlib]System.Diagnostics.DebuggableAttribute::'.ctor'(valuetype [mscorlib]System.Diagnostics.DebuggableAttribute/DebuggingModes)
    print(parse_signature(binascii.unhexlify(b"2001011111")))
    # void class [mscorlib]System.Console::WriteLine(string)
    print(parse_signature(binascii.unhexlify(b"0001010e")))
    # instance void object::'.ctor'()
    print(parse_signature(binascii.unhexlify(b"200001")))
    assert False