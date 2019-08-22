import re
import sys
from enum import IntEnum


class AES_Mode(IntEnum):
    CCP_AES_MODE_ECB = 0,
    CCP_AES_MODE_CBC = 1,
    CCP_AES_MODE_OFB = 2,
    CCP_AES_MODE_CFB = 3,
    CCP_AES_MODE_CTR = 4,
    CCP_AES_MODE_CMAC = 5,
    CCP_AES_MODE_GHASH = 6,
    CCP_AES_MODE_GCTR = 7,
    CCP_AES_MODE_GCM = 8,
    CCP_AES_MODE_GMAC = 9



class AES_Type(IntEnum):
    CCP_AES_TYPE_128 = 0,
    CCP_AES_TYPE_192 = 1,
    CCP_AES_TYPE_256 = 2


class SHA_Type(IntEnum):
    CCP_SHA_TYPE_1 = 1,
    CCP_SHA_TYPE_224 = 2,
    CCP_SHA_TYPE_256 = 3,
    CCP_SHA_TYPE_384 = 4,
    CCP_SHA_TYPE_512 = 5


class Passthrough_Bitwise(IntEnum):
    CCP_PASSTHRU_BITWISE_NOOP = 0,
    CCP_PASSTHRU_BITWISE_AND = 1,
    CCP_PASSTHRU_BITWISE_OR = 2,
    CCP_PASSTHRU_BITWISE_XOR = 3,
    CCP_PASSTHRU_BITWISE_MASK = 4


class Passthrough_ByteSwap(IntEnum):
    CCP_PASSTHRU_BYTESWAP_NOOP = 0,
    CCP_PASSTHRU_BYTESWAP_32BIT = 1,
    CCP_PASSTHRU_BYTESWAP_256BIT = 2


class Engines(IntEnum):
    CCP_ENGINE_AES = 0,
    CCP_ENGINE_XTS_AES_128 = 1,
    CCP_ENGINE_DES3 = 2,
    CCP_ENGINE_SHA = 3,
    CCP_ENGINE_RSA = 4,
    CCP_ENGINE_PASSTHRU = 5,
    CCP_ENGINE_ZLIB_DECOMPRESS = 6,
    CCP_ENGINE_ECC = 7,


class MemType(IntEnum):
    CCP_MEMTYPE_SYSTEM = 0,
    CCP_MEMTYPE_SB = 1,
    CCP_MEMTYPE_LOCAL = 2


# Taken from drivers/crypto/ccp/ccp-dev-v5.c
# /* CCP version 5: Union to define the function field (cmd_reg1/dword0) */
# union ccp_function {
# 	struct {
# 		u16 size:7;
# 		u16 encrypt:1;
# 		u16 mode:5;
# 		u16 type:2;
# 	} aes;
# 	struct {
# 		u16 size:7;
# 		u16 encrypt:1;
# 		u16 rsvd:5;
# 		u16 type:2;
# 	} aes_xts;
# 	struct {
# 		u16 size:7;
# 		u16 encrypt:1;
# 		u16 mode:5;
# 		u16 type:2;
# 	} des3;
# 	struct {
# 		u16 rsvd1:10;
# 		u16 type:4;
# 		u16 rsvd2:1;
# 	} sha;
# 	struct {
# 		u16 mode:3;
# 		u16 size:12;
# 	} rsa;
# 	struct {
# 		u16 byteswap:2;
# 		u16 bitwise:3;
# 		u16 reflect:2;
# 		u16 rsvd:8;
# 	} pt;
# 	struct  {
# 		u16 rsvd:13;
# 	} zlib;
# 	struct {
# 		u16 size:10;
# 		u16 type:2;
# 		u16 mode:3;
# 	} ecc;
# 	u16 raw;
# };

def parse_aes_function(function):
    size = (function & ((1 << 7) - 1))
    encrypt = (function >> 7) & 0b1
    mode = (function >> 8) & 0b11111
    aestype = (function >> 13) & 0b11

    formatstr = "[size: 0x{:x} encrypt: {:d} mode: {} type: {}]"

    if mode == AES_Mode.CCP_AES_MODE_CBC:
        smode = "CBC"
    elif mode == AES_Mode.CCP_AES_MODE_OFB:
        smode = "OFB"
    elif mode == AES_Mode.CCP_AES_MODE_ECB:
        smode = "ECB"
    elif mode == AES_Mode.CCP_AES_MODE_GCM:
        smode = "GCM"
    elif mode == AES_Mode.CCP_AES_MODE_CFB:
        smode = "CFB"
    elif mode == AES_Mode.CCP_AES_MODE_CMAC:
        smode = "CMAC"
    elif mode == AES_Mode.CCP_AES_MODE_CTR:
        smode = "CTR"
    elif mode == AES_Mode.CCP_AES_MODE_GCTR:
        smode = "GCTR"
    elif smode == AES_Mode.CCP_AES_MODE_GMAC:
        smode = "GMAC"
    elif mode == AES_Mode.CCP_AES_MODE_GHASH:
        smode = "GHASH"
    else:
        smode = "~INVALID~"

    if aestype == AES_Type.CCP_AES_TYPE_128:
        stype = "AES128"
    elif aestype == AES_Type.CCP_AES_TYPE_192:
        stype = "AES192"
    elif aestype == AES_Type.CCP_AES_TYPE_256:
        stype = "AES256"
    else:
        stype = "~INVALID~"

    return formatstr.format(size, encrypt, smode, stype)


def parse_sha_function(function):
    rsvd1 = (function & ((1 << 10) - 1))
    stype = (function >> 10) & (0b1111)
    rsvd2 = (function >> 14) & 0b1

    if(rsvd1 | rsvd2):
        return "ERROR reserved bits set in sha function"

    formatstr = "[type: {}]"

    if stype == SHA_Type.CCP_SHA_TYPE_1:
        stype = "SHA1"
    elif stype == SHA_Type.CCP_SHA_TYPE_224:
        stype = "SHA224"
    elif stype == SHA_Type.CCP_SHA_TYPE_256:
        stype = "SHA256"
    elif stype == SHA_Type.CCP_SHA_TYPE_384:
        stype = "SHA384"
    elif stype == SHA_Type.CCP_SHA_TYPE_512:
        stype = "SHA512"
    else:
        stype = "Unknown SHA type: 0x%x" % stype

    return formatstr.format(stype)


def parse_passthrough_function(function):
    byteswap = function & 0b11
    bitwise = (function >> 2) & 0b111
    reflect = (function >> 5) & 0b11
    rsvd = (function >> 7) & ((1 << 8) - 1)

    formatstr = "[bswap: {} bwise: {} reflect: {refl:d}]"

    if(rsvd != 0):
        return "ERROR reserved bits set in passthrough function"

    if byteswap == Passthrough_ByteSwap.CCP_PASSTHRU_BYTESWAP_NOOP:
        bswap = "NOOP"
    elif byteswap == Passthrough_ByteSwap.CCP_PASSTHRU_BYTESWAP_32BIT:
        bswap = "32BIT"
    elif byteswap == Passthrough_ByteSwap.CCP_PASSTHRU_BYTESWAP_256BIT:
        bswap = "256BIT"
    else:
        return "ERROR: Unknown byteswap value: %d" % byteswap

    if bitwise == Passthrough_Bitwise.CCP_PASSTHRU_BITWISE_AND:
        bwise = "AND"
    elif bitwise == Passthrough_Bitwise.CCP_PASSTHRU_BITWISE_MASK:
        bwise = "MASK"
    elif bitwise == Passthrough_Bitwise.CCP_PASSTHRU_BITWISE_NOOP:
        bwise = "NOOP"
    elif bitwise == Passthrough_Bitwise.CCP_PASSTHRU_BITWISE_OR:
        bwise = "OR"
    elif bitwise == Passthrough_Bitwise.CCP_PASSTHRU_BITWISE_XOR:
        bwise = "XOR"

    return formatstr.format(bswap, bwise, refl=reflect)


def parse_dword0(dword):

    formatstr = "soc: {soc:d} ioc: {ioc:d} init: {init:d} eom: {eom:d} engine: {engine} function: {function} prot: {prot:d}"
    soc = (dword & 0b1)
    ioc = ((dword >> 1) & 0b1)
    rsvd1 = ((dword >> 2) & 0b1)
    init = ((dword >> 3) & 0b1)
    eom = ((dword >> 4) & 0b1)
    engine = ((dword  >> 20) & 0b1111) 
    function = ((dword >> 5) & (( 1 << 15) -1))
    prot = ((dword >> 24) & 0b1)
    rsvd2 = ((dword >> 25) & 0b1111111)

    if (rsvd1 | rsvd2):
        return "ERROR, reserved bits set"


    func = ""
    if engine == Engines.CCP_ENGINE_AES:
        engine = "AES"
        func = parse_aes_function(function)
    elif engine == Engines.CCP_ENGINE_DES3:
        engine = "DES3"
    elif engine == Engines.CCP_ENGINE_ECC:
        engine = "ECC"
    elif engine == Engines.CCP_ENGINE_RSA:
        engine = "RSA"
    elif engine == Engines.CCP_ENGINE_SHA:
        engine = "SHA"
        func = parse_sha_function(function)
    elif engine == Engines.CCP_ENGINE_ZLIB_DECOMPRESS:
        engine = "ZLIB"
    elif engine == Engines.CCP_ENGINE_PASSTHRU:
        engine = "PASSTHRU"
        func = parse_passthrough_function(function)
    elif engine == Engines.CCP_ENGINE_XTS_AES_128:
        engine = "AES-XTS"
    else:
        print("Invalid engine value %d" % engine)

    if len(func) == 0:
        function = "[raw: {func:x}]".format(func=function)
    else:
        function = func

    return (formatstr.format(soc=soc,init=init,ioc=ioc,eom=eom,engine=engine,function=function,prot=prot),engine)


def parse_dword3(dword3):

    formatstr = "src_hi: {hi:x} src_mem: {mem} lsb_ctx_id: {id:d} fixed: {fixed:d}"

    src_hi = (dword3) & ((1 << 16) -1)
    src_mem = (dword3 >> 16) & (0b11)
    lsb_ctx_id = (dword3 >> 18) & 0b11111111
    rsvd1 = (dword3 >> 26) & 0b11111
    fixed = (dword3 >> 31) & 0b1

    if(rsvd1):
        return "ERROR: rsvd bit set in dword3"

    if src_mem == MemType.CCP_MEMTYPE_LOCAL:
        memt = "LOCAL"
    elif src_mem == MemType.CCP_MEMTYPE_SYSTEM:
        memt = "SYSTEM"
    elif src_mem == MemType.CCP_MEMTYPE_SB:
        memt = "SB"
    else:
        memt = "UNKNOWN"


    return formatstr.format(hi=src_hi,mem=memt,id=lsb_ctx_id,fixed=fixed)


def parse_dword4(engine,dword4):
    if engine == "SHA":
        return "sha_len_lo: %x" % dword4
    else:
        return "dst_lo: %x" % dword4

def parse_dword5(engine,dword5):

    formatstr = "dst_hi: {hi:x} dst_type: {mtype:s} fixed: {fix:d}"
    if engine == "SHA":
        return "sha_len_hi 0x%x" % dword5
    else:
        dst_hi = (dword5 & ((1 << 16) -1))
        dst_mem =  (dword5 >> 16) & 0b11
        rsvd = (dword5 >> 18) & ((1 << 13) -1)
        fixed = (dword5 >> 31) & 0b1

    if dst_mem == MemType.CCP_MEMTYPE_SYSTEM:
        mtype = "SYSTEM"
    elif dst_mem == MemType.CCP_MEMTYPE_LOCAL:
        mtype = "LOCAL"
    elif dst_mem == MemType.CCP_MEMTYPE_SB:
        mtype = "SB"
    else:
        mtype = "UNKNOWN"

    return formatstr.format(hi=dst_hi,mtype=mtype,fix=fixed)

