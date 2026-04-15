"""
RFC 9189 test vectors using pygost 6.0

Tests cover:
  A.1.1 - TLSTREE key diversification (Magma and Kuznyechik)
  A.1.2 - CTR_OMAC record encryption (Magma seqnum=0,1,2; Kuznyechik seqnum=0,1,2)
  A.1.3 - Handshake key derivation (Magma/256-bit curve: K_EXP, KExp15)
  A.2.1 - CNT_IMIT record encryption (seqnum=0,1,2)
  A.2.2 - CNT_IMIT handshake key wrap (PMSEXP)
"""

import hmac
import os
import struct
import sys
import unittest

_PYGOST_PATH = "/path/topygost"
if not os.path.isdir(_PYGOST_PATH):
    raise RuntimeError(
        f"pygost source not found at {_PYGOST_PATH}. "
    )
sys.path.insert(0, _PYGOST_PATH)

from pygost.gost28147 import cnt as gost28147_cnt
from pygost.gost28147 import ecb_encrypt as gost28147_ecb_encrypt
from pygost.gost28147_mac import MAC as GOST28147MAC
from pygost.gost3410 import CURVES, public_key, prv_unmarshal
from pygost.gost3410_vko import kek_34102012256, kek_34102012512
from pygost.gost3412 import GOST3412Kuznechik, GOST3412Magma
from pygost.gost3413 import ctr as gost3413_ctr, mac as gost3413_mac
from pygost.gost34112012256 import GOST34112012256
from pygost.wrap import diversify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DEBUG = False

def debug(msg: str):
    """Optional log output for observing cryptographic state"""
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def h(s):
    """Hex string (spaces OK) → bytes."""
    return bytes.fromhex(s.replace(" ", ""))


def kdf_gostr3411_2012_256(K: bytes, label: bytes, seed: bytes) -> bytes:
    """Single KDF call from RFC 7836 §4.5 (counter=1, L=256)."""
    # 0x01 | 0x00 is L=256 in big-endian, exactly as specified in RFC 7836 §4.5
    data = b"\x01" + label + b"\x00" + seed + b"\x01\x00"
    return hmac.new(K, data, GOST34112012256).digest()


def kdftree_256(K: bytes, label: bytes, seed: bytes) -> tuple:
    """KDF_TREE_GOSTR3411_2012_256 with L=512 (RFC 7836 §4.5, RFC 9189 KEG).
    Returns (K_i1, K_i2) = first and second 32-byte blocks.
    Used in KEG: K_Exp_MAC = block1, K_Exp_ENC = block2.
    """
    # RFC 9189 §8.3.1 requires KDFTREE_256 with L=512, thus we split into two 32-byte chunks.
    # 0x0200 represents L=512 in RFC 7836 §4.4
    L = b"\x02\x00"
    d1 = b"\x01" + label + b"\x00" + seed + L
    d2 = b"\x02" + label + b"\x00" + seed + L
    return (
        hmac.new(K, d1, GOST34112012256).digest(),
        hmac.new(K, d2, GOST34112012256).digest(),
    )


# TLSTREE masks (RFC 9189 Table 3)
MAGMA_C1 = 0xFFFFFFC000000000
MAGMA_C2 = 0xFFFFFFFFFE000000
MAGMA_C3 = 0xFFFFFFFFFFFFF000

KUZNYECHIK_C1 = 0xFFFFFFFF00000000
KUZNYECHIK_C2 = 0xFFFFFFFFFFF80000
KUZNYECHIK_C3 = 0xFFFFFFFFFFFFFFC0


def tlstree(K: bytes, seqnum: int, C1: int, C2: int, C3: int) -> bytes:
    """Derives connection keys according to RFC 9189 §8.1.
    If seqnum crosses a C1/C2/C3 boundary, the masks force K1/K2/K3 to re-derive.
    """
    assert isinstance(seqnum, int), f"seqnum must be an integer, got {type(seqnum)}"
    debug(f"tlstree(seqnum={seqnum})")
    
    s1 = struct.pack(">Q", seqnum & C1)
    s2 = struct.pack(">Q", seqnum & C2)
    s3 = struct.pack(">Q", seqnum & C3)
    
    K1 = kdf_gostr3411_2012_256(K, b"level1", s1)
    debug(f"  Level 1 (C1 mask {hex(C1)} -> {s1.hex()}): {K1[:8].hex()}...")
    
    K2 = kdf_gostr3411_2012_256(K1, b"level2", s2)
    debug(f"  Level 2 (C2 mask {hex(C2)} -> {s2.hex()}): {K2[:8].hex()}...")
    
    K3 = kdf_gostr3411_2012_256(K2, b"level3", s3)
    debug(f"  Level 3 (C3 mask {hex(C3)} -> {s3.hex()}): {K3[:8].hex()}...")
    return K3


def prf_tls_gost(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """PRF_TLS_GOSTR3411_2012_256 (RFC 9189 §4.3.4, RFC 7836 §6.1).

    Standard TLS P_hash construction using HMAC-Streebog-256.

    P_hash(secret, s) = HMAC(secret, A(1) || s) || HMAC(secret, A(2) || s) || ...
      where s = label || seed (RFC 5246 §5 label prepend convention)
      and A(0) = s, A(i) = HMAC(secret, A(i-1))

    Output is truncated to `length` bytes.
    """
    combined = label + seed  # A(0)
    A = combined
    out = b""
    while len(out) < length:
        A = hmac.new(secret, A, GOST34112012256).digest()        # A(i)
        out += hmac.new(secret, A + combined, GOST34112012256).digest()
    return out[:length]


def kimp15(PMSEXP: bytes, K_Exp_MAC: bytes, K_Exp_ENC: bytes,
           IV: bytes, cipher_cls, bs: int) -> bytes:
    """KImp15 key import (RFC 9189 §8.2.1), inverse of KExp15.

    PS || CEK_MAC = CTR_decrypt(K_Exp_ENC, IV, PMSEXP)
    Verify: OMAC(K_Exp_MAC, IV || PS) == CEK_MAC (constant-time equivalent)
    Returns PS on success; raises ValueError on MAC failure.

    CTR mode is self-inverse so decryption == encryption.
    """
    assert len(IV) == bs // 2, f"IV must be bs/2 ({bs//2} bytes), got {len(IV)}"
    cipher_enc = cipher_cls(K_Exp_ENC)
    decrypted = gost3413_ctr(cipher_enc.encrypt, bs, PMSEXP, IV)
    PS = decrypted[:-bs]
    cek_mac_got = decrypted[-bs:]
    cipher_mac = cipher_cls(K_Exp_MAC)
    cek_mac_exp = gost3413_mac(cipher_mac.encrypt, bs, IV + PS)
    if not hmac.compare_digest(cek_mac_got, cek_mac_exp):
        raise ValueError("KImp15: MAC verification failed")
    return PS


def kexp15(PS: bytes, K_Exp_MAC: bytes, K_Exp_ENC: bytes, IV: bytes, cipher_cls, bs: int) -> bytes:
    """
    KExp15 key export (RFC 9189 §8.2.1):
      CEK_MAC = OMAC(K_Exp_MAC, IV || PS)
      PMSEXP  = CTR(K_Exp_ENC, IV, PS || CEK_MAC)
    """
    assert len(IV) == bs // 2, f"IV must be bs/2 ({bs//2} bytes), got {len(IV)}"
    cipher_mac = cipher_cls(K_Exp_MAC)
    mac_data = IV + PS
    cek_mac = gost3413_mac(cipher_mac.encrypt, bs, mac_data)  # bs bytes
    debug(f"kexp15() -> CEK_MAC: {cek_mac.hex().upper()}")
    
    cipher_enc = cipher_cls(K_Exp_ENC)
    plaintext = PS + cek_mac
    ret = gost3413_ctr(cipher_enc.encrypt, bs, plaintext, IV)
    debug(f"kexp15() -> PMSEXP:  {ret.hex().upper()}")
    return ret


# ---------------------------------------------------------------------------
# A.1.1 - TLSTREE
# ---------------------------------------------------------------------------

K_ROOT = h("00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
           "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00")

TLSTREE_MAGMA_VECTORS = [
    # (seqnum, expected_key_hex)
    (0,           "19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D"),
    (4095,        "19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D"),
    (4096,        "FB30EE53CFCF89D748FC0C72EF160B8B53CBBBFD031282B026214AB2E07758FF"),
    (33554431,    "B85B36DC2282326BC035C572DC93F18D83AA0174F394209A513BB374DC0935AE"),
    (33554432,    "0FD7C09EFDF8E81573EECCF86E4B95E3AF7F34DAB1177CFD7DB97B6DA906408A"),
    (274877906943,"480F9972BAF25D4C369A96AF91BCA4553F79D8F0C5618B19FD44CFDC57FA3733"),
    (274877906944,"2528C1C6A8F0927BF2BE27BB78D27F2146D65593B0C7173A06CB9D88DF923265"),
]

TLSTREE_KUZNYECHIK_VECTORS = [
    (0,          "19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D"),
    (63,         "19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D"),
    (64,         "AEBE1EF418713BF044B9FCD9E572D437FB38B5D829567A6F7918396D9F4E096B"),
    (524287,     "6F18D4003EA2CB30F5FEC193A234F07D7C4394987F50758DE22B220D8A105106"),
    (524288,     "E54B16415B3B663E780B062D24F736C4495463C3A891E1FA46F7AE99FFF9F378"),
    (4294967295, "CF600904C71E7B88A49AC8E245774B3DBEEDFB81DE9A0E2F4E46C35607BC2F04"),
    (4294967296, "16180B24645400B836143837D86AAC93952AE3EB8244D5EC2AB02CFF30781138"),
]


# ---------------------------------------------------------------------------
# A.1.2.1 - CTR_OMAC record (Magma, seqnum=0)
# ---------------------------------------------------------------------------

A121_MAC_KEY = h("00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A"
                 "11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00")
A121_ENC_KEY = h("22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11"
                 "33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22")
A121_BASE_IV = h("00 00 00 00")  # 4 bytes for Magma (bs/2)

A121_seqnum = 0
A121_APP_DATA = b"\x00" * 7
A121_TYPE = 0x17
A121_VERSION = b"\x03\x03"

# Expected values
A121_K_MAC_0 = h("19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D")
A121_K_ENC_0 = h("58 AF BE 9A 4C 31 98 AA AB AA 26 92 C4 19 F1 79"
                  "7C 9B 92 DE B3 CC 74 46 B3 63 57 71 13 F0 FB 56")
A121_MAC_0   = h("F33EB6896FECE286")
A121_CIPHER  = h("9B420DA86FAF367F051443CE9C1072")  # 15 bytes (7 data + 8 MAC)

# seqnum=1 and seqnum=2: same 7-byte zero app data; seqnum=1,2 < 4096 so TLSTREE
# keys are unchanged (same C1 boundary).  Only the IV changes per RFC 9189 §4.1.1:
# IV_n = STR_4((INT(BASE_IV) + n) mod 2^32).  Values computed from RFC algorithms.
A121_IV_1    = h("00000001")
A121_K_MAC_1 = A121_K_MAC_0   # TLSTREE(root, 1, ...) == TLSTREE(root, 0, ...) at this range
A121_K_ENC_1 = A121_K_ENC_0
A121_MAC_1   = h("A82FCF2CFC9159C0")
A121_CIPHER_1 = h("B9ADDC3234696E25C105C9C78F66D1")  # 15 bytes

A121_IV_2    = h("00000002")
A121_K_MAC_2 = A121_K_MAC_0
A121_K_ENC_2 = A121_K_ENC_0
A121_MAC_2   = h("3E36063A82A4A103")
A121_CIPHER_2 = h("7ED694FA44C4A490AA890B3CA8D91F")  # 15 bytes


# ---------------------------------------------------------------------------
# A.1.2.2 - CTR_OMAC record (Kuznyechik, seqnum=0)
# ---------------------------------------------------------------------------
# Keys are the same as A.1.2.1 (same handshake scenario).
# IV is 8 bytes (n/2 for Kuznyechik, n=16).

A122_BASE_IV = h("00 00 00 00 00 00 00 00")  # 8 bytes for Kuznyechik (bs/2)

A122_seqnum   = 0
A122_APP_DATA = b"\x00" * 15            # 0x0F bytes (TLSCompressed.length = 0x000F)
A122_TYPE     = 0x17
A122_VERSION  = b"\x03\x03"

# Expected values (RFC 9189 §A.1.2.2, seqnum=0)
# K_MAC_0 / K_ENC_0 use the same A.1.2.1 roots; TLSTREE output is identical
# for seqnum=0 regardless of cipher suite.
A122_K_MAC_0 = h("19A76ED30F4D6D1F5B7263EC491AD83817C0B57D8A0356127140FB4F7425494D")
A122_K_ENC_0 = h("58 AF BE 9A 4C 31 98 AA AB AA 26 92 C4 19 F1 79"
                  "7C 9B 92 DE B3 CC 74 46 B3 63 57 71 13 F0 FB 56")
A122_MAC_0   = h("FD1719DD950837EB7C7BB8F500379981")   # 16 bytes (Kuznyechik OMAC)
A122_CIPHER  = h("4D1A305236573BFFC14E46DCBE746DB6"
                  "C99A175A81C4711E2F84C392C5407C")  # 31 bytes (15 data + 16 MAC)

# seqnum=1 and seqnum=2: same 15-byte zero app data; seqnum=1,2 < 64 so TLSTREE
# keys are unchanged (same C1 boundary).  IV_n = STR_8((INT(BASE_IV) + n) mod 2^64).
A122_IV_1    = h("0000000000000001")
A122_K_MAC_1 = A122_K_MAC_0
A122_K_ENC_1 = A122_K_ENC_0
A122_MAC_1   = h("C1D5205D2C0B6619988C27C13EE3AEB0")   # 16 bytes
A122_CIPHER_1 = h("BA95EE840283E3FE9844B3927031093D"
                   "7BCDCD358E7F5C3BFFB3E617876198")  # 31 bytes

A122_IV_2    = h("0000000000000002")
A122_K_MAC_2 = A122_K_MAC_0
A122_K_ENC_2 = A122_K_ENC_0
A122_MAC_2   = h("C8B523356D82476D1791C4B7DADD4A96")   # 16 bytes
A122_CIPHER_2 = h("E44CF92B7B7FAD9894AC223F3CE5B4AC"
                   "72244866121A643F1179645B01258A")  # 31 bytes


# ---------------------------------------------------------------------------
# A.1.3.1 - Handshake (Magma / 256-bit curve)
# ---------------------------------------------------------------------------

A131_CURVE = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
A131_d_eph  = 0xA5C77C7482373DE16CE4A6F73CCE7F78471493FF2C0709B8B706C9E8A25E6C1E
A131_Qs_x   = 0x6531D4A72E655BFC9DFB94293B26070282FABF10D5C49B7366148C60E0BF8167
A131_Qs_y   = 0x37F8CC71DC5D917FC4A66F7826E727508270B4FFC266C26CD4363E77B553A5B8
A131_UKM    = 0xC3EF0428D4B7A1F4C5025F2E65DD2B2E

A131_K_EXP     = h("1E585490E865FFD18F18D7C0A04D0EE84F1A5D797CEFADA01B1E3B7FDB90E029")
A131_K_Exp_MAC = h("2D8BA8C84CB232FF41F10C3AD924134223254F71E5696D3D29C3E4C9DAA6B293")
A131_K_Exp_ENC = h("849EB6340BFFAE6928A3C3E4FF92ECCB1E8F0CF7A188368E6B748E52EA378B0C")
A131_IV        = h("214A6A29")
A131_PS        = h("A5576CE7924A24F58113808DBD9EF856F5BDC3B183CE5DADCA36A53AA077651D")
A131_PMSEXP    = h("D7F0F0422367867B25FA4233A954F58BDE92E9C9BBFB8816C99F15E6398722A0B2B7BFE8493E9A5C")


# ---------------------------------------------------------------------------
# A.1.3.2 - Handshake (Kuznyechik / 512-bit curve) - key wrap only
# ---------------------------------------------------------------------------

A132_CURVE  = CURVES["id-tc26-gost-3410-2012-512-paramSetC"]
A132_d_eph  = 0x150ACD11B66DD695AD18418FA7A2DC636B7E29DCA24536AABC826EE3175BB1FADC3AA0D01D3092E120B0FCF7EB872F4B7E26EA17849D689222A48CF95A6E4831
A132_Qs_x   = 0xF14589DA479AD972C66563669B3FF58092E6A30A288BF447CD9FF6C3133E97247A9706B267703C9B4E239F0D7C7E3310C22D2752B35BD2E4FD39B8F11DEB833A
A132_Qs_y   = 0xF305E95B36502D4E60A1059FB20AB30BFC7C95727F3A2C04B1DFDDB53B0413F299F2DFE66A5E1CCB4101A7A01D612BE6BD78E1E3B3D567EBB16ABE587A11F4EA
A132_UKM    = 0xC3EF0428D4B7A1F4C5025F2E65DD2B2E

A132_K_Exp_MAC = h("7DAC56E48A4DC170FAA8FCBAE20DB845450CCCC4C6328BDC8D01157CEFA2A5F1")
A132_K_Exp_ENC = h("1F1CBAD8866166F01FFAAB0152E24BF4609D5F46A5C899C787900D08B9FCAD24")

A132_IV        = h("214A6A298E99E325")  # 8 bytes for Kuznyechik
A132_PS        = h("A5576CE7924A24F58113808DBD9EF856F5BDC3B183CE5DADCA36A53AA077651D")
A132_PMSEXP    = h("250D1B67A270AB04D3F65418E1D380B4CB945F0A3DCA51500CF3A1BEF37F76C07341A9839CCF6CBA7189DA61EB67176C")


# ---------------------------------------------------------------------------
# A.2.1 - CNT_IMIT record (seqnum=0)
# ---------------------------------------------------------------------------

A21_MAC_KEY = b"\xff" * 32
A21_ENC_KEY = b"\x00" * 32
A21_BASE_IV = b"\x00" * 8
A21_SBOX    = "id-tc26-gost-28147-param-Z"

A21_seqnum   = 0
A21_APP_DATA = b"\x00" * 7
A21_TYPE     = 0x17
A21_VERSION  = b"\x03\x03"

A21_MAC      = h("3001 34a1")
A21_CIPHER   = h("8671CDBF3C1AAE0F624B04")  # 11 bytes (7 data + 4 MAC)

# seqnum=1 and seqnum=2: same 7-byte zero app data (cumulative scheme).
# CNT_IMIT MAC covers ALL records 0..n (RFC 9189 §4.1.2).
# Encryption is a single CNT stream from the initial IV across all records.
# Values computed from RFC algorithms with the established keys above.
A21_MAC_1    = h("00E8D12F")              # MAC over seqnum 0+1 combined input
A21_CIPHER_1 = h("CFAA0CB42FA5A47AFBEC5C")   # 11 bytes: seqnum=1 portion of stream
A21_MAC_2    = h("B927FF89")              # MAC over seqnum 0+1+2 combined input
A21_CIPHER_2 = h("B9F2C0B04F8CA2EC7507DF")   # 11 bytes: seqnum=2 portion of stream


# ---------------------------------------------------------------------------
# A.2.2 - CNT_IMIT handshake PMSEXP
# ---------------------------------------------------------------------------

A22_K_EXP  = h("3FD999D1684A15CC9BDD5A35067AF69817150022E09554AC791A60F161F55349")
A22_UKM    = h("FBF39D10E800AF70")  # 8 bytes
A22_PS     = h("CE0DD6B6704212152BE4695A7E89F64C8929A40DBF0A5A55C2CE002B06BAB62F")
A22_PMSEXP = h("FBF39D10E800AF70D622D167A5642E29525A295CB9F28F96F28B0EFAA7D3A2BEE149B01178C2DFD54C933657")


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestTLSTREE(unittest.TestCase):

    def _check(self, vectors, C1, C2, C3, name):
        for seqnum, expected_hex in vectors:
            expected = bytes.fromhex(expected_hex.replace(" ", ""))
            got = tlstree(K_ROOT, seqnum, C1, C2, C3)
            self.assertEqual(got, expected, f"{name} seqnum={seqnum}")

    def test_magma(self):
        self._check(TLSTREE_MAGMA_VECTORS, MAGMA_C1, MAGMA_C2, MAGMA_C3, "Magma TLSTREE")

    def test_kuznyechik(self):
        self._check(TLSTREE_KUZNYECHIK_VECTORS, KUZNYECHIK_C1, KUZNYECHIK_C2, KUZNYECHIK_C3, "Kuznyechik TLSTREE")


class TestCTROMAC_Record(unittest.TestCase):
    """A.1.2.1 Magma CTR_OMAC record, seqnum=0"""

    def setUp(self):
        self.bs = 8  # Magma blocksize

    def _tlstree_magma(self, K, seq):
        return tlstree(K, seq, MAGMA_C1, MAGMA_C2, MAGMA_C3)

    def test_k_mac_derivation(self):
        got = self._tlstree_magma(A121_MAC_KEY, A121_seqnum)
        self.assertEqual(got, A121_K_MAC_0)

    def test_k_enc_derivation(self):
        got = self._tlstree_magma(A121_ENC_KEY, A121_seqnum)
        self.assertEqual(got, A121_K_ENC_0)

    def test_mac(self):
        # MAC input: seqnum_BE64 || type || version || length_BE16 || data
        length_be = struct.pack(">H", len(A121_APP_DATA))
        mac_input = (
            struct.pack(">Q", A121_seqnum)
            + bytes([A121_TYPE])
            + A121_VERSION
            + length_be
            + A121_APP_DATA
        )
        cipher = GOST3412Magma(A121_K_MAC_0)
        got = gost3413_mac(cipher.encrypt, self.bs, mac_input)
        # Explicit truncation to bs (8 bytes for Magma)
        self.assertEqual(got[:self.bs], A121_MAC_0)

    def test_ciphertext(self):
        cipher = GOST3412Magma(A121_K_ENC_0)
        plaintext = A121_APP_DATA + A121_MAC_0
        got = gost3413_ctr(cipher.encrypt, self.bs, plaintext, A121_BASE_IV)
        self.assertEqual(got, A121_CIPHER)

    def _record(self, seq, app_data, iv):
        """Helper: compute MAC + CTR-encrypt for one CTR_OMAC Magma record."""
        length_be = struct.pack(">H", len(app_data))
        mac_input = struct.pack(">Q", seq) + bytes([A121_TYPE]) + A121_VERSION + length_be + app_data
        K_MAC = self._tlstree_magma(A121_MAC_KEY, seq)
        K_ENC = self._tlstree_magma(A121_ENC_KEY, seq)
        mac = gost3413_mac(GOST3412Magma(K_MAC).encrypt, self.bs, mac_input)
        cipher = gost3413_ctr(GOST3412Magma(K_ENC).encrypt, self.bs, app_data + mac, iv)
        return K_MAC, K_ENC, mac, cipher

    def test_seqnum1(self):
        """A.1.2.1 seqnum=1: IV incremented by 1; TLSTREE keys unchanged (below C1 boundary)."""
        K_MAC, K_ENC, mac, cipher = self._record(1, A121_APP_DATA, A121_IV_1)
        self.assertEqual(K_MAC, A121_K_MAC_1)
        self.assertEqual(K_ENC, A121_K_ENC_1)
        self.assertEqual(mac,    A121_MAC_1)
        self.assertEqual(cipher, A121_CIPHER_1)

    def test_seqnum2(self):
        """A.1.2.1 seqnum=2: IV incremented by 2; TLSTREE keys unchanged (below C1 boundary)."""
        K_MAC, K_ENC, mac, cipher = self._record(2, A121_APP_DATA, A121_IV_2)
        self.assertEqual(K_MAC, A121_K_MAC_2)
        self.assertEqual(K_ENC, A121_K_ENC_2)
        self.assertEqual(mac,    A121_MAC_2)
        self.assertEqual(cipher, A121_CIPHER_2)


class TestCTROMAC_Kuznyechik(unittest.TestCase):
    """A.1.2.2 Kuznyechik CTR_OMAC record, seqnum=0 (RFC 9189 §A.1.2.2)."""

    def setUp(self):
        self.bs = 16  # Kuznyechik blocksize

    def _tlstree_kuz(self, K, seq):
        return tlstree(K, seq, KUZNYECHIK_C1, KUZNYECHIK_C2, KUZNYECHIK_C3)

    def test_k_mac_derivation(self):
        got = self._tlstree_kuz(A121_MAC_KEY, A122_seqnum)
        self.assertEqual(got, A122_K_MAC_0)

    def test_k_enc_derivation(self):
        got = self._tlstree_kuz(A121_ENC_KEY, A122_seqnum)
        self.assertEqual(got, A122_K_ENC_0)

    def test_mac(self):
        """OMAC(K_MAC_0, STR_8(seqnum) | type | version | length | fragment)."""
        length_be = struct.pack(">H", len(A122_APP_DATA))
        mac_input = (
            struct.pack(">Q", A122_seqnum)
            + bytes([A122_TYPE])
            + A122_VERSION
            + length_be
            + A122_APP_DATA
        )
        cipher = GOST3412Kuznechik(A122_K_MAC_0)
        got = gost3413_mac(cipher.encrypt, self.bs, mac_input)
        # Kuznyechik OMAC = 16 bytes (bs)
        self.assertEqual(got[:self.bs], A122_MAC_0)

    def test_ciphertext(self):
        """CTR(K_ENC_0, IV_0, fragment || MAC)."""
        cipher = GOST3412Kuznechik(A122_K_ENC_0)
        plaintext = A122_APP_DATA + A122_MAC_0
        got = gost3413_ctr(cipher.encrypt, self.bs, plaintext, A122_BASE_IV)
        self.assertEqual(got, A122_CIPHER)

    def _record(self, seq, app_data, iv):
        length_be = struct.pack(">H", len(app_data))
        mac_input = struct.pack(">Q", seq) + bytes([A122_TYPE]) + A122_VERSION + length_be + app_data
        K_MAC = self._tlstree_kuz(A121_MAC_KEY, seq)
        K_ENC = self._tlstree_kuz(A121_ENC_KEY, seq)
        mac = gost3413_mac(GOST3412Kuznechik(K_MAC).encrypt, self.bs, mac_input)
        cipher = gost3413_ctr(GOST3412Kuznechik(K_ENC).encrypt, self.bs, app_data + mac, iv)
        return K_MAC, K_ENC, mac, cipher

    def test_seqnum1(self):
        K_MAC, K_ENC, mac, cipher = self._record(1, A122_APP_DATA, A122_IV_1)
        self.assertEqual(K_MAC, A122_K_MAC_1)
        self.assertEqual(K_ENC, A122_K_ENC_1)
        self.assertEqual(mac, A122_MAC_1)
        self.assertEqual(cipher, A122_CIPHER_1)

    def test_seqnum2(self):
        K_MAC, K_ENC, mac, cipher = self._record(2, A122_APP_DATA, A122_IV_2)
        self.assertEqual(K_MAC, A122_K_MAC_2)
        self.assertEqual(K_ENC, A122_K_ENC_2)
        self.assertEqual(mac, A122_MAC_2)
        self.assertEqual(cipher, A122_CIPHER_2)


class TestHandshake_Magma(unittest.TestCase):
    """A.1.3.1 KEG key derivation and KExp15 wrapping (Magma)"""

    def test_k_exp(self):
        got = kek_34102012256(A131_CURVE, A131_d_eph, (A131_Qs_x, A131_Qs_y), A131_UKM)
        self.assertEqual(got, A131_K_EXP)

    def test_k_exp_enc_and_mac(self):
        # KEG_256 uses KDFTREE_256(K_EXP, "kdf tree", H[16..23], 1) with L=512
        # H[16..23] = seed = a583aeefdb67c7f4
        A131_seed = h("a583aeefdb67c7f4")
        mac, enc = kdftree_256(A131_K_EXP, b"kdf tree", A131_seed)
        self.assertEqual(mac, A131_K_Exp_MAC)
        self.assertEqual(enc, A131_K_Exp_ENC)

    def test_kexp15_pmsexp(self):
        got = kexp15(A131_PS, A131_K_Exp_MAC, A131_K_Exp_ENC, A131_IV, GOST3412Magma, bs=8)
        self.assertEqual(got, A131_PMSEXP)


class TestHandshake_Kuznyechik(unittest.TestCase):
    """A.1.3.2 KExp15 wrapping (Kuznyechik / 512-bit curve).

    KEG_512 (RFC 9189 §8.3.1) returns VKO_512(d, Q, UKM) = kek_34102012512
    directly as 64 bytes: K_Exp_MAC = first 32, K_Exp_ENC = last 32.
    """

    def test_k_exp(self):
        """RFC 9189 §A.1.3.2: KEG_512(d_eph, Q_s, UKM) == K_Exp_MAC | K_Exp_ENC."""
        got = kek_34102012512(A132_CURVE, A132_d_eph, (A132_Qs_x, A132_Qs_y), A132_UKM)
        # KEG_512 output is 64 bytes: K_Exp_MAC || K_Exp_ENC
        self.assertEqual(got[:32], A132_K_Exp_MAC, f"K_Exp_MAC mismatch. Expected {A132_K_Exp_MAC.hex()}, got {got[:32].hex()}")
        self.assertEqual(got[32:], A132_K_Exp_ENC, f"K_Exp_ENC mismatch. Expected {A132_K_Exp_ENC.hex()}, got {got[32:].hex()}")

    def test_kexp15_pmsexp(self):
        got = kexp15(A132_PS, A132_K_Exp_MAC, A132_K_Exp_ENC, A132_IV, GOST3412Kuznechik, bs=16)
        self.assertEqual(got, A132_PMSEXP)


class TestCNT_IMIT_Record(unittest.TestCase):
    """A.2.1 CNT_IMIT record, seqnum=0"""

    def setUp(self):
        self.sbox = A21_SBOX

    def test_mac(self):
        length_be = struct.pack(">H", len(A21_APP_DATA))
        # TLSPlaintext = type || version || length || data
        tls_plain = bytes([A21_TYPE]) + A21_VERSION + length_be + A21_APP_DATA
        mac_input = struct.pack(">Q", A21_seqnum) + tls_plain
        got = GOST28147MAC(A21_MAC_KEY, data=mac_input, iv=A21_BASE_IV, sbox=self.sbox).digest()[:4]
        self.assertEqual(got, A21_MAC)

    def test_ciphertext(self):
        plaintext = A21_APP_DATA + A21_MAC
        got = gost28147_cnt(A21_ENC_KEY, plaintext, iv=A21_BASE_IV, sbox=self.sbox)
        self.assertEqual(got, A21_CIPHER)

    def test_seqnum1(self):
        length_be = struct.pack(">H", len(A21_APP_DATA))
        tls_plain = bytes([A21_TYPE]) + A21_VERSION + length_be + A21_APP_DATA
        mac_input_0 = struct.pack(">Q", 0) + tls_plain
        mac_input_1 = struct.pack(">Q", 1) + tls_plain
        
        got_mac = GOST28147MAC(A21_MAC_KEY, data=mac_input_0 + mac_input_1, iv=A21_BASE_IV, sbox=self.sbox).digest()[:4]
        self.assertEqual(got_mac, A21_MAC_1)
        
        plain_0 = A21_APP_DATA + A21_MAC
        plain_1 = A21_APP_DATA + A21_MAC_1
        full_cipher = gost28147_cnt(A21_ENC_KEY, plain_0 + plain_1, iv=A21_BASE_IV, sbox=self.sbox)
        self.assertEqual(full_cipher[11:22], A21_CIPHER_1)

    def test_seqnum2(self):
        length_be = struct.pack(">H", len(A21_APP_DATA))
        tls_plain = bytes([A21_TYPE]) + A21_VERSION + length_be + A21_APP_DATA
        mac_input_0 = struct.pack(">Q", 0) + tls_plain
        mac_input_1 = struct.pack(">Q", 1) + tls_plain
        mac_input_2 = struct.pack(">Q", 2) + tls_plain
        
        got_mac = GOST28147MAC(A21_MAC_KEY, data=mac_input_0 + mac_input_1 + mac_input_2, iv=A21_BASE_IV, sbox=self.sbox).digest()[:4]
        self.assertEqual(got_mac, A21_MAC_2)
        
        plain_0 = A21_APP_DATA + A21_MAC
        plain_1 = A21_APP_DATA + A21_MAC_1
        plain_2 = A21_APP_DATA + A21_MAC_2
        full_cipher = gost28147_cnt(A21_ENC_KEY, plain_0 + plain_1 + plain_2, iv=A21_BASE_IV, sbox=self.sbox)
        self.assertEqual(full_cipher[22:33], A21_CIPHER_2)


class TestCNT_IMIT_Handshake(unittest.TestCase):
    """A.2.2 KExp28147 (RFC 9189 §8.2.2).

    K_EXP from the RFC A.2.2 test vector is the *raw VKO output* (R in §8.3.2
    step 3), not the final diversified key.  The diversify() call below applies
    CPDivers(UKM, R) to produce the actual encryption/MAC key, matching the
    KEG_28147 output K = CPDivers(UKM, R) passed into KExp28147.

    PMSEXP = UKM | ECB-Encrypt(K, PS) | gost28147IMIT(IV, K, PS)
    where K = CPDivers(UKM, K_EXP_raw).
    """

    def test_pmsexp(self):
        sbox = A21_SBOX
        div_key = diversify(A22_K_EXP, bytearray(A22_UKM), sbox=sbox)
        debug(f"A.2.2 CPDivers key: {div_key.hex().upper()}")
        
        cek_enc = gost28147_ecb_encrypt(div_key, A22_PS, sbox=sbox)
        debug(f"A.2.2 CEK_ENC:      {cek_enc.hex().upper()}")
        
        cek_mac = GOST28147MAC(div_key, data=A22_PS, iv=A22_UKM, sbox=sbox).digest()[:4]
        debug(f"A.2.2 CEK_MAC:      {cek_mac.hex().upper()}")
        
        got = A22_UKM + cek_enc + cek_mac
        debug(f"A.2.2 PMSEXP:       {got.hex().upper()}")
        self.assertEqual(got, A22_PMSEXP)


# ---------------------------------------------------------------------------
# A.1.3.1 - PRF / MS / Key Material / Finished (Magma)
# ---------------------------------------------------------------------------

# ClientHello.random and ServerHello.random (RFC 9189 A.1.3.1)
A131_r_c = h("933EA21EC3802A561550EC78D6ED51AC"
             "2439D7E749C31BC3A3456165889684CA")
A131_r_s = h("933EA21E49C31BC3A3456165889684CA"
             "A5576CE7924A24F58113808DBD9EF856")

# HASH(handshake_messages) used as seed for extended master secret (RFC 7627)
# Shown as "HASH(HM)" on both client and server before the MS value.
A131_HASH_HM_MS = h("7E1F59D3649DB60900EA4F8A585A657A"
                    "9277B30450584CF54351198CDEA30C49")

# Master secret (48 bytes) — RFC 9189 A.1.3.1
A131_MS = h("FDD27CB404AD4E4449684F7C5590E9E7"
            "02EF4101933B5277A4A96DF500B07CC3"
            "324FD8A6D907CBB03DF3FB331F1C4D0C")

# Connection key material block (136 bytes): 2×MAC32 + 2×ENC32 + 2×IV4
# Label "key expansion", seed = r_s || r_c (server || client per RFC 5246 §6.3)
A131_KM = h(
    "DD4E1017E3091FFD8675658A78009009"  # bytes   0-15  client_write_MAC_key [0]
    "3BBE69ECA693315CA85BE0A6143DC9F8"  # bytes  16-31  client_write_MAC_key [1]
    "1D64D023465F8BEA17F812F8C2D8BFC0"  # bytes  32-47  server_write_MAC_key [0]
    "D9BBABA7B4DFD3A17CE0E13B2D6365F3"  # bytes  48-63  server_write_MAC_key [1]
    "FC8B3459CF54FE449A04076453730800"  # bytes  64-79  client_write_key     [0]
    "751032559D07B6C4EAC6754871BC978A"  # bytes  80-95  client_write_key     [1]
    "B90E2AEE987714BBD8F757AEF784FF24"  # bytes  96-111 server_write_key     [0]
    "47B3942EB43E2635731C4C2822D02D79"  # bytes 112-127 server_write_key     [1]
    "2B6A813F"                          # bytes 128-131 client_write_IV (4 B)
    "93EDA6FA"                          # bytes 132-135 server_write_IV (4 B)
)

# HASH(HM) and verify_data for client Finished (RFC 9189 A.1.3.1)
A131_HASH_HM_CLIENT = h("7E1F59D3649DB60900EA4F8A585A657A"
                        "9277B30450584CF54351198CDEA30C49")
A131_CLIENT_VERIFY  = h("B461C5AD25EA1E62B370BD1F1BCB1691"
                        "FCCCBA378BBC1343BE54B38DF553B7A5")

# HASH(HM) and verify_data for server Finished (RFC 9189 A.1.3.1)
A131_HASH_HM_SERVER = h("DBD7D893824AEDFDD5FB7B754B47E1E6"
                        "AFE077DAE6D113634207C7EE0FC6F3B1")
A131_SERVER_VERIFY  = h("4539EC8D0AF7B1A62041AB434A437771"
                        "D34C4719D86EBBFD0F28C3E953550CD0")

# ---------------------------------------------------------------------------
# A.1.3.2 - PRF / MS / Key Material / Finished (Kuznyechik)
# ---------------------------------------------------------------------------

# Same ClientHello/ServerHello randoms as A.1.3.1 (same transcript prefix)
A132_r_c = A131_r_c
A132_r_s = A131_r_s

# HASH(HM) for extended master secret (different from A131 — different CKE)
A132_HASH_HM_MS = h("9D640DD8B2546B8705CC3E67F3BB832F"
                    "892A5BD5D45CA044850114C2E6560269")

# Master secret (48 bytes) — RFC 9189 A.1.3.2
A132_MS = h("E31817B0EC7F3BC94A8BC45F8912DEC5"
            "712A7A34785631C04BAE8143EE1790B4"
            "C9D3680F6C9DE1707458C875624DB6ED")

# Connection key material block (144 bytes): 2×MAC32 + 2×ENC32 + 2×IV8
A132_KM = h(
    "50525D334EF7006C1DEDB8B808EA03CC"  # bytes   0-15  client_write_MAC_key [0]
    "CF1FCB3D3365F972E17C7C314EDD9790"  # bytes  16-31  client_write_MAC_key [1]
    "6C7435220AA1B0C6DE6A1B0FAC29B617"  # bytes  32-47  server_write_MAC_key [0]
    "9EB323866225E07F304CA1D127758629"  # bytes  48-63  server_write_MAC_key [1]
    "7B97205D7A08C2CD7F603C094675E6C4"  # bytes  64-79  client_write_key     [0]
    "CC15F2840D9AEC63F02AFF51DBD574D2"  # bytes  80-95  client_write_key     [1]
    "766C772B832FCE58CB4DE5498877A67A"  # bytes  96-111 server_write_key     [0]
    "A45140B2ED526E61650A281B325635BC"  # bytes 112-127 server_write_key     [1]
    "CB8EF94C5BDF5B9F"                  # bytes 128-135 client_write_IV (8 B)
    "4748B95BF1B0E0BF"                  # bytes 136-143 server_write_IV (8 B)
)

# HASH(HM) and verify_data for client Finished (RFC 9189 A.1.3.2)
A132_HASH_HM_CLIENT = h("C9A480DA296CDD123E9AEB26888B8619"
                        "EA6778B723FAA8B2DC706ACBA5ABAF11")
A132_CLIENT_VERIFY  = h("987C13E6FA16F3D510AE83002358 7227"  # spaces stripped by h()
                        "3290094C8FC7B5F0C7D747C42735F8F1")

# HASH(HM) and verify_data for server Finished (RFC 9189 A.1.3.2)
A132_HASH_HM_SERVER = h("4A414CAD20F846D8F5D1052610A59DED"
                        "6D2B1BB2A89E135101FC9E49EDA80FB4")
A132_SERVER_VERIFY  = h("1E937DA477EE1F230A41D6E9D41446B7"
                        "F21CA1B2E2324A552D52B3255EB43DDF")


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

class TestPRF(unittest.TestCase):
    """RFC 9189 §4.3.4 / A.1.3.1-2: PRF_TLS_GOSTR3411_2012_256 validation."""

    def test_master_secret_magma(self):
        """A.1.3.1: PRF(PMS, "extended master secret", HASH(HM)) == MS."""
        got = prf_tls_gost(A131_PS, b"extended master secret", A131_HASH_HM_MS, 48)
        self.assertEqual(got, A131_MS)

    def test_key_material_magma(self):
        """A.1.3.1: PRF(MS, "key expansion", r_s||r_c) produces 136-byte key block."""
        km = prf_tls_gost(A131_MS, b"key expansion", A131_r_s + A131_r_c, 136)
        self.assertEqual(km, A131_KM)
        # Also verify individual key slices
        self.assertEqual(km[0:32],   A131_KM[0:32],   "client_write_MAC_key")
        self.assertEqual(km[32:64],  A131_KM[32:64],  "server_write_MAC_key")
        self.assertEqual(km[64:96],  A131_KM[64:96],  "client_write_key")
        self.assertEqual(km[96:128], A131_KM[96:128], "server_write_key")
        self.assertEqual(km[128:132], A131_KM[128:132], "client_write_IV")
        self.assertEqual(km[132:136], A131_KM[132:136], "server_write_IV")

    def test_client_finished_magma(self):
        """A.1.3.1: PRF(MS, "client finished", HASH(HM))[0:32] == client_verify_data."""
        got = prf_tls_gost(A131_MS, b"client finished", A131_HASH_HM_CLIENT, 32)
        self.assertEqual(got, A131_CLIENT_VERIFY)

    def test_server_finished_magma(self):
        """A.1.3.1: PRF(MS, "server finished", HASH(HM))[0:32] == server_verify_data."""
        got = prf_tls_gost(A131_MS, b"server finished", A131_HASH_HM_SERVER, 32)
        self.assertEqual(got, A131_SERVER_VERIFY)

    def test_master_secret_kuznyechik(self):
        """A.1.3.2: PRF(PMS, "extended master secret", HASH(HM)) == MS."""
        got = prf_tls_gost(A132_PS, b"extended master secret", A132_HASH_HM_MS, 48)
        self.assertEqual(got, A132_MS)

    def test_key_material_kuznyechik(self):
        """A.1.3.2: PRF(MS, "key expansion", r_s||r_c) produces 144-byte key block."""
        km = prf_tls_gost(A132_MS, b"key expansion", A132_r_s + A132_r_c, 144)
        self.assertEqual(km, A132_KM)

    def test_client_finished_kuznyechik(self):
        """A.1.3.2: PRF(MS, "client finished", HASH(HM))[0:32] == client_verify_data."""
        got = prf_tls_gost(A132_MS, b"client finished", A132_HASH_HM_CLIENT, 32)
        self.assertEqual(got, A132_CLIENT_VERIFY)

    def test_server_finished_kuznyechik(self):
        """A.1.3.2: PRF(MS, "server finished", HASH(HM))[0:32] == server_verify_data."""
        got = prf_tls_gost(A132_MS, b"server finished", A132_HASH_HM_SERVER, 32)
        self.assertEqual(got, A132_SERVER_VERIFY)


class TestKImp15(unittest.TestCase):
    """RFC 9189 §8.2.1: KImp15 key import (inverse of KExp15)."""

    def test_roundtrip_magma(self):
        """KExp15 then KImp15 must recover original PS (Magma)."""
        pmsexp = kexp15(A131_PS, A131_K_Exp_MAC, A131_K_Exp_ENC, A131_IV,
                        GOST3412Magma, bs=8)
        recovered = kimp15(pmsexp, A131_K_Exp_MAC, A131_K_Exp_ENC, A131_IV,
                           GOST3412Magma, bs=8)
        self.assertEqual(recovered, A131_PS)

    def test_roundtrip_kuznyechik(self):
        """KExp15 then KImp15 must recover original PS (Kuznyechik)."""
        pmsexp = kexp15(A132_PS, A132_K_Exp_MAC, A132_K_Exp_ENC, A132_IV,
                        GOST3412Kuznechik, bs=16)
        recovered = kimp15(pmsexp, A132_K_Exp_MAC, A132_K_Exp_ENC, A132_IV,
                           GOST3412Kuznechik, bs=16)
        self.assertEqual(recovered, A132_PS)

    def test_kimp15_from_rfc_pmsexp_magma(self):
        """A.1.3.1: KImp15(A131_PMSEXP, K_Imp_MAC, K_Imp_ENC, IV) == A131_PS."""
        recovered = kimp15(A131_PMSEXP, A131_K_Exp_MAC, A131_K_Exp_ENC, A131_IV,
                           GOST3412Magma, bs=8)
        self.assertEqual(recovered, A131_PS)

    def test_kimp15_from_rfc_pmsexp_kuznyechik(self):
        """A.1.3.2: KImp15(A132_PMSEXP, K_Imp_MAC, K_Imp_ENC, IV) == A132_PS."""
        recovered = kimp15(A132_PMSEXP, A132_K_Exp_MAC, A132_K_Exp_ENC, A132_IV,
                           GOST3412Kuznechik, bs=16)
        self.assertEqual(recovered, A132_PS)

    def test_kimp15_mac_failure(self):
        """Corrupted PMSEXP must raise ValueError (not silently return garbage)."""
        corrupted = bytearray(A131_PMSEXP)
        corrupted[0] ^= 0xFF
        with self.assertRaises(ValueError):
            kimp15(bytes(corrupted), A131_K_Exp_MAC, A131_K_Exp_ENC, A131_IV,
                   GOST3412Magma, bs=8)


class TestSyntheticE2E(unittest.TestCase):
    """Full synthetic GOST TLS 1.2 handshake + record round-trip (RFC 9189 §4).

    Uses Magma CTR_OMAC cipher suite with random keys each run.
    Exercises: KEG_256 → KExp15/KImp15 → PRF(MS) → PRF(key_expansion)
               → TLSTREE → CTR_OMAC record encrypt/decrypt + MAC verify.
    """

    def test_magma_ctr_omac_full_handshake(self):
        """Synthetic Magma CTR_OMAC: random keying, full chain from VKO to record."""
        from os import urandom

        curve = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
        bs = 8  # Magma block size

        # 1. Server: static keypair
        d_s = prv_unmarshal(urandom(32)) % curve.q or 1
        Q_s = public_key(curve, d_s)

        # 2. Client: ephemeral keypair
        d_eph = prv_unmarshal(urandom(32)) % curve.q or 1
        Q_eph = public_key(curve, d_eph)

        # 3. Hello randoms
        r_c = urandom(32)
        r_s = urandom(32)

        # 4. KEG_256 (RFC 9189 §8.3.1): H = HASH(r_c || r_s)
        H = GOST34112012256(r_c + r_s).digest()
        UKM_int = int.from_bytes(H[0:8], "little")        # INT(H[1..8], LE) per RFC 9189 §8.3.1
        seed_keg = H[16:24]                               # H[17..24]
        IV_wrap  = H[24:28]                               # H[25..28] for Magma

        # 5. Both derive same K_EXP via VKO (DH property guarantees equality)
        K_EXP_c = kek_34102012256(curve, d_eph, Q_s,  UKM_int)
        K_EXP_s = kek_34102012256(curve, d_s,   Q_eph, UKM_int)
        self.assertEqual(K_EXP_c, K_EXP_s, "VKO K_EXP mismatch")

        # 6. KEG_256 step 5: KDFTREE_256(K_EXP, "kdf tree", seed, 1)
        K_Exp_MAC, K_Exp_ENC = kdftree_256(K_EXP_c, b"kdf tree", seed_keg)

        # 7. Client wraps PMS; server unwraps
        PMS = urandom(32)
        PMSEXP = kexp15(PMS, K_Exp_MAC, K_Exp_ENC, IV_wrap, GOST3412Magma, bs=bs)
        PMS_recovered = kimp15(PMSEXP, K_Exp_MAC, K_Exp_ENC, IV_wrap, GOST3412Magma, bs=bs)
        self.assertEqual(PMS_recovered, PMS, "KImp15 failed to recover PMS")

        # 8. Master secret: simple variant (not extended; no transcript hash needed)
        MS = prf_tls_gost(PMS, b"master secret", r_c + r_s, 48)

        # 9. Key material: 136 bytes for Magma CTR_OMAC
        km = prf_tls_gost(MS, b"key expansion", r_s + r_c, 136)
        cw_mac = km[0:32]
        sw_mac = km[32:64]
        cw_enc = km[64:96]
        sw_enc = km[96:128]
        cw_iv  = km[128:132]

        # 10. Client encrypts a record (seqnum=0, type=0x17)
        plaintext = b"hello from client"
        seqnum = 0
        K_MAC = tlstree(cw_mac, seqnum, MAGMA_C1, MAGMA_C2, MAGMA_C3)
        K_ENC = tlstree(cw_enc, seqnum, MAGMA_C1, MAGMA_C2, MAGMA_C3)
        length_be = struct.pack(">H", len(plaintext))
        mac_input = struct.pack(">Q", seqnum) + b"\x17\x03\x03" + length_be + plaintext
        mac = gost3413_mac(GOST3412Magma(K_MAC).encrypt, bs, mac_input)
        ciphertext = gost3413_ctr(GOST3412Magma(K_ENC).encrypt, bs,
                                  plaintext + mac, cw_iv)

        # 11. Server decrypts (uses same cw_mac / cw_enc since it's client→server)
        K_MAC_s = tlstree(cw_mac, seqnum, MAGMA_C1, MAGMA_C2, MAGMA_C3)
        K_ENC_s = tlstree(cw_enc, seqnum, MAGMA_C1, MAGMA_C2, MAGMA_C3)
        decrypted = gost3413_ctr(GOST3412Magma(K_ENC_s).encrypt, bs, ciphertext, cw_iv)
        recovered_plain = decrypted[:-bs]
        recovered_mac   = decrypted[-bs:]

        # 12. Server verifies MAC and plaintext
        expected_mac = gost3413_mac(GOST3412Magma(K_MAC_s).encrypt, bs, mac_input)
        self.assertEqual(recovered_mac,   expected_mac, "MAC verification failed")
        self.assertEqual(recovered_plain, plaintext,    "Plaintext mismatch")

        # -----------------------------------------------------
        # 13. Generate PCAP & test external decrypt_rfc9189.py
        # -----------------------------------------------------
        import dpkt
        import time
        import subprocess
        import os
        import sys
        from pyasn1.type import univ
        from pyasn1.codec.der.encoder import encode as der_encode

        def make_tls_record(ctype, pld):
            return bytes([ctype]) + b"\x03\x03" + len(pld).to_bytes(2, "big") + pld
            
        def make_hs(htype, pld):
            return bytes([htype]) + len(pld).to_bytes(3, "big") + pld

        # ClientHello
        ch_payload = b"\x03\x03" + r_c + b"\x00" + b"\x00\x02\xc1\x01" + b"\x01\x00" + b"\x00\x00"
        ch_record = make_tls_record(22, make_hs(1, ch_payload))

        # ServerHello
        sh_payload = b"\x03\x03" + r_s + b"\x00" + b"\xc1\x01" + b"\x00" + b"\x00\x00"
        sh_record = make_tls_record(22, make_hs(2, sh_payload))

        # ClientKeyExchange (CKE)
        key_exp_asn = univ.OctetString(PMSEXP)
        alg_seq = univ.Sequence()
        alg_seq.setComponentByPosition(0, univ.ObjectIdentifier('1.2.643.2.2.19'))
        
        x_bytes = Q_eph[0].to_bytes(32, 'little')
        y_bytes = Q_eph[1].to_bytes(32, 'little')
        pub_bitstr = univ.BitString.fromOctetString(x_bytes + y_bytes)
        
        spki = univ.Sequence()
        spki.setComponentByPosition(0, alg_seq)
        spki.setComponentByPosition(1, pub_bitstr)
        
        gkt = univ.Sequence()
        gkt.setComponentByPosition(0, key_exp_asn)
        gkt.setComponentByPosition(1, spki)
        
        cke_payload = der_encode(gkt)
        cke_record = make_tls_record(22, make_hs(16, cke_payload))
        
        # Application Data
        app_record = make_tls_record(23, ciphertext)

        pcap_file = os.path.join(os.path.dirname(__file__), "synthetic_magma.pcap")
        with open(pcap_file, "wb") as f:
            pcap = dpkt.pcap.Writer(f)
            src_ip, dst_ip = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"
            pack_time = time.time()
            
            # Simple wrapper
            def write_packet(data, is_client):
                nonlocal pack_time
                tcp = dpkt.tcp.TCP(sport=1234, dport=443 if is_client else 1234, data=data)
                # Need basic TCP sequence tracking isn't strictly necessary for DPkt IP iter, but adds safety
                ip = dpkt.ip.IP(src=src_ip if is_client else dst_ip, dst=dst_ip if is_client else src_ip, p=dpkt.ip.IP_PROTO_TCP, data=bytes(tcp))
                eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip))
                pcap.writepkt(bytes(eth), pack_time)
                pack_time += 0.1
            
            write_packet(ch_record, True)
            write_packet(sh_record, False)
            write_packet(cke_record, True)
            write_packet(app_record, True)

        decoder_path = os.path.join(os.path.dirname(__file__), "decrypt_rfc9189.py")
        server_key_hex = hex(d_s)[2:].zfill(64)
        
        res = subprocess.run(
            [sys.executable, decoder_path, pcap_file, "--key", server_key_hex],
            capture_output=True, text=True
        )
        
        self.assertEqual(res.returncode, 0, f"Decoder failed. stderr: {res.stderr}\nstdout: {res.stdout}")
        self.assertIn("hello from client", res.stdout, "Decoded plaintext not found in stdout")
        
        if os.path.exists(pcap_file):
            os.remove(pcap_file)


if __name__ == "__main__":
    unittest.main(verbosity=2)
