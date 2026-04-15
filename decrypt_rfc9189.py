#!/usr/bin/env python3
import argparse
import binascii
import os
import struct
import sys
import collections

# Attempt to load dpkt and pyasn1 gracefully
try:
    import dpkt
    from pyasn1.codec.der.decoder import decode as der_decode
    from pyasn1.type import univ
except ImportError:
    sys.exit("Please install dependencies: pip install dpkt pyasn1")

# Guard for pygost
_PYGOST_PATH = "/path/to/pygost"
if not os.path.isdir(_PYGOST_PATH):
    raise RuntimeError(f"pygost source not found at {_PYGOST_PATH}")
sys.path.insert(0, _PYGOST_PATH)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_rfc9189 import (
    tlstree, kimp15, prf_tls_gost, kdftree_256,
    MAGMA_C1, MAGMA_C2, MAGMA_C3,
    KUZNYECHIK_C1, KUZNYECHIK_C2, KUZNYECHIK_C3
)
from pygost.gost3410 import CURVES
from pygost.gost3410_vko import kek_34102012256, kek_34102012512
from pygost.gost34112012256 import GOST34112012256
from pygost.gost3412 import GOST3412Magma, GOST3412Kuznechik
from pygost.gost3413 import ctr as gost3413_ctr, mac as gost3413_mac

def parse_args():
    parser = argparse.ArgumentParser(description="Decrypt GOST TLS 1.2 PCAP")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--key", required=True, help="Server private key (hex)")
    parser.add_argument("--curve", default="id-GostR3410-2001-CryptoPro-A-ParamSet", help="Curve OID")
    return parser.parse_args()

class TLSConnection:
    def __init__(self, server_priv_key_hex, curve_oid):
        self.server_d = int(server_priv_key_hex, 16)
        self.curve = CURVES[curve_oid]
        
        self.client_random = None
        self.server_random = None
        self.cipher_suite = None
        
        self.ms = None
        self.km = None
        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        
        self.client_seqnum = 0
        self.server_seqnum = 0
        
        self.handshake_messages = b""
        
    def is_kuznyechik(self):
        # 0xC100=Kuznyechik_CTR_OMAC, 0xC101=Magma_CTR_OMAC
        return self.cipher_suite == b'\xC1\x00'

    def process_handshake(self, hs_type, payload):
        # Keep track of everything up to ClientKeyExchange for MS computation
        # (Though RFC 9189 MS usually doesn't need transcript for simple extraction, extended master secret does.)
        
        if hs_type == 1: # ClientHello
            if len(payload) >= 34:
                self.client_random = payload[2:34]
                print(f"[*] Found ClientHello. random = {self.client_random.hex()}")
                
        elif hs_type == 2: # ServerHello
            if len(payload) >= 34:
                self.server_random = payload[2:34]
                print(f"[*] Found ServerHello. random = {self.server_random.hex()}")
                # Extract cipher suite
                session_id_len = payload[34]
                cs_offset = 35 + session_id_len
                self.cipher_suite = payload[cs_offset : cs_offset+2]
                print(f"[*] Cipher suite negotiated: {self.cipher_suite.hex()}")

        elif hs_type == 16: # ClientKeyExchange
            print(f"[*] Found ClientKeyExchange.")
            self.process_cke(payload)

    def process_cke(self, payload):
        # Decode ASN.1 GostKeyTransport
        decoded, rest = der_decode(payload)
        
        # decoded[0] is keyExp (PSExp)
        # decoded[1] is ephemeralPublicKey (SubjectPublicKeyInfo)
        
        # Extract PSExp
        if isinstance(decoded[0], univ.OctetString):
            psexp_bytes = bytes(decoded[0])
        else:
            print("[-] CKE format not standard GostKeyTransport! Check parsing.")
            return

        # Extract ephemeral public key (x, y)
        spki = decoded[1]
        bit_string = spki[1]
        pub_bytes = bit_string.asOctets()
        if len(pub_bytes) == 64:
            x_bytes = pub_bytes[:32]
            y_bytes = pub_bytes[32:]
            Q_eph = (int.from_bytes(x_bytes, "little"), int.from_bytes(y_bytes, "little"))
        else:
            print("[-] Public key not 64 bytes in CKE.")
            return
            
        print(f"[*] Q_eph extracted.")
        
        # 1. H = HASH(r_c | r_s)
        H = GOST34112012256(self.client_random + self.server_random).digest()
        
        if self.is_kuznyechik():
            UKM_int = int.from_bytes(H[0:8], "little")
            K_EXP_full = kek_34102012512(self.curve, self.server_d, Q_eph, UKM_int)
            K_Exp_MAC = K_EXP_full[:32]
            K_Exp_ENC = K_EXP_full[32:64]
            IV_wrap = H[24:32]
            cipher_cls = GOST3412Kuznechik
            bs = 16
        else:
            # Magma
            UKM_int = int.from_bytes(H[0:8], "little")
            K_EXP_c = kek_34102012256(self.curve, self.server_d, Q_eph, UKM_int)
            seed_keg = H[16:24]
            K_Exp_MAC, K_Exp_ENC = kdftree_256(K_EXP_c, b"kdf tree", seed_keg)
            IV_wrap = H[24:28]
            cipher_cls = GOST3412Magma
            bs = 8

        # Unwrap PMS
        try:
            pms = kimp15(psexp_bytes, K_Exp_MAC, K_Exp_ENC, IV_wrap, cipher_cls, bs)
            print(f"[+] PMS successfully unwrapped: {pms.hex()}")
        except Exception as e:
            print(f"[-] Failed to unwrap PMS: {e}")
            return

        # Simple Master Secret derivation
        # (Assuming no extended master secret for now, standard: PRF(PMS, "master secret", client_random + server_random))
        # Note: If Extended Master Secret is used, this needs the transcript hash.
        # For now we use the basic format from Section 4.3.4 (and A.1.3 vectors, which use extended MS).
        # We will attempt the basic PRF:
        print("[!] Generating basic Master Secret. (Extended Master Secret requires transcript hash).")
        self.ms = prf_tls_gost(pms, b"master secret", self.client_random + self.server_random, 48)
        
        # Derive Key Material (KM)
        km_len = 144 if self.is_kuznyechik() else 136
        self.km = prf_tls_gost(self.ms, b"key expansion", self.server_random + self.client_random, km_len)
        
        self.client_write_mac_key = self.km[0:32]
        self.server_write_mac_key = self.km[32:64]
        self.client_write_key     = self.km[64:96]
        self.server_write_key     = self.km[96:128]
        
        if self.is_kuznyechik():
            self.client_write_iv = self.km[128:136]
            self.server_write_iv = self.km[136:144]
        else:
            self.client_write_iv = self.km[128:132]
            self.server_write_iv = self.km[132:136]
            
        print("[+] Keys derived successfully!")

    def decrypt_record(self, payload, is_client):
        """Decrypt CTR_OMAC application data."""
        if not self.km:
            return None
            
        seq = self.client_seqnum if is_client else self.server_seqnum
        mac_key_base = self.client_write_mac_key if is_client else self.server_write_mac_key
        enc_key_base = self.client_write_key if is_client else self.server_write_key
        base_iv = self.client_write_iv if is_client else self.server_write_iv
        
        if self.is_kuznyechik():
            c1, c2, c3 = KUZNYECHIK_C1, KUZNYECHIK_C2, KUZNYECHIK_C3
            cipher_cls = GOST3412Kuznechik
            bs = 16
        else:
            c1, c2, c3 = MAGMA_C1, MAGMA_C2, MAGMA_C3
            cipher_cls = GOST3412Magma
            bs = 8
            
        # 1. TLSTREE key derivation
        k_enc = tlstree(enc_key_base, seq, c1, c2, c3)
        k_mac = tlstree(mac_key_base, seq, c1, c2, c3)
        
        # 2. IV construction: IV_n = STR((INT(BASE_IV) + n) mod 2^(bs*4))
        # Note: bs/2 bytes.
        iv_int = int.from_bytes(base_iv, "big")
        iv_n = (iv_int + seq) % (1 << (bs * 4))
        iv = iv_n.to_bytes(bs // 2, "big")
        
        # 3. Decrypt
        decrypted = gost3413_ctr(cipher_cls(k_enc).encrypt, bs, payload, iv)
        fragment = decrypted[:-bs]
        mac_got = decrypted[-bs:]
        
        # 4. Update seqnum
        if is_client:
            self.client_seqnum += 1
        else:
            self.server_seqnum += 1
            
        return fragment

def main():
    args = parse_args()
    
    with open(args.pcap, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        
        conn = TLSConnection(args.key, args.curve)
        tls_buffers = collections.defaultdict(bytes)
        
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP): continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP): continue
            tcp = ip.data
            
            if len(tcp.data) == 0: continue
            
            # Identify direction
            is_client = (tcp.dport == 443)
            flow_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            
            tls_buffers[flow_id] += tcp.data
            
            stream = tls_buffers[flow_id]
            while len(stream) >= 5:
                ctype, version, length = struct.unpack(">BHH", stream[:5])
                if len(stream) < 5 + length:
                    break
                    
                record_payload = stream[5:5+length]
                stream = stream[5+length:]
                tls_buffers[flow_id] = stream
                
                if ctype == 22: # Handshake
                    # Parse handshakes bridging records
                    hs_ptr = 0
                    while hs_ptr < len(record_payload):
                        hs_type = record_payload[hs_ptr]
                        # 3 bytes length
                        hs_len = int.from_bytes(record_payload[hs_ptr+1:hs_ptr+4], "big")
                        hs_payload = record_payload[hs_ptr+4 : hs_ptr+4+hs_len]
                        
                        conn.process_handshake(hs_type, hs_payload)
                        conn.handshake_messages += record_payload[hs_ptr : hs_ptr+4+hs_len]
                        
                        hs_ptr += 4 + hs_len
                        
                elif ctype == 23: # Application Data
                    cleartext = conn.decrypt_record(record_payload, is_client)
                    if cleartext:
                        direction = "C->S" if is_client else "S->C"
                        print(f"[{direction}] Decrypted Apps Data: {cleartext}")

if __name__ == "__main__":
    main()
