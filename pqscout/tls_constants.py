"""TLS registry values needed to identify cryptography in handshakes.
Values from IANA TLS parameters registry."""

# TLS versions (legacy_version / supported_versions)
TLS_VERSIONS = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

# Subset of cipher suites; each maps to (kex, auth, cipher, mac)
CIPHER_SUITES = {
    0x1301: ("TLS_AES_128_GCM_SHA256",        None,     None,    "AES-128-GCM", "SHA256"),
    0x1302: ("TLS_AES_256_GCM_SHA384",        None,     None,    "AES-256-GCM", "SHA384"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256",  None,     None,    "CHACHA20",    "SHA256"),
    0xc02f: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA",   "AES-128-GCM", "SHA256"),
    0xc030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA",   "AES-256-GCM", "SHA384"),
    0xc02b: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","ECDHE","ECDSA", "AES-128-GCM", "SHA256"),
    0xc02c: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","ECDHE","ECDSA", "AES-256-GCM", "SHA384"),
    0xc013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",     "ECDHE","RSA",   "AES-128-CBC", "SHA1"),
    0xc014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",     "ECDHE","RSA",   "AES-256-CBC", "SHA1"),
    0x009c: ("TLS_RSA_WITH_AES_128_GCM_SHA256",        "RSA",  "RSA",   "AES-128-GCM", "SHA256"),
    0x009d: ("TLS_RSA_WITH_AES_256_GCM_SHA384",        "RSA",  "RSA",   "AES-256-GCM", "SHA384"),
    0x002f: ("TLS_RSA_WITH_AES_128_CBC_SHA",           "RSA",  "RSA",   "AES-128-CBC", "SHA1"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA",           "RSA",  "RSA",   "AES-256-CBC", "SHA1"),
    0x000a: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA",          "RSA",  "RSA",   "3DES-CBC",    "SHA1"),
    0xc027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES-128-CBC", "SHA256"),
    0xc028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES-256-CBC", "SHA384"),
    0xcca8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "CHACHA20", "SHA256"),
    0xcca9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "CHACHA20", "SHA256"),
    0x009e: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AES-128-GCM", "SHA256"),
    0x009f: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AES-256-GCM", "SHA384"),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES-128-CBC", "SHA1"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES-256-CBC", "SHA1"),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "AES-128-CBC", "SHA256"),
    0x006b: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "AES-256-CBC", "SHA256"),
    0xccaa: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "RSA", "CHACHA20", "SHA256"),
    0x003c: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "AES-128-CBC", "SHA256"),
    0x003d: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "AES-256-CBC", "SHA256"),
}

# Named groups (supported_groups / key_share) - the key exchange primitive
NAMED_GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001d: "x25519",    0x001e: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    # Post-quantum / hybrid. Codepoints checked against the IANA "TLS
    # Supported Groups" registry (tls-parameters-8.csv, retrieved Oct 2026).
    # The original version of this table had three errors, found by that
    # check: 0x6399/0x639a were labelled as the ML-KEM hybrids but are the
    # obsolete pre-standard Kyber drafts; the pure ML-KEM groups were given
    # non-existent codepoints (0x023a-c instead of 0x0200-2); and
    # SecP256r1MLKEM768 (0x11eb) and SecP384r1MLKEM1024 (0x11ed) were missing,
    # so real servers using them would have been mis-scored as vulnerable.
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",   # IETF tls-mlkem
    0x11eb: "SecP256r1MLKEM768",                                   # RFC 10024
    0x11ec: "X25519MLKEM768",                                      # RFC 10024
    0x11ed: "SecP384r1MLKEM1024",                                  # RFC 10024
    0x6399: "X25519Kyber768Draft00",      # obsolete pre-standard (Kyber, not ML-KEM)
    0x639a: "SecP256r1Kyber768Draft00",   # obsolete pre-standard
}

# Groups considered quantum-safe (or hybrid) - everything else is vulnerable.
# The obsolete Kyber drafts still carry a post-quantum component, so they
# are not HNDL-exposed, but they are flagged separately as needing upgrade.
PQ_SAFE_GROUPS = {
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00",
}
OBSOLETE_PQ_GROUPS = {"X25519Kyber768Draft00", "SecP256r1Kyber768Draft00"}

HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello"}
EXT_SUPPORTED_GROUPS = 10
EXT_SIG_ALGS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
