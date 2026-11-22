"""Generates CryptoTestVectorsU.pas for the IAMClient4D crypto tests.

Sources:
- RFC 7515 Appendix A.2/A.3/A.4 and RFC 7520 Sections 4.1/4.2/4.3 (downloaded).
- OpenSSL CLI signatures for all RS*/PS*/ES* algorithms (fresh keys each run);
  ECDSA signatures are repeated until R or S starts with a zero byte.
- RSA vectors signed here (deterministic): RFC 7515 A.2 key and keys from a seeded
  generator; signatures starting with a zero byte and keys the providers must reject
  (e = 1, even e, e >= n, e > 64 bits with n > 3072 bits, n > 16384 bits, n < 2048 bits)
  or accept (n 9216 bits: above the TMS limit of 8192 bits; n 2056 bits: 257 bytes, not a size
  TMS works with, so the providers pad n and must take EM and emBits from n itself).
- AES-256-GCM vectors from the Go crypto/cipher test suite.

Usage: python gen_vectors.py <path to openssl executable>
Requires Python 3 standard library only.
"""

import base64
import hashlib
import math
import os
import random
import re
import subprocess
import sys
import tempfile
import urllib.request

RFC_URL = "https://www.rfc-editor.org/rfc/rfc{}.txt"
OUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CryptoTestVectorsU.pas")
PAYLOAD = '{"sub":"iam4d","iss":"https://idp.example","iat":1767225600%s}'


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def int_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def signing_input(alg: str, extra: str = "") -> str:
    header = b64url(('{"alg":"%s","typ":"JWT"}' % alg).encode())
    return header + "." + b64url((PAYLOAD % extra).encode())


# --- RFC extraction ---------------------------------------------------------

def rfc_text(number: int) -> str:
    raw = urllib.request.urlopen(RFC_URL.format(number)).read().decode("ascii", "replace")
    # Drop page footers/headers so wrapped values join cleanly
    lines = [l for l in raw.replace("\f", "\n").splitlines()
             if not re.match(r"^(Jones, et al\.|Miller\s|RFC 7515 |RFC 7520 )", l)]
    return "\n".join(lines)


def section(text: str, start: str, end: str) -> str:
    # Headings start at column 0; the table of contents is indented
    i = text.index("\n" + start)
    return text[i:text.index("\n" + end, i + len(start))]


def jwk_field(block: str, name: str) -> str:
    m = re.search(r'"%s":\s*"([^"]+)"' % name, block)
    return re.sub(r"\s+", "", m.group(1))


def compact_after(block: str, marker: str) -> str:
    """Joins the wrapped compact serialization that follows marker."""
    token = re.compile(r"^[A-Za-z0-9_\-.]+$")
    parts = []
    for line in block[block.index(marker):].splitlines()[1:]:
        s = line.strip()
        if not s:
            continue
        if token.match(s):
            parts.append(s)
        elif parts:
            break
    jws = "".join(parts)
    assert jws.count(".") == 2, jws
    return jws


def rfc_vectors():
    """Returns the RFC vectors and the RFC 7515 A.2 private key."""
    vectors = []
    t15 = rfc_text(7515)
    marker15 = "complete JWS"

    a2 = section(t15, "A.2.  Example JWS Using RSASSA", "A.3.  Example")
    rsa = '{"kty":"RSA","n":"%s","e":"%s"}' % (jwk_field(a2, "n"), jwk_field(a2, "e"))
    vectors.append(("RFC 7515 A.2", "RS256", rsa, compact_after(a2, marker15)))
    a2_key = RSAKey([int.from_bytes(b64url_decode(jwk_field(a2, f)), "big") for f in ("p", "q")])
    assert a2_key.n == int.from_bytes(b64url_decode(jwk_field(a2, "n")), "big")

    a3 = section(t15, "A.3.  Example JWS Using ECDSA P-256", "A.4.  Example")
    ec256 = '{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}' % (jwk_field(a3, "x"), jwk_field(a3, "y"))
    vectors.append(("RFC 7515 A.3", "ES256", ec256, compact_after(a3, marker15)))

    a4 = section(t15, "A.4.  Example JWS Using ECDSA P-521", "A.5.  Example")
    ec521 = '{"kty":"EC","crv":"P-521","x":"%s","y":"%s"}' % (jwk_field(a4, "x"), jwk_field(a4, "y"))
    vectors.append(("RFC 7515 A.4", "ES512", ec521, compact_after(a4, marker15)))

    t20 = rfc_text(7520)
    marker20 = "The resulting JWS object using the JWS Compact Serialization:"
    ec_key = section(t20, "3.1.  EC Public Key", "3.2.  EC Private Key")
    rsa_key = section(t20, "3.3.  RSA Public Key", "3.4.  RSA Private Key")
    ec521b = '{"kty":"EC","crv":"P-521","x":"%s","y":"%s"}' % (jwk_field(ec_key, "x"), jwk_field(ec_key, "y"))
    rsab = '{"kty":"RSA","n":"%s","e":"%s"}' % (jwk_field(rsa_key, "n"), jwk_field(rsa_key, "e"))

    s41 = section(t20, "4.1.  RSA v1.5 Signature", "4.2.  RSA-PSS Signature")
    vectors.append(("RFC 7520 4.1", "RS256", rsab, compact_after(s41, marker20)))
    s42 = section(t20, "4.2.  RSA-PSS Signature", "4.3.  ECDSA Signature")
    vectors.append(("RFC 7520 4.2", "PS384", rsab, compact_after(s42, marker20)))
    s43 = section(t20, "4.3.  ECDSA Signature", "4.4.  HMAC-SHA2")
    vectors.append(("RFC 7520 4.3", "ES512", ec521b, compact_after(s43, marker20)))

    return [(src, alg, jwk, jws.rsplit(".", 1)[0], jws.rsplit(".", 1)[1]) for src, alg, jwk, jws in vectors], a2_key


# --- OpenSSL generated vectors ----------------------------------------------

def der_read(data: bytes, pos: int):
    """Returns (tag, value, next_pos) of the DER element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length


def der_children(value: bytes):
    pos, items = 0, []
    while pos < len(value):
        tag, v, pos = der_read(value, pos)
        items.append((tag, v))
    return items


def spki_public_key(der: bytes) -> bytes:
    _, spki, _ = der_read(der, 0)
    _, bitstring = der_children(spki)[1]
    return bitstring[1:]  # skip unused-bits byte


def unsigned(value: bytes) -> bytes:
    return value.lstrip(b"\x00") or b"\x00"


class OpenSSL:
    def __init__(self, exe: str, workdir: str):
        self.exe = exe
        self.workdir = workdir

    def run(self, *args):
        subprocess.run([self.exe, *args], check=True, capture_output=True, cwd=self.workdir)

    def path(self, name):
        return os.path.join(self.workdir, name)

    def keypair(self, name, *genopts):
        self.run("genpkey", *genopts, "-out", self.path(name + ".pem"))
        self.run("pkey", "-in", self.path(name + ".pem"), "-pubout", "-outform", "DER", "-out", self.path(name + ".der"))
        with open(self.path(name + ".der"), "rb") as f:
            return spki_public_key(f.read())

    def sign(self, key, digest, message: bytes, *sigopts) -> bytes:
        with open(self.path("input.bin"), "wb") as f:
            f.write(message)
        opts = []
        for o in sigopts:
            opts += ["-sigopt", o]
        self.run("dgst", "-" + digest, "-sign", self.path(key + ".pem"), *opts,
                 "-out", self.path("sig.bin"), self.path("input.bin"))
        with open(self.path("sig.bin"), "rb") as f:
            return f.read()


def rsa_jwk(pub: bytes) -> str:
    _, seq, _ = der_read(pub, 0)
    (_, n), (_, e) = der_children(seq)
    return '{"kty":"RSA","n":"%s","e":"%s"}' % (b64url(unsigned(n)), b64url(unsigned(e)))


def ec_jwk(pub: bytes, crv: str, size: int) -> str:
    assert pub[0] == 4 and len(pub) == 1 + 2 * size
    return '{"kty":"EC","crv":"%s","x":"%s","y":"%s"}' % (crv, b64url(pub[1:1 + size]), b64url(pub[1 + size:]))


def ecdsa_raw(der_sig: bytes, size: int) -> bytes:
    _, seq, _ = der_read(der_sig, 0)
    (_, r), (_, s) = der_children(seq)
    return unsigned(r).rjust(size, b"\x00") + unsigned(s).rjust(size, b"\x00")


def openssl_vectors(exe: str):
    vectors = []
    with tempfile.TemporaryDirectory() as tmp:
        ossl = OpenSSL(exe, tmp)

        for bits, sha in ((2048, "sha256"), (3072, "sha384"), (4096, "sha512")):
            name = "rsa%d" % bits
            jwk = rsa_jwk(ossl.keypair(name, "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits))
            hlen = int(sha[3:]) // 8
            for alg, opts in (("RS" + sha[3:], ()),
                              ("PS" + sha[3:], ("rsa_padding_mode:pss", "rsa_pss_saltlen:%d" % hlen, "rsa_mgf1_md:" + sha))):
                data = signing_input(alg)
                sig = ossl.sign(name, sha, data.encode(), *opts)
                vectors.append(("OpenSSL RSA-%d" % bits, alg, jwk, data, b64url(sig)))

        for crv, curve, sha, size in (("P-256", "P-256", "sha256", 32),
                                      ("P-384", "P-384", "sha384", 48),
                                      ("P-521", "P-521", "sha512", 66)):
            name = "ec" + crv[2:]
            jwk = ec_jwk(ossl.keypair(name, "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve), crv, size)
            alg = "ES" + sha[3:]
            data = signing_input(alg)
            # R or S with a leading zero byte: exercises the minimal DER INTEGER encoding
            for _ in range(5000):
                sig = ecdsa_raw(ossl.sign(name, sha, data.encode()), size)
                if sig[0] == 0 or sig[size] == 0:
                    break
            else:
                raise RuntimeError("no %s signature with a leading zero byte" % crv)
            vectors.append(("OpenSSL " + crv, alg, jwk, data, b64url(sig)))
    return vectors


# --- RSA vectors signed here -------------------------------------------------

DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, math.isqrt(p) + 1, 2))]
E64 = 2 ** 64 - 59  # largest 64-bit prime


def crt(residues, moduli):
    x, m = 0, 1
    for r, p in zip(residues, moduli):
        x += m * ((r - x) * pow(m, -1, p) % p)
        m *= p
    return x


def sqrt_mod_prime(a: int, p: int):
    """Square root of a modulo the odd prime p (Tonelli-Shanks), None for a non-residue."""
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def is_probable_prime(n: int, rng: random.Random) -> bool:
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(32):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(rng: random.Random, bits: int, exponents) -> int:
    """Prime with its top 8 bits set, p - 1 coprime with every exponent."""
    while True:
        p = rng.getrandbits(bits) | (0xFF << (bits - 8)) | 1
        if all(math.gcd(e, p - 1) == 1 for e in exponents) and is_probable_prime(p, rng):
            return p


class RSAKey:
    """RSA key with any number of primes (only the public operation is checked by the tests)."""

    def __init__(self, primes):
        self.primes = primes
        self.n = math.prod(primes)
        self.k = (self.n.bit_length() + 7) // 8
        self.phi = math.prod(p - 1 for p in primes)
        self.lam = math.lcm(*(p - 1 for p in primes))

    def jwk(self, e: int) -> str:
        return '{"kty":"RSA","n":"%s","e":"%s"}' % (b64url(int_bytes(self.n)), b64url(int_bytes(e)))

    def private_op(self, m: int, e: int) -> bytes:
        d = pow(e, -1, self.lam)
        return crt([pow(m % p, d % (p - 1), p) for p in self.primes], self.primes).to_bytes(self.k, "big")

    def sqrt(self, m: int):
        """Signature for e = 2: square root of m modulo n, None if there is none."""
        roots = [sqrt_mod_prime(m, p) for p in self.primes]
        if None in roots:
            return None
        s = crt(roots, self.primes)
        assert s * s % self.n == m
        return s.to_bytes(self.k, "big")


def mgf1(seed: bytes, length: int, sha: str) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.new(sha, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def emsa_pkcs1(message: bytes, sha: str, k: int) -> int:
    t = DIGEST_INFO[sha] + hashlib.new(sha, message).digest()
    return int.from_bytes(b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t, "big")


def emsa_pss(message: bytes, sha: str, em_bits: int, salt: bytes) -> int:
    m_hash = hashlib.new(sha, message).digest()
    h_len, em_len = len(m_hash), (em_bits + 7) // 8
    h = hashlib.new(sha, b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - h_len - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, mgf1(h, em_len - h_len - 1, sha)))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return int.from_bytes(bytes(masked) + h + b"\xbc", "big")


def pss_encode(key: RSAKey, alg: str, data: str, counter: int) -> int:
    sha = "sha" + alg[2:]
    salt = hashlib.new(sha, b"iam4d-salt-%d" % counter).digest()  # salt length = hash length
    return emsa_pss(data.encode(), sha, key.n.bit_length() - 1, salt)


def search(make, limit=10000):
    """First non-None result of make(counter)."""
    for counter in range(limit):
        result = make(counter)
        if result is not None:
            return result
    raise RuntimeError("search limit reached")


def local_vectors(a2: RSAKey):
    """Returns (valid vectors with a leading zero signature byte, RSA key vectors)."""
    rng = random.Random(20260928)
    big = RSAKey([random_prime(rng, 2048, (3, 65537, E64)) for _ in range(2)])
    huge = RSAKey([random_prime(rng, 512, (65537,)) for _ in range(33)])
    assert big.n.bit_length() == 4096 and huge.n.bit_length() > 16384

    def leading_zero_rs(counter):
        data = signing_input("RS256", ',"n":%d' % counter)
        sig = a2.private_op(emsa_pkcs1(data.encode(), "sha256", a2.k), 65537)
        return (data, sig) if sig[0] == 0 else None

    def leading_zero_ps(counter):
        data = signing_input("PS256")
        sig = a2.private_op(pss_encode(a2, "PS256", data, counter), 65537)
        return (data, sig) if sig[0] == 0 else None

    leading = []
    for alg, make in (("RS256", leading_zero_rs), ("PS256", leading_zero_ps)):
        data, sig = search(make)
        leading.append(("Leading zero", alg, a2.jwk(65537), data, b64url(sig)))

    # (source, alg, key, e, signing input, signature, valid)
    checks = []

    def add(source, alg, key, e, data, sig, valid):
        checks.append((source, alg, key.jwk(e), data, b64url(sig), valid, key.n.bit_length()))

    def pkcs1(key, alg, e, extra=""):
        data = signing_input(alg, extra)
        return data, key.private_op(emsa_pkcs1(data.encode(), "sha" + alg[2:], key.k), e)

    # e = 1: the signature is the encoded message itself
    data = signing_input("RS256")
    add("e = 1", "RS256", a2, 1, data, emsa_pkcs1(data.encode(), "sha256", a2.k).to_bytes(a2.k, "big"), False)
    data = signing_input("PS256")
    add("e = 1", "PS256", a2, 1, data, pss_encode(a2, "PS256", data, 0).to_bytes(a2.k, "big"), False)

    # e = 2: square root of the encoded message
    def even_rs(counter):
        data = signing_input("RS256", ',"n":%d' % counter)
        sig = a2.sqrt(emsa_pkcs1(data.encode(), "sha256", a2.k))
        return None if sig is None else (data, sig)

    def even_ps(counter):
        data = signing_input("PS256")
        sig = a2.sqrt(pss_encode(a2, "PS256", data, counter))
        return None if sig is None else (data, sig)

    for alg, make in (("RS256", even_rs), ("PS256", even_ps)):
        data, sig = search(make)
        add("e = 2", alg, a2, 2, data, sig, False)

    # s^(e + k * phi(n)) = s^e mod n: same signature, larger exponent
    data, sig = pkcs1(a2, "RS256", 65537)
    add("n 2048 bits, e = 65537 + phi(n) < n", "RS256", a2, 65537 + a2.phi, data, sig, True)
    add("e = 65537 + 2 * phi(n) >= n", "RS256", a2, 65537 + 2 * a2.phi, data, sig, False)

    data, sig = pkcs1(big, "RS512", 3)
    add("n 4096 bits, e = 3", "RS512", big, 3, data, sig, True)
    data, sig = pkcs1(big, "RS512", E64)
    add("n 4096 bits, e = 2^64 - 59", "RS512", big, E64, data, sig, True)
    data, sig = pkcs1(big, "RS512", 65537)
    add("n 4096 bits, e = 65537 + phi(n) > 64 bits", "RS512", big, 65537 + big.phi, data, sig, False)

    data, sig = pkcs1(huge, "RS256", 65537)
    add("n %d bits" % huge.n.bit_length(), "RS256", huge, 65537, data, sig, False)

    # Generated after the keys above: their vectors do not change
    small = RSAKey([random_prime(rng, 512, (65537,)) for _ in range(2)])
    short = RSAKey([random_prime(rng, 1024, (65537,)), random_prime(rng, 1023, (65537,))])
    large = RSAKey([random_prime(rng, 512, (65537,)) for _ in range(18)])
    tms_max = RSAKey([random_prime(rng, 512, (65537,)) for _ in range(16)])
    assert [k.n.bit_length() for k in (small, short, large, tms_max)] == [1024, 2047, 9216, 8192]

    # Below the 2048-bit minimum (RFC 7518 3.3, 4.2); TMS verifies n up to 8192 bits
    for key, valid in ((small, False), (short, False), (large, True), (tms_max, True)):
        for alg in ("RS256", "PS256"):
            if alg == "RS256":
                data, sig = pkcs1(key, alg, 65537)
            else:
                data = signing_input(alg)
                sig = key.private_op(pss_encode(key, alg, data, 0), 65537)
            add("n %d bits" % key.n.bit_length(), alg, key, 65537, data, sig, valid)

    # Generated last: the vectors above do not change. 257 bytes, padded by TMS to 384
    odd = RSAKey([random_prime(rng, 1028, (65537,)) for _ in range(2)])
    assert odd.n.bit_length() == 2056
    for alg in ("RS256", "PS256"):
        if alg == "RS256":
            data, sig = pkcs1(odd, alg, 65537)
        else:
            data = signing_input(alg)
            sig = odd.private_op(pss_encode(odd, alg, data, 0), 65537)
        add("n 2056 bits", alg, odd, 65537, data, sig, True)

    return leading, checks


# --- AES-256-GCM (Go crypto/cipher gcm_test.go) ------------------------------

GCM_VECTORS = [
    # key, nonce, plaintext, aad, ciphertext || tag
    ("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "54cc7dc2c37ec006bcc6d1da",
     "007c5e5b3e59df24a7c355584fc1518d",
     "",
     "d50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197"),
    ("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "e1934f5db57cc983e6b180e7",
     "73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490c2c6f6166f4a59431e182663fcaea05a",
     "0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8",
     "fc1ae2b5dcd2c4176c3f538b4c3cc21197f79e608cc3730167936382e4b1e5a7b75ae1678bcebd876705477eb0e0fdbbcda92fb9a0dc58c8d8f84fb590e0422e6077ef"),
]


# --- Pascal output ----------------------------------------------------------

def pas_str(value: str, indent: str) -> str:
    value = value.replace("'", "''")
    chunks = [value[i:i + 100] for i in range(0, len(value), 100)] or [""]
    return (" +\n" + indent).join("'%s'" % c for c in chunks)


def write_unit(jws, rsa_checks, gcm):
    ind = " " * 6
    out = [
        "unit CryptoTestVectorsU;",
        "",
        "// Generated by gen_vectors.py - do not edit.",
        "",
        "interface",
        "",
        "type",
        "  TJWSVector = record",
        "    Source: string;",
        "    Alg: string;",
        "    JWK: string;",
        "    SigningInput: string;",
        "    Signature: string; // Base64URL",
        "  end;",
        "",
        "  // Signature valid for the key math; Valid: whether the key must be accepted (default settings)",
        "  TRSAKeyVector = record",
        "    Source: string;",
        "    Alg: string;",
        "    JWK: string;",
        "    SigningInput: string;",
        "    Signature: string; // Base64URL",
        "    Valid: Boolean;",
        "    Bits: Integer;     // modulus size",
        "  end;",
        "",
        "  TGCMVector = record",
        "    Key: string;       // hex",
        "    Nonce: string;     // hex",
        "    Plaintext: string; // hex",
        "    AAD: string;       // hex",
        "    Sealed: string;    // hex, ciphertext || tag",
        "  end;",
        "",
        "const",
        "  JWS_VECTORS: array[0..%d] of TJWSVector = (" % (len(jws) - 1),
    ]
    rows = []
    for src, alg, jwk, data, sig in jws:
        rows.append("    (Source: %s;\n     Alg: '%s';\n     JWK: %s;\n     SigningInput: %s;\n     Signature: %s)"
                    % (pas_str(src, ind), alg, pas_str(jwk, ind), pas_str(data, ind), pas_str(sig, ind)))
    out.append(",\n".join(rows))
    out += ["  );", "", "  RSA_KEY_VECTORS: array[0..%d] of TRSAKeyVector = (" % (len(rsa_checks) - 1)]
    rows = []
    for src, alg, jwk, data, sig, valid, bits in rsa_checks:
        rows.append("    (Source: %s;\n     Alg: '%s';\n     JWK: %s;\n     SigningInput: %s;\n     Signature: %s;\n"
                    "     Valid: %s;\n     Bits: %d)"
                    % (pas_str(src, ind), alg, pas_str(jwk, ind), pas_str(data, ind), pas_str(sig, ind),
                       "True" if valid else "False", bits))
    out.append(",\n".join(rows))
    out += ["  );", "", "  GCM_VECTORS: array[0..%d] of TGCMVector = (" % (len(gcm) - 1)]
    rows = []
    for key, nonce, pt, aad, sealed in gcm:
        rows.append("    (Key: %s;\n     Nonce: %s;\n     Plaintext: %s;\n     AAD: %s;\n     Sealed: %s)"
                    % (pas_str(key, ind), pas_str(nonce, ind), pas_str(pt, ind), pas_str(aad, ind), pas_str(sealed, ind)))
    out.append(",\n".join(rows))
    out += ["  );", "", "implementation", "", "end.", ""]
    with open(OUT_FILE, "w", newline="\r\n") as f:
        f.write("\n".join(out))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    rfc, a2_key = rfc_vectors()
    leading, rsa_checks = local_vectors(a2_key)
    jws = rfc + openssl_vectors(sys.argv[1]) + leading
    write_unit(jws, rsa_checks, GCM_VECTORS)
    print("%d JWS vectors, %d RSA key vectors, %d GCM vectors -> %s"
          % (len(jws), len(rsa_checks), len(GCM_VECTORS), OUT_FILE))


if __name__ == "__main__":
    main()
