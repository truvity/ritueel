#!/usr/bin/env python3
"""Generate the hand-off test vectors of version 1 into testdata/hand-off/v1/.

Test fixtures only. Every key here is a throw-away software key made by this script;
its private half is never written to disk, so the output holds public material only:
CSRs, certificates, public subkey packets, signatures and JSON files. The attestation
hierarchy is a made-up "Example Test" hierarchy and not the maker's. A second run makes
different bytes (ECDSA is randomised), so the committed files are the fixtures and this
script is the record of how they were made.

Made with Python 3.13 and cryptography 46.0.5.

usage: generate.py OUTDIR
"""
import base64, datetime as dt, hashlib, json, os, secrets, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

OUT = sys.argv[1]
UTC = dt.timezone.utc
CLOCK = dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)   # the ceremony time used by every vector
UNTIL = dt.datetime(2027, 12, 15, 12, 0, 0, tzinfo=UTC)   # 13 calendar months later
SEQUENCE = 7
DER, PEM = serialization.Encoding.DER, serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
HOST = "example.org"


def w(path, data):
    path = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def wj(path, obj):
    w(path, json.dumps(obj, indent=2) + "\n")


b64 = lambda b: base64.b64encode(b).decode()
sha = lambda b: hashlib.sha256(b).hexdigest()
spki = lambda pub: pub.public_bytes(DER, SPKI)
ts = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")


def name(cn, o="acme"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ski(pub):   # RFC 7093, method 1: the leftmost 160 bits of the SHA-256 of the key bits (EC keys here)
    return hashlib.sha256(pub.public_bytes(*POINT)).digest()[:20]


def ec384():
    return ec.generate_private_key(ec.SECP384R1())


# ---------------------------------------------------------------- X.509 pieces
def ca_cert(subject, key, issuer_name, issuer_key, nb, na, pathlen, issuer_pub=None, extra=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(int.from_bytes(secrets.token_bytes(19), "big") | 1 << 150).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(x509.SubjectKeyIdentifier(ski(key.public_key())), critical=False))
    for e, crit in extra:
        b = b.add_extension(e, critical=crit)
    if issuer_pub is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier(ski(issuer_pub), None, None), critical=False)
    return b.sign(issuer_key, hashes.SHA384() if isinstance(issuer_key, ec.EllipticCurvePrivateKey) else hashes.SHA256())


KU_CA = x509.KeyUsage(False, False, False, False, False, True, True, False, False)


def root(cn):
    k = ec384()
    n = name(cn)
    c = ca_cert(n, k, n, k, dt.datetime(2026, 1, 1, tzinfo=UTC), dt.datetime(2036, 1, 1, tzinfo=UTC), None,
                extra=[(KU_CA, True)])
    return k, c


# the certifier's test roots (what ritueel would hold): A is in the root list, B is not (it is the "untrusted issuer")
ROOT_A_KEY, ROOT_A = root("Example Test Root A (TEST ONLY)")
ROOT_B_KEY, ROOT_B = root("Example Test Root B (TEST ONLY)")
w("pki/test-root-a.pem", ROOT_A.public_bytes(PEM))

# the made-up attestation hierarchy: root -> intermediate -> per-card key -> per-slot certificate
ATT_ROOT_KEY, ATT_ROOT = root("Example Test Attestation Root (TEST ONLY)")
ATT_INT_KEY = ec384()
ATT_INT = ca_cert(name("Example Test Attestation Intermediate"), ATT_INT_KEY, ATT_ROOT.subject, ATT_ROOT_KEY,
                  dt.datetime(2025, 1, 1, tzinfo=UTC), dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), 1,
                  ATT_ROOT_KEY.public_key(), extra=[(KU_CA, True)])
w("pki/test-attestation-root.pem", ATT_ROOT.public_bytes(PEM))
w("pki/test-attestation-intermediate.pem", ATT_INT.public_bytes(PEM))
OTHER_ROOT_KEY, OTHER_ROOT = root("Example Other Attestation Root (TEST ONLY)")   # never pinned


class Card:
    """A made-up token: a per-card attestation key (RSA 2048, like the real one) certified by the test intermediate."""

    def __init__(self, int_key, int_cert, int_pub, cn="Example Test PIV Attestation"):
        self.key = rsa.generate_private_key(65537, 2048)
        self.cert = (x509.CertificateBuilder().subject_name(name(cn, "Example Test")).issuer_name(int_cert.subject)
                     .public_key(self.key.public_key()).serial_number(secrets.randbits(63) | 1 << 62)
                     .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(int_key, hashes.SHA384()))
        self.int_chain = [int_cert]

    def slot_cert(self, pub, slot="9c", firmware=bytes([5, 8, 0]), serial=12345678, policy=bytes([2, 1]), form=bytes([2])):
        """The certificate a token makes for a key born in a slot. The OIDs and encodings are the ones measured on a real
        token on 2026-10-31 (firmware 5.8.0): raw bytes for firmware, policy and form factor, a DER INTEGER for the serial."""
        base = "1.3.6.1.4.1.41482.3."
        sn = serial.to_bytes((serial.bit_length() + 8) // 8, "big")
        ext = [("3", firmware), ("7", b"\x02" + bytes([len(sn)]) + sn), ("8", policy), ("9", form)]
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey PIV Attestation {slot}")]))
             .issuer_name(self.cert.subject).public_key(pub).serial_number(secrets.randbits(63) | 1 << 62)
             .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)))
        for o, v in ext:
            b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(base + o), v), critical=False)
        return b.sign(self.key, hashes.SHA256())


CARD = Card(ATT_INT_KEY, ATT_INT, ATT_INT_KEY.public_key())
OTHER_INT_KEY = ec384()
OTHER_INT = ca_cert(name("Example Other Attestation Intermediate"), OTHER_INT_KEY, OTHER_ROOT.subject, OTHER_ROOT_KEY,
                    dt.datetime(2025, 1, 1, tzinfo=UTC), dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), 1,
                    OTHER_ROOT_KEY.public_key(), extra=[(KU_CA, True)])
OTHER_CARD = Card(OTHER_INT_KEY, OTHER_INT, OTHER_INT_KEY.public_key())


def attestation(pub, card=CARD, **kw):
    """The evidence member of a proof for a token: the slot certificate, then the card's own certificate (leaf first)."""
    return {"attestation": [b64(card.slot_cert(pub, **kw).public_bytes(DER)), b64(card.cert.public_bytes(DER))]}


ARN = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
ROLE = "arn:aws:iam::123456789012:role/example-key-holder"
ADMIN = "arn:aws:iam::123456789012:role/example-key-admin"


def kms_stub(pub, two_actors=False, spec="ECC_NIST_P384"):
    stmts = [{"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": ADMIN},
              "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"], "Resource": "*"},
             {"Sid": "Use", "Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*"}]
    if two_actors:
        stmts.append({"Sid": "Use2", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/example-other"},
                      "Action": "kms:Sign", "Resource": "*"})
    return {"describe_key": {"KeyMetadata": {"Arn": ARN, "KeyId": ARN.rsplit("/", 1)[1], "KeySpec": spec, "KeyUsage": "SIGN_VERIFY",
                                              "KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "MultiRegion": False,
                                              "SigningAlgorithms": ["ECDSA_SHA_384"]}},
            "get_public_key": {"KeyId": ARN, "KeySpec": spec, "PublicKey": b64(spki(pub))},
            "get_key_policy": {"PolicyName": "default", "Policy": json.dumps({"Version": "2012-10-17", "Statement": stmts})}}


# ---------------------------------------------------------------- CSR and certificate
def make_csr(key, cn="acme board-1 intermediate CA", nc=("%s" % HOST,), pathlen=0, hash_=hashes.SHA384()):
    b = (x509.CertificateSigningRequestBuilder().subject_name(name(cn))
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(KU_CA, critical=True))
    if nc:
        b = b.add_extension(x509.NameConstraints([x509.UniformResourceIdentifier(h) for h in nc], None), critical=True)
    return b.sign(key, hash_)


def issue(csr, issuer_key=ROOT_A_KEY, issuer=ROOT_A, nb=CLOCK, na=UNTIL, pubkey=None, pathlen=None):
    """What a conforming certifier issues for a CSR (the profile of the reference page): exactly what was asked, plus times."""
    exts = {type(e.value): e for e in csr.extensions}
    bc = exts[x509.BasicConstraints].value
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer.subject).public_key(pubkey or csr.public_key())
         .serial_number(int.from_bytes(secrets.token_bytes(19), "big") | 1 << 150).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=True, path_length=bc.path_length if pathlen is None else pathlen), critical=True)
         .add_extension(exts[x509.KeyUsage].value, critical=True))
    if x509.NameConstraints in exts:
        b = b.add_extension(exts[x509.NameConstraints].value, critical=True)
    b = (b.add_extension(x509.SubjectKeyIdentifier(ski(pubkey or csr.public_key())), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier(ski(issuer.public_key()), None, None), critical=False))
    return b.sign(issuer_key, hashes.SHA384())


def tamper_csr(csr):
    d = bytearray(csr.public_bytes(DER))
    d[-1] ^= 0x01
    return bytes(d)


def pem_csr(der):
    return ("-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(b64(der)[i:i + 64] for i in range(0, len(b64(der)), 64))
            + "\n-----END CERTIFICATE REQUEST-----\n").encode()


# ---------------------------------------------------------------- OpenPGP pieces (v4 packets, RFC 9580)
T_PRIMARY = int(dt.datetime(2026, 1, 1, tzinfo=UTC).timestamp())
T_SUBKEY = int(dt.datetime(2026, 10, 20, tzinfo=UTC).timestamp())
T_CEREMONY = int(CLOCK.timestamp())
T_UNTIL = int(UNTIL.timestamp())
OID_P384 = bytes.fromhex("2b81040022")
OID_ED25519 = bytes.fromhex("2b06010401da470f01")


def pkt(tag, body):
    return bytes([0xC0 | tag, 255]) + struct.pack(">I", len(body)) + body


def mpi(b):
    b = b.lstrip(b"\0")
    return struct.pack(">H", (len(b) - 1) * 8 + b[0].bit_length()) + b


def sub(t, d, crit=False):
    n = len(d) + 1
    ln = bytes([n]) if n < 192 else bytes([((n - 192) >> 8) + 192, (n - 192) & 255])
    return ln + bytes([t | (0x80 if crit else 0)]) + d


def keyhash(body):
    return b"\x99" + struct.pack(">H", len(body)) + body


def fpr(body):
    return hashlib.sha1(keyhash(body)).digest()


class PgpKey:
    """A v4 OpenPGP key packet. alg 19 = ECDSA P-384; alg 22 = EdDSALegacy (Ed25519), used only to make a refused vector."""

    def __init__(self, created, alg=19):
        self.alg, self.created = alg, created
        if alg == 19:
            self.priv = ec384()
            self.body = b"\x04" + struct.pack(">I", created) + b"\x13" + bytes([len(OID_P384)]) + OID_P384 + mpi(self.priv.public_key().public_bytes(*POINT))
            self.pub = self.priv.public_key()
        else:
            self.priv = ed25519.Ed25519PrivateKey.generate()
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.body = b"\x04" + struct.pack(">I", created) + b"\x16" + bytes([len(OID_ED25519)]) + OID_ED25519 + mpi(b"\x40" + raw)
            self.pub = self.priv.public_key()
        self.fpr = fpr(self.body)

    def sign_digest(self, d):   # returns the two MPIs of a signature
        if self.alg == 19:
            r, s = decode_dss_signature(self.priv.sign(d, ec.ECDSA(Prehashed(hashes.SHA384()))))
            return mpi(r.to_bytes(48, "big")) + mpi(s.to_bytes(48, "big"))
        raise NotImplementedError


def sig_body(stype, hashed, unhashed, data, signer, alg=19):
    head = b"\x04" + bytes([stype, alg, 9]) + struct.pack(">H", len(hashed)) + hashed   # 9 = SHA-384
    d = hashlib.sha384(data + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
    return head + struct.pack(">H", len(unhashed)) + unhashed + d[:2] + signer(d)


def issuer(k):
    return sub(33, b"\x04" + k.fpr), sub(16, k.fpr[-8:])   # issuer fingerprint (hashed), key id (unhashed)


def primary_cert(k, uid):
    """The public certificate of a test primary: key, user id, self-certification (certify only, expires in ten years)."""
    ih, iu = issuer(k)
    hashed = sub(2, struct.pack(">I", T_PRIMARY + 1)) + sub(27, b"\x01") + sub(9, struct.pack(">I", 10 * 365 * 86400), True) + ih
    cert = sig_body(0x13, hashed, iu, keyhash(k.body) + b"\xb4" + struct.pack(">I", len(uid)) + uid, k.sign_digest)
    return pkt(6, k.body) + pkt(13, uid) + pkt(2, cert)


def backsig(sk, primary, stype=0x19, creation=T_SUBKEY + 60):
    """The back-signature: made by the subkey over the primary and the subkey (RFC 9580, section 5.2.1.9)."""
    ih, iu = issuer(sk)
    signer = sk.sign_digest
    return sig_body(stype, sub(2, struct.pack(">I", creation)) + ih, iu, keyhash(primary.body) + keyhash(sk.body), signer)


def binding(sk, primary, back, until=T_UNTIL, embed=True, when=T_CEREMONY):
    """The subkey binding the certifier makes: signing capability only, expiry set so the subkey ends at 'until', the
    back-signature embedded in the unhashed area."""
    ih, iu = issuer(primary)
    hashed = sub(2, struct.pack(">I", when)) + sub(27, b"\x02") + sub(9, struct.pack(">I", until - sk.created), True) + ih
    unhashed = iu + (sub(32, back) if embed else b"")
    return sig_body(0x18, hashed, unhashed, keyhash(primary.body) + keyhash(sk.body), primary.sign_digest)


PRIM_A, PRIM_B = PgpKey(T_PRIMARY), PgpKey(T_PRIMARY)
CERT_A = primary_cert(PRIM_A, b"Example Test Release Root A <release-a@example.org>")
CERT_B = primary_cert(PRIM_B, b"Example Test Release Root B <release-b@example.org>")
w("pki/test-primary-a.pgp", CERT_A)
w("pki/test-primary-b.pgp", CERT_B)

# ---------------------------------------------------------------- cases
cases, responses = [], []
SUBKEYS = {}   # response id -> subkey, for the optional self-check below


def hexfp(k):
    return k.fpr.hex()


def proof(typ, request_bytes, store, evidence=None, version=1, **extra):
    p = {"handoff": version, "type": typ, "request_sha256": sha(request_bytes), "store": store}
    p.update(extra)
    if evidence is not None:
        p["evidence"] = evidence
    return p


def add(case, typ, cfg, expect, reason=None, files=(), stub=None):
    c = {"id": case, "type": typ, "config": cfg, "files": list(files), "expect": expect}
    if reason:
        c["reason"] = reason
    if stub:
        c["kms_stub"] = stub
    cases.append(c)


def x509_case(case, key=None, store="yubikey-piv", cfg="production", expect="refuse", reason=None, csr=None, csr_der=None,
              ev=None, version=1, extra_member=None, digest_of=None, stub=None, stub_pub=None, evidence_pub=None, **att):
    key = key or ec384()
    csr = csr or make_csr(key)
    der = csr_der or csr.public_bytes(DER)
    if store == "yubikey-piv":
        evidence = ev or attestation(evidence_pub or key.public_key(), **att)
    elif store == "aws-kms":
        evidence = {"key_arn": ARN, "public_key": b64(spki(evidence_pub or key.public_key()))}
    else:
        evidence = None
    p = proof("x509-intermediate", digest_of or der, store, evidence, version)
    if extra_member:
        p["unexpected"] = extra_member
    w(f"requests/{case}.csr.pem", pem_csr(der))
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.csr.pem", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "x509-intermediate", cfg, expect, reason, files, st)
    return csr, key


def x509_response(case, request_case, cert, expect, reason=None, csr=None):
    w(f"responses/{case}.chain.pem", cert.public_bytes(PEM))
    chain = f"responses/{case}.chain.pem"
    chain_bytes = cert.public_bytes(PEM)
    res = {"handoff": 1, "type": "x509-intermediate", "request_sha256": sha(csr.public_bytes(DER)), "outcome": "issued",
           "artifacts": [{"name": f"{case}.chain.pem", "sha256": sha(chain_bytes)}], "valid_from": ts(cert.not_valid_before_utc),
           "valid_until": ts(cert.not_valid_after_utc), "issuer": sha(ROOT_A.public_key().public_bytes(DER, SPKI)), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "x509-intermediate", "request": request_case, "files": [chain, f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


# ---- X.509 requests
csr, key = x509_case("x509-piv-valid", expect="accept")
x509_response("x509-piv-valid", "x509-piv-valid", issue(csr), "install", csr=csr)
k = ec384(); c = make_csr(k)
x509_case("x509-kms-valid", key=k, csr=c, store="aws-kms", expect="accept", stub=kms_stub(k.public_key()))
x509_response("x509-kms-valid", "x509-kms-valid", issue(c), "install", csr=c)
k = ec384(); c = make_csr(k)
x509_case("x509-software-valid", key=k, csr=c, store="software", cfg="development", expect="accept")
x509_response("x509-software-valid", "x509-software-valid", issue(c), "install", csr=c)
# the same files under the production configuration: software keys are not allowed there
src = cases[-1]
cases.append({"id": "x509-software-in-production", "type": "x509-intermediate", "config": "production", "files": src["files"],
              "expect": "refuse", "reason": "store-not-allowed"})

k = ec384(); c = make_csr(k)
x509_case("x509-csr-bad-signature", key=k, csr=c, csr_der=tamper_csr(c), cfg="development", store="software", reason="possession-invalid")
k = ec384(); x509_case("x509-p256", key=ec.generate_private_key(ec.SECP256R1()), cfg="development", store="software", reason="algorithm-unsupported")
x509_case("x509-version-2", version=2, reason="version-unsupported")
k = ec384(); c = make_csr(k); other = make_csr(ec384(), cn="another request")
x509_case("x509-request-mismatch", key=k, csr=c, digest_of=other.public_bytes(DER), reason="request-mismatch")
x509_case("x509-unknown-member", extra_member=True, reason="malformed")
k = ec384(); x509_case("x509-piv-key-mismatch", key=k, evidence_pub=ec384().public_key(), reason="key-mismatch")
k = ec384(); x509_case("x509-piv-untrusted-chain", key=k, ev=attestation(k.public_key(), card=OTHER_CARD), reason="proof-invalid")
x509_case("x509-piv-pin-never", policy=bytes([1, 1]), reason="policy")
x509_case("x509-piv-old-firmware", firmware=bytes([5, 4, 3]), reason="policy")
k = ec384(); x509_case("x509-no-name-constraints", key=k, csr=make_csr(k, nc=()), reason="policy")
k = ec384(); x509_case("x509-name-constraint-outside", key=k, csr=make_csr(k, nc=("other.example",)), reason="policy")
k = ec384(); x509_case("x509-kms-key-mismatch", key=k, store="aws-kms", evidence_pub=ec384().public_key(),
                       stub=kms_stub(k.public_key()), reason="key-mismatch")
k = ec384(); x509_case("x509-kms-two-actors", key=k, store="aws-kms", stub=kms_stub(k.public_key(), two_actors=True), reason="policy")

# ---- X.509 responses a requester must refuse (they answer the request x509-response-request)
k = ec384(); c = make_csr(k)
x509_case("x509-response-request", key=k, csr=c, store="software", cfg="development", expect="accept")
base = "x509-response-request"
x509_response("x509-response-wrong-key", base, issue(c, pubkey=ec384().public_key()), "refuse", "key-mismatch", csr=c)
x509_response("x509-response-pathlen-1", base, issue(c, pathlen=1), "refuse", "profile", csr=c)
x509_response("x509-response-expired", base, issue(c, nb=dt.datetime(2025, 9, 1, tzinfo=UTC), na=dt.datetime(2026, 10, 1, tzinfo=UTC)), "refuse", "validity", csr=c)
x509_response("x509-response-untrusted-issuer", base, issue(c, issuer_key=ROOT_B_KEY, issuer=ROOT_B), "refuse", "issuer", csr=c)


# ---- OpenPGP requests
def pgp_case(case, store="yubikey-piv", cfg="production", expect="refuse", reason=None, sk=None, primary=PRIM_A, back=None,
             version=1, stub=False, evidence_pub=None, proof_primary=None, omit_back=False, req_override=None, **att):
    sk = sk or PgpKey(T_SUBKEY)
    back = back if back is not None else backsig(sk, primary)
    req = req_override or (pkt(14, sk.body) + (b"" if omit_back else pkt(2, back)))
    pub = evidence_pub or sk.pub
    if store == "yubikey-piv":
        evidence = attestation(pub, **att)
    elif store == "aws-kms":
        evidence = {"key_arn": ARN, "public_key": b64(spki(pub))}
    else:
        evidence = None
    p = proof("openpgp-subkey", req, store, evidence, version, primary=proof_primary or hexfp(primary), capabilities=["sign"])
    w(f"requests/{case}.subkey.pgp", req)
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.subkey.pgp", f"requests/{case}.proof.json"]
    st = None
    if stub:
        st = f"requests/{case}.kms-stub.json"
        wj(st, kms_stub(sk.pub))
    add(case, "openpgp-subkey", cfg, expect, reason, files, st)
    return sk, back


def pgp_response(case, request_case, sk, back, primary=PRIM_A, expect="install", reason=None, cert_override=None, until=T_UNTIL, embed=True):
    body = cert_override or (pkt(14, sk.body) + pkt(2, binding(sk, primary, back, until=until, embed=embed)))
    w(f"responses/{case}.bound.pgp", body)
    SUBKEYS[case] = sk
    res = {"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha(pkt(14, sk.body) + pkt(2, back)), "outcome": "issued",
           "artifacts": [{"name": f"{case}.bound.pgp", "sha256": sha(body)}], "valid_from": ts(CLOCK), "valid_until": ts(dt.datetime.fromtimestamp(until, UTC)),
           "issuer": hexfp(primary), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "openpgp-subkey", "request": request_case, "files": [f"responses/{case}.bound.pgp", f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


sk, back = pgp_case("pgp-piv-valid", expect="accept")
pgp_response("pgp-piv-valid", "pgp-piv-valid", sk, back)
sk, back = pgp_case("pgp-kms-valid", store="aws-kms", expect="accept", stub=True)
pgp_response("pgp-kms-valid", "pgp-kms-valid", sk, back)
sk, back = pgp_case("pgp-software-valid", store="software", cfg="development", expect="accept")
pgp_response("pgp-software-valid", "pgp-software-valid", sk, back)
pgp_case("pgp-backsig-missing", omit_back=True, reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-primary", sk=sk, back=backsig(sk, PRIM_B), reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-type", sk=sk, back=backsig(sk, PRIM_A, stype=0x18), reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
bs = bytearray(backsig(sk, PRIM_A)); bs[-1] ^= 1
pgp_case("pgp-backsig-tampered", sk=sk, back=bytes(bs), reason="possession-invalid")
pgp_case("pgp-version-2", version=2, reason="version-unsupported")
pgp_case("pgp-unknown-primary", proof_primary="0" * 39 + "1", reason="unknown-primary")
pgp_case("pgp-piv-key-mismatch", evidence_pub=ec384().public_key(), reason="key-mismatch")
# an Ed25519 subkey: the request is well formed and signed, the algorithm is not one of version 1
esk = PgpKey(T_SUBKEY, alg=22)
ih, iu = issuer(esk)
hashed = sub(2, struct.pack(">I", T_SUBKEY + 60)) + ih
head = b"\x04" + bytes([0x19, 22, 9]) + struct.pack(">H", len(hashed)) + hashed
dg = hashlib.sha384(keyhash(PRIM_A.body) + keyhash(esk.body) + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
sg = esk.priv.sign(dg)
eback = head + struct.pack(">H", len(iu)) + iu + dg[:2] + mpi(sg[:32]) + mpi(sg[32:])
pgp_case("pgp-ed25519", sk=esk, back=eback, store="software", cfg="development", reason="algorithm-unsupported")

# ---- OpenPGP responses a requester must refuse (they answer the request pgp-response-request)
sk = PgpKey(T_SUBKEY); back = backsig(sk, PRIM_A)
pgp_case("pgp-response-request", sk=sk, back=back, store="software", cfg="development", expect="accept")
pgp_response("pgp-response-no-backsig", "pgp-response-request", sk, back, embed=False, expect="refuse", reason="profile")
other = PgpKey(T_SUBKEY)
pgp_response("pgp-response-wrong-subkey", "pgp-response-request", other, backsig(other, PRIM_A), expect="refuse", reason="key-mismatch")
pgp_response("pgp-response-wrong-primary", "pgp-response-request", sk, back, primary=PRIM_B, expect="refuse", reason="issuer")
# the expiry is shorter than 12 months: a requester that expects about 13 months refuses it
pgp_response("pgp-response-short-expiry", "pgp-response-request", sk, back, until=T_CEREMONY + 60 * 86400, expect="refuse", reason="validity")

# ---- optional self-check material: with VERIFY_DIR set, write a detached signature by each response's subkey over a
# fixed text, so that an independent verifier (sqv) can be run on primary-cert + bound.pgp. Not part of the fixtures.
if os.environ.get("VERIFY_DIR"):
    for cid, sk in SUBKEYS.items():
        data = b"hand-off vector check\n"
        ih, iu = issuer(sk)
        sig = sig_body(0x00, sub(2, struct.pack(">I", T_CEREMONY + 3600)) + ih, iu, data, sk.sign_digest)
        os.makedirs(os.environ["VERIFY_DIR"], exist_ok=True)
        open(os.path.join(os.environ["VERIFY_DIR"], cid + ".sig"), "wb").write(pkt(2, sig))
    open(os.path.join(os.environ["VERIFY_DIR"], "data.txt"), "wb").write(b"hand-off vector check\n")

# ---- manifest
wj("manifest.json", {
    "handoff": 1,
    "clock": ts(CLOCK),
    "pinned": {
        "attestation_roots": ["pki/test-attestation-root.pem"],
        "attestation_intermediates": ["pki/test-attestation-intermediate.pem"],
        "root_list": {"x509": ["pki/test-root-a.pem"], "openpgp": ["pki/test-primary-a.pgp"]},
        "known_openpgp_primaries": ["pki/test-primary-a.pgp", "pki/test-primary-b.pgp"],
        "trust_sequence": SEQUENCE,
    },
    "configs": {
        "production": {"stores": ["yubikey-piv", "aws-kms"], "min_firmware": "5.7.0", "pin_policy": ["once", "always"],
                       "require_name_constraints": True, "permitted_uri_hosts": [HOST], "validity_months": 13},
        "development": {"stores": ["yubikey-piv", "aws-kms", "software"], "min_firmware": "5.7.0", "pin_policy": ["once", "always"],
                        "require_name_constraints": True, "permitted_uri_hosts": [HOST], "validity_months": 13},
    },
    "requests": cases,
    "responses": responses,
})
print("cases:", len(cases), "responses:", len(responses))
