#!/usr/bin/env python3
"""Generate the hand-off test vectors of version 1 into testdata/hand-off/v1/, the root list and CA
bundle vectors of version 1 into testdata/root-list/v1/, the SSH CA key list vectors into
testdata/ssh-ca-keys/v1/ and the CRL vectors into testdata/crl/v1/, from one test trust set.

Test fixtures only. Every key here is a throw-away software key made by this script;
its private half is never written to disk, so the output holds public material only:
CSRs, certificates, public subkey packets, signatures and JSON files. The attestation
hierarchy is a made-up "Example Test" hierarchy and not the maker's. A second run makes
different bytes (ECDSA is randomised), so the committed files are the fixtures and this
script is the record of how they were made.

The test trust set has two roots, A and B, as on two root cards: each has an X.509 root
and an OpenPGP primary, and both are active on the signed root list. A third root, Z, is
on no list; it makes the "untrusted issuer" and "unknown primary" cases. The roots follow the
root profile of docs/reference/directory.md, and the root lists and CA bundles that name them
follow docs/reference/root-list.md, the SSH CA key lists docs/reference/ssh-ca-key-list.md and the
CRLs docs/reference/crl.md. All four sets are made in one run because the lists and the CRLs are
signed by the same throw-away root keys that issue the hand-off answers.

Made with Python 3.14 and cryptography 46.0.5.

usage: generate.py HANDOFF_OUTDIR ROOTLIST_OUTDIR SSHCA_OUTDIR CRL_OUTDIR
"""
import base64, datetime as dt, hashlib, json, os, secrets, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

OUT = sys.argv[1]
RL_OUT = sys.argv[2]
SSH_OUT = sys.argv[3]
CRL_OUT = sys.argv[4]
UTC = dt.timezone.utc
CLOCK = dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)   # the ceremony time used by every vector
UNTIL = dt.datetime(2027, 12, 15, 12, 0, 0, tzinfo=UTC)   # 13 calendar months later
SEQUENCE = 7
DER, PEM = serialization.Encoding.DER, serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
HOST = "example.org"


def w(path, data, out=None):
    path = os.path.join(out or OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def wj(path, obj, out=None):
    w(path, json.dumps(obj, indent=2) + "\n", out)


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
    """A made-up maker's attestation root (not a ritueel root): ten years, with an organisation."""
    k = ec384()
    n = name(cn)
    c = ca_cert(n, k, n, k, dt.datetime(2026, 1, 1, tzinfo=UTC), dt.datetime(2036, 1, 1, tzinfo=UTC), None,
                extra=[(KU_CA, True)])
    return k, c


T_ROOTS = dt.datetime(2026, 1, 1, tzinfo=UTC)          # when the test roots were made (their `init`)
T_ROOTS_UNTIL = dt.datetime(2029, 1, 1, tzinfo=UTC)    # 36 calendar months later


def ritueel_root(label):
    """A ritueel test root in the root profile: self-signed, the subject one common name `<name> Root <label>`
    with ` (TEST ONLY)` for a test root, basic constraints critical with no path length, key usage critical
    keyCertSign and cRLSign, a subject key identifier, no authority key identifier, 36 months."""
    k = ec384()
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Example Test Root {label} (TEST ONLY)")])
    return k, ca_cert(n, k, n, k, T_ROOTS, T_ROOTS_UNTIL, None, extra=[(KU_CA, True)])


# the certifier's test roots (what ritueel would hold): A and B are on the root list, Z is not (the "untrusted issuer")
ROOT_A_KEY, ROOT_A = ritueel_root("A")
ROOT_B_KEY, ROOT_B = ritueel_root("B")
ROOT_Z_KEY, ROOT_Z = ritueel_root("Z")
w("pki/test-root-a.pem", ROOT_A.public_bytes(PEM))
w("pki/test-root-b.pem", ROOT_B.public_bytes(PEM))
w("pki/test-root-z.pem", ROOT_Z.public_bytes(PEM))

# the made-up attestation hierarchy: root -> intermediate -> per-card key -> per-key certificate. The PIV applet and the
# OpenPGP applet of a card have their own intermediates under one maker root, as on a real card.
ATT_ROOT_KEY, ATT_ROOT = root("Example Test Attestation Root (TEST ONLY)")


def att_intermediate(cn, parent_key, parent):
    k = ec384()
    c = ca_cert(name(cn), k, parent.subject, parent_key, dt.datetime(2025, 1, 1, tzinfo=UTC),
                dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), 1, parent_key.public_key(), extra=[(KU_CA, True)])
    return k, c


ATT_INT_KEY, ATT_INT = att_intermediate("Example Test PIV Attestation Intermediate", ATT_ROOT_KEY, ATT_ROOT)
OPGP_INT_KEY, OPGP_INT = att_intermediate("Example Test OPGP Attestation Intermediate", ATT_ROOT_KEY, ATT_ROOT)
w("pki/test-attestation-root.pem", ATT_ROOT.public_bytes(PEM))
w("pki/test-attestation-intermediate.pem", ATT_INT.public_bytes(PEM))
w("pki/test-opgp-attestation-intermediate.pem", OPGP_INT.public_bytes(PEM))
OTHER_ROOT_KEY, OTHER_ROOT = root("Example Other Attestation Root (TEST ONLY)")   # never pinned


class Card:
    """A made-up token: a per-card attestation key (RSA 2048, like the real one) certified by a test intermediate."""

    def __init__(self, int_key, int_cert, cn="Example Test PIV Attestation"):
        self.key = rsa.generate_private_key(65537, 2048)
        self.cert = (x509.CertificateBuilder().subject_name(name(cn, "Example Test")).issuer_name(int_cert.subject)
                     .public_key(self.key.public_key()).serial_number(secrets.randbits(63) | 1 << 62)
                     .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(int_key, hashes.SHA384()))

    def slot_cert(self, pub, slot="9c", firmware=bytes([5, 8, 0]), serial=12345678, policy=bytes([2, 1]), form=bytes([2])):
        """The certificate a token makes for a key born in a PIV slot. The OIDs and encodings are the ones measured on a
        real token on 2026-10-31 (firmware 5.8.0): raw bytes for firmware, policy and form factor, a DER INTEGER for the
        serial."""
        base = "1.3.6.1.4.1.41482.3."
        sn = serial.to_bytes((serial.bit_length() + 8) // 8, "big")
        ext = [("3", firmware), ("7", b"\x02" + bytes([len(sn)]) + sn), ("8", policy), ("9", form)]
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey PIV Attestation {slot}")]))
             .issuer_name(self.cert.subject).public_key(pub).serial_number(secrets.randbits(63) | 1 << 62)
             .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)))
        for o, v in ext:
            b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(base + o), v), critical=False)
        return b.sign(self.key, hashes.SHA256())

    def opgp_cert(self, pub, slot="SIG"):
        """The certificate a card's OpenPGP applet makes for a key it generated. The extensions under 1.3.6.1.4.1.41482.5
        are not specified by the contract yet, so this certificate carries none: a certifier records the key as attested
        and enforces no PIN or touch policy."""
        return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey OPGP Attestation {slot}")]))
                .issuer_name(self.cert.subject).public_key(pub).serial_number(secrets.randbits(63) | 1 << 62)
                .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
                .sign(self.key, hashes.SHA256()))


CARD = Card(ATT_INT_KEY, ATT_INT)
OPGP_CARD = Card(OPGP_INT_KEY, OPGP_INT, cn="Example Test OPGP Attestation")
OTHER_INT_KEY, OTHER_INT = att_intermediate("Example Other Attestation Intermediate", OTHER_ROOT_KEY, OTHER_ROOT)
OTHER_CARD = Card(OTHER_INT_KEY, OTHER_INT)
OTHER_OPGP_CARD = Card(OTHER_INT_KEY, OTHER_INT, cn="Example Other OPGP Attestation")


def attestation(pub, card=CARD, **kw):
    """The evidence member of a proof for a PIV key: the slot certificate, then the card's own certificate (leaf first)."""
    return {"attestation": [b64(card.slot_cert(pub, **kw).public_bytes(DER)), b64(card.cert.public_bytes(DER))]}


def opgp_attestation(pub, card=OPGP_CARD):
    """The evidence member of a proof for an OpenPGP-card key: the key's certificate, then the card's own (leaf first)."""
    return {"attestation": [b64(card.opgp_cert(pub).public_bytes(DER)), b64(card.cert.public_bytes(DER))]}


# The certifier's own account is 123456789012. A requester's key in another account (111122223333) is read through the
# read-only role the certifier's policy lists for that account; an account with no listed role (444455556666) is unreadable.
ARN = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
ARN_OTHER = "arn:aws:kms:eu-west-1:111122223333:key/66666666-7777-8888-9999-000000000000"
ARN_UNLISTED = "arn:aws:kms:eu-west-1:444455556666:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
READ_ROLE = "arn:aws:iam::111122223333:role/example-certifier-read"


def kms_stub(pub, arn=ARN, two_actors=False, spec="ECC_NIST_P384", via_role=None, denied=False):
    """The answers of DescribeKey, GetPublicKey and GetKeyPolicy that a test replays instead of calling AWS. via_role is
    the role the certifier must assume first (a key in another account); denied means every read is refused."""
    acct = arn.split(":")[4]
    if denied:
        err = {"error": "AccessDeniedException"}
        return {"describe_key": err, "get_public_key": err, "get_key_policy": err}
    role = f"arn:aws:iam::{acct}:role/example-key-holder"
    stmts = [{"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:role/example-key-admin"},
              "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"], "Resource": "*"},
             {"Sid": "Use", "Effect": "Allow", "Principal": {"AWS": role}, "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*"}]
    if via_role:
        stmts.append({"Sid": "CertifierRead", "Effect": "Allow", "Principal": {"AWS": via_role},
                      "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"], "Resource": "*"})
    if two_actors:
        stmts.append({"Sid": "Use2", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:role/example-other"},
                      "Action": "kms:Sign", "Resource": "*"})
    stub = {}
    if via_role:
        stub["assume_role"] = {"RoleArn": via_role}
    stub.update({"describe_key": {"KeyMetadata": {"Arn": arn, "KeyId": arn.rsplit("/", 1)[1], "KeySpec": spec, "KeyUsage": "SIGN_VERIFY",
                                                   "KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "MultiRegion": False,
                                                   "SigningAlgorithms": ["ECDSA_SHA_384"]}},
                 "get_public_key": {"KeyId": arn, "KeySpec": spec, "PublicKey": b64(spki(pub))},
                 "get_key_policy": {"PolicyName": "default", "Policy": json.dumps({"Version": "2012-10-17", "Statement": stmts})}})
    return stub


# ---------------------------------------------------------------- CSR and certificate
def make_csr(key, cn="acme example intermediate CA", nc=("%s" % HOST,), pathlen=0, hash_=hashes.SHA384()):
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
        sg = self.priv.sign(d)
        return mpi(sg[:32]) + mpi(sg[32:])


def sig_body(stype, hashed, unhashed, data, signer, alg=19):
    head = b"\x04" + bytes([stype, alg, 9]) + struct.pack(">H", len(hashed)) + hashed   # 9 = SHA-384
    d = hashlib.sha384(data + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
    return head + struct.pack(">H", len(unhashed)) + unhashed + d[:2] + signer(d)


def issuer(k):
    """Every signature carries both: the Issuer Fingerprint subpacket (33, hashed) and the Issuer Key ID subpacket
    (16, unhashed). gpg 2.2 refuses a v4 signature without the key ID."""
    return sub(33, b"\x04" + k.fpr), sub(16, k.fpr[-8:])


T_PRIMARY_UNTIL = int(T_ROOTS_UNTIL.timestamp())


def primary_cert(k, uid):
    """The public certificate of a test primary: key, the release identity, a positive certification (certify only,
    expiring 36 months after it was made, as the root profile says)."""
    ih, iu = issuer(k)
    hashed = sub(2, struct.pack(">I", T_PRIMARY + 1)) + sub(27, b"\x01") + sub(9, struct.pack(">I", T_PRIMARY_UNTIL - k.created), True) + ih
    cert = sig_body(0x13, hashed, iu, keyhash(k.body) + b"\xb4" + struct.pack(">I", len(uid)) + uid, k.sign_digest)
    return pkt(6, k.body) + pkt(13, uid) + pkt(2, cert)


def backsig(sk, primary, stype=0x19, creation=T_SUBKEY + 60, key_id=True):
    """The back-signature: made by the subkey over the primary and the subkey (RFC 9580, section 5.2.1.9)."""
    ih, iu = issuer(sk)
    return sig_body(stype, sub(2, struct.pack(">I", creation)) + ih, iu if key_id else b"",
                    keyhash(primary.body) + keyhash(sk.body), sk.sign_digest, alg=sk.alg)


def binding(sk, primary, back, until=T_UNTIL, embed=True, when=T_CEREMONY):
    """The subkey binding the certifier makes: signing capability only, expiry set so the subkey ends at 'until', the
    back-signature for this primary embedded in the unhashed area."""
    ih, iu = issuer(primary)
    hashed = sub(2, struct.pack(">I", when)) + sub(27, b"\x02") + sub(9, struct.pack(">I", until - sk.created), True) + ih
    unhashed = iu + (sub(32, back) if embed else b"")
    return sig_body(0x18, hashed, unhashed, keyhash(primary.body) + keyhash(sk.body), primary.sign_digest)


PRIM_A, PRIM_B, PRIM_Z = PgpKey(T_PRIMARY), PgpKey(T_PRIMARY), PgpKey(T_PRIMARY)
PRIMARY_CERTS = {lbl: primary_cert(k, f"Example Test Release Root {lbl} (TEST ONLY) <release@example.org>".encode())
                 for lbl, k in (("A", PRIM_A), ("B", PRIM_B), ("Z", PRIM_Z))}
for lbl in "ABZ":
    w(f"pki/test-primary-{lbl.lower()}.pgp", PRIMARY_CERTS[lbl])
ACTIVE = [PRIM_A, PRIM_B]   # the active primaries on the test root list, in its order

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


def evidence_for(store, pub, arn=ARN, att=None, card=None):
    if store == "piv":
        return attestation(pub, **({"card": card} if card else {}), **(att or {}))
    if store == "openpgp-card":
        return opgp_attestation(pub, **({"card": card} if card else {}))
    if store == "aws-kms":
        return {"key_arn": arn, "public_key": b64(spki(pub))}
    return None


def x509_case(case, key=None, store="piv", cfg="production", expect="refuse", reason=None, csr=None, csr_der=None,
              ev=None, version=1, extra_member=None, digest_of=None, stub=None, evidence_pub=None, arn=ARN, **att):
    key = key or ec384()
    csr = csr or make_csr(key)
    der = csr_der or csr.public_bytes(DER)
    evidence = ev or evidence_for(store, evidence_pub or key.public_key(), arn=arn, att=att)
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


def x509_response(case, request_case, cert, expect, reason=None, csr=None, issuer_cert=ROOT_A):
    path = f"responses/{case}.cert.pem"
    body = cert.public_bytes(PEM)
    w(path, body)
    res = {"handoff": 1, "type": "x509-intermediate", "request_sha256": sha(csr.public_bytes(DER)), "outcome": "issued",
           "artifacts": [{"name": f"{case}.cert.pem", "sha256": sha(body)}], "valid_from": ts(cert.not_valid_before_utc),
           "valid_until": ts(cert.not_valid_after_utc), "issuer": sha(issuer_cert.public_key().public_bytes(DER, SPKI)), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "x509-intermediate", "request": request_case, "files": [path, f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


# ---- X.509 requests
csr, key = x509_case("x509-piv-valid", expect="accept")
x509_response("x509-piv-valid", "x509-piv-valid", issue(csr), "install", csr=csr)
k = ec384(); c = make_csr(k)
x509_case("x509-kms-valid", key=k, csr=c, store="aws-kms", expect="accept", stub=kms_stub(k.public_key()))
x509_response("x509-kms-valid", "x509-kms-valid", issue(c), "install", csr=c)
# a key in another account: the certifier assumes the read-only role its policy lists for that account
k = ec384(); c = make_csr(k)
x509_case("x509-kms-cross-account", key=k, csr=c, store="aws-kms", arn=ARN_OTHER, expect="accept",
          stub=kms_stub(k.public_key(), arn=ARN_OTHER, via_role=READ_ROLE))
# a key in an account for which the policy lists no read role: the certifier cannot read it
k = ec384(); c = make_csr(k)
x509_case("x509-kms-cross-account-no-role", key=k, csr=c, store="aws-kms", arn=ARN_UNLISTED,
          stub=kms_stub(k.public_key(), arn=ARN_UNLISTED, denied=True), reason="proof-invalid")
k = ec384(); c = make_csr(k)
x509_case("x509-software-valid", key=k, csr=c, store="software", cfg="development", expect="accept")
x509_response("x509-software-valid", "x509-software-valid", issue(c), "install", csr=c)
# the same files under the production configuration: software keys are not allowed there
src = cases[-1]
cases.append({"id": "x509-software-in-production", "type": "x509-intermediate", "config": "production", "files": src["files"],
              "expect": "refuse", "reason": "store-not-allowed"})
# the same files again, passing every check, but the person at the ceremony declines the request (check 10)
cases.append({"id": "x509-software-declined", "type": "x509-intermediate", "config": "development", "files": src["files"],
              "confirmation": "declined", "expect": "refuse", "reason": "declined"})

k = ec384(); c = make_csr(k)
x509_case("x509-csr-bad-signature", key=k, csr=c, csr_der=tamper_csr(c), cfg="development", store="software", reason="possession-invalid")
x509_case("x509-p256", key=ec.generate_private_key(ec.SECP256R1()), cfg="development", store="software", reason="algorithm-unsupported")
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

# ---- X.509 answers to the request x509-response-request: one from the other root, and four a requester must refuse
k = ec384(); c = make_csr(k)
x509_case("x509-response-request", key=k, csr=c, store="software", cfg="development", expect="accept")
base = "x509-response-request"
x509_response("x509-response-other-root", base, issue(c, issuer_key=ROOT_B_KEY, issuer=ROOT_B), "install", csr=c, issuer_cert=ROOT_B)
x509_response("x509-response-wrong-key", base, issue(c, pubkey=ec384().public_key()), "refuse", "key-mismatch", csr=c)
x509_response("x509-response-pathlen-1", base, issue(c, pathlen=1), "refuse", "profile", csr=c)
x509_response("x509-response-expired", base, issue(c, nb=dt.datetime(2025, 9, 1, tzinfo=UTC), na=dt.datetime(2026, 10, 1, tzinfo=UTC)), "refuse", "validity", csr=c)
x509_response("x509-response-untrusted-issuer", base, issue(c, issuer_key=ROOT_Z_KEY, issuer=ROOT_Z), "refuse", "issuer", csr=c, issuer_cert=ROOT_Z)


# ---- OpenPGP requests: the subkey, then one back-signature for each primary in `primaries`, in that order
def pgp_case(case, store="piv", cfg="production", expect="refuse", reason=None, sk=None, primaries=None, backs=None,
             version=1, stub=None, evidence_pub=None, proof_primaries=None, card=None):
    sk = sk or PgpKey(T_SUBKEY)
    primaries = ACTIVE if primaries is None else primaries
    backs = [backsig(sk, p) for p in primaries] if backs is None else backs
    req = pkt(14, sk.body) + b"".join(pkt(2, b) for b in backs)
    evidence = evidence_for(store, evidence_pub or sk.pub, card=card)
    names = proof_primaries if proof_primaries is not None else [hexfp(p) for p in primaries]
    p = proof("openpgp-subkey", req, store, evidence, version, primaries=names, capabilities=["sign"])
    w(f"requests/{case}.subkey.pgp", req)
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.subkey.pgp", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "openpgp-subkey", cfg, expect, reason, files, st)
    return sk, dict(zip((hexfp(p) for p in primaries), backs)), req


def pgp_response(case, request_case, sk, backs, req, primary=PRIM_A, expect="install", reason=None, until=T_UNTIL, embed=True):
    back = backs.get(hexfp(primary)) or backsig(sk, primary)
    body = pkt(14, sk.body) + pkt(2, binding(sk, primary, back, until=until, embed=embed))
    w(f"responses/{case}.bound.pgp", body)
    SUBKEYS[case] = sk
    res = {"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha(req), "outcome": "issued",
           "artifacts": [{"name": f"{case}.bound.pgp", "sha256": sha(body)}], "valid_from": ts(CLOCK), "valid_until": ts(dt.datetime.fromtimestamp(until, UTC)),
           "issuer": hexfp(primary), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "openpgp-subkey", "request": request_case, "files": [f"responses/{case}.bound.pgp", f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


sk, backs, req = pgp_case("pgp-piv-valid", expect="accept")
pgp_response("pgp-piv-valid", "pgp-piv-valid", sk, backs, req)
sk = PgpKey(T_SUBKEY)
sk, backs, req = pgp_case("pgp-kms-valid", sk=sk, store="aws-kms", expect="accept", stub=kms_stub(sk.pub))
pgp_response("pgp-kms-valid", "pgp-kms-valid", sk, backs, req)
sk, backs, req = pgp_case("pgp-openpgp-card-valid", store="openpgp-card", expect="accept")
pgp_response("pgp-openpgp-card-valid", "pgp-openpgp-card-valid", sk, backs, req)
sk, backs, req = pgp_case("pgp-software-valid", store="software", cfg="development", expect="accept")
pgp_response("pgp-software-valid", "pgp-software-valid", sk, backs, req)

pgp_case("pgp-backsig-missing", backs=[], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-missing-one", sk=sk, backs=[backsig(sk, PRIM_A)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-primary", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_Z)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-type", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_B, stype=0x18)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
bad = bytearray(backsig(sk, PRIM_B)); bad[-1] ^= 1
pgp_case("pgp-backsig-tampered", sk=sk, backs=[backsig(sk, PRIM_A), bytes(bad)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-no-key-id", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_B, key_id=False)], reason="possession-invalid")
pgp_case("pgp-version-2", version=2, reason="version-unsupported")
pgp_case("pgp-unknown-primary", primaries=[PRIM_A, PRIM_Z], reason="unknown-primary")
pgp_case("pgp-primaries-incomplete", primaries=[PRIM_A], reason="unknown-primary")
pgp_case("pgp-piv-key-mismatch", evidence_pub=ec384().public_key(), reason="key-mismatch")
pgp_case("pgp-openpgp-card-untrusted-chain", store="openpgp-card", card=OTHER_OPGP_CARD, reason="proof-invalid")
# an Ed25519 subkey: the request is well formed and signed, the algorithm is not one of version 1
pgp_case("pgp-ed25519", sk=PgpKey(T_SUBKEY, alg=22), store="software", cfg="development", reason="algorithm-unsupported")

# ---- OpenPGP answers to the request pgp-response-request: one bound by the other primary, and four a requester must refuse
sk, backs, req = pgp_case("pgp-response-request", store="software", cfg="development", expect="accept")
pgp_response("pgp-response-other-primary", "pgp-response-request", sk, backs, req, primary=PRIM_B)
pgp_response("pgp-response-no-backsig", "pgp-response-request", sk, backs, req, embed=False, expect="refuse", reason="profile")
other = PgpKey(T_SUBKEY)
pgp_response("pgp-response-wrong-subkey", "pgp-response-request", other, {}, req, expect="refuse", reason="key-mismatch")
pgp_response("pgp-response-wrong-primary", "pgp-response-request", sk, backs, req, primary=PRIM_Z, expect="refuse", reason="issuer")
# the expiry is shorter than 12 months: a requester that expects about 13 months refuses it
pgp_response("pgp-response-short-expiry", "pgp-response-request", sk, backs, req, until=T_CEREMONY + 60 * 86400, expect="refuse", reason="validity")

# ---- SSH CA key requests (type ssh-ca-key): the key as an OpenSSH public key line, and a proof of possession that is an
# SSHSIG signature (OpenSSH PROTOCOL.sshsig) over the bytes of that line in the namespace below.
SSH_NS = b"ssh-ca-key@ritueel.id"


def sshstr(b):
    return struct.pack(">I", len(b)) + b


def sshmpint(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return (b"\0" + b) if b[0] & 0x80 else b


class SshKey:
    """An SSH public key: ecdsa-sha2-nistp384, or ssh-ed25519 to make a refused vector."""

    def __init__(self, alg="ecdsa-sha2-nistp384"):
        self.alg = alg
        if alg == "ssh-ed25519":
            self.priv = ed25519.Ed25519PrivateKey.generate()
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.blob = sshstr(b"ssh-ed25519") + sshstr(raw)
        else:
            self.priv = ec384()
            self.blob = sshstr(alg.encode()) + sshstr(b"nistp384") + sshstr(self.priv.public_key().public_bytes(*POINT))
        self.pub = self.priv.public_key()
        self.text = f"{alg} {b64(self.blob)}"                       # the list's ssh_public_key
        self.line = (self.text + "\n").encode()                       # the bytes of <stem>.sshca.pub
        self.fingerprint = "SHA256:" + b64(hashlib.sha256(self.blob).digest()).rstrip("=")

    def signature(self, data):
        if self.alg == "ssh-ed25519":
            return sshstr(b"ssh-ed25519") + sshstr(self.priv.sign(data))
        r, s_ = decode_dss_signature(self.priv.sign(data, ec.ECDSA(hashes.SHA384())))
        return sshstr(self.alg.encode()) + sshstr(sshstr(sshmpint(r)) + sshstr(sshmpint(s_)))


def sshsig(key, message, ns=SSH_NS):
    """The armoured SSHSIG signature `ssh-keygen -Y sign` writes: hash algorithm sha512, an empty reserved string."""
    signed = b"SSHSIG" + sshstr(ns) + sshstr(b"") + sshstr(b"sha512") + sshstr(hashlib.sha512(message).digest())
    blob = (b"SSHSIG" + struct.pack(">I", 1) + sshstr(key.blob) + sshstr(ns) + sshstr(b"") + sshstr(b"sha512")
            + sshstr(key.signature(signed)))
    body = base64.b64encode(blob).decode()
    return ("-----BEGIN SSH SIGNATURE-----\n" + "".join(body[i:i + 70] + "\n" for i in range(0, len(body), 70))
            + "-----END SSH SIGNATURE-----\n").encode()


SSH_KEYS = {}   # case id -> (SshKey, use): the keys of the accepted requests, which the SSH CA key lists carry


def ssh_case(case, key=None, store="piv", cfg="production", expect="refuse", reason=None, use="user", ev=None, version=1,
             extra_member=None, digest_of=None, stub=None, evidence_pub=None, arn=ARN, sig_message=None, ns=SSH_NS, **att):
    key = key or SshKey()
    evidence = ev or evidence_for(store, evidence_pub or key.pub, arn=arn, att=att)
    p = proof("ssh-ca-key", digest_of or key.line, store, evidence, version)
    if use is not None:
        p["use"] = use
    if extra_member:
        p["unexpected"] = extra_member
    w(f"requests/{case}.sshca.pub", key.line)
    w(f"requests/{case}.sshca.sig", sshsig(key, sig_message or key.line, ns))
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.sshca.pub", f"requests/{case}.sshca.sig", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "ssh-ca-key", cfg, expect, reason, files, st)
    if expect == "accept":
        SSH_KEYS[case] = (key, use)
    return key


def ssh_response(case, request_case, key, ssh_list, expect="install", reason=None, issuer_label="A"):
    """The answer to an ssh-ca-key request: the key is listed, so there is no artifact; the requester reads the SSH CA key
    list `ssh_list` of the SSH CA key list vectors, which it holds."""
    res = {"handoff": 1, "type": "ssh-ca-key", "request_sha256": sha(key.line), "outcome": "issued", "artifacts": [],
           "valid_from": ts(CLOCK), "issuer": sha(spki({"A": ROOT_A, "B": ROOT_B}[issuer_label].public_key())), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "ssh-ca-key", "request": request_case, "files": [f"responses/{case}.result.json"],
         "ssh_ca_key_list": ssh_list, "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


k = ssh_case("ssh-piv-valid", expect="accept", use="user")
ssh_response("ssh-piv-valid", "ssh-piv-valid", k, "seq7-a")
k = SshKey()
ssh_case("ssh-kms-valid", key=k, store="aws-kms", expect="accept", use="host", stub=kms_stub(k.pub))
ssh_response("ssh-kms-valid", "ssh-kms-valid", k, "seq7-a")
k = ssh_case("ssh-software-valid", store="software", cfg="development", expect="accept", use="user")
ssh_response("ssh-software-valid", "ssh-software-valid", k, "seq7-a")
src = cases[-1]
cases.append({"id": "ssh-software-in-production", "type": "ssh-ca-key", "config": "production", "files": src["files"],
              "expect": "refuse", "reason": "store-not-allowed"})
ssh_case("ssh-openpgp-card", store="openpgp-card", reason="store-not-allowed")
k = SshKey()
ssh_case("ssh-bad-signature", key=k, store="software", cfg="development", sig_message=b"another request\n", reason="possession-invalid")
ssh_case("ssh-wrong-namespace", store="software", cfg="development", ns=b"file", reason="possession-invalid")
ssh_case("ssh-ed25519", key=SshKey("ssh-ed25519"), store="software", cfg="development", reason="algorithm-unsupported")
ssh_case("ssh-version-2", version=2, reason="version-unsupported")
k = SshKey()
ssh_case("ssh-request-mismatch", key=k, digest_of=SshKey().line, reason="request-mismatch")
ssh_case("ssh-unknown-member", extra_member=True, reason="malformed")
ssh_case("ssh-use-missing", use=None, reason="malformed")
ssh_case("ssh-use-both", use="both", reason="malformed")
ssh_case("ssh-piv-key-mismatch", evidence_pub=ec384().public_key(), reason="key-mismatch")
k = SshKey()
ssh_case("ssh-piv-untrusted-chain", key=k, ev=attestation(k.pub, card=OTHER_CARD), reason="proof-invalid")
ssh_case("ssh-piv-pin-never", policy=bytes([1, 1]), reason="policy")
k = SshKey()
ssh_case("ssh-kms-key-mismatch", key=k, store="aws-kms", evidence_pub=ec384().public_key(), stub=kms_stub(k.pub), reason="key-mismatch")
k = SshKey()
ssh_case("ssh-kms-two-actors", key=k, store="aws-kms", stub=kms_stub(k.pub, two_actors=True), reason="policy")

# ---- answers to the request ssh-response-request: one listed by the other root, and three a requester must refuse
k_resp = ssh_case("ssh-response-request", store="software", cfg="development", expect="accept", use="user")
ssh_response("ssh-response-other-root", "ssh-response-request", k_resp, "seq7-b", issuer_label="B")
ssh_response("ssh-response-key-not-listed", "ssh-response-request", k_resp, "seq7-a-without-key", expect="refuse", reason="key-mismatch")
ssh_response("ssh-response-wrong-use", "ssh-response-request", k_resp, "seq7-a-wrong-use", expect="refuse", reason="profile")
ssh_response("ssh-response-old-list", "ssh-response-request", k_resp, "seq6-b", expect="refuse", reason="issuer")

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
policy = {"min_firmware": "5.7.0", "pin_policy": ["once", "always"], "require_name_constraints": True,
          "permitted_uri_hosts": [HOST], "validity_months": 13, "kms_read_roles": {"111122223333": READ_ROLE}}
wj("manifest.json", {
    "handoff": 1,
    "clock": ts(CLOCK),
    "pinned": {
        "attestation_roots": ["pki/test-attestation-root.pem"],
        "attestation_intermediates": ["pki/test-attestation-intermediate.pem", "pki/test-opgp-attestation-intermediate.pem"],
        "root_list": {"x509": ["pki/test-root-a.pem", "pki/test-root-b.pem"], "openpgp": ["pki/test-primary-a.pgp", "pki/test-primary-b.pgp"]},
        "not_listed": {"x509": ["pki/test-root-z.pem"], "openpgp": ["pki/test-primary-z.pgp"]},
        "trust_sequence": SEQUENCE,
    },
    "configs": {
        "production": {"stores": ["piv", "openpgp-card", "aws-kms"], **policy},
        "development": {"stores": ["piv", "openpgp-card", "aws-kms", "software"], **policy},
    },
    "requests": cases,
    "responses": responses,
})
print("cases:", len(cases), "responses:", len(responses))


# ================================================================ root list and CA bundle vectors, version 1
# The same roots A, B and Z as above. The hand-off answers carry trust sequence 7, and the list `seq7-a` is the
# root list of that trust set: a requester that holds it can install them.
def canonical(obj):
    """RFC 8785 canonical JSON for the values used here: ASCII member names and strings, integers, no floats.
    For those, sorted keys, no whitespace and JSON.stringify's escaping are the whole of the scheme."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ROOTS = {"A": (ROOT_A_KEY, ROOT_A, PRIM_A), "B": (ROOT_B_KEY, ROOT_B, PRIM_B), "Z": (ROOT_Z_KEY, ROOT_Z, PRIM_Z)}
spki_hex = lambda lbl: sha(spki(ROOTS[lbl][1].public_key()))


def months13(t, n=13):
    """n (13) calendar months later, same day and time, or the last day of the month if it has none."""
    y, m = divmod(t.month - 1 + n, 12)
    y, m = t.year + y, m + 1
    last = (dt.datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=UTC) - dt.timedelta(days=1)).day
    return t.replace(year=y, month=m, day=min(t.day, last))


def entry(lbl):
    return {"label": lbl, "x509_spki_sha256": spki_hex(lbl), "openpgp_fingerprint": ROOTS[lbl][2].fpr.hex()}


def jws(signer, payload, typ="root-list+json"):
    """A detached JWS (RFC 7515, appendix F) in compact form: header..signature. ES384 over the payload's bytes."""
    key, cert, _ = ROOTS[signer]
    header = canonical({"alg": "ES384", "kid": spki_hex(signer), "typ": typ, "x5c": [b64(cert.public_bytes(DER))]})
    signing_input = (b64u(header) + "." + b64u(payload)).encode()
    r, s_ = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA384())))
    return b64u(header) + ".." + b64u(r.to_bytes(48, "big") + s_.to_bytes(48, "big"))


RECORDS = {n: sha(f"example ceremony record {n}\n".encode()) for n in range(1, 10)}   # made-up record digests
lists = []


def root_list(stem, signer, sequence, roots, signed_at, version=1, last_record=True, extra=None, tamper=None):
    doc = {"version": version, "sequence": sequence, "signed_at": ts(signed_at), "expires_at": ts(months13(signed_at)),
           "roots": [entry(r) for r in roots]}
    if last_record:
        doc["last_record_sha256"] = RECORDS[sequence - 1]
    if extra:
        doc.update(extra)
    payload = canonical(doc)
    sig = jws(signer, payload)
    if tamper:
        payload = canonical(tamper(doc))
    w(f"lists/{stem}.json", payload, RL_OUT)
    w(f"lists/{stem}.jws", sig, RL_OUT)
    lists.append({"id": stem, "signer": signer, "files": [f"lists/{stem}.json", f"lists/{stem}.jws"]})


T_INIT, T_SEQ6, T_SEQ8, T_SEQ9 = T_ROOTS, dt.datetime(2026, 6, 1, 12, tzinfo=UTC), dt.datetime(2026, 12, 1, 12, tzinfo=UTC), dt.datetime(2026, 12, 2, 12, tzinfo=UTC)
root_list("init-a", "A", 1, "AB", T_INIT, last_record=False)            # the first list, made by `init`: no record before it
root_list("seq6-b", "B", 6, "AB", T_SEQ6)
root_list("seq7-a", "A", 7, "AB", CLOCK)                                # the trust set of the hand-off answers
root_list("seq7-b", "B", 7, "AB", CLOCK)
root_list("seq8-b-without-a", "B", 8, "B", T_SEQ8)                      # root A revoked: signed by the surviving root
root_list("seq9-a", "A", 9, "AB", T_SEQ9)                               # signed by the revoked root
root_list("seq8-z", "Z", 8, "AB", T_SEQ8)                               # signed by a root on no list
root_list("seq8-a-version-2", "A", 8, "AB", T_SEQ8, version=2)
root_list("seq8-a-unknown-member", "A", 8, "AB", T_SEQ8, extra={"comment": "not a member of version 1"})


def swap_b_for_z(doc):
    doc = json.loads(json.dumps(doc))
    doc["roots"][1] = entry("Z")
    return doc


root_list("seq7-a-tampered", "A", 7, "AB", CLOCK, tamper=swap_b_for_z)   # root B replaced by Z after signing
root_list("seq7-a-without-b", "A", 7, "A", CLOCK)                      # a second, different list at sequence 7

rl_cases = []


def rl_case(cid, held, candidate, expect, reason=None, clock=None, warning=None):
    c = {"id": cid, "held": held, "candidate": candidate}
    if clock:
        c["clock"] = ts(clock)
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    rl_cases.append(c)


rl_case("first-list", None, "seq7-a", "accept")
rl_case("first-list-from-init", None, "init-a", "accept")
rl_case("update", "seq6-b", "seq7-a", "accept")
rl_case("update-by-the-other-root", "init-a", "seq7-b", "accept")
rl_case("revoke-a-root", "seq7-a", "seq8-b-without-a", "accept", clock=T_SEQ8)
rl_case("same-list-again", "seq7-a", "seq7-a", "accept")
rl_case("rollback", "seq7-a", "seq6-b", "refuse", "rollback")
rl_case("same-sequence-different-content", "seq7-a", "seq7-a-without-b", "refuse", "sequence-conflict")
rl_case("signed-by-a-revoked-root", "seq8-b-without-a", "seq9-a", "refuse", "unknown-signer", clock=T_SEQ9)
rl_case("unknown-signer", "seq7-a", "seq8-z", "refuse", "unknown-signer", clock=T_SEQ8)
rl_case("tampered", "seq6-b", "seq7-a-tampered", "refuse", "signature-invalid")
rl_case("expired", "init-a", "seq6-b", "refuse", "expired", clock=dt.datetime(2027, 8, 1, tzinfo=UTC))
rl_case("version-2", "seq7-a", "seq8-a-version-2", "refuse", "version-unsupported", clock=T_SEQ8)
rl_case("unknown-member", "seq7-a", "seq8-a-unknown-member", "refuse", "malformed", clock=T_SEQ8)
rl_case("held-list-expired", "seq7-a", None, "warn", clock=dt.datetime(2028, 1, 1, tzinfo=UTC), warning="expired")

# CA bundles: the trust sequence in the first line, then each root's certificate in the order of the root list
bundles = []


def ca_bundle(sequence, roots):
    body = f"# trust-sequence: {sequence}\n".encode() + b"".join(ROOTS[r][1].public_bytes(PEM) for r in roots)
    path = f"bundles/ca-bundle-{sequence}.pem"
    w(path, body, RL_OUT)
    bundles.append({"id": f"ca-bundle-{sequence}", "file": path, "sequence": sequence, "roots": list(roots)})


ca_bundle(7, "AB")
ca_bundle(8, "B")

for lbl in "ABZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), RL_OUT)
    w(f"pki/test-primary-{lbl.lower()}.pgp", PRIMARY_CERTS[lbl], RL_OUT)
wj("manifest.json", {
    "root_list": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "openpgp": f"pki/test-primary-{lbl.lower()}.pgp",
               "x509_spki_sha256": spki_hex(lbl), "openpgp_fingerprint": ROOTS[lbl][2].fpr.hex()} for lbl in "ABZ"],
    "initial_pins": ["A", "B"],
    "lists": lists,
    "cases": rl_cases,
    "bundles": bundles,
}, RL_OUT)
print("root lists:", len(lists), "cases:", len(rl_cases), "bundles:", len(bundles))


# ================================================================ SSH CA key list vectors, version 1
# The list at trust sequence 7 holds the keys of the accepted ssh-ca-key requests above, the key of the answer vectors,
# and a break-glass SSH CA for each of the roots A and B. The hand-off answers of type ssh-ca-key name these lists.
BREAK_GLASS = {lbl: SshKey() for lbl in "AB"}


def ssh_entry(name_, key, use, root_label=None):
    e = {"name": name_, "use": use, "ssh_public_key": key.text, "fingerprint": key.fingerprint}
    if root_label:
        e["root"] = root_label
    return e


def listed(without=(), wrong_use=()):
    """The entries of the list at sequence 7, sorted by name: the break-glass keys, then the requests' keys. A name in
    wrong_use is listed with the other use than the request asked for."""
    es = [ssh_entry(f"break-glass-{lbl}", BREAK_GLASS[lbl], "user", lbl) for lbl in "AB"]
    for c, (k, u) in SSH_KEYS.items():
        if c not in without:
            es.append(ssh_entry(c, k, ("host" if u == "user" else "user") if c in wrong_use else u))
    return sorted(es, key=lambda e: e["name"].encode())


ssh_lists = []


def ssh_list(stem, signer, sequence, entries, signed_at, version=1, extra=None, tamper=None, typ="ssh-ca-keys+json"):
    doc = {"version": version, "sequence": sequence, "signed_at": ts(signed_at), "expires_at": ts(months13(signed_at)), "keys": entries}
    if extra:
        doc.update(extra)
    payload = canonical(doc)
    sig = jws(signer, payload, typ)
    if tamper:
        payload = canonical(tamper(doc))
    w(f"lists/{stem}.json", payload, SSH_OUT)
    w(f"lists/{stem}.jws", sig, SSH_OUT)
    ssh_lists.append({"id": stem, "signer": signer, "files": [f"lists/{stem}.json", f"lists/{stem}.jws"]})


def user_keys_file(sequence, entries):
    """The file for sshd's TrustedUserCAKeys: the trust sequence in a comment, then every key whose use is user, in list order."""
    return (f"# trust-sequence: {sequence}\n" + "".join(e["ssh_public_key"] + "\n" for e in entries if e["use"] == "user")).encode()


ssh_list("seq6-b", "B", 6, [ssh_entry(f"break-glass-{lbl}", BREAK_GLASS[lbl], "user", lbl) for lbl in "AB"], T_SEQ6)
ssh_list("seq7-a", "A", 7, listed(), CLOCK)
ssh_list("seq7-b", "B", 7, listed(), CLOCK)
ssh_list("seq7-a-without-key", "A", 7, listed(without=("ssh-response-request",)), CLOCK)
ssh_list("seq7-a-wrong-use", "A", 7, listed(wrong_use=("ssh-response-request",)), CLOCK)
no_bg_a = [e for e in listed() if e["name"] != "break-glass-A"]
ssh_list("seq8-b-without-a", "B", 8, no_bg_a, T_SEQ8)                     # root A revoked: its break-glass key leaves, signed by B
ssh_list("seq8-a-retiring", "A", 8, no_bg_a, T_SEQ8)                      # root A retires and signs the lists that remove it
ssh_list("seq8-a-empty", "A", 8, [], T_SEQ8)                              # every key withdrawn
ssh_list("seq9-a", "A", 9, no_bg_a, T_SEQ9)                               # signed by the revoked root
ssh_list("seq8-z", "Z", 8, listed(), T_SEQ8)                              # signed by a root on no list
ssh_list("seq8-a-version-2", "A", 8, listed(), T_SEQ8, version=2)
ssh_list("seq8-a-unknown-member", "A", 8, listed(), T_SEQ8, extra={"comment": "not a member of version 1"})
dup = listed()
ssh_list("seq8-a-duplicate-key", "A", 8, sorted(dup + [dict(dup[2], name="zzz-copy")], key=lambda e: e["name"].encode()), T_SEQ8)
ssh_list("seq8-a-root-list-type", "A", 8, listed(), T_SEQ8, typ="root-list+json")   # the root list's type in the protected header


def swap_key(doc):
    doc = json.loads(json.dumps(doc))
    doc["keys"][2]["ssh_public_key"] = SshKey().text
    return doc


ssh_list("seq7-a-tampered", "A", 7, listed(), CLOCK, tamper=swap_key)     # a key replaced after signing

w("files/ssh-user-ca-keys-7.pub", user_keys_file(7, listed()), SSH_OUT)
w("files/ssh-user-ca-keys-7-with-host-key.pub", user_keys_file(7, listed()) + (SSH_KEYS["ssh-kms-valid"][0].text + "\n").encode(), SSH_OUT)

ssh_cases = []


def ssh_list_case(cid, held, candidate, expect, reason=None, clock=None, warning=None, roots="AB", rl_sequence=None, rl_signer=None, user_keys=None):
    c = {"id": cid, "held": held, "candidate": candidate, "root_list": {"roots": list(roots)}}
    if rl_sequence:
        c["root_list"].update({"sequence": rl_sequence, "signer": rl_signer})
    if clock:
        c["clock"] = ts(clock)
    if user_keys:
        c["user_keys"] = user_keys
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    ssh_cases.append(c)


ssh_list_case("first-list", None, "seq7-a", "accept")
ssh_list_case("update", "seq6-b", "seq7-a", "accept")
ssh_list_case("same-list-signed-by-the-other-root", "seq7-a", "seq7-b", "accept")
ssh_list_case("remove-a-revoked-roots-key", "seq7-a", "seq8-b-without-a", "accept", clock=T_SEQ8, roots="B", rl_sequence=8, rl_signer="B")
ssh_list_case("retiring-root-signs", "seq7-a", "seq8-a-retiring", "accept", clock=T_SEQ8, roots="B", rl_sequence=8, rl_signer="A")
ssh_list_case("every-key-withdrawn", "seq7-a", "seq8-a-empty", "accept", clock=T_SEQ8)
ssh_list_case("same-list-again", "seq7-a", "seq7-a", "accept")
ssh_list_case("user-keys-file", None, "seq7-a", "accept", user_keys="files/ssh-user-ca-keys-7.pub")
ssh_list_case("rollback", "seq7-a", "seq6-b", "refuse", "rollback")
ssh_list_case("same-sequence-different-content", "seq7-a", "seq7-a-without-key", "refuse", "sequence-conflict")
ssh_list_case("signed-by-a-revoked-root", "seq8-b-without-a", "seq9-a", "refuse", "unknown-signer", clock=T_SEQ9, roots="B", rl_sequence=9, rl_signer="B")
ssh_list_case("retiring-root-signs-after-its-root-list", "seq7-a", "seq8-a-retiring", "refuse", "unknown-signer", clock=T_SEQ8, roots="B", rl_sequence=9, rl_signer="B")
ssh_list_case("unknown-signer", "seq7-a", "seq8-z", "refuse", "unknown-signer", clock=T_SEQ8)
ssh_list_case("tampered", "seq6-b", "seq7-a-tampered", "refuse", "signature-invalid")
ssh_list_case("expired", "seq6-b", "seq7-a", "refuse", "expired", clock=dt.datetime(2028, 1, 1, tzinfo=UTC))
ssh_list_case("version-2", "seq7-a", "seq8-a-version-2", "refuse", "version-unsupported", clock=T_SEQ8)
ssh_list_case("unknown-member", "seq7-a", "seq8-a-unknown-member", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("duplicate-key", "seq7-a", "seq8-a-duplicate-key", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("root-list-type", "seq7-a", "seq8-a-root-list-type", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("user-keys-file-with-a-host-key", None, "seq7-a", "refuse", "user-keys-mismatch", user_keys="files/ssh-user-ca-keys-7-with-host-key.pub")
ssh_list_case("held-list-expired", "seq7-a", None, "warn", clock=dt.datetime(2028, 1, 1, tzinfo=UTC), warning="expired")

for lbl in "ABZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), SSH_OUT)
wj("manifest.json", {
    "ssh_ca_keys": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "x509_spki_sha256": spki_hex(lbl)} for lbl in "ABZ"],
    "lists": ssh_lists,
    "files": [{"id": "ssh-user-ca-keys-7", "file": "files/ssh-user-ca-keys-7.pub"},
              {"id": "ssh-user-ca-keys-7-with-host-key", "file": "files/ssh-user-ca-keys-7-with-host-key.pub"}],
    "cases": ssh_cases,
}, SSH_OUT)
print("ssh ca key lists:", len(ssh_lists), "cases:", len(ssh_cases))


# ================================================================ CRL vectors, version 1
# One CRL for each root, signed by that root. The CRL number is the trust sequence at which the root signed it: root A
# signed at sequence 7, root B at sequence 6, and B's CRL is still current because a CRL is valid for 25 months.
def crl_cert(root_lbl):
    key, root_cert, _ = ROOTS[root_lbl]
    csr = make_csr(ec384())
    return issue(csr, issuer_key=key, issuer=root_cert)


CA_A1, CA_B1 = crl_cert("A"), crl_cert("B")
w("certs/ca-a-1.pem", CA_A1.public_bytes(PEM), CRL_OUT)
w("certs/ca-b-1.pem", CA_B1.public_bytes(PEM), CRL_OUT)
CRL_CERTS = [{"id": "ca-a-1", "file": "certs/ca-a-1.pem", "issuer": "A", "serial": f"{CA_A1.serial_number:x}"},
             {"id": "ca-b-1", "file": "certs/ca-b-1.pem", "issuer": "B", "serial": f"{CA_B1.serial_number:x}"}]
crls = []


def crl(stem, signer, number, this, revoked=(), nxt=None, hash_=None, critical_ext=False, tamper=None):
    key, root_cert, _ = ROOTS[signer]
    b = (x509.CertificateRevocationListBuilder().issuer_name(root_cert.subject).last_update(this)
         .next_update(nxt or months13(this, 25))
         .add_extension(x509.AuthorityKeyIdentifier(ski(root_cert.public_key()), None, None), critical=False)
         .add_extension(x509.CRLNumber(number), critical=False))
    for cert in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(this)
                                      .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False).build())
    if critical_ext:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"), critical=True)
    der = b.sign(key, hash_ or hashes.SHA384()).public_bytes(DER)
    if tamper:
        der = tamper(der)
    pem = ("-----BEGIN X509 CRL-----\n" + "".join(b64(der)[i:i + 64] + "\n" for i in range(0, len(b64(der)), 64)) + "-----END X509 CRL-----\n")
    w(f"crls/{stem}.pem", pem, CRL_OUT)
    crls.append({"id": stem, "signer": signer, "file": f"crls/{stem}.pem", "number": number, "this_update": ts(this),
                 "next_update": ts(nxt or months13(this, 25)), "revoked": [{"serial": f"{c.serial_number:x}", "reason": "keyCompromise"} for c in revoked]})


def swap_serial(der):
    """Replace the revoked serial by another of the same length, after signing."""
    old = CA_A1.serial_number.to_bytes((CA_A1.serial_number.bit_length() + 7) // 8, "big")
    new = bytearray(old)
    new[-1] ^= 0x01
    assert old in der
    return der.replace(old, bytes(new))


T_B_CRL = dt.datetime(2025, 11, 15, 12, tzinfo=UTC)
crl("a-seq7-empty", "A", 7, CLOCK)
crl("b-seq6-empty", "B", 6, T_B_CRL)
crl("a-seq8-revokes", "A", 8, T_SEQ8, [CA_A1])
crl("a-seq7-revokes", "A", 7, CLOCK, [CA_A1])                              # another CRL with number 7
crl("z-seq8", "Z", 8, T_SEQ8)
crl("a-seq8-tampered", "A", 8, T_SEQ8, [CA_A1], tamper=swap_serial)
crl("a-seq5-expired", "A", 5, dt.datetime(2024, 9, 15, 12, tzinfo=UTC))
crl("a-seq9-not-yet-valid", "A", 9, dt.datetime(2027, 1, 1, 12, tzinfo=UTC))
crl("a-seq8-critical-extension", "A", 8, T_SEQ8, critical_ext=True)
crl("a-seq8-sha256", "A", 8, T_SEQ8, hash_=hashes.SHA256())

crl_cases = []


def crl_case(cid, held, candidate, expect, reason=None, clock=None, warning=None, roots="AB"):
    c = {"id": cid, "held": held, "candidate": candidate, "roots": list(roots)}
    if clock:
        c["clock"] = ts(clock)
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    crl_cases.append(c)


crl_case("first-crl", None, "a-seq7-empty", "accept")
crl_case("first-crl-of-the-other-root", None, "b-seq6-empty", "accept")
crl_case("the-other-roots-crl-a-year-on", None, "b-seq6-empty", "accept", clock=dt.datetime(2027, 11, 15, 12, tzinfo=UTC))
crl_case("update", "a-seq7-empty", "a-seq8-revokes", "accept", clock=T_SEQ8)
crl_case("same-crl-again", "a-seq7-empty", "a-seq7-empty", "accept")
crl_case("rollback", "a-seq8-revokes", "a-seq7-empty", "refuse", "rollback", clock=T_SEQ8)
crl_case("same-number-different-content", "a-seq7-empty", "a-seq7-revokes", "refuse", "sequence-conflict")
crl_case("unknown-signer", None, "z-seq8", "refuse", "unknown-signer", clock=T_SEQ8)
crl_case("signed-by-a-revoked-root", None, "a-seq8-revokes", "refuse", "unknown-signer", clock=T_SEQ8, roots="B")
crl_case("tampered", None, "a-seq8-tampered", "refuse", "signature-invalid", clock=T_SEQ8)
crl_case("expired", None, "a-seq5-expired", "refuse", "expired")
crl_case("not-yet-valid", None, "a-seq9-not-yet-valid", "refuse", "not-yet-valid")
crl_case("critical-extension", None, "a-seq8-critical-extension", "refuse", "malformed", clock=T_SEQ8)
crl_case("sha-256-signature", None, "a-seq8-sha256", "refuse", "malformed", clock=T_SEQ8)
crl_case("held-crl-expired", "a-seq7-empty", None, "warn", clock=dt.datetime(2029, 1, 1, tzinfo=UTC), warning="expired")

crl_revocation = [
    {"id": "listed", "cert": "ca-a-1", "crl": "a-seq8-revokes", "clock": ts(T_SEQ8), "expect": "revoked"},
    {"id": "not-listed", "cert": "ca-a-1", "crl": "a-seq7-empty", "expect": "good"},
    {"id": "other-root-not-listed", "cert": "ca-b-1", "crl": "b-seq6-empty", "expect": "good"},
]

for lbl in "ABZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), CRL_OUT)
wj("manifest.json", {
    "crl": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "x509_spki_sha256": spki_hex(lbl)} for lbl in "ABZ"],
    "certs": CRL_CERTS,
    "crls": crls,
    "cases": crl_cases,
    "revocation": crl_revocation,
}, CRL_OUT)
print("crls:", len(crls), "cases:", len(crl_cases), "revocation:", len(crl_revocation))
