# Known answers for `internal/pki`

These files are the expected bytes of the root and intermediate certificate bodies (the
TBSCertificate, RFC 5280, section 4.1.1.1), made by OpenSSL and not by the code under test. The tests
of `internal/pki` compare the builders' output with them. The folder has no `v<N>/manifest.json`, so
`just check-vectors` does not look at it, and nothing here depends on another folder of `testdata/`.

Everything is public material. The private keys were made for one run of the commands below, used
once and deleted. None is kept anywhere, and no file here holds one.

## The files

| File | What it is | How it was made |
|---|---|---|
| `root.pub.pem` | The public key of the root (ECDSA P-384). | `openssl ecparam -name secp384r1 -genkey -noout -out root.key`, then `openssl pkey -in root.key -pubout -out root.pub.pem` |
| `csr-nc.csr.pem` | A request: subject `O=acme, CN=acme example intermediate CA` (PrintableString), basic constraints, key usage `keyCertSign` and `cRLSign`, name constraints (URI `example.org`), extended key usage `serverAuth`, not critical. | `openssl req -new -key a.key -sha384 -config req.cnf -addext ...` (below) |
| `csr-eku.csr.pem` | A request: subject `O=acme, OU=ops, CN=acme example eku CA` (UTF8String), key usage with `digitalSignature`, name constraints (DNS `example.org`), extended key usage `serverAuth` and `clientAuth`, not critical. | `openssl req -new -key b.key -sha384 -utf8 -subj ... -addext ...` |
| `csr-eku-reversed.csr.pem` | A request: subject `CN=acme example client CA`, key usage `keyCertSign` only, name constraints (DNS `example.org`), extended key usage `clientAuth` then `serverAuth`, not critical (the order of the request is the order of the certificate). | `openssl req -new -key c.key -sha384 -utf8 -subj ... -addext ...` |
| `csr-no-eku.csr.pem` | A request that the contract refuses (`policy`): the same as the first `csr-nc.csr.pem` of an earlier version, with no extended key usage. Read by `ParseRequestFile` in a test, as a request that OpenSSL made. | `openssl req ... -addext ...` without the extended key usage |
| `csr-eku-critical.csr.pem` | A request that the contract refuses (`policy`): subject `CN=acme example client CA`, key usage `keyCertSign` only, name constraints (DNS `example.org`), extended key usage `clientAuth`, critical. | `openssl req -new -key c.key -sha384 -utf8 -subj ... -addext ...` |
| `root-test.sig.hex`, `inter-nc.sig.hex` | The DER ECDSA signature of the root key over the body `root-test.tbs` and `inter-nc.tbs` of `expected.txt`. | `openssl dgst -sha384 -sign root.key -out sig.der body.der`, then `xxd -p -c 500 sig.der` |
| `expected.txt` | One `name value` pair per line: the expected bodies in hex (`*.tbs`), their SHA-256 and SHA-384, the issuer name, and the key pins and key identifiers. | `reproduce.sh` |
| `root-test.cert.pem`, `inter-nc.cert.pem` | A whole root certificate and a whole intermediate certificate, to check `Assemble`. | `reproduce.sh`, from the body and the signature |
| `reproduce.sh` | Makes `expected.txt` and the two certificates again from the public files above. | |

The request commands, with the extensions that are in the table:

```sh
cat > req.cnf <<'EOF'
[req]
distinguished_name = dn
string_mask = default
prompt = no
[dn]
O = acme
CN = acme example intermediate CA
EOF
openssl req -new -key a.key -sha384 -config req.cnf \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "nameConstraints=critical,permitted;URI:example.org" \
  -addext "extendedKeyUsage=serverAuth" -out csr-nc.csr.pem
openssl req -new -key b.key -sha384 -utf8 -subj "/O=acme/OU=ops/CN=acme example eku CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
  -addext "nameConstraints=critical,permitted;DNS:example.org" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" -out csr-eku.csr.pem
openssl req -new -key c.key -sha384 -utf8 -subj "/CN=acme example client CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "nameConstraints=critical,permitted;DNS:example.org" \
  -addext "extendedKeyUsage=clientAuth,serverAuth" -out csr-eku-reversed.csr.pem
```

`csr-no-eku.csr.pem` is the request of `csr-nc` without the last `-addext`, and `csr-eku-critical.csr.pem` is the request of
`csr-eku-reversed` with `extendedKeyUsage=critical,clientAuth`; both are made with keys that are not the ones above, and
they stay as inputs that the builders refuse.

## The cases of `expected.txt`

`reproduce.sh` describes each body to `openssl asn1parse -genconf` as a structure: the serial, the
times, the names, the key, the extension values and their order are written out in the script. The
public key and the key identifiers are taken from the key files with OpenSSL (the identifier is the
first 20 octets of the SHA-256 of the subjectPublicKey bits). The signature algorithm is
ecdsa-with-SHA384, and the issuer of every intermediate is `CN=Example Test Root K (TEST ONLY)`.

| Case | Name, serial, validity | What it covers |
|---|---|---|
| `root-test` | `Example Test Root K (TEST ONLY)`, a 159-bit serial, 2026-11-15 12:00:00 for 36 months | the ordinary test root |
| `root-real` | `Example-Org 2 Root Z`, serial 2^63 + 1 (64 bits, a padding octet), 2024-02-29 08:30:00 to 2027-02-28 | no test mark, hyphen and digit in the name, the end of February |
| `root-2049` | serial 2^159 - 1 (20 octets, no padding), 2049-12-31 23:59:59 to 2052-12-31 23:59:59 | the last UTCTime second, then GeneralizedTime |
| `root-2050` | serial 2^64 - 1, 2050-01-01 00:00:00 to 2053-01-01 | the first GeneralizedTime second |
| `root-1950` | serial 0x0123456789abcdef01, 1950-01-01 00:00:00 to 1953-01-01 | the first UTCTime second |
| `root-1949` | serial 0x0123456789abcdef02, 1949-12-31 23:59:59 to 1952-12-31 23:59:59 | the last GeneralizedTime second before 1950 |
| `root-longest` | a name of 45 characters, so that the common name has 64 | the longest common name |
| `inter-nc` | 2026-11-15 12:00:00 for 13 months | `csr-nc`: the ordinary request, with one purpose (`serverAuth`) |
| `inter-eku` | 2027-01-31 10:20:30 for 13 months, serial 2^63 | `csr-eku`: a leap-day end (2028-02-29), the extended key usage not critical, the extension order |
| `inter-eku-reversed` | 2049-12-31 23:59:59 for 13 months, serial 2^159 - 1 | `csr-eku-reversed`: the purposes in the order `clientAuth`, `serverAuth` kept, a UTCTime start and a GeneralizedTime end (2051-01-31) |

## Make it again

```sh
./reproduce.sh testdata/x509-builders /tmp/x509-builders-again
diff testdata/x509-builders/expected.txt /tmp/x509-builders-again/expected.txt
diff testdata/x509-builders/root-test.cert.pem /tmp/x509-builders-again/root-test.cert.pem
diff testdata/x509-builders/inter-nc.cert.pem /tmp/x509-builders-again/inter-nc.cert.pem
```

The certificates also verify: `openssl verify -no-CApath -no-CAstore -attime 1794830400 -CAfile
root-test.cert.pem inter-nc.cert.pem` prints `OK` (1794830400 is 2026-11-16 12:00:00 UTC).
