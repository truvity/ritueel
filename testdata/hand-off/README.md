# Hand-off test vectors

Fixtures for the [hand-off contract](../../docs/reference/hand-off-contract.md): requests that a certifier must accept or refuse, and answers that a requester must install or refuse, with the expected outcome and reason code of each in `v1/manifest.json`.

Everything under `v1/` is public material made with throw-away software keys by `generate.py`. No private key is kept. The script is the record of how the files were made; running it again makes different bytes, so the committed files are the fixtures. A change to a vector that flips its outcome is a new contract version (a new directory).

Every key, serial and signature comes from a stream over one seed, with one stream for each part of the set, and ECDSA signs deterministically (RFC 6979). A run with the same seed in `RITUEEL_VECTOR_SEED` makes the same bytes, and a part added to the script changes no file of the other parts; without it the seed is random. The seed is not kept in the repository, because keys derived from a published seed would be private key material in it ([public content](../../docs/contributing/public-content.md)).

The same run writes the [root list vectors](../root-list/README.md), the [SSH CA key list vectors](../ssh-ca-keys/README.md) and the [CRL vectors](../crl/README.md), because the lists and the CRLs are signed by the same test roots. To regenerate all four, run `python3 testdata/hand-off/generate.py testdata/hand-off/v1 testdata/root-list/v1 testdata/ssh-ca-keys/v1 testdata/crl/v1` (Python 3 with `cryptography`) after removing the old files of the sets, then `just check-vectors`: it fails when the manifest and the tracked files disagree. A request of type `ssh-ca-key` has an SSH signature that `ssh-keygen -Y check-novalidate -n ssh-ca-key@ritueel.id -s <stem>.sshca.sig < <stem>.sshca.pub` checks. `.gitignore` keeps key files out of the repository and lets the `.pem` and `.asc` files under `testdata/` in; every key here is a throw-away test key whose private half was never written.

## The floor with `openssl`

The floor answers (`"floor": true` in the manifest) are certificates from a CA that is not ritueel, for the request `x509-response-request` ([the floor](../../docs/reference/hand-off-contract.md#the-floor-pkcs10-in-x509-out)). A CA tool makes one with a throwaway test CA. With OpenSSL 3.5.5, run on 2026-11-02 in a scratch directory:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -noenc -keyout ca.key -out ca.pem \
  -subj "/CN=Example Floor CA (TEST ONLY)" -days 3650 -sha384 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl x509 -req -in testdata/hand-off/v1/requests/x509-response-request.csr.pem -CA ca.pem -CAkey ca.key \
  -copy_extensions copyall -not_before 20261115120000Z -not_after 20271215120000Z -sha384 -out floor.cert.pem
```

The result passes the floor checks of the requester: `openssl verify -attime 1794744000 -CAfile ca.pem floor.cert.pem` prints `OK` at the vectors' clock; `openssl x509 -in floor.cert.pem -noout -pubkey` and `openssl req -in <the CSR> -noout -pubkey` print the same key; and `openssl x509 -in floor.cert.pem -noout -ext basicConstraints,keyUsage,nameConstraints` shows the three requested extensions, critical, as the CSR asked. `-copy_extensions copyall` is what makes it a floor certificate: without it OpenSSL drops the requested extensions, and the requester refuses the result for its profile, as it refuses the vector `x509-floor-extensions-dropped`. Delete `ca.key` when you are done.
