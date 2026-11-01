# Hand-off test vectors

Fixtures for the [hand-off contract](../../docs/reference/hand-off-contract.md): requests that a certifier must accept or refuse, and answers that a requester must install or refuse, with the expected outcome and reason code of each in `v1/manifest.json`.

Everything under `v1/` is public material made with throw-away software keys by `generate.py`. No private key is kept. The script is the record of how the files were made; running it again makes different bytes, so the committed files are the fixtures. A change to a vector that flips its outcome is a new contract version (a new directory).

The same run writes the [root list vectors](../root-list/README.md), because the root lists are signed by the same test roots. To regenerate both, run `python3 testdata/hand-off/generate.py testdata/hand-off/v1 testdata/root-list/v1` (Python 3 with `cryptography`) after removing the old files of both sets, then `just check-vectors`: it fails when the manifest and the tracked files disagree. `.gitignore` keeps key files out of the repository and lets the `.pem` and `.asc` files under `testdata/` in; every key here is a throw-away test key whose private half was never written.
