# Hand-off test vectors

Fixtures for the [hand-off contract](../../docs/reference/hand-off-contract.md): requests that a certifier must accept or refuse, and answers that a requester must install or refuse, with the expected outcome and reason code of each in `v1/manifest.json`.

Everything under `v1/` is public material made with throw-away software keys by `generate.py`. No private key is kept. The script is the record of how the files were made; running it again makes different bytes, so the committed files are the fixtures. A change to a vector that flips its outcome is a new contract version (a new directory).
