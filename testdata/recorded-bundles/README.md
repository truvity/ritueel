# Recorded bundles

Bundles that a build of ritueel wrote and that this folder keeps as they were written. They are not made again by the tests. A later build must still pass `ritueel check history` on each of them: a history written before a change is not rewritten by it. `internal/cli/check_recorded_bundle_test.go` runs the command on a copy of each and changes one byte in the copy to show that the test looks at the data.

## first-apply-x509-test-root

The bundle of one finished ceremony: the first `apply` of an X.509 test root, with two root keys, A and B, in the software store.

- **Written by** the code of commit `2c0d3ab` plus the change that moves the key directory check into `internal/keydir` (the first commit of the pull request that added this folder), which changes no behaviour. The test build identifies itself as `dev` and records the digest of the test executable in `plan.json`, so that member differs from build to build.
- **Files** (15, about 12 KiB): `ritueel.yaml`, `want/roots/x509.yaml`, `roots/{A,B}/root.json`, `trust/1-9c9a9768/{ca-bundle.pem,root-list.json,root-list.jws}`, and in `history/20261120T100000Z-apply/` the files `plan.json`, `attempt.json`, `births.jsonl`, `signatures.jsonl`, `transcript.txt`, `record.json` and the copies of the two wanted files in `wanted/`. The end of its history is `a19947c6`, the first eight characters of the digest of the record.
- **The key directory is not kept.** The ceremony wrote the two key files (`A.x509.key.pem`, `B.x509.key.pem`, marked TEST ONLY) and the two removal authorisations into a key directory outside the bundle. Nothing from it is in this folder: the keys were thrown away with the folder that held them. The bundle holds only public material and digests, such as the pins and the digest of a removal authorisation. `births.jsonl` names the place of each key, `A.x509.key.pem` and `B.x509.key.pem`.

### How it was made

In a scratch folder with the working tree of `2c0d3ab` plus that change, one test of `internal/cli` that was run once and not kept. It used the helpers of `apply_run_test.go` (`apRun`, `arPlan`, `arRun`, `newTicker`) and the fixed clock `apClock`, 2026-11-20T10:00:00Z:

1. `new --test-root <scratch>/ca`, through `Run` with the fixed clock.
2. Delete `want/roots/openpgp.yaml`, as a person does before the first `apply` of an X.509 root (the same step as `arBundle`).
3. Make the empty key directory `<scratch>/keys` with mode `0700`, outside the bundle.
4. `--dir <scratch>/ca --output json apply --plan-only --key-dir <scratch>/keys`, read the path and the digest of the plan from the result.
5. `--dir <scratch>/ca apply <plan path> --key-dir <scratch>/keys --confirm <digest>`, with a clock that shows one second more at each call (`newTicker`), standard input empty and not a terminal. It exits with code 0 and ends with `history: 1 ceremony records, end a19947c6`.
6. Copy `<scratch>/ca` to this folder, without the key directory. All files are stored with mode `0644` and folders with `0755`, as a checkout has them.

### Not reproducible byte for byte

The clock is fixed and the plan is a function of the wanted files and the clock, but the command line has no seam for the source of random numbers: the keys, and so the pins, the certificates, the serial numbers, the signatures, the root list and the record, come from `crypto/rand` and differ from run to run. Making the bundle again gives another bundle of the same shape, not these bytes. That is why the files are kept.

No absolute path, host name, user name or e-mail address of the machine that made it is in the files (searched before they were added); `ritueel.yaml` holds `release@example.org`.
