---
title: PostgreSQL with CloudNativePG under your private PKI
description: How a team can give a CloudNativePG cluster certificates from its own issuing system, with the checks, the limits and the tests to run first. Read, not run.
sidebar:
  order: 16
---

**Nothing in this guide was run on a cluster.** It rests on the [reading note](/research/postgresql-under-cloudnativepg-and-a-private-pki-2026-11-13/): the documents and source code of CloudNativePG 1.30 (tag v1.30.1, 2026-09-23) and PostgreSQL 18 (manual 18.7), read on 2026-11-13. It is advice that binds no one. "Concluded" marks what the note only concludes.

## Two modes, and the one this guide takes

CloudNativePG (CNPG) is an operator, a program that looks after a database in the cluster. By default it makes a CA of its own for each cluster and issues 90-day certificates from it: a small PKI outside your chain [1]. In **user-provided mode** you fill four Secrets, and your issuing system makes and renews the certificates [1]. This guide takes the second, so that every certificate chains to your root and your intermediate's limits apply.

## The four Secrets

| Secret | The issuing system puts in |
|---|---|
| `serverCASecret` | `ca.crt`: the roots of your CA bundle (concluded). |
| `serverTLSSecret` | `tls.crt`: the server leaf, then the intermediate; `tls.key`. |
| `clientCASecret` | `ca.crt`: the CA that signs client certificates. |
| `replicationTLSSecret` | A certificate with the common name `streaming_replica` (see below). |

Label each Secret `cnpg.io/reload`, or run `kubectl cnpg reload`, so that the cluster reads a change [1]. Put in the names your clients connect to, all inside the intermediate's permitted DNS zone. CNPG's own checks "verify server certificates against the CA only, disregarding the DNS name" [1]; your clients should not (test 2 asks what the operator does with a name outside the zone).

## Clients: `verify-full`

The default `sslmode` of libpq, `prefer`, does not verify. Set `verify-full` on every application, with `sslrootcert` set to your roots. It checks the chain and the name, and the libpq manual recommends it "in most security-sensitive environments" [2].

## Application roles: a certificate and a password

Give an application role a client certificate (the role name as common name) and keep its SCRAM password, with a `pg_hba` line of this kind (not run; check that it stands before CNPG's default lines):

```text
hostssl DATABASE ROLE all scram-sha-256 clientcert=verify-full
```

PostgreSQL calls `cert` alone "effectively trust authentication with clientcert=verify-full" [3], so a leaked client CA leaves no second factor. And passwords exist anyway: CNPG's last default line, `host all all all scram-sha-256`, matches connections without TLS too [1].

## The replication user

A fixed rule lets the role `streaming_replica` in, to the databases `postgres` and `replication`, on a certificate with that common name [1]. The client CA file is one for all clients, so any such certificate this CA signs is accepted (concluded). The issuing system never signs this name for an application, a person or another cluster. Filling the fourth Secret from it would be the one exception; the sister project's plan avoids it with CNPG's own CA for replication, trusted beside yours (a plan, not a running system). The note does not choose.

## Lifetime and key type

Make the lifetime as short as your issuing system can renew without a restart; PostgreSQL reads its SSL files at start and at reload [4]. CNPG's own 90 days is too long to stand in for revocation (next section). Test 4 tells how short you can go.

CNPG's own key is ECDSA P-256 [1]. A review of published recommendations preferred P-384 for database certificates; the choice in [Leaf keys](/guides/leaf-keys/) is P-256 or P-384, and both stay open. PostgreSQL with P-384 was not tested. Avoid Ed25519 for the server ([Leaf keys](/guides/leaf-keys/)).

## Revocation does not reach the database

CNPG manages no CRLs, and a user cannot set `ssl_crl_file` [1]. The project's CRLs list intermediates, and no certificate carries a CRL address ([the CRL page](/reference/crl/)). So the database never learns that a root revoked an intermediate. It accepts the client certificates under it until they expire, or until you act on the database (concluded). A CRL of your own would need an entry for every CA in a client chain, or logins fail (read in source, not tested) [4]. What stops a client, by conclusion and not by test: a short life; a changed or removed `pg_hba` or `pg_ident` line; a new client CA, which stops every certificate of the old one. Whether an open session ends is not stated.

## If you provide the client CA

`kubectl cnpg certificate` stops. If the CA Secret has no private key, the `DatabaseRole` certificates stop too ("you must issue and renew client certificates manually"). With `ca.key` in it the operator signs, which puts a CA key into the cluster [1].

## Run these tests first

The note lists eight; start with these.

1. `tls.crt` is leaf plus intermediate, `ca.crt` the root only: does the cluster start, and does `psql` with `verify-full` accept it?
2. A server leaf with one name outside the zone: what does the operator do, and does a running cluster keep serving?
3. A client leaf with the role as common name and no SAN, under a DNS constraint: does PostgreSQL accept it?
4. A renewal: how long from the changed Secret to the changed `ssl_cert_file`, and are open connections kept?
5. A revoked client leaf: is it refused at the next connection, and does an open session end?

**Again: nothing here was run on a cluster.**

## Sources

1. CloudNativePG 1.30, pages `certificates`, `ssl_connections`, `postgresql_conf`, `declarative_role_management` and the API reference, https://cloudnative-pg.io/docs/1.30/, and source at tag v1.30.1, https://github.com/cloudnative-pg/cloudnative-pg/tree/v1.30.1, read 2026-11-13 (the note's table lists each page).
2. PostgreSQL libpq documentation, branch REL_18_STABLE, `doc/src/sgml/libpq.sgml`, "SSL support", https://github.com/postgres/postgres.
3. PostgreSQL 18.7, "Certificate Authentication", https://www.postgresql.org/docs/current/auth-cert.html.
4. PostgreSQL 18.7, "Secure TCP/IP Connections with SSL", https://www.postgresql.org/docs/current/ssl-tcp.html, and `src/backend/libpq/be-secure-openssl.c`, branch REL_18_STABLE.
