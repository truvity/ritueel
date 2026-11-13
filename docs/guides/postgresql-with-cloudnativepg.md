---
title: PostgreSQL with CloudNativePG under your private PKI
description: How a team can give a CloudNativePG cluster certificates from its own issuing system, with the checks, the limits and the tests to run first. Read, not run.
sidebar:
  order: 16
---

**Nothing in this guide was run on a cluster.** It rests on the [reading note](/research/postgresql-under-cloudnativepg-and-a-private-pki-2026-11-13/): the documents and source code of CloudNativePG 1.30 (tag v1.30.1, 2026-09-23) and PostgreSQL 18 (manual 18.7), read on 2026-11-13. It is advice that binds no one. "Concluded" marks what the note only concludes.

## Two modes, and the mix this guide takes

CloudNativePG (CNPG) is an operator, a program that looks after a database in the cluster. By default it makes a CA of its own for each cluster and issues 90-day certificates from it: a small PKI outside your chain [1]. In **user-provided mode** your issuing system makes and renews the certificates of the Secrets that you fill [1]. The documentation also allows a mix, where only part of the certificates comes from outside [1]. This guide takes the mix: your issuing system fills the two server Secrets, so that the server certificate chains to your root and your intermediate's limits apply. The certificate for replication stays with the operator (see below). The client side is not settled by the sources; see "The client CA and the replication user".

## The four Secrets

| Secret | Who fills it under this guide |
|---|---|
| `serverCASecret` | Your issuing system. `ca.crt`: the roots of your CA bundle (concluded). |
| `serverTLSSecret` | Your issuing system. `tls.crt`: the server leaf, then the intermediate; `tls.key`. |
| `clientCASecret` | Open. If you leave it out, the operator keeps its own client CA, and the cluster trusts no client certificate of yours (concluded). If you fill it with your CA's `ca.crt` only, the operator refuses it while `replicationTLSSecret` is empty [1]. See below. |
| `replicationTLSSecret` | Nobody: it stays empty, and the operator makes the `streaming_replica` certificate from its own client CA [1]. |

Label each Secret that you fill `cnpg.io/reload`, or run `kubectl cnpg reload`, so that the cluster reads a change [1]. Put in the names your clients connect to, all inside the intermediate's permitted DNS zone. CNPG's own checks "verify server certificates against the CA only, disregarding the DNS name" [1]; your clients should not (test 2 asks what the operator does with a name outside the zone).

## Clients: `verify-full`

The default `sslmode` of libpq, `prefer`, does not verify. Set `verify-full` on every application, with `sslrootcert` set to your roots. It checks the chain and the name, and the libpq manual recommends it "in most security-sensitive environments" [2].

## Application roles: a certificate and a password

Give an application role a client certificate (the role name as common name) and keep its SCRAM password. The certificate needs a cluster that trusts your client CA, which is open (see above): until test 6 passes, rely on the password alone. The `pg_hba` line is of this kind (not run; check that it stands before CNPG's default lines):

```text
hostssl DATABASE ROLE all scram-sha-256 clientcert=verify-full
```

PostgreSQL calls `cert` alone "effectively trust authentication with clientcert=verify-full" [3], so a leaked client CA leaves no second factor. And passwords exist anyway: CNPG's last default line, `host all all all scram-sha-256`, matches connections without TLS too [1].

## The client CA and the replication user

A fixed rule lets the role `streaming_replica` in, to the databases `postgres` and `replication`, on a certificate with that common name [1]. The client CA file is one for all clients, so any such certificate this CA signs is accepted (concluded). The issuing system never signs this name for an application, a person or another cluster. Replication stays on CloudNativePG's own CA, which is trusted beside yours, and the fourth Secret is not filled from your issuing system. The sister project plans the same (a plan, not a running system). None of this was run on a cluster.

What the sources show about this, and what they do not:

- **Shown.** The documentation says that the operator "still creates and manages the two secrets related to client certificates" when you provide only the server pair [1]. Then replication runs on the operator's own client CA, and that CA is the only one in the client CA file of the instances.
- **Shown.** The API reference says that `clientCASecret` holds `ca.crt`, "used as `ssl_ca_file` of all the instances", and that if `replicationTLSSecret` is not defined, "ClientCASecret must provide also `ca.key`, and a new secret will be created using the provided CA" [1]. The code agrees: with a named client CA Secret and an empty `replicationTLSSecret`, a Secret without `ca.key` is refused, and with `ca.key` the operator signs the `streaming_replica` certificate with that CA (code at tag v1.30.1, not run). So your CA's key in `clientCASecret` is the opposite of this guide, and your CA's `ca.crt` alone does not work.
- **Not shown.** How one cluster trusts the operator's own client CA and yours together. No documentation page says it. The sister project's decision says that CloudNativePG "keeps a CA of its own for replication between its instances" and that "the server trusts sluis's chain for them beside the replication CA" [5]. It does not say which Secret holds which certificate, whether the client CA file holds two CAs, or who holds which key; it leaves the wiring of a database to that database's own repository [5]. This is a plan, and no source read shows the steps. Concluded from the code, not run: the operator checks the replication certificate against every certificate in that `ca.crt` but reads the first one to sign, so a file with two CAs may work [1]. Do not rely on it before test 6 passes.

## Lifetime and key type

Make the lifetime as short as your issuing system can renew without a restart; PostgreSQL reads its SSL files at start and at reload [4]. CNPG's own 90 days is too long to stand in for revocation (next section); it stays the life of the replication certificate, which the operator makes [1]. Test 4 tells how short you can go.

CNPG's own key is ECDSA P-256 [1]. A review of published recommendations preferred P-384 for database certificates; the choice in [Leaf keys](/guides/leaf-keys/) is P-256 or P-384, and both stay open. PostgreSQL with P-384 was not tested. Avoid Ed25519 for the server ([Leaf keys](/guides/leaf-keys/)).

## Key exchange

A hybrid key exchange agrees the session key with a classical and a post-quantum method together, so a recording of today's traffic cannot be decrypted later by a quantum computer. In PostgreSQL 18 and later the default of `ssl_groups` has no hybrid group; add `X25519MLKEM768` to it only when the OpenSSL of your image is 3.5 or later, because a group name that OpenSSL does not know stops the server at start [6] (read, not run; CloudNativePG does not block the parameter [7]).

## Revocation does not reach the database

CNPG manages no CRLs, and a user cannot set `ssl_crl_file` [1]. The project's CRLs list intermediates, and no certificate carries a CRL address ([the CRL page](/reference/crl/)). So the database never learns that a root revoked an intermediate. It accepts the client certificates under it until they expire, or until you act on the database (concluded). A CRL of your own would need an entry for every CA in a client chain, or logins fail (read in source, not tested) [4]. What stops a client, by conclusion and not by test: a short life; a changed or removed `pg_hba` or `pg_ident` line; a new client CA, which stops every certificate of the old one. Whether an open session ends is not stated.

## If you provide the client CA

This applies when you fill `clientCASecret`. `kubectl cnpg certificate` stops. If the CA Secret has no private key, the `DatabaseRole` certificates stop too ("you must issue and renew client certificates manually"), and the operator refuses the Secret while `replicationTLSSecret` is empty. With `ca.key` in it the operator signs, which puts a CA key into the cluster, and it signs the `streaming_replica` certificate with it, against the decision above [1].

## Run these tests first

The note lists eight; start with these.

1. `tls.crt` is leaf plus intermediate, `ca.crt` the root only: does the cluster start, and does `psql` with `verify-full` accept it?
2. A server leaf with one name outside the zone: what does the operator do, and does a running cluster keep serving?
3. A client leaf with the role as common name and no SAN, under a DNS constraint: does PostgreSQL accept it?
4. A renewal: how long from the changed Secret to the changed `ssl_cert_file`, and are open connections kept?
5. A revoked client leaf: is it refused at the next connection, and does an open session end?
6. The client CA: a cluster with the two server Secrets from your issuing system and the client side as the sister project plans it. Which Secret holds which certificate and which key? Does the cluster start with replication on the operator's own client CA? Does a client leaf of your CA log in beside it?

**Again: nothing here was run on a cluster.**

## Sources

1. CloudNativePG 1.30, pages `certificates`, `ssl_connections`, `postgresql_conf`, `declarative_role_management` and the API reference, https://cloudnative-pg.io/docs/1.30/, and source at tag v1.30.1 (the latest release on 2026-11-13), https://github.com/cloudnative-pg/cloudnative-pg/tree/v1.30.1, read 2026-11-13 (the note's table lists each page). For the Secrets of this guide the pages `certificates` and `cloudnative-pg.v1` (type `CertificatesConfiguration`) and the files `internal/controller/cluster_pki.go` and `pkg/certs/certs.go` were read again; the pages on the `main` branch say the same.
2. PostgreSQL libpq documentation, branch REL_18_STABLE, `doc/src/sgml/libpq.sgml`, "SSL support", https://github.com/postgres/postgres.
3. PostgreSQL 18.7, "Certificate Authentication", https://www.postgresql.org/docs/current/auth-cert.html.
4. PostgreSQL 18.7, "Secure TCP/IP Connections with SSL", https://www.postgresql.org/docs/current/ssl-tcp.html, and `src/backend/libpq/be-secure-openssl.c`, branch REL_18_STABLE.
5. The sister project, decision 0023, "Database client certificates", at commit 4fa7651 of `main`, read 2026-11-13 (the passage is the same on `main` that day), https://github.com/truvity/sluis/blob/4fa7651cd6d0c54369c9465fb11b80cda329cb17/docs/decisions/0023-certificate-authorities.md. Status "Accepted; amended by 0044"; the requirement for a database is marked planned. It is a plan and not a running system.
6. PostgreSQL 18.7, "Connections and Authentication", parameter `ssl_groups`, https://www.postgresql.org/docs/18/runtime-config-connection.html; `src/backend/libpq/be-secure-openssl.c`, branch REL_18_STABLE, https://github.com/postgres/postgres; OpenSSL 3.5, `SSL_CTX_set1_groups_list(3)` (`doc/man3/SSL_CTX_set1_curves.pod`, branch openssl-3.5), https://github.com/openssl/openssl; read 2026-11-13.
7. CloudNativePG 1.30, page "PostgreSQL Configuration", section "Fixed parameters", https://cloudnative-pg.io/docs/1.30/postgresql_conf/, and `pkg/postgres/configuration.go` at tag v1.30.1, https://github.com/cloudnative-pg/cloudnative-pg/tree/v1.30.1, read 2026-11-13.
