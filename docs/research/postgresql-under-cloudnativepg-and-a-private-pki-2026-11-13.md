---
title: A CloudNativePG 1.30 cluster's own checks of server certificates look at the CA and not the name, and a private PKI plugs in at four Secrets (read, 2026-11-13)
description: What CloudNativePG 1.30 and PostgreSQL 18 say about the certificates of one cluster, and where a private PKI plugs in. Read in documents and code, not run.
sidebar:
  order: 17
---

**Nothing in this note was measured.** No cluster was installed and no program was run. Every statement was read in a documentation page or in source code on the day named below. Most carry a label. Where the author draws a conclusion, the label says Concluded.

## Question

A team has a private PKI ([the chain](../learn/chain-private-pki.md)): a root key kept in a ceremony tool, an intermediate held by the system that issues for an environment, and short-lived leaf certificates. The team runs PostgreSQL in Kubernetes with the operator CloudNativePG (CNPG). An operator is a program inside the cluster that creates and looks after a database. Which certificates does one CNPG cluster use, who makes them, which chain does each side check, and where does the private PKI plug in?

This note covers PostgreSQL as run by CNPG only. Plain PostgreSQL appears only where it explains what CNPG sets.

## When

2026-11-13. The pages were read that day and can change. CNPG pages are for version 1.30 (the source files at tag v1.30.1, released 2026-09-23). PostgreSQL pages are for version 18 (the "current" manual; its index page says 18.7).

## Verdict

**A private PKI plugs into CNPG at four Secrets, and the operator's and the instances' own checks of server certificates look at the chain and not at the name.** A Secret is a Kubernetes object that holds files, such as a certificate.

- By default CNPG makes its own CA for each cluster and issues 90-day certificates from it: a small PKI outside the team's chain (Doc). In user-provided mode, the team's issuing system can fill four Secrets: server CA, server certificate, client CA and `streaming_replica` certificate (Doc).
- The operator and the instances "verify server certificates against the CA only, disregarding the DNS name" (Doc). Concluded: inside the cluster, names matter only to a client that is set to check them, such as libpq with `sslmode=verify-full` or a replica cluster set as in the CNPG example. A replica cluster is set by the user, and the documentation example checks the name.
- A fixed rule lets the role `streaming_replica` log in, to the databases `postgres` and `replication` from any address, with a certificate whose common name (the name field of the certificate's subject) is `streaming_replica` (Doc, Code). The client CA file is one for all clients, so (Concluded) any such certificate that this CA signs is accepted.
- CNPG does not manage CRLs, and a user cannot set `ssl_crl_file` (Doc, Code). A CRL (certificate revocation list) is a signed list of revoked certificates. The documentation names one way to stop a managed client certificate before it expires: rotate the client CA, or delete the certificate's Secret (Doc). The author concludes that a short life, or a changed or removed `pg_hba` or `pg_ident` line, also stops one (Concluded). `pg_hba.conf` is PostgreSQL's file of rules for who may connect, and how. `pg_ident.conf` maps names in certificates to roles.

## What was read

Labels: **Doc** is a documentation page. **Code** is CNPG source code, read and not run. **Design** is a decision record of the sister project, which is a plan and not a measurement. **Concluded** is the author's reading.

| Source | Version | Address |
|---|---|---|
| CNPG: Certificates | 1.30 | https://cloudnative-pg.io/docs/1.30/certificates/ |
| CNPG: Client TLS/SSL connections | 1.30 | https://cloudnative-pg.io/docs/1.30/ssl_connections/ |
| CNPG: PostgreSQL configuration (`pg_hba`, `pg_ident`, fixed parameters) | 1.30 | https://cloudnative-pg.io/docs/1.30/postgresql_conf/ |
| CNPG: Role management (client certificates of a `DatabaseRole`) | 1.30 | https://cloudnative-pg.io/docs/1.30/declarative_role_management/ |
| CNPG: kubectl plugin, connection pooling, replica clusters, bootstrap, security, operator configuration, API reference | 1.30 | https://cloudnative-pg.io/docs/1.30/ followed by `kubectl-plugin`, `connection_pooling`, `replica_cluster`, `bootstrap`, `security`, `operator_conf` or `cloudnative-pg.v1` |
| CNPG source, files under `pkg/certs`, `internal/controller`, `pkg/postgres`, `pkg/management` | tag v1.30.1 | https://github.com/cloudnative-pg/cloudnative-pg/tree/v1.30.1 |
| PostgreSQL: SSL, certificate authentication, `pg_hba.conf`, user name maps, connection settings, libpq SSL and connection parameters | 18 | https://www.postgresql.org/docs/18/ followed by `ssl-tcp`, `auth-cert`, `auth-pg-hba-conf`, `auth-username-maps`, `runtime-config-connection`, `libpq-ssl` or `libpq-connect`, each with `.html` |
| cert-manager: Certificate resource, target Secret (read 2026-11-13; the page shows no version) | none shown | https://cert-manager.io/docs/usage/certificate/ |
| Sister project sluis: decision 0023 and requirements for a database | commit 4fa7651 of `main` | https://github.com/truvity/sluis/blob/4fa7651cd6d0c54369c9465fb11b80cda329cb17/docs/decisions/0023-certificate-authorities.md |
| This project: the chain, the custody chain, the hand-off contract, record 0006, the consumers note | `main` | linked where used |

## What the reading over- and under-counts

- The pages were read from the Markdown source at tag v1.30.1. On 2026-11-13 the rendered pages of version 1.30 were compared for the sentences quoted here and agree.
- Documentation says what the authors intend. Code read on paper may differ from a running cluster. CNPG was not compiled.
- cert-manager and sluis are read for one purpose each. The sluis decision is a plan; its database requirement is marked `planned` ([requirements file](https://github.com/truvity/sluis/blob/4fa7651cd6d0c54369c9465fb11b80cda329cb17/docs/requirements/db.yaml)).

## The certificates of one cluster

Default mode, with nothing provided.

| Certificate | For what | Made by default | Life and renewal | Secret |
|---|---|---|---|---|
| Server CA | Signs the server certificate. Its `ca.crt` is the `sslrootcert` of clients. (Doc) | The operator, self-signed. (Doc) | 90 days, renewed 7 days before the end. The code re-signs it with the same key. (Doc, Code) | `<cluster>-ca`: `ca.crt`, `ca.key` |
| Server certificate | Shown by every instance. Names: the read-write, read and read-only services that are switched on and additional managed services, each in four spellings (name, name.namespace, name.namespace.svc, name.namespace.svc.domain), plus names you add. The common name is the read-write service. The instance manager's status port uses it too. (Code) | The operator, signed by the server CA, ECDSA P-256. (Doc, Code) | 90 days, renewed 7 days before the end. A renewal needs "a simple reload" and no downtime. (Doc) | `<cluster>-server`: `tls.crt`, `tls.key` |
| Client CA | `ssl_ca_file` of every instance. (Doc) | By default the same CA as the server CA. (Doc) | As the server CA | Same Secret |
| `streaming_replica` certificate | A replica proves itself to the primary. Common name `streaming_replica`. (Doc) | The operator, signed by the client CA. (Doc) | 90 days, renewed 7 days before | `<cluster>-replication` |
| Application client certificate | A user logs in with a certificate and no password. | Nobody. Three ways: `kubectl cnpg certificate` (one Secret, common name = user, 90 days by default, not renewed by the plugin: the plugin's code, read in one file, creates the Secret and ends, and has no renewal step; Code, not run); a `DatabaseRole` with a `clientCertificate` block (the operator renews it, 90 days and 7 days, set for the whole operator); or your own issuer. (Doc, Code) | See the way chosen | `<role>-client-cert` for a `DatabaseRole` |
| Pooler certificate | PgBouncer logs in as `cnpg_pooler_pgbouncer`. The pooler reuses the cluster's certificates by default. (Doc) | The operator, signed by the client CA. (Doc, Code) | As the client CA | A Secret of the cluster |
| The operator's own client certificate | The operator calls the sensitive endpoints of the instance manager. (Doc) | The operator, self-signed, in memory. (Doc) | New at each operator start. Trust is by a pinned fingerprint, not by a CA. (Doc) | None; never on disk |

CNPG handles more certificates that this note leaves out, because they are not the database's: the operator's webhook, the mutual TLS of CNPG-I plugins, and the CA of a backup object store (`endpointCA`). A replica cluster uses the source cluster's `-replication` and `-ca` Secrets to connect to it; it has no certificate of its own for that. (Concluded)

## Which side checks which chain

| Connection | Who checks | Against | Name checked? |
|---|---|---|---|
| Application to server | libpq, in the application | `sslrootcert`. The default `sslmode` is `prefer`, which does not verify. (Doc) | Only with `verify-full`. The CNPG example uses `verify-full`. (Doc) |
| Client certificate to server | PostgreSQL | `ssl_ca_file`. Only on a `hostssl` line with `cert` or `clientcert`. A CRL is read only if one is set. (Doc) | The common name against the role, or a map (Doc) |
| Replica to primary | libpq, with `sslmode=verify-ca` | `server-ca.crt` of the replica (Code) | No (Code) |
| Primary to replica | PostgreSQL | `ssl_ca_file`, rule `hostssl ... streaming_replica ... cert map=cnpg_streaming_replica` (Doc) | Common name `streaming_replica` |
| Operator to status port | The operator, in Go | The server CA. It takes the intermediates from what the instance sends. (Doc, Code) | No (Doc) |
| Instance manager to operator | The instance manager | A pinned fingerprint of one key (Doc) | No |
| Pooler to server | PgBouncer, `server_tls_sslmode=verify-ca` (Code) | `serverCASecret` of the pooler, or the cluster's | No |
| Replica cluster to source cluster | libpq, as set in `externalClusters` | `sslRootCert` (a Secret). The example uses `verify-full`. (Doc) | Yes in the example |

## The two modes side by side

| | Operator-managed (default) | User-provided |
|---|---|---|
| Whose CA | The operator's, one per cluster. A separate small PKI, outside the team's chain. (Concluded) | The team's. The `ca.crt` of `serverCASecret` and `clientCASecret` is the CA that validates (Doc). That it can be the root of the chain is Concluded. In the code every certificate in the file becomes a root of trust, so it may also be an intermediate (Code, test 2). |
| Who renews | The operator. (Doc) | The team's issuer. "any user-managed certificates not controlled by CloudNativePG must be re-issued following the renewal process". (Doc) |
| What it asks of the team | Apps need the cluster's `ca.crt`, and must refresh it before the copy they hold ends: the CA certificate is re-signed with the same key at each renewal. (Concluded from Code) | Four Secrets with the right keys and names. The label `cnpg.io/reload` on each, or `kubectl cnpg reload`. (Doc) The intermediate after the leaf in `tls.crt` (the CNPG pages do not say it; PostgreSQL 18 Doc, CNPG Code). |
| What stops working | Nothing | With a client CA you provide: `kubectl cnpg certificate` stops ("you can no longer generate client certificates"). If that CA Secret has no private key, the `DatabaseRole` certificates stop too ("you must issue and renew client certificates manually"). With `ca.key` in it the operator signs (API reference). (Doc) |
| When a certificate is renewed | A reload. (Doc) | On each reconcile the operator checks each provided leaf against its CA, and returns an error if it does not verify. What a running cluster does then is not stated. (Code) |
| What to check | Does the application verify the server name? Is `ca.crt` current? | Does the server check client certificates against the right CA only? Do the server names fit the intermediate's name constraint? Is the intermediate in `tls.crt`? |

The API reference names a third way: give the operator a CA together with its key (`ca.key`), and the operator signs. That puts a CA key into a Secret of the cluster. (Doc)

## Where the private PKI plugs in

| Link of the chain | In the project's words | In CNPG | Names |
|---|---|---|---|
| Root | Kept at a ceremony. Given out in the CA bundle ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 23). | `ca.crt` of `serverCASecret` and `clientCASecret`; `sslrootcert` of clients | None |
| Intermediate | Held by the system that issues for an environment. Name-constrained, path length 0 ([hand-off contract](../reference/hand-off-contract.md)). | Not given to CNPG. Its certificate follows the leaf in `tls.crt` (PostgreSQL 18 Doc, CNPG Code). | Its permitted DNS zone limits every server name below it |
| Server leaf | Issued automatically, short-lived | `serverTLSSecret`: `tls.crt`, `tls.key` | DNS names of the services the clients use |
| Application client leaf | The same | A Secret you name, mounted into the application | Common name = role name |
| `streaming_replica` leaf | The same | `replicationTLSSecret` | Common name `streaming_replica`, or a `pg_ident` map |

Which of these CNPG can take from a Secret that another tool fills (Doc): all four. The cert-manager example fills the server pair; its client example fills the client pair. cert-manager (read 2026-11-13; the page shows no version) says `tls.crt` holds the leaf followed by the chain, and that `ca.crt` is stored when the CA is known. It also says not to mount `ca.crt` directly into a trust store, "as it will be updated when the certificate is renewed". The CNPG example points `serverCASecret` at the leaf's own Secret, which holds that `ca.crt`.

The sister project describes this plan in a decision ([0023](https://github.com/truvity/sluis/blob/4fa7651cd6d0c54369c9465fb11b80cda329cb17/docs/decisions/0023-certificate-authorities.md)): server certificates through cert-manager, database client certificates with the role as the common name, never for `streaming_replica`, matched with `clientname=DN`. The same decision says that CNPG keeps a CA of its own for replication and that the server trusts the sluis chain beside it. That is a Design, `planned`, and was not read as a running system.

## Revocation and rotation

| Question | PostgreSQL 18 (Doc) | CNPG 1.30 (Doc, Code) |
|---|---|---|
| CRL for client certificates | `ssl_crl_file`, read at start and reload. `ssl_crl_dir`, read at each connection, files added at once. | "CNPG does not manage Certificate Revocation Lists (CRLs)." `ssl_crl_file` cannot be set by a user. `ssl_crl_dir` is not on that list; the pages read describe no way to put files into a pod (searched for "crl" in docs/src; the sample YAML files and the release notes were not searched). |
| CRL for the server certificate | `sslcrl`, `sslcrldir`, or `~/.postgresql/root.crl`, on the client | Nothing for CNPG's own connections |
| OCSP (a live question to a server about one certificate) | Not found on the pages read | Not found in the Markdown pages of docs/src nor in any .go file at tag v1.30.1 |
| Reload without restart | The server reads its SSL files at start and at reload. A bad file at reload is ignored and the old setting stays, with a log line. | Operator-managed: reload. User-provided: label `cnpg.io/reload` or `kubectl cnpg reload`. |
| Change a rule | `pg_hba.conf` and `pg_ident.conf` are read at start and at SIGHUP | A change in the cluster spec is reloaded "immediately" |
| Change the client CA | Needs a reload | For certificates the operator made: it "re-issues all managed client certificates" |

A leaf that must stop working today: short life helps only if the issuer's lifetime is hours, not CNPG's 90 days (Concluded). A changed or removed `pg_hba` or `pg_ident` line stops the name at the next connection (Concluded). A new client CA stops every certificate of the old one (Concluded). No page read says whether an open session ends.

## How to read it

**CNPG's own checks look at the chain only.** User-provided certificates often lack the name of the `<cluster>-rw` service, so names are ignored. (Doc) Concluded: this helps a team with a name constraint. The intermediate's constraint allows only names in its zone, and the contract decides one permitted zone ([hand-off contract](../reference/hand-off-contract.md)). A service name such as `<cluster>-rw.<namespace>.svc` is inside the zone only if the zone covers it. Go and OpenSSL both refused a name outside the constraint in this project's measurement ([chain page](../learn/chain-private-pki.md)). So the leaf can carry a name in the zone, and CNPG's checks do not need the service names.

**The client CA is trusted as a whole.** `ssl_ca_file` is one file for all users. CNPG gives "a CA shared across multiple clusters" as a reason why a certificate named `streaming_replica` may be impossible, and offers a `pg_ident` map. (Doc) Concluded: the control is what the issuer refuses to sign, such as that name.

**Name constraints reach the common name differently in each client.** The chain page records, measured on 2026-11-01, that Go 1.27 accepted a leaf with a common name and no SAN (subject alternative name, a name field of the certificate) and OpenSSL 3.5 refused it, under a DNS constraint. CNPG's operator checks with Go (Code). PostgreSQL and libpq use OpenSSL (Doc). A client leaf whose only name is the role needs a test.

**The intermediate's key usage decides which CA slot it fits.** CNPG checks the server leaf for server use and the replication leaf for client use (Code). Concluded: an intermediate limited to server use cannot sign client leaves that verify, so the two CA slots suit two intermediates, or one with both usages.

## What the team still has to learn about PostgreSQL

- **Name to role.** The `cert` method compares the common name with the role name. Any other form needs a `pg_ident` map or `clientname=DN`. (Doc)
- **Passwords still exist.** The last default line, `host all all all scram-sha-256`, matches TLS and non-TLS connections alike, so a role with a password gets in unless a line before it refuses. (Doc: `host` "records match SSL or non-SSL connection attempts") The operator also makes a password for the application owner. (Doc)
- **A certificate proves a name, not a right.** The role must exist with login, and its grants are separate. (Concluded)

## What this does not show

- **The Code rows are one reading** of one tag. Renewal timing, reload timing and error handling were not run.
- **Only libpq and PgBouncer are named as clients.** Drivers that do not use libpq (Go, Java) check names and constraints in their own way.
- **Not read for certificates:** CNPG-I plugins, the operator's webhook, backups to an object store, logical replication and failover.
- **One version of each**, and cert-manager and sluis were not installed or tried. Other versions, in particular of the CNPG role certificates, may differ.

## Tests a real cluster would have to run

1. Server leaf under an intermediate with a permitted zone, `tls.crt` = leaf + intermediate, `ca.crt` = root only: does the cluster start, and does `psql` with `verify-full` and only the root accept it?
2. The same with `ca.crt` = the intermediate and no root: do the operator and libpq `verify-ca` accept it?
3. A server leaf with one name outside the zone, such as the `.svc` name: what does the operator do, and does a running cluster keep serving?
4. A client leaf with the role as common name and no SAN, under a DNS constraint: does PostgreSQL accept it?
5. A renewal in user-provided mode: how long from the changed Secret to the changed `ssl_cert_file`, and are open connections kept?
6. `ssl_crl_dir` in `postgresql.parameters`: does the webhook accept it, and can a directory made with `openssl rehash` reach the pod?
7. A revoked client leaf: is it refused at the next connection, does PostgreSQL check a CRL entry for the intermediate or only for the leaf, and does a session that is open then end?
8. A replica cluster with `verify-full` and the team's server leaf: which `host` value passes?

## What this decides

Nothing for ritueel. The note gives plain words and tables for the part of the chain after the hand-off ([hand-off contract](../reference/hand-off-contract.md), [after the ceremony](./after-the-ceremony-consumers-2026-11-11.md)): where the CA bundle goes into a CNPG cluster, which names a leaf needs, and where revocation stops. The root's CRL revokes an intermediate ([CRL page](../reference/crl.md)); it does not reach a leaf. The CRL page says a relying party configures the file, "the way a server is told which CRL file to load". In CNPG the parameter that does so, `ssl_crl_file`, is fixed. No mode is recommended: the pages read give no ground for one. The tests are the next step. Nothing is blocked.

## Changes made

None. Nothing was installed, started or changed.
