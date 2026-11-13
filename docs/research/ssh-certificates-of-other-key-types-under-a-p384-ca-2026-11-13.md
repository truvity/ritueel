---
title: A P-384 SSH CA key certified Ed25519, RSA and P-256 keys; Go accepted all five certificates and ssh-keygen checked the two user ones (2026-11-13)
description: Whether a P-384 SSH CA key can certify keys of other types: ssh-keygen 10.2p1 and Go x/crypto/ssh v0.59.0 on software keys, with commands, results and limits.
sidebar:
  order: 19
---

## Question

Can an ECDSA P-384 SSH CA key (a certificate authority key, which signs certificates for other keys) certify host keys and user keys of other types, and do OpenSSH and one Go library accept such certificates?

A user certificate says that a user key may log in as the listed principals (user names). A host certificate says that a host key belongs to the listed host names. The checking side trusts one CA key.

## When

2026-11-13, one run, repeated the same day by a second reader with the same outcomes.

## Verdict

**Yes, in this test.** A P-384 CA key certified an Ed25519 user key, an RSA 3072 user key, a P-384 host key, a P-256 host key and an Ed25519 host key. Go `x/crypto/ssh` accepted all five certificates. OpenSSH `ssh-keygen` checked the two user certificates against the CA (check 2). For the three host certificates `ssh-keygen` could only print them (check 1), which shows that a certificate is well formed and nothing more. Each control (wrong CA, changed signature, wrong name) was refused by the checks it was made for; not every control was made for every check. No `sshd` and no `ssh` client was run.

## What was tested

| Item | Value |
|---|---|
| OpenSSH | `OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5` (`ssh -V`); `ssh` and `ssh-keygen` are from one package |
| Go | go1.27.0 linux/amd64, `golang.org/x/crypto` v0.59.0 |
| System | a Linux machine (Ubuntu 26.04, x86-64) |
| Keys | Software keys made new for the test in an empty temporary folder. No card, no ssh-agent, no real key, no network during the checks. |
| "Accepted" | Check 1: `ssh-keygen -L` printed the certificate and exited 0; it trusts no CA and does not check the time. Check 2: `ssh-keygen -Y verify` printed `Good "test" signature`, with the CA named in the `allowed_signers` file. Check 3: the Go program printed `accepted`: the CA, the name, the time and the CA signature were checked. |

## Method

All certificates are made by `ssh-keygen -s` (`-h` for host certificates), valid for one hour; all checks ran within that hour.

```
mkdir work && cd work
ssh-keygen -q -t ecdsa -b 384 -N '' -f ca_p384
ssh-keygen -q -t ed25519 -N '' -f ca_ed25519
ssh-keygen -q -t ed25519 -N '' -f user_ed25519
ssh-keygen -q -t rsa -b 3072 -N '' -f user_rsa3072
ssh-keygen -q -t ecdsa -b 384 -N '' -f host_p384
ssh-keygen -q -t ecdsa -b 256 -N '' -f host_p256
ssh-keygen -q -t ed25519 -N '' -f host_ed25519
ssh-keygen -q -s ca_p384 -I c1 -n alice -V +1h -z 1 user_ed25519.pub
ssh-keygen -q -s ca_p384 -I c2 -n alice -V +1h -z 2 user_rsa3072.pub
ssh-keygen -q -s ca_p384 -h -I c3 -n host1.example -V +1h -z 3 host_p384.pub
ssh-keygen -q -s ca_p384 -h -I c4 -n host1.example -V +1h -z 4 host_p256.pub
ssh-keygen -q -s ca_p384 -h -I c5 -n host1.example -V +1h -z 5 host_ed25519.pub
cp user_ed25519 cmp_user_ed25519; cp user_ed25519.pub cmp_user_ed25519.pub
cp host_p384.pub cmp_host_p384.pub
ssh-keygen -q -s ca_ed25519 -I c6 -n alice -V +1h -z 6 cmp_user_ed25519.pub
ssh-keygen -q -s ca_ed25519 -h -I c7 -n host1.example -V +1h -z 7 cmp_host_p384.pub
```

Check 1, `ssh-keygen -L -f CERT`, prints a certificate. A changed signature stops it (control 10).

Check 2, `ssh-keygen -Y verify`, is run for user certificates only (it refused the host certificates). The user key signs a message with its certificate. The verifier trusts one CA through an `allowed_signers` file. Rows 1, 2 and 6:

```
echo "msg" > m.txt
ssh-keygen -q -Y sign -f user_ed25519-cert.pub -n test m.txt
echo "alice cert-authority,namespaces=\"test\" $(cut -d' ' -f1,2 ca_p384.pub)" > allowed
ssh-keygen -Y verify -f allowed -I alice -n test -s m.txt.sig < m.txt
```

```
for pair in "user_rsa3072 ca_p384" "cmp_user_ed25519 ca_ed25519"; do
  set -- $pair
  echo "msg" > m_$1.txt
  ssh-keygen -q -Y sign -f $1-cert.pub -n test m_$1.txt
  echo "alice cert-authority,namespaces=\"test\" $(cut -d' ' -f1,2 $2.pub)" > allowed_$1
  ssh-keygen -Y verify -f allowed_$1 -I alice -n test -s m_$1.txt.sig < m_$1.txt
done
```

Check 3 is the Go program below. Build it with `go mod init sshcheck`, `go get golang.org/x/crypto@v0.59.0` (needs the network once) and `go build -o sshcheck .`. `./sshcheck CA.pub CERT NAME` calls `CertChecker.Authenticate` for a user certificate and `CheckHostKey` for a host certificate. Both call `CheckCert` (name, time, signature); the program's own function `same` checks which CA signed. The runs used `CGO_ENABLED=0 GOPROXY=off`.

```go
package main

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type meta struct {
	ssh.ConnMetadata
	user string
}

func (m meta) User() string { return m.user }

func load(path string) ssh.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		panic(err)
	}
	return k
}

func main() {
	ca := load(os.Args[1])
	cert, ok := load(os.Args[2]).(*ssh.Certificate)
	if !ok {
		panic("not a certificate")
	}
	same := func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), ca.Marshal()) }
	c := &ssh.CertChecker{
		IsUserAuthority: same,
		IsHostAuthority: func(k ssh.PublicKey, addr string) bool { return same(k) },
	}
	var err error
	if cert.CertType == ssh.HostCert {
		err = c.CheckHostKey(os.Args[3]+":22", nil, cert)
	} else {
		_, err = c.Authenticate(meta{user: os.Args[3]}, cert)
	}
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	fmt.Println("accepted; CA signature", cert.Signature.Format)
}
```

Rows 1 to 7, then controls 8, 9 and 11:

```
./sshcheck ca_p384.pub user_ed25519-cert.pub alice
./sshcheck ca_p384.pub user_rsa3072-cert.pub alice
./sshcheck ca_p384.pub host_p384-cert.pub host1.example
./sshcheck ca_p384.pub host_p256-cert.pub host1.example
./sshcheck ca_p384.pub host_ed25519-cert.pub host1.example
./sshcheck ca_ed25519.pub cmp_user_ed25519-cert.pub alice
./sshcheck ca_ed25519.pub cmp_host_p384-cert.pub host1.example
./sshcheck ca_ed25519.pub user_ed25519-cert.pub alice
./sshcheck ca_p384.pub cmp_user_ed25519-cert.pub alice
./sshcheck ca_p384.pub user_ed25519-cert.pub bob
./sshcheck ca_p384.pub host_p384-cert.pub other.example
```

Controls 8 and 9 for check 2 (the same message, the other CA):

```
echo msg > m8.txt; echo msg > m9.txt
echo "alice cert-authority,namespaces=\"test\" $(cut -d' ' -f1,2 ca_ed25519.pub)" > allowed_other
ssh-keygen -q -Y sign -f user_ed25519-cert.pub -n test m8.txt
ssh-keygen -Y verify -f allowed_other -I alice -n test -s m8.txt.sig < m8.txt
echo "alice cert-authority,namespaces=\"test\" $(cut -d' ' -f1,2 ca_p384.pub)" > allowed_other2
ssh-keygen -q -Y sign -f cmp_user_ed25519-cert.pub -n test m9.txt
ssh-keygen -Y verify -f allowed_other2 -I alice -n test -s m9.txt.sig < m9.txt
```

Control 10 flips bit 0 of the 5th byte from the end of the decoded certificate, which lies in the CA signature, and checks the changed copies:

```
python3 -I - <<'PY'
import base64
for name in ("user_ed25519", "host_p384"):
    kind, blob = open(name + "-cert.pub").read().split()[:2]
    data = bytearray(base64.b64decode(blob))
    data[-5] ^= 1
    open("flip_" + name + "-cert.pub", "w").write(kind + " " + base64.b64encode(bytes(data)).decode() + "\n")
PY
ssh-keygen -L -f flip_user_ed25519-cert.pub
ssh-keygen -L -f flip_host_p384-cert.pub
./sshcheck ca_p384.pub flip_user_ed25519-cert.pub alice
./sshcheck ca_p384.pub flip_host_p384-cert.pub host1.example
```

## Numbers

| # | Certificate | CA key | Check 1 (`-L`) | Check 2 (`-Y verify`) | Check 3 (Go) |
|---|---|---|---|---|---|
| 1 | user, Ed25519 | P-384 | printed | accepted | accepted |
| 2 | user, RSA 3072 | P-384 | printed | accepted | accepted |
| 3 | host, P-384 | P-384 | printed | not possible | accepted |
| 4 | host, P-256 | P-384 | printed | not possible | accepted |
| 5 | host, Ed25519 | P-384 | printed | not possible | accepted |
| 6 | user, Ed25519 (comparison) | Ed25519 | printed | accepted | accepted |
| 7 | host, P-384 (comparison) | Ed25519 | printed | not possible | accepted |

For each host certificate, `ssh-keygen -Y verify` answered `not a user certificate`.

| # | What was changed | Result |
|---|---|---|
| 8 | Certificate 1, against the Ed25519 CA | Check 2: `Could not verify signature`. Check 3: `signed by unrecognized authority`. |
| 9 | Certificate 6, against the P-384 CA | Refused by checks 2 and 3, as in row 8. |
| 10 | One bit flipped in the CA signature of certificates 1 and 3 | Check 1: `incorrect signature`. Check 3: `certificate signature does not verify`. |
| 11 | A name the certificate does not list (`bob`, `other.example`) | Check 3: `principal ... not in the set of valid principals`. |

Controls 8 and 9 were made for user certificates; control 10 for certificates 1 and 3 and for checks 1 and 3; control 11 for check 3 only. Check 2 has no changed-signature control.

`ssh-keygen -L -f` for certificate 3, shortened:

```
Type: ecdsa-sha2-nistp384-cert-v01@openssh.com host certificate
Public key: ECDSA-CERT SHA256:<fingerprint>
Signing CA: ECDSA SHA256:<fingerprint> (using ecdsa-sha2-nistp384)
Key ID: "c3"
Serial: 3
Principals: host1.example
```

## How to read it

The verdict and tables are measured; this section is a reading. OpenSSH's description of the format says that a CA key may be of another type than the key it certifies ([`PROTOCOL.certkeys`](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_0_P1/PROTOCOL.certkeys), tag V_10_0_P1: the description of version 10.0; the file is not in the later tags, and this note tested 10.2p1). For these two programs the test shows that a P-384 CA does not limit the type of the host keys and user keys it certifies.

Check 1 proves little. In the second reader's repeat, a host certificate that had expired an hour before was printed by `ssh-keygen -L` with exit 0, and refused by the Go check (`cert has expired`). No control shows that `-Y verify` checks the CA signature itself; controls 8 and 9 show only that it checks which CA the `allowed_signers` file names.

## What this does not show

- **No login to a running `sshd`** was made, and no `ssh` client connected. The checks ran on files. `sshd` and `ssh` have their own settings, for example `CASignatureAlgorithms` in `sshd_config(5)`, whose default list contains `ecdsa-sha2-nistp384` (read, not tried).
- **No other client or library** was tried, for example PuTTY, libssh or Paramiko.
- **Nothing was tried on a host in FIPS mode.**
- **No card held any of the keys**; a card or a cloud key store may sign differently.
- That `-Y verify` takes user certificates only was observed; the manual page does not state it.
- One run, one machine. Other CA curves (P-256, P-521) were not tried.

## What this decides

Nothing for ritueel. It supports one statement in a guide: a P-384 SSH CA key can certify host and user keys of other types, for these two programs and versions. The [SSH CA key list](../reference/ssh-ca-key-list.md) stays P-384 only.

## Changes made

None outside an empty temporary folder, which holds the throw-away keys of the test.
