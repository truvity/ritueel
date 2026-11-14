#!/bin/bash
# Rebuilds every derived file of testdata/x509-builders/ with OpenSSL, from the public inputs only.
#
# Usage: reproduce.sh FOLDER OUTDIR
#   FOLDER  testdata/x509-builders (root.pub.pem, the *.csr.pem, the *.sig.hex)
#   OUTDIR  where the rebuilt files go; compare with: diff -r FOLDER OUTDIR (only the files that
#           OUTDIR has are compared: the inputs are not copied)
#
# The expected bytes are described to OpenSSL's ASN.1 generator (openssl asn1parse -genconf) as a
# structure, with the times, names, serials and extension values written out below. Nothing here
# is the code under test. No private key is read or written: the signatures in *.sig.hex are inputs.
set -euo pipefail
dir=$1 out=$2
mkdir -p "$out"

point() { # the uncompressed point of a P-384 public key in PEM, as hex
  openssl pkey -pubin -in "$1" -outform DER | openssl asn1parse -inform DER -strparse 20 -noout -out /dev/stdout | xxd -p -c 200 | tr -d '\n'
}
csrpub() { openssl req -in "$1" -noout -pubkey; }
kid() { printf '%s' "$1" | xxd -r -p | sha256sum | cut -c1-40; } # RFC 7093 method 1
pin() { openssl pkey -pubin -in "$1" -outform DER | sha256sum | cut -d' ' -f1; }

rootpub=$dir/root.pub.pem
RP=$(point "$rootpub"); RK=$(kid "$RP")
: > "$out/expected.txt"
say() { printf '%s %s\n' "$1" "$2" >> "$out/expected.txt"; }
say root.pin "$(pin "$rootpub")"
say root.keyid "$RK"

# The name of the root, as OpenSSL writes it: one RDN, one common name, UTF8String.
rootname() { # CN
cat <<EOT
[rname]
rdn = SET:rrdn
[rrdn]
atv = SEQUENCE:ratv
[ratv]
type = OID:2.5.4.3
value = UTF8:$1
EOT
}

# root NAME CN SERIAL NOTBEFORE NOTAFTER   (the times as OpenSSL writes them: UTCTIME:... or GENERALIZEDTIME:...)
root() {
  local name=$1 cn=$2 serial=$3 nb=$4 na=$5
  {
cat <<EOT
asn1 = SEQUENCE:tbs
[tbs]
version = EXPLICIT:0,INTEGER:2
serial = INTEGER:0x$serial
sigalg = SEQUENCE:alg
issuer = SEQUENCE:rname
validity = SEQUENCE:val
subject = SEQUENCE:rname
spki = SEQUENCE:spki
exts = EXPLICIT:3,SEQUENCE:exts
[alg]
oid = OID:1.2.840.10045.4.3.3
[val]
nb = $nb
na = $na
[spki]
algo = SEQUENCE:spkialg
key = FORMAT:HEX,BITSTRING:$RP
[spkialg]
a = OID:1.2.840.10045.2.1
b = OID:1.3.132.0.34
[exts]
bc = SEQUENCE:bc
ski = SEQUENCE:ski
ku = SEQUENCE:ku
[bc]
id = OID:2.5.29.19
crit = BOOLEAN:TRUE
val = OCTWRAP,SEQWRAP,BOOLEAN:TRUE
[ski]
id = OID:2.5.29.14
val = OCTWRAP,FORMAT:HEX,OCTETSTRING:$RK
[ku]
id = OID:2.5.29.15
crit = BOOLEAN:TRUE
val = OCTWRAP,FORMAT:BITLIST,BITSTRING:5,6
EOT
rootname "$cn"
  } > "$out/$name.cnf"
  finish "$name"
}

# inter NAME CSR SERIAL NOTBEFORE NOTAFTER SUBJECT_SECTIONS KU_BITS NC_TYPE EKU_CRIT EKU_OIDS
#   NC_TYPE: none, uri or dns (one permitted subtree, example.org). EKU_OIDS: space separated, empty for none.
inter() {
  local name=$1 csr=$2 serial=$3 nb=$4 na=$5 subject=$6 kubits=$7 nc=$8 ekucrit=$9
  shift 9
  local ekus=("$@")
  local CP CK
  CP=$(csrpub "$dir/$csr.csr.pem" | { f=$(mktemp); cat > "$f"; point "$f"; rm -f "$f"; })
  CK=$(kid "$CP")
  say "$csr.keyid" "$CK"
  local exts="bc = SEQUENCE:bc
ku = SEQUENCE:ku"
  [ "$nc" = none ] || exts="$exts
nc = SEQUENCE:nc"
  [ "${#ekus[@]}" -eq 0 ] || exts="$exts
eku = SEQUENCE:eku"
  exts="$exts
ski = SEQUENCE:ski
aki = SEQUENCE:aki"
  {
cat <<EOT
asn1 = SEQUENCE:tbs
[tbs]
version = EXPLICIT:0,INTEGER:2
serial = INTEGER:0x$serial
sigalg = SEQUENCE:alg
issuer = SEQUENCE:rname
validity = SEQUENCE:val
subject = SEQUENCE:sname
spki = SEQUENCE:spki
exts = EXPLICIT:3,SEQUENCE:exts
[alg]
oid = OID:1.2.840.10045.4.3.3
[val]
nb = $nb
na = $na
[spki]
algo = SEQUENCE:spkialg
key = FORMAT:HEX,BITSTRING:$CP
[spkialg]
a = OID:1.2.840.10045.2.1
b = OID:1.3.132.0.34
[exts]
$exts
[bc]
id = OID:2.5.29.19
crit = BOOLEAN:TRUE
val = OCTWRAP,SEQUENCE:bcval
[bcval]
ca = BOOLEAN:TRUE
pl = INTEGER:0
[ku]
id = OID:2.5.29.15
crit = BOOLEAN:TRUE
val = OCTWRAP,FORMAT:BITLIST,BITSTRING:$kubits
[ski]
id = OID:2.5.29.14
val = OCTWRAP,FORMAT:HEX,OCTETSTRING:$CK
[aki]
id = OID:2.5.29.35
val = OCTWRAP,SEQUENCE:akival
[akival]
kid = IMPLICIT:0,FORMAT:HEX,OCTETSTRING:$RK
EOT
    if [ "$nc" != none ]; then
      local tag=6; [ "$nc" = dns ] && tag=2
cat <<EOT
[nc]
id = OID:2.5.29.30
crit = BOOLEAN:TRUE
val = OCTWRAP,SEQUENCE:ncval
[ncval]
permitted = IMPLICIT:0,SEQUENCE:permitted
[permitted]
st = SEQUENCE:subtree
[subtree]
base = IMPLICIT:$tag,IA5STRING:example.org
EOT
    fi
    if [ "${#ekus[@]}" -gt 0 ]; then
cat <<EOT
[eku]
id = OID:2.5.29.37
EOT
      [ "$ekucrit" = critical ] && echo "crit = BOOLEAN:TRUE"
cat <<EOT
val = OCTWRAP,SEQUENCE:ekuval
[ekuval]
EOT
      local i=0; for o in "${ekus[@]}"; do echo "o$i = OID:$o"; i=$((i+1)); done
    fi
    echo "$subject"
    rootname "Example Test Root K (TEST ONLY)"
  } > "$out/$name.cnf"
  finish "$name"
}

# finish NAME: DER and hex of the TBS, digests, and, when a signature file exists, the certificate.
finish() {
  local n=$1
  openssl asn1parse -genconf "$out/$n.cnf" -noout -out "$out/$n.tbs.der"
  xxd -p -c 2000 "$out/$n.tbs.der" | tr -d '\n' > "$out/$n.tbs.hex"; echo >> "$out/$n.tbs.hex"
  say "$n.tbs" "$(tr -d '\n' < "$out/$n.tbs.hex")"
  say "$n.tbs.sha256" "$(sha256sum "$out/$n.tbs.der" | cut -d' ' -f1)"
  say "$n.tbs.sha384" "$(openssl dgst -sha384 -hex "$out/$n.tbs.der" | sed 's/.*= //')"
  if [ -f "$dir/$n.sig.hex" ]; then
    local sig; sig=$(tr -d '\n' < "$dir/$n.sig.hex")
    { printf 'asn1 = SEQUENCE:cert\n[cert]\ntbs = SEQUENCE:tbs\nsigalg = SEQUENCE:alg\nsig = FORMAT:HEX,BITSTRING:%s\n' "$sig"; tail -n +2 "$out/$n.cnf"; } > "$out/$n.cert.cnf"
    openssl asn1parse -genconf "$out/$n.cert.cnf" -noout -out "$out/$n.cert.der"
    openssl x509 -inform DER -in "$out/$n.cert.der" -outform PEM -out "$out/$n.cert.pem"
  fi
}

# --- the root certificates (the key is root.pub.pem; times are UTC) ---------------------------
root root-test 'Example Test Root K (TEST ONLY)' 4b1c9e0d77a2f35b8c6e1d0a93f4b27c5e8a1d36 \
  UTCTIME:261115120000Z UTCTIME:291115120000Z
root root-real 'Example-Org 2 Root Z' 8000000000000001 \
  UTCTIME:240229083000Z UTCTIME:270228083000Z
root root-2049 'Example Test Root K (TEST ONLY)' 7fffffffffffffffffffffffffffffffffffffff \
  UTCTIME:491231235959Z GENERALIZEDTIME:20521231235959Z
root root-2050 'Example Test Root K (TEST ONLY)' ffffffffffffffff \
  GENERALIZEDTIME:20500101000000Z GENERALIZEDTIME:20530101000000Z
root root-1950 'Example Test Root K (TEST ONLY)' 0123456789abcdef01 \
  UTCTIME:500101000000Z UTCTIME:530101000000Z
root root-1949 'Example Test Root K (TEST ONLY)' 0123456789abcdef02 \
  GENERALIZEDTIME:19491231235959Z UTCTIME:521231235959Z
# The longest common name of RFC 5280: 64 characters (a name of 45 characters, " Root K", " (TEST ONLY)").
root root-longest 'Abcdefghij Abcdefghij Abcdefghij Abcdefghij a Root K (TEST ONLY)' 0fedcba9876543210f \
  UTCTIME:261115120000Z UTCTIME:291115120000Z

# --- the intermediate certificates (issuer: the root of root-test) ----------------------------
say issuer "$(openssl asn1parse -genconf <(printf 'asn1 = SEQUENCE:rname\n'; rootname 'Example Test Root K (TEST ONLY)') -noout -out /dev/stdout | xxd -p -c 200 | tr -d '\n')"

sub_nc='[sname]
rdn1 = SET:srdn1
rdn2 = SET:srdn2
[srdn1]
atv = SEQUENCE:satv1
[satv1]
type = OID:2.5.4.10
value = PRINTABLESTRING:acme
[srdn2]
atv = SEQUENCE:satv2
[satv2]
type = OID:2.5.4.3
value = PRINTABLESTRING:acme example intermediate CA'
sub_eku='[sname]
rdn1 = SET:srdn1
rdn2 = SET:srdn2
rdn3 = SET:srdn3
[srdn1]
atv = SEQUENCE:satv1
[satv1]
type = OID:2.5.4.10
value = UTF8:acme
[srdn2]
atv = SEQUENCE:satv2
[satv2]
type = OID:2.5.4.11
value = UTF8:ops
[srdn3]
atv = SEQUENCE:satv3
[satv3]
type = OID:2.5.4.3
value = UTF8:acme example eku CA'
sub_ekucrit='[sname]
rdn1 = SET:srdn1
[srdn1]
atv = SEQUENCE:satv1
[satv1]
type = OID:2.5.4.3
value = UTF8:acme example client CA'

# serverAuth 1.3.6.1.5.5.7.3.1, clientAuth 1.3.6.1.5.5.7.3.2
inter inter-nc csr-nc 73a1553666c0f868e34f116d4af6a1acb8c6b6 \
  UTCTIME:261115120000Z UTCTIME:271215120000Z "$sub_nc" 5,6 uri plain 1.3.6.1.5.5.7.3.1
inter inter-eku csr-eku 8000000000000000 \
  UTCTIME:270131102030Z UTCTIME:280229102030Z "$sub_eku" 0,5,6 dns plain 1.3.6.1.5.5.7.3.1 1.3.6.1.5.5.7.3.2
inter inter-eku-reversed csr-eku-reversed 7fffffffffffffffffffffffffffffffffffffff \
  UTCTIME:491231235959Z GENERALIZEDTIME:20510131235959Z "$sub_ekucrit" 5 dns plain 1.3.6.1.5.5.7.3.2 1.3.6.1.5.5.7.3.1
for c in csr-nc csr-eku csr-eku-reversed csr-no-eku csr-eku-critical; do
  say "$c.pin" "$(openssl req -in "$dir/$c.csr.pem" -noout -pubkey | { f=$(mktemp); cat > "$f"; pin "$f"; rm -f "$f"; })"
done
