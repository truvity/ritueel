import { SubjectKind } from '../gen/ritueel/local/v1alpha1/common_pb';
import type { Finding, Root } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';

// The page joins in the page, as the contract's README says: a finding is
// about a key when its subject is that key's full fingerprint, or a card the
// key's subkeys sit on. Names are never used to join.

function fingerprintsOf(r: Root): Set<string> {
  const out = new Set<string>();
  r.keys.forEach((k) => out.add(k.fingerprint));
  if (r.certificate?.primary) out.add(r.certificate.primary.fingerprint);
  r.delegatedKeys.forEach((d) => out.add(d.fingerprint));
  r.certificate?.subkeySets.forEach((s) => s.subkeys.forEach((k) => out.add(k.fingerprint)));
  if (r.cloudKey?.alias) out.add(r.cloudKey.alias);
  return out;
}

function cardSerialsOf(r: Root): Set<string> {
  const out = new Set<string>(r.cardSerials);
  r.certificate?.subkeySets.forEach((s) => s.cardSerial && out.add(s.cardSerial));
  return out;
}

/** The root a fingerprint (of its key, a subkey or a delegated key) belongs to. Joined on the full fingerprint, never on a name. */
export function rootOf(roots: Root[] | undefined, identifier: string): Root | undefined {
  return roots?.find((r) => fingerprintsOf(r).has(identifier));
}

/** The findings that are about this root, worst first. */
export function touching(r: Root, all: Finding[]): Finding[] {
  const fps = fingerprintsOf(r);
  const serials = cardSerialsOf(r);
  return all
    .filter((f) => {
      const s = f.subject;
      if (!s) return false;
      if (fps.has(s.identifier)) return true;
      return s.kind === SubjectKind.CARD && serials.has(s.identifier);
    })
    .sort((a, b) => b.severity - a.severity);
}
